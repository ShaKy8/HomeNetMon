"""Read the garage door state from a camera frame with Claude vision.

Two jobs, both pure functions over JPEG bytes:

* ``frame_changed`` -- a cheap local gate (64x36 grayscale thumbnails, mean
  absolute difference) so an unchanged frame is never sent to the API.
* ``classify`` -- one Messages API call with the image and a frozen prompt;
  the answer is a structured ``DoorReading`` (open / closed / unknown with a
  confidence and a one-line reason). ``usage`` comes back with it so the
  monitor can show what the day has cost.

The API key comes from ``ANTHROPIC_API_KEY`` (config.py). Model choice is a
runtime setting; only the three models in ``ALLOWED_MODELS`` are accepted.
Structured-output schemas accept no numeric or length constraints, so the
pydantic model is plain and the values are clamped after parsing.
"""

from __future__ import annotations

import base64
import io
import logging
from typing import Literal

from PIL import Image, ImageOps, UnidentifiedImageError
from pydantic import BaseModel

logger = logging.getLogger(__name__)

ALLOWED_MODELS = ('claude-opus-5', 'claude-sonnet-5', 'claude-haiku-4-5')
DEFAULT_MODEL = 'claude-opus-5'
EFFORT_MODELS = ('claude-opus-5', 'claude-sonnet-5')          # claude-haiku-4-5 rejects output_config.effort
PRICING_USD_PER_MTOK = {                                       # (input, output), Anthropic API list prices
    'claude-opus-5': (5.0, 25.0),
    'claude-sonnet-5': (2.0, 10.0),
    'claude-haiku-4-5': (1.0, 5.0),
}
MAX_WIDTH = 1024
JPEG_QUALITY = 80
THUMB_SIZE = (64, 36)
DEFAULT_THRESHOLD = 6.0        # mean |a-b| over the thumbnail, 0..255
MAX_TOKENS = 2048              # adaptive thinking counts against this
REASON_LIMIT = 160

SYSTEM_PROMPT = (
    "You read a single still image from a fixed home security camera that is pointed at a residential "
    "garage door. Decide whether the garage door is OPEN or CLOSED.\n"
    "- open: any part of the door is raised, or the opening (the garage interior, the gap under the door, "
    "daylight or darkness through the doorway) is visible.\n"
    "- closed: the door fills its frame from the ground to the top.\n"
    "- unknown: the door is not in view, the frame is black, blurred, blocked or the camera is looking elsewhere.\n"
    "Cars, people, shadows and headlights do not change the answer by themselves. Night-vision (grey or "
    "infrared) frames are normal; report night=true for them and still judge the door.\n"
    "Return door_visible=false whenever the door itself cannot be seen. Give a confidence between 0 and 1 "
    "and a reason of at most one short sentence naming what you saw."
)


class DoorReading(BaseModel):
    state: Literal['open', 'closed', 'unknown']
    confidence: float
    door_visible: bool
    night: bool
    reason: str


class VisionError(Exception):
    """The image could not be read or the API call did not yield a reading."""


# ---- frames -------------------------------------------------------------------------------

def _open(jpeg_bytes: bytes) -> Image.Image:
    try:
        image = Image.open(io.BytesIO(jpeg_bytes))
        image.load()
        return image
    except (UnidentifiedImageError, OSError, ValueError) as e:
        raise VisionError(f'not an image: {e}') from e


def prepare_frame(jpeg_bytes: bytes, max_width: int = MAX_WIDTH, quality: int = JPEG_QUALITY) -> bytes:
    """Re-encode as RGB JPEG no wider than ``max_width`` (fewer image tokens, same content)."""
    image = ImageOps.exif_transpose(_open(jpeg_bytes)).convert('RGB')
    if image.width > max_width:
        height = max(1, round(image.height * max_width / image.width))
        image = image.resize((max_width, height), Image.Resampling.LANCZOS)
    out = io.BytesIO()
    image.save(out, format='JPEG', quality=quality, optimize=True)
    return out.getvalue()


def frame_signature(jpeg_bytes: bytes) -> list[int]:
    """Grayscale thumbnail pixels; two frames with the same signature look the same."""
    image = _open(jpeg_bytes).convert('L').resize(THUMB_SIZE, Image.Resampling.BILINEAR)
    return list(image.getdata())


def frame_changed(prev_jpeg: bytes | None, new_jpeg: bytes, threshold: float = DEFAULT_THRESHOLD) -> tuple[bool, float]:
    """(changed, score): score is the mean absolute pixel difference of the thumbnails (0..255)."""
    if prev_jpeg is None:
        return True, 255.0
    a, b = frame_signature(prev_jpeg), frame_signature(new_jpeg)
    score = sum(abs(x - y) for x, y in zip(a, b, strict=True)) / max(1, len(a))
    return score >= threshold, round(score, 2)


# ---- classification -----------------------------------------------------------------------

def estimate_cost_usd(model: str, input_tokens: int, output_tokens: int) -> float:
    price_in, price_out = PRICING_USD_PER_MTOK.get(model, PRICING_USD_PER_MTOK[DEFAULT_MODEL])
    return round((input_tokens or 0) * price_in / 1e6 + (output_tokens or 0) * price_out / 1e6, 6)


def classify(jpeg_bytes: bytes, model: str = DEFAULT_MODEL, scene_hint: str = '',
             api_key: str | None = None) -> tuple[DoorReading, dict]:
    """One vision call. Returns (reading, usage); raises VisionError when no reading came back."""
    if model not in ALLOWED_MODELS:
        raise ValueError(f'model must be one of {ALLOWED_MODELS}')
    import anthropic

    text = 'Classify the garage door in this image.'
    hint = (scene_hint or '').strip()
    if hint:
        text += f'\nScene notes from the homeowner: {hint[:300]}'
    request = {
        'model': model,
        'max_tokens': MAX_TOKENS,
        'system': SYSTEM_PROMPT,
        'messages': [{'role': 'user', 'content': [
            {'type': 'image', 'source': {'type': 'base64', 'media_type': 'image/jpeg',
                                         'data': base64.standard_b64encode(jpeg_bytes).decode('ascii')}},
            {'type': 'text', 'text': text},
        ]}],
        'output_format': DoorReading,
    }
    if model in EFFORT_MODELS:
        request['output_config'] = {'effort': 'low'}

    client = anthropic.Anthropic(api_key=api_key or None, timeout=45.0, max_retries=1)
    try:
        response = client.messages.parse(**request)
    except anthropic.AuthenticationError as e:
        raise VisionError('ANTHROPIC_API_KEY was rejected') from e
    except anthropic.RateLimitError as e:
        raise VisionError('Claude API rate limit hit; will retry next check') from e
    except anthropic.APIStatusError as e:
        raise VisionError(f'Claude API error {e.status_code}: {e.message}') from e
    except anthropic.APITimeoutError as e:
        raise VisionError('Claude API timed out') from e
    except anthropic.APIConnectionError as e:
        raise VisionError(f'Claude API unreachable: {e}') from e

    stop = getattr(response, 'stop_reason', None)
    if stop in ('refusal', 'max_tokens'):
        raise VisionError(f'Claude gave no reading (stop_reason={stop})')
    reading = getattr(response, 'parsed_output', None)
    if reading is None:
        raise VisionError('Claude returned no structured reading')
    reading.confidence = max(0.0, min(1.0, float(reading.confidence)))
    reading.reason = (reading.reason or '').strip()[:REASON_LIMIT]

    usage = getattr(response, 'usage', None)
    in_tokens = int(getattr(usage, 'input_tokens', 0) or 0)
    out_tokens = int(getattr(usage, 'output_tokens', 0) or 0)
    return reading, {
        'model': model,
        'input_tokens': in_tokens,
        'output_tokens': out_tokens,
        'cache_read_input_tokens': int(getattr(usage, 'cache_read_input_tokens', 0) or 0),
        'cache_creation_input_tokens': int(getattr(usage, 'cache_creation_input_tokens', 0) or 0),
        'est_cost_usd': estimate_cost_usd(model, in_tokens, out_tokens),
    }
