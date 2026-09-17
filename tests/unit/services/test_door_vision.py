"""services/door_vision.py: frame preparation, the change gate and the Claude call (SDK faked)."""

import io
import sys
import types
from types import SimpleNamespace

import pytest
from PIL import Image

from services import door_vision as dv
from services.door_vision import DoorReading, VisionError


def _jpeg(width=1600, height=900, color=(40, 60, 80), box=None):
    image = Image.new('RGB', (width, height), color)
    if box:
        Image.Image.paste(image, (240, 240, 240), box)
    out = io.BytesIO()
    image.save(out, format='JPEG', quality=85)
    return out.getvalue()


# ---- frames ------------------------------------------------------------------------------

def test_prepare_frame_downscales_and_reencodes():
    out = dv.prepare_frame(_jpeg(1600, 900))
    image = Image.open(io.BytesIO(out))
    assert image.width == 1024 and image.height == 576 and image.format == 'JPEG'
    small = dv.prepare_frame(_jpeg(640, 360))
    assert Image.open(io.BytesIO(small)).width == 640


def test_prepare_frame_rejects_garbage():
    with pytest.raises(VisionError):
        dv.prepare_frame(b'not an image')


def test_frame_changed_gate():
    base = _jpeg()
    assert dv.frame_changed(None, base) == (True, 255.0)
    changed, score = dv.frame_changed(base, _jpeg())
    assert changed is False and score < 1.0
    changed, score = dv.frame_changed(base, _jpeg(box=(0, 0, 800, 900)))     # half the frame goes bright
    assert changed is True and score > dv.DEFAULT_THRESHOLD


def test_estimate_cost():
    assert dv.estimate_cost_usd('claude-opus-5', 1_000_000, 0) == 5.0
    assert dv.estimate_cost_usd('claude-haiku-4-5', 1000, 200) == pytest.approx(0.002)
    assert dv.estimate_cost_usd('unknown-model', 1_000_000, 0) == 5.0        # falls back to the default model


# ---- classify with a fake SDK --------------------------------------------------------------

class FakeAPIError(Exception):
    def __init__(self, status_code=500, message='boom'):
        super().__init__(message)
        self.status_code, self.message = status_code, message


class FakeSDK:
    """Builds a module that looks like `anthropic` for one test."""

    def __init__(self, response=None, error=None):
        self.response, self.error, self.calls = response, error, []
        module = types.ModuleType('anthropic')
        module.AuthenticationError = type('AuthenticationError', (FakeAPIError,), {})
        module.RateLimitError = type('RateLimitError', (FakeAPIError,), {})
        module.APIStatusError = FakeAPIError
        module.APITimeoutError = type('APITimeoutError', (Exception,), {})
        module.APIConnectionError = type('APIConnectionError', (Exception,), {})
        sdk = self

        class Messages:
            def parse(self, **kwargs):
                sdk.calls.append(kwargs)
                if sdk.error:
                    raise sdk.error
                return sdk.response

        class Anthropic:
            def __init__(self, api_key=None, timeout=None, max_retries=None):
                sdk.client_args = {'api_key': api_key, 'timeout': timeout, 'max_retries': max_retries}
                self.messages = Messages()
        module.Anthropic = Anthropic
        self.module = module


def _response(state='closed', confidence=0.93, reason='Door panels fill the frame.', stop='end_turn',
              night=False, visible=True, parsed=True):
    reading = DoorReading(state=state, confidence=confidence, door_visible=visible, night=night, reason=reason)
    return SimpleNamespace(parsed_output=reading if parsed else None, stop_reason=stop,
                           usage=SimpleNamespace(input_tokens=1200, output_tokens=60, cache_read_input_tokens=0,
                                                 cache_creation_input_tokens=0))


@pytest.fixture
def sdk(monkeypatch):
    holder = {}

    def install(response=None, error=None):
        fake = FakeSDK(response, error)
        monkeypatch.setitem(sys.modules, 'anthropic', fake.module)
        holder['sdk'] = fake
        return fake
    return install


def test_classify_sends_the_image_and_returns_reading_with_usage(sdk):
    fake = sdk(_response())
    reading, usage = dv.classify(_jpeg(640, 360), 'claude-opus-5', scene_hint='white door, camera on the left', api_key='k')
    assert reading.state == 'closed' and reading.confidence == 0.93
    assert usage == {'model': 'claude-opus-5', 'input_tokens': 1200, 'output_tokens': 60, 'cache_read_input_tokens': 0,
                     'cache_creation_input_tokens': 0, 'est_cost_usd': pytest.approx(0.0075)}
    call = fake.calls[0]
    assert call['model'] == 'claude-opus-5' and call['output_format'] is DoorReading and call['system'] == dv.SYSTEM_PROMPT
    assert call['output_config'] == {'effort': 'low'} and call['max_tokens'] == dv.MAX_TOKENS
    image_block, text_block = call['messages'][0]['content']
    assert image_block['source']['media_type'] == 'image/jpeg' and image_block['source']['type'] == 'base64'
    assert 'white door, camera on the left' in text_block['text']
    assert fake.client_args == {'api_key': 'k', 'timeout': 45.0, 'max_retries': 1}


def test_classify_omits_effort_for_haiku_and_clamps_values(sdk):
    fake = sdk(_response(confidence=1.7, reason='x' * 500))
    reading, _ = dv.classify(_jpeg(640, 360), 'claude-haiku-4-5')
    assert 'output_config' not in fake.calls[0]
    assert reading.confidence == 1.0 and len(reading.reason) == dv.REASON_LIMIT


def test_classify_rejects_unknown_models_before_calling(sdk):
    fake = sdk(_response())
    with pytest.raises(ValueError):
        dv.classify(_jpeg(640, 360), 'gpt-4')
    assert fake.calls == []


@pytest.mark.parametrize('response', [_response(stop='refusal'), _response(stop='max_tokens'), _response(parsed=False)])
def test_classify_without_a_reading_is_an_error(sdk, response):
    sdk(response)
    with pytest.raises(VisionError):
        dv.classify(_jpeg(640, 360))


def test_classify_maps_sdk_errors(sdk):
    fake = sdk()
    for error, needle in ((fake.module.AuthenticationError(401, 'bad key'), 'rejected'),
                          (fake.module.RateLimitError(429, 'slow down'), 'rate limit'),
                          (FakeAPIError(500, 'boom'), '500'),
                          (fake.module.APITimeoutError('t'), 'timed out'),
                          (fake.module.APIConnectionError('dns'), 'unreachable')):
        fake.error = error
        with pytest.raises(VisionError) as info:
            dv.classify(_jpeg(640, 360))
        assert needle in str(info.value)
