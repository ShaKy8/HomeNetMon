"""Ring account bridge for the garage camera.

Ring has no personal API: the Partner API is for certified app publishers. This
module wraps the unofficial ``ring-doorbell`` library (the one Home Assistant
uses) behind a small synchronous surface so the rest of HomeNetMon never sees
aiohttp, asyncio or the library's exceptions.

The library is async-only. ``RingBridge`` therefore owns ONE asyncio event loop
in its own daemon thread (``RingBridge``); every public method submits a
coroutine to that loop and waits. The aiohttp session inside ``Auth`` is bound
to that loop, which is why ``Auth`` is always constructed there.

Sign-in happens once (email + password, then the 2FA code Ring sends); only
the OAuth token is kept, in ``token_file`` with mode 0600. The password is
never stored.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import logging
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SNAPSHOT_REFRESH_ENDPOINT = '/clients_api/snapshots/update_all'   # PUT {doorbot_ids, refresh: true}: ask the camera for a new frame


class RingError(Exception):
    """Ring could not be reached or answered with an error."""


class RingAuthError(RingError):
    """Wrong email / password / code, or the stored token was rejected."""


def _lib():
    """The ring_doorbell package and its const module, imported lazily (tests stub both)."""
    try:
        rd = importlib.import_module('ring_doorbell')
        const = importlib.import_module('ring_doorbell.const')
    except ImportError as e:
        raise RingError('ring-doorbell is not installed (pip install -r requirements.txt)') from e
    return rd, const


def _iso(value: Any) -> str | None:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value) if value else None


class RingBridge:
    THREAD_NAME = 'RingBridge'

    def __init__(self, token_file: str | os.PathLike, user_agent: str, timeout: float = 30.0):
        self.token_file = Path(token_file)
        self.user_agent = user_agent
        self.timeout = timeout
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._auth = None
        self._ring = None
        self._token: dict | None = None
        self._lock = threading.Lock()

    # ---- lifecycle ------------------------------------------------------------------
    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._token = self._load_token()
            self._loop = asyncio.new_event_loop()
            self._thread = threading.Thread(target=self._loop.run_forever, daemon=True, name=self.THREAD_NAME)
            self._thread.start()

    def stop(self) -> None:
        loop, thread = self._loop, self._thread
        if loop is None:
            return
        try:
            self._run(self._close(), timeout=5)
        except Exception:
            pass
        loop.call_soon_threadsafe(loop.stop)
        if thread is not None:
            thread.join(5)
        self._loop, self._thread = None, None

    def signed_in(self) -> bool:
        return self._token is not None

    def _run(self, coro, timeout: float | None = None):
        if self._loop is None or self._thread is None or not self._thread.is_alive():
            self.start()
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return future.result(timeout or self.timeout)
        except TimeoutError:
            future.cancel()
            raise RingError(f'Ring did not answer within {timeout or self.timeout:.0f} s') from None

    # ---- public (sync) surface --------------------------------------------------------
    def login(self, email: str, password: str, otp: str | None = None) -> dict:
        """{'status': 'ok'} or {'status': '2fa_required'}; RingAuthError on bad credentials."""
        return self._run(self._login(email.strip(), password, (otp or '').strip() or None), timeout=60)

    def logout(self) -> None:
        self._run(self._logout(), timeout=15)

    def cameras(self) -> list[dict]:
        return self._run(self._cameras())

    def latest_snapshot(self, device_id: int | str, since_ms: int | None = None) -> tuple[bytes | None, int | None]:
        """The camera's most recent stored frame (no wake-up), unless it is not newer than ``since_ms``."""
        return self._run(self._latest_snapshot(device_id, since_ms))

    def fresh_snapshot(self, device_id: int | str, retries: int = 6, delay: int = 2) -> tuple[bytes | None, int | None]:
        """Ask the camera for a new frame and wait for it; (None, last_ts) when it declines (battery cams)."""
        return self._run(self._fresh_snapshot(device_id, retries, delay), timeout=retries * delay + 30)

    def motion_events(self, device_id: int | str, limit: int = 5) -> list[dict]:
        return self._run(self._motion_events(device_id, limit))

    def health(self, device_id: int | str) -> dict:
        return self._run(self._health(device_id))

    # ---- coroutines (run on the bridge loop) ----------------------------------------
    async def _ensure_ring(self):
        if self._ring is not None:
            return self._ring
        if self._token is None:
            raise RingAuthError('Not signed in to Ring')
        rd, _ = _lib()
        auth = rd.Auth(self.user_agent, self._token, self._save_token)
        ring = rd.Ring(auth)
        try:
            await ring.async_create_session()
            await ring.async_update_data()
        except rd.AuthenticationError as e:
            await self._quiet_close(auth)
            self._forget_token()
            raise RingAuthError(f'Ring rejected the stored sign-in; sign in again ({e})') from e
        except Exception as e:
            await self._quiet_close(auth)
            raise RingError(f'Ring session failed: {e}') from e
        self._auth, self._ring = auth, ring
        return ring

    async def _login(self, email: str, password: str, otp: str | None) -> dict:
        rd, _ = _lib()
        await self._close()
        auth = rd.Auth(self.user_agent, None, self._save_token)
        try:
            token = await auth.async_fetch_token(email, password, otp)
        except rd.Requires2FAError:
            await self._quiet_close(auth)
            return {'status': '2fa_required'}
        except rd.AuthenticationError as e:
            await self._quiet_close(auth)
            raise RingAuthError(f'Ring rejected the sign-in: {e}') from e
        except Exception as e:
            await self._quiet_close(auth)
            raise RingError(f'Ring sign-in failed: {e}') from e
        self._save_token(token)
        ring = rd.Ring(auth)
        try:
            await ring.async_create_session()
            await ring.async_update_data()
        except Exception as e:
            await self._quiet_close(auth)
            raise RingError(f'Signed in, but the Ring session failed: {e}') from e
        self._auth, self._ring = auth, ring
        return {'status': 'ok'}

    async def _logout(self) -> None:
        await self._close()
        self._forget_token()

    async def _close(self) -> None:
        auth, self._auth, self._ring = self._auth, None, None
        if auth is not None:
            await self._quiet_close(auth)

    @staticmethod
    async def _quiet_close(auth) -> None:
        try:
            await auth.async_close()
        except Exception:
            pass

    async def _device(self, device_id):
        ring = await self._ensure_ring()
        device = self._find(ring, device_id)
        if device is None:
            try:
                await ring.async_update_data()
            except Exception as e:
                raise RingError(f'Ring device list failed: {e}') from e
            device = self._find(ring, device_id)
        if device is None:
            raise RingError(f'Ring camera {device_id} is not on this account')
        return device

    @staticmethod
    def _find(ring, device_id):
        for device in ring.devices().video_devices:
            if str(device.id) == str(device_id):
                return device
        return None

    def _camera_info(self, device) -> dict:
        rd, _ = _lib()
        try:
            is_battery = bool(device.has_capability(rd.RingCapability.BATTERY))
        except Exception:
            is_battery = False
        try:
            battery = device.battery_life
        except Exception:
            battery = None
        try:
            wifi = device.wifi_signal_strength
        except Exception:
            wifi = None
        return {
            'id': device.id, 'name': device.name, 'kind': getattr(device, 'kind', None),
            'model': getattr(device, 'model', None), 'battery_life': battery, 'wifi_signal_strength': wifi,
            'is_battery': is_battery or battery is not None,
        }

    async def _cameras(self) -> list[dict]:
        ring = await self._ensure_ring()
        try:
            devices = list(ring.devices().video_devices)
        except Exception as e:
            raise RingError(f'Ring device list failed: {e}') from e
        return [self._camera_info(d) for d in devices]

    async def _health(self, device_id) -> dict:
        device = await self._device(device_id)
        try:
            await device.async_update_health_data()
        except Exception as e:
            logger.debug(f"Ring health data for {device_id} unavailable: {e}")
        return self._camera_info(device)

    async def _snapshot_timestamp(self, ring, device_id) -> int:
        _, const = _lib()
        try:
            resp = await ring.async_query(const.SNAPSHOT_TIMESTAMP_ENDPOINT, method='POST',
                                          json={'doorbot_ids': [int(device_id)]})
            stamps = (resp.json() or {}).get('timestamps') or []
        except Exception as e:
            raise RingError(f'Ring snapshot lookup failed: {e}') from e
        if not stamps:
            return 0
        try:
            return int(stamps[0].get('timestamp') or 0)
        except (TypeError, ValueError, AttributeError):
            return 0

    async def _snapshot_image(self, ring, device_id) -> bytes | None:
        _, const = _lib()
        try:
            resp = await ring.async_query(const.SNAPSHOT_ENDPOINT.format(int(device_id)))
        except Exception as e:
            logger.debug(f"Ring snapshot image for {device_id} unavailable: {e}")
            return None
        content = getattr(resp, 'content', None)
        return bytes(content) if content else None

    async def _latest_snapshot(self, device_id, since_ms: int | None) -> tuple[bytes | None, int | None]:
        ring = await self._ensure_ring()
        ts = await self._snapshot_timestamp(ring, device_id)
        if not ts:
            return None, None
        if since_ms is not None and ts <= since_ms:
            return None, ts
        return await self._snapshot_image(ring, device_id), ts

    async def _fresh_snapshot(self, device_id, retries: int, delay: int) -> tuple[bytes | None, int | None]:
        ring = await self._ensure_ring()
        ids = {'doorbot_ids': [int(device_id)]}
        requested_ms = int(time.time() * 1000)
        try:
            # What the Ring app does when you open the live view thumbnail (ring-client-api's requestSnapshotUpdate).
            await ring.async_query(SNAPSHOT_REFRESH_ENDPOINT, method='PUT', json={**ids, 'refresh': True})
        except Exception as e:
            logger.debug(f"Ring snapshot refresh for {device_id} not accepted: {e}")
        ts = 0
        for _ in range(max(1, retries)):
            await asyncio.sleep(delay)
            ts = await self._snapshot_timestamp(ring, device_id)
            if ts and ts >= requested_ms:
                return await self._snapshot_image(ring, device_id), ts
        return None, ts or None

    async def _motion_events(self, device_id, limit: int) -> list[dict]:
        device = await self._device(device_id)
        try:
            events = await device.async_history(limit=limit, kind='motion')
        except Exception as e:
            raise RingError(f'Ring history failed: {e}') from e
        out = []
        for event in events or []:
            out.append({'id': event.get('id'), 'created_at': _iso(event.get('created_at'))})
        return out

    # ---- token file -----------------------------------------------------------------
    def _save_token(self, token: dict) -> None:
        self._token = dict(token)
        try:
            self.token_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            tmp = self.token_file.with_suffix(self.token_file.suffix + '.tmp')
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as fh:
                json.dump(self._token, fh)
            os.replace(tmp, self.token_file)
            os.chmod(self.token_file, 0o600)
        except OSError as e:
            logger.error(f"Could not write the Ring token file {self.token_file}: {e}")

    def _load_token(self) -> dict | None:
        try:
            data = json.loads(self.token_file.read_text(encoding='utf-8'))
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as e:
            logger.warning(f"Ring token file {self.token_file} unreadable: {e}")
            return None
        return data if isinstance(data, dict) and data.get('refresh_token') else None

    def _forget_token(self) -> None:
        self._token = None
        try:
            self.token_file.unlink()
        except FileNotFoundError:
            pass
        except OSError as e:
            logger.warning(f"Could not remove the Ring token file {self.token_file}: {e}")
