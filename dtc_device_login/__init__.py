"""One device-login flow for apps on the DTC shared auth layer.

Cognito has no RFC 8628 device grant. Apps that already sign operators in
through that layer, and also need a CLI that cannot open a browser, broker
the grant themselves and mint their own credential after approval. The
polling loop used to be copied in each app. This module is that loop.

The wire shape is the device authorization grant:

- ``POST {base}/api/auth/device`` with an optional JSON body
- ``POST {base}/api/auth/device/token`` with ``grant_type`` and ``device_code``

Pending, slow-down, denial, and expiry use the RFC 8628 ``error`` codes.
A 200 response with no ``error`` is the app's credential payload, returned
unchanged. An app whose routes are mounted elsewhere passes ``start_path``
and ``token_path``.
"""

from __future__ import annotations

import time

GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"
START_PATH = "/api/auth/device"
TOKEN_PATH = "/api/auth/device/token"
SLOW_DOWN_SECONDS = 5


class DeviceLoginError(Exception):
    def __init__(self, message: str, code: str = "error"):
        super().__init__(message)
        self.code = code


def absolute_verification_uri(base_url: str, start: dict) -> str:
    raw = str(start.get("verification_uri_complete") or start.get("verification_uri") or "/device")
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw
    return base_url.rstrip("/") + "/" + raw.lstrip("/")


def wait_seconds(timeout: int | None, expires_in: int) -> int:
    """Wait out the code's lifetime, and any longer explicit timeout.

    A reported lifetime wins over a shorter timeout so the CLI does not give
    up while the code is still valid. Fifteen seconds of padding covers the
    last poll. With no lifetime and no timeout, wait ten minutes.
    """
    lifetime = int(expires_in or 0)
    if timeout is None:
        return lifetime if lifetime > 0 else 600
    if lifetime > 0:
        return max(int(timeout), lifetime + 15)
    return int(timeout)


def _interval(start: dict) -> float:
    try:
        interval = float(start.get("interval") or 5)
    except (TypeError, ValueError):
        interval = 5
    return interval if interval >= 1 else 1


def _prompt(prompt, text: str) -> None:
    if prompt is None:
        print(text, end="")
    else:
        prompt(text)


def device_login(
    base_url: str,
    poster,
    *,
    start_body: dict | None = None,
    start_path: str = START_PATH,
    token_path: str = TOKEN_PATH,
    prompt=None,
    present_uri=None,
    sleeper=time.sleep,
    clock=time.time,
    timeout: int | None = None,
    transient: tuple = (),
):
    """Run the device login. ``poster(url, body)`` returns ``(status, dict)``."""
    base = str(base_url or "").rstrip("/")
    if not base:
        raise DeviceLoginError("A server URL is required.", "invalid_request")
    status, start = poster(f"{base}{start_path}", dict(start_body or {}))
    offered = (
        status == 200
        and isinstance(start, dict)
        and start.get("device_code")
        and start.get("user_code")
    )
    if not offered:
        raise DeviceLoginError("The server did not offer device login.", "invalid_response")

    interval = _interval(start)
    try:
        lifetime = int(start.get("expires_in") or 0)
    except (TypeError, ValueError):
        lifetime = 0
    deadline = clock() + wait_seconds(timeout, lifetime)
    uri = absolute_verification_uri(base, start)
    if present_uri is not None:
        uri = present_uri(uri)
    minutes = max((lifetime or int(deadline - clock())) // 60, 1)
    unit = "minute" if minutes == 1 else "minutes"
    _prompt(
        prompt,
        (
            f"\n  Confirm this code:  {start['user_code']}\n"
            f"  Open in a browser:  {uri}\n"
            "\n"
            "  Open that link on a machine you trust and sign in as usual.\n"
            f"  Waiting for confirmation (the code is valid for {minutes} {unit})...\n"
        ),
    )

    while clock() < deadline:
        sleeper(interval)
        if clock() >= deadline:
            break
        try:
            status, result = poster(
                f"{base}{token_path}",
                {"grant_type": GRANT_TYPE, "device_code": start["device_code"]},
            )
        except transient:
            continue
        if not isinstance(result, dict):
            result = {}
        if status == 200 and not result.get("error"):
            return result
        code = str(result.get("error") or "")
        if code == "slow_down":
            interval += SLOW_DOWN_SECONDS
            continue
        if code == "authorization_pending":
            continue
        if code == "access_denied":
            raise DeviceLoginError("The login was denied in the browser.", code)
        if code == "expired_token":
            raise DeviceLoginError("The code expired. Run login again.", code)
        detail = code or f"Device login failed ({status})."
        raise DeviceLoginError(detail, code or "error")
    raise DeviceLoginError("Timed out waiting for approval. Run login again.", "timeout")
