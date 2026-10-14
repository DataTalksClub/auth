import time

import pytest

from dtc_device_login import (
    GRANT_TYPE,
    DeviceLoginError,
    device_login,
    wait_seconds,
)


def scripted(responses):
    calls = []

    def poster(url, body):
        calls.append({"url": url, "body": body})
        status, payload = responses.pop(0)
        return status, payload

    return poster, calls


def test_wait_seconds_holds_for_the_code_lifetime():
    assert wait_seconds(600, 900) == 915
    assert wait_seconds(900, 900) == 915
    assert wait_seconds(30, 0) == 30
    assert wait_seconds(0, 0) == 0
    assert wait_seconds(None, 0) == 600
    assert wait_seconds(None, 120) == 120


def test_device_login_polls_until_the_credential_arrives():
    poster, calls = scripted([
        (200, {
            "device_code": "secret",
            "user_code": "ABCD-EFGH",
            "verification_uri": "/device",
            "expires_in": 900,
            "interval": 2,
        }),
        (400, {"error": "authorization_pending"}),
        (200, {"token": "issued", "email": "op@datatalks.club"}),
    ])
    lines = []
    result = device_login(
        "https://app.example.test/",
        poster,
        start_body={"label": "laptop"},
        prompt=lines.append,
        sleeper=lambda seconds: None,
        clock=lambda: 1_000,
    )

    assert result == {"token": "issued", "email": "op@datatalks.club"}
    assert calls[0]["url"] == "https://app.example.test/api/auth/device"
    assert calls[0]["body"] == {"label": "laptop"}
    assert calls[1]["body"] == {"grant_type": GRANT_TYPE, "device_code": "secret"}
    assert calls[2]["url"].endswith("/api/auth/device/token")
    text = lines[0]
    assert "ABCD-EFGH" in text
    assert "https://app.example.test/device" in text
    assert "valid for 15 minutes" in text
    assert "secret" not in text


def test_device_login_backs_off_and_stops_on_denial():
    poster, _calls = scripted([
        (200, {"device_code": "secret", "user_code": "ABCD-EFGH", "expires_in": 60, "interval": 5}),
        (400, {"error": "slow_down"}),
        (400, {"error": "access_denied"}),
    ])
    sleeps = []
    with pytest.raises(DeviceLoginError, match="denied in the browser") as caught:
        device_login(
            "https://app.example.test",
            poster,
            sleeper=sleeps.append,
            clock=lambda: 0,
        )
    assert caught.value.code == "access_denied"
    assert sleeps == [5, 10]


def test_device_login_times_out_without_a_lifetime():
    poster, _calls = scripted([
        (200, {"device_code": "secret", "user_code": "ABCD-EFGH"}),
    ])
    with pytest.raises(DeviceLoginError, match="Timed out") as caught:
        device_login(
            "https://app.example.test",
            poster,
            sleeper=lambda _seconds: None,
            clock=time.time,
            timeout=0,
        )
    assert caught.value.code == "timeout"


def test_custom_paths_and_rewritten_link():
    poster, calls = scripted([
        (200, {
            "device_code": "secret",
            "user_code": "ABCD-EFGH",
            "verification_uri_complete": "https://lambda.example/device?user_code=ABCD-EFGH",
            "expires_in": 30,
            "interval": 1,
        }),
        (200, {"access_token": "a"}),
    ])
    device_login(
        "https://app.example.test",
        poster,
        start_path="/api/agent/device/start",
        token_path="/api/agent/device/token",
        present_uri=lambda uri: uri.replace("https://lambda.example", "https://app.example.test"),
        prompt=lambda _text: None,
        sleeper=lambda _seconds: None,
        clock=lambda: 0,
    )
    assert calls[0]["url"].endswith("/api/agent/device/start")
    assert calls[1]["url"].endswith("/api/agent/device/token")
