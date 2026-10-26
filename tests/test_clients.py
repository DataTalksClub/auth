import json
from pathlib import Path
from urllib.parse import urlsplit

CONFIG = json.loads((Path(__file__).parents[1] / "config" / "clients.json").read_text())


def _callback_urls(client):
    if "callback_urls" in client:
        return list(client["callback_urls"])
    return [client["callback_url"]]


def _logout_urls(client):
    if "logout_urls" in client:
        return list(client["logout_urls"])
    return [client["logout_url"]]


def test_client_registry_is_complete_and_unique():
    clients = CONFIG["clients"]
    assert {client["name"] for client in clients} == {
        "dapier",
        "dataops",
        "studio",
        "relay",
        "gym",
        "dapier-cli",
        "agent-hub",
    }
    assert len({client["client_id"] for client in clients}) == len(clients)
    seen = []
    for client in clients:
        seen.extend(_callback_urls(client))
    assert len(set(seen)) == len(seen)


def _check_pair(callback_url, logout_url):
    callback = urlsplit(callback_url)
    logout = urlsplit(logout_url)
    assert not callback.query and not callback.fragment
    assert not logout.query and not logout.fragment
    if callback.hostname == "localhost":
        # Native/loopback client: Cognito permits cleartext loopback
        # redirects only as http://localhost on an explicit fixed port.
        assert callback.scheme == logout.scheme == "http"
        assert callback.port and logout.port == callback.port
        assert logout.hostname == "localhost"
        assert callback.path in ("/callback", "/auth/callback")
    else:
        assert callback.scheme == logout.scheme == "https"
        assert logout.hostname == callback.hostname
    return callback


def test_client_urls_are_https_and_callbacks_are_clean():
    for client in CONFIG["clients"]:
        callbacks = _callback_urls(client)
        logouts = _logout_urls(client)
        assert len(callbacks) == len(logouts)
        for callback_url, logout_url in zip(callbacks, logouts, strict=True):
            callback = _check_pair(callback_url, logout_url)
            if callback.hostname != "localhost":
                assert callback.path == "/auth/callback"
