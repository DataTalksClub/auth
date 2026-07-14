import json
from pathlib import Path
from urllib.parse import urlsplit

CONFIG = json.loads((Path(__file__).parents[1] / "config" / "clients.json").read_text())


def test_client_registry_is_complete_and_unique():
    clients = CONFIG["clients"]
    assert {client["name"] for client in clients} == {
        "dapier",
        "dataops",
        "studio",
        "datamailer",
        "gym",
    }
    assert len({client["client_id"] for client in clients}) == len(clients)
    assert len({client["callback_url"] for client in clients}) == len(clients)


def test_client_urls_are_https_and_callbacks_are_clean():
    for client in CONFIG["clients"]:
        callback = urlsplit(client["callback_url"])
        logout = urlsplit(client["logout_url"])
        assert callback.scheme == logout.scheme == "https"
        assert callback.path == "/auth/callback"
        assert not callback.query and not callback.fragment
        assert logout.hostname == callback.hostname

