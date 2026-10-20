"""The live verifier must exercise first signup and refuse other AWS accounts."""

import runpy
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "verify_deployment.py"


def load_verifier(monkeypatch, client):
    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(client=client))
    return runpy.run_path(str(SCRIPT))


def test_guard_event_preserves_trigger_and_missing_verification(monkeypatch):
    verifier = load_verifier(monkeypatch, lambda *_args: None)
    event = verifier["guard_event"](
        "verifier@datatalks.club", None, "PreSignUp_ExternalProvider"
    )
    assert event["triggerSource"] == "PreSignUp_ExternalProvider"
    assert event["request"]["userAttributes"] == {"email": "verifier@datatalks.club"}


def test_live_verifier_refuses_non_sandbox_before_resource_access(monkeypatch):
    calls = []

    def client(service):
        calls.append(service)
        return SimpleNamespace(get_caller_identity=lambda: {"Account": "000000000000"})

    verifier = load_verifier(monkeypatch, client)
    with pytest.raises(AssertionError):
        verifier["verify_live"]()
    assert calls == ["sts"]
