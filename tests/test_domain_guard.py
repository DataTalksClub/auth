import copy
import importlib.util
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).parents[1] / "src" / "index.py"
SPEC = importlib.util.spec_from_file_location("domain_guard", MODULE_PATH)
domain_guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(domain_guard)


def event(trigger, email, *, verified="true", username="Google_subject"):
    return {
        "triggerSource": trigger,
        "userName": username,
        "request": {"userAttributes": {"email": email, "email_verified": verified}},
        "response": {},
    }


@pytest.mark.parametrize("email", ["person@datatalks.club", "PERSON@DATATALKS.CLUB"])
def test_external_google_signup_accepts_verified_workspace_email(email):
    result = domain_guard.handler(event("PreSignUp_ExternalProvider", email), None)
    assert result["response"] == {"autoConfirmUser": True, "autoVerifyEmail": True}


@pytest.mark.parametrize(
    ("email", "verified"),
    [
        ("person@example.com", "true"),
        ("person@notdatatalks.club", "true"),
        ("@datatalks.club", "true"),
        ("person@datatalks.club", "false"),
        ("", "true"),
    ],
)
def test_external_google_signup_rejects_unapproved_or_unverified_email(email, verified):
    with pytest.raises(ValueError, match="approved Workspace domain"):
        domain_guard.handler(event("PreSignUp_ExternalProvider", email, verified=verified), None)


def test_google_pre_authentication_rechecks_domain():
    allowed = event("PreAuthentication_Authentication", "person@datatalks.club")
    assert domain_guard.handler(allowed, None) is allowed
    with pytest.raises(ValueError):
        domain_guard.handler(event("PreAuthentication_Authentication", "person@example.com"), None)


def test_non_google_and_admin_password_triggers_pass_through():
    for value in (
        event("PreSignUp_AdminCreateUser", "person@example.com", username="person@example.com"),
        event(
            "PreAuthentication_Authentication",
            "person@example.com",
            username="person@example.com",
        ),
        {"triggerSource": "PostConfirmation_ConfirmSignUp", "request": {}, "response": {}},
    ):
        original = copy.deepcopy(value)
        assert domain_guard.handler(value, None) == original
