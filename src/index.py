"""Cognito trigger that restricts Google federation to the DTC Workspace domain."""

import os

ALLOWED_DOMAIN = os.environ.get("ALLOWED_GOOGLE_DOMAIN", "datatalks.club").lower().lstrip("@")


def _verified(value):
    return value is True or str(value).strip().lower() == "true"


def handler(event, _context):
    trigger = event.get("triggerSource")
    federated_signup = trigger == "PreSignUp_ExternalProvider"
    federated_login = trigger == "PreAuthentication_Authentication" and str(
        event.get("userName", "")
    ).lower().startswith("google_")
    if not federated_signup and not federated_login:
        return event

    attributes = event.get("request", {}).get("userAttributes", {})
    email = str(attributes.get("email", "")).strip().lower()
    expected_suffix = "@" + ALLOWED_DOMAIN
    if (
        not email.endswith(expected_suffix)
        or email == expected_suffix
        or not _verified(attributes.get("email_verified"))
    ):
        raise ValueError(
            "Sign-in is restricted to a verified account in the approved Workspace domain"
        )

    if federated_signup:
        event.setdefault("response", {})["autoConfirmUser"] = True
        event["response"]["autoVerifyEmail"] = True
    return event
