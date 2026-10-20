#!/usr/bin/env python3
"""Verify the deployed shared-auth contract without real user credentials."""

import argparse
import base64
import hashlib
import io
import json
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import boto3

ROOT = Path(__file__).parents[1]
CONFIG = json.loads((ROOT / "config" / "clients.json").read_text())


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def invoke(lambda_client, function_name, payload):
    response = lambda_client.invoke(
        FunctionName=function_name, Payload=json.dumps(payload).encode()
    )
    body = json.load(io.BytesIO(response["Payload"].read()))
    return response.get("FunctionError"), body


def guard_event(email, email_verified="true", trigger="PreAuthentication_Authentication"):
    attributes = {"email": email}
    if email_verified is not None:
        attributes["email_verified"] = email_verified
    return {
        "triggerSource": trigger,
        "userName": "Google_verifier",
        "request": {"userAttributes": attributes},
        "response": {},
    }


def verify_live():
    # Fail closed before inspecting or mutating any resource outside the sandbox.
    assert boto3.client("sts").get_caller_identity()["Account"] == "817685572750"
    region = CONFIG["region"]
    pool = CONFIG["user_pool_id"]
    cognito = boto3.client("cognito-idp", region_name=region)
    cloudformation = boto3.client("cloudformation", region_name=region)
    lambda_client = boto3.client("lambda", region_name=region)
    opener = urllib.request.build_opener(NoRedirect)

    for client in CONFIG["clients"]:
        deployed = cognito.describe_user_pool_client(
            UserPoolId=pool, ClientId=client["client_id"]
        )["UserPoolClient"]
        assert set(deployed["SupportedIdentityProviders"]) == {"Google"}
        assert client["callback_url"] in deployed["CallbackURLs"]
        assert client["logout_url"] in deployed["LogoutURLs"]

        verifier = secrets.token_urlsafe(48)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        query = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": client["client_id"],
                "redirect_uri": client["callback_url"],
                "scope": "openid email profile",
                "state": secrets.token_urlsafe(24),
                "nonce": secrets.token_urlsafe(24),
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "identity_provider": "Google",
            }
        )
        try:
            response = opener.open(
                f"{CONFIG['auth_base_url']}/oauth2/authorize?{query}", timeout=15
            )
        except urllib.error.HTTPError as error:
            response = error
        assert response.status in {302, 303}
        assert urllib.parse.urlsplit(response.headers["Location"]).hostname == "accounts.google.com"
        print(f"{client['name']}: client and Google redirect OK")

    # The guard reads these claims from the trigger event, so Cognito must map
    # them off the Google identity. An unmapped claim arrives as absent and the
    # guard rejects every Google sign-in, including allowed ones.
    mapping = cognito.describe_identity_provider(UserPoolId=pool, ProviderName="Google")[
        "IdentityProvider"
    ]["AttributeMapping"]
    for claim in ("email", "email_verified"):
        assert mapping.get(claim) == claim, f"Google provider does not map {claim}"
    print("Google attribute mapping OK")

    resource = cloudformation.describe_stack_resource(
        StackName="dtcdev-shared-auth", LogicalResourceId="DomainGuardFunction"
    )["StackResourceDetail"]
    function_name = resource["PhysicalResourceId"]
    for trigger in ("PreSignUp_ExternalProvider", "PreAuthentication_Authentication"):
        error, body = invoke(
            lambda_client, function_name, guard_event("verifier@datatalks.club", trigger=trigger)
        )
        assert error is None, f"{trigger}: verified Workspace account rejected"
        if trigger == "PreSignUp_ExternalProvider":
            assert body["response"] == {"autoConfirmUser": True, "autoVerifyEmail": True}
        for email, verified in (
            ("verifier@example.com", "true"),
            ("verifier@datatalks.club", None),
            ("verifier@datatalks.club", "false"),
        ):
            error, body = invoke(
                lambda_client, function_name, guard_event(email, verified, trigger)
            )
            assert error == "Unhandled" and "Workspace domain" in body["errorMessage"]
        print(f"{trigger}: Workspace allowed; other domain/missing/false verification denied")

    users = cognito.list_users(UserPoolId=pool)["Users"]
    assert not [user for user in users if "codex-" in user["Username"]]
    print("domain allow/deny and temporary-user cleanup OK")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true", required=True)
    parser.parse_args()
    try:
        verify_live()
    except Exception as error:
        print(f"verification failed: {error}", file=sys.stderr)
        raise


if __name__ == "__main__":
    main()
