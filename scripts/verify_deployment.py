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


def guard_event(email):
    return {
        "triggerSource": "PreAuthentication_Authentication",
        "userName": "Google_verifier",
        "request": {"userAttributes": {"email": email, "email_verified": "true"}},
        "response": {},
    }


def verify_live():
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
        assert set(deployed["SupportedIdentityProviders"]) == {"COGNITO", "Google"}
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

    resource = cloudformation.describe_stack_resource(
        StackName="dtcdev-shared-auth", LogicalResourceId="DomainGuardFunction"
    )["StackResourceDetail"]
    function_name = resource["PhysicalResourceId"]
    error, _ = invoke(lambda_client, function_name, guard_event("verifier@datatalks.club"))
    assert error is None
    error, body = invoke(lambda_client, function_name, guard_event("verifier@example.com"))
    assert error == "Unhandled" and "Workspace domain" in body["errorMessage"]

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
