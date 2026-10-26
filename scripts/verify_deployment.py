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
        deployed = cognito.describe_user_pool_client(UserPoolId=pool, ClientId=client["client_id"])[
            "UserPoolClient"
        ]
        assert set(deployed["SupportedIdentityProviders"]) == {"Google"}
        callbacks = client.get("callback_urls", [client.get("callback_url")])
        logouts = client.get("logout_urls", [client.get("logout_url")])
        assert len(callbacks) == len(logouts)
        for callback_url in callbacks:
            assert callback_url in deployed["CallbackURLs"]
        for logout_url in logouts:
            assert logout_url in deployed["LogoutURLs"]

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
                "redirect_uri": callbacks[0],
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

    stack_resources = {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cloudformation.describe_stack_resources(StackName="dtcdev-shared-auth")[
            "StackResources"
        ]
    }
    assert "McpOAuthFunction" in stack_resources, "McpOAuthFunction missing in dtcdev-shared-auth"
    verify_oauth_issuer_live(region, opener)


def verify_oauth_issuer_live(region, opener):
    from src.oauth_server import sha256_hex, verify_access_token

    issuer = CONFIG.get("oauth_issuer_url", "https://oauth.dtcdev.click").rstrip("/")
    for wk in ("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"):
        with urllib.request.urlopen(f"{issuer}{wk}", timeout=15) as resp:
            assert resp.status == 200
            doc = json.loads(resp.read().decode("utf-8"))
        assert doc["issuer"] == issuer
        assert doc["code_challenge_methods_supported"] == ["S256"]
        assert doc["authorization_response_iss_parameter_supported"] is True
        assert doc["client_id_metadata_document_supported"] is True

    with urllib.request.urlopen(f"{issuer}/.well-known/jwks.json", timeout=15) as resp:
        assert resp.status == 200
        jwks = json.loads(resp.read().decode("utf-8"))
    assert len(jwks.get("keys") or []) >= 1
    assert jwks["keys"][0]["alg"] == "RS256"
    print("OAuth 2.1 discovery and JWKS OK")

    # Cursor-style multi-URI DCR
    dcr_req = urllib.request.Request(
        f"{issuer}/oauth/register",
        data=json.dumps(
            {
                "client_name": "verify-deployment-cursor",
                "redirect_uris": [
                    "cursor://anysphere.cursor-mcp/oauth/callback",
                    "http://localhost:54321/callback",
                ],
            }
        ).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(dcr_req, timeout=15) as resp:
        assert resp.status == 201
        dcr_doc = json.loads(resp.read().decode("utf-8"))
    dcr_client_id = dcr_doc["client_id"]

    # Authorize redirect chain -> Cognito -> Google
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    auth_qs = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": dcr_client_id,
            "redirect_uri": "cursor://anysphere.cursor-mcp/oauth/callback",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "verify-state",
        }
    )
    try:
        r1 = opener.open(f"{issuer}/oauth/authorize?{auth_qs}", timeout=15)
    except urllib.error.HTTPError as err:
        r1 = err
    assert r1.status in {302, 303}
    cog_url = r1.headers["Location"]
    assert urllib.parse.urlsplit(cog_url).hostname == "auth.dtcdev.click"
    try:
        r2 = opener.open(cog_url, timeout=15)
    except urllib.error.HTTPError as err:
        r2 = err
    assert r2.status in {302, 303}
    assert urllib.parse.urlsplit(r2.headers["Location"]).hostname == "accounts.google.com"

    # Device code start
    dev_req = urllib.request.Request(
        f"{issuer}/oauth/device",
        data=json.dumps({"client_id": "dtc-cli", "resource": "https://hub.dtcdev.click"}).encode(
            "utf-8"
        ),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(dev_req, timeout=15) as resp:
        assert resp.status == 200
        dev_doc = json.loads(resp.read().decode("utf-8"))
    assert dev_doc.get("device_code") and dev_doc.get("user_code")

    # Service token via client_credentials (secret read from Secrets Manager, never printed)
    sm = boto3.client("secretsmanager", region_name=region)
    svc_map = json.loads(
        sm.get_secret_value(SecretId="dtcdev-shared-auth/service-clients")["SecretString"]
    )
    test_svc = svc_map["mcp-auth-test-service"]
    tok_req = urllib.request.Request(
        f"{issuer}/oauth/token",
        data=urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": "mcp-auth-test-service",
                "client_secret": test_svc["client_secret"],
            }
        ).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(tok_req, timeout=15) as resp:
        assert resp.status == 200
        tok_doc = json.loads(resp.read().decode("utf-8"))
    claims = verify_access_token(
        tok_doc["access_token"],
        expected_issuer=issuer,
        expected_audience="https://hub.dtcdev.click/mcp",
        jwks=jwks,
    )
    assert claims["client_id"] == "mcp-auth-test-service"
    assert claims["scope"] == "mcp:ping"

    # Cleanup ephemeral test artifacts from DynamoDB
    table = boto3.resource("dynamodb", region_name=region).Table("dtcdev-shared-auth-oauth")
    table.delete_item(Key={"pk": f"CLIENT#{dcr_client_id}"})
    table.delete_item(Key={"pk": f"DEVICE#{sha256_hex(dev_doc['device_code'])}"})
    table.delete_item(Key={"pk": f"USERCODE#{dev_doc['user_code']}"})
    print("OAuth 2.1 DCR, authorize redirect, device flow, and client_credentials OK")


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
