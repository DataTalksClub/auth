"""Automated conformance tests for the DTC shared MCP OAuth 2.1 + DCR issuer (AC 2-9)."""

from __future__ import annotations

import base64
import json
import urllib.parse

import pytest

from dtc_device_login import device_login
from scripts.provision_service_clients import SERVICE_CLIENT_CATALOG, build_updated_service_clients
from src.oauth_server import (
    CANONICAL_RESOURCES,
    CONSENT_CSP,
    DEFAULT_HUMAN_SCOPE,
    DEVICE_GRANT_TYPE,
    RESOURCE_DATAOPS_API,
    RESOURCE_DATAOPS_MCP_CUSTOM,
    RESOURCE_DATAOPS_MCP_LAMBDA,
    RESOURCE_DATAOPS_MCP_PORTAL,
    RESOURCE_HUB_API,
    RESOURCE_HUB_MCP,
    SESSION_COOKIE_NAME,
    InMemoryOAuthStore,
    LocalRs256Signer,
    OAuthServer,
    b64url_decode,
    b64url_encode,
    is_valid_redirect_uri,
    normalize_resource,
    parse_spki_rsa_public_key,
    pkce_s256_challenge,
    sha256_hex,
    verify_access_token,
)

# Deterministic 2048-bit RSA test key (two 1024-bit primes p, q with e = 65537)
_TEST_P = (3 << 1022) + 1037
_TEST_Q = (3 << 1022) + 102799
_TEST_N = _TEST_P * _TEST_Q
_TEST_E = 65537
_TEST_PHI = (_TEST_P - 1) * (_TEST_Q - 1)
_TEST_D = pow(_TEST_E, -1, _TEST_PHI)


class FakeClock:
    def __init__(self, initial: int = 1793000000) -> None:
        self.current = initial

    def __call__(self) -> int:
        return self.current

    def advance(self, seconds: int) -> None:
        self.current += seconds


def _make_event(
    method: str,
    path: str,
    *,
    query: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    body: dict[str, object] | str | None = None,
    content_type: str = "application/json",
    cookies: list[str] | None = None,
) -> dict[str, object]:
    hdrs = dict(headers or {})
    raw_body = ""
    if isinstance(body, dict):
        if "application/x-www-form-urlencoded" in content_type:
            raw_body = urllib.parse.urlencode(body)
        else:
            raw_body = json.dumps(body)
        hdrs.setdefault("content-type", content_type)
    elif isinstance(body, str):
        raw_body = body
        hdrs.setdefault("content-type", content_type)

    return {
        "requestContext": {"http": {"method": method, "path": path}},
        "rawPath": path,
        "rawQueryString": urllib.parse.urlencode(query or {}),
        "headers": hdrs,
        "cookies": cookies or [],
        "body": raw_body,
    }


@pytest.fixture
def env_setup():
    clock = FakeClock()
    store = InMemoryOAuthStore()
    signer = LocalRs256Signer(_TEST_N, _TEST_E, _TEST_D, kid="test-kid-2026")
    cognito_identity = {
        "sub": "google-uid-alexey",
        "email": "alexey@datatalks.club",
        "email_verified": True,
    }

    def fake_cognito_exchange(code: str, _verifier: str, _nonce: str) -> dict[str, object]:
        if code == "bad-cognito-code":
            raise ValueError("Invalid Cognito authorization code")
        return dict(cognito_identity)

    cimd_docs = {
        "https://claude.ai/oauth/client-metadata.json": {
            "client_id": "https://claude.ai/oauth/client-metadata.json",
            "client_name": "Claude Desktop CIMD",
            "redirect_uris": [
                "claude://oauth/callback",
                "http://127.0.0.1:43123/oauth/callback",
            ],
        }
    }

    service_clients = {
        "mcp-auth-test-service": {
            "client_id": "mcp-auth-test-service",
            "secret_sha256": sha256_hex("dtcsvc_test_secret_123"),
            "audience": RESOURCE_HUB_MCP,
            "allowed_scopes": ["mcp:ping"],
            "ttl_seconds": 900,
            "registration_source": "admin_service",
        },
        "dataops-invoice-reader": {
            "client_id": "dataops-invoice-reader",
            "secret_sha256": sha256_hex("dtcsvc_invoice_secret_456"),
            "audience": RESOURCE_DATAOPS_API,
            "allowed_scopes": ["invoice:read"],
            "ttl_seconds": 900,
            "registration_source": "admin_service",
        },
        "hub-fleet-host": {
            "client_id": "hub-fleet-host",
            "secret_sha256": sha256_hex("dtcsvc_fleet_secret_789"),
            "audience": RESOURCE_HUB_API,
            "allowed_scopes": ["hub:host"],
            "ttl_seconds": 900,
            "registration_source": "admin_service",
        },
    }

    server = OAuthServer(
        issuer_url="https://oauth.dtcdev.click",
        cognito_base_url="https://auth.dtcdev.click",
        cognito_issuer_url="https://cognito-idp.us-east-1.amazonaws.com/us-east-1_H7nJu52Bs",
        cognito_client_id="cognito-broker-client-id",
        allowed_domain="datatalks.club",
        store=store,
        signer=signer,
        session_secret="unit-test-hmac-secret-key-0123456789abcdef",
        service_clients=service_clients,
        cognito_token_exchanger=fake_cognito_exchange,
        cimd_fetcher=lambda url: cimd_docs[url],
        clock=clock,
    )
    return {
        "server": server,
        "clock": clock,
        "store": store,
        "signer": signer,
        "cognito_identity": cognito_identity,
    }


def _complete_login_and_consent(
    server: OAuthServer,
    authorize_query: dict[str, str],
    *,
    decision: str = "approve",
) -> dict[str, object]:
    """Run GET /oauth/authorize -> Cognito -> /auth/callback -> consent GET/POST."""
    # 1. Initial unauthenticated GET /oauth/authorize redirects to Cognito
    r1 = server.dispatch(_make_event("GET", "/oauth/authorize", query=authorize_query))
    assert r1["statusCode"] == 302
    cognito_loc = urllib.parse.urlsplit(r1["headers"]["location"])
    assert cognito_loc.hostname == "auth.dtcdev.click"
    assert cognito_loc.path == "/oauth2/authorize"
    cognito_qs = dict(urllib.parse.parse_qsl(cognito_loc.query))
    assert cognito_qs["identity_provider"] == "Google"
    assert cognito_qs["code_challenge_method"] == "S256"

    # 2. Cognito redirects back to /auth/callback
    r2 = server.dispatch(
        _make_event(
            "GET",
            "/auth/callback",
            query={"code": "valid-cognito-code", "state": cognito_qs["state"]},
        )
    )
    assert r2["statusCode"] == 303
    cookie_header = r2["headers"]["set-cookie"]
    cookie_pair = cookie_header.split(";", 1)[0]
    assert cookie_pair.startswith(f"{SESSION_COOKIE_NAME}=")

    # 3. Authenticated GET /oauth/authorize renders consent screen with cursor://-safe CSP
    r3 = server.dispatch(
        _make_event("GET", "/oauth/authorize", query=authorize_query, cookies=[cookie_pair])
    )
    assert r3["statusCode"] == 200
    assert r3["headers"]["content-security-policy"] == CONSENT_CSP
    assert "cursor:" in r3["headers"]["content-security-policy"]
    assert "claude:" in r3["headers"]["content-security-policy"]
    assert "vscode:" in r3["headers"]["content-security-policy"]

    # Extract CSRF token from form
    body_html = r3["body"]
    marker = 'name="csrf_token" value="'
    idx = body_html.index(marker) + len(marker)
    csrf_token = body_html[idx : body_html.index('"', idx)]

    # 4. POST /oauth/authorize with decision
    form_data = dict(authorize_query)
    form_data["csrf_token"] = csrf_token
    form_data["decision"] = decision
    return server.dispatch(
        _make_event(
            "POST",
            "/oauth/authorize",
            body=form_data,
            content_type="application/x-www-form-urlencoded",
            cookies=[cookie_pair],
        )
    )


# --- AC 2: Discovery & JWKS ---


def test_discovery_endpoints_and_jwks(env_setup):
    server = env_setup["server"]
    for path in (
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-authorization-server/mcp",
        "/.well-known/openid-configuration",
        "/.well-known/openid-configuration/mcp",
    ):
        resp = server.dispatch(_make_event("GET", path))
        assert resp["statusCode"] == 200
        doc = json.loads(resp["body"])
        assert doc["issuer"] == "https://oauth.dtcdev.click"
        assert doc["code_challenge_methods_supported"] == ["S256"]
        assert set(doc["grant_types_supported"]) >= {
            "authorization_code",
            "refresh_token",
            "client_credentials",
            DEVICE_GRANT_TYPE,
        }
        assert doc["token_endpoint_auth_methods_supported"] == [
            "none",
            "client_secret_post",
            "client_secret_basic",
        ]
        assert doc["authorization_response_iss_parameter_supported"] is True
        assert doc["client_id_metadata_document_supported"] is True
        assert doc["registration_endpoint"] == "https://oauth.dtcdev.click/oauth/register"
        assert doc["device_authorization_endpoint"] == "https://oauth.dtcdev.click/oauth/device"
        assert doc["revocation_endpoint"] == "https://oauth.dtcdev.click/oauth/revoke"
        assert doc["jwks_uri"] == "https://oauth.dtcdev.click/.well-known/jwks.json"

    jwks_resp = server.dispatch(_make_event("GET", "/.well-known/jwks.json"))
    assert jwks_resp["statusCode"] == 200
    jwks = json.loads(jwks_resp["body"])
    assert len(jwks["keys"]) == 1
    assert jwks["keys"][0]["alg"] == "RS256"
    assert jwks["keys"][0]["kty"] == "RSA"


# --- AC 3 & AC 9: Conformance per Client Family ---


def test_conformance_chatgpt_dcr_and_pre_registered_and_iss(env_setup):
    """ChatGPT custom connectors: DCR + RFC 9207 iss + pre-registered public client fallback."""
    server = env_setup["server"]

    # 1. Dynamic Client Registration with ChatGPT static & dynamic callbacks
    reg = server.dispatch(
        _make_event(
            "POST",
            "/oauth/register",
            body={
                "client_name": "ChatGPT Connector",
                "redirect_uris": [
                    "https://chatgpt.com/connector_platform_oauth_redirect",
                    "https://chatgpt.com/connector/oauth/cb_abc123",
                ],
            },
        )
    )
    assert reg["statusCode"] == 201
    client_id = json.loads(reg["body"])["client_id"]

    verifier = "chatgpt-pkce-verifier-0123456789abcdef0123456789abcdef"
    challenge = pkce_s256_challenge(verifier)
    consent = _complete_login_and_consent(
        server,
        {
            "client_id": client_id,
            "redirect_uri": "https://chatgpt.com/connector_platform_oauth_redirect",
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": RESOURCE_HUB_MCP,
            "state": "chatgpt-state-1",
        },
    )
    assert consent["statusCode"] == 303
    redir = urllib.parse.urlsplit(consent["headers"]["location"])
    qs = dict(urllib.parse.parse_qsl(redir.query))
    assert qs["state"] == "chatgpt-state-1"
    assert qs["iss"] == "https://oauth.dtcdev.click"
    assert qs["code"].startswith("mcpcode_")

    tok_resp = server.dispatch(
        _make_event(
            "POST",
            "/oauth/token",
            body={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": qs["code"],
                "redirect_uri": "https://chatgpt.com/connector_platform_oauth_redirect",
                "code_verifier": verifier,
                "resource": RESOURCE_HUB_MCP,
            },
            content_type="application/x-www-form-urlencoded",
        )
    )
    assert tok_resp["statusCode"] == 200
    tok = json.loads(tok_resp["body"])
    assert tok["expires_in"] == 3600
    claims = verify_access_token(
        tok["access_token"],
        expected_issuer="https://oauth.dtcdev.click",
        expected_audience=RESOURCE_HUB_MCP,
        jwks=server.jwks_document(),
        now=env_setup["clock"](),
    )
    assert claims["email"] == "alexey@datatalks.club"
    assert claims["email_verified"] is True
    assert claims["aud"] == RESOURCE_HUB_MCP
    assert claims["client_id"] == client_id

    # 2. Manual UI entry using pre-registered public client id (dtc-mcp-public)
    consent_pub = _complete_login_and_consent(
        server,
        {
            "client_id": "dtc-mcp-public",
            "redirect_uri": "https://chatgpt.com/connector/oauth/custom_999",
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "pub-state",
        },
    )
    assert consent_pub["statusCode"] == 303


def test_conformance_claude_ai_scope_and_no_90d_expiry(env_setup):
    """claude.ai connectors: claudeai scope, resource default, >90-day client persistence."""
    server = env_setup["server"]
    clock = env_setup["clock"]

    reg = server.dispatch(
        _make_event(
            "POST",
            "/oauth/register",
            body={
                "client_name": "Claude Web Connector",
                "redirect_uris": [
                    "https://claude.ai/api/mcp/auth_callback",
                    "https://claude.com/api/mcp/auth_callback",
                ],
                "scope": "claudeai openid",
            },
        )
    )
    assert reg["statusCode"] == 201
    client_id = json.loads(reg["body"])["client_id"]
    assert "ttl" not in env_setup["store"].get(f"CLIENT#{client_id}")

    # Advance clock by 180 days (>90 days) — client must still work!
    clock.advance(180 * 86400)

    verifier = "claude-ai-pkce-verifier-0123456789abcdef0123456789abcdef"
    consent = _complete_login_and_consent(
        server,
        {
            "client_id": client_id,
            "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
            "response_type": "code",
            "code_challenge": pkce_s256_challenge(verifier),
            "code_challenge_method": "S256",
            "scope": "claudeai",
            "resource": RESOURCE_DATAOPS_MCP_LAMBDA,
            "state": "claude-state",
        },
    )
    assert consent["statusCode"] == 303
    qs = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(consent["headers"]["location"]).query))

    tok_resp = server.dispatch(
        _make_event(
            "POST",
            "/oauth/token",
            body={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": qs["code"],
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
                "code_verifier": verifier,
            },
        )
    )
    assert tok_resp["statusCode"] == 200
    tok = json.loads(tok_resp["body"])
    claims = verify_access_token(
        tok["access_token"],
        expected_issuer="https://oauth.dtcdev.click",
        expected_audience=RESOURCE_DATAOPS_MCP_LAMBDA,
        jwks=server.jwks_document(),
        now=clock(),
    )
    assert claims["aud"] == RESOURCE_DATAOPS_MCP_LAMBDA
    assert "claudeai" in claims["scope"].split()
    assert "admin" in claims["scope"].split()


def test_conformance_claude_desktop_cimd_and_claude_scheme(env_setup):
    """Claude Desktop: CIMD client_id URL and claude:// scheme redirect."""
    server = env_setup["server"]
    verifier = "claude-desktop-verifier-0123456789abcdef0123456789abcdef"
    cimd_client_id = "https://claude.ai/oauth/client-metadata.json"

    consent = _complete_login_and_consent(
        server,
        {
            "client_id": cimd_client_id,
            "redirect_uri": "claude://oauth/callback",
            "response_type": "code",
            "code_challenge": pkce_s256_challenge(verifier),
            "code_challenge_method": "S256",
            "state": "cimd-state",
        },
    )
    assert consent["statusCode"] == 303
    assert consent["headers"]["location"].startswith("claude://oauth/callback?")
    qs = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(consent["headers"]["location"]).query))
    assert qs["iss"] == "https://oauth.dtcdev.click"


def test_conformance_cursor_multi_uri_dcr_and_scheme_safety(env_setup):
    """Cursor: multi-URI DCR with cursor:// + localhost, vscode:// allowed, bad schemes rejected."""
    server = env_setup["server"]

    # Cursor sends cursor:// alongside localhost in a single redirect_uris array
    reg = server.dispatch(
        _make_event(
            "POST",
            "/oauth/register",
            body={
                "client_name": "Cursor MCP",
                "redirect_uris": [
                    "cursor://anysphere.cursor-mcp/oauth/callback",
                    "http://localhost:51234/callback",
                    "http://127.0.0.1:51234/callback",
                    "vscode://vscode.mcp/callback",
                ],
            },
        )
    )
    assert reg["statusCode"] == 201
    client_id = json.loads(reg["body"])["client_id"]

    verifier = "cursor-pkce-verifier-0123456789abcdef0123456789abcdef"
    consent = _complete_login_and_consent(
        server,
        {
            "client_id": client_id,
            "redirect_uri": "cursor://anysphere.cursor-mcp/oauth/callback",
            "response_type": "code",
            "code_challenge": pkce_s256_challenge(verifier),
            "code_challenge_method": "S256",
            "state": "cursor-state",
        },
    )
    assert consent["statusCode"] == 303
    assert consent["headers"]["location"].startswith(
        "cursor://anysphere.cursor-mcp/oauth/callback?"
    )
    assert "cursor:" in consent["headers"]["content-security-policy"]

    # Dangerous schemes rejected in DCR
    for bad_uri in (
        "javascript:alert(1)",
        "data:text/html,hi",
        "file:///etc/passwd",
        "http://evil.example.com/callback",
        "https://example.com/callback#frag",
    ):
        assert not is_valid_redirect_uri(bad_uri)
        bad_reg = server.dispatch(
            _make_event(
                "POST",
                "/oauth/register",
                body={"redirect_uris": ["cursor://anysphere.cursor-mcp/oauth/callback", bad_uri]},
            )
        )
        assert bad_reg["statusCode"] == 400


def test_conformance_claude_code_refresh_rotation_replay_and_revoke(env_setup):
    """Claude Code: localhost DCR, refresh rotation, replay revocation, /oauth/revoke."""
    server = env_setup["server"]
    clock = env_setup["clock"]

    reg = server.dispatch(
        _make_event(
            "POST",
            "/oauth/register",
            body={
                "client_name": "Claude Code CLI",
                "redirect_uris": ["http://localhost:45678/callback"],
            },
        )
    )
    assert reg["statusCode"] == 201
    client_id = json.loads(reg["body"])["client_id"]

    verifier = "claude-code-verifier-0123456789abcdef0123456789abcdef"
    consent = _complete_login_and_consent(
        server,
        {
            "client_id": client_id,
            "redirect_uri": "http://localhost:59999/callback",  # ephemeral loopback port match
            "response_type": "code",
            "code_challenge": pkce_s256_challenge(verifier),
            "code_challenge_method": "S256",
            "state": "cc-state",
        },
    )
    assert consent["statusCode"] == 303
    code = dict(
        urllib.parse.parse_qsl(urllib.parse.urlsplit(consent["headers"]["location"]).query)
    )["code"]

    tok1_resp = server.dispatch(
        _make_event(
            "POST",
            "/oauth/token",
            body={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": code,
                "redirect_uri": "http://localhost:59999/callback",
                "code_verifier": verifier,
            },
        )
    )
    assert tok1_resp["statusCode"] == 200
    tok1 = json.loads(tok1_resp["body"])
    r1 = tok1["refresh_token"]

    # Rotate refresh token once -> succeeds and issues r2
    tok2_resp = server.dispatch(
        _make_event(
            "POST",
            "/oauth/token",
            body={"grant_type": "refresh_token", "client_id": client_id, "refresh_token": r1},
        )
    )
    assert tok2_resp["statusCode"] == 200
    tok2 = json.loads(tok2_resp["body"])
    r2 = tok2["refresh_token"]
    assert r2 != r1

    # Replay consumed r1 -> fails AND revokes family so r2 is now also invalid!
    replay_resp = server.dispatch(
        _make_event(
            "POST",
            "/oauth/token",
            body={"grant_type": "refresh_token", "client_id": client_id, "refresh_token": r1},
        )
    )
    assert replay_resp["statusCode"] == 400
    after_replay = server.dispatch(
        _make_event(
            "POST",
            "/oauth/token",
            body={"grant_type": "refresh_token", "client_id": client_id, "refresh_token": r2},
        )
    )
    assert after_replay["statusCode"] == 400

    # Revoke access token via POST /oauth/revoke
    rev_resp = server.dispatch(
        _make_event("POST", "/oauth/revoke", body={"token": tok2["access_token"]})
    )
    assert rev_resp["statusCode"] == 200
    with pytest.raises(ValueError, match="token_revoked"):
        verify_access_token(
            tok2["access_token"],
            expected_issuer="https://oauth.dtcdev.click",
            expected_audience=RESOURCE_HUB_MCP,
            jwks=server.jwks_document(),
            now=clock(),
            is_revoked_jti=server.is_jti_revoked,
        )


def test_conformance_codex_and_cross_audience_isolation(env_setup):
    """Codex + AC 6: tokens for one audience are strictly rejected by all other audiences."""
    server = env_setup["server"]
    clock = env_setup["clock"]

    reg = server.dispatch(
        _make_event(
            "POST",
            "/oauth/register",
            body={
                "client_name": "Codex CLI",
                "redirect_uris": ["http://127.0.0.1:38123/callback", "http://[::1]:38123/callback"],
            },
        )
    )
    assert reg["statusCode"] == 201
    client_id = json.loads(reg["body"])["client_id"]

    audiences = [
        RESOURCE_HUB_MCP,
        RESOURCE_HUB_API,
        RESOURCE_DATAOPS_MCP_LAMBDA,
        RESOURCE_DATAOPS_MCP_CUSTOM,
        RESOURCE_DATAOPS_MCP_PORTAL,
        RESOURCE_DATAOPS_API,
    ]
    minted_tokens: dict[str, str] = {}

    for aud in audiences:
        verifier = f"codex-verifier-for-{sha256_hex(aud)[:32]}"
        consent = _complete_login_and_consent(
            server,
            {
                "client_id": client_id,
                "redirect_uri": "http://127.0.0.1:38123/callback",
                "response_type": "code",
                "code_challenge": pkce_s256_challenge(verifier),
                "code_challenge_method": "S256",
                "resource": aud,
                "state": "codex",
            },
        )
        code = dict(
            urllib.parse.parse_qsl(urllib.parse.urlsplit(consent["headers"]["location"]).query)
        )["code"]
        tok_resp = server.dispatch(
            _make_event(
                "POST",
                "/oauth/token",
                body={
                    "grant_type": "authorization_code",
                    "client_id": client_id,
                    "code": code,
                    "redirect_uri": "http://127.0.0.1:38123/callback",
                    "code_verifier": verifier,
                    "resource": aud,
                },
            )
        )
        assert tok_resp["statusCode"] == 200
        minted_tokens[aud] = json.loads(tok_resp["body"])["access_token"]

    # Every token succeeds ONLY for its own audience and is rejected by every other audience
    for target_aud, token in minted_tokens.items():
        claims = verify_access_token(
            token,
            expected_issuer="https://oauth.dtcdev.click",
            expected_audience=target_aud,
            jwks=server.jwks_document(),
            now=clock(),
        )
        assert claims["aud"] == target_aud
        for other_aud in audiences:
            if other_aud != target_aud:
                with pytest.raises(ValueError, match="audience_mismatch"):
                    verify_access_token(
                        token,
                        expected_issuer="https://oauth.dtcdev.click",
                        expected_audience=other_aud,
                        jwks=server.jwks_document(),
                        now=clock(),
                    )


# --- AC 7 & AC 9: Device Authorization Grant (hub & dataops CLIs) ---


def test_conformance_device_flow_and_dtc_device_login_integration(env_setup):
    """RFC 8628 device flow for hub and dataops CLIs with slow_down, approval, and refresh token."""
    server = env_setup["server"]
    clock = env_setup["clock"]

    # Start device flow for DataOps CLI (RESOURCE_DATAOPS_API)
    start_resp = server.dispatch(
        _make_event(
            "POST",
            "/oauth/device",
            body={"client_id": "dtc-cli", "resource": "https://ops.dtcdev.click/api"},
        )
    )
    assert start_resp["statusCode"] == 200
    start_data = json.loads(start_resp["body"])
    device_code = start_data["device_code"]
    user_code = start_data["user_code"]
    assert start_data["verification_uri"] == "https://oauth.dtcdev.click/device"

    # First poll -> authorization_pending
    p1 = server.dispatch(
        _make_event(
            "POST",
            "/oauth/token",
            body={"grant_type": DEVICE_GRANT_TYPE, "device_code": device_code},
        )
    )
    assert p1["statusCode"] == 400
    assert json.loads(p1["body"])["error"] == "authorization_pending"

    # Immediate second poll without waiting interval -> slow_down
    clock.advance(1)
    p2 = server.dispatch(
        _make_event(
            "POST",
            "/oauth/token",
            body={"grant_type": DEVICE_GRANT_TYPE, "device_code": device_code},
        )
    )
    assert p2["statusCode"] == 400
    assert json.loads(p2["body"])["error"] == "slow_down"

    # Browser login and device approval
    r_login = server.dispatch(_make_event("GET", "/device", query={"code": user_code}))
    assert r_login["statusCode"] == 302
    c_qs = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(r_login["headers"]["location"]).query))
    r_cb = server.dispatch(
        _make_event(
            "GET",
            "/auth/callback",
            query={"code": "valid-cognito-code", "state": c_qs["state"]},
        )
    )
    cookie_pair = r_cb["headers"]["set-cookie"].split(";", 1)[0]
    r_page = server.dispatch(
        _make_event("GET", "/device", query={"code": user_code}, cookies=[cookie_pair])
    )
    assert r_page["statusCode"] == 200
    marker = 'name="csrf_token" value="'
    idx = r_page["body"].index(marker) + len(marker)
    csrf = r_page["body"][idx : r_page["body"].index('"', idx)]

    r_approve = server.dispatch(
        _make_event(
            "POST",
            "/device",
            body={"user_code": user_code, "csrf_token": csrf, "decision": "approve"},
            content_type="application/x-www-form-urlencoded",
            cookies=[cookie_pair],
        )
    )
    assert r_approve["statusCode"] == 200

    # Poll via dtc_device_login helper -> returns token + refresh_token bound to DataOps API
    clock.advance(15)
    p3 = server.dispatch(
        _make_event(
            "POST",
            "/oauth/token",
            body={"grant_type": DEVICE_GRANT_TYPE, "device_code": device_code},
        )
    )
    assert p3["statusCode"] == 200
    tok = json.loads(p3["body"])
    assert tok["refresh_token"].startswith("mcpr_")
    claims = verify_access_token(
        tok["access_token"],
        expected_issuer="https://oauth.dtcdev.click",
        expected_audience=RESOURCE_DATAOPS_API,
        jwks=server.jwks_document(),
        now=clock(),
    )
    assert claims["aud"] == RESOURCE_DATAOPS_API
    assert claims["email"] == "alexey@datatalks.club"

    # Also test end-to-end through dtc_device_login.device_login()
    def poster(url: str, payload: dict[str, object]) -> tuple[int, dict[str, object]]:
        path = urllib.parse.urlsplit(url).path
        resp = server.dispatch(_make_event("POST", path, body=payload))
        data = json.loads(resp["body"])
        if path == "/api/auth/device" and resp["statusCode"] == 200:
            # Auto-approve in background before first poll
            uc = data["user_code"]
            server.dispatch(
                _make_event(
                    "POST",
                    "/device",
                    body={"user_code": uc, "csrf_token": csrf, "decision": "approve"},
                    content_type="application/x-www-form-urlencoded",
                    cookies=[cookie_pair],
                )
            )
        return resp["statusCode"], data

    cli_result = device_login(
        "https://oauth.dtcdev.click",
        poster,
        start_body={"client_id": "dtc-cli", "resource": RESOURCE_HUB_API},
        prompt=lambda _t: None,
        sleeper=lambda s: clock.advance(int(s)),
        clock=clock,
    )
    assert cli_result["access_token"]
    assert cli_result["refresh_token"].startswith("mcpr_")


# --- AC 8 & AC 9: Confidential Service Clients (client_credentials) ---


def test_conformance_client_credentials_service_tokens(env_setup):
    """Service tokens: Basic & Post auth, single bound audience, minimal scope, DCR forbidden."""
    server = env_setup["server"]
    clock = env_setup["clock"]

    # 1. Valid client_secret_basic request for dataops-invoice-reader
    basic_hdr = base64.b64encode(b"dataops-invoice-reader:dtcsvc_invoice_secret_456").decode(
        "ascii"
    )
    resp = server.dispatch(
        _make_event(
            "POST",
            "/oauth/token",
            headers={"authorization": f"Basic {basic_hdr}"},
            body={"grant_type": "client_credentials"},
            content_type="application/x-www-form-urlencoded",
        )
    )
    assert resp["statusCode"] == 200
    tok = json.loads(resp["body"])
    assert tok["expires_in"] == 900
    assert "refresh_token" not in tok
    assert tok["scope"] == "invoice:read"
    claims = verify_access_token(
        tok["access_token"],
        expected_issuer="https://oauth.dtcdev.click",
        expected_audience=RESOURCE_DATAOPS_API,
        jwks=server.jwks_document(),
        now=clock(),
    )
    assert claims["aud"] == RESOURCE_DATAOPS_API
    assert claims["sub"] == "service:dataops-invoice-reader"
    assert claims["client_id"] == "dataops-invoice-reader"
    assert claims["scope"] == "invoice:read"

    # 2. Requesting a different audience is rejected with 400 invalid_target
    bad_aud = server.dispatch(
        _make_event(
            "POST",
            "/oauth/token",
            headers={"authorization": f"Basic {basic_hdr}"},
            body={"grant_type": "client_credentials", "resource": RESOURCE_HUB_API},
        )
    )
    assert bad_aud["statusCode"] == 400
    assert json.loads(bad_aud["body"])["error"] == "invalid_target"

    # 3. Requesting an unapproved scope is rejected with 400 invalid_scope
    bad_scope = server.dispatch(
        _make_event(
            "POST",
            "/oauth/token",
            headers={"authorization": f"Basic {basic_hdr}"},
            body={"grant_type": "client_credentials", "scope": "admin"},
        )
    )
    assert bad_scope["statusCode"] == 400
    assert json.loads(bad_scope["body"])["error"] == "invalid_scope"

    # 4. Wrong secret is rejected with 401 invalid_client
    wrong_secret = server.dispatch(
        _make_event(
            "POST",
            "/oauth/token",
            body={
                "grant_type": "client_credentials",
                "client_id": "dataops-invoice-reader",
                "client_secret": "wrong",
            },
        )
    )
    assert wrong_secret["statusCode"] == 401

    # 5. DCR cannot register a client_credentials-only client or use client_credentials
    dcr_cc = server.dispatch(
        _make_event(
            "POST",
            "/oauth/register",
            body={
                "redirect_uris": ["https://example.com/cb"],
                "grant_types": ["client_credentials"],
            },
        )
    )
    assert dcr_cc["statusCode"] == 400

    dcr_normal = server.dispatch(
        _make_event(
            "POST",
            "/oauth/register",
            body={
                "redirect_uris": ["https://example.com/cb"],
                "token_endpoint_auth_method": "client_secret_post",
            },
        )
    )
    assert dcr_normal["statusCode"] == 201
    dcr_doc = json.loads(dcr_normal["body"])
    dcr_try_cc = server.dispatch(
        _make_event(
            "POST",
            "/oauth/token",
            body={
                "grant_type": "client_credentials",
                "client_id": dcr_doc["client_id"],
                "client_secret": dcr_doc["client_secret"],
            },
        )
    )
    assert dcr_try_cc["statusCode"] == 400
    assert json.loads(dcr_try_cc["body"])["error"] == "unauthorized_client"


# --- AC 4 & AC 10: Non-datatalks.club Denial & PKCE Enforcement ---


def test_non_datatalks_account_denied_and_pkce_enforced(env_setup):
    server = env_setup["server"]
    cognito_identity = env_setup["cognito_identity"]

    # PKCE missing or plain is rejected on /oauth/authorize
    no_pkce = server.dispatch(
        _make_event(
            "GET",
            "/oauth/authorize",
            query={
                "client_id": "dtc-mcp-public",
                "redirect_uri": "http://localhost:8080/cb",
                "response_type": "code",
            },
        )
    )
    assert no_pkce["statusCode"] == 400

    # Non-datatalks.club Google user is denied at /auth/callback with 403
    cognito_identity["email"] = "outsider@gmail.com"
    r1 = server.dispatch(
        _make_event(
            "GET",
            "/oauth/authorize",
            query={
                "client_id": "dtc-mcp-public",
                "redirect_uri": "http://localhost:8080/cb",
                "response_type": "code",
                "code_challenge": pkce_s256_challenge("v" * 43),
                "code_challenge_method": "S256",
            },
        )
    )
    qs = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(r1["headers"]["location"]).query))
    r2 = server.dispatch(
        _make_event(
            "GET", "/auth/callback", query={"code": "valid-cognito-code", "state": qs["state"]}
        )
    )
    assert r2["statusCode"] == 403
    assert json.loads(r2["body"])["error"] == "access_denied"

    # Cognito DomainGuardFunction error redirect to /auth/callback also returns 403
    r3 = server.dispatch(
        _make_event(
            "GET",
            "/auth/callback",
            query={
                "error": "invalid_request",
                "error_description": (
                    "PreSignUp failed: Sign-in is restricted to a verified account "
                    "in the approved Workspace domain"
                ),
            },
        )
    )
    assert r3["statusCode"] == 403


def test_spki_parser_and_service_client_provisioning_helper():
    # Build a synthetic SPKI DER for RSA public key (n=0x010001, e=0x010001) and parse it
    def der_len(n: int) -> bytes:
        if n < 0x80:
            return bytes([n])
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(b)]) + b

    def der_tlv(tag: int, body: bytes) -> bytes:
        return bytes([tag]) + der_len(len(body)) + body

    n_bytes = _TEST_N.to_bytes(256, "big")
    e_bytes = (65537).to_bytes(3, "big")
    rsa_pub = der_tlv(0x30, der_tlv(0x02, b"\x00" + n_bytes) + der_tlv(0x02, e_bytes))
    alg_id = der_tlv(0x30, bytes.fromhex("06092a864886f70d0101010500"))
    spki = der_tlv(0x30, alg_id + der_tlv(0x03, b"\x00" + rsa_pub))

    parsed_n, parsed_e = parse_spki_rsa_public_key(spki)
    assert parsed_n == n_bytes
    assert parsed_e == e_bytes

    # Provisioning helper preserves existing secrets and populates all catalog entries
    first_map, changed1 = build_updated_service_clients({})
    assert changed1 is True
    assert set(first_map.keys()) == set(SERVICE_CLIENT_CATALOG.keys())
    second_map, changed2 = build_updated_service_clients(first_map)
    assert changed2 is False
    for cid in SERVICE_CLIENT_CATALOG:
        assert second_map[cid]["client_secret"] == first_map[cid]["client_secret"]
        assert normalize_resource(second_map[cid]["audience"]) in CANONICAL_RESOURCES
        assert len(b64url_decode("dGVzdA")) == 4


def test_review_findings_hardening_and_edge_cases(env_setup):
    """Cover reviewer findings 1-13 (PKCE plain, defaults, deny, reuse, revoke, device edges)."""
    server = env_setup["server"]
    clock = env_setup["clock"]
    store = env_setup["store"]

    # Finding 1: code_challenge_method=plain is explicitly rejected with 400
    plain_pkce = server.dispatch(
        _make_event(
            "GET",
            "/oauth/authorize",
            query={
                "client_id": "dtc-mcp-public",
                "redirect_uri": "http://localhost:8080/cb",
                "response_type": "code",
                "code_challenge": "plain-challenge-0123456789abcdef0123456789abcdef",
                "code_challenge_method": "plain",
            },
        )
    )
    assert plain_pkce["statusCode"] == 400

    # Finding 2: Missing resource & scope default to RESOURCE_HUB_MCP and DEFAULT_HUMAN_SCOPE
    v_def = "default-resource-scope-verifier-0123456789abcdef0123456789ab"
    c_def = _complete_login_and_consent(
        server,
        {
            "client_id": "dtc-mcp-public",
            "redirect_uri": "http://localhost:8080/cb",
            "response_type": "code",
            "code_challenge": pkce_s256_challenge(v_def),
            "code_challenge_method": "S256",
            "state": "def-state",
        },
    )
    code_def = dict(
        urllib.parse.parse_qsl(urllib.parse.urlsplit(c_def["headers"]["location"]).query)
    )["code"]

    # Finding 9: Omitting redirect_uri on authorization_code exchange fails when set at authorize
    no_redir_tok = server.dispatch(
        _make_event(
            "POST",
            "/oauth/token",
            body={
                "grant_type": "authorization_code",
                "client_id": "dtc-mcp-public",
                "code": code_def,
                "code_verifier": v_def,
            },
        )
    )
    assert no_redir_tok["statusCode"] == 400

    # Finding 4: Auth-code reuse / wrong verifier fails
    c_def2 = _complete_login_and_consent(
        server,
        {
            "client_id": "dtc-mcp-public",
            "redirect_uri": "http://localhost:8080/cb",
            "response_type": "code",
            "code_challenge": pkce_s256_challenge(v_def),
            "code_challenge_method": "S256",
            "state": "def-state-2",
        },
    )
    code_def2 = dict(
        urllib.parse.parse_qsl(urllib.parse.urlsplit(c_def2["headers"]["location"]).query)
    )["code"]
    tok_ok = server.dispatch(
        _make_event(
            "POST",
            "/oauth/token",
            body={
                "grant_type": "authorization_code",
                "client_id": "dtc-mcp-public",
                "code": code_def2,
                "redirect_uri": "http://localhost:8080/cb",
                "code_verifier": v_def,
            },
        )
    )
    assert tok_ok["statusCode"] == 200
    tok_ok_doc = json.loads(tok_ok["body"])
    claims_def = verify_access_token(
        tok_ok_doc["access_token"],
        expected_issuer="https://oauth.dtcdev.click",
        expected_audience=RESOURCE_HUB_MCP,
        jwks=server.jwks_document(),
        now=clock(),
    )
    assert claims_def["aud"] == RESOURCE_HUB_MCP
    assert claims_def["scope"] == DEFAULT_HUMAN_SCOPE

    # Double exchange of consumed code_def2 fails
    tok_reuse = server.dispatch(
        _make_event(
            "POST",
            "/oauth/token",
            body={
                "grant_type": "authorization_code",
                "client_id": "dtc-mcp-public",
                "code": code_def2,
                "redirect_uri": "http://localhost:8080/cb",
                "code_verifier": v_def,
            },
        )
    )
    assert tok_reuse["statusCode"] == 400

    # Finding 3: Deny consent returns error=access_denied, state, and iss; evil redirect rejected
    evil_redir = server.dispatch(
        _make_event(
            "GET",
            "/oauth/authorize",
            query={
                "client_id": "dtc-mcp-public",
                "redirect_uri": "https://evil.example.com/cb",
                "response_type": "code",
                "code_challenge": pkce_s256_challenge(v_def),
                "code_challenge_method": "S256",
            },
        )
    )
    assert evil_redir["statusCode"] == 400

    c_deny = _complete_login_and_consent(
        server,
        {
            "client_id": "dtc-mcp-public",
            "redirect_uri": "http://localhost:8080/cb",
            "response_type": "code",
            "code_challenge": pkce_s256_challenge(v_def),
            "code_challenge_method": "S256",
            "state": "deny-state-1",
        },
        decision="deny",
    )
    assert c_deny["statusCode"] == 303
    deny_qs = dict(
        urllib.parse.parse_qsl(urllib.parse.urlsplit(c_deny["headers"]["location"]).query)
    )
    assert deny_qs["error"] == "access_denied"
    assert deny_qs["state"] == "deny-state-1"
    assert deny_qs["iss"] == "https://oauth.dtcdev.click"

    # Finding 5 & 7: Refresh token revocation & unauthenticated forged JWT revocation blocked
    forged_jwt = (
        b64url_encode(b'{"alg":"RS256","kid":"fake"}')
        + "."
        + b64url_encode(b'{"jti":"forged-jti-1","iss":"https://oauth.dtcdev.click","exp":9999999999}')
        + "."
        + b64url_encode(b"bad-sig")
    )
    server.dispatch(_make_event("POST", "/oauth/revoke", body={"token": forged_jwt}))
    assert store.get("REVOKED_JTI#forged-jti-1") is None

    rev_ref = server.dispatch(
        _make_event("POST", "/oauth/revoke", body={"token": tok_ok_doc["refresh_token"]})
    )
    assert rev_ref["statusCode"] == 200
    use_revoked_ref = server.dispatch(
        _make_event(
            "POST",
            "/oauth/token",
            body={
                "grant_type": "refresh_token",
                "client_id": "dtc-mcp-public",
                "refresh_token": tok_ok_doc["refresh_token"],
            },
        )
    )
    assert use_revoked_ref["statusCode"] == 400

    # Finding 6 & 8: Device flow deny, expired_token, and client_id mismatch
    dev_start = json.loads(
        server.dispatch(
            _make_event("POST", "/oauth/device", body={"client_id": "dtc-cli"})
        )["body"]
    )
    mismatch_poll = server.dispatch(
        _make_event(
            "POST",
            "/oauth/token",
            body={
                "grant_type": DEVICE_GRANT_TYPE,
                "device_code": dev_start["device_code"],
                "client_id": "other-client",
            },
        )
    )
    assert mismatch_poll["statusCode"] == 400
    assert json.loads(mismatch_poll["body"])["error"] == "invalid_grant"

    clock.advance(601)
    expired_poll = server.dispatch(
        _make_event(
            "POST",
            "/oauth/token",
            body={
                "grant_type": DEVICE_GRANT_TYPE,
                "device_code": dev_start["device_code"],
                "client_id": "dtc-cli",
            },
        )
    )
    assert json.loads(expired_poll["body"])["error"] == "expired_token"

    # Finding 11 & 12: client_secret_post positive test & mixed DCR client_credentials rejected
    cc_post = server.dispatch(
        _make_event(
            "POST",
            "/oauth/token",
            body={
                "grant_type": "client_credentials",
                "client_id": "mcp-auth-test-service",
                "client_secret": "dtcsvc_test_secret_123",
            },
        )
    )
    assert cc_post["statusCode"] == 200

    mixed_dcr = server.dispatch(
        _make_event(
            "POST",
            "/oauth/register",
            body={
                "redirect_uris": ["http://localhost:8080/cb"],
                "grant_types": ["authorization_code", "client_credentials"],
            },
        )
    )
    assert mixed_dcr["statusCode"] == 400

