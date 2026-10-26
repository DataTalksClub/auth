"""Serverless OAuth 2.1 Authorization Server + RFC 7591 DCR + RFC 8628 Device Grant.

Delegates human sign-in to the shared DTC Cognito Google SSO pool
(auth.dtcdev.click, restricted to verified @datatalks.club accounts by
DomainGuardFunction) and issues 1-hour RS256 audience-bound JWT access tokens
(RFC 8707), single-use rotating refresh tokens, and short-lived
client_credentials service tokens for Hub and DataOps.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import ipaddress
import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

# PKCS#1 v1.5 DigestInfo prefix for SHA-256 (RFC 8017 Section 9.2)
_SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")

# Canonical audiences (AC 6)
RESOURCE_HUB_MCP = "https://hub.dtcdev.click/mcp"
RESOURCE_HUB_API = "https://hub.dtcdev.click"
RESOURCE_DATAOPS_MCP_LAMBDA = (
    "https://frzdkakcapcyf6ywflhieyimgu0vtclr.lambda-url.eu-west-1.on.aws/mcp"
)
RESOURCE_DATAOPS_MCP_CUSTOM = "https://mcp.ops.dtcdev.click/mcp"
RESOURCE_DATAOPS_MCP_PORTAL = "https://ops.dtcdev.click/mcp"
RESOURCE_DATAOPS_API = "https://ops.dtcdev.click"

CANONICAL_RESOURCES = (
    RESOURCE_HUB_MCP,
    RESOURCE_HUB_API,
    RESOURCE_DATAOPS_MCP_LAMBDA,
    RESOURCE_DATAOPS_MCP_CUSTOM,
    RESOURCE_DATAOPS_MCP_PORTAL,
    RESOURCE_DATAOPS_API,
)

RESOURCE_ALIASES: dict[str, str] = {
    "https://hub.dtcdev.click/mcp": RESOURCE_HUB_MCP,
    "https://hub.dtcdev.click/mcp/": RESOURCE_HUB_MCP,
    "https://oauth.dtcdev.click/mcp": RESOURCE_HUB_MCP,
    "https://oauth.dtcdev.click/mcp/": RESOURCE_HUB_MCP,
    "https://oauth.dtcdev.click": RESOURCE_HUB_MCP,
    "https://oauth.dtcdev.click/": RESOURCE_HUB_MCP,
    "https://hub.dtcdev.click": RESOURCE_HUB_API,
    "https://hub.dtcdev.click/": RESOURCE_HUB_API,
    "https://hub.dtcdev.click/api": RESOURCE_HUB_API,
    "https://hub.dtcdev.click/api/": RESOURCE_HUB_API,
    RESOURCE_DATAOPS_MCP_LAMBDA: RESOURCE_DATAOPS_MCP_LAMBDA,
    f"{RESOURCE_DATAOPS_MCP_LAMBDA}/": RESOURCE_DATAOPS_MCP_LAMBDA,
    "https://frzdkakcapcyf6ywflhieyimgu0vtclr.lambda-url.eu-west-1.on.aws": (
        RESOURCE_DATAOPS_MCP_LAMBDA
    ),
    "https://frzdkakcapcyf6ywflhieyimgu0vtclr.lambda-url.eu-west-1.on.aws/": (
        RESOURCE_DATAOPS_MCP_LAMBDA
    ),
    RESOURCE_DATAOPS_MCP_CUSTOM: RESOURCE_DATAOPS_MCP_CUSTOM,
    f"{RESOURCE_DATAOPS_MCP_CUSTOM}/": RESOURCE_DATAOPS_MCP_CUSTOM,
    "https://mcp.ops.dtcdev.click": RESOURCE_DATAOPS_MCP_CUSTOM,
    "https://mcp.ops.dtcdev.click/": RESOURCE_DATAOPS_MCP_CUSTOM,
    RESOURCE_DATAOPS_MCP_PORTAL: RESOURCE_DATAOPS_MCP_PORTAL,
    f"{RESOURCE_DATAOPS_MCP_PORTAL}/": RESOURCE_DATAOPS_MCP_PORTAL,
    RESOURCE_DATAOPS_API: RESOURCE_DATAOPS_API,
    "https://ops.dtcdev.click/": RESOURCE_DATAOPS_API,
    "https://ops.dtcdev.click/api": RESOURCE_DATAOPS_API,
    "https://ops.dtcdev.click/api/": RESOURCE_DATAOPS_API,
    "https://el4jt4z2k4lnxwvoqawrdcsedm0axjzc.lambda-url.eu-west-1.on.aws": RESOURCE_DATAOPS_API,
    "https://el4jt4z2k4lnxwvoqawrdcsedm0axjzc.lambda-url.eu-west-1.on.aws/": RESOURCE_DATAOPS_API,
    "https://el4jt4z2k4lnxwvoqawrdcsedm0axjzc.lambda-url.eu-west-1.on.aws/api": (
        RESOURCE_DATAOPS_API
    ),
    "https://el4jt4z2k4lnxwvoqawrdcsedm0axjzc.lambda-url.eu-west-1.on.aws/api/": (
        RESOURCE_DATAOPS_API
    ),
}

STANDARD_HUMAN_SCOPES = (
    "openid",
    "email",
    "profile",
    "offline_access",
    "mcp",
    "admin",
    "read",
    "write",
    "claudeai",
)
DEFAULT_HUMAN_SCOPE = "openid email profile offline_access mcp admin"

PRE_REGISTERED_PUBLIC_CLIENTS: dict[str, dict[str, Any]] = {
    "dtc-mcp-public": {
        "client_id": "dtc-mcp-public",
        "client_name": "DTC MCP Public Client (ChatGPT / Claude / Cursor / CLI)",
        "token_endpoint_auth_method": "none",
        "grant_types": [
            "authorization_code",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code",
        ],
        "response_types": ["code"],
        "registration_source": "pre_registered",
    },
    "dtc-cli": {
        "client_id": "dtc-cli",
        "client_name": "DTC Shared CLI Client (hub & dataops)",
        "token_endpoint_auth_method": "none",
        "grant_types": [
            "authorization_code",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code",
        ],
        "response_types": ["code"],
        "registration_source": "pre_registered",
    },
}

ALLOWED_CUSTOM_SCHEMES = {"cursor", "claude", "vscode"}
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}
DEVICE_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ23456789"
DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"

HUMAN_ACCESS_TOKEN_TTL_SECONDS = 3600
SERVICE_ACCESS_TOKEN_TTL_SECONDS = 900
REFRESH_TOKEN_TTL_SECONDS = 90 * 86400
AUTH_CODE_TTL_SECONDS = 120
UPSTREAM_STATE_TTL_SECONDS = 600
DEVICE_CODE_TTL_SECONDS = 600
SESSION_COOKIE_TTL_SECONDS = 12 * 3600
SESSION_COOKIE_NAME = "dtc_oauth_session"

CONSENT_CSP = (
    "default-src 'none'; "
    "style-src 'unsafe-inline'; "
    "form-action 'self' https: http://127.0.0.1:* http://localhost:* http://[::1]:* "
    "cursor: claude: vscode:; "
    "frame-ancestors 'none'; "
    "base-uri 'none'"
)

CORS_HEADERS = {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "Authorization, Content-Type, Accept, MCP-Protocol-Version",
    "cache-control": "no-store",
}


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    padded = text + "=" * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def pkce_s256_challenge(verifier: str) -> str:
    return b64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())


def _read_asn1_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    if offset >= len(data):
        raise ValueError("Truncated ASN.1 DER data")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise ValueError("Truncated ASN.1 DER length")
    first_len = data[offset]
    offset += 1
    if first_len < 0x80:
        length = first_len
    else:
        num_octets = first_len & 0x7F
        if num_octets == 0 or offset + num_octets > len(data):
            raise ValueError("Invalid ASN.1 DER length")
        length = int.from_bytes(data[offset : offset + num_octets], "big")
        offset += num_octets
    if offset + length > len(data):
        raise ValueError("ASN.1 DER value exceeds buffer")
    return tag, data[offset : offset + length], offset + length


def parse_spki_rsa_public_key(spki_der: bytes) -> tuple[bytes, bytes]:
    """Extract (n_bytes, e_bytes) from a DER SubjectPublicKeyInfo RSA public key."""
    tag, seq_body, _ = _read_asn1_tlv(spki_der, 0)
    if tag != 0x30:
        raise ValueError("Expected outer SEQUENCE in SPKI")
    alg_tag, _alg_body, next_off = _read_asn1_tlv(seq_body, 0)
    if alg_tag != 0x30:
        raise ValueError("Expected AlgorithmIdentifier SEQUENCE")
    bit_tag, bit_body, _ = _read_asn1_tlv(seq_body, next_off)
    if bit_tag != 0x03 or not bit_body or bit_body[0] != 0x00:
        raise ValueError("Expected BIT STRING in SPKI")
    rsa_tag, rsa_body, _ = _read_asn1_tlv(bit_body[1:], 0)
    if rsa_tag != 0x30:
        raise ValueError("Expected RSAPublicKey SEQUENCE")
    n_tag, n_raw, next_rsa = _read_asn1_tlv(rsa_body, 0)
    e_tag, e_raw, _ = _read_asn1_tlv(rsa_body, next_rsa)
    if n_tag != 0x02 or e_tag != 0x02:
        raise ValueError("Expected INTEGER modulus and exponent")
    n_bytes = n_raw.lstrip(b"\x00")
    e_bytes = e_raw.lstrip(b"\x00")
    if not n_bytes or not e_bytes:
        raise ValueError("Empty RSA modulus or exponent")
    return n_bytes, e_bytes


def jwk_from_rsa_numbers(n_bytes: bytes, e_bytes: bytes, kid: str | None = None) -> dict[str, str]:
    computed_kid = kid or b64url_encode(hashlib.sha256(n_bytes + b"." + e_bytes).digest()[:16])
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": computed_kid,
        "n": b64url_encode(n_bytes),
        "e": b64url_encode(e_bytes),
    }


def verify_rs256_signature(jwk: dict[str, Any], signing_input: bytes, signature: bytes) -> bool:
    """Verify RSASSA-PKCS1-v1_5 SHA-256 signature against a JWK dictionary."""
    try:
        n_bytes = b64url_decode(jwk["n"])
        e_bytes = b64url_decode(jwk["e"])
    except Exception:
        return False
    n = int.from_bytes(n_bytes, "big")
    e = int.from_bytes(e_bytes, "big")
    k = len(n_bytes)
    if k < 128 or len(signature) != k:
        return False
    s = int.from_bytes(signature, "big")
    if s <= 0 or s >= n:
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    digest_info = _SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(signing_input).digest()
    ps_len = k - 3 - len(digest_info)
    if ps_len < 8:
        return False
    expected_em = b"\x00\x01" + (b"\xff" * ps_len) + b"\x00" + digest_info
    return hmac.compare_digest(em, expected_em)


class KmsRs256Signer:
    """Signs JWTs using an AWS KMS RSA_2048 SIGN_VERIFY key."""

    def __init__(self, kms_client: Any, key_id: str):
        self._kms = kms_client
        self._key_id = key_id
        self._cached_jwk: dict[str, str] | None = None

    def get_jwk(self) -> dict[str, str]:
        if self._cached_jwk is None:
            resp = self._kms.get_public_key(KeyId=self._key_id)
            n_bytes, e_bytes = parse_spki_rsa_public_key(resp["PublicKey"])
            self._cached_jwk = jwk_from_rsa_numbers(n_bytes, e_bytes)
        return self._cached_jwk

    def sign(self, signing_input: bytes) -> bytes:
        resp = self._kms.sign(
            KeyId=self._key_id,
            Message=signing_input,
            MessageType="RAW",
            SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
        )
        return bytes(resp["Signature"])


class LocalRs256Signer:
    """Pure-Python RSA-2048 signer for fast deterministic unit and conformance tests."""

    def __init__(self, n: int, e: int, d: int, kid: str | None = None):
        self._n = n
        self._e = e
        self._d = d
        self._k = (n.bit_length() + 7) // 8
        self._jwk = jwk_from_rsa_numbers(
            n.to_bytes(self._k, "big"),
            e.to_bytes((e.bit_length() + 7) // 8, "big"),
            kid=kid,
        )

    def get_jwk(self) -> dict[str, str]:
        return dict(self._jwk)

    def sign(self, signing_input: bytes) -> bytes:
        digest_info = _SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(signing_input).digest()
        ps_len = self._k - 3 - len(digest_info)
        em = b"\x00\x01" + (b"\xff" * ps_len) + b"\x00" + digest_info
        m = int.from_bytes(em, "big")
        s = pow(m, self._d, self._n)
        return s.to_bytes(self._k, "big")


def encode_jwt_rs256(signer: Any, claims: dict[str, Any]) -> str:
    jwk = signer.get_jwk()
    header = {"alg": "RS256", "typ": "JWT", "kid": jwk["kid"]}
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    claims_b64 = b64url_encode(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{claims_b64}".encode("ascii")
    sig_b64 = b64url_encode(signer.sign(signing_input))
    return f"{header_b64}.{claims_b64}.{sig_b64}"


def verify_access_token(
    token: str,
    *,
    expected_issuer: str,
    expected_audience: str | set[str] | tuple[str, ...],
    jwks: dict[str, Any],
    now: int | None = None,
    is_revoked_jti: Any = None,
) -> dict[str, Any]:
    """Verify an RS256 access token and strictly enforce issuer and RFC 8707 audience."""
    if not isinstance(token, str) or len(token) > 16384:
        raise ValueError("invalid_token_format")
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("invalid_token_format")
    try:
        header = json.loads(b64url_decode(parts[0]).decode("utf-8"))
        claims = json.loads(b64url_decode(parts[1]).decode("utf-8"))
        sig = b64url_decode(parts[2])
    except Exception as err:
        raise ValueError("invalid_token_encoding") from err

    if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
        raise ValueError("invalid_token_header")

    keys = jwks.get("keys") or []
    key = next((k for k in keys if k.get("kid") == header["kid"]), None)
    if not key:
        raise ValueError("signing_key_not_found")

    if not verify_rs256_signature(key, f"{parts[0]}.{parts[1]}".encode("ascii"), sig):
        raise ValueError("invalid_signature")

    current_time = int(time.time()) if now is None else int(now)
    if claims.get("iss") != expected_issuer.rstrip("/"):
        raise ValueError("issuer_mismatch")

    exp = claims.get("exp")
    if not isinstance(exp, int | float) or current_time >= exp:
        raise ValueError("token_expired")

    allowed_audiences = (
        {expected_audience} if isinstance(expected_audience, str) else set(expected_audience)
    )
    aud_claim = claims.get("aud")
    token_audiences = {aud_claim} if isinstance(aud_claim, str) else set(aud_claim or [])
    if not token_audiences or not (token_audiences & allowed_audiences):
        raise ValueError("audience_mismatch")

    jti = claims.get("jti")
    if jti and is_revoked_jti and is_revoked_jti(str(jti)):
        raise ValueError("token_revoked")

    return claims


def is_valid_redirect_uri(uri: Any) -> bool:
    """Validate redirect_uri per AC 3: https://, loopback http, cursor://, claude://, vscode://."""
    if not isinstance(uri, str) or not uri or len(uri) > 2048:
        return False
    if any(ch in uri for ch in ("\r", "\n", "\t", " ")):
        return False
    try:
        parsed = urllib.parse.urlsplit(uri)
    except Exception:
        return False
    if parsed.fragment or parsed.username or parsed.password:
        return False
    scheme = (parsed.scheme or "").lower()
    if scheme == "https":
        return bool(parsed.hostname)
    if scheme == "http":
        host = (parsed.hostname or "").lower()
        return host in LOOPBACK_HOSTS
    if scheme in ALLOWED_CUSTOM_SCHEMES:
        return bool(parsed.netloc or parsed.path)
    return False


def matches_registered_redirect_uri(requested_uri: str, registered_uris: list[str]) -> bool:
    """Match redirect_uri against registered URIs, allowing ephemeral loopback port matching."""
    if not is_valid_redirect_uri(requested_uri):
        return False
    if requested_uri in registered_uris:
        return True
    req = urllib.parse.urlsplit(requested_uri)
    if req.scheme.lower() == "http" and (req.hostname or "").lower() in LOOPBACK_HOSTS:
        for candidate in registered_uris:
            cand = urllib.parse.urlsplit(candidate)
            if (
                cand.scheme.lower() == "http"
                and (cand.hostname or "").lower() == (req.hostname or "").lower()
                and (cand.path or "/") == (req.path or "/")
            ):
                return True
    return False


def is_allowed_public_client_redirect(uri: str) -> bool:
    """Check if redirect_uri is allowed for pre-registered public clients."""
    if not is_valid_redirect_uri(uri):
        return False
    parsed = urllib.parse.urlsplit(uri)
    scheme = parsed.scheme.lower()
    if scheme in ALLOWED_CUSTOM_SCHEMES or scheme == "http":
        return True
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    if host == "chatgpt.com" and (
        path == "/connector_platform_oauth_redirect" or path.startswith("/connector/oauth/")
    ):
        return True
    if host == "chat.openai.com" and path.startswith("/aip/"):
        return True
    return host in {"claude.ai", "claude.com"} and path == "/api/mcp/auth_callback"


def normalize_resource(
    raw_resource: str | None,
    *,
    default_resource: str = RESOURCE_HUB_MCP,
) -> str:
    """Normalize and validate an RFC 8707 resource indicator against registered audiences."""
    if raw_resource is None or str(raw_resource).strip() == "":
        return default_resource
    cleaned = str(raw_resource).strip()
    if cleaned in RESOURCE_ALIASES:
        return RESOURCE_ALIASES[cleaned]
    raise ValueError(f"Unknown or unregistered resource indicator: {cleaned}")


def normalize_human_scope(raw_scope: str | None) -> str:
    """Accept missing or standard OIDC/MCP scopes and map to human MCP/CLI grant."""
    if raw_scope is None:
        return DEFAULT_HUMAN_SCOPE
    if not isinstance(raw_scope, str) or len(raw_scope) > 1024:
        raise ValueError("invalid_scope")
    requested = [s for s in raw_scope.strip().split() if s]
    if not requested:
        return DEFAULT_HUMAN_SCOPE
    kept = [s for s in requested if s in STANDARD_HUMAN_SCOPES]
    for required in ("mcp", "admin"):
        if required not in kept:
            kept.append(required)
    return " ".join(kept)


def is_allowed_workspace_email(email: Any, email_verified: Any, allowed_domain: str) -> bool:
    """Enforce verified @datatalks.club identity (mirrors DomainGuardFunction)."""
    verified = email_verified is True or str(email_verified).strip().lower() == "true"
    if not verified or not isinstance(email, str):
        return False
    cleaned = email.strip().lower()
    suffix = "@" + allowed_domain.lower().lstrip("@")
    return cleaned.endswith(suffix) and cleaned != suffix


class InMemoryOAuthStore:
    """In-memory store matching DynamoDBOAuthStore semantics for fast unit tests."""

    def __init__(self) -> None:
        self.items: dict[str, dict[str, Any]] = {}

    def get(self, pk: str) -> dict[str, Any] | None:
        item = self.items.get(pk)
        return dict(item) if item is not None else None

    def put(self, pk: str, data: dict[str, Any]) -> None:
        record = dict(data)
        record["pk"] = pk
        self.items[pk] = record

    def delete(self, pk: str) -> None:
        self.items.pop(pk, None)

    def consume_once(self, pk: str, flag_field: str = "used") -> dict[str, Any] | None:
        item = self.items.get(pk)
        if not item or item.get(flag_field):
            return None
        item[flag_field] = True
        return dict(item)


class DynamoDBOAuthStore:
    """DynamoDB persistence for DCR clients, auth codes, refresh tokens, and device codes."""

    def __init__(self, table: Any) -> None:
        self._table = table

    def get(self, pk: str) -> dict[str, Any] | None:
        resp = self._table.get_item(Key={"pk": pk}, ConsistentRead=True)
        item = resp.get("Item")
        return dict(item) if item else None

    def put(self, pk: str, data: dict[str, Any]) -> None:
        item = dict(data)
        item["pk"] = pk
        self._table.put_item(Item=item)

    def delete(self, pk: str) -> None:
        self._table.delete_item(Key={"pk": pk})

    def consume_once(self, pk: str, flag_field: str = "used") -> dict[str, Any] | None:
        try:
            resp = self._table.update_item(
                Key={"pk": pk},
                UpdateExpression="SET #f = :true",
                ConditionExpression=(
                    "attribute_exists(pk) AND (#f = :false OR attribute_not_exists(#f))"
                ),
                ExpressionAttributeNames={"#f": flag_field},
                ExpressionAttributeValues={":true": True, ":false": False},
                ReturnValues="ALL_OLD",
            )
            attrs = resp.get("Attributes")
            return dict(attrs) if attrs else None
        except Exception:
            return None


def _is_public_ip_host(hostname: str) -> bool:
    """Prevent SSRF on Client ID Metadata Document (CIMD) fetches."""
    host = hostname.strip("[]").lower()
    if host in {"localhost", "metadata.google.internal"} or host.endswith(".internal"):
        return False
    try:
        ip = ipaddress.ip_address(host)
        return not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return True


def _parse_basic_auth(auth_header: str) -> tuple[str, str] | None:
    if not auth_header or not auth_header.lower().startswith("basic "):
        return None
    raw_b64 = auth_header[6:].strip()
    try:
        decoded = base64.b64decode(raw_b64).decode("utf-8")
    except Exception:
        return None
    if ":" not in decoded:
        return None
    cid, secret = decoded.split(":", 1)
    return urllib.parse.unquote_plus(cid), urllib.parse.unquote_plus(secret)


class OAuthServer:
    """Shared DTC OAuth 2.1 + DCR + Device Code + Service Client Authorization Server."""

    def __init__(
        self,
        *,
        issuer_url: str,
        cognito_base_url: str,
        cognito_issuer_url: str,
        cognito_client_id: str,
        allowed_domain: str = "datatalks.club",
        store: Any,
        signer: Any,
        session_secret: str,
        service_clients: dict[str, dict[str, Any]] | None = None,
        cognito_token_exchanger: Any = None,
        cimd_fetcher: Any = None,
        clock: Any = time.time,
    ) -> None:
        self.issuer_url = issuer_url.rstrip("/")
        self.cognito_base_url = cognito_base_url.rstrip("/")
        self.cognito_issuer_url = cognito_issuer_url.rstrip("/")
        self.cognito_client_id = cognito_client_id
        self.allowed_domain = allowed_domain.lower().lstrip("@")
        self.store = store
        self.signer = signer
        self.session_secret = session_secret.encode("utf-8")
        self.service_clients = dict(service_clients or {})
        self.cognito_token_exchanger = cognito_token_exchanger or self._default_cognito_exchange
        self.cimd_fetcher = cimd_fetcher or self._default_cimd_fetcher
        self.clock = clock
        self._cognito_jwks_cache: dict[str, Any] | None = None

    def now(self) -> int:
        return int(self.clock())

    def discovery_metadata(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer_url,
            "authorization_endpoint": f"{self.issuer_url}/oauth/authorize",
            "token_endpoint": f"{self.issuer_url}/oauth/token",
            "registration_endpoint": f"{self.issuer_url}/oauth/register",
            "device_authorization_endpoint": f"{self.issuer_url}/oauth/device",
            "revocation_endpoint": f"{self.issuer_url}/oauth/revoke",
            "jwks_uri": f"{self.issuer_url}/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": [
                "authorization_code",
                "refresh_token",
                "client_credentials",
                DEVICE_GRANT_TYPE,
            ],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": [
                "none",
                "client_secret_post",
                "client_secret_basic",
            ],
            "revocation_endpoint_auth_methods_supported": [
                "none",
                "client_secret_post",
                "client_secret_basic",
            ],
            "authorization_response_iss_parameter_supported": True,
            "client_id_metadata_document_supported": True,
            "scopes_supported": list(STANDARD_HUMAN_SCOPES),
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "resource_indicators_supported": True,
            "resources_supported": list(CANONICAL_RESOURCES),
        }

    def protected_resource_metadata(self, resource: str = RESOURCE_HUB_MCP) -> dict[str, Any]:
        return {
            "resource": resource,
            "authorization_servers": [self.issuer_url],
            "scopes_supported": list(STANDARD_HUMAN_SCOPES),
            "bearer_methods_supported": ["header"],
            "resource_name": "DTC Shared MCP OAuth 2.1 Server",
        }

    def jwks_document(self) -> dict[str, Any]:
        return {"keys": [self.signer.get_jwk()]}

    # --- Session Cookie & CSRF ---

    def create_session_cookie_value(self, user: dict[str, Any]) -> str:
        now = self.now()
        payload = {
            "sub": str(user["sub"]),
            "email": str(user["email"]).strip().lower(),
            "email_verified": True,
            "iat": now,
            "exp": now + SESSION_COOKIE_TTL_SECONDS,
        }
        body = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        sig = b64url_encode(
            hmac.new(self.session_secret, body.encode("ascii"), hashlib.sha256).digest()
        )
        return f"{body}.{sig}"

    def verify_session_cookie_value(self, cookie_val: str | None) -> dict[str, Any] | None:
        if not cookie_val or "." not in cookie_val:
            return None
        body, sig = cookie_val.split(".", 1)
        expected = b64url_encode(
            hmac.new(self.session_secret, body.encode("ascii"), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(sig, expected):
            return None
        try:
            payload = json.loads(b64url_decode(body).decode("utf-8"))
        except Exception:
            return None
        if not isinstance(payload, dict) or self.now() >= int(payload.get("exp") or 0):
            return None
        if not is_allowed_workspace_email(
            payload.get("email"), payload.get("email_verified"), self.allowed_domain
        ):
            return None
        return payload

    def csrf_token_for_session(self, session: dict[str, Any], purpose: str) -> str:
        msg = f"{purpose}:{session['sub']}:{session['email']}:{session['iat']}".encode()
        return b64url_encode(hmac.new(self.session_secret, msg, hashlib.sha256).digest())

    # --- Client Lookup (DCR, Pre-registered, CIMD, Service Clients) ---

    def _default_cimd_fetcher(self, client_id_url: str) -> dict[str, Any]:
        parsed = urllib.parse.urlsplit(client_id_url)
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            raise ValueError("invalid_cimd_url")
        if not _is_public_ip_host(parsed.hostname):
            raise ValueError("disallowed_cimd_host")
        req = urllib.request.Request(
            client_id_url, headers={"Accept": "application/json", "User-Agent": "dtc-oauth/1.0"}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            raw = resp.read(65536)
        return json.loads(raw.decode("utf-8"))

    def resolve_client(self, client_id: str) -> dict[str, Any] | None:
        if not client_id or not isinstance(client_id, str) or len(client_id) > 2048:
            return None
        if client_id in PRE_REGISTERED_PUBLIC_CLIENTS:
            return dict(PRE_REGISTERED_PUBLIC_CLIENTS[client_id])
        stored = self.store.get(f"CLIENT#{client_id}")
        if stored:
            return stored
        if client_id.startswith("https://"):
            try:
                doc = self.cimd_fetcher(client_id)
                if not isinstance(doc, dict) or doc.get("client_id") != client_id:
                    return None
                uris = doc.get("redirect_uris")
                if (
                    not isinstance(uris, list)
                    or not uris
                    or not all(is_valid_redirect_uri(u) for u in uris)
                ):
                    return None
                return {
                    "client_id": client_id,
                    "client_name": str(doc.get("client_name") or client_id)[:200],
                    "redirect_uris": list(uris),
                    "token_endpoint_auth_method": "none",
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "registration_source": "cimd",
                }
            except Exception:
                return None
        return None

    def resolve_service_client(self, client_id: str) -> dict[str, Any] | None:
        if client_id in self.service_clients:
            return dict(self.service_clients[client_id])
        stored = self.store.get(f"SERVICE_CLIENT#{client_id}")
        if stored and stored.get("registration_source") == "admin_service":
            return stored
        return None

    def touch_client(self, client_id: str) -> None:
        stored = self.store.get(f"CLIENT#{client_id}")
        if stored:
            stored["last_used_at"] = self.now()
            # Ensure no 90-day TTL expires in-use clients (AC 3)
            stored.pop("ttl", None)
            self.store.put(f"CLIENT#{client_id}", stored)

    # --- Dynamic Client Registration (POST /oauth/register, AC 3) ---

    def handle_register(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        if not isinstance(body, dict):
            return 400, {"error": "invalid_client_metadata"}

        redirect_uris = body.get("redirect_uris")
        if (
            not isinstance(redirect_uris, list)
            or not redirect_uris
            or len(redirect_uris) > 25
            or not all(is_valid_redirect_uri(u) for u in redirect_uris)
        ):
            return 400, {
                "error": "invalid_redirect_uri",
                "error_description": (
                    "redirect_uris must be a non-empty list of valid https, loopback http, "
                    "cursor://, claude://, or vscode:// URIs"
                ),
            }

        requested_grants = body.get("grant_types")
        if requested_grants is not None:
            if not isinstance(requested_grants, list) or not all(
                isinstance(g, str) for g in requested_grants
            ):
                return 400, {"error": "invalid_client_metadata"}
            if "client_credentials" in requested_grants and len(requested_grants) == 1:
                return 400, {
                    "error": "invalid_client_metadata",
                    "error_description": "client_credentials clients cannot be registered via DCR",
                }
        grant_types = ["authorization_code", "refresh_token"]

        auth_method = str(body.get("token_endpoint_auth_method") or "none")
        if auth_method not in {"none", "client_secret_post", "client_secret_basic"}:
            return 400, {"error": "invalid_client_metadata"}

        try:
            scope = normalize_human_scope(body.get("scope"))
        except ValueError:
            return 400, {"error": "invalid_client_metadata", "error_description": "Invalid scope"}

        default_resource = RESOURCE_HUB_MCP
        if body.get("resource"):
            try:
                default_resource = normalize_resource(str(body["resource"]))
            except ValueError:
                return 400, {
                    "error": "invalid_client_metadata",
                    "error_description": "Invalid resource",
                }

        now = self.now()
        client_id = f"mcpc_{secrets.token_urlsafe(18)}"
        client_name = str(body.get("client_name") or "MCP Client")[:200]
        record: dict[str, Any] = {
            "client_id": client_id,
            "client_name": client_name,
            "redirect_uris": list(redirect_uris),
            "grant_types": grant_types,
            "response_types": ["code"],
            "token_endpoint_auth_method": auth_method,
            "scope": scope,
            "default_resource": default_resource,
            "registration_source": "dcr",
            "client_id_issued_at": now,
            "last_used_at": now,
        }
        response_doc = dict(record)
        if auth_method in {"client_secret_post", "client_secret_basic"}:
            raw_secret = f"mcps_{secrets.token_urlsafe(24)}"
            record["client_secret_sha256"] = sha256_hex(raw_secret)
            response_doc["client_secret"] = raw_secret
            response_doc["client_secret_expires_at"] = 0

        self.store.put(f"CLIENT#{client_id}", record)
        return 201, response_doc

    # --- Authorization Endpoint (/oauth/authorize, AC 4) ---

    def _validate_authorize_params(
        self, params: dict[str, str]
    ) -> tuple[dict[str, Any] | None, tuple[int, dict[str, Any]] | None]:
        client_id = (params.get("client_id") or "").strip()
        client = self.resolve_client(client_id)
        if not client:
            return None, (
                400,
                {"error": "invalid_client", "error_description": "Unknown client_id"},
            )

        redirect_uri = (params.get("redirect_uri") or "").strip()
        if client.get("registration_source") == "pre_registered":
            if not is_allowed_public_client_redirect(redirect_uri):
                return None, (
                    400,
                    {"error": "invalid_request", "error_description": "Disallowed redirect_uri"},
                )
        else:
            registered_uris = client.get("redirect_uris") or []
            if not redirect_uri and len(registered_uris) == 1:
                redirect_uri = registered_uris[0]
            if not matches_registered_redirect_uri(redirect_uri, registered_uris):
                return None, (
                    400,
                    {"error": "invalid_request", "error_description": "Mismatched redirect_uri"},
                )

        if params.get("response_type") != "code":
            return None, (
                400,
                {
                    "error": "unsupported_response_type",
                    "error_description": "response_type=code required",
                },
            )

        code_challenge = (params.get("code_challenge") or "").strip()
        code_challenge_method = (params.get("code_challenge_method") or "").strip()
        if not code_challenge or len(code_challenge) < 32 or code_challenge_method != "S256":
            return None, (
                400,
                {
                    "error": "invalid_request",
                    "error_description": (
                        "PKCE code_challenge with code_challenge_method=S256 is required"
                    ),
                },
            )

        default_res = str(client.get("default_resource") or RESOURCE_HUB_MCP)
        try:
            resource = normalize_resource(params.get("resource"), default_resource=default_res)
        except ValueError as err:
            return None, (400, {"error": "invalid_target", "error_description": str(err)})

        try:
            scope = normalize_human_scope(params.get("scope"))
        except ValueError:
            return None, (400, {"error": "invalid_scope", "error_description": "Invalid scope"})

        state = params.get("state") or ""
        return {
            "client": client,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "resource": resource,
            "scope": scope,
            "state": state,
        }, None

    def _start_cognito_login(self, state_payload: dict[str, Any]) -> dict[str, Any]:
        now = self.now()
        upstream_state = secrets.token_urlsafe(24)
        cognito_verifier = secrets.token_urlsafe(48)
        cognito_challenge = pkce_s256_challenge(cognito_verifier)
        nonce = secrets.token_urlsafe(24)
        record = dict(state_payload)
        record.update(
            {
                "cognito_verifier": cognito_verifier,
                "nonce": nonce,
                "created_at": now,
                "used": False,
                "ttl": now + UPSTREAM_STATE_TTL_SECONDS,
            }
        )
        self.store.put(f"UPSTREAM#{upstream_state}", record)
        query = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": self.cognito_client_id,
                "redirect_uri": f"{self.issuer_url}/auth/callback",
                "scope": "openid email profile",
                "state": upstream_state,
                "nonce": nonce,
                "code_challenge": cognito_challenge,
                "code_challenge_method": "S256",
                "identity_provider": "Google",
            }
        )
        return {
            "statusCode": 302,
            "headers": {
                "location": f"{self.cognito_base_url}/oauth2/authorize?{query}",
                "cache-control": "no-store",
            },
            "body": "",
        }

    def handle_authorize_get(
        self, params: dict[str, str], session: dict[str, Any] | None
    ) -> dict[str, Any]:
        validated, err = self._validate_authorize_params(params)
        if err is not None:
            status, body = err
            return self._json_response(status, body)
        assert validated is not None
        self.touch_client(validated["client_id"])

        if session is None:
            return self._start_cognito_login(
                {
                    "kind": "authorize",
                    "authorize_params": {
                        "client_id": validated["client_id"],
                        "redirect_uri": validated["redirect_uri"],
                        "response_type": "code",
                        "code_challenge": validated["code_challenge"],
                        "code_challenge_method": "S256",
                        "resource": validated["resource"],
                        "scope": validated["scope"],
                        "state": validated["state"],
                    },
                }
            )

        csrf = self.csrf_token_for_session(session, "authorize")
        client_name = html.escape(
            str(validated["client"].get("client_name") or validated["client_id"])
        )
        email_esc = html.escape(str(session["email"]))
        resource_esc = html.escape(str(validated["resource"]))
        scope_esc = html.escape(str(validated["scope"]))
        hidden_fields = {
            "client_id": validated["client_id"],
            "redirect_uri": validated["redirect_uri"],
            "response_type": "code",
            "code_challenge": validated["code_challenge"],
            "code_challenge_method": "S256",
            "resource": validated["resource"],
            "scope": validated["scope"],
            "state": validated["state"],
            "csrf_token": csrf,
        }
        inputs_html = "\n".join(
            f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(str(v))}">'
            for k, v in hidden_fields.items()
        )
        page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authorize MCP Access · DataTalksClub</title>
  <style>
    body {{
      font-family: system-ui, sans-serif;
      background: #f7f7f5;
      color: #222;
      display: grid;
      place-items: center;
      min-height: 100vh;
      margin: 0;
    }}
    .card {{
      background: #fff;
      border: 1px solid #e2e2dd;
      border-radius: 12px;
      padding: 28px;
      max-width: 460px;
      width: 100%;
    }}
    h1 {{ font-size: 20px; margin: 0 0 12px; }}
    p {{ font-size: 14px; color: #555; line-height: 1.5; }}
    .meta {{
      background: #f2f2ee;
      padding: 12px;
      border-radius: 8px;
      font-size: 13px;
      margin: 16px 0;
      word-break: break-all;
    }}
    .actions {{ display: flex; gap: 12px; margin-top: 20px; }}
    button {{
      flex: 1;
      padding: 10px 16px;
      border-radius: 6px;
      font-weight: 600;
      cursor: pointer;
      border: 1px solid transparent;
    }}
    .approve {{ background: #1f6f64; color: #fff; }}
    .deny {{ background: #fff; color: #444; border-color: #ccc; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Authorize {client_name}</h1>
    <p>Signed in as <strong>{email_esc}</strong></p>
    <div class="meta">
      <div><strong>Resource:</strong> {resource_esc}</div>
      <div><strong>Scope:</strong> {scope_esc}</div>
    </div>
    <form method="post" action="/oauth/authorize">
      {inputs_html}
      <div class="actions">
        <button class="approve" type="submit" name="decision" value="approve">Allow</button>
        <button class="deny" type="submit" name="decision" value="deny">Deny</button>
      </div>
    </form>
  </div>
</body>
</html>"""
        return {
            "statusCode": 200,
            "headers": {
                "content-type": "text/html; charset=utf-8",
                "content-security-policy": CONSENT_CSP,
                "cache-control": "no-store",
                "x-frame-options": "DENY",
            },
            "body": page,
        }

    def handle_authorize_post(
        self, form: dict[str, str], session: dict[str, Any] | None
    ) -> dict[str, Any]:
        if session is None:
            return self._json_response(
                401, {"error": "access_denied", "error_description": "Login required"}
            )

        expected_csrf = self.csrf_token_for_session(session, "authorize")
        if not hmac.compare_digest(str(form.get("csrf_token") or ""), expected_csrf):
            return self._json_response(
                403, {"error": "invalid_request", "error_description": "Invalid CSRF token"}
            )

        validated, err = self._validate_authorize_params(form)
        if err is not None:
            status, body = err
            return self._json_response(status, body)
        assert validated is not None
        self.touch_client(validated["client_id"])

        decision = (form.get("decision") or "").strip().lower()
        redirect_uri = validated["redirect_uri"]
        state = validated["state"]

        if decision != "approve":
            location = self._append_query_params(
                redirect_uri,
                {"error": "access_denied", "state": state, "iss": self.issuer_url},
            )
            return {
                "statusCode": 303,
                "headers": {
                    "location": location,
                    "content-security-policy": CONSENT_CSP,
                    "cache-control": "no-store",
                },
                "body": "",
            }

        now = self.now()
        raw_code = f"mcpcode_{secrets.token_urlsafe(32)}"
        self.store.put(
            f"CODE#{sha256_hex(raw_code)}",
            {
                "client_id": validated["client_id"],
                "redirect_uri": redirect_uri,
                "code_challenge": validated["code_challenge"],
                "code_challenge_method": "S256",
                "resource": validated["resource"],
                "scope": validated["scope"],
                "sub": session["sub"],
                "email": session["email"],
                "email_verified": True,
                "created_at": now,
                "expires_at": now + AUTH_CODE_TTL_SECONDS,
                "ttl": now + AUTH_CODE_TTL_SECONDS,
                "used": False,
            },
        )
        location = self._append_query_params(
            redirect_uri,
            {"code": raw_code, "state": state, "iss": self.issuer_url},
        )
        return {
            "statusCode": 303,
            "headers": {
                "location": location,
                "content-security-policy": CONSENT_CSP,
                "cache-control": "no-store",
            },
            "body": "",
        }

    # --- Cognito Callback (/auth/callback) ---

    def _default_cognito_exchange(
        self, code: str, code_verifier: str, expected_nonce: str
    ) -> dict[str, Any]:
        token_url = f"{self.cognito_base_url}/oauth2/token"
        form_bytes = urllib.parse.urlencode(
            {
                "grant_type": "authorization_code",
                "client_id": self.cognito_client_id,
                "code": code,
                "redirect_uri": f"{self.issuer_url}/auth/callback",
                "code_verifier": code_verifier,
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            token_url,
            data=form_bytes,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            token_data = json.loads(resp.read().decode("utf-8"))

        id_token = token_data.get("id_token")
        if not id_token:
            raise ValueError("Missing id_token from Cognito")

        if self._cognito_jwks_cache is None:
            jwks_url = f"{self.cognito_issuer_url}/.well-known/jwks.json"
            with urllib.request.urlopen(jwks_url, timeout=10) as jwks_resp:
                self._cognito_jwks_cache = json.loads(jwks_resp.read().decode("utf-8"))

        claims = verify_access_token(
            id_token,
            expected_issuer=self.cognito_issuer_url,
            expected_audience=self.cognito_client_id,
            jwks=self._cognito_jwks_cache,
            now=self.now(),
        )
        if claims.get("nonce") != expected_nonce:
            raise ValueError("Cognito id_token nonce mismatch")
        return claims

    def handle_cognito_callback(self, params: dict[str, str]) -> dict[str, Any]:
        if params.get("error"):
            desc = str(params.get("error_description") or params.get("error") or "Access denied")
            prefix = "Sign-in is restricted to a verified account in the approved Workspace domain"
            return self._json_response(
                403,
                {
                    "error": "access_denied",
                    "error_description": f"{prefix}: {desc}",
                },
            )

        code = (params.get("code") or "").strip()
        state = (params.get("state") or "").strip()
        if not code or not state:
            return self._json_response(
                400, {"error": "invalid_request", "error_description": "Missing code or state"}
            )

        upstream = self.store.consume_once(f"UPSTREAM#{state}", "used")
        if not upstream or self.now() > int(upstream.get("ttl") or 0):
            return self._json_response(
                400, {"error": "invalid_grant", "error_description": "Expired or invalid state"}
            )

        try:
            claims = self.cognito_token_exchanger(
                code, str(upstream["cognito_verifier"]), str(upstream["nonce"])
            )
        except Exception as err:
            return self._json_response(
                400, {"error": "invalid_grant", "error_description": str(err)}
            )

        email = claims.get("email")
        email_verified = claims.get("email_verified")
        if not is_allowed_workspace_email(email, email_verified, self.allowed_domain):
            msg = "Sign-in is restricted to a verified account in the approved Workspace domain"
            return self._json_response(
                403,
                {"error": "access_denied", "error_description": msg},
            )

        cookie_val = self.create_session_cookie_value(
            {"sub": claims["sub"], "email": str(email).strip().lower()}
        )
        cookie_header = (
            f"{SESSION_COOKIE_NAME}={cookie_val}; HttpOnly; Secure; SameSite=Lax; "
            f"Path=/; Max-Age={SESSION_COOKIE_TTL_SECONDS}"
        )

        if upstream.get("kind") == "device":
            user_code = upstream.get("user_code") or ""
            target = (
                f"/device?{urllib.parse.urlencode({'code': user_code})}" if user_code else "/device"
            )
        else:
            auth_params = upstream.get("authorize_params") or {}
            target = f"/oauth/authorize?{urllib.parse.urlencode(auth_params)}"

        return {
            "statusCode": 303,
            "headers": {
                "location": target,
                "set-cookie": cookie_header,
                "cache-control": "no-store",
            },
            "cookies": [cookie_header],
            "body": "",
        }

    # --- Token Endpoint (/oauth/token, AC 5, AC 7, AC 8) ---

    def _issue_human_token_pair(
        self,
        *,
        sub: str,
        email: str,
        client_id: str,
        resource: str,
        scope: str,
        family_id: str | None = None,
    ) -> dict[str, Any]:
        now = self.now()
        jti = secrets.token_urlsafe(16)
        claims = {
            "iss": self.issuer_url,
            "aud": resource,
            "sub": sub,
            "email": email,
            "email_verified": True,
            "scope": scope,
            "client_id": client_id,
            "token_use": "access",
            "iat": now,
            "nbf": now,
            "exp": now + HUMAN_ACCESS_TOKEN_TTL_SECONDS,
            "jti": jti,
        }
        access_token = encode_jwt_rs256(self.signer, claims)
        refresh_token = f"mcpr_{secrets.token_urlsafe(32)}"
        eff_family = family_id or secrets.token_urlsafe(16)
        self.store.put(
            f"REFRESH#{sha256_hex(refresh_token)}",
            {
                "family_id": eff_family,
                "client_id": client_id,
                "resource": resource,
                "scope": scope,
                "sub": sub,
                "email": email,
                "email_verified": True,
                "consumed": False,
                "revoked": False,
                "created_at": now,
                "expires_at": now + REFRESH_TOKEN_TTL_SECONDS,
                "ttl": now + REFRESH_TOKEN_TTL_SECONDS,
            },
        )
        result: dict[str, Any] = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": HUMAN_ACCESS_TOKEN_TTL_SECONDS,
            "refresh_token": refresh_token,
            "scope": scope,
        }
        if "openid" in scope.split():
            id_claims = {
                "iss": self.issuer_url,
                "aud": client_id,
                "sub": sub,
                "email": email,
                "email_verified": True,
                "token_use": "id",
                "iat": now,
                "exp": now + HUMAN_ACCESS_TOKEN_TTL_SECONDS,
            }
            result["id_token"] = encode_jwt_rs256(self.signer, id_claims)
        return result

    def _authenticate_client(
        self, params: dict[str, Any], headers: dict[str, str]
    ) -> tuple[str, str | None]:
        basic = _parse_basic_auth(headers.get("authorization") or "")
        if basic is not None:
            return basic[0], basic[1]
        cid = str(params.get("client_id") or "").strip()
        secret = params.get("client_secret")
        return cid, (str(secret) if secret is not None else None)

    def handle_token(
        self, params: dict[str, Any], headers: dict[str, str]
    ) -> tuple[int, dict[str, Any]]:
        grant_type = str(params.get("grant_type") or "").strip()
        client_id, client_secret = self._authenticate_client(params, headers)

        if grant_type == "authorization_code":
            return self._handle_authorization_code_grant(params, client_id, client_secret)
        if grant_type == "refresh_token":
            return self._handle_refresh_token_grant(params, client_id, client_secret)
        if grant_type == "client_credentials":
            return self._handle_client_credentials_grant(params, client_id, client_secret)
        if grant_type == DEVICE_GRANT_TYPE:
            return self._handle_device_code_grant(params, client_id)
        return 400, {"error": "unsupported_grant_type"}

    def _verify_dcr_client_secret_if_needed(
        self, client: dict[str, Any], provided_secret: str | None
    ) -> bool:
        expected_hash = client.get("client_secret_sha256")
        if not expected_hash:
            return True
        if not provided_secret:
            return False
        return hmac.compare_digest(sha256_hex(provided_secret), str(expected_hash))

    def _handle_authorization_code_grant(
        self, params: dict[str, Any], client_id: str, client_secret: str | None
    ) -> tuple[int, dict[str, Any]]:
        raw_code = str(params.get("code") or "").strip()
        code_verifier = str(params.get("code_verifier") or "").strip()
        if not raw_code or not code_verifier:
            return 400, {
                "error": "invalid_request",
                "error_description": "Missing code or code_verifier",
            }

        code_row = self.store.consume_once(f"CODE#{sha256_hex(raw_code)}", "used")
        if not code_row or self.now() >= int(code_row.get("expires_at") or 0):
            return 400, {"error": "invalid_grant", "error_description": "Invalid or expired code"}

        effective_client_id = client_id or str(code_row["client_id"])
        if effective_client_id != code_row["client_id"]:
            return 400, {"error": "invalid_grant", "error_description": "client_id mismatch"}

        client = self.resolve_client(effective_client_id)
        if not client or not self._verify_dcr_client_secret_if_needed(client, client_secret):
            return 401, {"error": "invalid_client"}

        redirect_uri = str(params.get("redirect_uri") or "").strip()
        if redirect_uri and redirect_uri != code_row["redirect_uri"]:
            return 400, {"error": "invalid_grant", "error_description": "redirect_uri mismatch"}

        if pkce_s256_challenge(code_verifier) != code_row["code_challenge"]:
            return 400, {"error": "invalid_grant", "error_description": "PKCE verification failed"}

        stored_resource = str(code_row["resource"])
        if params.get("resource"):
            try:
                requested_resource = normalize_resource(
                    str(params["resource"]), default_resource=stored_resource
                )
            except ValueError as err:
                return 400, {"error": "invalid_target", "error_description": str(err)}
            if requested_resource != stored_resource:
                return 400, {"error": "invalid_target", "error_description": "Resource mismatch"}

        self.touch_client(effective_client_id)
        tokens = self._issue_human_token_pair(
            sub=str(code_row["sub"]),
            email=str(code_row["email"]),
            client_id=effective_client_id,
            resource=stored_resource,
            scope=str(code_row["scope"]),
        )
        return 200, tokens

    def _handle_refresh_token_grant(
        self, params: dict[str, Any], client_id: str, client_secret: str | None
    ) -> tuple[int, dict[str, Any]]:
        raw_refresh = str(params.get("refresh_token") or "").strip()
        if not raw_refresh:
            return 400, {"error": "invalid_request", "error_description": "Missing refresh_token"}

        pk = f"REFRESH#{sha256_hex(raw_refresh)}"
        existing = self.store.get(pk)
        if not existing:
            return 400, {"error": "invalid_grant"}

        family_id = str(existing["family_id"])
        family_revoked = self.store.get(f"FAMILY#{family_id}")
        if family_revoked and family_revoked.get("revoked"):
            return 400, {
                "error": "invalid_grant",
                "error_description": "Refresh token family revoked",
            }

        if existing.get("consumed"):
            # Replay of a single-use rotating refresh token -> revoke entire family!
            self.store.put(
                f"FAMILY#{family_id}",
                {
                    "revoked": True,
                    "revoked_at": self.now(),
                    "ttl": self.now() + REFRESH_TOKEN_TTL_SECONDS,
                },
            )
            return 400, {
                "error": "invalid_grant",
                "error_description": "Refresh token replay detected",
            }

        if existing.get("revoked") or self.now() >= int(existing.get("expires_at") or 0):
            return 400, {"error": "invalid_grant"}

        effective_client_id = client_id or str(existing["client_id"])
        if effective_client_id != existing["client_id"]:
            return 400, {"error": "invalid_grant", "error_description": "client_id mismatch"}

        client = self.resolve_client(effective_client_id)
        if client and not self._verify_dcr_client_secret_if_needed(client, client_secret):
            return 401, {"error": "invalid_client"}

        stored_resource = str(existing["resource"])
        if params.get("resource"):
            try:
                requested_resource = normalize_resource(
                    str(params["resource"]), default_resource=stored_resource
                )
            except ValueError as err:
                return 400, {"error": "invalid_target", "error_description": str(err)}
            if requested_resource != stored_resource:
                return 400, {"error": "invalid_target", "error_description": "Resource mismatch"}

        consumed_row = self.store.consume_once(pk, "consumed")
        if not consumed_row:
            self.store.put(
                f"FAMILY#{family_id}",
                {
                    "revoked": True,
                    "revoked_at": self.now(),
                    "ttl": self.now() + REFRESH_TOKEN_TTL_SECONDS,
                },
            )
            return 400, {"error": "invalid_grant"}

        self.touch_client(effective_client_id)
        tokens = self._issue_human_token_pair(
            sub=str(existing["sub"]),
            email=str(existing["email"]),
            client_id=effective_client_id,
            resource=stored_resource,
            scope=str(existing["scope"]),
            family_id=family_id,
        )
        return 200, tokens

    def _handle_client_credentials_grant(
        self, params: dict[str, Any], client_id: str, client_secret: str | None
    ) -> tuple[int, dict[str, Any]]:
        if not client_id or not client_secret:
            return 401, {
                "error": "invalid_client",
                "error_description": "Client credentials required",
            }

        # Explicitly reject DCR or public clients attempting client_credentials (AC 8)
        svc = self.resolve_service_client(client_id)
        if not svc:
            if self.resolve_client(client_id):
                return 400, {
                    "error": "unauthorized_client",
                    "error_description": "DCR and public clients cannot use client_credentials",
                }
            return 401, {"error": "invalid_client"}

        expected_hash = str(svc.get("secret_sha256") or "")
        if not expected_hash or not hmac.compare_digest(sha256_hex(client_secret), expected_hash):
            return 401, {"error": "invalid_client"}

        bound_audience = normalize_resource(str(svc["audience"]))
        if params.get("resource") or params.get("audience"):
            raw_res = str(params.get("resource") or params.get("audience"))
            try:
                req_res = normalize_resource(raw_res, default_resource=bound_audience)
            except ValueError as err:
                return 400, {"error": "invalid_target", "error_description": str(err)}
            if req_res != bound_audience:
                return 400, {
                    "error": "invalid_target",
                    "error_description": "Service client is bound to a different audience",
                }

        allowed_scopes = list(svc.get("allowed_scopes") or [])
        raw_scope = str(params.get("scope") or "").strip()
        if raw_scope:
            req_scopes = raw_scope.split()
            if not all(s in allowed_scopes for s in req_scopes):
                return 400, {
                    "error": "invalid_scope",
                    "error_description": (
                        "Requested scope exceeds service client's minimal allowed scopes"
                    ),
                }
            granted_scope = " ".join(req_scopes)
        else:
            granted_scope = " ".join(allowed_scopes)

        ttl = int(svc.get("ttl_seconds") or SERVICE_ACCESS_TOKEN_TTL_SECONDS)
        now = self.now()
        claims = {
            "iss": self.issuer_url,
            "aud": bound_audience,
            "sub": f"service:{client_id}",
            "client_id": client_id,
            "scope": granted_scope,
            "email": None,
            "email_verified": False,
            "token_use": "access",
            "grant_type": "client_credentials",
            "iat": now,
            "nbf": now,
            "exp": now + ttl,
            "jti": secrets.token_urlsafe(16),
        }
        token = encode_jwt_rs256(self.signer, claims)
        return 200, {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": ttl,
            "scope": granted_scope,
        }

    # --- Revocation Endpoint (POST /oauth/revoke, RFC 7009, AC 5) ---

    def handle_revoke(
        self, params: dict[str, Any], headers: dict[str, str]
    ) -> tuple[int, dict[str, Any]]:
        token = str(params.get("token") or "").strip()
        if not token:
            return 200, {}
        client_id, client_secret = self._authenticate_client(params, headers)
        if client_id:
            client = self.resolve_client(client_id)
            if client and not self._verify_dcr_client_secret_if_needed(client, client_secret):
                return 401, {"error": "invalid_client"}

        if token.startswith("mcpr_"):
            pk = f"REFRESH#{sha256_hex(token)}"
            existing = self.store.get(pk)
            if existing:
                existing["revoked"] = True
                self.store.put(pk, existing)
                family_id = existing.get("family_id")
                if family_id:
                    self.store.put(
                        f"FAMILY#{family_id}",
                        {
                            "revoked": True,
                            "revoked_at": self.now(),
                            "ttl": self.now() + REFRESH_TOKEN_TTL_SECONDS,
                        },
                    )
        elif token.count(".") == 2:
            try:
                parts = token.split(".")
                claims = json.loads(b64url_decode(parts[1]).decode("utf-8"))
                jti = claims.get("jti")
                exp = int(claims.get("exp") or (self.now() + HUMAN_ACCESS_TOKEN_TTL_SECONDS))
                if jti:
                    self.store.put(f"REVOKED_JTI#{jti}", {"revoked": True, "ttl": exp})
            except Exception:
                pass
        return 200, {}

    def is_jti_revoked(self, jti: str) -> bool:
        row = self.store.get(f"REVOKED_JTI#{jti}")
        return bool(row and row.get("revoked"))

    # --- Device Authorization Grant (RFC 8628, AC 7) ---

    def _generate_user_code(self) -> str:
        part1 = "".join(secrets.choice(DEVICE_CODE_ALPHABET) for _ in range(4))
        part2 = "".join(secrets.choice(DEVICE_CODE_ALPHABET) for _ in range(4))
        return f"{part1}-{part2}"

    def handle_device_start(self, params: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        client_id = str(params.get("client_id") or "dtc-cli").strip() or "dtc-cli"
        raw_resource = params.get("resource") or params.get("audience")
        default_res = RESOURCE_HUB_API if client_id in {"dtc-cli", "hub-cli"} else RESOURCE_HUB_MCP
        try:
            resource = normalize_resource(
                str(raw_resource) if raw_resource else None,
                default_resource=default_res,
            )
        except ValueError as err:
            return 400, {"error": "invalid_target", "error_description": str(err)}

        try:
            scope = normalize_human_scope(params.get("scope"))
        except ValueError:
            return 400, {"error": "invalid_scope"}

        now = self.now()
        device_code = f"mcpd_{secrets.token_urlsafe(32)}"
        user_code = self._generate_user_code()
        device_hash = sha256_hex(device_code)

        self.store.put(
            f"DEVICE#{device_hash}",
            {
                "user_code": user_code,
                "client_id": client_id,
                "resource": resource,
                "scope": scope,
                "status": "pending",
                "interval": 5,
                "last_polled_at": 0,
                "created_at": now,
                "expires_at": now + DEVICE_CODE_TTL_SECONDS,
                "ttl": now + DEVICE_CODE_TTL_SECONDS,
            },
        )
        self.store.put(
            f"USERCODE#{user_code}",
            {
                "device_code_hash": device_hash,
                "expires_at": now + DEVICE_CODE_TTL_SECONDS,
                "ttl": now + DEVICE_CODE_TTL_SECONDS,
            },
        )
        verification_uri = f"{self.issuer_url}/device"
        return 200, {
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": verification_uri,
            "verification_uri_complete": f"{verification_uri}?code={user_code}",
            "expires_in": DEVICE_CODE_TTL_SECONDS,
            "interval": 5,
        }

    def handle_device_page_get(
        self, params: dict[str, str], session: dict[str, Any] | None
    ) -> dict[str, Any]:
        user_code = (params.get("code") or params.get("user_code") or "").strip().upper()
        if session is None:
            return self._start_cognito_login({"kind": "device", "user_code": user_code})

        csrf = self.csrf_token_for_session(session, "device")
        email_esc = html.escape(str(session["email"]))
        code_esc = html.escape(user_code)
        page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Device Verification · DataTalksClub</title>
  <style>
    body {{
      font-family: system-ui, sans-serif;
      background: #f7f7f5;
      color: #222;
      display: grid;
      place-items: center;
      min-height: 100vh;
      margin: 0;
    }}
    .card {{
      background: #fff;
      border: 1px solid #e2e2dd;
      border-radius: 12px;
      padding: 28px;
      max-width: 440px;
      width: 100%;
    }}
    input[type=text] {{
      width: 100%;
      padding: 10px;
      font-size: 18px;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      margin: 12px 0;
      box-sizing: border-box;
    }}
    .actions {{ display: flex; gap: 12px; margin-top: 16px; }}
    button {{
      flex: 1;
      padding: 10px 16px;
      border-radius: 6px;
      font-weight: 600;
      cursor: pointer;
      border: 1px solid transparent;
    }}
    .approve {{ background: #1f6f64; color: #fff; }}
    .deny {{ background: #fff; color: #444; border-color: #ccc; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Confirm CLI Device Login</h1>
    <p>Signed in as <strong>{email_esc}</strong></p>
    <form method="post" action="/device">
      <input type="hidden" name="csrf_token" value="{html.escape(csrf)}">
      <label for="user_code">Device Code</label>
      <input id="user_code" type="text" name="user_code" value="{code_esc}" required>
      <div class="actions">
        <button class="approve" type="submit" name="decision" value="approve">Approve</button>
        <button class="deny" type="submit" name="decision" value="deny">Deny</button>
      </div>
    </form>
  </div>
</body>
</html>"""
        return {
            "statusCode": 200,
            "headers": {"content-type": "text/html; charset=utf-8", "cache-control": "no-store"},
            "body": page,
        }

    def handle_device_page_post(
        self, form: dict[str, str], session: dict[str, Any] | None
    ) -> dict[str, Any]:
        if session is None:
            return self._json_response(401, {"error": "access_denied"})
        expected_csrf = self.csrf_token_for_session(session, "device")
        if not hmac.compare_digest(str(form.get("csrf_token") or ""), expected_csrf):
            return self._json_response(403, {"error": "invalid_request"})

        user_code = str(form.get("user_code") or form.get("code") or "").strip().upper()
        lookup = self.store.get(f"USERCODE#{user_code}")
        if not lookup or self.now() >= int(lookup.get("expires_at") or 0):
            return self._json_response(
                400, {"error": "expired_token", "error_description": "Invalid or expired user_code"}
            )

        dev_pk = f"DEVICE#{lookup['device_code_hash']}"
        device_row = self.store.get(dev_pk)
        if not device_row or self.now() >= int(device_row.get("expires_at") or 0):
            return self._json_response(400, {"error": "expired_token"})

        decision = str(form.get("decision") or "approve").strip().lower()
        if decision == "approve":
            device_row["status"] = "approved"
            device_row["sub"] = session["sub"]
            device_row["email"] = session["email"]
            device_row["email_verified"] = True
            msg = "Device login approved. You may close this window and return to your terminal."
        else:
            device_row["status"] = "denied"
            msg = "Device login denied."
        self.store.put(dev_pk, device_row)
        return {
            "statusCode": 200,
            "headers": {"content-type": "text/html; charset=utf-8", "cache-control": "no-store"},
            "body": f"<!doctype html><html><body><p>{html.escape(msg)}</p></body></html>",
        }

    def _handle_device_code_grant(
        self, params: dict[str, Any], client_id: str
    ) -> tuple[int, dict[str, Any]]:
        raw_device = str(params.get("device_code") or "").strip()
        if not raw_device:
            return 400, {"error": "invalid_request", "error_description": "Missing device_code"}

        dev_pk = f"DEVICE#{sha256_hex(raw_device)}"
        device_row = self.store.get(dev_pk)
        if not device_row:
            return 400, {"error": "invalid_grant"}

        now = self.now()
        if now >= int(device_row.get("expires_at") or 0):
            return 400, {"error": "expired_token"}

        status = device_row.get("status")
        if status == "denied":
            return 400, {"error": "access_denied"}
        if status == "consumed":
            return 400, {"error": "invalid_grant"}
        if status == "pending":
            last_polled = int(device_row.get("last_polled_at") or 0)
            interval = int(device_row.get("interval") or 5)
            if last_polled > 0 and (now - last_polled) < interval:
                device_row["interval"] = interval + 5
                device_row["last_polled_at"] = now
                self.store.put(dev_pk, device_row)
                return 400, {"error": "slow_down"}
            device_row["last_polled_at"] = now
            self.store.put(dev_pk, device_row)
            return 400, {"error": "authorization_pending"}

        if status == "approved":
            device_row["status"] = "consumed"
            self.store.put(dev_pk, device_row)
            eff_client = client_id or str(device_row.get("client_id") or "dtc-cli")
            stored_resource = str(device_row["resource"])
            if params.get("resource"):
                try:
                    req_res = normalize_resource(
                        str(params["resource"]), default_resource=stored_resource
                    )
                except ValueError as err:
                    return 400, {"error": "invalid_target", "error_description": str(err)}
                if req_res != stored_resource:
                    return 400, {
                        "error": "invalid_target",
                        "error_description": "Resource mismatch",
                    }
            tokens = self._issue_human_token_pair(
                sub=str(device_row["sub"]),
                email=str(device_row["email"]),
                client_id=eff_client,
                resource=stored_resource,
                scope=str(device_row["scope"]),
            )
            return 200, tokens

        return 400, {"error": "invalid_grant"}

    # --- HTTP Request Dispatcher (API Gateway V2 PayloadFormatVersion 2.0) ---

    @staticmethod
    def _append_query_params(url: str, extra: dict[str, str]) -> str:
        split = urllib.parse.urlsplit(url)
        existing = urllib.parse.parse_qsl(split.query, keep_blank_values=True)
        for k, v in extra.items():
            if v is not None and v != "":
                existing.append((k, v))
        new_query = urllib.parse.urlencode(existing)
        return urllib.parse.urlunsplit((split.scheme, split.netloc, split.path, new_query, ""))

    @staticmethod
    def _json_response(
        status: int, body: dict[str, Any], extra_headers: dict[str, str] | None = None
    ) -> dict[str, Any]:
        headers = {"content-type": "application/json; charset=utf-8", **CORS_HEADERS}
        if extra_headers:
            headers.update(extra_headers)
        return {
            "statusCode": status,
            "headers": headers,
            "body": json.dumps(body),
        }

    def _extract_session(
        self, event: dict[str, Any], headers: dict[str, str]
    ) -> dict[str, Any] | None:
        raw_cookies: list[str] = list(event.get("cookies") or [])
        if "cookie" in headers:
            raw_cookies.extend(part.strip() for part in headers["cookie"].split(";"))
        for item in raw_cookies:
            if item.startswith(f"{SESSION_COOKIE_NAME}="):
                val = item[len(SESSION_COOKIE_NAME) + 1 :].split(";")[0].strip()
                verified = self.verify_session_cookie_value(val)
                if verified:
                    return verified
        return None

    @staticmethod
    def _parse_body(event: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
        raw_body = event.get("body") or ""
        if event.get("isBase64Encoded") and raw_body:
            raw_body = base64.b64decode(raw_body).decode("utf-8", errors="replace")
        if not raw_body:
            return {}
        ctype = (headers.get("content-type") or "").lower()
        if "application/x-www-form-urlencoded" in ctype:
            return dict(urllib.parse.parse_qsl(raw_body, keep_blank_values=True))
        try:
            parsed = json.loads(raw_body)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
        return dict(urllib.parse.parse_qsl(raw_body, keep_blank_values=True))

    def dispatch(self, event: dict[str, Any]) -> dict[str, Any]:
        req_ctx = event.get("requestContext") or {}
        http_ctx = req_ctx.get("http") or {}
        method = str(http_ctx.get("method") or event.get("httpMethod") or "GET").upper()
        path = str(event.get("rawPath") or http_ctx.get("path") or event.get("path") or "/")
        headers = {str(k).lower(): str(v) for k, v in (event.get("headers") or {}).items()}
        raw_qs = event.get("rawQueryString")
        if raw_qs is not None:
            query_params = dict(urllib.parse.parse_qsl(raw_qs, keep_blank_values=True))
        else:
            query_params = {
                str(k): str(v) for k, v in (event.get("queryStringParameters") or {}).items()
            }

        if method == "OPTIONS":
            return {"statusCode": 204, "headers": dict(CORS_HEADERS), "body": ""}

        if path in {"/", "/healthz"} and method == "GET":
            return self._json_response(
                200, {"ok": True, "service": "dtc-shared-oauth", "issuer": self.issuer_url}
            )

        if (
            path.startswith("/.well-known/oauth-authorization-server")
            or path.startswith("/.well-known/openid-configuration")
        ) and method in {"GET", "HEAD"}:
            return self._json_response(200, self.discovery_metadata())

        if path.startswith("/.well-known/oauth-protected-resource") and method in {"GET", "HEAD"}:
            return self._json_response(200, self.protected_resource_metadata(RESOURCE_HUB_MCP))

        if path in {"/.well-known/jwks.json", "/oauth/jwks.json"} and method in {"GET", "HEAD"}:
            return self._json_response(200, self.jwks_document())

        if path == "/mcp":
            auth_hdr = headers.get("authorization") or ""
            prm_url = f"{self.issuer_url}/.well-known/oauth-protected-resource/mcp"
            if not auth_hdr.lower().startswith("bearer "):
                www_auth = f'Bearer resource_metadata="{prm_url}", scope="mcp admin"'
                return self._json_response(
                    401,
                    {"error": "unauthorized", "error_description": "Bearer token required"},
                    extra_headers={"www-authenticate": www_auth},
                )
            token_str = auth_hdr[7:].strip()
            try:
                claims = verify_access_token(
                    token_str,
                    expected_issuer=self.issuer_url,
                    expected_audience=CANONICAL_RESOURCES,
                    jwks=self.jwks_document(),
                    now=self.now(),
                    is_revoked_jti=self.is_jti_revoked,
                )
                return self._json_response(
                    200, {"ok": True, "sub": claims.get("sub"), "aud": claims.get("aud")}
                )
            except ValueError as err:
                www_err = f'Bearer resource_metadata="{prm_url}", error="invalid_token"'
                return self._json_response(
                    401,
                    {"error": "invalid_token", "error_description": str(err)},
                    extra_headers={"www-authenticate": www_err},
                )

        if path == "/oauth/register" and method == "POST":
            body = self._parse_body(event, headers)
            status, resp_body = self.handle_register(body)
            return self._json_response(status, resp_body)

        if path == "/oauth/authorize":
            session = self._extract_session(event, headers)
            if method == "GET":
                return self.handle_authorize_get(query_params, session)
            if method == "POST":
                form = self._parse_body(event, headers)
                return self.handle_authorize_post(form, session)

        if path == "/auth/callback" and method == "GET":
            return self.handle_cognito_callback(query_params)

        if path in {"/oauth/token", "/api/auth/device/token"} and method == "POST":
            body = self._parse_body(event, headers)
            status, resp_body = self.handle_token(body, headers)
            return self._json_response(status, resp_body)

        if path == "/oauth/revoke" and method == "POST":
            body = self._parse_body(event, headers)
            status, resp_body = self.handle_revoke(body, headers)
            return self._json_response(status, resp_body)

        if path in {"/oauth/device", "/api/auth/device"} and method == "POST":
            body = self._parse_body(event, headers)
            status, resp_body = self.handle_device_start(body)
            return self._json_response(status, resp_body)

        if path == "/device":
            session = self._extract_session(event, headers)
            if method == "GET":
                return self.handle_device_page_get(query_params, session)
            if method == "POST":
                form = self._parse_body(event, headers)
                return self.handle_device_page_post(form, session)

        return self._json_response(404, {"error": "not_found"})


_CACHED_SERVER: OAuthServer | None = None


def _build_default_server() -> OAuthServer:
    import boto3

    region = os.environ.get("AWS_REGION", "us-east-1")
    ddb = boto3.resource("dynamodb", region_name=region)
    kms = boto3.client("kms", region_name=region)
    sm = boto3.client("secretsmanager", region_name=region)

    table_name = os.environ["OAUTH_TABLE_NAME"]
    signing_key_id = os.environ["SIGNING_KEY_ID"]
    session_secret_arn = os.environ["SESSION_SECRET_ARN"]
    service_clients_secret_arn = os.environ.get("SERVICE_CLIENTS_SECRET_ARN", "")

    session_secret = sm.get_secret_value(SecretId=session_secret_arn)["SecretString"]
    service_clients: dict[str, dict[str, Any]] = {}
    if service_clients_secret_arn:
        try:
            raw_svc = sm.get_secret_value(SecretId=service_clients_secret_arn)["SecretString"]
            parsed = json.loads(raw_svc)
            if isinstance(parsed, dict):
                service_clients = parsed
        except Exception:
            service_clients = {}

    return OAuthServer(
        issuer_url=os.environ.get("ISSUER_URL", "https://oauth.dtcdev.click"),
        cognito_base_url=os.environ.get("COGNITO_BASE_URL", "https://auth.dtcdev.click"),
        cognito_issuer_url=os.environ.get(
            "COGNITO_ISSUER_URL", "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_H7nJu52Bs"
        ),
        cognito_client_id=os.environ["COGNITO_CLIENT_ID"],
        allowed_domain=os.environ.get("ALLOWED_GOOGLE_DOMAIN", "datatalks.club"),
        store=DynamoDBOAuthStore(ddb.Table(table_name)),
        signer=KmsRs256Signer(kms, signing_key_id),
        session_secret=session_secret,
        service_clients=service_clients,
    )


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    global _CACHED_SERVER
    if _CACHED_SERVER is None:
        _CACHED_SERVER = _build_default_server()
    return _CACHED_SERVER.dispatch(event)
