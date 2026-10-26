#!/usr/bin/env python3
"""Idempotently provision confidential service clients in Secrets Manager and DynamoDB.

Never prints client secrets. Fails closed outside AWS sandbox account 817685572750.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
from typing import Any

SANDBOX_ACCOUNT_ID = "817685572750"
DEFAULT_SECRET_NAME = "dtcdev-shared-auth/service-clients"
DEFAULT_TABLE_NAME = "dtcdev-shared-auth-oauth"

SERVICE_CLIENT_CATALOG: dict[str, dict[str, Any]] = {
    "mcp-auth-test-service": {
        "audience": "https://hub.dtcdev.click/mcp",
        "allowed_scopes": ["mcp:ping"],
        "ttl_seconds": 900,
        "description": "Live verification confidential service client (AC 8 / AC 10)",
    },
    "dataops-invoice-reader": {
        "audience": "https://ops.dtcdev.click",
        "allowed_scopes": ["invoice:read"],
        "ttl_seconds": 900,
        "description": "Replaces dops_svc_ INVOICE_READER_TOKEN_SHA256 in 151a4c6c",
    },
    "dataops-automation-service": {
        "audience": "https://ops.dtcdev.click",
        "allowed_scopes": ["dataops:read", "dataops:write"],
        "ttl_seconds": 900,
        "description": "Confidential service client for DataOps API automation",
    },
    "hub-fleet-host": {
        "audience": "https://hub.dtcdev.click",
        "allowed_scopes": ["hub:host"],
        "ttl_seconds": 900,
        "description": "Replaces Hub fleet host controller credential in 151a4c6c",
    },
    "hub-fleet-agent": {
        "audience": "https://hub.dtcdev.click",
        "allowed_scopes": ["hub:agent"],
        "ttl_seconds": 900,
        "description": "Replaces Hub agent session credential in 151a4c6c",
    },
    "hub-admin-service": {
        "audience": "https://hub.dtcdev.click",
        "allowed_scopes": ["hub:admin", "admin"],
        "ttl_seconds": 900,
        "description": "Confidential service client for Hub automation callers",
    },
}


def _sha256_hex(val: str) -> str:
    return hashlib.sha256(val.encode("utf-8")).hexdigest()


def build_updated_service_clients(
    existing_map: dict[str, Any],
    catalog: dict[str, dict[str, Any]] = SERVICE_CLIENT_CATALOG,
) -> tuple[dict[str, dict[str, Any]], bool]:
    """Merge catalog with existing Secrets Manager entries, preserving existing secrets."""
    updated: dict[str, dict[str, Any]] = {}
    changed = False
    for client_id, spec in catalog.items():
        prev = existing_map.get(client_id) if isinstance(existing_map, dict) else None
        raw_secret = (
            prev.get("client_secret")
            if isinstance(prev, dict)
            and isinstance(prev.get("client_secret"), str)
            and prev.get("client_secret", "").startswith("dtcsvc_")
            else None
        )
        if not raw_secret:
            raw_secret = f"dtcsvc_{secrets.token_urlsafe(32)}"
            changed = True
        secret_hash = _sha256_hex(raw_secret)
        entry = {
            "client_id": client_id,
            "client_secret": raw_secret,
            "secret_sha256": secret_hash,
            "audience": spec["audience"],
            "allowed_scopes": list(spec["allowed_scopes"]),
            "ttl_seconds": int(spec["ttl_seconds"]),
            "registration_source": "admin_service",
            "description": spec.get("description", ""),
        }
        if prev != entry:
            changed = True
        updated[client_id] = entry
    return updated, changed


def provision_live(region: str, secret_id: str, table_name: str) -> None:
    import boto3

    account = boto3.client("sts", region_name=region).get_caller_identity()["Account"]
    assert account == SANDBOX_ACCOUNT_ID, f"Refusing to run outside {SANDBOX_ACCOUNT_ID}"

    sm = boto3.client("secretsmanager", region_name=region)
    ddb = boto3.resource("dynamodb", region_name=region)
    table = ddb.Table(table_name)

    existing_map: dict[str, Any] = {}
    try:
        raw = sm.get_secret_value(SecretId=secret_id).get("SecretString") or "{}"
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            existing_map = parsed
    except Exception:
        existing_map = {}

    updated_map, changed = build_updated_service_clients(existing_map)
    if changed:
        sm.put_secret_value(SecretId=secret_id, SecretString=json.dumps(updated_map))

    # Sync hash-only records to DynamoDB (never store plaintext secret in DynamoDB)
    for client_id, entry in updated_map.items():
        table.put_item(
            Item={
                "pk": f"SERVICE_CLIENT#{client_id}",
                "client_id": client_id,
                "secret_sha256": entry["secret_sha256"],
                "audience": entry["audience"],
                "allowed_scopes": entry["allowed_scopes"],
                "ttl_seconds": entry["ttl_seconds"],
                "registration_source": "admin_service",
                "description": entry["description"],
            }
        )
        print(
            f"provisioned service client: {client_id} "
            f"(aud={entry['audience']}, scopes={entry['allowed_scopes']}, "
            f"ttl={entry['ttl_seconds']}s)"
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--secret-id", default=DEFAULT_SECRET_NAME)
    parser.add_argument("--table-name", default=DEFAULT_TABLE_NAME)
    args = parser.parse_args()
    provision_live(args.region, args.secret_id, args.table_name)


if __name__ == "__main__":
    main()
