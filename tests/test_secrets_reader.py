import base64
import json
from types import SimpleNamespace

import pytest

from src.dataops_secrets import SecretReader


def test_reader_binds_decrypt_to_secret_and_returns_exact_value():
    calls = []

    def get_item(**kwargs):
        calls.append(kwargs)
        return {"Item": {"data": {"S": base64.b64encode(b"cipher").decode()}}}

    def decrypt(**kwargs):
        calls.append(kwargs)
        return {"Plaintext": json.dumps({"value": "original\n"}).encode()}

    reader = SecretReader(
        table_name="team", key_id="key", region="eu-west-1",
        dynamodb=SimpleNamespace(get_item=get_item), kms=SimpleNamespace(decrypt=decrypt),
    )
    assert reader.read("auth.session") == {"value": "original\n"}
    assert calls[0]["Key"]["SK"] == {"S": "SECRET#auth.session"}
    assert calls[0]["ConsistentRead"] is True
    assert calls[1]["EncryptionContext"] == {"secret": "auth.session"}
    assert calls[1]["KeyId"] == "key"


def test_missing_secret_fails_without_decrypt():
    reader = SecretReader(
        table_name="team", key_id="key", region="eu-west-1",
        dynamodb=SimpleNamespace(get_item=lambda **_: {}), kms=object(),
    )
    with pytest.raises(ValueError, match="does not exist"):
        reader.read("auth.session")
