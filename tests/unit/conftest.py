"""Shared unit-test fixtures: a fresh Ed25519 signing key per test module.

Unit tests never touch files, network, or environment secrets; the key is
generated in memory (operator tooling path, never committed).
"""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from taxstamps.crypto.eddsa import SigningKey


@pytest.fixture(scope="session")
def signing_key() -> SigningKey:
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    return SigningKey(kid="blueeconomy-tax-stamps-0", private_key=load_pem_private_key(pem, None))
