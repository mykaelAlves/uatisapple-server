import os
import stat
import uuid

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from src.crypto import (
    RSA_KEY_SIZE,
    ServerIdentity,
    derive_s2c_key,
    handshake_digest,
    load_or_create_identity,
)


def raw_pk(sk: X25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def test_identity_is_persisted_with_restricted_permissions(tmp_path):
    first = load_or_create_identity(tmp_path)
    key_mode = stat.S_IMODE(os.stat(tmp_path / "server.key").st_mode)
    assert key_mode == 0o600
    assert (tmp_path / "server.crt").exists()

    second = load_or_create_identity(tmp_path)
    assert second.certificate_der == first.certificate_der


def test_certificate_is_self_signed_rsa(identity: ServerIdentity):
    cert = identity.certificate
    assert cert.issuer == cert.subject
    public_key = cert.public_key()
    assert isinstance(public_key, rsa.RSAPublicKey)
    assert public_key.key_size == RSA_KEY_SIZE >= 2048


def test_handshake_signature_verifies(identity: ServerIdentity):
    pk_s, pk_c = (
        raw_pk(X25519PrivateKey.generate()),
        raw_pk(X25519PrivateKey.generate()),
    )
    client_id, salt = uuid.uuid4().bytes, os.urandom(16)
    signature = identity.sign_handshake(pk_s, pk_c, client_id, salt)
    public_key = identity.certificate.public_key()
    assert isinstance(public_key, rsa.RSAPublicKey)
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)

    digest = handshake_digest(pk_s, pk_c, client_id, salt)
    public_key.verify(signature, digest, pss, utils.Prehashed(hashes.SHA256()))
    public_key.verify(signature, pk_s + pk_c + client_id + salt, pss, hashes.SHA256())

    with pytest.raises(InvalidSignature):
        public_key.verify(
            signature, pk_s + os.urandom(32) + client_id + salt, pss, hashes.SHA256()
        )


def test_s2c_key_matches_client_derivation():
    sk_s, sk_c = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    salt = os.urandom(16)
    server_key = derive_s2c_key(sk_s, raw_pk(sk_c), salt)

    shared = sk_c.exchange(sk_s.public_key())
    client_key = HKDF(
        algorithm=hashes.SHA256(), length=16, salt=salt, info=b"S2C"
    ).derive(shared)
    assert server_key == client_key
    assert len(server_key) == 16


def test_s2c_key_rejects_low_order_point():
    with pytest.raises(ValueError):
        derive_s2c_key(X25519PrivateKey.generate(), bytes(32), os.urandom(16))
