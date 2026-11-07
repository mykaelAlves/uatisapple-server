import datetime
import hashlib
import os
import struct
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID
from loguru import logger

RSA_KEY_SIZE = 3072
CERT_VALIDITY_DAYS = 365
SALT_SIZE = 16
KEY_SIZE = 16
X25519_KEY_SIZE = 32
GCM_TAG_SIZE = 16
NONCE_SIZE = 12
SEQ_SIZE = 8

S2C_INFO = b"S2C"
DIRECTION_S2C = b"\x00\x00\x00\x01"

PSS_PADDING = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH
)


def fingerprint(data: bytes) -> str:
    """Fingerprint curto (SHA-256) para logs. Nunca logar a chave em si."""
    return hashlib.sha256(data).hexdigest()[:16]


@dataclass(frozen=True)
class ServerIdentity:
    private_key: rsa.RSAPrivateKey
    certificate: x509.Certificate

    @property
    def certificate_der(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.DER)

    @property
    def certificate_fingerprint(self) -> str:
        return hashlib.sha256(self.certificate_der).hexdigest()

    def sign_handshake(
        self, pk_server: bytes, pk_client: bytes, client_id: bytes, salt: bytes
    ) -> bytes:
        """Assina H = SHA256(pk_S || pk_C || client_id || salt) com RSA-PSS(SHA256)."""
        digest = handshake_digest(pk_server, pk_client, client_id, salt)
        return self.private_key.sign(
            digest, PSS_PADDING, utils.Prehashed(hashes.SHA256())
        )


def handshake_digest(
    pk_server: bytes, pk_client: bytes, client_id: bytes, salt: bytes
) -> bytes:
    return hashlib.sha256(pk_server + pk_client + client_id + salt).digest()


def _generate_identity(common_name: str) -> ServerIdentity:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=CERT_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    return ServerIdentity(private_key, certificate)


def load_or_create_identity(
    cert_dir: Path, common_name: str = "uatisapple-server"
) -> ServerIdentity:
    """Carrega `server.key`/`server.crt` de `cert_dir` ou gera um novo par.

    O `server.crt` deve ser distribuído aos clientes fora do canal (pinning).
    O `server.key` é gravado com permissão 0600 e nunca deve ser versionado.
    """
    key_path = cert_dir / "server.key"
    cert_path = cert_dir / "server.crt"

    if key_path.exists() and cert_path.exists():
        private_key = serialization.load_pem_private_key(
            key_path.read_bytes(), password=None
        )
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError(f"{key_path} não contém uma chave RSA")
        certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
        if certificate.public_key() != private_key.public_key():
            raise ValueError(f"{cert_path} não corresponde a {key_path}")
        logger.info(f"Chave e certificado carregados de {cert_dir}.")
        return ServerIdentity(private_key, certificate)

    logger.info(f"Gerando par RSA-{RSA_KEY_SIZE} e certificado autoassinado...")
    identity = _generate_identity(common_name)
    cert_dir.mkdir(parents=True, exist_ok=True)

    key_bytes = identity.private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key_bytes)
    cert_path.write_bytes(identity.certificate.public_bytes(serialization.Encoding.PEM))
    logger.info(f"Chave e certificado salvos em {cert_dir}.")
    return identity


def derive_s2c_key(sk_server: X25519PrivateKey, pk_client: bytes, salt: bytes) -> bytes:
    """Key_S2C = HKDF-Expand(HKDF-Extract(salt, X25519(sk_S, pk_C)), "S2C", 16).

    Levanta `ValueError` se `pk_client` for inválida (ex.: ponto de ordem baixa).
    """
    shared = sk_server.exchange(X25519PublicKey.from_public_bytes(pk_client))
    return HKDF(
        algorithm=hashes.SHA256(), length=KEY_SIZE, salt=salt, info=S2C_INFO
    ).derive(shared)


def s2c_nonce(seq_no: int) -> bytes:
    """Nonce das mensagens administrativas: direction(0x00000001) || seq_no (BE)."""
    return DIRECTION_S2C + struct.pack(">Q", seq_no)


def encrypt_admin(key: bytes, seq_no: int, plaintext: bytes, aad: bytes) -> bytes:
    """Retorna ciphertext || tag (16 bytes)."""
    return AESGCM(key).encrypt(s2c_nonce(seq_no), plaintext, aad)
