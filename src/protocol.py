import struct
import uuid
from dataclasses import dataclass
from enum import IntEnum

from src.crypto import (
    GCM_TAG_SIZE,
    NONCE_SIZE,
    SALT_SIZE,
    SEQ_SIZE,
    X25519_KEY_SIZE,
    encrypt_admin,
)

CLIENT_ID_SIZE = 16
MAX_PLAINTEXT_SIZE = 4096


E2E_HEADER_SIZE = NONCE_SIZE + 2 * CLIENT_ID_SIZE + SEQ_SIZE
E2E_MIN_SIZE = E2E_HEADER_SIZE + GCM_TAG_SIZE
E2E_MAX_SIZE = E2E_HEADER_SIZE + MAX_PLAINTEXT_SIZE + GCM_TAG_SIZE

CLIENT_HELLO_SIZE = CLIENT_ID_SIZE + X25519_KEY_SIZE


MAX_CLIENT_FRAME_SIZE = 1 + max(E2E_MAX_SIZE, CLIENT_HELLO_SIZE)

MAX_SERVER_FRAME_SIZE = 64 * 1024

SEQ = struct.Struct(">Q")
U16 = struct.Struct(">H")


class MsgType(IntEnum):
    CLIENT_HELLO = 0x01
    SERVER_HELLO = 0x02
    E2E = 0x10
    ADMIN = 0x20


class AdminType(IntEnum):
    REGISTERED = 0x01
    PEER_LIST = 0x02
    PEER_JOINED = 0x03
    PEER_LEFT = 0x04
    ERROR = 0x05
    DISCONNECT = 0x06


class ErrorCode(IntEnum):
    FRAMING = 0x01
    INVALID_MESSAGE = 0x02
    UNKNOWN_RECIPIENT = 0x03
    SENDER_MISMATCH = 0x04
    REPLAY = 0x05
    DUPLICATE_CLIENT_ID = 0x06
    SERVER_FULL = 0x07


class DisconnectReason(IntEnum):
    PROTOCOL_ERROR = 0x01
    SERVER_SHUTDOWN = 0x02


class ProtocolError(Exception):
    """Mensagem malformada ou inesperada."""


@dataclass(frozen=True)
class ClientHello:
    client_id: uuid.UUID
    public_key: bytes


@dataclass(frozen=True)
class E2EHeader:
    sender_id: uuid.UUID
    recipient_id: uuid.UUID
    seq_no: int
    payload_size: int


@dataclass(frozen=True)
class PeerInfo:
    client_id: uuid.UUID
    public_key: bytes
    pair_salt: bytes

    def encode(self) -> bytes:
        return self.client_id.bytes + self.public_key + self.pair_salt


def split_type(frame: bytes) -> tuple[int, bytes]:
    return frame[0], frame[1:]


def parse_client_id(raw: bytes) -> uuid.UUID:
    client_id = uuid.UUID(bytes=raw)
    if client_id.version != 4:
        raise ProtocolError("client_id não é um UUID v4")
    return client_id


def parse_client_hello(frame: bytes) -> ClientHello:
    """CLIENT_HELLO: 0x01 || client_id (16B) || pk_C (32B, X25519 raw)."""
    msg_type, body = split_type(frame)
    if msg_type != MsgType.CLIENT_HELLO:
        raise ProtocolError(f"esperado CLIENT_HELLO, recebido tipo 0x{msg_type:02x}")
    if len(body) != CLIENT_HELLO_SIZE:
        raise ProtocolError(
            f"CLIENT_HELLO com {len(body)} bytes (esperado {CLIENT_HELLO_SIZE})"
        )
    return ClientHello(
        client_id=parse_client_id(body[:CLIENT_ID_SIZE]),
        public_key=body[CLIENT_ID_SIZE:],
    )


def build_server_hello(
    pk_server: bytes, salt: bytes, signature: bytes, certificate_der: bytes
) -> bytes:
    """SERVER_HELLO: 0x02 || pk_S (32) || salt (16) || len(sig) (2) || sig
    || len(cert) (2) || cert (DER)."""
    assert len(pk_server) == X25519_KEY_SIZE and len(salt) == SALT_SIZE
    return (
        bytes([MsgType.SERVER_HELLO])
        + pk_server
        + salt
        + U16.pack(len(signature))
        + signature
        + U16.pack(len(certificate_der))
        + certificate_der
    )


def parse_e2e_header(frame: bytes) -> E2EHeader:
    """Lê apenas o cabeçalho de roteamento do frame E2E (o conteúdo é opaco).

    Levanta `ProtocolError` se o tamanho do frame estiver fora dos limites.
    """
    body = frame[1:]
    if not E2E_MIN_SIZE <= len(body) <= E2E_MAX_SIZE:
        raise ProtocolError(
            f"frame E2E com {len(body)} bytes "
            f"(esperado entre {E2E_MIN_SIZE} e {E2E_MAX_SIZE})"
        )
    offset = NONCE_SIZE
    sender = uuid.UUID(bytes=body[offset : offset + CLIENT_ID_SIZE])
    offset += CLIENT_ID_SIZE
    recipient = uuid.UUID(bytes=body[offset : offset + CLIENT_ID_SIZE])
    offset += CLIENT_ID_SIZE
    (seq_no,) = SEQ.unpack_from(body, offset)
    return E2EHeader(sender, recipient, seq_no, len(body) - E2E_HEADER_SIZE)


def build_admin(
    key: bytes, seq_no: int, admin_type: AdminType, payload: bytes
) -> bytes:
    """ADMIN: 0x20 || seq_no (8) || AES-128-GCM(Key_S2C, nonce, admin_type || payload).

    nonce = 0x00000001 || seq_no ; AAD = 0x20 || seq_no.
    """
    header = bytes([MsgType.ADMIN]) + SEQ.pack(seq_no)
    return header + encrypt_admin(key, seq_no, bytes([admin_type]) + payload, header)


def peer_list_payload(peers: list[PeerInfo]) -> bytes:
    return U16.pack(len(peers)) + b"".join(p.encode() for p in peers)


def peer_joined_payload(peer: PeerInfo) -> bytes:
    return peer.encode()


def peer_left_payload(client_id: uuid.UUID) -> bytes:
    return client_id.bytes


def error_payload(code: ErrorCode, message: str) -> bytes:
    return bytes([code]) + message.encode()


def disconnect_payload(reason: DisconnectReason, message: str) -> bytes:
    return bytes([reason]) + message.encode()
