import struct
import uuid

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.protocol import (
    E2E_MAX_SIZE,
    E2E_MIN_SIZE,
    AdminType,
    MsgType,
    PeerInfo,
    ProtocolError,
    build_admin,
    build_server_hello,
    parse_client_hello,
    parse_e2e_header,
    peer_list_payload,
)


def hello(client_id: bytes, pk: bytes = b"k" * 32) -> bytes:
    return bytes([MsgType.CLIENT_HELLO]) + client_id + pk


def test_parse_client_hello():
    cid = uuid.uuid4()
    parsed = parse_client_hello(hello(cid.bytes))
    assert parsed.client_id == cid
    assert parsed.public_key == b"k" * 32


@pytest.mark.parametrize(
    "frame",
    [
        pytest.param(hello(uuid.uuid4().bytes)[:-1], id="curto"),
        pytest.param(hello(uuid.uuid4().bytes) + b"x", id="longo"),
        pytest.param(b"\x10" + hello(uuid.uuid4().bytes)[1:], id="tipo-errado"),
        pytest.param(hello(uuid.uuid1().bytes), id="uuid-v1"),
    ],
)
def test_parse_client_hello_rejects_invalid(frame: bytes):
    with pytest.raises(ProtocolError):
        parse_client_hello(frame)


def test_build_server_hello_layout():
    sig, cert = b"s" * 384, b"c" * 700
    frame = build_server_hello(b"p" * 32, b"t" * 16, sig, cert)
    assert frame[0] == MsgType.SERVER_HELLO
    assert frame[1:33] == b"p" * 32
    assert frame[33:49] == b"t" * 16
    assert struct.unpack(">H", frame[49:51])[0] == len(sig)
    assert frame[51 : 51 + len(sig)] == sig
    assert struct.unpack(">H", frame[51 + len(sig) : 53 + len(sig)])[0] == len(cert)
    assert frame[53 + len(sig) :] == cert


def e2e_frame(payload_size: int, seq_no: int = 7) -> tuple[bytes, uuid.UUID, uuid.UUID]:
    sender, recipient = uuid.uuid4(), uuid.uuid4()
    frame = (
        bytes([MsgType.E2E])
        + b"n" * 12
        + sender.bytes
        + recipient.bytes
        + struct.pack(">Q", seq_no)
        + b"c" * payload_size
    )
    return frame, sender, recipient


def test_parse_e2e_header():
    frame, sender, recipient = e2e_frame(16 + 5, seq_no=2**63)
    header = parse_e2e_header(frame)
    assert header.sender_id == sender
    assert header.recipient_id == recipient
    assert header.seq_no == 2**63
    assert header.payload_size == 21


@pytest.mark.parametrize("body_size", [E2E_MIN_SIZE, E2E_MAX_SIZE])
def test_parse_e2e_header_accepts_bounds(body_size: int):
    frame, _, _ = e2e_frame(body_size - 52)
    parse_e2e_header(frame)


@pytest.mark.parametrize("body_size", [E2E_MIN_SIZE - 1, E2E_MAX_SIZE + 1])
def test_parse_e2e_header_rejects_out_of_bounds(body_size: int):
    frame, _, _ = e2e_frame(body_size - 52)
    with pytest.raises(ProtocolError):
        parse_e2e_header(frame)


def test_build_admin_is_decryptable_with_s2c_key():
    key = AESGCM.generate_key(bit_length=128)
    frame = build_admin(key, 5, AdminType.PEER_LEFT, b"payload")
    assert frame[0] == MsgType.ADMIN
    assert frame[1:9] == struct.pack(">Q", 5)
    nonce = b"\x00\x00\x00\x01" + frame[1:9]
    plaintext = AESGCM(key).decrypt(nonce, frame[9:], frame[:9])
    assert plaintext == bytes([AdminType.PEER_LEFT]) + b"payload"


def test_peer_list_payload():
    peers = [PeerInfo(uuid.uuid4(), b"k" * 32, b"s" * 16) for _ in range(2)]
    payload = peer_list_payload(peers)
    assert payload[:2] == b"\x00\x02"
    assert len(payload) == 2 + 2 * 64
    assert payload[2:18] == peers[0].client_id.bytes
