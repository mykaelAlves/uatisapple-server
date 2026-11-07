import asyncio
import os
import struct
import uuid
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from src.network import recv_msg, send_msg
from src.protocol import (
    MAX_SERVER_FRAME_SIZE,
    AdminType,
    MsgType,
)

RECV_TIMEOUT = 3.0


class ReplayError(Exception):
    pass


@dataclass
class Peer:
    public_key: bytes
    pair_salt: bytes
    key_send: bytes
    key_recv: bytes
    iv_base_send: bytes = field(default_factory=lambda: os.urandom(4))
    seq_send: int = 0
    seq_recv: int = -1


def hkdf(salt: bytes, ikm: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=16, salt=salt, info=info).derive(ikm)


class FakeClient:
    def __init__(self, pinned_cert_der: bytes, client_id: uuid.UUID | None = None):
        self.pinned_cert_der = pinned_cert_der
        self.client_id = client_id or uuid.uuid4()
        self.sk = X25519PrivateKey.generate()
        self.pk = self.sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.peers: dict[uuid.UUID, Peer] = {}
        self.admin_seq_recv = -1
        self.salt: bytes | None = None
        self.s2c_key: bytes | None = None
        self.reader: asyncio.StreamReader
        self.writer: asyncio.StreamWriter

    async def open(self, host: str, port: int) -> None:
        self.reader, self.writer = await asyncio.open_connection(host, port)

    async def connect(self, host: str, port: int) -> None:
        await self.open(host, port)
        await self.send_frame(
            bytes([MsgType.CLIENT_HELLO]) + self.client_id.bytes + self.pk
        )
        await self.complete_handshake()

    async def complete_handshake(self) -> None:
        frame = await self.recv_frame()
        assert frame is not None, "servidor fechou a conexão no handshake"
        assert frame[0] == MsgType.SERVER_HELLO
        body = frame[1:]
        pk_server, salt = body[:32], body[32:48]
        (sig_len,) = struct.unpack_from(">H", body, 48)
        signature = body[50 : 50 + sig_len]
        (cert_len,) = struct.unpack_from(">H", body, 50 + sig_len)
        cert_der = body[52 + sig_len : 52 + sig_len + cert_len]
        assert len(body) == 52 + sig_len + cert_len

        assert cert_der == self.pinned_cert_der, "certificado não confere com o pin"
        cert = x509.load_der_x509_certificate(cert_der)
        material = pk_server + self.pk + self.client_id.bytes + salt
        cert.public_key().verify(
            signature,
            material,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )

        shared = self.sk.exchange(X25519PublicKey.from_public_bytes(pk_server))
        self.salt = salt
        self.s2c_key = hkdf(salt, shared, b"S2C")

    async def close(self) -> None:
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except (ConnectionError, OSError):
            pass

    async def send_frame(self, data: bytes) -> None:
        await send_msg(self.writer, data)

    async def send_raw(self, data: bytes) -> None:
        self.writer.write(data)
        await self.writer.drain()

    async def recv_frame(self, timeout: float = RECV_TIMEOUT) -> bytes | None:
        async with asyncio.timeout(timeout):
            return await recv_msg(self.reader, MAX_SERVER_FRAME_SIZE)

    async def expect_closed(self, timeout: float = RECV_TIMEOUT) -> None:
        async with asyncio.timeout(timeout):
            data = await self.reader.read()
        assert data == b"", f"esperava conexão fechada, recebeu {len(data)} bytes"

    def decrypt_admin(self, frame: bytes) -> tuple[AdminType, bytes]:
        assert frame[0] == MsgType.ADMIN, f"esperava ADMIN, recebeu 0x{frame[0]:02x}"
        assert self.s2c_key is not None
        header, ciphertext = frame[:9], frame[9:]
        (seq_no,) = struct.unpack(">Q", frame[1:9])
        if seq_no <= self.admin_seq_recv:
            raise ReplayError("seq_no administrativo repetido")
        nonce = b"\x00\x00\x00\x01" + frame[1:9]
        plaintext = AESGCM(self.s2c_key).decrypt(nonce, ciphertext, header)
        self.admin_seq_recv = seq_no
        return AdminType(plaintext[0]), plaintext[1:]

    async def recv_admin(self) -> tuple[AdminType, bytes]:
        frame = await self.recv_frame()
        assert frame is not None, "conexão fechada"
        admin_type, payload = self.decrypt_admin(frame)
        self._handle_admin(admin_type, payload)
        return admin_type, payload

    async def expect_admin(self, expected: AdminType) -> bytes:
        admin_type, payload = await self.recv_admin()
        assert admin_type == expected, f"esperava {expected!r}, recebeu {admin_type!r}"
        return payload

    async def expect_registered(self) -> None:
        await self.expect_admin(AdminType.REGISTERED)
        await self.expect_admin(AdminType.PEER_LIST)

    def _handle_admin(self, admin_type: AdminType, payload: bytes) -> None:
        if admin_type == AdminType.PEER_LIST:
            (count,) = struct.unpack_from(">H", payload)
            assert len(payload) == 2 + 64 * count
            for i in range(count):
                self._add_peer(payload[2 + 64 * i : 2 + 64 * (i + 1)])
        elif admin_type == AdminType.PEER_JOINED:
            assert len(payload) == 64
            self._add_peer(payload)
        elif admin_type == AdminType.PEER_LEFT:
            self.peers.pop(uuid.UUID(bytes=payload), None)

    def _add_peer(self, entry: bytes) -> None:
        peer_id = uuid.UUID(bytes=entry[:16])
        pk_peer, pair_salt = entry[16:48], entry[48:64]
        z = self.sk.exchange(X25519PublicKey.from_public_bytes(pk_peer))

        i_am_a = self.client_id.bytes < peer_id.bytes
        key_a2b = hkdf(pair_salt, z, b"A2B")
        key_b2a = hkdf(pair_salt, z, b"B2A")
        self.peers[peer_id] = Peer(
            public_key=pk_peer,
            pair_salt=pair_salt,
            key_send=key_a2b if i_am_a else key_b2a,
            key_recv=key_b2a if i_am_a else key_a2b,
        )

    def encrypt_to(self, peer_id: uuid.UUID, plaintext: bytes) -> bytes:
        peer = self.peers[peer_id]
        peer.seq_send += 1
        seq = struct.pack(">Q", peer.seq_send)
        aad = self.client_id.bytes + peer_id.bytes + seq
        nonce = peer.iv_base_send + seq
        ciphertext = AESGCM(peer.key_send).encrypt(nonce, plaintext, aad)
        return bytes([MsgType.E2E]) + nonce + aad + ciphertext

    def decrypt_from(self, frame: bytes) -> tuple[uuid.UUID, bytes]:
        assert frame[0] == MsgType.E2E
        body = frame[1:]
        nonce, aad, ciphertext = body[:12], body[12:52], body[52:]
        sender_id = uuid.UUID(bytes=aad[:16])
        assert uuid.UUID(bytes=aad[16:32]) == self.client_id
        (seq_no,) = struct.unpack(">Q", aad[32:40])
        peer = self.peers[sender_id]
        if seq_no <= peer.seq_recv:
            raise ReplayError("seq_no repetido")
        plaintext = AESGCM(peer.key_recv).decrypt(nonce, ciphertext, aad)
        peer.seq_recv = seq_no
        return sender_id, plaintext
