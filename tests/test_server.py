import asyncio
import struct
import uuid

import pytest
from cryptography.exceptions import InvalidTag

from src.network import LENGTH_PREFIX
from src.protocol import (
    AdminType,
    DisconnectReason,
    ErrorCode,
    MsgType,
)
from tests.conftest import RunningServer, ServerFactory
from tests.fake_client import FakeClient, ReplayError

pytestmark = pytest.mark.asyncio


async def expect_error(client: FakeClient, code: ErrorCode) -> None:
    payload = await client.expect_admin(AdminType.ERROR)
    assert payload[0] == code, f"esperava {code!r}, recebeu {ErrorCode(payload[0])!r}"


async def expect_fatal(client: FakeClient, code: ErrorCode) -> None:
    await expect_error(client, code)
    payload = await client.expect_admin(AdminType.DISCONNECT)
    assert payload[0] == DisconnectReason.PROTOCOL_ERROR
    await client.expect_closed()


async def wait_until(predicate, timeout: float = 2.0) -> None:
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.01)


async def pair(server: RunningServer) -> tuple[FakeClient, FakeClient]:
    a = await server.connected_client()
    b = await server.connected_client()
    await a.expect_admin(AdminType.PEER_JOINED)
    return a, b


async def test_handshake_and_registration(server: RunningServer):
    client = server.client()
    await client.connect(server.host, server.port)
    await client.expect_admin(AdminType.REGISTERED)
    payload = await client.expect_admin(AdminType.PEER_LIST)
    assert payload == b"\x00\x00"

    session = server.relay.sessions[client.client_id]
    assert session.public_key == client.pk
    assert session.salt == client.salt
    assert session.seq_send == 2
    assert session.seq_recv == {}
    await client.close()


async def test_each_handshake_uses_fresh_salt_and_server_key(server: RunningServer):
    a = await server.connected_client()
    b = await server.connected_client()
    assert a.salt != b.salt
    assert a.s2c_key != b.s2c_key


async def test_public_keys_are_distributed_with_shared_pair_salt(
    server: RunningServer,
):
    a = await server.connected_client()
    b = await server.connected_client()
    await a.expect_admin(AdminType.PEER_JOINED)

    assert a.peers[b.client_id].public_key == b.pk
    assert b.peers[a.client_id].public_key == a.pk
    assert a.peers[b.client_id].pair_salt == b.peers[a.client_id].pair_salt

    assert a.peers[b.client_id].key_send == b.peers[a.client_id].key_recv
    assert a.peers[b.client_id].key_recv == b.peers[a.client_id].key_send


async def test_new_client_receives_all_existing_peers(server: RunningServer):
    existing = [await server.connected_client() for _ in range(3)]
    newcomer = await server.connected_client()
    assert set(newcomer.peers) == {c.client_id for c in existing}
    for c in existing:
        while newcomer.client_id not in c.peers:
            await c.recv_admin()
    salts = {p.pair_salt for p in newcomer.peers.values()}
    assert len(salts) == 3


async def test_concurrent_connections(server: RunningServer):
    clients = await asyncio.gather(*(server.connected_client() for _ in range(10)))
    assert len(server.relay.sessions) == 10
    assert {c.client_id for c in clients} == set(server.relay.sessions)


async def test_e2e_messages_are_relayed_both_ways(server: RunningServer):
    a, b = await pair(server)

    frame = a.encrypt_to(b.client_id, b"ola, B")
    await a.send_frame(frame)
    received = await b.recv_frame()
    assert received == frame
    assert b.decrypt_from(received) == (a.client_id, b"ola, B")

    await b.send_frame(b.encrypt_to(a.client_id, b"ola, A"))
    assert a.decrypt_from(await a.recv_frame()) == (b.client_id, b"ola, A")


async def test_only_recipient_receives_message(server: RunningServer):
    a, b = await pair(server)
    c = await server.connected_client()
    await a.expect_admin(AdminType.PEER_JOINED)
    await b.expect_admin(AdminType.PEER_JOINED)

    frame = a.encrypt_to(b.client_id, b"segredo")
    await a.send_frame(frame)
    assert b.decrypt_from(await b.recv_frame())[1] == b"segredo"
    with pytest.raises(TimeoutError):
        await c.recv_frame(timeout=0.3)


async def test_max_plaintext_size_is_relayed(server: RunningServer):
    a, b = await pair(server)
    await a.send_frame(a.encrypt_to(b.client_id, b"x" * 4096))
    assert b.decrypt_from(await b.recv_frame())[1] == b"x" * 4096


async def test_tampered_frame_is_rejected_by_recipient(server: RunningServer):
    a, b = await pair(server)
    frame = bytearray(a.encrypt_to(b.client_id, b"mensagem original"))
    frame[-20] ^= 0x01
    await a.send_frame(bytes(frame))

    received = await b.recv_frame()
    with pytest.raises(InvalidTag):
        b.decrypt_from(received)


async def test_spoofed_sender_id_is_rejected(server: RunningServer):
    a, b = await pair(server)
    frame = bytearray(a.encrypt_to(b.client_id, b"oi"))
    frame[1 + 12 : 1 + 28] = uuid.uuid4().bytes
    await a.send_frame(bytes(frame))
    await expect_error(a, ErrorCode.SENDER_MISMATCH)
    with pytest.raises(TimeoutError):
        await b.recv_frame(timeout=0.3)

    await a.send_frame(a.encrypt_to(b.client_id, b"oi de novo"))
    assert b.decrypt_from(await b.recv_frame())[1] == b"oi de novo"


async def test_unknown_recipient_is_rejected(server: RunningServer):
    a, b = await pair(server)
    frame = bytearray(a.encrypt_to(b.client_id, b"oi"))
    frame[1 + 28 : 1 + 44] = uuid.uuid4().bytes
    await a.send_frame(bytes(frame))
    await expect_error(a, ErrorCode.UNKNOWN_RECIPIENT)


async def test_message_to_self_is_rejected(server: RunningServer):
    a, b = await pair(server)
    frame = bytearray(a.encrypt_to(b.client_id, b"oi"))
    frame[1 + 28 : 1 + 44] = a.client_id.bytes
    await a.send_frame(bytes(frame))
    await expect_error(a, ErrorCode.UNKNOWN_RECIPIENT)


async def test_replay_is_rejected_by_server(server: RunningServer):
    a, b = await pair(server)
    frame = a.encrypt_to(b.client_id, b"uma vez")
    await a.send_frame(frame)
    await b.recv_frame()

    await a.send_frame(frame)
    await expect_error(a, ErrorCode.REPLAY)
    with pytest.raises(TimeoutError):
        await b.recv_frame(timeout=0.3)


async def test_replay_reaches_recipient_when_server_check_disabled(
    make_server: ServerFactory,
):
    server = await make_server(check_replay=False)
    a, b = await pair(server)
    frame = a.encrypt_to(b.client_id, b"uma vez")
    await a.send_frame(frame)
    b.decrypt_from(await b.recv_frame())

    await a.send_frame(frame)
    with pytest.raises(ReplayError):
        b.decrypt_from(await b.recv_frame())


async def test_seq_no_is_tracked_per_recipient(server: RunningServer):
    a, b = await pair(server)
    c = await server.connected_client()
    await a.expect_admin(AdminType.PEER_JOINED)
    await b.expect_admin(AdminType.PEER_JOINED)

    await a.send_frame(a.encrypt_to(b.client_id, b"para B"))
    await a.send_frame(a.encrypt_to(c.client_id, b"para C"))
    assert b.decrypt_from(await b.recv_frame())[1] == b"para B"
    assert c.decrypt_from(await c.recv_frame())[1] == b"para C"


async def test_admin_messages_use_monotonic_seq_and_are_authenticated(
    server: RunningServer,
):
    a = await server.connected_client()
    others = []
    for _ in range(3):
        others.append(await server.connected_client())
        await a.expect_admin(AdminType.PEER_JOINED)
    assert a.admin_seq_recv == 4

    others.append(await server.connected_client())
    frame = bytearray(await a.recv_frame())
    frame[-1] ^= 0x01
    with pytest.raises(InvalidTag):
        a.decrypt_admin(bytes(frame))


async def test_admin_replay_is_detected_by_client(server: RunningServer):
    a = await server.connected_client()
    _ = await server.connected_client()
    frame = await a.recv_frame()
    a.decrypt_admin(frame)
    with pytest.raises(ReplayError):
        a.decrypt_admin(frame)


async def test_disconnect_removes_session_and_notifies_peers(server: RunningServer):
    a, b = await pair(server)
    await b.close()

    payload = await a.expect_admin(AdminType.PEER_LEFT)
    assert uuid.UUID(bytes=payload) == b.client_id
    assert b.client_id not in server.relay.sessions
    assert b.client_id not in a.peers
    assert list(server.relay.sessions) == [a.client_id]


async def test_disconnect_clears_replay_state_of_other_sessions(
    server: RunningServer,
):
    a, b = await pair(server)
    await a.send_frame(a.encrypt_to(b.client_id, b"oi"))
    await b.recv_frame()
    assert server.relay.sessions[a.client_id].seq_recv == {b.client_id: 1}

    await b.close()
    await a.expect_admin(AdminType.PEER_LEFT)
    assert server.relay.sessions[a.client_id].seq_recv == {}


async def test_reconnect_requires_full_handshake_with_new_salt_and_seq(
    server: RunningServer,
):
    a, b = await pair(server)
    old_salt = b.salt
    old_pair_salt = a.peers[b.client_id].pair_salt
    await a.send_frame(a.encrypt_to(b.client_id, b"antes"))
    await b.recv_frame()
    await b.close()
    await a.expect_admin(AdminType.PEER_LEFT)

    b2 = await server.connected_client(client_id=b.client_id)
    await a.expect_admin(AdminType.PEER_JOINED)
    assert b2.salt != old_salt
    assert a.peers[b.client_id].pair_salt != old_pair_salt
    assert server.relay.sessions[b.client_id].seq_send == 2
    assert b2.admin_seq_recv == 1

    await a.send_frame(a.encrypt_to(b.client_id, b"depois"))
    assert b2.decrypt_from(await b2.recv_frame())[1] == b"depois"


async def test_duplicate_active_client_id_is_rejected(server: RunningServer):
    a = await server.connected_client()
    impostor = server.client(client_id=a.client_id)
    await impostor.connect(server.host, server.port)
    await expect_fatal(impostor, ErrorCode.DUPLICATE_CLIENT_ID)
    assert server.relay.sessions[a.client_id].public_key == a.pk


async def test_server_full_is_rejected(make_server: ServerFactory):
    server = await make_server(max_clients=1)
    _ = await server.connected_client()
    extra = server.client()
    await extra.connect(server.host, server.port)
    await expect_fatal(extra, ErrorCode.SERVER_FULL)
    assert len(server.relay.sessions) == 1


async def test_zero_length_prefix_is_fatal(server: RunningServer):
    a = await server.connected_client()
    await a.send_raw(LENGTH_PREFIX.pack(0))
    await expect_fatal(a, ErrorCode.FRAMING)
    await wait_until(lambda: a.client_id not in server.relay.sessions)


async def test_oversized_length_prefix_is_fatal(server: RunningServer):
    a = await server.connected_client()
    await a.send_raw(LENGTH_PREFIX.pack(10 * 1024 * 1024))
    await expect_fatal(a, ErrorCode.FRAMING)


async def test_prefix_larger_than_payload_is_fatal(server: RunningServer):
    a, b = await pair(server)
    frame = a.encrypt_to(b.client_id, b"oi")
    await a.send_raw(LENGTH_PREFIX.pack(len(frame) + 50) + frame)
    await expect_fatal(a, ErrorCode.FRAMING)

    payload = await b.expect_admin(AdminType.PEER_LEFT)
    assert uuid.UUID(bytes=payload) == a.client_id


async def test_e2e_frame_too_short_is_fatal(server: RunningServer):
    a = await server.connected_client()
    await a.send_frame(bytes([MsgType.E2E]) + b"\x00" * 30)
    await expect_fatal(a, ErrorCode.FRAMING)


async def test_e2e_frame_too_long_is_fatal(server: RunningServer):
    a, b = await pair(server)
    await a.send_frame(a.encrypt_to(b.client_id, b"x" * 4097))
    await expect_fatal(a, ErrorCode.FRAMING)


async def test_unexpected_message_type_is_fatal(server: RunningServer):
    a = await server.connected_client()
    await a.send_frame(bytes([MsgType.CLIENT_HELLO]) + a.client_id.bytes + a.pk)
    await expect_fatal(a, ErrorCode.INVALID_MESSAGE)


async def test_fatal_error_notifies_peers(server: RunningServer):
    a, b = await pair(server)
    await b.send_raw(LENGTH_PREFIX.pack(0))
    await expect_fatal(b, ErrorCode.FRAMING)
    payload = await a.expect_admin(AdminType.PEER_LEFT)
    assert uuid.UUID(bytes=payload) == b.client_id


@pytest.mark.parametrize(
    "hello",
    [
        pytest.param(lambda c: bytes([MsgType.CLIENT_HELLO]) + c.pk, id="curto"),
        pytest.param(
            lambda c: bytes([MsgType.CLIENT_HELLO]) + c.client_id.bytes + c.pk + b"x",
            id="longo",
        ),
        pytest.param(
            lambda c: bytes([MsgType.E2E]) + c.client_id.bytes + c.pk, id="tipo"
        ),
        pytest.param(
            lambda c: bytes([MsgType.CLIENT_HELLO]) + uuid.uuid1().bytes + c.pk,
            id="uuid-v1",
        ),
        pytest.param(
            lambda c: bytes([MsgType.CLIENT_HELLO]) + c.client_id.bytes + bytes(32),
            id="pk-ordem-baixa",
        ),
    ],
)
async def test_invalid_client_hello_closes_connection(server: RunningServer, hello):
    client = server.client()
    await client.open(server.host, server.port)
    await client.send_frame(hello(client))
    await client.expect_closed()
    assert server.relay.sessions == {}


async def test_invalid_framing_in_handshake_closes_connection(server: RunningServer):
    client = server.client()
    await client.open(server.host, server.port)
    await client.send_raw(struct.pack(">I", 0))
    await client.expect_closed()


async def test_handshake_timeout_closes_connection(server: RunningServer):
    client = server.client()
    await client.open(server.host, server.port)
    await client.expect_closed(timeout=3)


async def test_client_rejects_server_with_wrong_certificate(
    server: RunningServer, tmp_path
):
    from src.crypto import load_or_create_identity

    other = load_or_create_identity(tmp_path)
    client = FakeClient(other.certificate_der)
    with pytest.raises(AssertionError, match="pin"):
        await client.connect(server.host, server.port)
    await client.close()


async def test_shutdown_notifies_clients(server: RunningServer):
    a = await server.connected_client()
    await server.relay.shutdown()
    payload = await a.expect_admin(AdminType.DISCONNECT)
    assert payload[0] == DisconnectReason.SERVER_SHUTDOWN
    await a.expect_closed()
