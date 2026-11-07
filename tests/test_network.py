import asyncio

import pytest

from src.network import LENGTH_PREFIX, FramingError, recv_msg

pytestmark = pytest.mark.asyncio


def make_reader(data: bytes, eof: bool = True) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    if eof:
        reader.feed_eof()
    return reader


async def test_recv_valid_frames():
    reader = make_reader(LENGTH_PREFIX.pack(3) + b"abc" + LENGTH_PREFIX.pack(1) + b"z")
    assert await recv_msg(reader, max_size=10) == b"abc"
    assert await recv_msg(reader, max_size=10) == b"z"
    assert await recv_msg(reader, max_size=10) is None


async def test_clean_eof_returns_none():
    assert await recv_msg(make_reader(b""), max_size=10) is None


async def test_frame_at_max_size_is_accepted():
    reader = make_reader(LENGTH_PREFIX.pack(10) + b"x" * 10)
    assert await recv_msg(reader, max_size=10) == b"x" * 10


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(b"\x00\x00", id="prefixo-truncado"),
        pytest.param(LENGTH_PREFIX.pack(0), id="tamanho-zero"),
        pytest.param(LENGTH_PREFIX.pack(11) + b"x" * 11, id="acima-do-maximo"),
        pytest.param(LENGTH_PREFIX.pack(5) + b"abc", id="corpo-truncado"),
    ],
)
async def test_invalid_framing_raises(data: bytes):
    with pytest.raises(FramingError):
        await recv_msg(make_reader(data), max_size=10)


async def test_body_timeout_raises_framing_error():
    reader = make_reader(LENGTH_PREFIX.pack(5) + b"ab", eof=False)
    with pytest.raises(FramingError, match="tempo esgotado"):
        await recv_msg(reader, max_size=10, body_timeout=0.05)


async def test_send_msg_prefixes_length():
    from src.network import send_msg

    received: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

    async def on_connect(reader, writer):
        received.set_result(await reader.readexactly(9))
        writer.close()

    server = await asyncio.start_server(on_connect, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    _, writer = await asyncio.open_connection("127.0.0.1", port)
    await send_msg(writer, b"hello")
    assert await received == LENGTH_PREFIX.pack(5) + b"hello"
    writer.close()
    server.close()
