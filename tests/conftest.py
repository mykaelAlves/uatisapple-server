import asyncio
import contextlib
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass

import pytest
import pytest_asyncio

from src.crypto import ServerIdentity, load_or_create_identity
from src.server import ServerRelay
from tests.fake_client import FakeClient


@pytest.fixture(scope="session")
def identity(tmp_path_factory: pytest.TempPathFactory) -> ServerIdentity:
    return load_or_create_identity(tmp_path_factory.mktemp("certs"))


@dataclass
class RunningServer:
    relay: ServerRelay
    host: str
    port: int
    identity: ServerIdentity

    def client(self, **kwargs) -> FakeClient:
        return FakeClient(self.identity.certificate_der, **kwargs)

    async def connected_client(self, **kwargs) -> FakeClient:
        client = self.client(**kwargs)

        await client.connect(self.host, self.port)
        await client.expect_registered()

        return client


ServerFactory = Callable[..., Awaitable[RunningServer]]


@pytest_asyncio.fixture
async def make_server(identity: ServerIdentity) -> AsyncIterator[ServerFactory]:
    servers: list[tuple[asyncio.Server, ServerRelay]] = []

    async def factory(**relay_kwargs) -> RunningServer:
        relay_kwargs.setdefault("handshake_timeout", 1.0)
        relay_kwargs.setdefault("frame_body_timeout", 0.5)
        relay = ServerRelay(identity, **relay_kwargs)
        server = await asyncio.start_server(relay.handle_client, "127.0.0.1", 0)
        servers.append((server, relay))
        host, port = server.sockets[0].getsockname()[:2]

        return RunningServer(relay, host, port, identity)

    yield factory

    for server, relay in servers:
        await relay.shutdown()
        server.close()

        with contextlib.suppress(TimeoutError):
            async with asyncio.timeout(3):
                await server.wait_closed()


@pytest_asyncio.fixture
async def server(make_server: ServerFactory) -> RunningServer:
    return await make_server()
