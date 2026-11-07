import asyncio

from loguru import logger

from src.client_session import ClientId, ClientSession
from src.network import recv_msg

BUFFER_LIMIT = 10*1024*1024 #10MB

class ServerRelay:
    def __init__(self):
        logger.info("Criando sessões, gerando chaves e certificado...")

        self.sessions: dict[ClientId, ClientSession] = {}
        # TODO: chaves e certificaods

        logger.info("Sessões criadas, chaves e certificado gerados com sucesso!")

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        addr = writer.get_extra_info("peername")
        logger.info(f"Nova conexão de {addr}.")
        client_id = None
        raw_data = recv_msg(reader)
        


async def server_run():
    relay = ServerRelay()
    server = await asyncio.start_server(
        client_connected_cb=relay.handle_client, 
        host="127.0.0.1", 
        port=6767,
        limit=BUFFER_LIMIT
    )

    addr = server.sockets[0].getsockname()
    logger.info(f"Servidor rodando em {addr}.")

    async with server:
        await server.serve_forever()
