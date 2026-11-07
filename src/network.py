import asyncio


async def send_msg(writer: asyncio.StreamWriter, msg: bytes) -> None:
    pass


async def recv_msg(reader: asyncio.StreamReader) -> bytes | None:
    pass
