import asyncio
import struct

LENGTH_PREFIX = struct.Struct(">I")


class FramingError(Exception):
    """Framing inválido (tamanho incorreto, frame truncado, ...). Erro fatal."""


async def send_msg(
    writer: asyncio.StreamWriter, msg: bytes, timeout: float | None = None
) -> None:
    writer.write(LENGTH_PREFIX.pack(len(msg)) + msg)
    async with asyncio.timeout(timeout):
        await writer.drain()


async def recv_msg(
    reader: asyncio.StreamReader, max_size: int, body_timeout: float | None = None
) -> bytes | None:
    try:
        prefix = await reader.readexactly(LENGTH_PREFIX.size)
    except asyncio.IncompleteReadError as e:
        if not e.partial:
            return None
        raise FramingError("prefixo de comprimento truncado") from e

    (length,) = LENGTH_PREFIX.unpack(prefix)
    if length == 0 or length > max_size:
        raise FramingError(f"comprimento inválido: {length} (máximo {max_size})")

    try:
        async with asyncio.timeout(body_timeout):
            return await reader.readexactly(length)
    except asyncio.IncompleteReadError as e:
        raise FramingError(f"frame truncado: {len(e.partial)} de {length} bytes") from e
    except TimeoutError as e:
        raise FramingError(
            f"tempo esgotado aguardando {length} bytes anunciados no prefixo"
        ) from e
