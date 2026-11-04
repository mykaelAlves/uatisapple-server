import asyncio
import loguru

from src.server import server_run

if __name__ == "__main__":
    try:
        asyncio.run(server_run())
    except:
        loguru.logger.exception("Servidor desligado inesperadamente!")
