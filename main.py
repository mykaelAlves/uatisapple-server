import asyncio

from loguru import logger

from src.server import server_run

if __name__ == "__main__":
    try:
        asyncio.run(server_run())
    except KeyboardInterrupt:
        logger.warning("Servidor encerrado com ctrlc!")
    except Exception:
        logger.exception("Erro inesperado!")
