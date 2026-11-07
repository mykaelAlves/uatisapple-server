import argparse
import asyncio
from pathlib import Path

from loguru import logger

from src.crypto import load_or_create_identity
from src.server import DEFAULT_HOST, DEFAULT_MAX_CLIENTS, DEFAULT_PORT, server_run


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Servidor relay Uatisapple (E2E).")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--cert-dir",
        type=Path,
        default=Path("certs"),
        help="diretório de server.key/server.crt (gerados se não existirem)",
    )
    parser.add_argument("--max-clients", type=int, default=DEFAULT_MAX_CLIENTS)
    parser.add_argument(
        "--no-replay-check",
        action="store_true",
        help="não rejeitar replays no servidor (para demonstrar a rejeição no "
        "cliente destinatário)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    try:
        identity = load_or_create_identity(args.cert_dir)
        asyncio.run(
            server_run(
                identity,
                host=args.host,
                port=args.port,
                max_clients=args.max_clients,
                check_replay=not args.no_replay_check,
            )
        )
    except KeyboardInterrupt:
        logger.warning("Servidor encerrado com ctrl+c!")
    except Exception:
        logger.exception("Erro inesperado!")
