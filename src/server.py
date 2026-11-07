import asyncio
import contextlib
import os

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from loguru import logger

from src.client_session import ClientId, ClientSession
from src.crypto import SALT_SIZE, ServerIdentity, derive_s2c_key, fingerprint
from src.network import FramingError, recv_msg, send_msg
from src.protocol import (
    MAX_CLIENT_FRAME_SIZE,
    AdminType,
    DisconnectReason,
    E2EHeader,
    ErrorCode,
    MsgType,
    PeerInfo,
    ProtocolError,
    build_admin,
    build_server_hello,
    disconnect_payload,
    error_payload,
    parse_client_hello,
    parse_e2e_header,
    peer_joined_payload,
    peer_left_payload,
    peer_list_payload,
)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 6767
DEFAULT_MAX_CLIENTS = 100
HANDSHAKE_TIMEOUT = 10.0
FRAME_BODY_TIMEOUT = 10.0
SEND_TIMEOUT = 5.0


class ServerRelay:
    def __init__(
        self,
        identity: ServerIdentity,
        max_clients: int = DEFAULT_MAX_CLIENTS,
        check_replay: bool = True,
        handshake_timeout: float = HANDSHAKE_TIMEOUT,
        frame_body_timeout: float = FRAME_BODY_TIMEOUT,
        send_timeout: float = SEND_TIMEOUT,
    ):
        self.identity = identity
        self.max_clients = max_clients
        self.check_replay = check_replay
        self.handshake_timeout = handshake_timeout
        self.frame_body_timeout = frame_body_timeout
        self.send_timeout = send_timeout

        self.sessions: dict[ClientId, ClientSession] = {}

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        addr = writer.get_extra_info("peername")
        logger.info(f"Nova conexão de {addr}.")
        session: ClientSession | None = None
        try:
            session = await self._handshake(reader, writer, addr)
            if session is not None:
                await self._serve(session, reader)
        except (ConnectionError, OSError) as e:
            logger.info(f"Conexão {addr} perdida: {e!r}.")
        except Exception:
            logger.exception(f"Erro inesperado na conexão {addr}.")
        finally:
            if session is not None:
                await self._unregister(session)
            await self._close(writer)
            logger.info(f"Conexão {addr} encerrada.")

    async def _handshake(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, addr
    ) -> ClientSession | None:
        try:
            async with asyncio.timeout(self.handshake_timeout):
                frame = await recv_msg(
                    reader, MAX_CLIENT_FRAME_SIZE, self.frame_body_timeout
                )
        except TimeoutError:
            logger.warning(f"{addr}: tempo esgotado aguardando CLIENT_HELLO.")
            return None
        except FramingError as e:
            logger.warning(f"{addr}: framing inválido no handshake: {e}.")
            return None
        if frame is None:
            logger.info(f"{addr}: desconectou antes do handshake.")
            return None

        try:
            hello = parse_client_hello(frame)
        except ProtocolError as e:
            logger.warning(f"{addr}: CLIENT_HELLO inválido: {e}.")
            return None

        sk_server = X25519PrivateKey.generate()
        pk_server = sk_server.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        salt = os.urandom(SALT_SIZE)
        try:
            s2c_key = derive_s2c_key(sk_server, hello.public_key, salt)
        except ValueError:
            logger.warning(f"{addr}: chave pública X25519 inválida.")
            return None
        finally:
            del sk_server

        signature = self.identity.sign_handshake(
            pk_server, hello.public_key, hello.client_id.bytes, salt
        )
        session = ClientSession(
            client_id=hello.client_id,
            public_key=hello.public_key,
            writer=writer,
            salt=salt,
            s2c_key=s2c_key,
        )
        server_hello = build_server_hello(
            pk_server, salt, signature, self.identity.certificate_der
        )
        if not await self._send_raw(session, server_hello):
            return None

        cid = hello.client_id
        if cid in self.sessions:
            logger.warning(f"[{cid}] Rejeitado: client_id já possui sessão ativa.")
            await self._reject(
                session, ErrorCode.DUPLICATE_CLIENT_ID, "client_id já está conectado"
            )
            return None
        if len(self.sessions) >= self.max_clients:
            logger.warning(f"[{cid}] Rejeitado: limite de {self.max_clients} clientes.")
            await self._reject(session, ErrorCode.SERVER_FULL, "servidor lotado")
            return None

        peers, announcements = self._register(session)
        logger.info(
            f"[{cid}] Registrado (pk {fingerprint(hello.public_key)}). "
            f"Clientes ativos: {len(self.sessions)}."
        )

        await self.send_admin(session, AdminType.REGISTERED, b"")
        await self.send_admin(session, AdminType.PEER_LIST, peer_list_payload(peers))
        await asyncio.gather(
            *(
                self.send_admin(other, AdminType.PEER_JOINED, peer_joined_payload(info))
                for other, info in announcements
            )
        )
        return session

    def _register(
        self, session: ClientSession
    ) -> tuple[list[PeerInfo], list[tuple[ClientSession, PeerInfo]]]:
        """Insere a sessão e gera um salt novo para cada par (novo, existente).

        Executa sem `await`, então a tabela e as listas enviadas ficam consistentes
        mesmo com registros concorrentes.
        """
        peers: list[PeerInfo] = []
        announcements: list[tuple[ClientSession, PeerInfo]] = []
        for other in self.sessions.values():
            pair_salt = os.urandom(SALT_SIZE)
            peers.append(PeerInfo(other.client_id, other.public_key, pair_salt))
            announcements.append(
                (other, PeerInfo(session.client_id, session.public_key, pair_salt))
            )
        self.sessions[session.client_id] = session
        return peers, announcements

    async def _serve(self, session: ClientSession, reader: asyncio.StreamReader):
        cid = session.client_id
        while True:
            try:
                frame = await recv_msg(
                    reader, MAX_CLIENT_FRAME_SIZE, self.frame_body_timeout
                )
            except FramingError as e:
                logger.warning(f"[{cid}] Framing inválido: {e}. Desconectando.")
                await self._reject(session, ErrorCode.FRAMING, str(e))
                return
            if frame is None:
                logger.info(f"[{cid}] Cliente desconectou.")
                return

            if frame[0] != MsgType.E2E:
                logger.warning(
                    f"[{cid}] Tipo de mensagem inesperado 0x{frame[0]:02x}. "
                    "Desconectando."
                )
                await self._reject(
                    session, ErrorCode.INVALID_MESSAGE, "tipo de mensagem inesperado"
                )
                return
            try:
                header = parse_e2e_header(frame)
            except ProtocolError as e:
                logger.warning(f"[{cid}] Framing inválido: {e}. Desconectando.")
                await self._reject(session, ErrorCode.FRAMING, str(e))
                return

            await self._relay(session, header, frame)

    async def _relay(
        self, session: ClientSession, header: E2EHeader, frame: bytes
    ) -> None:
        """Encaminha o frame E2E intacto. O conteúdo nunca é decifrado."""
        cid = session.client_id
        rid = header.recipient_id

        if header.sender_id != cid:
            logger.warning(f"[{cid}] Frame rejeitado: sender_id não confere.")
            await self.send_admin(
                session,
                AdminType.ERROR,
                error_payload(ErrorCode.SENDER_MISMATCH, "sender_id não confere"),
            )
            return

        recipient = self.sessions.get(rid) if rid != cid else None
        if recipient is None:
            logger.warning(f"[{cid}] Frame rejeitado: destinatário {rid} inexistente.")
            await self.send_admin(
                session,
                AdminType.ERROR,
                error_payload(
                    ErrorCode.UNKNOWN_RECIPIENT, f"destinatário {rid} não conectado"
                ),
            )
            return

        if self.check_replay:
            if header.seq_no <= session.last_seq_to(rid):
                logger.warning(
                    f"[{cid}] Frame para {rid} rejeitado: replay "
                    f"(seq_no não é maior que o último recebido)."
                )
                await self.send_admin(
                    session,
                    AdminType.ERROR,
                    error_payload(ErrorCode.REPLAY, "seq_no já utilizado"),
                )
                return
            session.seq_recv[rid] = header.seq_no

        logger.info(f"[{cid}] → [{rid}] frame E2E ({header.payload_size} bytes).")
        await self._send_raw(recipient, frame)

    async def _unregister(self, session: ClientSession) -> None:
        cid = session.client_id
        if self.sessions.get(cid) is not session:
            return
        del self.sessions[cid]
        for other in self.sessions.values():
            other.seq_recv.pop(cid, None)
        logger.info(f"[{cid}] Sessão removida. Clientes ativos: {len(self.sessions)}.")

        await asyncio.gather(
            *(
                self.send_admin(other, AdminType.PEER_LEFT, peer_left_payload(cid))
                for other in list(self.sessions.values())
            )
        )

    async def shutdown(self) -> None:
        """Avisa todos os clientes e fecha as conexões."""
        sessions = list(self.sessions.values())
        if not sessions:
            return
        logger.info(f"Encerrando {len(sessions)} sessões...")
        await asyncio.gather(
            *(
                self.send_admin(
                    s,
                    AdminType.DISCONNECT,
                    disconnect_payload(
                        DisconnectReason.SERVER_SHUTDOWN, "servidor encerrando"
                    ),
                )
                for s in sessions
            )
        )
        for s in sessions:
            s.writer.close()

    async def send_admin(
        self, session: ClientSession, admin_type: AdminType, payload: bytes
    ) -> bool:
        """Envia uma mensagem administrativa cifrada com Key_S2C e seq_send próprio."""
        if session.writer.is_closing():
            return False
        try:
            async with session.send_lock:
                frame = build_admin(
                    session.s2c_key, session.next_admin_seq(), admin_type, payload
                )
                await send_msg(session.writer, frame, self.send_timeout)
            return True
        except (ConnectionError, OSError, TimeoutError) as e:
            self._drop(session, e)
            return False

    async def _send_raw(self, session: ClientSession, data: bytes) -> bool:
        if session.writer.is_closing():
            return False
        try:
            async with session.send_lock:
                await send_msg(session.writer, data, self.send_timeout)
            return True
        except (ConnectionError, OSError, TimeoutError) as e:
            self._drop(session, e)
            return False

    async def _reject(self, session: ClientSession, code: ErrorCode, message: str):
        """Erro fatal: envia ERROR + DISCONNECT. O chamador encerra a conexão."""
        await self.send_admin(session, AdminType.ERROR, error_payload(code, message))
        await self.send_admin(
            session,
            AdminType.DISCONNECT,
            disconnect_payload(DisconnectReason.PROTOCOL_ERROR, message),
        )

    def _drop(self, session: ClientSession, error: BaseException) -> None:
        """Falha ao enviar: aborta a conexão; o handler do cliente faz a limpeza."""
        logger.warning(f"[{session.client_id}] Falha ao enviar: {error!r}.")
        transport = session.writer.transport
        if transport is not None:
            transport.abort()

    @staticmethod
    async def _close(writer: asyncio.StreamWriter) -> None:
        if not writer.is_closing():
            writer.close()
        with contextlib.suppress(Exception):
            async with asyncio.timeout(2):
                await writer.wait_closed()


async def server_run(
    identity: ServerIdentity,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    max_clients: int = DEFAULT_MAX_CLIENTS,
    check_replay: bool = True,
) -> None:
    relay = ServerRelay(identity, max_clients=max_clients, check_replay=check_replay)
    server = await asyncio.start_server(relay.handle_client, host=host, port=port)

    addr = server.sockets[0].getsockname()
    logger.info(f"Certificado SHA-256: {identity.certificate_fingerprint}")
    logger.info(f"Servidor rodando em {addr}.")

    async with server:
        try:
            await server.serve_forever()
        finally:
            await relay.shutdown()
