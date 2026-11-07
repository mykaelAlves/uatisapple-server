import asyncio
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from src.client_session import ClientId, ClientSession


@pytest.fixture
def mock_writer():
    return MagicMock(spec=asyncio.StreamWriter)


@pytest.fixture
def valid_public_key():
    return b"0" * 32


def test_create_client_session_success(mock_writer, valid_public_key):
    client_id = ClientId("client-123")
    session = ClientSession(
        client_id=client_id,
        public_key=valid_public_key,
        writer=mock_writer,
    )

    assert session.client_id == "client-123"
    assert session.public_key == valid_public_key
    assert session.writer is mock_writer
    assert session.seq_send == 0


def test_create_client_session_with_custom_seq_send(mock_writer, valid_public_key):
    session = ClientSession(
        client_id=ClientId("client-456"),
        public_key=valid_public_key,
        writer=mock_writer,
        seq_send=42,
    )

    assert session.seq_send == 42


@pytest.mark.parametrize("key_length", [32, 64, 128])
def test_create_client_session_valid_key_lengths(mock_writer, key_length):
    public_key = b"x" * key_length
    session = ClientSession(
        client_id=ClientId("client-key-len"),
        public_key=public_key,
        writer=mock_writer,
    )

    assert session.public_key == public_key


@pytest.mark.parametrize("short_key", [b"", b"short", b"a" * 31])
def test_create_client_session_public_key_too_short(mock_writer, short_key):
    with pytest.raises(ValidationError) as exc_info:
        ClientSession(
            client_id=ClientId("client-short-key"),
            public_key=short_key,
            writer=mock_writer,
        )

    errors = exc_info.value.errors()
    assert any(
        err["loc"] == ("public_key",) and err["type"] == "bytes_too_short"
        for err in errors
    )


@pytest.mark.parametrize("invalid_seq", [-1, -100])
def test_create_client_session_seq_send_negative(
    mock_writer, valid_public_key, invalid_seq
):
    with pytest.raises(ValidationError) as exc_info:
        ClientSession(
            client_id=ClientId("client-negative-seq"),
            public_key=valid_public_key,
            writer=mock_writer,
            seq_send=invalid_seq,
        )

    errors = exc_info.value.errors()
    assert any(
        err["loc"] == ("seq_send",) and err["type"] == "greater_than_equal"
        for err in errors
    )

def test_create_client_session_missing_required_fields(mock_writer, valid_public_key):
    # Missing client_id
    with pytest.raises(ValidationError) as exc_info:
        ClientSession( # pyright: ignore[reportCallIssue]
            public_key=valid_public_key,
            writer=mock_writer,
        )
    assert any(err["loc"] == ("client_id",) for err in exc_info.value.errors())

    # Missing public_key
    with pytest.raises(ValidationError) as exc_info:
        ClientSession( # pyright: ignore[reportCallIssue]
            client_id=ClientId("client-missing-key"),
            writer=mock_writer,
        )
    assert any(err["loc"] == ("public_key",) for err in exc_info.value.errors())

    # Missing writer
    with pytest.raises(ValidationError) as exc_info:
        ClientSession( # pyright: ignore[reportCallIssue]
            client_id=ClientId("client-missing-writer"),
            public_key=valid_public_key,
        )
    assert any(err["loc"] == ("writer",) for err in exc_info.value.errors())


def test_create_client_session_invalid_writer_type(valid_public_key):
    with pytest.raises(ValidationError) as exc_info:
        ClientSession(
            client_id=ClientId("client-invalid-writer"),
            public_key=valid_public_key,
            writer="not_a_writer",  # type: ignore[arg-type]
        )

    errors = exc_info.value.errors()
    assert any(
        err["loc"] == ("writer",) and err["type"] == "is_instance_of" for err in errors
    )


def test_create_client_session_invalid_public_key_type(mock_writer):
    with pytest.raises(ValidationError) as exc_info:
        ClientSession(
            client_id=ClientId("client-invalid-key-type"),
            public_key=123456,  # type: ignore[arg-type]
            writer=mock_writer,
        )

    errors = exc_info.value.errors()
    assert any(err["loc"] == ("public_key",) for err in errors)


def test_client_session_seq_send_increment(mock_writer, valid_public_key):
    session = ClientSession(
        client_id=ClientId("client-seq-inc"),
        public_key=valid_public_key,
        writer=mock_writer,
    )
    assert session.seq_send == 0

    session.seq_send += 1
    assert session.seq_send == 1

    session.seq_send += 5
    assert session.seq_send == 6
