import asyncio
import uuid
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from src.client_session import MAX_SEQ, ClientSession


@pytest.fixture
def mock_writer():
    return MagicMock(spec=asyncio.StreamWriter)


@pytest.fixture
def fields(mock_writer):
    return {
        "client_id": uuid.uuid4(),
        "public_key": b"k" * 32,
        "writer": mock_writer,
        "salt": b"s" * 16,
        "s2c_key": b"q" * 16,
    }


def test_create_client_session_success(fields):
    session = ClientSession(**fields)

    assert session.client_id == fields["client_id"]
    assert session.public_key == fields["public_key"]
    assert session.writer is fields["writer"]
    assert session.salt == fields["salt"]
    assert session.seq_send == 0
    assert session.seq_recv == {}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("public_key", b"a" * 31),
        ("public_key", b"a" * 33),
        ("salt", b"a" * 15),
        ("salt", b"a" * 17),
        ("s2c_key", b"a" * 15),
        ("seq_send", -1),
        ("seq_send", MAX_SEQ + 1),
        ("client_id", uuid.uuid1()),
        ("client_id", "nao-e-uuid"),
        ("writer", "not_a_writer"),
    ],
)
def test_invalid_fields_are_rejected(fields, field, value):
    with pytest.raises(ValidationError) as exc_info:
        ClientSession(**{**fields, field: value})
    assert any(err["loc"] == (field,) for err in exc_info.value.errors())


@pytest.mark.parametrize("missing", ["client_id", "public_key", "writer", "salt"])
def test_missing_required_fields(fields, missing):
    del fields[missing]
    with pytest.raises(ValidationError) as exc_info:
        ClientSession(**fields)
    assert any(err["loc"] == (missing,) for err in exc_info.value.errors())


def test_next_admin_seq_is_monotonic(fields):
    session = ClientSession(**fields)
    assert [session.next_admin_seq() for _ in range(3)] == [0, 1, 2]
    assert session.seq_send == 3


def test_seq_send_cannot_overflow(fields):
    session = ClientSession(**{**fields, "seq_send": MAX_SEQ})
    with pytest.raises(ValidationError):
        session.next_admin_seq()


def test_last_seq_to_defaults_to_minus_one(fields):
    session = ClientSession(**fields)
    peer = uuid.uuid4()
    assert session.last_seq_to(peer) == -1
    session.seq_recv[peer] = 4
    assert session.last_seq_to(peer) == 4


def test_secrets_are_not_in_repr(fields):
    text = repr(ClientSession(**fields))
    assert "salt" not in text
    assert "s2c_key" not in text
    assert str(fields["client_id"]) in text


def test_each_session_has_its_own_send_lock(fields):
    a = ClientSession(**fields)
    b = ClientSession(**{**fields, "client_id": uuid.uuid4()})
    assert a.send_lock is not b.send_lock
