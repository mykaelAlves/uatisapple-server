import asyncio
from typing import NewType

from pydantic import BaseModel, Field

ClientId = NewType("ClientId", str)

class ClientSession(BaseModel):
    client_id: ClientId
    public_key: bytes
    writer: asyncio.StreamWriter
    seq_send: int = Field(default=0, ge=0)
    