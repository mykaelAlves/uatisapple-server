import asyncio
from typing import NewType

from pydantic import BaseModel, Field

ClientId = NewType("ClientId", str)


class ClientSession(BaseModel):
    model_config = {"arbitrary_types_allowed": True}

    client_id: ClientId
    public_key: bytes = Field(..., min_length=32)
    writer: asyncio.StreamWriter
    seq_send: int = Field(default=0, ge=0)
