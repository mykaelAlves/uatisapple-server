import asyncio
from uuid import UUID

from pydantic import UUID4, BaseModel, ConfigDict, Field, PrivateAttr

ClientId = UUID

MAX_SEQ = 2**64 - 1


class ClientSession(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, validate_assignment=True)

    client_id: UUID4
    public_key: bytes = Field(min_length=32, max_length=32)
    writer: asyncio.StreamWriter = Field(repr=False)
    salt: bytes = Field(min_length=16, max_length=16, repr=False)
    s2c_key: bytes = Field(min_length=16, max_length=16, repr=False)

    seq_send: int = Field(default=0, ge=0, le=MAX_SEQ)

    seq_recv: dict[UUID, int] = Field(default_factory=dict, repr=False)

    _send_lock: asyncio.Lock = PrivateAttr(default_factory=asyncio.Lock)

    @property
    def send_lock(self) -> asyncio.Lock:
        return self._send_lock

    def last_seq_to(self, recipient_id: UUID) -> int:
        return self.seq_recv.get(recipient_id, -1)

    def next_admin_seq(self) -> int:
        seq = self.seq_send
        self.seq_send = seq + 1
        return seq
