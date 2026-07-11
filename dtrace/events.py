"""Event types and event stream parsing."""

import json
import struct
from enum import IntEnum, IntFlag
from dataclasses import dataclass
from typing import BinaryIO, Iterator


class EventType(IntEnum):
    MALLOC = 1
    FREE = 2
    CALLOC = 3
    MEMCPY = 4
    MEMMOVE = 5
    SENDTO = 6
    RECVFROM = 7
    SEND = 8
    RECV = 9


class RetFlag(IntFlag):
    RET_MASK = 0x1000


@dataclass(slots=True)
class RawEvent:
    ts: int
    pid: int
    tid: int
    type: int
    addr: int
    addr2: int
    size: int
    sample: bytes = b""

    @property
    def event_type(self) -> EventType:
        return EventType(self.type & ~0x1000)

    @property
    def is_ret(self) -> bool:
        return bool(self.type & 0x1000)

    @property
    def is_alloc(self) -> bool:
        return self.event_type in (EventType.MALLOC, EventType.CALLOC) and not self.is_ret

    @property
    def is_free(self) -> bool:
        return self.event_type == EventType.FREE

    @property
    def is_alloc_ret(self) -> bool:
        return self.event_type in (EventType.MALLOC, EventType.CALLOC) and self.is_ret

    @property
    def is_copy(self) -> bool:
        return self.event_type in (EventType.MEMCPY, EventType.MEMMOVE)

    @property
    def is_network_send(self) -> bool:
        return self.event_type in (EventType.SENDTO, EventType.SEND)

    @property
    def is_network_recv(self) -> bool:
        return self.event_type in (EventType.RECVFROM, EventType.RECV)

    def __str__(self) -> str:
        t = self.event_type.name if self.event_type in EventType.__members__.values() else str(self.event_type)
        if self.is_ret:
            t += "_RET"
        return f"[{self.ts}] pid={self.pid} {t} addr={self.addr:#x} addr2={self.addr2:#x} size={self.size}"

    @classmethod
    def from_json(cls, line: str) -> "RawEvent":
        d = json.loads(line)
        sample = b""
        if "sample" in d and d["sample"]:
            sample = bytes(d["sample"])
        elif "sample_b64" in d:
            import base64
            sample = base64.b64decode(d["sample_b64"])
        return cls(
            ts=d["ts"],
            pid=d["pid"],
            tid=d["tid"],
            type=d["type"],
            addr=d["addr"],
            addr2=d["addr2"],
            size=d["size"],
            sample=sample,
        )

    def to_json(self) -> str:
        d = {
            "ts": self.ts,
            "pid": self.pid,
            "tid": self.tid,
            "type": self.type,
            "addr": self.addr,
            "addr2": self.addr2,
            "size": self.size,
        }
        if self.sample:
            import base64
            d["sample_b64"] = base64.b64encode(self.sample).decode()
        return json.dumps(d)


def parse_line(line: str) -> RawEvent | None:
    line = line.strip()
    if not line or not line.startswith("{"):
        return None
    try:
        return RawEvent.from_json(line)
    except (json.JSONDecodeError, KeyError):
        return None


def iter_events(source: Iterator[str]) -> Iterator[RawEvent]:
    for line in source:
        ev = parse_line(line)
        if ev:
            yield ev
