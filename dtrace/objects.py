"""Memory Object Recovery — from raw events to tracked allocations."""

import bisect
from uuid import uuid4, UUID
from dataclasses import dataclass, field
from typing import Iterator
from .events import RawEvent, EventType


@dataclass(slots=True)
class Allocation:
    uuid: UUID
    addr: int
    size: int
    pid: int
    tid: int
    created_ts: int
    destroyed_ts: int | None = None
    event_create: RawEvent | None = None
    event_destroy: RawEvent | None = None


@dataclass(slots=True)
class CopyEvent:
    uuid: UUID
    dst_addr: int
    src_addr: int
    size: int
    ts: int
    event: RawEvent


@dataclass(slots=True)
class NetworkEvent:
    uuid: UUID
    fd: int
    buf_addr: int
    size: int
    ts: int
    is_send: bool
    event: RawEvent


@dataclass
class MemoryObject:
    uuid: UUID
    addr: int
    size: int
    pid: int
    tid: int
    label: str = "unknown"
    type_hint: str | None = None
    untracked: bool = False

    allocations: list[Allocation] = field(default_factory=list)
    copies_in: list[CopyEvent] = field(default_factory=list)
    copies_out: list[CopyEvent] = field(default_factory=list)
    network_sends: list[NetworkEvent] = field(default_factory=list)
    network_recvs: list[NetworkEvent] = field(default_factory=list)
    samples: list[bytes] = field(default_factory=list)

    created_ts: int = 0
    destroyed_ts: int | None = None

    def __post_init__(self):
        if self.allocations:
            self.created_ts = min(a.created_ts for a in self.allocations)
            active = [a for a in self.allocations if a.destroyed_ts is not None]
            if active and len(active) == len(self.allocations):
                self.destroyed_ts = max(a.destroyed_ts for a in active)

    @property
    def is_alive(self) -> bool:
        return self.destroyed_ts is None

    @property
    def total_size(self) -> int:
        return sum(a.size for a in self.allocations)

    @property
    def is_ghost(self) -> bool:
        return len(self.allocations) == 0 and not self.untracked


class ObjectRecovery:
    """Recovers Memory Objects from RawEvents."""

    def __init__(self):
        self._pending_allocs: dict[int, RawEvent] = {}
        self._objects: dict[UUID, MemoryObject] = {}
        self._addr_to_obj: dict[int, UUID] = {}
        self._events: list[RawEvent] = []

        # Interval index for O(log n) address lookup
        # List of (start, end, uuid) sorted by start
        self._interval_idx: list[tuple[int, int, UUID]] = []

    def _rebuild_index(self):
        self._interval_idx.clear()
        for uid, obj in self._objects.items():
            self._interval_idx.append((obj.addr, obj.addr + obj.size, uid))
        self._interval_idx.sort(key=lambda x: x[0])

    @property
    def objects(self) -> list[MemoryObject]:
        return list(self._objects.values())

    def find_object(self, addr: int) -> MemoryObject | None:
        if not self._interval_idx:
            return None
        i = bisect.bisect_right(self._interval_idx, (addr, 1 << 64, UUID(int=0)))
        if i == 0:
            return None
        start, end, uid = self._interval_idx[i - 1]
        if start <= addr < end:
            return self._objects.get(uid)
        return None

    def feed(self, ev: RawEvent):
        self._events.append(ev)

        if ev.is_alloc:
            self._pending_allocs[ev.tid] = ev

        elif ev.is_alloc_ret:
            pending = self._pending_allocs.pop(ev.tid, None)
            if pending:
                size = pending.size if pending.event_type == EventType.MALLOC else pending.addr * pending.addr2
                self._register_allocation(ev.addr, size, ev.pid, ev.tid, pending.ts, ev)

        elif ev.is_free:
            self._register_free(ev.addr, ev.ts)

        elif ev.is_copy:
            self._register_copy(ev)

        elif ev.is_network_send:
            self._register_net(ev, is_send=True)

        elif ev.is_network_recv:
            self._register_net(ev, is_send=False)

    # ─── Direct API for non-eBPF tracers (LD_PRELOAD, etc.) ───

    def add_allocation(self, addr: int, size: int, pid: int, tid: int,
                        ts: int, event: RawEvent | None = None):
        """Register an allocation directly (single event)."""
        self._register_allocation(addr, size, pid, tid, ts, event)

    def add_free(self, addr: int, ts: int, event: RawEvent | None = None):
        """Register a free directly."""
        self._register_free(addr, ts)

    def add_copy(self, dst_addr: int, src_addr: int, size: int, ts: int,
                 event: RawEvent | None = None):
        """Register a memory copy directly."""
        copy = CopyEvent(
            uuid=uuid4(),
            dst_addr=dst_addr,
            src_addr=src_addr,
            size=size,
            ts=ts,
            event=event,
        )
        src_obj = self.find_object(src_addr)
        if not src_obj:
            src_obj = self._ensure_untracked(src_addr, size, ts, 0)
        src_obj.copies_out.append(copy)

        dst_obj = self.find_object(dst_addr)
        if not dst_obj:
            dst_obj = self._ensure_untracked(dst_addr, size, ts, 0)
        dst_obj.copies_in.append(copy)
        if event and event.sample:
            dst_obj.samples.append(event.sample)

    def add_network_send(self, buf_addr: int, fd: int, size: int, ts: int,
                          event: RawEvent | None = None):
        """Register a network send directly."""
        net = NetworkEvent(
            uuid=uuid4(),
            fd=fd,
            buf_addr=buf_addr,
            size=size,
            ts=ts,
            is_send=True,
            event=event,
        )
        obj = self.find_object(buf_addr)
        if not obj:
            obj = self._ensure_untracked(buf_addr, size, ts, 0)
        obj.network_sends.append(net)
        if event and event.sample:
            obj.samples.append(event.sample)

    def add_network_recv(self, buf_addr: int, fd: int, size: int, ts: int,
                          event: RawEvent | None = None):
        """Register a network recv directly."""
        net = NetworkEvent(
            uuid=uuid4(),
            fd=fd,
            buf_addr=buf_addr,
            size=size,
            ts=ts,
            is_send=False,
            event=event,
        )
        obj = self.find_object(buf_addr)
        if not obj:
            obj = self._ensure_untracked(buf_addr, size, ts, 0)
        obj.network_recvs.append(net)
        if event and event.sample:
            obj.samples.append(event.sample)

    def _register_allocation(self, addr: int, size: int, pid: int, tid: int,
                              ts: int, ret_ev: RawEvent):
        alloc = Allocation(
            uuid=uuid4(),
            addr=addr,
            size=size,
            pid=pid,
            tid=tid,
            created_ts=ts,
            event_create=ret_ev,
        )

        existing_uuid = self._addr_to_obj.get(addr)
        if existing_uuid and existing_uuid in self._objects:
            obj = self._objects[existing_uuid]
            obj.allocations.append(alloc)
            old_size = obj.size
            obj.size = max(obj.size, addr + size - obj.addr)
            obj.created_ts = min(obj.created_ts, ts)
            if old_size != obj.size:
                self._rebuild_index()
        else:
            obj = MemoryObject(
                uuid=uuid4(),
                addr=addr,
                size=size,
                pid=pid,
                tid=tid,
                created_ts=ts,
                allocations=[alloc],
            )
            self._objects[obj.uuid] = obj
            self._addr_to_obj[addr] = obj.uuid
            self._interval_idx.append((addr, addr + size, obj.uuid))
            self._interval_idx.sort(key=lambda x: x[0])

    def _register_free(self, addr: int, ts: int):
        uuid_str = self._addr_to_obj.get(addr)
        if uuid_str and uuid_str in self._objects:
            obj = self._objects[uuid_str]
            for alloc in obj.allocations:
                if alloc.addr == addr and alloc.destroyed_ts is None:
                    alloc.destroyed_ts = ts
                    break
            if all(a.destroyed_ts is not None for a in obj.allocations if a.addr != 0):
                obj.destroyed_ts = ts

    def _ensure_untracked(self, addr: int, size: int, ts: int, pid: int) -> MemoryObject:
        obj = self.find_object(addr)
        if obj:
            return obj
        obj = MemoryObject(
            uuid=uuid4(),
            addr=addr,
            size=size,
            pid=pid,
            tid=0,
            untracked=True,
            label=f"buf_{addr:#x}",
            created_ts=ts,
        )
        self._objects[obj.uuid] = obj
        self._interval_idx.append((addr, addr + size, obj.uuid))
        self._interval_idx.sort(key=lambda x: x[0])
        return obj

    def _register_copy(self, ev: RawEvent):
        copy = CopyEvent(
            uuid=uuid4(),
            dst_addr=ev.addr,
            src_addr=ev.addr2,
            size=ev.size,
            ts=ev.ts,
            event=ev,
        )

        src_obj = self.find_object(ev.addr2)
        if not src_obj:
            src_obj = self._ensure_untracked(ev.addr2, ev.size, ev.ts, ev.pid)
        src_obj.copies_out.append(copy)

        dst_obj = self.find_object(ev.addr)
        if not dst_obj:
            dst_obj = self._ensure_untracked(ev.addr, ev.size, ev.ts, ev.pid)
        dst_obj.copies_in.append(copy)

    def _register_net(self, ev: RawEvent, is_send: bool):
        net = NetworkEvent(
            uuid=uuid4(),
            fd=ev.addr,
            buf_addr=ev.addr2,
            size=ev.size,
            ts=ev.ts,
            is_send=is_send,
            event=ev,
        )

        obj = self.find_object(ev.addr2)
        if not obj:
            obj = self._ensure_untracked(ev.addr2, ev.size, ev.ts, ev.pid)
        if is_send:
            obj.network_sends.append(net)
        else:
            obj.network_recvs.append(net)
        if is_send and ev.sample:
            obj.samples.append(ev.sample)

    def summary(self) -> str:
        lines = [f"Memory Objects: {len(self._objects)}"]
        ghosts = sum(1 for o in self._objects.values() if o.is_ghost)
        untracked = sum(1 for o in self._objects.values() if o.untracked)
        if ghosts:
            lines.append(f"  (ghost nodes: {ghosts})")
        if untracked:
            lines.append(f"  (untracked buffers: {untracked})")
        for obj in sorted(self._objects.values(), key=lambda o: o.created_ts):
            if obj.untracked:
                status = "untracked"
            elif obj.is_ghost:
                status = "ghost"
            elif obj.is_alive:
                status = "alive"
            else:
                status = "dead"
            lines.append(
                f"  [{status}] {obj.uuid} addr={obj.addr:#x} "
                f"size={obj.size} allocs={len(obj.allocations)} "
                f"copies_in={len(obj.copies_in)} "
                f"copies_out={len(obj.copies_out)} "
                f"net_send={len(obj.network_sends)} "
                f"net_recv={len(obj.network_recvs)}"
            )
        return "\n".join(lines)
