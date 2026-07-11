"""Taint engine for DataTrace.

Core idea (from DSO/MPTC project notes):
  * Every allocation carries a 64-bit taint label (bitmask).
  * Each bit marks an *origin* of the data (network recv, file input, argv...).
  * A copy combines source labels via an L-function (default: union / bitwise OR).
  * Sinks (sendto/send) are checked: if their bytes carry an untrusted label,
    that is a data-flow path worth reporting.

Shadow memory is modelled as an interval map keyed by [start, end) -> label,
which is exact enough for memcpy/memmove propagation and far cheaper than a
per-byte shadow map for whole-binary traces.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

# Taint origin bits (64-bit label)
T_NETWORK = 1 << 0      # data from recvfrom()/recv() — attacker-influenced
T_FILE = 1 << 1         # data read from a file
T_ARGV = 1 << 2         # process arguments / environment
T_CONST = 1 << 3        # derived from a compile-time constant (still "trusted")
T_HEAP = 1 << 4         # freshly malloc'd zeroed memory (no origin yet)
T_STACK = 1 << 5        # stack scratch (no origin yet)

ORIGIN_NAMES = {
    T_NETWORK: "network",
    T_FILE: "file",
    T_ARGV: "argv",
    T_CONST: "const",
    T_HEAP: "heap",
    T_STACK: "stack",
}


def label_to_names(label: int) -> list[str]:
    names = [ORIGIN_NAMES[b] for b in ORIGIN_NAMES if label & b]
    if not names:
        names = ["clean"]
    return names


def L_union(labels: Iterable[int]) -> int:
    """L-function: union of all source origins (bitwise OR)."""
    out = 0
    for l in labels:
        out |= l
    return out


def L_intersect(labels: Iterable[int]) -> int:
    """L-function: intersection (all sources must agree)."""
    it = iter(labels)
    try:
        out = next(it)
    except StopIteration:
        return 0
    for l in it:
        out &= l
    return out


L_DEFAULT = L_union


@dataclass(slots=True)
class Interval:
    start: int
    end: int          # exclusive
    label: int


@dataclass
class TaintSink:
    kind: str         # "sendto" / "send"
    ts: int
    pid: int
    addr: int
    size: int
    label: int        # combined taint of the bytes being sent


@dataclass
class TaintReport:
    tainted_objects: list = field(default_factory=list)
    sinks: list = field(default_factory=list)
    untrusted_to_sink: list = field(default_factory=list)

    def summary(self) -> str:
        lines = ["=== Taint Report ==="]
        lines.append(f"Allocations carrying a taint label: {len(self.tainted_objects)}")
        for o in self.tainted_objects[:20]:
            lines.append(f"  {o['addr']:#x}..{o['addr']+o['size']:#x} "
                         f"size={o['size']} -> {','.join(label_to_names(o['label']))}")
        if len(self.tainted_objects) > 20:
            lines.append(f"  ... and {len(self.tainted_objects)-20} more")
        lines.append(f"Network sinks observed: {len(self.sinks)}")
        lines.append(f"UNTRUSTED data reaching a sink: {len(self.untrusted_to_sink)}")
        for s in self.untrusted_to_sink[:20]:
            lines.append(f"  [{s.kind}] {s.addr:#x} size={s.size} "
                         f"taint={','.join(label_to_names(s.label))}")
        return "\n".join(lines)


class TaintEngine:
    """64-bit taint tracker over an event stream."""

    def __init__(self, lfunc=L_DEFAULT):
        self.lfunc = lfunc
        self._intervals: list[Interval] = []
        self._allocs: dict[int, Interval] = {}
        self.sinks: list[TaintSink] = []
        self._events = 0

    def _query(self, addr: int, size: int) -> int:
        """Taint over [addr, addr+size): L of every overlapping interval."""
        end = addr + size
        labels = [iv.label for iv in self._intervals
                  if not (iv.end <= addr or iv.start >= end)]
        return self.lfunc(labels) if labels else 0

    def _set(self, addr: int, size: int, label: int):
        """Overwrite taint for [addr, addr+size) with `label`."""
        if size <= 0:
            return
        end = addr + size
        kept = []
        for iv in self._intervals:
            if iv.end <= addr or iv.start >= end:
                kept.append(iv)
                continue
            if iv.start < addr:
                kept.append(Interval(iv.start, addr, iv.label))
            if iv.end > end:
                kept.append(Interval(end, iv.end, iv.label))
        kept.append(Interval(addr, end, label))
        self._intervals = kept
        for base, iv in list(self._allocs.items()):
            if addr <= base < end:
                self._allocs[base] = Interval(base, iv.end, label)

    def _remove(self, addr: int):
        self._intervals = [iv for iv in self._intervals if iv.start != addr]
        self._allocs.pop(addr, None)

    def feed(self, ev) -> None:
        """Feed a RawEvent (see dtrace.events)."""
        self._events += 1
        t = ev.event_type
        if ev.is_alloc_ret:
            iv = Interval(ev.addr, ev.addr + ev.size, T_HEAP)
            self._allocs[ev.addr] = iv
            self._intervals.append(iv)
        elif ev.is_free:
            self._remove(ev.addr)
        elif ev.is_copy:
            src_taint = self._query(ev.addr2, ev.size)
            dst_old = self._query(ev.addr, ev.size)
            self._set(ev.addr, ev.size, self.lfunc([src_taint, dst_old]))
        elif ev.is_network_recv:
            self._set(ev.addr, ev.size, self._query(ev.addr, ev.size) | T_NETWORK)
        elif ev.is_network_send:
            label = self._query(ev.addr, ev.size) | self._query(ev.addr2, ev.size)
            buf_addr = ev.addr if (self._query(ev.addr, ev.size) & ~T_HEAP) else ev.addr2
            self.sinks.append(TaintSink("sendto", ev.ts, ev.pid,
                                        buf_addr, ev.size, label))

    def feed_all(self, events: Iterable) -> None:
        for ev in events:
            self.feed(ev)

    def report(self) -> TaintReport:
        tainted = [
            {"addr": iv.start, "size": iv.end - iv.start, "label": iv.label}
            for iv in self._intervals
            if iv.label & ~T_HEAP
        ]
        untrusted = [s for s in self.sinks if s.label & T_NETWORK]
        return TaintReport(tainted_objects=tainted, sinks=self.sinks,
                           untrusted_to_sink=untrusted)

    def flow_dot(self, title: str = "taint-flow") -> str:
        """Graphviz DOT of which taint origins reach which sinks."""
        lines = [f'digraph "{title}" {{', "  rankdir=LR;"]
        origin_nodes = {}
        idx = 0
        for bit, name in ORIGIN_NAMES.items():
            if bit in (T_HEAP, T_STACK, T_CONST):
                continue
            nid = f"o{idx}"
            origin_nodes[bit] = nid
            lines.append(f'  {nid} [label="{name}", shape=box, style=filled, '
                         f'fillcolor="#ffd966"];')
            idx += 1
        for i, s in enumerate(self.sinks):
            sid = f"s{i}"
            tag = "UNTRUSTED" if (s.label & T_NETWORK) else "ok"
            color = "#f8cecc" if (s.label & T_NETWORK) else "#dae8fc"
            lines.append(f'  {sid} [label="{s.kind}\\n{s.addr:#x}\\nsize={s.size}\\n[{tag}]", '
                         f'shape=ellipse, style=filled, fillcolor="{color}"];')
            for bit, nid in origin_nodes.items():
                if s.label & bit:
                    lines.append(f"  {nid} -> {sid};")
        lines.append("}")
        return "\n".join(lines)


def build_from_events(events: Iterable) -> TaintEngine:
    eng = TaintEngine()
    eng.feed_all(events)
    return eng
