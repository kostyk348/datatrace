"""PcapEventSource — ingest packet captures into the DataTrace pipeline.

Reads a pcap file, reassembles TCP/UDP flows, recovers protocol schema,
and optionally bridges into the provenance graph via virtual memory objects.

Usage:
    source = PcapEventSource()
    source.feed("capture.pcap")
    source.analyze()
    print(source.summary())
"""

import struct
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import Any
from .pcap import Packet, iter_packets
from .schema import SchemaRecovery, ProtocolSchema, MessageType, ProtoField


GAME_SERVER_PORTS = {
    26000, 27015, 27016, 27960, 27961, 27965, 27969,
    7777, 7778, 8000, 28910, 28960, 29910,
    3074, 22000, 23000, 25565,
}

WELL_KNOWN_PORTS = {19, 53, 80, 123, 443, 993, 3306, 6379, 8080, 8443}

SERVER_PORT_CANDIDATES = WELL_KNOWN_PORTS | GAME_SERVER_PORTS


@dataclass
class FlowKey:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: int

    def reverse(self) -> "FlowKey":
        return FlowKey(self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.proto)

    def __hash__(self) -> int:
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.proto))


@dataclass
class FlowStats:
    packet_count: int = 0
    byte_count: int = 0
    first_ts: int = 0
    last_ts: int = 0
    duration_us: int = 0
    interarrival_us: list[int] = field(default_factory=list)

    @property
    def avg_interarrival_us(self) -> float:
        if not self.interarrival_us:
            return 0.0
        return sum(self.interarrival_us) / len(self.interarrival_us)

    @property
    def pps(self) -> float:
        dur_s = self.duration_us / 1e6
        return self.packet_count / dur_s if dur_s > 0 else 0

    @property
    def bps(self) -> float:
        dur_s = self.duration_us / 1e6
        return self.byte_count * 8 / dur_s if dur_s > 0 else 0


@dataclass
class Flow:
    key: FlowKey
    packets: list[Packet] = field(default_factory=list)
    payloads: list[bytes] = field(default_factory=list)
    stats: FlowStats = field(default_factory=FlowStats)

    @property
    def is_server_side(self) -> bool:
        return _is_server_port(self.key.dst_port)

    @property
    def server_port(self) -> int:
        return self.key.dst_port if self.is_server_side else self.key.src_port

    @property
    def protocol_name(self) -> str:
        return {6: "TCP", 17: "UDP"}.get(self.key.proto, f"IP-{self.key.proto}")

    def finalize_stats(self):
        self.stats.packet_count = len(self.packets)
        self.stats.byte_count = sum(len(p.payload) for p in self.packets)
        if self.packets:
            self.stats.first_ts = self.packets[0].ts
            self.stats.last_ts = self.packets[-1].ts
            self.stats.duration_us = self.packets[-1].ts - self.packets[0].ts
            for i in range(1, len(self.packets)):
                gap = self.packets[i].ts - self.packets[i - 1].ts
                if gap > 0:
                    self.stats.interarrival_us.append(gap)


@dataclass
class MessageBoundary:
    """A single application-layer message within a flow."""
    flow_key: FlowKey
    ts: int
    payload: bytes
    direction: str  # "C→S" or "S→C"
    msg_index: int
    seq: int = 0
    is_retransmit: bool = False


@dataclass
class SessionTimeline:
    """Ordered sequence of messages in one direction of a flow."""
    flow_key: FlowKey
    direction: str
    messages: list[MessageBoundary] = field(default_factory=list)

    @property
    def first_ts(self) -> int:
        return self.messages[0].ts if self.messages else 0

    @property
    def last_ts(self) -> int:
        return self.messages[-1].ts if self.messages else 0

    @property
    def duration_us(self) -> int:
        return self.last_ts - self.first_ts if self.messages else 0

    def detect_sessions(self, gap_us: int = 5_000_000) -> list[int]:
        """Split timeline into sessions at gaps > gap_us. Returns split indices."""
        splits = [0]
        for i in range(1, len(self.messages)):
            gap = self.messages[i].ts - self.messages[i - 1].ts
            if gap > gap_us:
                splits.append(i)
        splits.append(len(self.messages))
        return splits


class TcpReassembler:
    """Simple TCP stream reassembly tracking sequence numbers."""

    def __init__(self):
        self._partial: dict[FlowKey, bytes] = {}
        self._next_seq: dict[FlowKey, int] = {}

    def feed(self, pkt: Packet) -> list[MessageBoundary]:
        """Feed a TCP packet, return completed reassembled messages.

        Extracts TCP sequence number from the raw packet data.
        Falls back to whole-payload mode if header parsing fails.
        """
        key = FlowKey(
            pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.proto
        )
        tcp_hdr = self._parse_tcp_header(pkt.raw)
        if tcp_hdr is None:
            return [MessageBoundary(
                flow_key=key, ts=pkt.ts, payload=pkt.payload,
                direction="", msg_index=0,
            )]

        seq, ack, flags, hdr_len = tcp_hdr
        payload = pkt.payload[hdr_len:] if hdr_len < len(pkt.payload) else b""

        is_retransmit = False
        if key in self._next_seq and seq < self._next_seq[key]:
            is_retransmit = True
            return []

        expected_seq = self._next_seq.get(key, seq)
        if seq > expected_seq and self._partial.get(key):
            gap = seq - expected_seq
            self._partial[key] += b"\x00" * gap

        self._next_seq[key] = seq + len(payload)

        if key not in self._partial:
            self._partial[key] = b""
        self._partial[key] += payload

        msgs = []
        while len(self._partial[key]) >= 4:
            pkt_type = int.from_bytes(self._partial[key][:4], 'little')
            if pkt_type == 0:
                break
            msg_len = min(len(self._partial[key]), 4096)
            chunk = self._partial[key][:msg_len]
            msgs.append(MessageBoundary(
                flow_key=key, ts=pkt.ts, payload=chunk,
                direction="", msg_index=0, seq=seq,
                is_retransmit=False,
            ))
            self._partial[key] = self._partial[key][msg_len:]

        return msgs

    @staticmethod
    def _parse_tcp_header(raw: bytes) -> tuple | None:
        """Extract (seq, ack, flags, hdr_len) from raw IP packet."""
        if len(raw) < 40:
            return None
        ip_ver = raw[0] >> 4
        ip_hdr_len = (raw[0] & 0x0F) * 4
        if ip_ver == 4:
            if len(raw) < ip_hdr_len + 20:
                return None
            tcp_offset = ip_hdr_len
        elif ip_ver == 6:
            ipv6_hdr_len = 40
            next_hdr = raw[6]
            tcp_offset = ipv6_hdr_len
            if next_hdr != 6:
                return None
        else:
            return None

        if tcp_offset + 14 > len(raw):
            return None
        seq = struct.unpack_from(">I", raw, tcp_offset + 4)[0]
        ack = struct.unpack_from(">I", raw, tcp_offset + 8)[0]
        flags = raw[tcp_offset + 13]
        data_offset = (raw[tcp_offset + 12] >> 4) * 4
        return seq, ack, flags, data_offset


def _is_server_port(port: int) -> bool:
    return port < 1024 or port in SERVER_PORT_CANDIDATES


def _classify_direction(src_port: int, dst_port: int) -> str:
    """Classify packet direction: C→S or S→C based on port heuristics."""
    if _is_server_port(dst_port):
        return "C→S"
    if _is_server_port(src_port):
        return "S→C"
    if src_port > dst_port:
        return "C→S"
    return "S→C"


def _detect_protocol(payloads: list[bytes], ports: tuple[int, int]) -> str:
    """Detect application protocol from payload patterns."""
    if not payloads:
        return "unknown"
    first = payloads[0]
    if len(first) < 2:
        return "unknown"

    # HTTP
    if first[:4] in (b"GET ", b"POST", b"PUT ", b"HEAD", b"HTTP"):
        return "HTTP"
    if first[:4] in (b"PRI ", b"* HT"):
        return "HTTP2"

    # DNS
    if len(first) >= 12 and ports[0] == 53 or ports[1] == 53:
        return "DNS"

    # TLS
    if first[0] == 0x16 and first[1] == 0x03:
        return "TLS"

    # Check all payloads for common patterns
    text_count = 0
    binary_count = 0
    for p in payloads[:20]:
        text = sum(1 for b in p[:64] if 32 <= b < 127)
        if text > len(p[:64]) * 0.7:
            text_count += 1
        else:
            binary_count += 1

    if text_count > binary_count:
        return "text"
    return "binary"


class PcapEventSource:
    """Full pipeline from pcap to protocol schema + provenance overview."""

    def __init__(self):
        self._packets: list[Packet] = []
        self._flows: dict[FlowKey, Flow] = {}
        self._timelines: list[SessionTimeline] = []
        self._schema: ProtocolSchema | None = None
        self._protocol_map: dict[FlowKey, str] = {}

    def feed(self, path: str) -> int:
        """Parse a pcap file and group packets into flows.

        Returns packet count.
        """
        count = 0
        for pkt in iter_packets(path):
            self._packets.append(pkt)
            key = FlowKey(
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                src_port=pkt.src_port,
                dst_port=pkt.dst_port,
                proto=pkt.proto,
            )
            if key not in self._flows:
                self._flows[key] = Flow(key=key)
            flow = self._flows[key]
            flow.packets.append(pkt)
            flow.payloads.append(pkt.payload)
            count += 1
        for flow in self._flows.values():
            flow.finalize_stats()
        return count

    def build_flows(self):
        """Build session timelines from grouped flows with direction detection."""
        self._timelines.clear()

        for key, flow in self._flows.items():
            c2s_key, s2c_key = self._resolve_directions(key)

            c2s_tl = SessionTimeline(flow_key=c2s_key, direction="C→S")
            s2c_tl = SessionTimeline(flow_key=s2c_key, direction="S→C")
            c2s_idx = 0
            s2c_idx = 0

            for pkt in flow.packets:
                direction = _classify_direction(pkt.src_port, pkt.dst_port)
                if direction == "C→S":
                    tl = c2s_tl
                    idx = c2s_idx
                    c2s_idx += 1
                else:
                    tl = s2c_tl
                    idx = s2c_idx
                    s2c_idx += 1

                mb = MessageBoundary(
                    flow_key=key,
                    ts=pkt.ts,
                    payload=pkt.payload,
                    direction=direction,
                    msg_index=idx,
                )
                tl.messages.append(mb)

            if c2s_tl.messages:
                self._timelines.append(c2s_tl)
            if s2c_tl.messages:
                self._timelines.append(s2c_tl)

        self._timelines.sort(key=lambda tl: tl.first_ts if tl.messages else 0)

        # Detect protocol per flow
        for key, flow in self._flows.items():
            self._protocol_map[key] = _detect_protocol(
                flow.payloads, (key.src_port, key.dst_port)
            )

    @staticmethod
    def _resolve_directions(key: FlowKey) -> tuple[FlowKey, FlowKey]:
        """Determine C→S and S→C flow keys from a bidirectional flow."""
        if _is_server_port(key.dst_port):
            return key, key.reverse()
        if _is_server_port(key.src_port):
            return key.reverse(), key
        if key.dst_port < key.src_port:
            return key, key.reverse()
        return key.reverse(), key

    def recover_schema(self) -> ProtocolSchema:
        """Recover protocol schema from all flows."""
        sr = SchemaRecovery()
        sr.feed_packets(self._packets)
        self._schema = sr.recover_schema()
        return self._schema

    def analyze(self) -> dict:
        """Run full analysis: build flows, recover schema, classify messages."""
        self.build_flows()
        schema = self.recover_schema()

        message_classes: dict[str, list[MessageBoundary]] = {}
        for tl in self._timelines:
            for mb in tl.messages:
                if len(mb.payload) < 4:
                    continue
                pkt_type = int.from_bytes(mb.payload[:4], 'little')
                matched = False
                for mt in schema.messages:
                    if mt.type_id == pkt_type:
                        key = f"type_{mt.type_id}_len_{mt.total_len}"
                        if key not in message_classes:
                            message_classes[key] = []
                        message_classes[key].append(mb)
                        matched = True
                        break
                if not matched:
                    key = f"unknown_len_{len(mb.payload)}"
                    if key not in message_classes:
                        message_classes[key] = []
                    message_classes[key].append(mb)

        flow_summaries = []
        for key, flow in self._flows.items():
            fwd, rev = self._resolve_directions(key)
            c2s_count = 0
            s2c_count = 0
            for pkt in flow.packets:
                if _classify_direction(pkt.src_port, pkt.dst_port) == "C→S":
                    c2s_count += 1
                else:
                    s2c_count += 1

            flow_summaries.append({
                "src": f"{key.src_ip}:{key.src_port}",
                "dst": f"{key.dst_ip}:{key.dst_port}",
                "proto": flow.protocol_name,
                "app_protocol": self._protocol_map.get(key, "unknown"),
                "packets": flow.stats.packet_count,
                "bytes": flow.stats.byte_count,
                "duration_us": flow.stats.duration_us,
                "c2s_packets": c2s_count,
                "s2c_packets": s2c_count,
                "pps": flow.stats.pps,
                "bps": flow.stats.bps,
                "avg_interarrival_us": flow.stats.avg_interarrival_us,
            })

        return {
            "flows": len(self._flows),
            "packets": len(self._packets),
            "timelines": len(self._timelines),
            "schema": schema,
            "message_classes": message_classes,
            "flow_summaries": flow_summaries,
            "total_timeline_ms": (
                (self._timelines[-1].last_ts - self._timelines[0].first_ts) / 1e6
                if self._timelines else 0
            ),
            "protocols": Counter(self._protocol_map.values()),
        }

    def summary(self) -> str:
        """Produce a human-readable summary of the pcap analysis."""
        result = self.analyze()
        schema = result["schema"]

        lines = [
            "=== Pcap Analysis ===",
            f"Packets: {result['packets']}",
            f"Flows:   {result['flows']}",
            f"Timelines: {result['timelines']}",
            f"Span:    {result['total_timeline_ms']:.1f} ms",
            "",
            "Protocols:",
        ]
        for proto, count in result["protocols"].most_common():
            lines.append(f"  {proto:<12} {count} flow(s)")
        lines.append("")

        # Top flows by bytes
        lines.append("Top flows:")
        for fs in sorted(
            result["flow_summaries"],
            key=lambda x: x["bytes"],
            reverse=True,
        )[:5]:
            lines.append(
                f"  {fs['src']} → {fs['dst']} "
                f"({fs['proto']}/{fs['app_protocol']}) "
                f"{fs['packets']}pkts/{fs['bytes']}B "
                f"dir={fs['c2s_packets']}C→S/{fs['s2c_packets']}S→C"
            )
        lines.append("")

        lines.append(schema.summary())
        lines.append("")

        lines.append("Message classes:")
        for key, msgs in sorted(
            result["message_classes"].items(),
            key=lambda x: len(x[1]),
            reverse=True,
        ):
            sample = msgs[0].payload[:16].hex() if msgs[0].payload else "(empty)"
            direction_counts = Counter(m.direction for m in msgs)
            dir_str = ", ".join(f"{d}={c}" for d, c in direction_counts.most_common())
            lines.append(
                f"  {key:<30} count={len(msgs):<5} "
                f"{dir_str}  sample={sample}"
            )

        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Export analysis as a serializable dict."""
        result = self.analyze()
        schema = result["schema"]
        return {
            "packet_count": result["packets"],
            "flow_count": result["flows"],
            "timeline_count": result["timelines"],
            "span_ms": result["total_timeline_ms"],
            "protocols": dict(result["protocols"]),
            "flows": result["flow_summaries"],
            "schema": [
                {
                    "type_id": mt.type_id,
                    "total_len": mt.total_len,
                    "count": mt.count,
                    "sample_payload": mt.sample_payload.hex() if mt.sample_payload else "",
                    "direction_ratio": _direction_ratio_for_type(self._timelines, mt.type_id),
                    "fields": [
                        {
                            "offset": f.offset,
                            "size": f.size,
                            "type": f.type_hint,
                            "semantic": f.semantic_hint,
                            "constant": f.constant_value,
                            "unique_values": f.unique_values,
                        }
                        for f in mt.fields
                    ],
                }
                for mt in schema.messages
            ],
        }


def _direction_ratio_for_type(
    timelines: list[SessionTimeline], type_id: int
) -> dict[str, int]:
    """Count C→S vs S→C messages for a given message type."""
    result: dict[str, int] = {"C→S": 0, "S→C": 0}
    for tl in timelines:
        for mb in tl.messages:
            if len(mb.payload) >= 4:
                mt = int.from_bytes(mb.payload[:4], 'little')
                if mt == type_id:
                    result[mb.direction] += 1
    return result


def _build_synthetic_objects(recovery, source: PcapEventSource):
    """Build synthetic MemoryObjects from pcap message flows.

    Populates recovery with one MemoryObject per unique (type_id, entity_id)
    pair, including network events for direction-aware systems detection.
    """
    from uuid import uuid4
    from .objects import MemoryObject, Allocation, NetworkEvent, ObjectRecovery
    from .events import RawEvent, EventType
    from collections import defaultdict

    # Only process binary (non-HTTP/TLS) timelines
    binary_timelines = [
        tl for tl in source._timelines
        if source._protocol_map.get(tl.flow_key, "unknown") not in ("HTTP", "HTTP2", "TLS")
    ]

    type_payloads: dict[int, dict[int, list[tuple[bytes, str, int]]]] = defaultdict(lambda: defaultdict(list))
    for tl in binary_timelines:
        for mb in tl.messages:
            if len(mb.payload) >= 8:
                mt = int.from_bytes(mb.payload[:4], 'little')
                eid = int.from_bytes(mb.payload[4:8], 'little')
                type_payloads[mt][eid].append((mb.payload[:256], mb.direction, mb.ts))

    for mt, entity_map in type_payloads.items():
        for eid, entries in entity_map.items():
            payloads = [e[0] for e in entries]
            directions = [e[1] for e in entries]
            timestamps = [e[2] for e in entries]
            first_ts = timestamps[0]
            mo = MemoryObject(
                uuid=uuid4(),
                addr=(mt << 32) | eid,
                size=len(payloads[0]),
                pid=0,
                tid=0,
                label=f"msg_type_{mt}_entity_{eid}",
                untracked=True,
                created_ts=first_ts,
            )
            mo.allocations.append(Allocation(
                uuid=uuid4(), addr=mo.addr, size=mo.size,
                pid=0, tid=0, created_ts=first_ts,
            ))
            for p in payloads:
                mo.samples.append(p)

            is_c2s = all(d == "C→S" for d in directions)
            for ts in timestamps:
                revt = RawEvent(
                    ts=ts, pid=0, tid=0,
                    type=EventType.SENDTO if is_c2s else EventType.RECVFROM,
                    addr=mo.addr, addr2=0, size=mo.size,
                )
                nevt = NetworkEvent(
                    uuid=uuid4(), fd=0, buf_addr=mo.addr,
                    size=mo.size, ts=ts,
                    is_send=is_c2s,
                    event=revt,
                )
                if is_c2s:
                    mo.network_sends.append(nevt)
                else:
                    mo.network_recvs.append(nevt)

            recovery._objects[mo.uuid] = mo
            recovery._addr_to_obj[mo.addr] = mo.uuid
            recovery._interval_idx.append(
                (mo.addr, mo.addr + mo.size, mo.uuid)
            )
