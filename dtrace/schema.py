"""Protocol Schema Recovery — infer message layout from packet samples."""

import struct
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any
from .pcap import Packet
from .objects import ObjectRecovery


FIELD_TYPES = ["uint8", "uint16", "uint32", "uint64", "float", "bytes"]


@dataclass
class ProtoField:
    offset: int
    size: int
    type_hint: str = "bytes"
    semantic_hint: str = ""
    constant_value: int | None = None
    unique_values: int = 0

    def __str__(self) -> str:
        return f"  [{self.offset:+3d}] {self.type_hint:<8} {self.semantic_hint}"


@dataclass
class MessageType:
    type_id: int
    total_len: int
    count: int
    fields: list[ProtoField] = field(default_factory=list)
    sample_payload: bytes = b""

    def summary(self) -> str:
        lines = [f"MessageType(type_id={self.type_id}, len={self.total_len}, count={self.count})"]
        for f in self.fields:
            lines.append(str(f))
        return "\n".join(lines)


@dataclass
class ProtocolSchema:
    messages: list[MessageType] = field(default_factory=list)
    server_port: int = 0
    client_port: int = 0

    def summary(self) -> str:
        lines = [f"Protocol Schema — {len(self.messages)} message type(s)"]
        for m in self.messages:
            lines.append("")
            lines.append(m.summary())
        return "\n".join(lines)


class SchemaRecovery:
    """Infer protocol schema from packet captures + client memory traces."""

    def __init__(self, recovery: ObjectRecovery | None = None):
        self.recovery = recovery
        self._packets: list[Packet] = []

    def feed_packets(self, packets: list[Packet]):
        self._packets.extend(packets)

    def _cluster_packets(self) -> list[list[Packet]]:
        """Cluster packets by (payload_len, first 4 bytes)."""
        clusters: dict[tuple[int, int], list[Packet]] = defaultdict(list)
        for pkt in self._packets:
            if len(pkt.payload) < 4:
                continue
            # Skip text-based protocols (HTTP, etc.)
            text_ratio = sum(1 for b in pkt.payload[:32] if 32 <= b < 127) / max(len(pkt.payload[:32]), 1)
            if text_ratio > 0.8 and len(pkt.payload) > 20:
                continue
            type_id = int.from_bytes(pkt.payload[:4], 'little')
            # Skip likely text headers
            if type_id in (0x47455420, 0x48545450, 0x50524920):  # "GET ", "HTTP", "PRI "
                continue
            key = (len(pkt.payload), type_id)
            clusters[key].append(pkt)

        sorted_clusters = sorted(clusters.values(), key=lambda c: len(c), reverse=True)
        return [c for c in sorted_clusters if len(c) >= 2]

    def _infer_field_type(self, values: list[int], sample_payload: bytes, offset: int, size: int) -> str:
        if not values:
            return "bytes"
        unique = len(set(values))
        if unique == 1:
            return "magic"
        total_range = max(values) - min(values) if values else 0
        if size == 4:
            fvals = [struct.unpack_from("<f", sample_payload[offset:offset+4])[0] for _ in [0]]
            return "float"
        if size == 8:
            fvals = [struct.unpack_from("<d", sample_payload[offset:offset+8])[0] for _ in [0]]
            return "double"
        return f"uint{size * 8}"

    def _extract_values(self, packets: list[Packet], offset: int, size: int) -> list[int]:
        values = []
        for pkt in packets:
            if offset + size <= len(pkt.payload):
                val = int.from_bytes(pkt.payload[offset:offset+size], 'little')
                values.append(val)
        return values

    def _is_likely_float(self, packets: list[Packet], offset: int) -> bool:
        float_count = 0
        for pkt in packets[:20]:
            if offset + 4 > len(pkt.payload):
                continue
            try:
                val = struct.unpack_from("<f", pkt.payload, offset)[0]
                if 0.001 < abs(val) < 100000 and (val == int(val) for _ in []):
                    pass
                if 0.001 < abs(val) < 10000000:
                    float_count += 1
            except struct.error:
                pass
        return float_count >= len(packets[:20]) * 0.5

    def _detect_fields(self, cluster: list[Packet]) -> list[ProtoField]:
        if not cluster:
            return []
        sample = cluster[0].payload

        fields: list[ProtoField] = []
        offset = 0
        max_len = max(len(p.payload) for p in cluster)

        while offset + 1 < max_len:
            best_size = 1
            best_type = "uint8"
            best_unique = 0

            # Pass 1: look for a constant (unique==1) field, prefer larger
            for size in (8, 4, 2, 1):
                if offset + size > max_len:
                    continue
                vals = self._extract_values(cluster, offset, size)
                if not vals:
                    continue
                unique = len(set(vals))
                if unique == 0:
                    continue
                if unique == 1:
                    best_size = size
                    best_type = "magic"
                    best_unique = 1
                    break

            # Pass 2: if smaller constant was float padding, check float
            if best_unique == 1 and best_size < 4 and offset + 4 <= max_len:
                # The 4-byte value at this offset might be a float whose lower bytes
                # happen to be zero (magic at 2B level). Check float first.
                if self._is_likely_float(cluster, offset):
                    best_size = 4
                    best_type = "float"
                    best_unique = len(set(self._extract_values(cluster, offset, 4)))
                else:
                    # Check if 4-byte is also constant (real zero padding)
                    vals_4 = self._extract_values(cluster, offset, 4)
                    if len(set(vals_4)) == 1:
                        best_size = 4
                        best_type = "magic"
                        best_unique = 1

            # Pass 3: if no constant field, check for float or pick largest varying
            if best_unique != 1:
                if offset + 4 <= max_len and self._is_likely_float(cluster, offset):
                    best_size = 4
                    best_type = "float"
                else:
                    for size in (8, 4, 2, 1):
                        if offset + size > max_len:
                            continue
                        vals = self._extract_values(cluster, offset, size)
                        if not vals:
                            continue
                        unique = len(set(vals))
                        if unique > 1:
                            best_size = size
                            best_type = f"uint{size * 8}"
                            break

            vals = self._extract_values(cluster, offset, best_size)
            unique = len(set(vals)) if vals else 0

            semantic_hint = ""
            if self.recovery and unique > 1:
                mobj = self.recovery.find_object(0)
                if mobj:
                    for alloc in mobj.allocations:
                        pass

            if offset == 0 and unique == 1:
                semantic_hint = "msg_type"
            elif offset == 0 and unique > 1:
                semantic_hint = "msg_type"

            fields.append(ProtoField(
                offset=offset,
                size=best_size,
                type_hint=best_type,
                semantic_hint=semantic_hint,
                unique_values=unique,
            ))
            offset += best_size

        return fields

    def recover_schema(self) -> ProtocolSchema:
        clusters = self._cluster_packets()
        schema = ProtocolSchema()

        if self._packets:
            port_counter: Counter[int] = Counter()
            for pkt in self._packets:
                port_counter[pkt.dst_port] += 1
                port_counter[pkt.src_port] += 1
            if port_counter:
                schema.server_port = port_counter.most_common(1)[0][0]

        for cluster in clusters:
            if not cluster:
                continue
            sample = cluster[0].payload
            type_id = int.from_bytes(sample[:4], 'little') if len(sample) >= 4 else 0
            fields = self._detect_fields(cluster)

            mt = MessageType(
                type_id=type_id,
                total_len=len(cluster[0].payload),
                count=len(cluster),
                fields=fields,
                sample_payload=sample[:64],
            )
            schema.messages.append(mt)

        return schema
