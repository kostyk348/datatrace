"""Size Pattern Recognition — statistical inference from object metadata."""

from collections import Counter, defaultdict
from .objects import ObjectRecovery, MemoryObject


# Common struct sizes in game engines
COMMON_SIZES = {
    4:  "int32 / float",
    8:  "vec2 / int64 / ptr",
    12: "vec3",
    16: "vec4 / quat / mat2x2 / ColorRGBA",
    20: "Transform (pos3 + quat)",
    24: "mat3x3",
    32: "mat4x4 / AABB",
    36: "Transform (3x vec3 + padding)",
    52: "Entity (typical game object)",
    64: "Entity / Packet header",
    68: "PlayerState",
    72: "PlayerState / Weapon",
    76: "RigidBody",
    80: "Vehicle / Character",
    128: "Inventory / Mesh header",
    256: "Snapshot / Frame buffer",
    512: "Network packet",
    1024: "Texture header / Sound clip header",
    4096: "Memory pool / Page / Entity array",
}


# Thresholds for pattern classification
FRAME_INTERVAL_US = 16_000  # 16ms (60fps)
FRAME_INTERVAL_JITTER = 0.2  # 20% jitter allowed
PACKET_LIFETIME_MS = 10
ENTITY_MIN_LIFETIME_MS = 100


class SizePatternRecognizer:
    """Statistical pattern recognition on MemoryObjects."""

    def __init__(self, recovery: ObjectRecovery):
        self.recovery = recovery

    def analyze(self) -> dict:
        results = {
            "type_hints": self._infer_types(),
            "frame_buffers": self._find_frame_buffers(),
            "packets": self._find_packets(),
            "entities": self._find_entities(),
            "periodic": self._find_periodic(),
        }
        return results

    def _allocs_by_size(self) -> dict[int, list]:
        by_size: dict[int, list] = defaultdict(list)
        for obj in self.recovery.objects:
            if obj.allocations:
                key = (obj.size // 4) * 4  # round to 4
                by_size[key].append(obj)
        return dict(by_size)

    def _allocs_by_addr(self, addr: int):
        """Find all allocations at the same address (for reuse detection)."""
        results = []
        for obj in self.recovery.objects:
            if obj.addr == addr:
                results.append(obj)
        return results

    def _infer_types(self) -> dict[str, str]:
        hints: dict[str, str] = {}
        for obj in self.recovery.objects:
            if obj.is_ghost:
                continue
            # Exact struct size match
            if obj.size in COMMON_SIZES:
                hints[str(obj.uuid)] = COMMON_SIZES[obj.size]
            # Multiple allocations same address + same size + short-lived = temp buffer
            elif len(obj.allocations) > 5 and all(
                a.destroyed_ts and (a.destroyed_ts - a.created_ts) < 1_000_000
                for a in obj.allocations if a.destroyed_ts
            ):
                hints[str(obj.uuid)] = "temp_buffer"
        return hints

    def _find_frame_buffers(self) -> list[dict]:
        """Objects reallocated at regular ~16ms intervals."""
        frames = []
        # Group allocations at same address
        addr_allocs: dict[int, list[MemoryObject]] = defaultdict(list)
        for obj in self.recovery.objects:
            if obj.allocations:
                addr_allocs[obj.addr].append(obj)

        for addr, objs in addr_allocs.items():
            alive = [o for o in objs if not o.is_ghost]
            # Collect all creation timestamps
            timestamps = []
            for o in alive:
                for a in o.allocations:
                    timestamps.append(a.created_ts)
            timestamps.sort()

            if len(timestamps) < 3:
                continue

            # Check intervals
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)]
            if not intervals:
                continue

            mean_interval = sum(intervals) / len(intervals)
            # Check if intervals are consistent (low variance)
            if mean_interval > 0:
                variance = sum((i - mean_interval) ** 2 for i in intervals) / len(intervals)
                cv = (variance ** 0.5) / mean_interval  # coefficient of variation

                if cv < FRAME_INTERVAL_JITTER:
                    fps = round(1_000_000_000 / mean_interval)
                    objs_at_addr = [o for o in alive if o.addr == addr]
                    if objs_at_addr:
                        frames.append({
                            "addr": addr,
                            "size": objs_at_addr[0].size,
                            "mean_interval_ns": int(mean_interval),
                            "fps": fps,
                            "allocs": len(objs_at_addr),
                            "cv": round(cv, 3),
                        })
        return frames

    def _find_packets(self) -> list[dict]:
        """Objects that live <10ms and are sent via sendto."""
        packets = []
        for obj in self.recovery.objects:
            if obj.is_ghost:
                continue
            if not obj.network_sends:
                continue
            # Check lifetime from allocations
            for alloc in obj.allocations:
                if alloc.destroyed_ts:
                    lifetime_ms = (alloc.destroyed_ts - alloc.created_ts) / 1_000_000
                    if lifetime_ms < PACKET_LIFETIME_MS:
                        packets.append({
                            "addr": obj.addr,
                            "size": obj.size,
                            "lifetime_ms": round(lifetime_ms, 1),
                            "net_sends": len(obj.network_sends),
                        })
        return packets

    def _find_entities(self) -> list[dict]:
        """Long-lived objects with many copies (likely game entities)."""
        entities = []
        for obj in self.recovery.objects:
            if obj.is_ghost:
                continue
            if not obj.allocations:
                continue
            max_lifetime = 0
            for alloc in obj.allocations:
                if alloc.destroyed_ts:
                    ms = (alloc.destroyed_ts - alloc.created_ts) / 1_000_000
                    if ms > max_lifetime:
                        max_lifetime = ms
            if max_lifetime > ENTITY_MIN_LIFETIME_MS and obj.copies_out > 0:
                entities.append({
                    "addr": obj.addr,
                    "size": obj.size,
                    "lifetime_ms": round(max_lifetime, 1),
                    "copies_out": len(obj.copies_out),
                    "copies_in": len(obj.copies_in),
                })
        return entities

    def _find_periodic(self) -> list[dict]:
        """Detect periodic reallocation patterns for any timing."""
        periodic = []
        # Group all allocs by addr
        addr_ts: dict[int, list[int]] = defaultdict(list)
        for obj in self.recovery.objects:
            if obj.allocations:
                for a in obj.allocations:
                    addr_ts[obj.addr].append(a.created_ts)

        for addr, timestamps in addr_ts.items():
            if len(timestamps) < 5:
                continue
            timestamps.sort()
            gaps = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)]
            if not gaps:
                continue
            mean_gap = sum(gaps) / len(gaps)
            if mean_gap > 0:
                variance = sum((g - mean_gap) ** 2 for g in gaps) / len(gaps)
                cv = (variance ** 0.5) / mean_gap
                if cv < FRAME_INTERVAL_JITTER * 2:
                    hz = round(1_000_000_000 / mean_gap) if mean_gap > 0 else 0
                    periodic.append({
                        "addr": addr,
                        "count": len(timestamps),
                        "mean_interval_ms": round(mean_gap / 1_000_000, 1),
                        "approx_hz": hz,
                        "cv": round(cv, 3),
                    })
        return periodic

    def summary(self) -> str:
        results = self.analyze()
        lines = ["=== Size Pattern Recognition ==="]

        hints = results["type_hints"]
        if hints:
            lines.append(f"Type hints: {len(hints)} objects")
            for uid, hint in list(hints.items())[:10]:
                lines.append(f"  {uid[:8]}... → {hint}")

        fb = results["frame_buffers"]
        lines.append(f"Frame buffers: {len(fb)}")
        for f in fb[:5]:
            lines.append(f"  addr={f['addr']:#x} size={f['size']} "
                         f"interval={f['mean_interval_ns']/1e6:.1f}ms "
                         f"({f['fps']}fps)")

        pkts = results["packets"]
        lines.append(f"Packets: {len(pkts)}")
        for p in pkts[:5]:
            lines.append(f"  addr={p['addr']:#x} size={p['size']} "
                         f"lifetime={p['lifetime_ms']}ms")

        ents = results["entities"]
        lines.append(f"Entities: {len(ents)}")
        for e in ents[:5]:
            lines.append(f"  addr={e['addr']:#x} size={e['size']} "
                         f"lifetime={e['lifetime_ms']}ms copies={e['copies_out']}")

        periodic = results["periodic"]
        lines.append(f"Periodic allocs: {len(periodic)}")
        for p in periodic[:5]:
            lines.append(f"  addr={p['addr']:#x} count={p['count']} "
                         f"interval={p['mean_interval_ms']}ms ({p['approx_hz']}Hz)")

        return "\n".join(lines)
