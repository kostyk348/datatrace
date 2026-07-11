"""Hierarchical Object Model — from flat memory objects to structured entities.

Layers:
  MemoryObject  →  raw allocation (current objects.py)
         ↓
  Record        →  typed fields within a buffer (field inference)
         ↓
  Entity        →  persistent object with identity, lifecycle
         ↓
  System        →  processing unit (reads/writes entities, discovered from patterns)

Usage:
    builder = HierarchyBuilder(recovery, graph)
    builder.build()
    print(builder.summary())
"""

from uuid import UUID, uuid4
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any
from .objects import ObjectRecovery, MemoryObject, CopyEvent, NetworkEvent
from .graph import ProvenanceGraph, Node


# ─── Field Inference ───

@dataclass
class InferredField:
    offset: int
    size: int
    type_hint: str = "bytes"
    semantic_hint: str = ""
    constant_value: int | None = None
    unique_values: int = 0
    sample_bytes: bytes = b""

    def __str__(self) -> str:
        return (f"  [{self.offset:+3d}] {self.type_hint:<8} "
                f"{self.semantic_hint:<16} "
                f"const={self.constant_value}")


# ─── Record Layer ───

@dataclass
class Record:
    """A structured buffer with inferred field layout."""
    uuid: UUID
    size: int
    fields: list[InferredField] = field(default_factory=list)
    memory_objects: list[MemoryObject] = field(default_factory=list)
    sample_payload: bytes = b""
    source: str = "inferred"  # "inferred", "schema", "manual"

    def summary(self) -> str:
        lines = [
            f"Record(size={self.size}, fields={len(self.fields)}) "
            f"source={self.source}"
        ]
        for f in self.fields:
            lines.append(str(f))
        return "\n".join(lines)


# ─── Entity Layer ───

@dataclass
class EntityLifecycle:
    created_ts: int = 0
    destroyed_ts: int | None = None
    num_updates: int = 0
    num_network_events: int = 0
    num_copies: int = 0


@dataclass
class Entity:
    """A persistent object with identity, composed of records.

    An entity is discovered by:
    - Consistent allocation size across many instances
    - Repeated serialization/deserialization pattern
    - Network send/receive with tracking ID
    """
    uuid: UUID
    record_type: Record
    label: str = "unknown"
    entity_id: int | None = None
    instances: list[MemoryObject] = field(default_factory=list)
    lifecycle: EntityLifecycle = field(default_factory=EntityLifecycle)
    relationships: dict[str, list[UUID]] = field(default_factory=dict)

    def summary(self) -> str:
        return (f"Entity(id={self.entity_id}, label={self.label}, "
                f"record={self.record_type.size}B, "
                f"instances={len(self.instances)}, "
                f"updates={self.lifecycle.num_updates})")


# ─── System Layer ───

@dataclass
class SystemIO:
    entity_id: int
    read_count: int = 0
    write_count: int = 0
    last_ts: int = 0


@dataclass
class System:
    """A processing unit that reads/writes entities.

    Discovered from patterns:
    - Serialize: entity → copy → network_send  (output system)
    - Deserialize: network_recv → copy → entity (input system)
    - Transform: entity → copy → entity        (processing system)
    """
    uuid: UUID
    name: str
    kind: str  # "serializer", "deserializer", "processor", "unknown"
    inputs: list[SystemIO] = field(default_factory=list)
    outputs: list[SystemIO] = field(default_factory=list)
    entities: list[UUID] = field(default_factory=list)

    def summary(self) -> str:
        return (f"System(name={self.name}, kind={self.kind}, "
                f"entities={len(self.entities)}, "
                f"inputs={len(self.inputs)}, outputs={len(self.outputs)})")


# ─── Hierarchical Model ───

@dataclass
class HierarchicalModel:
    records: dict[UUID, Record] = field(default_factory=dict)
    entities: dict[UUID, Entity] = field(default_factory=dict)
    systems: dict[UUID, System] = field(default_factory=dict)
    record_by_size: dict[int, Record] = field(default_factory=dict)

    def summary(self) -> str:
        lines = [
            "=== Hierarchical Object Model ===",
            f"Records: {len(self.records)}",
            f"Entities: {len(self.entities)}",
            f"Systems: {len(self.systems)}",
            "",
        ]
        if self.records:
            lines.append("Records by size:")
            for size in sorted(self.record_by_size):
                rec = self.record_by_size[size]
                ns = sum(
                    1 for e in self.entities.values()
                    if e.record_type.uuid == rec.uuid
                )
                lines.append(
                    f"  [{size}B] {len(rec.fields)} fields, "
                    f"{ns} entities, source={rec.source}"
                )
            lines.append("")
        if self.entities:
            lines.append("Entities:")
            for e in sorted(self.entities.values(),
                            key=lambda x: x.lifecycle.num_updates,
                            reverse=True)[:20]:
                lines.append(f"  {e.summary()}")
            lines.append("")
        if self.systems:
            lines.append("Systems:")
            for s in sorted(self.systems.values(),
                            key=lambda x: len(x.entities),
                            reverse=True):
                lines.append(f"  {s.summary()}")
        return "\n".join(lines)


# ─── Hierarchy Builder ───

class HierarchyBuilder:
    """Builds HierarchicalModel from ObjectRecovery + ProvenanceGraph."""

    def __init__(self, recovery: ObjectRecovery, graph: ProvenanceGraph):
        self.recovery = recovery
        self.graph = graph
        self.model = HierarchicalModel()
        self._size_samples: dict[int, list[MemoryObject]] = defaultdict(list)
        self._entity_id_candidates: dict[int, list[MemoryObject]] = defaultdict(list)

    def build(self) -> HierarchicalModel:
        self._collect_size_samples()
        self._infer_records()
        self._discover_entities()
        self._discover_systems()
        self._tag_graph()
        return self.model

    def _collect_size_samples(self):
        """Group memory objects by allocation size."""
        for obj in self.recovery.objects:
            if obj.is_ghost:
                continue
            if obj.size > 0 and obj.size < 1024 * 1024:
                self._size_samples[obj.size].append(obj)

    def _infer_fields(self, objects: list[MemoryObject]) -> list[InferredField]:
        """Infer field layout from network sends of same-sized objects."""
        samples: list[bytes] = []
        for obj in objects:
            for s in obj.samples:
                if len(s) >= 4:
                    samples.append(s)

        if len(samples) < 2:
            return []

        max_len = max(len(s) for s in samples)
        fields: list[InferredField] = []
        offset = 0

        while offset + 1 < max_len:
            # Try larger sizes first
            best_size = 1
            best_type = "uint8"
            best_unique = 0
            best_constant = None

            for size in (8, 4, 2, 1):
                if offset + size > max_len:
                    continue
                vals = []
                for s in samples:
                    if offset + size <= len(s):
                        val = int.from_bytes(s[offset:offset + size], 'little')
                        vals.append(val)
                if not vals:
                    continue
                unique = len(set(vals))
                if unique == 1:
                    best_size = size
                    best_type = "magic"
                    best_unique = 1
                    best_constant = vals[0]
                    break
                if unique > best_unique:
                    best_size = size
                    best_unique = unique
                    best_type = f"uint{size * 8}"
                    best_constant = None

            # Check if it could be a float
            if best_unique > 1 and best_size == 4 and offset + 4 <= max_len:
                float_count = 0
                for s in samples[:10]:
                    if offset + 4 <= len(s):
                        import struct
                        try:
                            v = struct.unpack_from("<f", s, offset)[0]
                            if 0.001 < abs(v) < 10000000:
                                float_count += 1
                        except struct.error:
                            pass
                if float_count >= 5:
                    best_type = "float"

            vals = []
            for s in samples:
                if offset + best_size <= len(s):
                    vals.append(int.from_bytes(s[offset:offset + best_size], 'little'))

            semantic = ""
            if offset == 0 and best_unique == 1:
                semantic = "msg_type"

            fields.append(InferredField(
                offset=offset,
                size=best_size,
                type_hint=best_type,
                semantic_hint=semantic,
                constant_value=best_constant,
                unique_values=best_unique,
                sample_bytes=samples[0][offset:offset + best_size] if samples else b"",
            ))
            offset += best_size

        return fields

    def _infer_records(self):
        """Create Records from allocation size clusters with field inference."""
        for size, objects in self._size_samples.items():
            # For pcap-derived objects, even 1 is enough if samples exist
            has_samples = any(obj.samples for obj in objects)
            if len(objects) < 2 and not has_samples:
                continue
            if len(objects) < 1:
                continue

            # Get network send samples for field inference
            net_samples = [obj for obj in objects if obj.network_sends or obj.network_recvs]
            copy_objects = [obj for obj in objects if obj.copies_out]

            fields: list[InferredField] = []
            source = "inferred"

            if net_samples and len(net_samples) >= 2:
                fields = self._infer_fields(net_samples)
                # Determine direction from net_samples
                has_sends = any(obj.network_sends for obj in net_samples)
                has_recvs = any(obj.network_recvs for obj in net_samples)
                if has_sends and not has_recvs:
                    source = "network_send"
                elif has_recvs and not has_sends:
                    source = "network_recv"
                else:
                    source = "network_sample"
            elif len(copy_objects) >= 2:
                fields = self._infer_fields(objects)
                source = "copy_pattern"
            elif any(obj.samples for obj in objects):
                # Use raw samples (e.g. pcap payloads) directly
                sampled_objs = [obj for obj in objects if obj.samples]
                if len(sampled_objs) >= 1:
                    fields = self._infer_fields(sampled_objs)
                    source = "pcap_sample"

            # Get a representative sample payload
            sample = b""
            for obj in objects:
                if obj.samples:
                    sample = obj.samples[0]
                    break

            record = Record(
                uuid=uuid4(),
                size=size,
                fields=fields,
                memory_objects=objects[:10],
                sample_payload=sample,
                source=source,
            )
            self.model.records[record.uuid] = record
            self.model.record_by_size[size] = record

    def _discover_entities(self):
        """Discover entities from records.

        An entity = record type + instances that share an identity
        (tracked via consistent first-field value = entity_id).
        """
        for size, record in self.model.record_by_size.items():
            objects = self._size_samples.get(size, [])

            # Try to cluster by entity_id (first 4 bytes of samples)
            id_clusters: dict[int, list[MemoryObject]] = defaultdict(list)
            for obj in objects:
                for s in obj.samples:
                    if len(s) >= 8:
                        # Try offset 0 as entity_id (msg_type is constant)
                        # Try offset 4 as entity_id (first varying field)
                        candidate_id = int.from_bytes(s[4:8], 'little')
                        id_clusters[candidate_id].append(obj)
                        break
                if not obj.samples and obj.network_sends:
                    # No samples, use address as identity marker
                    pass

            # Each cluster is a separate entity instance
            for entity_id, instances in id_clusters.items():
                if len(instances) < 1:
                    continue

                lc = EntityLifecycle()
                lc.num_updates = len(instances)
                for inst in instances:
                    lc.num_copies += len(inst.copies_out) + len(inst.copies_in)
                    lc.num_network_events += (
                        len(inst.network_sends) + len(inst.network_recvs)
                    )
                    if inst.created_ts:
                        if lc.created_ts == 0 or inst.created_ts < lc.created_ts:
                            lc.created_ts = inst.created_ts
                    if inst.destroyed_ts:
                        if (lc.destroyed_ts is None
                                or inst.destroyed_ts > lc.destroyed_ts):
                            lc.destroyed_ts = inst.destroyed_ts

                entity = Entity(
                    uuid=uuid4(),
                    record_type=record,
                    label=f"Entity_{entity_id}",
                    entity_id=entity_id,
                    instances=instances,
                    lifecycle=lc,
                )
                self.model.entities[entity.uuid] = entity

            # If no entity_id clustering, create one entity per record type
            if not id_clusters and objects:
                lc = EntityLifecycle()
                lc.num_updates = len(objects)
                entity = Entity(
                    uuid=uuid4(),
                    record_type=record,
                    label=f"Record_{size}B",
                    entity_id=None,
                    instances=objects,
                    lifecycle=lc,
                )
                self.model.entities[entity.uuid] = entity

    def _discover_systems(self):
        """Discover processing systems from entity + copy + network patterns.

        Systems are groups of operations on the same entity type:
        - Serializer: entity → copy → network_send
        - Deserializer: network_recv → copy → entity
        - Processor: entity → copy → entity (transform)
        """
        if not self.model.entities:
            return

        # Track entity relationships through copy/net events
        serializer_io: list[SystemIO] = []
        deserializer_io: list[SystemIO] = []

        for entity in self.model.entities.values():
            total_sends = sum(
                len(inst.network_sends) for inst in entity.instances
            )
            total_recvs = sum(
                len(inst.network_recvs) for inst in entity.instances
            )
            total_copies = sum(
                len(inst.copies_out) for inst in entity.instances
            )

            eid = entity.entity_id or 0
            if total_sends > 0:
                serializer_io.append(SystemIO(
                    entity_id=eid,
                    write_count=total_sends,
                ))
            if total_recvs > 0:
                deserializer_io.append(SystemIO(
                    entity_id=eid,
                    read_count=total_recvs,
                ))

        if serializer_io:
            sys = System(
                uuid=uuid4(),
                name="NetworkSerializer",
                kind="serializer",
                outputs=serializer_io,
                entities=[e.uuid for e in self.model.entities.values()],
            )
            self.model.systems[sys.uuid] = sys

        if deserializer_io:
            sys = System(
                uuid=uuid4(),
                name="NetworkDeserializer",
                kind="deserializer",
                inputs=deserializer_io,
                entities=[e.uuid for e in self.model.entities.values()],
            )
            self.model.systems[sys.uuid] = sys

        # Discover processor systems: entity pairs linked by copies
        copy_pairs: Counter[tuple[str, str]] = Counter()
        for entity in self.model.entities.values():
            for inst in entity.instances:
                for copy in inst.copies_out:
                    dst_obj = self.recovery.find_object(copy.dst_addr)
                    if dst_obj:
                        for other in self.model.entities.values():
                            if other.entity_id != entity.entity_id:
                                if dst_obj in other.instances:
                                    copy_pairs[(entity.label, other.label)] += 1

        for (src, dst), count in copy_pairs.most_common(3):
            sys = System(
                uuid=uuid4(),
                name=f"{src}→{dst}",
                kind="processor",
                inputs=[SystemIO(entity_id=0, read_count=count)],
                outputs=[SystemIO(entity_id=0, write_count=count)],
            )
            self.model.systems[sys.uuid] = sys

    def _tag_graph(self):
        """Tag provenance graph nodes with hierarchy metadata."""
        for entity in self.model.entities.values():
            # Add hierarchy tag to existing graph nodes
            for inst in entity.instances:
                for node in self.graph.nodes.values():
                    addr = node.props.get("addr")
                    if addr is not None:
                        for mobj in entity.instances:
                            if mobj.addr == addr:
                                node.props["hierarchy:entity_id"] = (
                                    entity.entity_id
                                )
                                node.props["hierarchy:entity_label"] = (
                                    entity.label
                                )
                                node.props["hierarchy:record_size"] = (
                                    entity.record_type.size
                                )
