"""Semantic Analysis — pattern matching on the provenance graph."""

from uuid import UUID
from .graph import ProvenanceGraph, Node
from .objects import ObjectRecovery


class SemanticAnalyzer:
    def __init__(self, graph: ProvenanceGraph, recovery: ObjectRecovery):
        self.graph = graph
        self.recovery = recovery

    def analyze(self) -> dict:
        results = {
            "serialization_patterns": self._find_serialization_patterns(),
            "deserialization_patterns": self._find_deserialization_patterns(),
            "object_lifecycles": self._find_lifecycles(),
            "data_flows": self._find_data_flows(),
        }
        return results

    def _find_serialization_patterns(self):
        patterns = []
        for obj_node in self.graph.find_by_kind("memory_object"):
            if obj_node.props.get("is_ghost"):
                continue
            seen_edges: set[tuple[str, str, str]] = set()
            for s in self.graph.successors(obj_node.id):
                if s.kind == "copy":
                    for cs in self.graph.successors(s.id):
                        if cs.kind == "memory_object":
                            for ns in self.graph.successors(cs.id):
                                if ns.kind == "network_send":
                                    key = (obj_node.label, s.label, ns.label)
                                    if key not in seen_edges:
                                        seen_edges.add(key)
                                        patterns.append({
                                            "type": "serialization",
                                            "object": obj_node.label,
                                            "object_id": str(obj_node.id),
                                            "copy": s.label,
                                            "network": ns.label,
                                        })
                elif s.kind == "network_send":
                    key = (obj_node.label, "", s.label)
                    if key not in seen_edges:
                        seen_edges.add(key)
                        patterns.append({
                            "type": "serialization",
                            "object": obj_node.label,
                            "object_id": str(obj_node.id),
                            "copy": "",
                            "network": s.label,
                        })
        return patterns

    def _find_deserialization_patterns(self):
        patterns = []
        seen_edges: set[tuple[str, str]] = set()
        for net_node in self.graph.find_by_kind("network_recv"):
            for s in self.graph.successors(net_node.id):
                if s.kind == "memory_object" and not s.props.get("is_ghost"):
                    for cs in self.graph.successors(s.id):
                        if cs.kind == "copy":
                            key = (net_node.label, cs.label)
                            if key not in seen_edges:
                                seen_edges.add(key)
                                patterns.append({
                                    "type": "deserialization",
                                    "network": net_node.label,
                                    "object": s.label,
                                    "object_id": str(s.id),
                                    "copy": cs.label,
                                })
        return patterns

    def _find_lifecycles(self):
        cycles = []
        for obj_node in self.graph.find_by_kind("memory_object"):
            if obj_node.props.get("is_ghost"):
                continue
            addr = obj_node.props.get("addr", 0)
            obj = self.recovery.find_object(addr)
            if obj and obj.allocations:
                for alloc in obj.allocations:
                    if alloc.destroyed_ts:
                        lifetime_ns = alloc.destroyed_ts - alloc.created_ts
                        if lifetime_ns >= 1_000_000:
                            lifetime_str = f"{lifetime_ns/1_000_000:.1f}ms"
                        elif lifetime_ns >= 1_000:
                            lifetime_str = f"{lifetime_ns/1_000:.0f}µs"
                        else:
                            lifetime_str = f"{lifetime_ns}ns"
                        cycles.append({
                            "type": "lifecycle",
                            "object": obj_node.label,
                            "object_id": str(obj_node.id),
                            "addr": obj.addr,
                            "size": obj.size,
                            "created_ts": alloc.created_ts,
                            "destroyed_ts": alloc.destroyed_ts,
                            "lifetime_ns": lifetime_ns,
                            "lifetime_str": lifetime_str,
                            "copies_in": len(obj.copies_in),
                            "copies_out": len(obj.copies_out),
                            "net_sends": len(obj.network_sends),
                            "net_recvs": len(obj.network_recvs),
                        })
        return cycles

    def _find_data_flows(self):
        flows = []
        seen: set[str] = set()
        for obj_node in self.graph.find_by_kind("memory_object"):
            if obj_node.props.get("is_ghost"):
                continue
            paths = self.graph.paths_from(obj_node.id, max_depth=5)
            for path in paths:
                if len(path) >= 2:
                    flow_desc = " → ".join(
                        f"{n.kind}({n.label})" for n in path
                    )
                    if flow_desc not in seen:
                        seen.add(flow_desc)
                        flows.append({
                            "start": str(path[0].id),
                            "end": str(path[-1].id),
                            "path": flow_desc,
                        })
        return flows

    def summary(self) -> str:
        results = self.analyze()
        lines = ["=== Semantic Analysis ==="]
        sp = results["serialization_patterns"]
        dp = results["deserialization_patterns"]
        lc = results["object_lifecycles"]
        df = results["data_flows"]

        lines.append(f"Serialization patterns: {len(sp)}")
        for p in sp[:5]:
            parts = [p['object']]
            if p['copy']:
                parts.append(p['copy'])
            parts.append(p['network'])
            lines.append(f"  {' → '.join(parts)}")

        lines.append(f"Deserialization patterns: {len(dp)}")
        for p in dp[:5]:
            parts = [p['network'], p['copy']]
            lines.append(f"  {' → '.join(parts)}")

        lines.append(f"Object lifecycles: {len(lc)}")
        for c in lc[:5]:
            lines.append(
                f"  {c['object']} size={c['size']} "
                f"lifetime={c['lifetime_str']} "
                f"(copies_in={c['copies_in']}, net_sends={c['net_sends']})"
            )

        lines.append(f"Data flows: {len(df)}")
        for f in df[:5]:
            lines.append(f"  {f['path']}")

        if len(sp) > 5 or len(dp) > 5 or len(lc) > 5 or len(df) > 5:
            lines.append("  ... (truncated)")

        return "\n".join(lines)
