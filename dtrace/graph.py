"""Provenance Graph Engine — DAG of objects, transforms, and I/O."""

from uuid import UUID, uuid4
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from .objects import MemoryObject, CopyEvent, NetworkEvent

if TYPE_CHECKING:
    from .objects import ObjectRecovery


@dataclass(slots=True)
class Node:
    id: UUID
    kind: str
    label: str
    props: dict[str, Any] = field(default_factory=dict)
    source: str | None = None
    created_ts: int = 0


@dataclass(slots=True)
class Edge:
    id: UUID
    source_id: UUID
    target_id: UUID
    kind: str
    props: dict[str, Any] = field(default_factory=dict)
    timestamp: int = 0


class ProvenanceGraph:
    def __init__(self, recovery: "ObjectRecovery | None" = None):
        self.nodes: dict[UUID, Node] = {}
        self.edges: dict[UUID, Edge] = {}
        self._adj: dict[UUID, list[Edge]] = {}
        self._radj: dict[UUID, list[Edge]] = {}
        self._global_ts: int = 0

        self._copy_nodes: dict[UUID, UUID] = {}
        self._net_nodes: dict[UUID, UUID] = {}
        self._obj_nodes: dict[int, UUID] = {}
        self._recovery = recovery

    def _ts(self, ts: int) -> int:
        if ts > self._global_ts:
            self._global_ts = ts
        return ts or self._global_ts

    def add_node(self, kind: str, label: str, props: dict | None = None,
                 source: str | None = None, ts: int = 0) -> Node:
        node = Node(id=uuid4(), kind=kind, label=label,
                    props=props or {}, source=source, created_ts=self._ts(ts))
        self.nodes[node.id] = node
        self._adj[node.id] = []
        self._radj[node.id] = []
        return node

    def add_edge(self, src: UUID, dst: UUID, kind: str,
                 props: dict | None = None, ts: int = 0) -> Edge:
        edge = Edge(id=uuid4(), source_id=src, target_id=dst, kind=kind,
                    props=props or {}, timestamp=self._ts(ts))
        self.edges[edge.id] = edge
        self._adj[src].append(edge)
        self._radj[dst].append(edge)
        return edge

    def successors(self, node_id: UUID) -> list[Node]:
        result: list[Node] = []
        for e in self._adj.get(node_id, []):
            if e.target_id in self.nodes:
                result.append(self.nodes[e.target_id])
        return result

    def predecessors(self, node_id: UUID) -> list[Node]:
        result: list[Node] = []
        for e in self._radj.get(node_id, []):
            if e.source_id in self.nodes:
                result.append(self.nodes[e.source_id])
        return result

    def paths_from(self, node_id: UUID, max_depth: int = 10) -> list[list[Node]]:
        paths: list[list[Node]] = []
        visited: set[UUID] = set()
        def dfs(cur: UUID, path: list[Node]):
            if len(path) > max_depth:
                return
            visited.add(cur)
            succs = self.successors(cur)
            if not succs:
                paths.append(list(path))
            for s in succs:
                if s.id not in visited:
                    path.append(s); dfs(s.id, path); path.pop()
            visited.discard(cur)
        if node_id in self.nodes:
            dfs(node_id, [self.nodes[node_id]])
        return paths

    def paths_to(self, node_id: UUID, max_depth: int = 10) -> list[list[Node]]:
        paths: list[list[Node]] = []
        visited: set[UUID] = set()
        def dfs(cur: UUID, path: list[Node]):
            if len(path) > max_depth:
                return
            visited.add(cur)
            preds = self.predecessors(cur)
            if not preds:
                paths.append(list(reversed(path)))
            for p in preds:
                if p.id not in visited:
                    path.append(p); dfs(p.id, path); path.pop()
            visited.discard(cur)
        if node_id in self.nodes:
            dfs(node_id, [self.nodes[node_id]])
        return paths

    def find_by_label(self, sub: str) -> list[Node]:
        return [n for n in self.nodes.values() if sub.lower() in n.label.lower()]

    def find_by_kind(self, kind: str) -> list[Node]:
        return [n for n in self.nodes.values() if n.kind == kind]

    def _addr_to_node(self, addr: int, obj: MemoryObject | None = None) -> UUID | None:
        """Return node UUID for address. Uses recovery + cache. Returns None if no match."""
        if addr in self._obj_nodes:
            return self._obj_nodes[addr]
        if self._recovery:
            recovered = self._recovery.find_object(addr)
            if recovered:
                return self._ensure_obj_node(recovered)
        return None

    def _ensure_obj_node(self, obj: MemoryObject) -> UUID:
        if obj.addr in self._obj_nodes:
            return self._obj_nodes[obj.addr]
        label = obj.label if obj.label != "unknown" else f"obj_{obj.addr:#x}"
        node = self.add_node(
            kind="memory_object",
            label=label,
            props={"addr": obj.addr, "size": obj.size, "pid": obj.pid,
                   "alive": obj.is_alive, "type_hint": obj.type_hint,
                   "is_ghost": obj.is_ghost},
            ts=obj.created_ts,
        )
        self._obj_nodes[obj.addr] = node.id
        return node.id

    def ingest_object(self, obj: MemoryObject):
        obj_nid = self._ensure_obj_node(obj)

        for copy in obj.copies_in:
            if copy.uuid in self._copy_nodes:
                cnid = self._copy_nodes[copy.uuid]
                if obj_nid not in [e.target_id for e in self._radj[cnid]]:
                    self.add_edge(cnid, obj_nid, "creates", ts=copy.ts)
                continue

            copy_node = self.add_node(
                kind="copy",
                label=f"memcpy({copy.dst_addr:#x},{copy.src_addr:#x},{copy.size})",
                props={"dst": copy.dst_addr, "src": copy.src_addr, "size": copy.size},
                ts=copy.ts,
            )
            self._copy_nodes[copy.uuid] = copy_node.id

            src_nid = self._addr_to_node(copy.src_addr)
            if src_nid:
                self.add_edge(src_nid, copy_node.id, "copies_from", ts=copy.ts)
            self.add_edge(copy_node.id, obj_nid, "creates", ts=copy.ts)

        for copy in obj.copies_out:
            if copy.uuid in self._copy_nodes:
                cnid = self._copy_nodes[copy.uuid]
                if obj_nid not in [e.source_id for e in self._adj[cnid]]:
                    self.add_edge(obj_nid, cnid, "copies_from", ts=copy.ts)
                continue

            copy_node = self.add_node(
                kind="copy",
                label=f"memcpy({copy.dst_addr:#x},{copy.src_addr:#x},{copy.size})",
                props={"dst": copy.dst_addr, "src": copy.src_addr, "size": copy.size},
                ts=copy.ts,
            )
            self._copy_nodes[copy.uuid] = copy_node.id
            self.add_edge(obj_nid, copy_node.id, "copies_from", ts=copy.ts)

            dst_nid = self._addr_to_node(copy.dst_addr)
            if dst_nid:
                self.add_edge(copy_node.id, dst_nid, "creates", ts=copy.ts)

        for net in obj.network_sends:
            if net.uuid not in self._net_nodes:
                net_n = self.add_node(
                    kind="network_send",
                    label=f"sendto(fd={net.fd},size={net.size})",
                    props={"fd": net.fd, "size": net.size, "buf": net.buf_addr},
                    ts=net.ts,
                )
                self._net_nodes[net.uuid] = net_n.id
            self.add_edge(obj_nid, self._net_nodes[net.uuid], "sends", ts=net.ts)

        for net in obj.network_recvs:
            if net.uuid not in self._net_nodes:
                net_n = self.add_node(
                    kind="network_recv",
                    label=f"recvfrom(fd={net.fd},size={net.size})",
                    props={"fd": net.fd, "size": net.size, "buf": net.buf_addr},
                    ts=net.ts,
                )
                self._net_nodes[net.uuid] = net_n.id
            self.add_edge(self._net_nodes[net.uuid], obj_nid, "receives", ts=net.ts)

    def summary(self) -> str:
        lines = [f"Provenance Graph: {len(self.nodes)} nodes, {len(self.edges)} edges"]
        kinds: dict[str, int] = {}
        for n in self.nodes.values():
            kinds[n.kind] = kinds.get(n.kind, 0) + 1
        for k, c in sorted(kinds.items()):
            lines.append(f"  {k}: {c}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "nodes": [
                {"id": str(n.id), "kind": n.kind, "label": n.label,
                 "props": n.props, "created_ts": n.created_ts}
                for n in self.nodes.values()
            ],
            "edges": [
                {"id": str(e.id), "source": str(e.source_id),
                 "target": str(e.target_id), "kind": e.kind,
                 "props": e.props, "timestamp": e.timestamp}
                for e in self.edges.values()
            ],
        }
