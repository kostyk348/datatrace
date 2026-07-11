#!/usr/bin/env python3
"""Test the full DataTrace pipeline with mock events."""
import sys
sys.path.insert(0, "/home/lain/datatrace")

from dtrace.events import RawEvent, EventType
from dtrace.objects import ObjectRecovery
from dtrace.graph import ProvenanceGraph
from dtrace.analysis import SemanticAnalyzer


def make_ev(ts: int, type: int, addr: int = 0, addr2: int = 0,
            size: int = 0, pid: int = 100, tid: int = 200) -> RawEvent:
    return RawEvent(ts=ts, pid=pid, tid=tid, type=type,
                    addr=addr, addr2=addr2, size=size)


def test_pipeline():
    recovery = ObjectRecovery()

    # Simulate a game server session:
    # 1. malloc(4096) for entity array
    ev1 = make_ev(1000, EventType.MALLOC, size=4096)
    ev1_ret = make_ev(1005, EventType.MALLOC | 0x1000, addr=0x7f00000100)
    recovery.feed(ev1)
    recovery.feed(ev1_ret)

    # 2. calloc(1, 64) for Player entity
    ev2 = make_ev(1100, EventType.CALLOC, addr=1, addr2=64)
    ev2_ret = make_ev(1105, EventType.CALLOC | 0x1000, addr=0x7f00000200)
    recovery.feed(ev2)
    recovery.feed(ev2_ret)

    # 3. calloc(1, 64) for Enemy entity
    ev3 = make_ev(1200, EventType.CALLOC, addr=1, addr2=64)
    ev3_ret = make_ev(1205, EventType.CALLOC | 0x1000, addr=0x7f00000300)
    recovery.feed(ev3)
    recovery.feed(ev3_ret)

    # 4. memcpy to serialize world state
    ev4 = make_ev(2000, EventType.MEMCPY, addr=0x7f00000400, addr2=0x7f00000100, size=256)
    recovery.feed(ev4)

    # 5. memcpy from entity to packet
    ev5 = make_ev(2100, EventType.MEMCPY, addr=0x7f00000500, addr2=0x7f00000200, size=64)
    recovery.feed(ev5)

    # 6. sendto
    ev6 = make_ev(3000, EventType.SENDTO, addr=3, addr2=0x7f00000500, size=512)
    recovery.feed(ev6)

    # 7. recvfrom
    ev7 = make_ev(3100, EventType.RECVFROM, addr=3, addr2=0x7f00000600, size=512)
    recovery.feed(ev7)

    # 8. memcpy from receive buffer
    ev8 = make_ev(3200, EventType.MEMCPY, addr=0x7f00000200, addr2=0x7f00000600, size=64)
    recovery.feed(ev8)

    # 9. free entities
    ev9 = make_ev(5000, EventType.FREE, addr=0x7f00000200)
    ev10 = make_ev(5010, EventType.FREE, addr=0x7f00000300)
    ev11 = make_ev(5020, EventType.FREE, addr=0x7f00000100)
    recovery.feed(ev9)
    recovery.feed(ev10)
    recovery.feed(ev11)

    print(recovery.summary())
    print()

    # Build graph
    graph = ProvenanceGraph()
    for obj in recovery.objects:
        graph.ingest_object(obj)
    print(graph.summary())
    print()

    # Analyze
    analyzer = SemanticAnalyzer(graph, recovery)
    print(analyzer.summary())

    # Final state
    print("\n=== FINAL ===")
    print(f"Objects: {len(recovery.objects)}")
    print(f"Graph nodes: {len(graph.nodes)}, edges: {len(graph.edges)}")

    # Verify
    assert len(recovery.objects) >= 3, f"Expected >=3 objects, got {len(recovery.objects)}"
    assert len(graph.nodes) >= 5, f"Expected >=5 nodes, got {len(graph.nodes)}"
    assert len(graph.edges) >= 3, f"Expected >=3 edges, got {len(graph.edges)}"

    print("\n✓ All assertions passed!")


if __name__ == "__main__":
    test_pipeline()
