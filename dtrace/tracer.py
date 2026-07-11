"""Process tracer — run target with LD_PRELOAD, capture events into pipeline.

Usage:
    tracer = ProcessTracer()
    tracer.run(["/path/to/binary", "--arg"])
    model = tracer.hierarchy
    print(model.summary())
"""

import os
import sys
import subprocess
import tempfile
from pathlib import Path
from .events import iter_events, RawEvent
from .objects import ObjectRecovery
from .graph import ProvenanceGraph
from .hierarchy import HierarchyBuilder
from .taint import TaintEngine


PRELOAD_SO = Path(__file__).parent / "preload.so"


class ProcessTracer:
    """Run a target process with LD_PRELOAD and build provenance graph."""

    def __init__(self, preload_so: str | None = None):
        self.preload_so = preload_so or str(PRELOAD_SO)
        self.recovery = ObjectRecovery()
        self.graph = ProvenanceGraph()
        self.hierarchy = None
        self.taint = TaintEngine()
        self._raw_events: list[RawEvent] = []

    def run(self, argv: list[str], timeout: int = 30) -> int:
        """Run the target binary and capture events.

        Returns the exit code.
        """
        env = os.environ.copy()
        existing = env.get("LD_PRELOAD", "")
        if existing:
            env["LD_PRELOAD"] = self.preload_so + ":" + existing
        else:
            env["LD_PRELOAD"] = self.preload_so

        with tempfile.NamedTemporaryFile(mode="w+", suffix=".jsonl", delete=False) as f:
            event_path = f.name

        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=open(event_path, "w"),
            env=env,
        )

        try:
            stdout, _ = proc.communicate(timeout=timeout)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            rc = -1

        # Parse events
        with open(event_path) as f:
            self._raw_events = list(iter_events(f))

        # Feed into recovery
        for ev in self._raw_events:
            if ev.is_alloc_ret:
                self.recovery.add_allocation(ev.addr, ev.size, ev.pid, ev.tid, ev.ts, ev)
            elif ev.is_free:
                self.recovery.add_free(ev.addr, ev.ts)
            elif ev.is_copy:
                self.recovery.add_copy(ev.addr, ev.addr2, ev.size, ev.ts, ev)
            elif ev.is_network_send:
                self.recovery.add_network_send(ev.addr, ev.addr2 & 0xFFFFFFFF, ev.size, ev.ts, ev)
            elif ev.is_network_recv:
                self.recovery.add_network_recv(ev.addr, ev.addr2 & 0xFFFFFFFF, ev.size, ev.ts, ev)

        # Build graph
        for obj in self.recovery.objects:
            self.graph.ingest_object(obj)

        # Build hierarchy
        builder = HierarchyBuilder(self.recovery, self.graph)
        self.hierarchy = builder.build()

        # Taint propagation over the same event stream
        for ev in self._raw_events:
            self.taint.feed(ev)

        os.unlink(event_path)
        return rc

    @property
    def summary(self) -> str:
        lines = [
            f"Trace: {len(self._raw_events)} events, "
            f"{len(self.recovery.objects)} objects, "
            f"{len(self.graph.nodes)} graph nodes",
        ]
        if self.hierarchy:
            lines.append(self.hierarchy.summary())
        return "\n".join(lines)
