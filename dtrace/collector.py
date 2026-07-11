"""Event Collector — reads raw events and orchestrates the pipeline."""

import sys
import subprocess
import signal
import threading
from pathlib import Path
from .events import iter_events, RawEvent
from .objects import ObjectRecovery
from .graph import ProvenanceGraph
from .analysis import SemanticAnalyzer
from .taint import TaintEngine


class DataTraceCollector:
    """Orchestrates the DataTrace pipeline.

    1. Spawns BPF agent or reads from pipe/file
    2. Feeds events to ObjectRecovery
    3. Builds ProvenanceGraph
    4. Runs SemanticAnalysis
    5. Propagates taint labels
    """

    def __init__(self):
        self.recovery = ObjectRecovery()
        self.graph = ProvenanceGraph(recovery=self.recovery)
        self.analyzer: SemanticAnalyzer | None = None
        self.taint = TaintEngine()
        self._process: subprocess.Popen | None = None
        self._events_collected = 0

    def feed_events(self, source: str, buffer: bool = True):
        """Read events from a file path or stdin ('-')."""
        f: list[str]
        if source == "-":
            f = sys.stdin
        else:
            f = open(source)  # type: ignore

        for ev in iter_events(f):  # type: ignore
            self._events_collected += 1
            self.recovery.feed(ev)
            self.taint.feed(ev)
            if buffer and self._events_collected % 1000 == 0:
                print(f"[collector] {self._events_collected} events processed", file=sys.stderr)

        if source != "-":
            f.close()  # type: ignore

    def build_graph(self):
        """Build provenance graph from recovered objects."""
        for obj in self.recovery.objects:
            self.graph.ingest_object(obj)

        self.analyzer = SemanticAnalyzer(self.graph, self.recovery)

    def analyze(self) -> dict:
        if not self.analyzer:
            self.build_graph()
        return self.analyzer.analyze() if self.analyzer else {}

    def summary(self) -> str:
        parts = [
            f"=== DataTrace Summary ===",
            f"Events collected: {self._events_collected}",
            "",
            self.recovery.summary(),
            "",
            self.graph.summary(),
        ]
        if self.analyzer:
            parts.append("")
            parts.append(self.analyzer.summary())
        return "\n".join(parts)

    def run_live(self, pid: int):
        """Run BPF agent on a live process and collect events."""
        agent_path = Path(__file__).parent.parent / "bpf_agent" / "trace"

        if not agent_path.exists():
            print(f"[collector] BPF agent not found at {agent_path}", file=sys.stderr)
            print("[collector] Building...", file=sys.stderr)
            import subprocess as sp
            sp.run(["make", "-C", str(agent_path.parent)], cwd=agent_path.parent)

        self._process = subprocess.Popen(
            [str(agent_path), str(pid)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        def read_stderr():
            if self._process and self._process.stderr:
                for line in self._process.stderr:
                    print(f"[trace] {line.strip()}", file=sys.stderr)

        t = threading.Thread(target=read_stderr, daemon=True)
        t.start()

        # Read events from stdout
        if self._process and self._process.stdout:
            for line in self._process.stdout:
                if not line.strip():
                    continue
                ev = RawEvent.from_json(line.strip())
                self._events_collected += 1
                self.recovery.feed(ev)
                self.taint.feed(ev)

    def stop(self):
        if self._process:
            self._process.send_signal(signal.SIGINT)
            self._process.wait(timeout=5)
