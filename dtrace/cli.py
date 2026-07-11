#!/usr/bin/env python3
"""DataTrace CLI."""

import sys
import json
import argparse
import os
import subprocess
from pathlib import Path
from .collector import DataTraceCollector
from .pcap_source import PcapEventSource
from .taint import TaintEngine, T_NETWORK
from .pcap import iter_packets
from .schema import SchemaRecovery
from .codegen import CodeGenerator
from .hierarchy import HierarchyBuilder


def load_args(args):
    collector = DataTraceCollector()
    if args.file:
        collector.feed_events(args.file)
    if args.stdin:
        collector.feed_events("-")
    if not args.file and not args.stdin:
        if not sys.stdin.isatty():
            collector.feed_events("-")
        elif not args.command:
            print("DataTrace — Runtime Knowledge Graph", file=sys.stderr)
            print("Usage: cat events.json | python3 -m dtrace <command> [args]", file=sys.stderr)
            print("       python3 -m dtrace --file events.json <command> [args]", file=sys.stderr)
            print("       sudo ./bpf_agent/trace <pid> | python3 -m dtrace <command>", file=sys.stderr)
            print(file=sys.stderr)
            print("Commands: graph, analyze, summary, find <q>, path <id>,", file=sys.stderr)
            print("         samples, export, pcap, schema, codegen", file=sys.stderr)
            sys.exit(0)
    collector.build_graph()
    return collector


def cmd_graph(args):
    collector = load_args(args)
    print(collector.summary())


def cmd_analyze(args):
    collector = load_args(args)
    results = collector.analyze()
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(collector.analyzer.summary())


def cmd_find(args):
    collector = load_args(args)
    nodes = collector.graph.find_by_label(args.query)
    if not nodes:
        nodes = collector.graph.find_by_kind(args.query)
    print(f"Found {len(nodes)} node(s):")
    for n in nodes:
        print(f"  [{n.kind}] {n.label}  id={n.id}")


def cmd_path(args):
    collector = load_args(args)
    from uuid import UUID
    try:
        node_id = UUID(args.node_id)
    except ValueError:
        nodes = collector.graph.find_by_label(args.node_id)
        if not nodes:
            print(f"No node found for '{args.node_id}'")
            return
        node_id = nodes[0].id
    if node_id not in collector.graph.nodes:
        print(f"Node not found")
        return
    if args.reverse:
        paths = collector.graph.paths_to(node_id)
        label = "Paths TO"
    else:
        paths = collector.graph.paths_from(node_id)
        label = "Paths FROM"
    print(f"{label} {collector.graph.nodes[node_id].label}:")
    for i, path in enumerate(paths[:10]):
        print(f"  Path {i+1}:")
        for n in path:
            print(f"    [{n.kind}] {n.label}")


def cmd_summary(args):
    collector = load_args(args)
    print(collector.summary())


def cmd_samples(args):
    collector = load_args(args)
    for obj in collector.recovery.objects:
        if not obj.samples:
            continue
        print(f"Object {obj.addr:#x} size={obj.size}")
        for i, s in enumerate(obj.samples):
            hexline = " ".join(f"{b:02x}" for b in s[:16])
            ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in s[:16])
            print(f"  sample[{i}]: {hexline:<48} {ascii_repr}" if args.hex else
                  f"  sample[{i}]: {repr(s[:16])}")
        if args.hex and obj.samples:
            # detect protocol fields across samples
            print(f"  Protocol analysis ({len(obj.samples)} samples):")
            # check if first 4 bytes are consistent (e.g. msg_type=1)
            msg_type = obj.samples[0][0:4]
            all_same = all(s[0:4] == msg_type for s in obj.samples)
            if all_same:
                val = int.from_bytes(msg_type, 'little')
                print(f"    msg_type: {val} (consistent across all samples)")
            for field_ofs, field_len, label in [(0,4,"msg_type"), (4,8,"timestamp"), (12,4,"entity_id")]:
                vals = set()
                for s in obj.samples:
                    if field_ofs + field_len <= len(s):
                        vals.add(int.from_bytes(s[field_ofs:field_ofs+field_len], 'little'))
                if len(vals) == 1:
                    print(f"    {label}: {vals.pop()} (constant)")
                elif vals:
                    print(f"    {label}: {sorted(vals)[:5]}... ({len(vals)} unique)")


def cmd_export(args):
    collector = load_args(args)
    data = collector.graph.to_dict()
    if args.output:
        with open(args.output, "w") as f:
            json.dump(data, f, indent=2)
        print(f"Exported to {args.output}")
    else:
        print(json.dumps(data, indent=2))


def cmd_pcap(args):
    """Parse a pcap file and run full protocol analysis."""
    source = PcapEventSource()
    count = source.feed(args.pcap)
    print(f"Loaded {count} packets from {args.pcap}")
    print()

    if args.json:
        import json
        print(json.dumps(source.to_dict(), indent=2))
    else:
        print(source.summary())


def cmd_schema(args):
    """Recover protocol schema from pcap."""
    source = PcapEventSource()
    if args.pcap:
        source.feed(args.pcap)
    elif args.file or not sys.stdin.isatty():
        collector = load_args(args)
        packets = []
        if args.pcap:
            packets = list(iter_packets(args.pcap))
        sr = SchemaRecovery(collector.recovery)
        sr.feed_packets(packets)
        result = sr.recover_schema()
        if args.json:
            import json
            print(json.dumps([
                {"type_id": m.type_id, "len": m.total_len, "count": m.count,
                 "sample": m.sample_payload.hex() if m.sample_payload else "",
                 "fields": [{"offset": f.offset, "size": f.size, "type": f.type_hint,
                              "semantic": f.semantic_hint, "constant": f.constant_value,
                              "unique": f.unique_values} for f in m.fields]}
                for m in result.messages
            ], indent=2))
        else:
            print(result.summary())
        return
    else:
        print("No pcap file specified. Use --pcap <file> or pipe events via stdin.")
        return

    schema = source.recover_schema()
    if args.json:
        import json
        print(json.dumps([
            {"type_id": m.type_id, "len": m.total_len, "count": m.count,
             "sample": m.sample_payload.hex() if m.sample_payload else "",
             "fields": [{"offset": f.offset, "size": f.size, "type": f.type_hint,
                          "semantic": f.semantic_hint, "constant": f.constant_value,
                          "unique": f.unique_values} for f in m.fields]}
            for m in schema.messages
        ], indent=2))
    else:
        print(schema.summary())


def cmd_hierarchy(args):
    """Build hierarchical object model from events + pcap."""
    if args.pcap:
        # Pcap-only mode: create synthetic memory objects from packets
        source = PcapEventSource()
        source.feed(args.pcap)
        schema = source.recover_schema()
        source.build_flows()

        from .objects import ObjectRecovery
        from .pcap_source import _build_synthetic_objects
        from .graph import ProvenanceGraph
        recovery = ObjectRecovery()
        _build_synthetic_objects(recovery, source)

        # Build graph from synthetic objects
        graph = ProvenanceGraph(recovery=recovery)
        for obj in recovery.objects:
            graph.ingest_object(obj)

        builder = HierarchyBuilder(recovery, graph)
        model = builder.build()
    else:
        collector = load_args(args)
        builder = HierarchyBuilder(collector.recovery, collector.graph)
        model = builder.build()

    if args.json:
        import json
        data = {
            "records": [
                {
                    "size": r.size,
                    "fields": len(r.fields),
                    "source": r.source,
                    "field_list": [
                        {"offset": f.offset, "size": f.size,
                         "type": f.type_hint, "semantic": f.semantic_hint}
                        for f in r.fields
                    ],
                }
                for r in model.records.values()
            ],
            "entities": [
                {
                    "label": e.label,
                    "record_size": e.record_type.size,
                    "instances": len(e.instances),
                    "updates": e.lifecycle.num_updates,
                    "net_events": e.lifecycle.num_network_events,
                    "copies": e.lifecycle.num_copies,
                }
                for e in model.entities.values()
            ],
            "systems": [
                {"name": s.name, "kind": s.kind, "entities": len(s.entities)}
                for s in model.systems.values()
            ],
        }
        print(json.dumps(data, indent=2))
    else:
        print(model.summary())


def cmd_trace(args):
    """Run a binary with LD_PRELOAD tracer and build hierarchy."""
    from .tracer import ProcessTracer
    tracer = ProcessTracer(preload_so=args.preload_so)
    rc = tracer.run(args.target, timeout=args.timeout)
    print(f"(exit: {rc})\n")
    print(tracer.summary)
    if args.json and tracer.hierarchy:
        import json
        data = {
            "events": len(tracer._raw_events),
            "objects": len(tracer.recovery.objects),
            "graph_nodes": len(tracer.graph.nodes),
            "records": [str(k) for k in tracer.hierarchy.records.keys()],
            "entities": [str(k) for k in tracer.hierarchy.entities.keys()],
            "systems": [str(k) for k in tracer.hierarchy.systems.keys()],
        }
        print(json.dumps(data, indent=2))


def cmd_taint(args):
    """Analyze taint propagation over a captured event stream."""
    collector = load_args(args)
    report = collector.taint.report()
    print(report.summary())
    if args.dot:
        dot = collector.taint.flow_dot("taint-flow")
        with open(args.dot, "w") as f:
            f.write(dot)
        print(f"\nWrote flow graph to {args.dot}")


def cmd_run(args):
    """Run a binary with LD_PRELOAD tracer + taint analysis.

    Unified entry point:
        datatrace run <binary> [--taint] [--emit flow:out.dot] [--timeout N]
    """
    from .tracer import ProcessTracer
    tracer = ProcessTracer(preload_so=args.preload_so)
    rc = tracer.run(args.target, timeout=args.timeout)
    print(f"(exit: {rc})\n")
    print(tracer.summary)
    if args.taint or args.emit:
        print()
        print(tracer.taint.report().summary())
    if args.emit:
        spec = args.emit
        kind, _, path = spec.partition(":")
        if kind in ("flow", "dot"):
            dot = tracer.taint.flow_dot("taint-flow")
            with open(path or "taint_flow.dot", "w") as f:
                f.write(dot)
            print(f"\nWrote taint flow graph to {path or 'taint_flow.dot'}")
        else:
            print(f"Unknown --emit kind '{kind}' (use 'flow:out.dot')")


def cmd_codegen(args):
    """Generate server stub + structs from pcap + optional live trace."""
    source = PcapEventSource()
    if args.pcap:
        source.feed(args.pcap)
    else:
        print("No pcap file specified. Use --pcap <file>")
        return

    schema = source.recover_schema()

    if args.python:
        # Build hierarchy model to inform codegen
        from .hierarchy import HierarchyBuilder
        from .graph import ProvenanceGraph
        from .objects import ObjectRecovery
        from .pcap_source import _build_synthetic_objects
        source.build_flows()
        recovery = ObjectRecovery()
        _build_synthetic_objects(recovery, source)
        graph = ProvenanceGraph(recovery=recovery)
        for obj in recovery.objects:
            graph.ingest_object(obj)
        builder = HierarchyBuilder(recovery, graph)
        model = builder.build()
        from .codegen import PythonCodeGenerator
        gen = PythonCodeGenerator(schema, model)
    else:
        gen = CodeGenerator(schema, None)

    if args.output:
        files = gen.generate(args.output)
        for name, content in files.items():
            import os
            path = os.path.join(args.output, name)
            with open(path, "w") as f:
                f.write(content)
            print(f"  wrote {path}")
    else:
        print(gen.summary())


def main():
    parser = argparse.ArgumentParser(description="DataTrace", add_help=False)
    parser.add_argument("--file", "-f", help="Events file")
    parser.add_argument("--stdin", "-s", action="store_true", help="Read stdin")
    parser.add_argument("--json", action="store_true", help="JSON output")

    sub = parser.add_subparsers(dest="command")
    sub.add_parser("graph")
    sub.add_parser("analyze")
    sub.add_parser("summary")
    p_find = sub.add_parser("find")
    p_find.add_argument("query")
    p_path = sub.add_parser("path")
    p_path.add_argument("node_id")
    p_path.add_argument("--reverse", "-r", action="store_true")
    p_samples = sub.add_parser("samples")
    p_samples.add_argument("--hex", "-x", action="store_true", help="Hex dump format")
    p_export = sub.add_parser("export")
    p_export.add_argument("--output", "-o")

    p_pcap = sub.add_parser("pcap", help="Parse pcap file")
    p_pcap.add_argument("pcap", help="Path to pcap file")
    p_pcap.add_argument("--json", action="store_true", help="JSON output")

    p_schema = sub.add_parser("schema", help="Recover protocol schema")
    p_schema.add_argument("--pcap", "-p", help="Optional pcap file for packet data")
    p_schema.add_argument("--json", action="store_true", help="JSON output")

    p_codegen = sub.add_parser("codegen", help="Generate server stub code")
    p_codegen.add_argument("--output", "-o", default=".", help="Output directory")
    p_codegen.add_argument("--pcap", "-p", help="Optional pcap file")
    p_codegen.add_argument("--python", action="store_true", help="Generate Python (asyncio) instead of C")

    p_hierarchy = sub.add_parser("hierarchy", help="Build hierarchical object model")
    p_hierarchy.add_argument("--pcap", "-p", help="Optional pcap file")
    p_hierarchy.add_argument("--json", action="store_true", help="JSON output")

    p_trace = sub.add_parser("trace", help="Run binary with LD_PRELOAD tracer")
    p_trace.add_argument("target", nargs="+", metavar="BINARY [ARGS...]", help="Binary and arguments to trace")
    p_trace.add_argument("--preload-so", default=None, help="Path to preload.so")
    p_trace.add_argument("--timeout", type=int, default=30, help="Timeout in seconds")
    p_trace.add_argument("--json", action="store_true", help="JSON output")

    p_taint = sub.add_parser("taint", help="Analyze taint propagation over events")
    p_taint.add_argument("--dot", "-d", default=None, help="Write taint flow graph (DOT)")
    p_taint.add_argument("--json", action="store_true", help="JSON output")

    p_run = sub.add_parser("run", help="Run binary + taint analysis (unified)")
    p_run.add_argument("target", nargs="+", metavar="BINARY [ARGS...]", help="Binary and arguments to trace")
    p_run.add_argument("--preload-so", default=None, help="Path to preload.so")
    p_run.add_argument("--timeout", type=int, default=30, help="Timeout in seconds")
    p_run.add_argument("--taint", action="store_true", help="Print taint report")
    p_run.add_argument("--emit", default=None, help="Emit artifact, e.g. flow:out.dot")

    args, extra = parser.parse_known_args()

    commands = {
        "graph": cmd_graph,
        "analyze": cmd_analyze,
        "find": cmd_find,
        "path": cmd_path,
        "samples": cmd_samples,
        "summary": cmd_summary,
        "export": cmd_export,
        "pcap": cmd_pcap,
        "schema": cmd_schema,
        "codegen": cmd_codegen,
        "hierarchy": cmd_hierarchy,
        "trace": cmd_trace,
        "taint": cmd_taint,
        "run": cmd_run,
    }

    if args.command in commands:
        commands[args.command](args)
    else:
        # Default: show summary
        collector = load_args(args)
        print(collector.summary())

if __name__ == "__main__":
    main()
