## DataTrace — LD_PRELOAD / eBPF Taint Tracker

Trace how **untrusted** data (network `recvfrom`, file reads, argv, …) flows
through a process and reach **sinks** (e.g. `sendto`). DataTrace instruments a
target with an `LD_PRELOAD` agent that emits a JSONL event stream, then a Python
taint engine reconstructs data-flow and flags untrusted bytes reaching a sink.

```
target ──(LD_PRELOAD)──> events.jsonl ──> TaintEngine ──> report + flow.dot
```

### Build the preload agent

```sh
cd dtrace
gcc -shared -fPIC -o preload.so preload.c -ldl
```

### Usage

**Offline** — replay a captured event stream:

```sh
python3 -m dtrace --file events.jsonl taint
python3 -m dtrace --file events.jsonl taint --dot > flow.dot   # graphviz
```

> Note: `--file X` must come **before** the subcommand (`taint`/`run`).

**Live** — trace a binary end-to-end (preload agent built-in):

```sh
python3 -m dtrace run --taint /path/to/target
python3 -m dtrace run --taint --emit flow:/tmp/flow.dot /path/to/target
```

### Example

A program that `recvfrom()`s attacker data, `memcpy()`s it into a second buffer,
then `sendto()`s that buffer is flagged:

```
=== Taint Report ===
Network sinks observed: 2
UNTRUSTED data reaching a sink: 1
  [sendto] 0x55..8060 size=20 taint=network,heap
```

A `const` buffer copied and sent stays clean (`UNTRUSTED: 0`).

### Architecture

| File | Role |
|---|---|
| `dtrace/preload.c` | LD_PRELOAD agent, hooks `malloc`/`free`/`memcpy`/`recvfrom`/`sendto`, emits `EV_*` JSONL on stderr |
| `dtrace/events.py` | `RawEvent` / `EventType` parsing (`RawEvent.from_json`) |
| `dtrace/taint.py` | `TaintEngine` — 64-bit bitmask labels (T_NETWORK/T_FILE/T_ARGV/T_HEAP…), interval-map shadow memory, `L_union`/`L_intersect`, sinks, `TaintReport`, `flow_dot` |
| `dtrace/tracer.py` | `ProcessTracer` — runs target with preload, `ProcessTracer.taint` |
| `dtrace/collector.py` | `DataTraceCollector` — `feed_events` + `run_live` |
| `dtrace/cli.py` | subcommands `taint` (`--dot`) and `run` (`--taint`, `--emit flow:out.dot`) |

### Taint model

- Each byte-range carries a 64-bit **label** (bitmask of origins):
  `T_NETWORK`, `T_FILE`, `T_ARGV`, `T_CONST`, `T_HEAP`, `T_STACK`.
- `recvfrom`/`recv` mark the destination buffer `T_NETWORK`.
- `memcpy(dst, src)` propagates `L_union(src_label, dst_label)`.
- `sendto`/`send` is a **sink**: if the buffer carries `T_NETWORK` (or other
  non-heap origin) it is reported as an untrusted data-flow path.
- `flow_dot()` renders which origins reach which sinks (Graphviz DOT).

### Other tooling in this repo

- `bpf_agent/` — experimental eBPF tracer (kernel-side `tracer.bpf.c` + loader).
- `font_analysis/` — ATM/font reverse-engineering helpers.
- `photon_region/` — occlusion-culling region allocator (weston/wlroots patches).
- `libatme/` — separate ATM engine library (not part of DataTrace core).

### Requirements

- Python 3.10+, `gcc`, `libdl` (for the preload agent).
- No root required for the LD_PRELOAD path.

### License

MIT
