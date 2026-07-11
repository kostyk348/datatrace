#!/bin/bash
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo "=== DataTrace ==="
echo ""

# Build everything
echo ":: Building..."
make -C bpf_agent -s 2>/dev/null
gcc -O2 -Wall -o test/game_server test/game_server.c -s 2>/dev/null
echo "   done."

export PYTHONPATH="$DIR:$PYTHONPATH"

if [ "$1" = "live" ]; then
    # Start game_server, then trace it
    ./test/game_server &
    GAME_PID=$!
    sleep 0.5

    echo ":: Tracing game_server (PID=$GAME_PID)..."
    echo "   Press Ctrl+C to stop."
    echo ""

    # Run BPF agent as root, pipe to Python analyzer
    sudo ./bpf_agent/trace $GAME_PID | python3 -m dtrace analyze -l

    kill $GAME_PID 2>/dev/null || true

elif [ "$1" = "mock" ]; then
    echo ":: Running mock test..."
    python3 test/test_pipeline.py

elif [ "$1" = "shell" ]; then
    # Interactive: pipe events to CLI
    echo ":: Starting interactive CLI..."
    echo "   Available commands: graph, find <query>, path <id>, export, analyze, summary"
    python3 -m dtrace "$2" "$3" "$4" "$5"

else
    echo "Usage:"
    echo "  $0 live    — Trace game_server (requires sudo)"
    echo "  $0 mock    — Run mock test"
    echo "  $0 shell <cmd> [args] — Run CLI command directly"
    echo ""
    echo "CLI commands:"
    echo "  Python -m dtrace graph -f <file>    Build and show graph"
    echo "  Python -m dtrace find -l <query>    Find objects"
    echo "  Python -m dtrace path -l <id>       Trace provenance path"
    echo "  Python -m dtrace analyze -l         Run analysis"
    echo "  Python -m dtrace export -l -o <file> Export as JSON"
    echo ""
    echo "To trace a running process:"
    echo "  sudo ./bpf_agent/trace <pid> | python3 -m dtrace analyze -l"
fi
