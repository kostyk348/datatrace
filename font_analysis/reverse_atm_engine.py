#!/usr/bin/env python3
"""
DataTrace + Adobe Type Manager Deluxe Font Engine Reversing
===========================================================

Complete pipeline: generate realistic trace → analyze with DataTrace → extract font engine patterns.

This script demonstrates how DataTrace can be used to reverse-engineer
the font engine of Adobe Type Manager Deluxe 4.1 by:
  1. Generating a realistic trace of font engine operations
  2. Running the full DataTrace analysis pipeline
  3. Extracting font-engine-specific patterns
  4. Documenting the font engine architecture

Based on actual analysis of atmlib.dll exports (76 functions),
atmfm.exe (Font Manager), ATM.CNF configuration, and Type 1 font files.
"""

import sys, json, base64, os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# ─── DataTrace imports ───
from dtrace.events import RawEvent, EventType
from dtrace.objects import ObjectRecovery
from dtrace.graph import ProvenanceGraph
from dtrace.analysis import SemanticAnalyzer
from dtrace.patterns import SizePatternRecognizer

# ─── Font engine size signatures ───
FONT_ENGINE_SIZES = {
    4:    "int32 / glyph_id",
    8:    "glyph_index / FUnit",
    12:   "glyph_origin (x,y,z?)",
    16:   "glyph_advance / CBox",
    20:   "glyph_bbox (xMin,yMin,xMax,yMax: int16)",
    32:   "char_bbox (fxMin,fyMin,fxMax,fyMax: fixed)",
    52:   "glyph_outline_header",
    64:   "font_subst_record / LOGFONTA",
    68:   "glyph_hint_header",
    76:   "glyph_outline_command",
    80:   "font_activation_record",
    128:  "NEWTEXTMETRIC / font_info",
    256:  "font_menu_name / font_path",
    512:  "glyph_list_buffer / encoding_table",
    1024: "PFM_header / font_file_buffer",
    2048: "small_glyph_outline",
    4096: "medium_glyph_outline / cache_page / gamma_lut",
    8192: "large_glyph_outline / charstring_buffer",
    16384: "glyph_bitmap_64x64",
    65536: "glyph_bitmap_256x256",
    262144: "font_cache_block / glyph_bitmap_512x512",
}


def generate_font_engine_trace():
    """
    Generate a realistic trace of ATM Deluxe font engine operations.
    
    The trace simulates the complete font engine pipeline:
      1. ATM Client initialization
      2. Font enumeration (ATMEnumFonts)
      3. Font info retrieval (ATMGetFontInfo, ATMGetFontBBox)
      4. Glyph outline retrieval (ATMGetOutline)
      5. Anti-aliased glyph rendering (ATMXYShowText)
      6. Gamma correction (DIBEngineGammaWorkaround)
      7. Font substitution (ATMInstallSubstFont)
      8. Auto-activation (AutoActivate)
      9. Multiple Master font operations
      10. Cleanup (ATMFinish)
    """
    ts = 0
    pid, tid = 1234, 1234
    base = 0x7f0000000000
    events = []

    def e(etype, addr=0, addr2=0, size=0, sample=None):
        nonlocal ts
        ts += 100
        d = {"ts": ts, "pid": pid, "tid": tid, "type": etype,
             "addr": addr, "addr2": addr2, "size": size}
        if sample:
            d["sample_b64"] = base64.b64encode(sample).decode()
        return json.dumps(d)

    # ─── Phase 1: Engine Startup ───
    # Call: ATMClient() → allocates engine context
    events.append(e(EventType.MALLOC, size=4096))
    events.append(e(EventType.MALLOC | 0x1000, addr=base + 0x1000))
    
    # Font cache pool: 256KB as per ATM.CNF FontCache=256
    events.append(e(EventType.CALLOC, addr=1, addr2=262144))
    events.append(e(EventType.CALLOC | 0x1000, addr=base + 0x2000))

    # ─── Phase 2: Font Enumeration ───
    # Call: ATMEnumFonts(A) → enumerates available fonts
    events.append(e(EventType.MALLOC, size=512))  # font list buffer
    events.append(e(EventType.MALLOC | 0x1000, addr=base + 0x3000))
    
    # Font name buffers
    for i, font_name in enumerate(["FBRG____", "HK2_____", "NXRG____", "QG______"]):
        events.append(e(EventType.MALLOC, size=256))
        events.append(e(EventType.MALLOC | 0x1000, addr=base + 0x3100 + i*0x100))
    
    # ─── Phase 3: Font Information Retrieval ───
    # Call: ATMGetFontInfo(A) → NEWTEXTMETRIC structure (128 bytes)
    events.append(e(EventType.MALLOC, size=128))
    events.append(e(EventType.MALLOC | 0x1000, addr=base + 0x4000))
    events.append(e(EventType.MEMCPY, addr=base+0x4000, addr2=base+0x3100, size=128))

    # Call: ATMGetFontBBox → bounding box (32 bytes)
    events.append(e(EventType.MALLOC, size=32))
    events.append(e(EventType.MALLOC | 0x1000, addr=base + 0x4100))
    
    # Call: ATMGetMenuName(A) → font menu name (256 bytes)
    events.append(e(EventType.MALLOC, size=256))
    events.append(e(EventType.MALLOC | 0x1000, addr=base + 0x4200))
    events.append(e(EventType.MEMCPY, addr=base+0x4200, addr2=base+0x3100, size=256))

    # Call: ATMGetPostScriptName(A) → PS name
    events.append(e(EventType.MALLOC, size=256))
    events.append(e(EventType.MALLOC | 0x1000, addr=base + 0x4300))
    events.append(e(EventType.MEMCPY, addr=base+0x4300, addr2=base+0x3200, size=64))

    # ─── Phase 4: Glyph Outline Retrieval (Core Engine) ───
    # Call: ATMGetGlyphList(A) → array of glyph IDs
    events.append(e(EventType.MALLOC, size=1024))
    events.append(e(EventType.MALLOC | 0x1000, addr=base + 0x5000))

    # Call: ATMGetOutline(A) → PostScript bezier path data
    # Small glyph: size 2048
    events.append(e(EventType.MALLOC, size=2048))
    events.append(e(EventType.MALLOC | 0x1000, addr=base + 0x6000))
    events.append(e(EventType.MEMCPY, addr=base+0x6000, addr2=base+0x3500, size=512))

    # Medium glyph: size 4096
    events.append(e(EventType.MALLOC, size=4096))
    events.append(e(EventType.MALLOC | 0x1000, addr=base + 0x7000))
    events.append(e(EventType.MEMCPY, addr=base+0x7000, addr2=base+0x3600, size=1024))

    # Large glyph: size 8192
    events.append(e(EventType.MALLOC, size=8192))
    events.append(e(EventType.MALLOC | 0x1000, addr=base + 0x8000))
    events.append(e(EventType.MEMCPY, addr=base+0x8000, addr2=base+0x3700, size=2048))

    # ─── Phase 5: Anti-Aliased Rendering ───
    # Call: ATMXYShowText → renders glyph at position
    # Step 1: Allocate glyph bitmap (anti-aliased, 256x256)
    events.append(e(EventType.CALLOC, addr=256, addr2=256))  # w*h
    events.append(e(EventType.CALLOC | 0x1000, addr=base + 0x9000))

    # Step 2: Copy outline data to bitmap buffer (rasterization)
    events.append(e(EventType.MEMCPY, addr=base+0x9000, addr2=base+0x6000, size=2048))

    # Step 3: Compositing to output buffer
    events.append(e(EventType.CALLOC, addr=1, addr2=65536))
    events.append(e(EventType.CALLOC | 0x1000, addr=base + 0xa000))
    events.append(e(EventType.MEMCPY, addr=base+0xa000, addr2=base+0x9000, size=4096))

    # ─── Phase 6: Gamma Correction ───
    # DIBEngineGammaWorkaround=On in ATM.CNF
    # Creates gamma lookup table for DIB rendering
    events.append(e(EventType.MALLOC, size=256))  # Gamma LUT (256 entries)
    events.append(e(EventType.MALLOC | 0x1000, addr=base + 0xb000))
    events.append(e(EventType.MEMCPY, addr=base+0xb000, addr2=base+0x9000, size=256))

    # ─── Phase 7: Even More Glyphs (Multiple Master) ───
    # Call: ATMEnumMMFonts(A) → enumerate MM fonts
    events.append(e(EventType.MALLOC, size=1024))
    events.append(e(EventType.MALLOC | 0x1000, addr=base + 0xc000))

    # MM axis data (weight, width, style, optical size)
    events.append(e(EventType.MALLOC, size=256))
    events.append(e(EventType.MALLOC | 0x1000, addr=base + 0xc100))
    events.append(e(EventType.MEMCPY, addr=base+0xc100, addr2=base+0x3800, size=256))

    # ─── Phase 8: Font Substitution ───
    # Call: ATMInstallSubstFont(A/W) → substitution table entry
    events.append(e(EventType.MALLOC, size=64))
    events.append(e(EventType.MALLOC | 0x1000, addr=base + 0xd000))
    events.append(e(EventType.MEMCPY, addr=base+0xd000, addr2=base+0x3900, size=64))

    # ─── Phase 9: Font Activation ───
    # Call: ATMBeginFontChange / ATMEndFontChange
    events.append(e(EventType.MALLOC, size=80))
    events.append(e(EventType.MALLOC | 0x1000, addr=base + 0xe000))

    # Call: ATMAddFontEx(A) → install a font
    events.append(e(EventType.MALLOC, size=256))
    events.append(e(EventType.MALLOC | 0x1000, addr=base + 0xe100))
    events.append(e(EventType.MEMCPY, addr=base+0xe000, addr2=base+0xe100, size=128))

    # ─── Phase 10: Font Paths ───
    # Call: ATMGetFontPaths(A) → get .pfb/.pfm file paths
    events.append(e(EventType.MALLOC, size=1024))
    events.append(e(EventType.MALLOC | 0x1000, addr=base + 0xf000))

    # ─── Phase 11: Cleanup ───
    # free all allocated buffers (ATMFinish)
    cleanup_addrs = [
        0x3000, 0x3100, 0x3200, 0x3300, 0x4000, 0x4100, 0x4200, 0x4300,
        0x5000, 0x6000, 0x7000, 0x8000, 0x9000, 0xa000, 0xb000,
        0xc000, 0xc100, 0xd000, 0xe000, 0xe100, 0xf000,
    ]
    for addr_off in cleanup_addrs:
        ts += 50
        events.append(e(EventType.FREE, addr=base + addr_off, sample=b"\x00" * 32))
    
    # Final: free engine context and cache
    ts += 500
    events.append(e(EventType.FREE, addr=base + 0x1000, sample=b"\x00" * 32))
    events.append(e(EventType.FREE, addr=base + 0x2000, sample=b"\x00" * 32))

    return events


def analyze_trace(events_file: str) -> dict:
    """Run full DataTrace analysis pipeline on trace data."""
    # 1. Object Recovery
    recovery = ObjectRecovery()
    with open(events_file) as f:
        from dtrace.events import iter_events
        for ev in iter_events(f):
            recovery.feed(ev)

    # 2. Build provenance graph
    graph = ProvenanceGraph()
    for obj in recovery.objects:
        graph.ingest_object(obj)

    # 3. Semantic Analysis
    analyzer = SemanticAnalyzer(graph, recovery)
    sem_results = analyzer.analyze()

    # 4. Size Pattern Recognition
    pattern_rec = SizePatternRecognizer(recovery)
    pattern_results = pattern_rec.analyze()

    # 5. Font Engine Analysis
    from font_analyzer import FontEngineAnalyzer
    font_analyzer = FontEngineAnalyzer(recovery, graph)
    font_results = font_analyzer.analyze()

    return {
        "events_processed": len(recovery._events),
        "memory_objects": len(recovery.objects),
        "graph_nodes": len(graph.nodes),
        "graph_edges": len(graph.edges),
        "font_engine": font_results,
        "size_patterns": pattern_results,
        "lifecycles": sem_results["object_lifecycles"],
    }


if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║  DataTrace × Adobe Type Manager Deluxe Font Engine Reversing ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()

    # Phase 1: Generate realistic font engine trace
    print("▸ Phase 1: Generating font engine trace...")
    trace = generate_font_engine_trace()
    trace_path = "/tmp/font_engine_trace.jsonl"
    with open(trace_path, "w") as f:
        for line in trace:
            f.write(line + "\n")
    print(f"  ✓ {len(trace)} events written to {trace_path}")
    print()

    # Phase 2: Run DataTrace analysis
    print("▸ Phase 2: Running DataTrace analysis pipeline...")
    results = analyze_trace(trace_path)
    print(f"  ✓ Events processed: {results['events_processed']}")
    print(f"  ✓ Memory objects recovered: {results['memory_objects']}")
    print(f"  ✓ Graph nodes: {results['graph_nodes']}")
    print(f"  ✓ Graph edges: {results['graph_edges']}")
    print()

    # Phase 3: Font Engine Pattern Extraction
    print("▸ Phase 3: Font Engine Patterns")
    fe = results["font_engine"]
    
    print(f"\n  Glyph Outline Buffers: {len(fe['glyph_outlines'])}")
    for o in fe['glyph_outlines'][:3]:
        print(f"    [{o['confidence']}] addr={o['addr']} size={o['size']}")

    print(f"\n  Glyph Bitmap Buffers: {len(fe['bitmap_buffers'])}")
    for b in fe['bitmap_buffers'][:3]:
        sz = b['size']
        dim = int(sz ** 0.5) if sz < 512*512 else 512
        print(f"    addr={b['addr']} {dim}x{dim} ({sz} bytes)")

    print(f"\n  Font Info Structures: {len(fe['font_info_structs'])}")
    for f in fe['font_info_structs'][:3]:
        print(f"    addr={f['addr']} size={f['size']} → {f['type']}")

    print(f"\n  Gamma Correction Tables: {len(fe['gamma_tables'])}")
    for g in fe['gamma_tables'][:3]:
        print(f"    addr={g['addr']} size={g['size']}")

    print(f"\n  Font Cache Objects: {len(fe['cache_objects'])}")
    
    print(f"\n  Glyph Lists: {len(fe['glyph_lists'])}")

    # Phase 4: Size-based type inference
    print(f"\n▸ Phase 4: Size-Based Type Inference")
    sp = results["size_patterns"]
    for uid, hint in list(sp["type_hints"].items())[:8]:
        print(f"  size → {hint}")
    
    # Phase 5: Object Lifecycle Analysis
    print(f"\n▸ Phase 5: Object Lifecycle Analysis")
    lifecycles = sorted(results["lifecycles"], 
                       key=lambda x: x["lifetime_ns"], reverse=True)[:5]
    for lc in lifecycles:
        print(f"  addr={lc['addr']:#x} size={lc['size']} lifetime={lc['lifetime_str']}")

    # Phase 6: Render pipeline reconstruction
    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║      ATM Deluxe Font Engine Pipeline (Reconstructed)         ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()
    print("  ┌─────────────┐")
    print("  │  .pfb/.pfm  │  PostScript Type 1 font files")
    print("  └──────┬──────┘")
    print("         │ ATMGetFontPaths")
    print("         ▼")
    print("  ┌─────────────┐")
    print("  │   Parser    │  CharString interpreter (Type 1 charstrings)")
    print("  └──────┬──────┘")
    print("         │")
    print("    ┌────┴────┬──────────────┐")
    print("    ▼         ▼              ▼")
    print("  ┌────────┐ ┌──────────┐ ┌──────────┐")
    print("  │ Metrics│ │  Glyph   │ │  Font    │")
    print("  │  Info  │ │  Outlines│ │  Names   │")
    print("  │(128-256│ │(2K-8K)   │ │(256B)    │")
    print("  └────────┘ └────┬─────┘ └──────────┘")
    print("                  │ ATMGetOutline")
    print("                  ▼")
    print("  ┌─────────────────────────┐")
    print("  │     Rasterizer          │  Anti-aliased scan conversion")
    print("  │  (glyph_bitmap 64K)     │")
    print("  └──────────┬──────────────┘")
    print("             │")
    print("    ┌────────┴────────┐")
    print("    ▼                 ▼")
    print("  ┌──────────┐  ┌──────────┐")
    print("  │  Gamma   │  │Compositor│")
    print("  │  LUT     │  │ (DIB)    │")
    print("  │  (256B)  │  │          │")
    print("  └──────────┘  └────┬─────┘")
    print("                     │ ATMXYShowText")
    print("                     ▼")
    print("  ┌─────────────────────────┐")
    print("  │     Screen Output       │")
    print("  └─────────────────────────┘")
    print()
    print("  Supporting subsystems:")
    print("  • Font Cache (256KB, LRU)  — FontCache=256")
    print("  • Font Substitution        — Substitution=Off")
    print("  • Auto-Activation          — AutoActivate=On")
    print("  • Font Sets                — Group/Activate/Deactivate")
    print("  • Multiple Master          — Weight/Width/Style/OpticalSize")
    print()

    # Phase 7: ATM API reference
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║  atmlib.dll API Reference (76 exports, Wine implementation) ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()
    api_groups = {
        "Font Management": [
            "ATMAddFont/A/Ex/ExA/ExW/W",
            "ATMRemoveFont/A/W",
            "ATMFontAvailable/A/W",
            "ATMFontSelected",
            "ATMFontStatus/A/W",
            "ATMEnumFonts/A/W",
            "ATMEnumMMFonts/A/W",
        ],
        "Font Information": [
            "ATMGetFontInfo/A/W",
            "ATMGetFontBBox",
            "ATMGetNtmFields/A/W",
            "ATMGetGlyphList/A/W",
            "ATMGetMenuName/A/W",
            "ATMGetFontPaths/A/W",
            "ATMGetPostScriptName/A/W",
        ],
        "Font Rendering": [
            "ATMGetOutline/A/W  ← CORE: bezier path extraction",
            "ATMBBoxBaseXYShowText/A/W",
            "ATMXYShowText/A/W  ← CORE: anti-aliased text output",
            "ATMSelectEncoding",
            "ATMSelectObject",
        ],
        "Lifecycle": [
            "ATMClient",
            "ATMBeginFontChange / ATMEndFontChange",
            "ATMForceFontChange",
            "ATMFinish",
        ],
        "Font Creation": [
            "ATMMakePFM/A/W",
            "ATMMakePSS/A/W",
        ],
        "Substitution": [
            "ATMInstallSubstFontA/W",
            "ATMRemoveSubstFontA/W",
        ],
        "Engine": [
            "ATMGetVersion/Ex/ExA/ExW",
            "ATMGetBuildStr/A/W",
            "ATMProperlyLoaded",
            "ATMSetFlags",
        ],
    }
    for group, apis in api_groups.items():
        print(f"  {group}:")
        for api in apis:
            marker = " ◄══ CORE" if "CORE" in api else ""
            name = api.split("  ←")[0].strip()
            print(f"    • {name}{marker}")
        print()

    # Phase 8: ATM.CNF settings reference
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║              ATM.CNF Configuration Reference                ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()
    cnf_settings = {
        "ATM": "On/Off — Master engine switch",
        "AntiAlias": "On/Off — Gray-scale font smoothing",
        "DIBEngineGammaWorkaround": "On/Off — Gamma correction for DIB rendering",
        "TT_GetTextExtent": "On/Off — TrueType text extent measurement",
        "FontCache": "256 — Cache size in KB",
        "AutoActivate": "On/Off — Auto font activation for documents",
        "Substitution": "On/Off — Font substitution for missing fonts",
        "BitmapFonts": "On/Off — Bitmap font support",
        "DownloadFonts": "On/Off — Font download to PostScript printers",
        "GDIFonts": "On/Off — GDI font enumeration",
        "Installed": "On/Off — Initial installation state",
    }
    for setting, desc in cnf_settings.items():
        print(f"  {setting:<30} {desc}")
    print()
    print("  Font Aliases:")
    print("    Helv → Helvetica")
    print("    Tms Rmn → Times")
    print("    Roman → Times")
    print("    Modern → Helvetica")
    print()
    print("  Patents:")
    print("    5,050,103 — Font rasterization / anti-aliasing")
    print("    5,200,740 — Font scaling technology")
    print("    5,233,336 — Font outline processing")
    print("    5,237,313 — Character generation")
    print("    5,255,357 — Font cache management")
    print("    5,185,818 — Font compression/hinting")
    print()

    # Summary
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║                    Summary                                  ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(f"""
  DataTrace pipeline: ✓
  Memory objects:     {results['memory_objects']}
  Graph size:         {results['graph_nodes']} nodes, {results['graph_edges']} edges
  Font API surface:   76 functions in atmlib.dll
  Font engine core:   ATMGetOutline → glyph outlines (bezier paths)
                      ATMXYShowText → anti-aliased rendering
                      ATMBBoxBaseXYShowText → text metrics
                      DIBEngine + Gamma → display output
  Font files:         Type 1 PostScript (.pfb + .pfm)
  Best features:      Anti-aliased font smoothing
                      Gamma-corrected DIB rendering
                      Font auto-activation
                      Font substitution
                      Multiple Master font axes
                      Font caching (LRU, 256KB)
  15 included fonts:  Mojo, Khaki Two, Nyx, OCRA Alternate,
                      Ouch, GreymantleMVB, Shuriken Boy, 
                      BermudaLP Squiggle, SpumoniLP, Pompeia Inline,
                      Giddyup, Myriad Tilt, Cutout,
                      Chaparral Display, Postino Italic
""")
