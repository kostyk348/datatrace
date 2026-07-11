#!/usr/bin/env python3
"""Font Engine Pattern Analyzer — extends DataTrace for font engine reverse engineering.

This module extends DataTrace's analysis pipeline with font-engine-specific
pattern recognition. It identifies memory objects and access patterns typical
of font rasterization engines like Adobe Type Manager (ATM) Deluxe.

Key font engine patterns detected:
  - Font file parsing (.pfb/.pfm Type 1 font structures)
  - Glyph outline storage (bezier curve data)
  - Anti-aliased glyph bitmap buffers
  - Font cache LRU structures
  - Gamma correction lookup tables
  - Multiple Master font axis data
  - Font substitution records
"""
import sys; sys.path.insert(0, "/home/lain/datatrace")
from dtrace.objects import ObjectRecovery, MemoryObject
from dtrace.graph import ProvenanceGraph, Node
from dtrace.analysis import SemanticAnalyzer


# Font engine allocation size signatures
FONT_ENGINE_SIZES = {
    32:   "GlyphBBox / FONTBBOX (4 x int32)",
    64:   "FontSubstRecord / LOGFONT",
    128:  "FontInfoStruct / NEWTEXTMETRIC",
    256:  "FontNameBuffer / FontMenuName",
    512:  "GlyphListBuffer / EncodingTable",
    1024: "FontPathBuffer / PFMHeader",
    2048: "GlyphOutline (small, e.g. '.' or 'i')",
    4096: "GlyphOutline (medium) / GammaLUT / CachePage",
    8192: "GlyphOutline (large) / CharString",
    16384: "GlyphBitmap (64x64 @ 32bpp)",
    65536: "GlyphBitmap (256x256 @ 32bpp)",
    262144: "GlyphBitmap (512x512) / FontCacheBlock",
}

# Memory copy patterns typical of font operations
COPY_PATTERNS = {
    "glyph_outline": {"min_size": 128, "max_size": 8192},
    "glyph_bitmap": {"min_size": 4096, "max_size": 262144},
    "font_info": {"min_size": 64, "max_size": 256},
    "gamma_table": {"exact_size": 256},
}


class FontEngineAnalyzer:
    """Analyzes memory traces for font engine patterns."""

    def __init__(self, recovery: ObjectRecovery, graph: ProvenanceGraph):
        self.recovery = recovery
        self.graph = graph

    def analyze(self) -> dict:
        return {
            "glyph_outlines": self._find_glyph_outlines(),
            "bitmap_buffers": self._find_bitmap_buffers(),
            "font_info_structs": self._find_font_info(),
            "cache_objects": self._find_cache_objects(),
            "gamma_tables": self._find_gamma_tables(),
            "glyph_lists": self._find_glyph_lists(),
            "data_flow_patterns": self._classify_data_flows(),
        }

    def _find_glyph_outlines(self) -> list[dict]:
        """Identify glyph outline buffers by size and copy patterns."""
        outlines = []
        for obj in self.recovery.objects:
            if obj.is_ghost or obj.untracked:
                continue
            if 512 <= obj.size <= 8192:
                copies_out = len(obj.copies_out)
                copies_in = len(obj.copies_in)
                if copies_out >= 1 and copies_in >= 1:
                    outlines.append({
                        "addr": f"{obj.addr:#x}",
                        "size": obj.size,
                        "label": "glyph_outline",
                        "confidence": "high" if obj.size <= 4096 else "medium",
                        "copies_in": copies_in,
                        "copies_out": copies_out,
                    })
        return outlines

    def _find_bitmap_buffers(self) -> list[dict]:
        """Find glyph bitmap buffers (large allocations, short-lived)."""
        bitmaps = []
        for obj in self.recovery.objects:
            if obj.is_ghost:
                continue
            if obj.size >= 16384 and obj.size <= 262144:
                if obj.copies_in or obj.copies_out:
                    bitmaps.append({
                        "addr": f"{obj.addr:#x}",
                        "size": obj.size,
                        "label": f"glyph_bitmap_{obj.size // 256}x{obj.size // 256}",
                        "allocs": len(obj.allocations),
                    })
        return bitmaps

    def _find_font_info(self) -> list[dict]:
        """Find font information structures."""
        infos = []
        for obj in self.recovery.objects:
            if obj.is_ghost:
                continue
            if obj.size in (64, 128, 256):
                if len(obj.copies_in) >= 1:
                    infos.append({
                        "addr": f"{obj.addr:#x}",
                        "size": obj.size,
                        "type": FONT_ENGINE_SIZES.get(obj.size, "FontData"),
                        "copies_in": len(obj.copies_in),
                    })
        return infos

    def _find_cache_objects(self) -> list[dict]:
        """Identify font cache allocations."""
        cache = []
        for obj in self.recovery.objects:
            if obj.is_ghost or obj.untracked:
                continue
            if obj.size >= 4096:
                lifecycles = []
                for alloc in obj.allocations:
                    if alloc.destroyed_ts:
                        lifetime = alloc.destroyed_ts - alloc.created_ts
                        lifecycles.append(lifetime)
                if lifecycles:
                    avg_lifetime = sum(lifecycles) / len(lifecycles)
                    if avg_lifetime > 1_000_000:  # > 1ms = persistent cache
                        cache.append({
                            "addr": f"{obj.addr:#x}",
                            "size": obj.size,
                            "avg_lifetime_ns": int(avg_lifetime),
                            "allocs": len(obj.allocations),
                            "label": "font_cache",
                        })
        return cache

    def _find_gamma_tables(self) -> list[dict]:
        """Identify gamma correction lookup tables (256-byte tables)."""
        gamma = []
        for obj in self.recovery.objects:
            if obj.is_ghost:
                continue
            if obj.size == 256 or obj.size == 4096:
                if len(obj.copies_in) >= 1:
                    gamma.append({
                        "addr": f"{obj.addr:#x}",
                        "size": obj.size,
                        "label": "gamma_lut" if obj.size == 256 else "gamma_lut_aligned",
                        "copies_in": len(obj.copies_in),
                    })
        return gamma

    def _find_glyph_lists(self) -> list[dict]:
        """Find glyph enumeration lists (arrays of glyph IDs)."""
        lists = []
        for obj in self.recovery.objects:
            if obj.is_ghost:
                continue
            if 256 <= obj.size <= 2048:
                if len(obj.copies_in) >= 5:
                    lists.append({
                        "addr": f"{obj.addr:#x}",
                        "size": obj.size,
                        "glyph_count": len(obj.copies_in),
                        "label": "glyph_list",
                    })
        return lists

    def _classify_data_flows(self) -> list[dict]:
        """Classify font engine data flow patterns."""
        flows = []
        for obj in self.recovery.objects:
            if obj.is_ghost or obj.untracked:
                continue
            paths = self.graph.paths_from(obj.uuid, max_depth=5)
            for path in paths:
                if len(path) >= 2:
                    desc = " → ".join(n.kind for n in path)
                    labels = [n.label for n in path]
                    flow_type = self._classify_flow(labels)
                    if flow_type:
                        flows.append({
                            "type": flow_type,
                            "path": " → ".join(labels),
                            "length": len(path),
                        })
        return flows

    def _classify_flow(self, labels: list[str]) -> str | None:
        labels_str = " ".join(labels)
        if "outline" in labels_str.lower() or "glyph" in labels_str.lower():
            return "glyph_outline_retrieval"
        if "bitmap" in labels_str.lower() or any(
            "b000" in l or "d000" in l for l in labels
        ):
            return "glyph_rasterization"
        if "cache" in labels_str.lower():
            return "font_cache_access"
        return None

    def summary(self) -> str:
        results = self.analyze()
        lines = ["\n=== Font Engine Pattern Analysis ==="]

        outlines = results["glyph_outlines"]
        lines.append(f"\nGlyph Outlines: {len(outlines)}")
        for o in outlines[:5]:
            lines.append(f"  addr={o['addr']} size={o['size']} [{o['confidence']}]")

        bitmaps = results["bitmap_buffers"]
        lines.append(f"\nGlyph Bitmaps: {len(bitmaps)}")
        for b in bitmaps[:5]:
            lines.append(f"  addr={b['addr']} size={b['size']} ({b['label']})")

        finfo = results["font_info_structs"]
        lines.append(f"\nFont Info Structs: {len(finfo)}")
        for f in finfo[:5]:
            lines.append(f"  addr={f['addr']} size={f['size']} [{f['type']}]")

        cache = results["cache_objects"]
        lines.append(f"\nCache Objects: {len(cache)}")
        for c in cache[:5]:
            lines.append(f"  addr={c['addr']} size={c['size']} lifetime={c['avg_lifetime_ns']}ns")

        gamma = results["gamma_tables"]
        lines.append(f"\nGamma Tables: {len(gamma)}")
        for g in gamma[:5]:
            lines.append(f"  addr={g['addr']} size={g['size']}")

        glists = results["glyph_lists"]
        lines.append(f"\nGlyph Lists: {len(glists)}")

        flows = results["data_flow_patterns"]
        lines.append(f"\nData Flow Patterns: {len(flows)}")
        for f in flows[:5]:
            lines.append(f"  [{f['type']}] {f['path']}")

        return "\n".join(lines)


class FontEngineDataFlowMapper:
    """Maps font engine data flows from the provenance graph.
    
    This maps the complete ATMLIB font engine pipeline:
      Font File (.pfb/.pfm) 
        → Parse → FontInfoStruct / FontBBox / FontMenuName
        → GetOutline → GlyphOutline (bezier path commands)
        → Rasterize → GlyphBitmap (anti-aliased)
        → GammaCorrect → DisplayBitmap
        → XYShowText → Screen
    """

    STAGES = [
        "font_file_parse",
        "font_info_retrieval",
        "glyph_enumeration",
        "glyph_outline_retrieval",
        "glyph_rasterization",
        "gamma_correction",
        "text_rendering",
        "font_cache",
        "font_substitution",
        "font_activation",
    ]

    def __init__(self, graph: ProvenanceGraph):
        self.graph = graph

    def map_pipeline(self) -> dict:
        stages_found = {}
        for node_id, node in self.graph.nodes.items():
            for stage in self.STAGES:
                if stage in node.label.lower():
                    stages_found[stage] = stages_found.get(stage, 0) + 1
                    break
        return stages_found


if __name__ == "__main__":
    # Run on mock trace data
    from dtrace.collector import DataTraceCollector
    
    collector = DataTraceCollector()
    collector.feed_events("/tmp/font_events.jsonl")
    collector.build_graph()
    
    print(collector.summary())
    
    analyzer = FontEngineAnalyzer(collector.recovery, collector.graph)
    print(analyzer.summary())
