#!/usr/bin/env python3
"""Generate mock trace events simulating ATM Deluxe font engine operations."""
import sys
import json
import random
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

SAMPLE_SIZE = 32

def ev(ts, etype, addr=0, addr2=0, size=0, sample=None):
    d = {"ts": ts, "pid": 1234, "tid": 1234, "type": etype,
         "addr": addr, "addr2": addr2, "size": size}
    if sample:
        import base64
        d["sample_b64"] = base64.b64encode(sample).decode()
    return json.dumps(d)

# Event types
MALLOC, FREE, CALLOC = 1, 2, 3
MEMCPY, MEMMOVE = 4, 5
SENDTO, RECVFROM = 6, 7
RET_MASK = 0x1000

ts = 0
BASE = 0x7f0000000000

# Simulate font engine initialization
# ATMStartup -> allocates engine context (atmlib internal state)
events = []
ts += 1000
events.append(ev(ts, MALLOC, size=4096))  # Engine context (main ATM struct)
events.append(ev(ts+5, MALLOC | RET_MASK, addr=0x7f00001000))

ts += 500
events.append(ev(ts, CALLOC, addr=1, addr2=4096))  # Font cache pool
events.append(ev(ts+5, CALLOC | RET_MASK, addr=0x7f00002000))

# ATMEnumFonts -> enumerates system fonts
ts += 500
events.append(ev(ts, CALLOC, addr=1, addr2=512))  # Font list buffer
events.append(ev(ts+5, CALLOC | RET_MASK, addr=0x7f00003000))

# Memory of font names
ts += 200
events.append(ev(ts, MALLOC, size=256))
events.append(ev(ts+5, MALLOC | RET_MASK, addr=0x7f00003500))

ts += 200
events.append(ev(ts, MALLOC, size=256))
events.append(ev(ts+5, MALLOC | RET_MASK, addr=0x7f00003800))

# ATMGetFontPaths -> gets paths to .pfb/.pfm files
ts += 500
events.append(ev(ts, MALLOC, size=1024))  # Path buffer
events.append(ev(ts+5, MALLOC | RET_MASK, addr=0x7f00004000))

# Reading font file (simulated via memcpy from file read buffer)
ts += 300
events.append(ev(ts, MEMCPY, addr=0x7f00005000, addr2=0x7f00004000, size=260))
ts += 100
events.append(ev(ts, MEMCPY, addr=0x7f00005080, addr2=0x7f00003800, size=256))

# ATMGetFontInfo -> retrieves font metrics
ts += 500
events.append(ev(ts, MALLOC, size=128))  # Font info struct (LOGFONT-like)
events.append(ev(ts+5, MALLOC | RET_MASK, addr=0x7f00006000))

ts += 100
# Fill font info
events.append(ev(ts, MEMCPY, addr=0x7f00006000, addr2=0x7f00005000, size=128))

# ATMGetFontBBox -> bounding box
ts += 400
events.append(ev(ts, MALLOC, size=32))  # BBOX struct (4 x int)
events.append(ev(ts+5, MALLOC | RET_MASK, addr=0x7f00007000))

# ATMGetGlyphList -> enumerate glyphs in font
ts += 500
events.append(ev(ts, MALLOC, size=1024))  # Glyph list
events.append(ev(ts+5, MALLOC | RET_MASK, addr=0x7f00008000))

# Fill glyph list with a few glyph entries
for i in range(10):
    ts += 50
    glyph_addr = 0x7f00008000 + i * 8
    events.append(ev(ts, MEMCPY, addr=glyph_addr, addr2=0, size=8))  # glyph_id

# ATMGetOutline -> get PostScript outline for a glyph
# This is the CORE font engine feature - converts glyph to bezier paths
ts += 1000
events.append(ev(ts, MALLOC, size=2048))  # Outline buffer
events.append(ev(ts+5, MALLOC | RET_MASK, addr=0x7f00009000))

ts += 200
# Memcpy outline data (PostScript path commands)
outline_data = bytes([random.randint(0,255) for _ in range(512)])
events.append(ev(ts, MEMCPY, addr=0x7f00009000, addr2=0x7f00005000, size=512))

# ATMGetOutline -> second glyph
ts += 300
events.append(ev(ts, MALLOC, size=4096))
events.append(ev(ts+5, MALLOC | RET_MASK, addr=0x7f0000a000))

outline_data2 = bytes([random.randint(0,255) for _ in range(1024)])
events.append(ev(ts, MEMCPY, addr=0x7f0000a000, addr2=0x7f00005080, size=1024))

# ATMXYShowText / ATMBBoxBaseXYShowText -> text rendering
# The renderer allocates a bitmap buffer for the glyph
ts += 1000
events.append(ev(ts, CALLOC, addr=1, addr2=65536))  # 256x256 glyph bitmap
events.append(ev(ts+5, CALLOC | RET_MASK, addr=0x7f0000b000))

ts += 100
# Memcpy to compositing buffer (rendering)
events.append(ev(ts, MEMCPY, addr=0x7f0000c000, addr2=0x7f0000b000, size=4096))

# Second text render
ts += 500
events.append(ev(ts, CALLOC, addr=1, addr2=65536))
events.append(ev(ts+5, CALLOC | RET_MASK, addr=0x7f0000d000))

# DIBEngine gamma correction workaround
# (mentioned in ATM.CNF - DIBEngineGammaWorkaround=On)
ts += 300
events.append(ev(ts, MALLOC, size=4096))  # Gamma LUT
events.append(ev(ts+5, MALLOC | RET_MASK, addr=0x7f0000e000))

# Gamma table
events.append(ev(ts, MEMCPY, addr=0x7f0000e000, addr2=0x7f0000b000, size=256))

# Font substitution
# ATMInstallSubstFont - record substitution
ts += 500
events.append(ev(ts, MALLOC, size=64))  # Subst font record
events.append(ev(ts+5, MALLOC | RET_MASK, addr=0x7f0000f000))

# Auto-activation (AutoActivate=On in ATM.CNF)
ts += 400
events.append(ev(ts, MALLOC, size=256))  # Activation record
events.append(ev(ts+5, MALLOC | RET_MASK, addr=0x7f00010000))

# ATMFontAvailable check
ts += 200
events.append(ev(ts, MEMCPY, addr=0x7f00011000, addr2=0x7f00003500, size=64))

# Free operations - cleanup
ts += 2000
events.append(ev(ts, FREE, addr=0x7f00003000, sample=b"\x00" * 32))
events.append(ev(ts+50, FREE, addr=0x7f00003500, sample=b"\x00" * 32))
events.append(ev(ts+100, FREE, addr=0x7f00003800, sample=b"\x00" * 32))
events.append(ev(ts+150, FREE, addr=0x7f00004000, sample=b"\x00" * 32))
events.append(ev(ts+200, FREE, addr=0x7f00006000, sample=b"\x00" * 32))
events.append(ev(ts+250, FREE, addr=0x7f00007000, sample=b"\x00" * 32))
events.append(ev(ts+300, FREE, addr=0x7f00008000, sample=b"\x00" * 32))
events.append(ev(ts+350, FREE, addr=0x7f00009000, sample=b"\x00" * 32))
events.append(ev(ts+400, FREE, addr=0x7f0000a000, sample=b"\x00" * 32))
events.append(ev(ts+450, FREE, addr=0x7f0000b000, sample=b"\x00" * 32))
events.append(ev(ts+500, FREE, addr=0x7f0000c000, sample=b"\x00" * 32))
events.append(ev(ts+550, FREE, addr=0x7f0000d000, sample=b"\x00" * 32))
events.append(ev(ts+600, FREE, addr=0x7f0000e000, sample=b"\x00" * 32))
events.append(ev(ts+650, FREE, addr=0x7f0000f000, sample=b"\x00" * 32))
events.append(ev(ts+700, FREE, addr=0x7f00010000, sample=b"\x00" * 32))

# ATMFinish cleanup
ts += 1000
events.append(ev(ts, FREE, addr=0x7f00001000, sample=b"\x00" * 32))
events.append(ev(ts+50, FREE, addr=0x7f00002000, sample=b"\x00" * 32))

for e in events:
    print(e)
