#!/usr/bin/env python3
"""xref-scanner: find RIP-relative references from .text to target .rodata strings
in libminecraftpe.so (Android Bedrock 1.26.52.3) without a full disassembly pass.

Method: numpy byte-pattern scan for REX.W + [8A-8F|63] + ModRM(mod=00,rm=101) + disp32
whose displacement resolves exactly to a target string's vaddr. vaddr==file offset in
this DSO's first LOAD segment (verified against readelf -SW: .rodata/.text both have
offset == vaddr), so mapping is the identity for the ranges we touch.
"""
import numpy as np, sys

PATH = "/opt/data/notes/mcpelauncher/versions/1.26.52.3/lib/x86_64/libminecraftpe.so"
TARGETS = [
    b"splitscreen.unavailable.toastMessage",
    b"video.split_screen",
    b"splitscreen_join_popup",
    b"splitscreen.joinPrompt",
    b"core.splitScreen",
    b"gfx_splitscreen",
]

data = np.memmap(PATH, dtype=np.uint8, mode="r")
N = len(data)

# 1. locate each target's file offset (vaddr == offset for these ranges)
found = {}
for t in TARGETS:
    i = None
    lo = 0
    arr = data  # numpy find on uint8: use bytes search instead (fast C)
    del i, lo, arr
with open(PATH, "rb", buffering=0) as f:
    raw = f  # we re-read lazily below; rodata scan is quick with a windowed search
    f.seek(0x2300000)
    blob = f.read(0x1420000 + 0x10000)  # all of .rodata plus slack
    for t in TARGETS:
        off = blob.find(t)
        if off >= 0:
            v = 0x2300000 + off
            found[t.decode()] = v
            print(f"target {t.decode():40s} vaddr=0x{v:x}")

if not found:
    sys.exit("no targets found in .rodata")

TEXT_OFF, TEXT_V, TEXT_SIZE = 0x6878940, 0x6878940, 0x1036C405
with open(PATH, "rb", buffering=0) as f:
    f.seek(TEXT_OFF)
    text = np.frombuffer(f.read(TEXT_SIZE), dtype=np.uint8)  # 272 MB resident — ok on this box

tv = text.view(np.int8)
rex = (text == 0x48) | (text == 0x4C)
op = ((text >= 0x8A) & (text <= 0x8F)) | (text == 0x63)

# need 7 valid consecutive byte positions; compare shifted slices
L = len(text)
def sh(a, k):  # slice a[k:] padded to L
    out = np.zeros(L, dtype=bool)
    m = L - k
    out[:m] = a[k:] if a.dtype == bool else text[k:] == 0  # placeholder
    return out

# Build masks explicitly (cheap boolean arrays, 272 MB each — we have RAM)
m_rex  = np.zeros(L, bool); m_rex[:L-0] = rex[:L]
m_op   = np.zeros(L, bool); m_op[:L-1]  = op[1:L]
# modrm at p+2: mod==00, rm==101  -> (b & 0xC7) == 0x05
b2 = text[2:L]
m_modrm = np.zeros(L, bool); m_modrm[:L-2] = ((b2 & 0xC7) == 0x05)

cand = m_rex & m_op & m_modrm
idx = np.flatnonzero(cand)
print(f"pattern candidates: {len(idx)}")

# disp32 at p+3 (little-endian) ; lea target vaddr = (TEXT_V + p + 7) + disp32
d = text[3:L].astype(np.uint32)          # d[i] = byte at file p+3 when i == p
n = len(d) - 3                            # last p with a full disp32 inside the buffer
val = d[:n] | (d[1:n+1] << 8) | (d[2:n+2] << 16) | (d[3:n+3] << 24)
disp = val.astype(np.int64)
disp[val >= np.uint32(0x80000000)] -= 2**32

tset = {v: name for name, v in found.items()}
tvals = idx[idx < n].astype(np.int64)
refvaddr = TEXT_V + tvals + 7 + disp[tvals]
for i2, rv in enumerate(refvaddr):
    key = tset.get(int(rv))
    if key:
        p = int(tvals[i2])
        print(f"xref .text+0x{p-TEXT_V+x if False else p+TEXT_V:x} (0x{p+TEXT_V:x}) -> {key}")
