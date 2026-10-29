#!/usr/bin/env python3
# Copyright (c) 2026 haasanen — SPDX-License-Identifier: GPL-3.0-only
"""disasm-context v2 — capstone slice disassembly with exact RIP-relative string
annotation (uses operand detail, not byte heuristics).

vaddr == file offset for the first LOAD segment of this DSO (verified).
Usage: disasm-context.py [--start ADDR] [--len N] ADDR [ADDR ...]
"""
import sys, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_REG_RIP

PATH = "/opt/data/notes/mcpelauncher/versions/1.26.52.3/lib/x86_64/libminecraftpe.so"
TEXT_START, TEXT_SIZE = 0x6878940, 0x1036C405
TEXT_END = TEXT_START + TEXT_SIZE

# segments where vaddr == file offset: first R+X LOAD [0, 0x16c997d0)
IDENT_MAX = 0x16C997D0

def read_at(f, vaddr, n):
    if 0 <= vaddr < IDENT_MAX:
        pos = f.tell()
        f.seek(vaddr)
        b = f.read(n)
        f.seek(pos)
        return b
    return b""

def cstring(f, vaddr):
    b = read_at(f, vaddr, 128)
    z = b.find(b"\0")
    if z <= 0:
        return None
    try:
        s = b[:z].decode("utf-8")
    except UnicodeDecodeError:
        return None
    return s if 3 < len(s) < 120 and s.isprintable() else None

PROLOGS = (b"\x55\x48\x89\xe5", b"\x41\x56\x41\x55\x41\x54\x53", b"\x41\x55\x41\x54\x53",
           b"\x55\x48\x8b\xec", b"\x53\x48\x83\xec", b"\x56\x57\x53\x48", b"\x55\x53\x48\x83",
           b"\x56\x48\x83\xec", b"\x53\x48\x81\xec", b"\x57\x56\x55\x48", b"\x55\x48\x83\xec",
           b"\x56\x53\x48\x83", b"\x57\x48\x83\xec", b"\x55\x41\x56\x41", b"\x41\x57\x41\x56",
           b"\x55\x41\x57\x41\x56", b"\x56\x41\x57\x41\x56", b"\x55\x41\x55\x41\x56")

def find_start(f, a):
    for back in range(0, 0x400):
        probe = a - back
        head = read_at(f, probe, 16)
        if any(head.startswith(p) for p in PROLOGS):
            prev = read_at(f, probe - 1, 1)
            if prev in (b"\xcc", b"\x00", b"\x90") or probe == TEXT_START:
                return probe
    return max(a - 0x40, TEXT_START)

def main():
    argv = sys.argv[1:]
    span_over = 0
    if argv[:1] == ["--len"]:
        span_over = int(argv[1], 16) or int(argv[1]); argv = argv[2:]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    with open(PATH, "rb") as f:
        for a in (int(x, 16) for x in argv):
            if not (TEXT_START <= a < TEXT_END):
                print(f"0x{a:x}: outside .text, skipped"); continue
            start = find_start(f, a)
            n = span_over if span_over else min(0x60 + (a - start) + 0x40, 0x1400)
            code = read_at(f, start, n)
            print(f"\n=== xref 0x{a:x} — function start guess 0x{start:x} ({a - start} bytes in)")
            for ins in md.disasm(code, start):
                ann = ""
                for op in ins.operands:
                    if op.type == 3 and op.mem.base == X86_REG_RIP:   # CS_OP_MEM
                        tgt = ins.address + ins.size + op.mem.disp
                        s = cstring(f, tgt)
                        if s:
                            ann += f"   ; -> {s!r}"
                        elif tgt >= IDENT_MAX:
                            ann += f"   ; -> 0x{tgt:x} (data seg)"
                mark = "   <== xref" if ins.address <= a < ins.address + ins.size else ""
                print(f"  0x{ins.address:x}: {ins.mnemonic}\t{ins.op_str}{ann}{mark}")

if __name__ == "__main__":
    main()
