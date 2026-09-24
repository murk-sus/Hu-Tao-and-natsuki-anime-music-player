# -*- coding: utf-8 -*-
import os
import re

execfile(os.path.join(os.environ.get("GITHUB_WORKSPACE","/tmp"), "scripts", "00_load_symbols.py"))

WORKSPACE = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WORKSPACE, "nk_copyio.txt")

COPY_SYMS = [
    "_copyin", "_copyout", "_copyinstr", "_copyoutstr",
    "_copyin_word", "_copyout_word",
    "copyin", "copyout", "copyinstr", "copyoutstr",
    "_memmove_phys", "_bcopy",
]

COPY_STRINGS = [
    "ipc_object_copyin_from_kernel",
    "ipc_object_copyout_dest",
    "ipc_right_copyin_check",
    "vm_map_copyout_internal",
]

lines = []
lines.append("=== COPYIN / COPYOUT OFFSETS ===")
lines.append("Program: " + currentProgram.getName())
lines.append("")

lines.append("--- COPY FUNCTIONS ---")
for sym in COPY_SYMS:
    a = sym_get(sym)
    if a:
        lines.append("[+] {:<35} {}".format(sym, fmt(a)))
    else:
        hits = syms_named(sym.lstrip("_"))
        found = False
        for ha, hn in hits[:2]:
            lines.append("[+] {:<35} {}".format(hn, fmt(ha)))
            found = True
        if not found:
            lines.append("[-] " + sym + " NOT_FOUND")

lines.append("")
lines.append("--- COPYIN/COPYOUT via string xrefs ---")

for cs in COPY_STRINGS:
    results = find_str_contains(cs)
    for saddr, sval in results[:2]:
        xrefs = xrefs_to(saddr)
        lines.append("[+] str: {} @ {}".format(repr(sval[:60]), fmt(saddr)))
        for xr in xrefs[:4]:
            f = func_at(xr)
            fname = f.getName() if f else "?"
            entry = int(f.getEntryPoint().getOffset()) & 0xFFFFFFFFFFFFFFFF if f else 0
            lines.append("       xref @ {}  entry={}  name={}".format(
                fmt(xr), fmt(entry), fname))

lines.append("")
lines.append("--- COPYIN/OUT PATTERNS (ARM64 scan) ---")

COPY_PAT_SYMS = []
for pat in ("copyin", "copyout"):
    COPY_PAT_SYMS += syms_named(pat)

for a, n in COPY_PAT_SYMS[:10]:
    f = func_at(a)
    if f is None:
        continue
    body = f.getBody()
    if body is None:
        continue
    sz = body.getNumAddresses()
    lines.append("[+] {:<35} {}  body_size={}".format(n, fmt(a), sz))

write_lines(OUT, lines)
print("[+] 04_find_copyio.py done -> " + OUT)
