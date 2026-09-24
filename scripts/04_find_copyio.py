# -*- coding: utf-8 -*-
import os

execfile(os.path.join(os.environ.get("GITHUB_WORKSPACE", "/tmp"),
                     "scripts", "00_load_symbols.py"))

WORKSPACE = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WORKSPACE, "nk_copyio.txt")

COPY_SYMS = [
    "_copyin", "_copyout", "_copyinstr", "_copyoutstr",
    "_copyin_word", "_copyout_word",
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
        continue
    hits = syms_named(sym.lstrip("_"))
    if hits:
        for ha, hn in hits[:2]:
            lines.append("[+] {:<35} {}".format(hn, fmt(ha)))
    else:
        lines.append("[-] " + sym + " NOT_FOUND")

lines.append("")
lines.append("--- COPYIN/COPYOUT via string xrefs ---")
for cs in COPY_STRINGS:
    for saddr, sval in find_str_contains(cs)[:2]:
        xrefs = xrefs_to(saddr)
        lines.append("[+] str: {} @ {}".format(repr(sval[:60]), fmt(saddr)))
        for xr in xrefs[:4]:
            f = func_at(xr)
            fname = f.getName() if f else "?"
            entry = 0
            if f:
                entry = int(f.getEntryPoint().getOffset()) & 0xFFFFFFFFFFFFFFFF
            lines.append("       xref @ {}  entry={}  name={}".format(
                fmt(xr), fmt(entry), fname))

lines.append("")
lines.append("--- COPYIN/OUT symbol bodies ---")
seen = set()
for pat in ("copyin", "copyout"):
    for a, n in syms_named(pat):
        if a in seen:
            continue
        seen.add(a)
        f = func_at(a)
        if f is None:
            continue
        body = f.getBody()
        if body is None:
            continue
        lines.append("[+] {:<35} {}  body_size={}".format(
            n, fmt(a), body.getNumAddresses()))

write_lines(OUT, lines)
print("[+] 04_find_copyio.py done -> " + OUT)