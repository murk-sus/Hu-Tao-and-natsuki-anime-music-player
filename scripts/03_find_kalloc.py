# -*- coding: utf-8 -*-
import os
import re

execfile(os.path.join(os.environ.get("GITHUB_WORKSPACE", "/tmp"),
                     "scripts", "00_load_symbols.py"))

WORKSPACE = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WORKSPACE, "nk_kalloc.txt")

KALLOC_SYMS = [
    "_kalloc_type_impl", "_kalloc_data_external", "_kalloc_ext",
    "_kalloc_large_external", "_kfree_type_impl", "_kfree_ext",
    "_zalloc_ext", "_zfree_ext", "_zone_create",
]

ZONE_STRINGS = [
    "necp_client", "necp_client_flow_registration",
    "necp_fd_data", "necp_session",
    "necp_kernel_socket_policy", "necp_arena_info",
    "early.kalloc", "data.kalloc", "kalloc.type.var",
    "ipc_entry", "ipc_kmsg", "task", "proc", "thread",
    "vm_map_entry", "vm_map_copy",
]

KNOWN = [
    ("NCC_RESULTS_LEN_OFF",  0x5a0),
    ("NCC_RESULTS_PTR_OFF",  0x5a8),
    ("NCC_FLOWS_ROOT_OFF",   0x4a0),
    ("NCC_REFCOUNT_OFF",     0x38),
    ("NCC_LOCK_OFF",         0x50),
    ("NCC_PID_OFF",          0x4c),
    ("NCC_FLAGS_OFF",        0x74),
    ("NCC_OWNER_PROC_OFF",   0x550),
    ("NCC_ALLOC_SIZE",       0x8000),
    ("NCF_PARENT_OFF",       0x88),
    ("NCF_RESULTS_HEAD_OFF", 0x90),
    ("NCF_RESULTS_PTR_OFF",  0xa8),
    ("NFR_ALLOC_SIZE",       0x2a0),
    ("NFR_RESULTS_PTR_OFF",  0x5a8),
]

lines = []
lines.append("=== KALLOC / ZONE OFFSETS ===")
lines.append("Program: " + currentProgram.getName())
lines.append("")

lines.append("--- KALLOC FUNCTIONS ---")
for sym in KALLOC_SYMS:
    a = sym_get(sym)
    if a:
        lines.append("[+] {:<45} {}".format(sym, fmt(a)))
        continue
    hits = syms_named(sym.lstrip("_"))
    if hits:
        for ha, hn in hits[:2]:
            lines.append("[+] {:<45} {}".format(hn, fmt(ha)))
    else:
        lines.append("[-] " + sym + " NOT_FOUND")

lines.append("")
lines.append("--- ZONE NAME STRINGS ---")
for zname in ZONE_STRINGS:
    results = find_str_contains(zname)
    for saddr, sval in results[:3]:
        xrefs = xrefs_to(saddr)
        lines.append("[+] str: {:<50} @ {}  xrefs={}".format(
            repr(sval[:48]), fmt(saddr), len(xrefs)))
        for xr in xrefs[:4]:
            f = func_at(xr)
            fname = f.getName() if f else "?"
            lines.append("       xref @ {}  func={}".format(fmt(xr), fname))

lines.append("")
lines.append("--- KNOWN NECP STRUCT OFFSETS ---")
for name, val in KNOWN:
    lines.append("#define {:<35} 0x{:x}".format(name, val))

write_lines(OUT, lines)
print("[+] 03_find_kalloc.py done -> " + OUT)