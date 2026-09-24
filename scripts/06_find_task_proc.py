# -*- coding: utf-8 -*-
import os
import re

execfile(os.path.join(os.environ.get("GITHUB_WORKSPACE", "/tmp"),
                     "scripts", "00_load_symbols.py"))

WORKSPACE = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WORKSPACE, "nk_task_proc.txt")

STRUCT_SYMS = [
    "_allproc", "_kernproc", "_nprocs",
    "_proc_task", "_proc_pid", "_proc_ucred", "_proc_fd", "_proc_textvp",
    "_proc_ppid", "_proc_list_entry", "_proc_ro",
    "_kauth_cred_getuid", "_kauth_cred_getgid",
    "_cs_enforcement_disable", "_amfi_get_out_of_my_way",
    "_task_for_pid", "_get_task_ipcspace", "_task_map",
    "_vm_map_pmap", "_vm_map_lookup_entry",
    "_pmap_enter_options", "_pmap_expand",
    "_vnode_mount", "_rootvnode", "_kernel_map",
    "_vm_kernel_slide", "_gPhysBase", "_gVirtBase",
    "_host_priv_self", "_realhost",
    "_pmap_ro_zone_validate_element",
]

STRUCT_STRINGS = [
    "proc_task",
    "proc_ro",
    "proc_ro->task backref",
    "task_init",
    "task->map->pmap",
    "set_bsdtask_info",
    "swap_task_map",
    "p != kernproc",
    "so != NULL || p == kernproc",
    "pmap_ro_zone_validate_element",
    "zone_require failed: address not in a zone",
    "zalloc_ro_mut failed",
]

KNOWN_OFFSETS = [
    ("PROC_TASK_OFF",         0x10),
    ("PROC_PID_OFF",          0x68),
    ("PROC_UCRED_OFF",        0xd0),
    ("PROC_TEXTVP_OFF",       0xd8),
    ("PROC_RO_OFF",           0x18),
    ("TASK_VM_MAP_OFF",       0x28),
    ("TASK_IPC_SPACE_OFF",    0xd0),
    ("TASK_BSD_INFO_OFF",     0x390),
    ("TASK_PROC_RO_OFF",      0x3b0),
    ("UCRED_UID_OFF",         0x18),
    ("UCRED_RUID_OFF",        0x1c),
    ("UCRED_SVUID_OFF",       0x20),
    ("UCRED_GID_OFF",         0x24),
    ("UCRED_RGID_OFF",        0x28),
    ("UCRED_SVGID_OFF",       0x2c),
    ("VM_MAP_PMAP_OFF",       0x48),
    ("FILEDESC_OFILES_OFF",   0x00),
]

EXTRACT_FUNCS = [
    "proc_task", "proc_pid", "proc_ucred",
    "proc_ro_ref_task", "set_bsdtask_info",
]

lines = []
lines.append("=== TASK / PROC / UCRED OFFSETS ===")
lines.append("Program: " + currentProgram.getName())
lines.append("")

lines.append("--- SYMBOLS ---")
for sym in STRUCT_SYMS:
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
lines.append("--- STRINGS ---")
for ss in STRUCT_STRINGS:
    for saddr, sval in find_str_contains(ss)[:2]:
        xrefs = xrefs_to(saddr)
        lines.append("[+] {:<55} @ {}".format(repr(sval[:52]), fmt(saddr)))
        for xr in xrefs[:3]:
            f = func_at(xr)
            fname = f.getName() if f else "?"
            entry = 0
            if f:
                entry = int(f.getEntryPoint().getOffset()) & 0xFFFFFFFFFFFFFFFF
            lines.append("       xref @ {}  entry={}  func={}".format(
                fmt(xr), fmt(entry), fname))

lines.append("")
lines.append("--- STRUCT FIELD OFFSETS (static, verify on-device) ---")
for name, val in KNOWN_OFFSETS:
    lines.append("#define {:<35} 0x{:x}".format(name, val))

lines.append("")
lines.append("--- DECOMPILE OFFSET EXTRACTION ---")
pat = re.compile(r"\(([A-Za-z_][\w ]*\*)\)\s*\(\s*(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)")
for fname in EXTRACT_FUNCS:
    for a, n in syms_named(fname)[:1]:
        f = ensure_func(a)
        code = decompile(f)
        if not code:
            lines.append("[-] decompile failed: " + n)
            continue
        for m in pat.finditer(code):
            try:
                off = int(m.group(3), 0)
                if 0 < off < 0x1000:
                    lines.append("  {} @ {}  field+{:#x}  type={}".format(
                        n, fmt(a), off, m.group(1).strip()))
            except Exception:
                pass

write_lines(OUT, lines)
print("[+] 06_find_task_proc.py done -> " + OUT)