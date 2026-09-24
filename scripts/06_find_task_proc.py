# -*- coding: utf-8 -*-
import os
import re

execfile(os.path.join(os.environ.get("GITHUB_WORKSPACE", "/tmp"),
                     "scripts", "00_load_symbols.py"))

WORKSPACE = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WORKSPACE, "nk_task_proc.txt")

STRING_ANCHORS = [
    "p != kernproc",
    "so != NULL || p == kernproc",
    "proc_task",
    "task_init @%s:%d",
    "proc_ro->task backref mismatch",
    "task->map->pmap",
    "set_bsdtask_info trying to set random bsd_info",
    "swap_task_map @%s:%d",
    "zone_require failed: address not in a zone",
    "zalloc_ro_mut failed",
    "pmap_ro_zone_validate_element",
]

SYMBOLS = [
    "_allproc", "_kernproc", "_nprocs",
    "_kauth_cred_getuid", "_kauth_cred_getgid",
    "_cs_enforcement_disable",
    "_task_for_pid", "_get_task_ipcspace",
    "_pmap_expand", "_pmap_enter_options",
    "_rootvnode", "_kernel_map",
    "_vm_kernel_slide",
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


def find_string_addr(s):
    a = find_str_exact(s)
    if a is not None:
        return a
    for a, _ in find_str_contains(s)[:1]:
        return a
    return None


lines = ["=== TASK / PROC / UCRED OFFSETS ===",
         "Program: " + currentProgram.getName(),
         ""]

# 1. прямые символы
lines.append("--- SYMBOLS (symbols.json / ghidra) ---")
for sym in SYMBOLS:
    a = sym_get(sym)
    if a:
        lines.append("[+] {:<45} {}".format(sym, fmt(a)))
        continue
    hits = syms_named(sym.lstrip("_"))
    if hits:
        for ha, hn in hits[:3]:
            lines.append("[+] {:<45} {}".format(hn, fmt(ha)))
    else:
        lines.append("[-] " + sym + " NOT_FOUND")

# 2. строки -> xref -> функции
lines.append("")
lines.append("--- STRING XREFS -> FUNCTIONS ---")
anchor_funcs = {}
for s in STRING_ANCHORS:
    sa = find_string_addr(s)
    if sa is None:
        lines.append("[-] string not found: " + repr(s[:60]))
        continue
    lines.append("[+] string {:<55} @ {}".format(repr(s[:52]), fmt(sa)))
    for xr in xrefs_to(sa):
        f = func_at(xr)
        if f is None:
            continue
        entry = int(f.getEntryPoint().getOffset()) & 0xFFFFFFFFFFFFFFFF
        fname = f.getName()
        lines.append("       xref @ {}  func @ {}  ({})".format(
            fmt(xr), fmt(entry), fname))
        anchor_funcs[fname] = entry

# 3. adrp-резолв глобалов внутри найденных функций
lines.append("")
lines.append("--- RESOLVED GLOBALS (adrp+ldr/add) ---")
resolved = set()
for fname, fentry in anchor_funcs.items():
    f = func_at(fentry)
    if f is None:
        continue
    for insn_addr, tgt, kind in resolve_adrp_pairs(f):
        if tgt in resolved:
            continue
        resolved.add(tgt)
        lines.append("  {} +{} -> {}  ({})".format(
            fname[:32], fmt(insn_addr), fmt(tgt), kind))

# 4. accessor-скан tiny-функций
lines.append("")
lines.append("--- ACCESSOR FUNCS (ldr x0,[x0,#N];ret) ---")
fm = currentProgram.getFunctionManager()
found_accessors = {}
for func in fm.getFunctions(True):
    body = func.getBody()
    if body is None:
        continue
    if body.getNumAddresses() > 12:
        continue
    insn = currentProgram.getListing().getInstructionAt(body.getMinAddress())
    if insn is None:
        continue
    if insn.getMnemonicString().lower() != "ldr":
        continue
    txt = insn.toString()
    if "[x0" not in txt:
        continue
    m = re.search(r"#0x([0-9a-fA-F]+)", txt)
    if not m:
        continue
    off = int(m.group(1), 16)
    if not (0 < off < 0x1000):
        continue
    nxt = insn.getNext()
    if nxt is None or nxt.getMnemonicString().lower() != "ret":
        continue
    found_accessors.setdefault(off, []).append(
        (int(func.getEntryPoint().getOffset()) & 0xFFFFFFFFFFFFFFFF,
         func.getName()))

for off in sorted(found_accessors.keys()):
    entries = found_accessors[off]
    lines.append("#define ACCESSOR_off_0x{:x}   ({} funcs)".format(off, len(entries)))
    for a, n in entries[:8]:
        lines.append("    {}  {}".format(fmt(a), n))

# 5. статические offset-хинты
lines.append("")
lines.append("--- STRUCT FIELD OFFSETS (static; verify) ---")
for name, val in KNOWN_OFFSETS:
    lines.append("#define {:<35} 0x{:x}".format(name, val))

# 6. декомпиляция найденных функций -> поля
lines.append("")
lines.append("--- DECOMPILED FIELD ACCESSES ---")
field_pat = re.compile(
    r"\(([A-Za-z_][\w \*]*)\*\)\s*\(\s*(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)")
done = set()
for fname, fentry in anchor_funcs.items():
    if fentry in done:
        continue
    done.add(fentry)
    f = func_at(fentry)
    code = decompile(f)
    if not code:
        continue
    hits = 0
    for m in field_pat.finditer(code):
        try:
            off = int(m.group(3), 0)
            if 0 < off < 0x1000:
                lines.append("  {} @ {}  field +{:#x}  type={}".format(
                    fname, fmt(fentry), off, m.group(1).strip()))
                hits += 1
        except Exception:
            pass
    if hits == 0:
        lines.append("  {} @ {}  (no field accesses)".format(fname, fmt(fentry)))

write_lines(OUT, lines)
print("[+] 06_find_task_proc.py done -> " + OUT)