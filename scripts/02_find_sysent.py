# -*- coding: utf-8 -*-
import os
import re

execfile(os.path.join(os.environ.get("GITHUB_WORKSPACE", "/tmp"),
                     "scripts", "00_load_symbols.py"))

WORKSPACE = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT      = os.path.join(WORKSPACE, "nk_sysent.txt")
ANCHOR_H = os.path.join(WORKSPACE, "nk_anchors.h")

SYSCALL_ENTRY_SIZE = 16


def looks_like_sysent(base, min_hits=10):
    if base is None or not is_kva(base):
        return False
    hits = 0
    for i in range(20):
        p = read_u64(base + i * SYSCALL_ENTRY_SIZE)
        if is_kva(p):
            hits += 1
    return hits >= min_hits


def walk_sysent(base, limit=800):
    entries = []
    for i in range(limit):
        a = base + i * SYSCALL_ENTRY_SIZE
        p = read_u64(a)
        if not is_kva(p):
            break
        narg = read_u32(a + 8)
        if narg is None or narg > 64:
            narg = 0
        name = "?"
        f = func_at(p)
        if f:
            name = f.getName()
        entries.append((i, p, narg, name))
    return entries


# ---- locate sysent ----

sysent_base = None
sysent_source = "NOT_FOUND"

# 1) via symbols.json
for sym_name in ("_sysent", "sysent", "_unix_sysent", "unix_sysent",
                 "_unix_sysent_table"):
    a = sym_get(sym_name)
    if a and looks_like_sysent(a):
        sysent_base = a
        sysent_source = "sym:" + sym_name
        break

# 2) via Ghidra symtable
if sysent_base is None:
    for pat in ("sysent", "unix_sysent"):
        for a, n in syms_named(pat):
            if looks_like_sysent(a):
                sysent_base = a
                sysent_source = "ghidra:" + n
                break
        if sysent_base:
            break

# 3) via disasm of unix_syscall[64] — look for KVA literals that look like sysent
if sysent_base is None:
    for name in ("unix_syscall64", "unix_syscall",
                 "_unix_syscall64", "_unix_syscall"):
        for a, n in syms_named(name):
            f = ensure_func(a)
            if f is None:
                continue
            body = f.getBody()
            if body is None:
                continue
            listing = currentProgram.getListing()
            insn = listing.getInstructionAt(body.getMinAddress())
            cnt = 0
            while insn is not None and body.contains(insn.getAddress()) and cnt < 20000:
                text = insn.toString()
                for m in re.finditer(r"0x([0-9a-fA-F]{8,16})", text):
                    try:
                        cand = int(m.group(1), 16) & 0xFFFFFFFFFFFFFFFF
                        if is_kva(cand) and looks_like_sysent(cand, 12):
                            sysent_base = cand
                            sysent_source = n + "_disasm"
                            break
                    except Exception:
                        pass
                if sysent_base:
                    break
                insn = insn.getNext()
                cnt += 1
            if sysent_base:
                break
        if sysent_base:
            break

entries = walk_sysent(sysent_base) if sysent_base else []
print("[+] sysent source: " + sysent_source)
print("[+] sysent base: " + (fmt(sysent_base) if sysent_base else "n/a"))
print("[+] sysent entries: " + str(len(entries)))

# ---- dump ----

lines = []
lines.append("=== SYSENT TABLE ===")
lines.append("Program: " + currentProgram.getName())
lines.append("sysent source: " + sysent_source)
lines.append("sysent addr: " + (fmt(sysent_base) if sysent_base else "n/a"))
lines.append("entries: " + str(len(entries)))
lines.append("")
lines.append("{:<6} {:<20} {:<5} {}".format("NUM", "HANDLER", "NARG", "NAME"))
lines.append("-" * 80)
for i, handler, narg, name in entries:
    lines.append("{:<6} {} {:<5} {}".format(i, fmt(handler), narg, name))
write_lines(OUT, lines)

# ---- anchors.h ----

anchors = []
anchors.append("#ifndef NK_ANCHORS_H")
anchors.append("#define NK_ANCHORS_H")
anchors.append("")
anchors.append("#define NK_KERNEL_UNSLID_BASE  0xFFFFFFF007004000ULL")
if sysent_base:
    anchors.append("#define NK_SYSENT_BASE         " + fmt(sysent_base) + "ULL")
for i, handler, narg, name in entries:
    if name and name != "?" and not name.startswith("FUN_"):
        key = re.sub(r"[^A-Za-z0-9_]", "_", name).upper()
        anchors.append("#define NK_SYSENT_{:<40} {} /* #{} narg={} */".format(
            key, fmt(handler) + "ULL", i, narg))
anchors.append("")
anchors.append("#endif")
write_lines(ANCHOR_H, anchors)

print("[+] 02_find_sysent.py done -> " + OUT)