# -*- coding: utf-8 -*-
import os
import re

execfile(os.path.join(os.environ.get("GITHUB_WORKSPACE","/tmp"), "scripts", "00_load_symbols.py"))

WORKSPACE = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT       = os.path.join(WORKSPACE, "nk_sysent.txt")
ANCHOR_H  = os.path.join(WORKSPACE, "nk_anchors.h")

SYSCALL_ENTRY_SIZE = 16

def looks_like_sysent(base, min_hits=10):
    hits = 0
    for i in range(20):
        p = read_u64(base + i * SYSCALL_ENTRY_SIZE)
        if is_kva(p):
            hits += 1
    return hits >= min_hits

def walk_sysent(base, limit=600):
    entries = []
    for i in range(limit):
        a = base + i * SYSCALL_ENTRY_SIZE
        p = read_u64(a)
        if not is_kva(p):
            break
        narg = read_u32(a + 8)
        if narg is None or narg > 32:
            break
        name = "?"
        f = func_at(p)
        if f:
            name = f.getName()
        entries.append((i, p, narg, name))
    return entries

sysent_base = None
sysent_source = "NOT_FOUND"

for sym_name in ("_sysent", "sysent", "_unix_sysent", "unix_sysent"):
    a = sym_get(sym_name)
    if a and looks_like_sysent(a):
        sysent_base = a
        sysent_source = sym_name
        break

if sysent_base is None:
    for name in ("unix_syscall64", "unix_syscall", "_unix_syscall64"):
        hits = syms_named(name)
        for a, n in hits[:2]:
            f = ensure_func(a)
            if f is None:
                continue
            body = f.getBody()
            if body is None:
                continue
            insn = currentProgram.getListing().getInstructionAt(body.getMinAddress())
            cnt = 0
            while insn and body.contains(insn.getAddress()) and cnt < 30000:
                for m in re.finditer(r"0x([0-9a-fA-F]{8,16})", insn.toString()):
                    try:
                        cand = int(m.group(1), 16) & 0xFFFFFFFFFFFFFFFF
                        if is_kva(cand) and looks_like_sysent(cand):
                            sysent_base = cand
                            sysent_source = n + "_disasm"
                    except Exception:
                        pass
                if sysent_base:
                    break
                insn = insn.getNext()
                cnt += 1
            if sysent_base:
                break
    if sysent_base:
        print("[+] sysent found via " + sysent_source + " @ " + fmt(sysent_base))

if sysent_base is None:
    for needle in ("exit", "fork", "read", "write"):
        saddr = find_str_exact(needle)
        if saddr is None:
            continue
        for ref in xrefs_to(saddr)[:8]:
            for back in range(0, 200):
                cand = ref - back * 8
                if cand < 0xFFFFFFF000000000:
                    break
                for delta in range(0, 0x200000, SYSCALL_ENTRY_SIZE):
                    base_cand = cand - delta
                    if base_cand < 0xFFFFFFF000000000:
                        break
                    if looks_like_sysent(base_cand, 12):
                        sysent_base = base_cand
                        sysent_source = "string_xref:" + needle
                        break
                if sysent_base:
                    break
            if sysent_base:
                break

entries = walk_sysent(sysent_base) if sysent_base else []

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

anchors = []
anchors.append("#ifndef NK_ANCHORS_H")
anchors.append("#define NK_ANCHORS_H")
anchors.append("")
anchors.append("#define NK_KERNEL_UNSLID_BASE  0xFFFFFFF007004000ULL")
if sysent_base:
    anchors.append("#define NK_SYSENT_BASE         " + fmt(sysent_base) + "ULL")
for i, handler, narg, name in entries:
    if name and name != "?":
        key = re.sub(r"[^A-Za-z0-9_]", "_", name).upper()
        anchors.append("#define NK_SYSENT_{:<40} {} /* #{} */".format(key, fmt(handler) + "ULL", i))
anchors.append("")
anchors.append("#endif")
write_lines(ANCHOR_H, anchors)

print("[+] 02_find_sysent.py done -> " + OUT)
