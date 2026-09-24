# -*- coding: utf-8 -*-
import os
import re

execfile(os.path.join(os.environ.get("GITHUB_WORKSPACE", "/tmp"),
                     "scripts", "00_load_symbols.py"))

WORKSPACE = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT      = os.path.join(WORKSPACE, "nk_sysent.txt")
ANCHOR_H = os.path.join(WORKSPACE, "nk_anchors.h")

STRIDE = 16


def looks_like_sysent(base, need=16):
    if not is_kva(base):
        return False
    hits = 0
    for i in range(need):
        p = read_u64(base + i * STRIDE)
        if not is_kva(p):
            continue
        n = read_u32(base + i * STRIDE + 8)
        if n is not None and n <= 32:
            hits += 1
    return hits >= need - 2


def walk_sysent(base, limit=800):
    entries = []
    for i in range(limit):
        a = base + i * STRIDE
        p = read_u64(a)
        if not is_kva(p):
            break
        narg = read_u32(a + 8) or 0
        f = func_at(p)
        name = f.getName() if f else "?"
        entries.append((i, p, narg, name))
    return entries


sysent_base = None
sysent_source = "NOT_FOUND"

# 1. symbols.json
for sym_name in ("_sysent", "sysent", "_unix_sysent", "unix_sysent",
                 "_unix_sysent_table"):
    a = sym_get(sym_name)
    if a and looks_like_sysent(a):
        sysent_base = a
        sysent_source = "sym:" + sym_name
        break

# 2. ghidra symtable
if sysent_base is None:
    for a, n in syms_named("sysent"):
        if looks_like_sysent(a):
            sysent_base = a
            sysent_source = "ghidra:" + n
            break

# 3. disasm unix_syscall* -> adrp-резолв
if sysent_base is None:
    for name in ("unix_syscall64", "unix_syscall", "unix_syscall_return",
                 "mach_syscall64", "mach_syscall"):
        for a, n in funcs_named(name):
            f = ensure_func(a)
            if f is None:
                continue
            for insn_addr, tgt, kind in resolve_adrp_pairs(f):
                if looks_like_sysent(tgt, 20):
                    sysent_base = tgt
                    sysent_source = n + "_adrp"
                    break
            if sysent_base:
                break
        if sysent_base:
            break

# 4. скан __DATA / __DATA_CONST блоков
if sysent_base is None:
    print("[*] scanning data blocks for sysent...")
    mem = currentProgram.getMemory()
    for block in mem.getBlocks():
        if not block.isInitialized():
            continue
        s = block.getStart().getOffset() & 0xFFFFFFFFFFFFFFFF
        e = block.getEnd().getOffset() & 0xFFFFFFFFFFFFFFFF
        if not (0xFFFFFFF000000000 <= s < 0xFFFFFFF200000000):
            continue
        bname = block.getName().upper()
        if "DATA" not in bname and "CONST" not in bname:
            continue
        print("[*]   scan block {} {} - {}".format(
            block.getName(), fmt(s), fmt(e)))
        a = s & ~0x7
        while a + STRIDE * 100 < e:
            p0 = read_u64(a)
            if not is_kva(p0):
                a += 8
                continue
            p1 = read_u64(a + STRIDE)
            p2 = read_u64(a + STRIDE * 2)
            if not (is_kva(p1) and is_kva(p2)):
                a += 8
                continue
            ok = 0
            for i in range(100):
                p = read_u64(a + i * STRIDE)
                if is_kva(p):
                    n = read_u32(a + i * STRIDE + 8)
                    if n is not None and n <= 32:
                        ok += 1
            if ok >= 95:
                sysent_base = a
                sysent_source = "scan:" + block.getName()
                break
            a += 16
        if sysent_base:
            break

entries = walk_sysent(sysent_base) if sysent_base else []
print("[+] sysent source: " + sysent_source)
print("[+] sysent base:   " + (fmt(sysent_base) if sysent_base else "n/a"))
print("[+] sysent entries:" + str(len(entries)))

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

anchors = ["#ifndef NK_ANCHORS_H", "#define NK_ANCHORS_H", "",
           "#define NK_KERNEL_UNSLID_BASE  0xFFFFFFF007004000ULL"]
if sysent_base:
    anchors.append("#define NK_SYSENT_BASE         " + fmt(sysent_base) + "ULL")
for i, handler, narg, name in entries:
    if (not name or name == "?" or name.startswith("FUN_")
            or name.startswith("s_")):
        continue
    key = re.sub(r"[^A-Za-z0-9_]", "_", name).upper()
    anchors.append("#define NK_SYSENT_{:<40} {} /* #{} narg={} */".format(
        key, fmt(handler) + "ULL", i, narg))
anchors += ["", "#endif"]
write_lines(ANCHOR_H, anchors)

print("[+] 02_find_sysent.py done -> " + OUT)