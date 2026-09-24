# -*- coding: utf-8 -*-

import os
import re
import json

from ghidra.program.model.symbol import RefType
from ghidra.program.model.scalar import Scalar

WORKSPACE = os.environ.get("GITHUB_WORKSPACE", "/tmp")
SYSENT_OUT = os.path.join(WORKSPACE, "spectre_sysent.txt")
GADGETS_OUT = os.path.join(WORKSPACE, "spectre_gadgets.txt")
CANDIDATES_OUT = os.path.join(WORKSPACE, "spectre_candidates.txt")
STRINGS_OUT = os.path.join(WORKSPACE, "spectre_strings.txt")
PACS_OUT = os.path.join(WORKSPACE, "spectre_pac.txt")

DECOM_TIMEOUT = 120
MAX_GADGETS = 8000
MAX_CANDIDATES = 400

SYSENT_SYMBOL_VARIANTS = [
    "_sysent", "sysent", "unix_sysent", "unix_sysent_table",
    "_unix_sysent", "_unix_sysent_table", "sysent_table",
    "_sysent_table", "bsd_syscall_table", "_bsd_syscall_table",
    "nsysent", "_nsysent",
]

SYSCALL_NAME_STRINGS = [
    "nosys", "exit", "fork", "read", "write", "open", "close",
    "getpid", "necp_open", "necp_client_action",
    "necp_session_open", "necp_session_action",
    "syscall", "workq_open", "workq_kernreturn",
]

SYSCALL_ENTRY_SIZE = 16

INDEX_REGS = [
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
    "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7",
    "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
    "w8", "w9", "w10", "w11", "w12", "w13", "w14", "w15",
    "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
    "w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23",
]

IDX_LOAD_MNEM = (
    "ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw",
    "ldur", "ldurb", "ldurh", "ldursb", "ldursh", "ldursw",
)

BRANCH_IND = ("blr", "br", "braa", "brab", "blraa", "blrab", "ret", "retaa", "retab")

SB_BARRIERS = ("sb", "csdb", "ssbb", "pssbb", "dsb", "isb", "dmb")

KVA_LO = 0xFFFFFFF000000000
KVA_HI = 0xFFFFFFF200000000

NEEDLES = [
    "syscall", "sysent", "unix_sys", "necp", "dispatch",
    "handler", "spectre", "barrier", "sb", "csdb",
    "pac", "autia", "autib", "xpaci", "ptrauth",
    "kalloc", "zone", "ipc", "task", "proc",
]


def fmt_hex(v):
    return "0x{:016X}".format(v & 0xFFFFFFFFFFFFFFFF)


def to_java_long(v):
    v = int(v) & 0xFFFFFFFFFFFFFFFF
    if v >= 0x8000000000000000:
        v -= 0x10000000000000000
    return v


def safe_addr(a):
    try:
        return toAddr(to_java_long(a))
    except Exception:
        return None


def to_unsigned(v):
    return int(v) & 0xFFFFFFFFFFFFFFFF


def ensure_func(a):
    ga = safe_addr(a)
    if ga is None:
        return None
    try:
        f = getFunctionAt(ga)
        if f:
            return f
    except Exception:
        pass
    try:
        f = getFunctionContaining(ga)
        if f:
            return f
    except Exception:
        pass
    try:
        disassemble(ga)
    except Exception:
        pass
    try:
        return createFunction(ga, None)
    except Exception:
        return None


def decompile(f):
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.util.task import ConsoleTaskMonitor
    ifc = DecompInterface()
    ifc.setOptions(DecompileOptions())
    ifc.openProgram(currentProgram)
    r = ifc.decompileFunction(f, DECOM_TIMEOUT, ConsoleTaskMonitor())
    if not r.decompileCompleted():
        return ""
    return r.getDecompiledFunction().getC()


def symbol_address(name):
    st = currentProgram.getSymbolTable()
    try:
        for sym in st.getAllSymbols(True):
            if sym.getName() == name:
                return to_unsigned(sym.getAddress().getOffset())
    except Exception:
        pass
    return None


def find_symbols_by_pattern(pattern):
    out = []
    st = currentProgram.getSymbolTable()
    try:
        for sym in st.getAllSymbols(True):
            if pattern in sym.getName():
                out.append((to_unsigned(sym.getAddress().getOffset()), sym.getName()))
    except Exception:
        pass
    return out


def find_string_addr(s):
    listing = currentProgram.getListing()
    it = listing.getDefinedData(True)
    while it.hasNext():
        d = it.next()
        try:
            if d.hasStringValue() and str(d.getValue()) == s:
                return to_unsigned(d.getAddress().getOffset())
        except Exception:
            pass
    return None


def find_data_xrefs_to(addr):
    out = []
    ga = safe_addr(addr)
    if ga is None:
        return out
    rm = currentProgram.getReferenceManager()
    try:
        for r in rm.getReferencesTo(ga):
            if r.getReferenceType() in (RefType.DATA, RefType.DATA_IND, RefType.READ):
                out.append(to_unsigned(r.getFromAddress().getOffset()))
    except Exception:
        pass
    return out


def read_qword_safe(a):
    ga = safe_addr(a)
    if ga is None:
        return None
    try:
        return to_unsigned(currentProgram.getMemory().getLong(ga))
    except Exception:
        return None


def read_dword_safe(a):
    ga = safe_addr(a)
    if ga is None:
        return None
    try:
        return to_unsigned(currentProgram.getMemory().getInt(ga))
    except Exception:
        return None


def read_word_safe(a):
    ga = safe_addr(a)
    if ga is None:
        return None
    try:
        return to_unsigned(currentProgram.getMemory().getShort(ga))
    except Exception:
        return None


def looks_like_sysent(a, kva_lo=KVA_LO, kva_hi=KVA_HI):
    ptr = read_qword_safe(a)
    if ptr is None:
        return False
    if ptr < kva_lo or ptr >= kva_hi:
        return False
    hits = 0
    for k in range(8):
        p = read_qword_safe(a + k * SYSCALL_ENTRY_SIZE)
        if p is not None and kva_lo <= p < kva_hi:
            hits += 1
    return hits >= 6


def find_sysent_by_symbols():
    found = []
    for n in SYSENT_SYMBOL_VARIANTS:
        a = symbol_address(n)
        if a is not None:
            found.append((a, n))
    for pat in ("sysent", "syscall_table", "bsd_syscall"):
        for a, name in find_symbols_by_pattern(pat):
            found.append((a, name))
    uniq = {}
    for a, n in found:
        uniq[a] = n
    return sorted(uniq.items())


def find_sysent_via_unix_syscall():
    targets = ["unix_syscall", "unix_syscall64", "unix_syscall_return",
               "unix_syscall32", "mach_syscall", "mach_syscall64"]
    for name in targets:
        addr = symbol_address(name)
        if addr is None:
            continue
        f = ensure_func(addr)
        if f is None:
            continue
        insn = getInstructionAt(safe_addr(addr))
        if insn is None:
            continue
        cnt = 0
        while insn is not None and cnt < 20000:
            mnem = insn.getMnemonicString().lower()
            if mnem in ("adrp", "add", "ldr", "adr"):
                text = insn.toString()
                for m in re.finditer(r"0x([0-9a-fA-F]{6,16})", text):
                    try:
                        cand = int(m.group(1), 16)
                        cand &= 0xFFFFFFFFFFFFFFFF
                        if KVA_LO <= cand < KVA_HI:
                            if looks_like_sysent(cand):
                                return cand, "unix_syscall"
                    except Exception:
                        pass
            insn = insn.getNext()
            cnt += 1
    return None, None


def walk_sysent_table(table_addr):
    entries = []
    for i in range(1024):
        a = table_addr + i * SYSCALL_ENTRY_SIZE
        ptr = read_qword_safe(a)
        if ptr is None:
            break
        if ptr == 0:
            continue
        if (ptr >> 48) != 0xFFFF:
            continue
        handler = ptr & 0x0000FFFFFFFFFFFF
        if handler < KVA_LO or handler > KVA_HI:
            continue
        name = "?"
        try:
            f = getFunctionAt(safe_addr(handler))
            if f is not None:
                name = f.getName()
        except Exception:
            pass
        narg = read_dword_safe(a + 8)
        if narg is None:
            narg = 0
        entries.append((i, handler, name, narg))
    return entries


def find_sysent_via_strings():
    str_addr = None
    found_name = None
    for s in SYSCALL_NAME_STRINGS:
        a = find_string_addr(s)
        if a is not None:
            found_name = s
            str_addr = a
            break
    if str_addr is None:
        return None, None

    xrefs = find_data_xrefs_to(str_addr)
    if not xrefs:
        return None, None
    xrefs.sort()
    ptr_cell = xrefs[0]

    best = None
    for off in range(64, 0x40000, 8):
        cand = ptr_cell - off
        if cand < KVA_LO:
            break
        if looks_like_sysent(cand):
            best = cand
            break
    if best is None:
        return None, None
    return best, found_name


def find_sysent_table():
    found = find_sysent_by_symbols()
    if found:
        return found[0][0], found[0][1]

    a, n = find_sysent_via_unix_syscall()
    if a is not None:
        return a, n

    a, n = find_sysent_via_strings()
    if a is not None:
        return a, "syscallnames"

    return None, None


def scan_strings():
    result = {}
    listing = currentProgram.getListing()
    it = listing.getDefinedData(True)
    while it.hasNext():
        d = it.next()
        try:
            if d.hasStringValue():
                v = d.getValue()
                if v is not None:
                    result[str(v)] = to_unsigned(d.getAddress().getOffset())
        except Exception:
            pass
    return result


def parse_indexed_load(text):
    t = text.replace("\t", " ").strip()
    low = t.lower()
    if not any(low.startswith(m + " ") for m in IDX_LOAD_MNEM):
        return None
    if "[" not in t or "]" not in t:
        return None
    inner = t[t.find("[") + 1:t.find("]")]
    parts = [p.strip() for p in inner.split(",")]
    if len(parts) < 2:
        return None
    base = parts[0].split()[0].lower()
    idx = parts[1].split()[0].lower()
    scale = 1
    if len(parts) >= 3 and "lsl" in parts[2].lower():
        try:
            scale = 1 << int(parts[2].split("#")[1])
        except Exception:
            pass
    return base, idx, scale


def is_cond_branch(mnem):
    if mnem in ("cbz", "cbnz", "tbz", "tbnz"):
        return True
    if mnem.startswith("b."):
        return True
    return False


def find_branch_after(insn, window=8):
    cur = insn.getNext()
    n = 0
    while cur is not None and n < window:
        mnem = cur.getMnemonicString().lower()
        if mnem in BRANCH_IND:
            return cur, True
        if mnem == "ret":
            return cur, True
        if is_cond_branch(mnem):
            return cur, False
        cur = cur.getNext()
        n += 1
    return None, False


def has_barrier_between(start_insn, end_addr, limit=16):
    cur = start_insn.getNext()
    n = 0
    while cur is not None and n < limit:
        if to_unsigned(cur.getAddress().getOffset()) >= end_addr:
            break
        if cur.getMnemonicString().lower() in SB_BARRIERS:
            return True
        cur = cur.getNext()
        n += 1
    return False


def score_gadget(load_insn, branch_insn, barrier, is_syscall, scale):
    s = 0
    if barrier:
        s -= 30
    if is_syscall:
        s += 20
    if branch_insn is None:
        return 0
    mnem = branch_insn.getMnemonicString().lower()
    if mnem in BRANCH_IND:
        s += 15
    elif is_cond_branch(mnem):
        s += 8
    if scale == 8:
        s += 5
    if scale in (1, 4, 16):
        s += 3
    return s


def scan_function_for_gadgets(func, syscall_addrs):
    entry = to_unsigned(func.getEntryPoint().getOffset())
    listing = currentProgram.getListing()
    body = func.getBody()
    if body is None:
        return []
    insn = listing.getInstructionAt(body.getMinAddress())
    if insn is None:
        return []
    results = []
    limit = 100000
    cnt = 0
    is_syscall = entry in syscall_addrs
    while insn is not None and body.contains(insn.getAddress()) and cnt < limit:
        text = insn.toString()
        parsed = parse_indexed_load(text)
        if parsed is not None:
            base, idx, scale = parsed
            if idx in INDEX_REGS:
                br, is_ind = find_branch_after(insn, window=8)
                if br is not None:
                    barrier = has_barrier_between(
                        insn, to_unsigned(br.getAddress().getOffset()))
                    score = score_gadget(insn, br, barrier, is_syscall, scale)
                    if score >= 8:
                        results.append({
                            "score": score,
                            "func": func.getName(),
                            "entry": entry,
                            "load_addr": to_unsigned(insn.getAddress().getOffset()),
                            "load_text": text.strip(),
                            "branch_addr": to_unsigned(br.getAddress().getOffset()),
                            "branch_text": br.toString().strip(),
                            "barrier": barrier,
                            "syscall": is_syscall,
                            "is_indirect": is_ind,
                            "scale": scale,
                        })
        insn = insn.getNext()
        cnt += 1
    return results


def scan_all_functions(syscall_addrs, sysent_entries):
    all_hits = []
    fm = currentProgram.getFunctionManager()
    it = fm.getFunctions(True)
    cnt = 0
    for f in it:
        cnt += 1
        if cnt % 500 == 0:
            print("[*] scanned {} functions...".format(cnt))
        hits = scan_function_for_gadgets(f, syscall_addrs)
        for h in hits:
            for (i, handler, name, narg) in sysent_entries:
                if handler == h["entry"]:
                    h["syscall_num"] = i
                    h["syscall_name"] = name
                    break
            all_hits.append(h)
        if len(all_hits) > MAX_GADGETS * 2:
            break
    return all_hits


def scan_pac_references():
    pac_out = []
    fm = currentProgram.getFunctionManager()
    it = fm.getFunctions(True)
    cnt = 0
    for f in it:
        cnt += 1
        if cnt % 2000 == 0:
            print("[*] pac scan {} funcs...".format(cnt))
        body = f.getBody()
        if body is None:
            continue
        insn = currentProgram.getListing().getInstructionAt(body.getMinAddress())
        n = 0
        while insn is not None and body.contains(insn.getAddress()) and n < 5000:
            mnem = insn.getMnemonicString().lower()
            if mnem in ("braa", "brab", "blraa", "blrab", "autia", "autib",
                        "paciza", "pacizb", "pacda", "pacdb", "xpaci", "xpacd"):
                pac_out.append({
                    "func": f.getName(),
                    "addr": to_unsigned(insn.getAddress().getOffset()),
                    "text": insn.toString().strip(),
                })
            insn = insn.getNext()
            n += 1
        if len(pac_out) > 200000:
            break
    return pac_out


def dump_sysent(entries, output):
    output.write("\n=== SYSENT TABLE ({} entries) ===\n".format(len(entries)))
    output.write("{:<6} {:<20} {:<40} {}\n".format("NUM", "HANDLER", "NAME", "NARG"))
    output.write("-" * 90 + "\n")
    for i, handler, name, narg in entries:
        output.write("{:<6} {} {:<40} {}\n".format(
            i, fmt_hex(handler), name, narg))


def main():
    print("[*] program: " + currentProgram.getName())

    strings = scan_strings()

    sysent_addr, sysent_name = find_sysent_table()
    sysent_entries = []
    if sysent_addr is not None:
        print("[*] sysent found: {} @ {}".format(sysent_name, fmt_hex(sysent_addr)))
        sysent_entries = walk_sysent_table(sysent_addr)
        print("[*] sysent entries: {}".format(len(sysent_entries)))
    else:
        print("[!] sysent symbol not found; scanning all functions only")

    syscall_addrs = set()
    for (i, handler, name, narg) in sysent_entries:
        syscall_addrs.add(handler)

    print("[*] scanning functions for spectre gadgets...")
    all_hits = scan_all_functions(syscall_addrs, sysent_entries)
    print("[*] raw gadget hits: {}".format(len(all_hits)))

    seen = set()
    deduped = []
    for h in all_hits:
        key = (h["entry"], h["load_addr"], h["branch_addr"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(h)
    deduped.sort(key=lambda x: -x["score"])
    print("[*] deduped gadgets: {}".format(len(deduped)))

    print("[*] scanning pac references...")
    pac_hits = scan_pac_references()
    print("[*] pac hits: {}".format(len(pac_hits)))

    with open(SYSENT_OUT, "w") as f:
        f.write("=== SYSENT TABLE ===\n")
        f.write("Program: {}\n".format(currentProgram.getName()))
        f.write("sysent symbol: {}\n".format(sysent_name or "(not found)"))
        f.write("sysent addr: {}\n".format(fmt_hex(sysent_addr) if sysent_addr else "n/a"))
        dump_sysent(sysent_entries, f)

    with open(GADGETS_OUT, "w") as f:
        f.write("=== SPECTRE-LIKE GADGETS ===\n")
        f.write("Program: {}\n".format(currentProgram.getName()))
        f.write("Total: {}\n\n".format(len(deduped)))
        for h in deduped:
            f.write("--- score={} func={} entry={} ---\n".format(
                h["score"], h["func"], fmt_hex(h["entry"])))
            f.write("  load:    {} @ {}\n".format(h["load_text"], fmt_hex(h["load_addr"])))
            f.write("  branch:  {} @ {}\n".format(h["branch_text"], fmt_hex(h["branch_addr"])))
            f.write("  barrier: {}   syscall: {}   scale: {}\n".format(
                h["barrier"], h["syscall"], h["scale"]))
            if "syscall_num" in h:
                f.write("  syscall_num: {} name={}\n".format(
                    h["syscall_num"], h["syscall_name"]))
            f.write("\n")

    with open(CANDIDATES_OUT, "w") as f:
        f.write("=== TOP CANDIDATES (score >= 15) ===\n")
        f.write("{:<8} {:<6} {:<20} {:<40} {:<40}\n".format(
            "SCORE", "SYSNUM", "FUNC", "LOAD", "BRANCH"))
        f.write("-" * 130 + "\n")
        for h in deduped:
            if h["score"] < 15:
                continue
            f.write("{:<8} {:<6} {:<20} {:<40} {:<40}\n".format(
                h["score"],
                h.get("syscall_num", "-"),
                h["func"][:20],
                h["load_text"][:40],
                h["branch_text"][:40]))
        f.write("\n=== RAW JSON ===\n")
        f.write(json.dumps(deduped[:MAX_CANDIDATES], indent=2, default=str))

    with open(STRINGS_OUT, "w") as f:
        f.write("=== SYSCALL-RELATED STRINGS ===\n")
        for s, a in sorted(strings.items(), key=lambda x: x[1]):
            low = s.lower()
            if any(p in low for p in NEEDLES):
                f.write("  {}  \"{}\"\n".format(fmt_hex(a), s))

    with open(PACS_OUT, "w") as f:
        f.write("=== PAC REFERENCES ===\n")
        f.write("Program: {}\n".format(currentProgram.getName()))
        f.write("Total: {}\n\n".format(len(pac_hits)))
        for h in pac_hits[:100000]:
            f.write("{}  {}  {}\n".format(fmt_hex(h["addr"]), h["func"], h["text"]))

    print("[*] wrote: " + SYSENT_OUT)
    print("[*] wrote: " + GADGETS_OUT)
    print("[*] wrote: " + CANDIDATES_OUT)
    print("[*] wrote: " + STRINGS_OUT)
    print("[*] wrote: " + PACS_OUT)


main()
