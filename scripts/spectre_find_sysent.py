# -*- coding: utf-8 -*-

import os
import re
import json

WORKSPACE = os.environ.get("GITHUB_WORKSPACE", "/tmp")
SYSENT_OUT = os.path.join(WORKSPACE, "spectre_sysent.txt")
GADGETS_OUT = os.path.join(WORKSPACE, "spectre_gadgets.txt")
CANDIDATES_OUT = os.path.join(WORKSPACE, "spectre_candidates.txt")
STRINGS_OUT = os.path.join(WORKSPACE, "spectre_strings.txt")

DECOM_TIMEOUT = 120
MAX_GADGETS = 500
MAX_CANDIDATES = 200

SYSENT_SYMBOLS = [
    "_sysent", "sysent", "unix_sysent", "unix_sysent_table",
    "_unix_sysent", "_sysent_table", "_unix_sysent_table",
]

DISPATCH_PATTERNS = [
    "syscall", "unix_syscall", "dispatch_syscall",
    "syscall_dispatch", "syscall_sw", "unix_syscall_return",
]

SYSCALL_ENTRY_SIZE = 16

INDEX_REGS = [
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
    "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7",
    "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
    "w8", "w9", "w10", "w11", "w12", "w13", "w14", "w15",
]

IDX_LOAD_MNEM = (
    "ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw",
    "ldur", "ldurb", "ldurh", "ldursb", "ldursh", "ldursw",
)

BRANCH_IND = ("blr", "br", "braa", "brab", "blraa", "blrab")

SB_BARRIERS = ("sb", "csdb", "ssbb", "pssbb", "dsb", "isb", "dmb")

KVA_LO = 0xFFFFFFF000000000
KVA_HI = 0xFFFFFFF200000000

NEEDLES = [
    "syscall", "sysent", "unix_sys", "necp", "dispatch",
    "handler", "spectre", "barrier", "sb", "csdb",
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


def find_sysent_table():
    for n in SYSENT_SYMBOLS:
        a = symbol_address(n)
        if a is not None:
            return a, n
    return None, None


def read_qword(a):
    ga = safe_addr(a)
    if ga is None:
        return None
    try:
        return to_unsigned(currentProgram.getMemory().getLong(ga))
    except Exception:
        return None


def walk_sysent_table(table_addr):
    entries = []
    for i in range(800):
        ptr = read_qword(table_addr + i * SYSCALL_ENTRY_SIZE)
        if ptr is None:
            break
        if ptr == 0:
            continue
        if (ptr >> 48) != 0xFFFF:
            continue
        handler = ptr & 0x0000FFFFFFFFFFFF
        if handler < 0xFFFFFFF000000000 or handler > 0xFFFFFFF200000000:
            continue
        f = None
        try:
            f = getFunctionAt(safe_addr(handler))
        except Exception:
            pass
        name = f.getName() if f else "?"
        entries.append((i, handler, name))
    return entries


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
    if scale in (1, 4):
        s += 3
    return s


def scan_function_for_gadgets(func, syscall_addrs, output):
    entry = to_unsigned(func.getEntryPoint().getOffset())
    listing = currentProgram.getListing()
    body = func.getBody()
    if body is None:
        return []

    insn = listing.getInstructionAt(body.getMinAddress())
    if insn is None:
        return []

    results = []
    limit = 50000
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


def scan_sysent_handlers(sysent_entries):
    syscall_addrs = set(e[1] for e in sysent_entries)
    all_hits = []
    seen = set()
    for idx, handler, name in sysent_entries:
        if handler in seen:
            continue
        seen.add(handler)
        f = ensure_func(handler)
        if f is None:
            continue
        hits = scan_function_for_gadgets(f, syscall_addrs, None)
        for h in hits:
            h["syscall_num"] = idx
            h["syscall_name"] = name
            all_hits.append(h)
        if len(all_hits) > MAX_GADGETS * 4:
            break
    return all_hits


def scan_all_functions(sysent_entries):
    syscall_addrs = set(e[1] for e in sysent_entries)
    all_hits = []
    fm = currentProgram.getFunctionManager()
    it = fm.getFunctions(True)
    cnt = 0
    for f in it:
        cnt += 1
        if cnt % 500 == 0:
            print("[*] scanned {} functions...".format(cnt))
        hits = scan_function_for_gadgets(f, syscall_addrs, None)
        all_hits.extend(hits)
        if len(all_hits) > MAX_GADGETS * 4:
            break
    return all_hits


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


def dump_sysent(entries, output):
    output.write("\n=== SYSENT TABLE ({} entries) ===\n".format(len(entries)))
    output.write("{:<6} {:<20} {:<40}\n".format("NUM", "HANDLER", "NAME"))
    output.write("-" * 80 + "\n")
    for idx, handler, name in sorted(entries, key=lambda x: x[0]):
        output.write("{:<6} {} {:<40}\n".format(idx, fmt_hex(handler), name))


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

    syscall_hits = []
    if sysent_entries:
        print("[*] scanning syscall handlers...")
        syscall_hits = scan_sysent_handlers(sysent_entries)
        print("[*] syscall handler hits: {}".format(len(syscall_hits)))

    all_hits = list(syscall_hits)
    if len(all_hits) < 20:
        print("[*] scanning all functions (fallback)...")
        all_hits.extend(scan_all_functions(sysent_entries))

    seen = set()
    deduped = []
    for h in all_hits:
        key = (h["entry"], h["load_addr"], h["branch_addr"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(h)
    deduped.sort(key=lambda x: -x["score"])

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
        f.write("=== TOP CANDIDATES (score >= 20) ===\n")
        f.write("{:<8} {:<6} {:<20} {:<40} {:<40}\n".format(
            "SCORE", "SYSNUM", "FUNC", "LOAD", "BRANCH"))
        f.write("-" * 130 + "\n")
        for h in deduped:
            if h["score"] < 20:
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

    print("[*] wrote: " + SYSENT_OUT)
    print("[*] wrote: " + GADGETS_OUT)
    print("[*] wrote: " + CANDIDATES_OUT)
    print("[*] wrote: " + STRINGS_OUT)


main()
