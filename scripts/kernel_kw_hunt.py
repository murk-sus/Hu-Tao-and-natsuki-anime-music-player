# -*- coding: utf-8 -*-

import os
import re
import json

from ghidra.program.model.symbol import RefType
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor

WORKSPACE = os.environ.get("GITHUB_WORKSPACE", "/tmp")

SYSENT_OUT  = os.path.join(WORKSPACE, "nk_sysent.txt")
ANCHOR_OUT  = os.path.join(WORKSPACE, "nk_anchors.h")
NECP_OUT    = os.path.join(WORKSPACE, "nk_necp_full.txt")
ZONE_OUT    = os.path.join(WORKSPACE, "nk_zone_offsets.txt")
KALLOC_OUT  = os.path.join(WORKSPACE, "nk_kalloc_sites.txt")
COPY_OUT    = os.path.join(WORKSPACE, "nk_copy_ops.txt")
IOKIT_OUT   = os.path.join(WORKSPACE, "nk_iokit_methods.txt")
KW_OUT      = os.path.join(WORKSPACE, "nk_kw_gadgets.txt")
UAF_OUT     = os.path.join(WORKSPACE, "nk_uaf_candidates.txt")
REPORT_OUT  = os.path.join(WORKSPACE, "nk_report.txt")

DECOM_TIMEOUT = 120

KVA_LO = 0xFFFFFFF000000000
KVA_HI = 0xFFFFFFF200000000
SYSCALL_ENTRY = 16

SYSCALL_NAMES = [
    "nosys", "exit", "fork", "read", "write", "open", "close",
    "getpid", "necp_open", "necp_client_action",
    "necp_session_open", "necp_session_action",
    "syscall", "workq_open", "workq_kernreturn",
]

NECP_NEEDLES = [
    "necp_client", "necp_session", "necp_kernel", "necp_policy",
    "necp_arena", "necp_flow", "necp_route", "necp_socket",
    "necp_domain", "necp_string_id", "necp_uuid_id", "necp_agent",
    "necp_fd", "necp_nai", "necp_stats",
]

ZONE_NEEDLES = [
    "necp_client", "necp_client_flow", "necp_client_flow_registration",
    "necp_client_assertion", "necp_fd_data", "necp_session",
    "necp_kernel_socket_policy", "necp_kernel_ip_output_policy",
    "necp_string_id_mapping", "necp_uuid_id_mapping",
    "necp_route_rule", "necp_aggregate_route_rule",
    "necp_domain_filter", "necp_domain_trie", "necp_arena_info",
    "necp_client_update", "necp_client_parsed_parameters",
    "necp_flow_defunct",
]

KALLOC_NEEDLES = [
    "kalloc_type", "kalloc_ext", "kalloc_data", "kalloc_zone",
    "zalloc", "kfree_type", "kfree_ext",
]

COPY_NEEDLES = [
    "copyin", "copyout", "copyinstr", "copyoutstr",
    "copyinmsg", "copyoutmsg",
]

IOKIT_NEEDLES = [
    "externalMethod", "IOExternalMethodDispatch",
    "IOConnectCall", "userClient", "UserClient",
]

KW_MNEMS = ("str", "stp", "stur", "strb", "strh", "stlr", "stxr")

STRUCT_OPS_NEEDLES = [
    "necp_client_add", "necp_client_remove", "necp_client_destroy",
    "necp_client_destroy_internal", "necp_create_flow",
    "necp_client_add_flow", "necp_client_remove_flow",
    "necp_client_claim", "necp_client_copy", "necp_client_copy_internal",
    "necp_client_update_cache", "necp_client_flow_registration",
    "destroy_client_flow_registration", "flow_registration_release",
    "necp_session_action", "necp_session_add_policy",
    "necp_session_get_policy", "necp_session_delete_policy",
]


def fmt(v):
    return "0x{:016X}".format(v & 0xFFFFFFFFFFFFFFFF)


def to_long(v):
    v = int(v) & 0xFFFFFFFFFFFFFFFF
    if v >= 0x8000000000000000:
        v -= 0x10000000000000000
    return v


def safe_addr(a):
    try:
        return toAddr(to_long(a))
    except Exception:
        return None


def read_u64(a):
    ga = safe_addr(a)
    if ga is None:
        return None
    try:
        return int(currentProgram.getMemory().getLong(ga)) & 0xFFFFFFFFFFFFFFFF
    except Exception:
        return None


def read_u32(a):
    ga = safe_addr(a)
    if ga is None:
        return None
    try:
        return int(currentProgram.getMemory().getInt(ga)) & 0xFFFFFFFF
    except Exception:
        return None


def is_kva(v):
    return v is not None and KVA_LO <= v < KVA_HI


def find_str(s):
    listing = currentProgram.getListing()
    it = listing.getDefinedData(True)
    while it.hasNext():
        d = it.next()
        try:
            if d.hasStringValue() and str(d.getValue()) == s:
                return int(d.getAddress().getOffset()) & 0xFFFFFFFFFFFFFFFF
        except Exception:
            pass
    return None


def data_xrefs(a):
    ga = safe_addr(a)
    if ga is None:
        return []
    out = []
    rm = currentProgram.getReferenceManager()
    try:
        for r in rm.getReferencesTo(ga):
            try:
                out.append(int(r.getFromAddress().getOffset()) & 0xFFFFFFFFFFFFFFFF)
            except Exception:
                pass
    except Exception:
        pass
    return out


def call_xrefs(a):
    ga = safe_addr(a)
    if ga is None:
        return []
    out = []
    rm = currentProgram.getReferenceManager()
    try:
        for r in rm.getReferencesTo(ga):
            if r.getReferenceType() in (RefType.UNCONDITIONAL_CALL,
                                        RefType.CONDITIONAL_CALL,
                                        RefType.COMPUTED_CALL,
                                        RefType.UNCONDITIONAL_JUMP):
                try:
                    out.append(int(r.getFromAddress().getOffset()) & 0xFFFFFFFFFFFFFFFF)
                except Exception:
                    pass
    except Exception:
        pass
    return out


def symbols_named(pat):
    out = []
    st = currentProgram.getSymbolTable()
    try:
        for sym in st.getAllSymbols(True):
            n = sym.getName()
            if pat in n:
                try:
                    out.append((int(sym.getAddress().getOffset()) & 0xFFFFFFFFFFFFFFFF, n))
                except Exception:
                    pass
    except Exception:
        pass
    return out


def func_at(a):
    ga = safe_addr(a)
    if ga is None:
        return None
    try:
        f = getFunctionAt(ga)
        if f is not None:
            return f
    except Exception:
        pass
    try:
        f = getFunctionContaining(ga)
        if f is not None:
            return f
    except Exception:
        pass
    return None


def ensure_func(a):
    f = func_at(a)
    if f is not None:
        return f
    ga = safe_addr(a)
    if ga is None:
        return None
    try:
        disassemble(ga)
    except Exception:
        pass
    try:
        return createFunction(ga, None)
    except Exception:
        return None


IFC = None


def decompile(f):
    global IFC
    if f is None:
        return ""
    if IFC is None:
        IFC = DecompInterface()
        IFC.setOptions(DecompileOptions())
        IFC.openProgram(currentProgram)
    try:
        r = IFC.decompileFunction(f, DECOM_TIMEOUT, ConsoleTaskMonitor())
        if not r.decompileCompleted():
            return ""
        return r.getDecompiledFunction().getC()
    except Exception:
        return ""


# ==================== SYSENT ====================

def check_names_base(base, count=16):
    for i in range(count):
        v = read_u64(base + i * 8)
        if not is_kva(v):
            return False
        try:
            d = getDataAt(safe_addr(v))
            if d is None or not d.hasStringValue():
                return False
        except Exception:
            return False
    return True


def looks_like_sysent(base, min_hits=12):
    hits = 0
    for i in range(16):
        p = read_u64(base + i * SYSCALL_ENTRY)
        if is_kva(p):
            hits += 1
    return hits >= min_hits


def try_sysent_by_symbols():
    for pat in ("_sysent", "sysent", "unix_sysent", "unix_sysent_table"):
        for a, n in symbols_named(pat):
            if looks_like_sysent(a):
                return a, n
    return None, None


def try_sysent_by_names():
    for nm in SYSCALL_NAMES:
        s = find_str(nm)
        if s is None:
            continue
        xrefs = sorted(data_xrefs(s))
        for ref in xrefs:
            for k in range(0, 600):
                names_base = ref - k * 8
                if names_base < KVA_LO:
                    break
                if not check_names_base(names_base, 16):
                    continue
                for off in range(64, 0x200000, 16):
                    cand = names_base - off
                    if cand < KVA_LO:
                        break
                    if looks_like_sysent(cand):
                        return cand, names_base, k, nm
    return None, None, None, None


def try_sysent_by_unix_syscall():
    for name in ("unix_syscall", "unix_syscall64", "unix_syscall_return"):
        for a, n in symbols_named(name):
            f = ensure_func(a)
            if f is None:
                continue
            body = f.getBody()
            if body is None:
                continue
            insn = currentProgram.getListing().getInstructionAt(body.getMinAddress())
            cnt = 0
            while insn is not None and body.contains(insn.getAddress()) and cnt < 20000:
                for m in re.finditer(r"0x([0-9a-fA-F]{6,16})", insn.toString()):
                    try:
                        cand = int(m.group(1), 16) & 0xFFFFFFFFFFFFFFFF
                        if is_kva(cand) and looks_like_sysent(cand):
                            return cand, n
                    except Exception:
                        pass
                insn = insn.getNext()
                cnt += 1
    return None, None


def walk_sysent(base, limit=1200):
    entries = []
    for i in range(limit):
        a = base + i * SYSCALL_ENTRY
        p = read_u64(a)
        if not is_kva(p):
            break
        narg = read_u32(a + 8)
        if narg is None or narg > 32:
            break
        entries.append((i, p & 0x0000FFFFFFFFFFFF, narg))
    return entries


def resolve_sysent():
    a, n = try_sysent_by_symbols()
    if a is not None:
        return a, n, walk_sysent(a)
    a, n = try_sysent_by_unix_syscall()
    if a is not None:
        return a, n, walk_sysent(a)
    a, names, k, nm = try_sysent_by_names()
    if a is not None:
        return a, nm, walk_sysent(a)
    return None, None, []


# ==================== NECP ====================

def collect_necp_symbols():
    seen = {}
    for needle in NECP_NEEDLES:
        for a, n in symbols_named(needle):
            if a not in seen:
                seen[a] = n
    return seen


def collect_zone_symbols():
    out = []
    for zn in ZONE_NEEDLES:
        s = find_str(zn)
        if s is None:
            continue
        xrefs = sorted(data_xrefs(s))
        out.append((zn, s, xrefs))
    return out


# ==================== KALLOC / COPY / IOKIT ====================

def find_callee_addr(name):
    for a, n in symbols_named(name):
        return a
    return None


def find_nearest_mov_before(insn, limit=8):
    args = []
    cur = insn.getPrevious()
    for _ in range(limit):
        if cur is None:
            break
        mn = cur.getMnemonicString().lower()
        if mn in ("mov", "movz", "movk", "orr", "adrp", "add", "ldr"):
            args.append(cur.toString())
        if mn in ("bl", "blr", "b"):
            break
        cur = cur.getPrevious()
    return list(reversed(args))


def scan_for_callsites(funcs, needles, out_lines, tag):
    for faddr, fname in funcs:
        f = func_at(faddr)
        if f is None:
            continue
        body = f.getBody()
        if body is None:
            continue
        insn = currentProgram.getListing().getInstructionAt(body.getMinAddress())
        cnt = 0
        while insn is not None and body.contains(insn.getAddress()) and cnt < 20000:
            mn = insn.getMnemonicString().lower()
            if mn in ("bl", "blr", "b"):
                tgt = insn.toString()
                if any(n in tgt for n in needles):
                    setup = find_nearest_mov_before(insn, 8)
                    out_lines.append(
                        "{} {} @ {}  callsite={}".format(
                            tag, fname,
                            fmt(int(insn.getAddress().getOffset()) & 0xFFFFFFFFFFFFFFFF),
                            tgt))
                    for s in setup:
                        out_lines.append("    {}".format(s))
                    out_lines.append("")
            insn = insn.getNext()
            cnt += 1


def scan_kw_gadgets(funcs):
    out = []
    for faddr, fname in funcs:
        f = func_at(faddr)
        if f is None:
            continue
        body = f.getBody()
        if body is None:
            continue
        insn = currentProgram.getListing().getInstructionAt(body.getMinAddress())
        cnt = 0
        while insn is not None and body.contains(insn.getAddress()) and cnt < 20000:
            mn = insn.getMnemonicString().lower().split(".")[0]
            if mn in KW_MNEMS:
                txt = insn.toString()
                if "[" in txt and "]" in txt:
                    src = txt.split(",")[0].strip()
                    dst = txt.split("[", 1)[1].split("]", 1)[0].split(",")[0].strip()
                    if re.match(r"^[xw][0-9]+$", src) and re.match(r"^[xw][0-9]+$", dst):
                        out.append({
                            "func": fname,
                            "addr": int(insn.getAddress().getOffset()) & 0xFFFFFFFFFFFFFFFF,
                            "text": txt,
                            "src": src,
                            "dst": dst,
                        })
            insn = insn.getNext()
            cnt += 1
    return out


def scan_uaf_candidates(funcs):
    out = []
    for faddr, fname in funcs:
        f = func_at(faddr)
        if f is None:
            continue
        body = f.getBody()
        if body is None:
            continue
        listing = currentProgram.getListing()
        insn = listing.getInstructionAt(body.getMinAddress())
        seen_kfree = []
        cnt = 0
        while insn is not None and body.contains(insn.getAddress()) and cnt < 20000:
            mn = insn.getMnemonicString().lower()
            if mn in ("bl", "blr"):
                tgt = insn.toString()
                if any(k in tgt for k in ("kfree", "kfree_type", "kfree_ext", "zfree")):
                    here = int(insn.getAddress().getOffset()) & 0xFFFFFFFFFFFFFFFF
                    seen_kfree.append((here, find_nearest_mov_before(insn, 6)))
                elif any(k in tgt for k in ("kalloc", "zalloc")):
                    pass
            insn = insn.getNext()
            cnt += 1
        if seen_kfree:
            out.append((fname, seen_kfree))
    return out


# ==================== WRITERS ====================

def write_lines(path, lines):
    with open(path, "w") as f:
        for line in lines:
            f.write(line)
            f.write("\n")


def write_sysent(entries, sysent_base, sysent_name):
    lines = []
    lines.append("=== SYSENT ===")
    lines.append("Program: {}".format(currentProgram.getName()))
    lines.append("sysent symbol: {}".format(sysent_name or "(not found)"))
    lines.append("sysent addr: {}".format(fmt(sysent_base) if sysent_base else "n/a"))
    lines.append("")
    lines.append("{:<6} {:<20} {:<40} {}".format("NUM", "HANDLER", "NAME", "NARG"))
    lines.append("-" * 90)
    for i, handler, narg in entries:
        name = "?"
        try:
            f = func_at(handler)
            if f is not None:
                name = f.getName()
        except Exception:
            pass
        lines.append("{:<6} {} {:<40} {}".format(i, fmt(handler), name, narg))
    write_lines(SYSENT_OUT, lines)


def write_anchors(entries, sysent_base):
    lines = []
    lines.append("#ifndef NK_ANCHORS_H")
    lines.append("#define NK_ANCHORS_H")
    lines.append("")
    if sysent_base:
        lines.append("#define NK_SYSENT_BASE {}".format(fmt(sysent_base)))
    for i, handler, narg in entries:
        name = ""
        try:
            f = func_at(handler)
            if f is not None:
                name = f.getName()
        except Exception:
            pass
        if "necp" not in name.lower() and "necp" not in "":
            continue
        key = re.sub(r"[^A-Za-z0-9_]", "_", name).upper()
        lines.append("#define NK_HANDLER_{}  {}  /* idx={} narg={} */".format(
            key, fmt(handler), i, narg))
    lines.append("")
    lines.append("#endif")
    write_lines(ANCHOR_OUT, lines)


def write_necp(funcs):
    lines = []
    lines.append("=== NECP SYMBOLS ({} functions) ===".format(len(funcs)))
    lines.append("")
    for a, n in sorted(funcs.items(), key=lambda x: x[1]):
        lines.append("========================================================")
        lines.append("{} @ {}".format(n, fmt(a)))
        lines.append("========================================================")
        f = ensure_func(a)
        code = decompile(f)
        if code:
            for line in code.splitlines():
                lines.append(line)
        lines.append("")
    write_lines(NECP_OUT, lines)


def write_zones(zones):
    lines = []
    lines.append("=== ZONE NAME POINTERS ===")
    for zn, s, xrefs in zones:
        lines.append("{}  name@{}  xrefs={}".format(zn, fmt(s), len(xrefs)))
        for r in xrefs[:8]:
            lines.append("    xref@{}  maybe_zone_base={}".format(fmt(r), fmt(r - 0x18)))
    write_lines(ZONE_OUT, lines)


def write_kalloc(lines):
    write_lines(KALLOC_OUT, lines)


def write_copy(lines):
    write_lines(COPY_OUT, lines)


def write_iokit(lines):
    write_lines(IOKIT_OUT, lines)


def write_kw(gadgets):
    lines = []
    lines.append("=== KW GADGETS ({} hits) ===".format(len(gadgets)))
    lines.append("")
    lines.append("{:<20} {:<20} {:<40}".format("FUNC", "ADDR", "INSN"))
    lines.append("-" * 90)
    for g in gadgets:
        lines.append("{:<20} {} {}".format(g["func"][:20], fmt(g["addr"]), g["text"]))
    write_lines(KW_OUT, lines)


def write_uaf(cands):
    lines = []
    lines.append("=== UAF CANDIDATES ({} functions) ===".format(len(cands)))
    for fname, kfrees in cands:
        lines.append("")
        lines.append("func {}  kfree-sites={}".format(fname, len(kfrees)))
        for addr, setup in kfrees:
            lines.append("  kfree @ {}".format(fmt(addr)))
            for s in setup:
                lines.append("      {}".format(s))
    write_lines(UAF_OUT, lines)


# ==================== MAIN ====================

def main():
    print("[*] program: " + currentProgram.getName())

    sysent_base, sysent_name, entries = resolve_sysent()
    print("[*] sysent: {} entries".format(len(entries)))
    write_sysent(entries, sysent_base, sysent_name)
    write_anchors(entries, sysent_base)

    necp_funcs = collect_necp_symbols()
    print("[*] necp funcs: {}".format(len(necp_funcs)))
    write_necp(necp_funcs)

    zones = collect_zone_symbols()
    print("[*] zones: {}".format(len(zones)))
    write_zones(zones)

    struct_funcs = []
    seen_sf = set()
    for needle in STRUCT_OPS_NEEDLES:
        for a, n in symbols_named(needle):
            if a not in seen_sf:
                seen_sf.add(a)
                struct_funcs.append((a, n))

    kalloc_lines = []
    kalloc_lines.append("=== KALLOC/KFREE CALLSITES ({} funcs) ===".format(len(struct_funcs)))
    kalloc_lines.append("")
    scan_for_callsites(struct_funcs, KALLOC_NEEDLES, kalloc_lines, "KALLOC")
    write_kalloc(kalloc_lines)

    copy_lines = []
    copy_lines.append("=== COPYIN/COPYOUT CALLSITES ({} funcs) ===".format(len(struct_funcs)))
    copy_lines.append("")
    scan_for_callsites(struct_funcs, COPY_NEEDLES, copy_lines, "COPY")
    write_copy(copy_lines)

    iokit_funcs = []
    seen_if = set()
    for needle in IOKIT_NEEDLES:
        for a, n in symbols_named(needle):
            if a not in seen_if:
                seen_if.add(a)
                iokit_funcs.append((a, n))
    iokit_lines = []
    iokit_lines.append("=== IOKIT USERCLIENT / EXTERNAL METHODS ({} funcs) ===".format(len(iokit_funcs)))
    iokit_lines.append("")
    for a, n in sorted(iokit_funcs, key=lambda x: x[1]):
        iokit_lines.append("{} @ {}".format(n, fmt(a)))
    write_iokit(iokit_lines)

    print("[*] scanning kw gadgets in struct funcs + necp funcs")
    kw_targets = list(struct_funcs) + list(necp_funcs.items())
    kw_gadgets = scan_kw_gadgets(kw_targets)
    print("[*] kw gadget hits: {}".format(len(kw_gadgets)))
    write_kw(kw_gadgets)

    print("[*] scanning uaf candidates in struct funcs")
    uaf_cands = scan_uaf_candidates(struct_funcs)
    print("[*] uaf candidate funcs: {}".format(len(uaf_cands)))
    write_uaf(uaf_cands)

    report = []
    report.append("=== KERNEL KW HUNT REPORT ===")
    report.append("Program: {}".format(currentProgram.getName()))
    report.append("sysent base: {}".format(fmt(sysent_base) if sysent_base else "n/a"))
    report.append("sysent entries: {}".format(len(entries)))
    report.append("necp funcs: {}".format(len(necp_funcs)))
    report.append("zones: {}".format(len(zones)))
    report.append("struct funcs: {}".format(len(struct_funcs)))
    report.append("iokit funcs: {}".format(len(iokit_funcs)))
    report.append("kw gadgets: {}".format(len(kw_gadgets)))
    report.append("uaf candidates: {}".format(len(uaf_cands)))
    report.append("")
    report.append("FILES:")
    for p in (SYSENT_OUT, ANCHOR_OUT, NECP_OUT, ZONE_OUT,
              KALLOC_OUT, COPY_OUT, IOKIT_OUT, KW_OUT, UAF_OUT):
        report.append("  " + p)
    write_lines(REPORT_OUT, report)

    print("[*] wrote: " + REPORT_OUT)


main()
