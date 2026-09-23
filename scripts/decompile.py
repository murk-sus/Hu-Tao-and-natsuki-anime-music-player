# -*- coding: utf-8 -*-

import os
import re
import json

WORKSPACE = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT_PATH = os.path.join(WORKSPACE, "offsets.txt")
SYMBOLS_JSON = os.path.join(WORKSPACE, "symbols.json")

INSTR_LIMIT = 500
FUNC_SIZE_LIMIT = 96
FIELD_OFFSET_MAX = 0x2000
ACCESSOR_CANDIDATE_LIMIT = 5000
DECOM_TIMEOUT_SECS = 120

TARGET_SYMBOLS = [
    "_allproc", "_kernproc", "_nprocs",
    "_proc_pid", "_proc_task", "_proc_ucred", "_proc_fd", "_proc_textvp",
    "_proc_ppid", "_proc_list_entry",
    "_kauth_cred_getuid", "_kauth_cred_getruid", "_kauth_cred_getsvuid",
    "_kauth_cred_getgid", "_kauth_cred_getrgid", "_kauth_cred_getsvgid",
    "_kauth_cred_getgroups", "_kauth_cred_getngroups",
    "_cs_enforcement_disable", "_amfi_get_out_of_my_way",
    "_necp_client_action", "_necp_client_copy_result",
    "_necp_client_add_flow", "_necp_client_remove_flow", "_necp_update_flow",
    "_necp_client_copy", "_necp_client_copy_internal",
    "_necp_client_update_cache", "_necp_client_update_flows",
    "_necp_client_acquire_agent_token", "_necp_arena_initialize",
    "_necp_session_action", "_necp_session_add_policy",
    "_task_for_pid", "_task_map", "_get_task_ipcspace",
    "_vm_map_pmap", "_vm_map_lookup_entry", "_pmap_enter_options",
    "_vnode_mount", "_vnode_data", "_vnode_vtype",
    "_fd_ofiles", "_fileproc_fglob",
    "_socket_so_rcv", "_socket_so_snd",
    "_rootvnode", "_kernel_map", "_host_priv_self",
    "_bsd_syscall_table", "_mach_trap_table", "_mig_kern_subsystem",
    "_vm_kernel_slide", "_kernproc_self", "_procs_tree",
    "_kalloc_init", "_kalloc_large", "_kalloc_heap_init",
    "_kalloc_type_validate_flags",
    "_dlil_ifaddr_bytes", "_route_output", "_rtinit_locked",
    "_pmap_enter_pte", "_pmap_expand",
    "_resolve_kernel_task", "_task_info",
    "_proc_info_internal",
    "_sptm_get_page_table_refcnt",
]

ANCHOR_STRINGS = [
    "allproc", "kernproc",
    "necp_client", "necp_session", "necp_arena",
    "cs_enforcement", "amfi_get_out_of_my_way",
    "task_for_pid", "proc_info",
    "kalloc_type",
    "dlil_ifaddr", "rtm_scrub",
    "vm_kernel_slide",
]

SYSCALL_TABLE_SYMS = ["_bsd_syscall_table", "bsd_syscall_table"]
MACH_TRAP_SYMS    = ["_mach_trap_table",    "mach_trap_table"]
MIG_SUBSYS_SYMS   = ["_mig_kern_subsystem", "mig_kern_subsystem"]

SYSCALL_INTERESTING_IDX = (
    0, 1, 2, 3, 4, 5, 6, 20, 27, 32, 33, 47, 49, 50,
    65, 66, 97, 116, 128, 144, 147, 149, 154, 170,
    202, 220, 224, 226, 250, 286, 294, 301, 302, 322,
    336, 337, 501, 502,
)


def _to_unsigned(v):
    return int(v) & 0xFFFFFFFFFFFFFFFF


def _to_java_long(v):
    v = _to_unsigned(v)
    if v >= 0x8000000000000000:
        v -= 0x10000000000000000
    return int(v)


def _fmt(v):
    return "0x{:016X}".format(_to_unsigned(v))


def load_symbols_json():
    result = {}
    if not os.path.exists(SYMBOLS_JSON):
        return result
    try:
        with open(SYMBOLS_JSON) as fh:
            raw = fh.read().strip()
        if not raw:
            return result
        data = json.loads(raw)
    except Exception:
        return result

    def _add(name, addr):
        if not name or addr is None:
            return
        try:
            if isinstance(addr, str):
                addr_int = int(addr, 16) if addr.startswith(("0x", "0X")) else int(addr, 0)
            else:
                addr_int = int(addr)
            u = _to_unsigned(addr_int)
            result[name] = u
            if not name.startswith("_"):
                result["_" + name] = u
        except Exception:
            pass

    def _walk(node):
        if isinstance(node, dict):
            name = node.get("name") or node.get("symbol")
            addr = node.get("address") or node.get("addr") or node.get("value")
            if name and addr is not None:
                _add(name, addr)
                return
            for k, v in node.items():
                if isinstance(v, str) and v.startswith(("0x", "0X")):
                    try:
                        _add(k, v)
                        continue
                    except Exception:
                        pass
                _walk(v)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(data)
    return result


def find_symbol_address(name, symbols):
    if name in symbols:
        return symbols[name]
    bare = name.lstrip("_")
    for candidate in (bare, "_" + name, name.lower()):
        if candidate in symbols:
            return symbols[candidate]
    lower = name.lower()
    for k, v in symbols.items():
        if k.lower() == lower:
            return v
    for k, v in symbols.items():
        if k.lower().endswith(lower):
            return v
    st = currentProgram.getSymbolTable()
    try:
        for sym in st.getSymbols(name):
            return _to_unsigned(sym.getAddress().getOffset())
    except Exception:
        pass
    try:
        for sym in st.getSymbols(bare):
            return _to_unsigned(sym.getAddress().getOffset())
    except Exception:
        pass
    return None


def _safe_addr(addr):
    try:
        return toAddr(_to_java_long(addr))
    except Exception:
        return None


def read_u64(addr):
    ga = _safe_addr(addr)
    if ga is None:
        return None
    try:
        return _to_unsigned(getLong(ga))
    except Exception:
        return None


def read_u32(addr):
    ga = _safe_addr(addr)
    if ga is None:
        return None
    try:
        return _to_unsigned(getInt(ga)) & 0xFFFFFFFF
    except Exception:
        return None


def scan_strings():
    result = {}
    listing = currentProgram.getListing()
    it = listing.getDefinedData(True)
    while it.hasNext():
        d = it.next()
        try:
            if d.hasStringValue():
                val = d.getValue()
                if val is not None:
                    s = str(val)
                    if s:
                        result[s] = _to_unsigned(d.getAddress().getOffset())
        except Exception:
            continue
    return result


def find_xrefs_to(addr):
    refs = []
    ga = _safe_addr(addr)
    if ga is None:
        return refs
    rm = currentProgram.getReferenceManager()
    try:
        for r in rm.getReferencesTo(ga):
            refs.append(_to_unsigned(r.getFromAddress().getOffset()))
    except Exception:
        pass
    return refs


def dump_instructions_from(addr, limit=INSTR_LIMIT):
    lines = []
    ga = _safe_addr(addr)
    if ga is None:
        return ["  ERROR: bad addr {}".format(_fmt(addr))]
    instr = getInstructionAt(ga)
    if instr is None:
        try:
            disassemble(ga)
            instr = getInstructionAt(ga)
        except Exception:
            pass
    if instr is None:
        return ["  no instruction at {}".format(_fmt(addr))]
    count = 0
    while instr is not None and count < limit:
        lines.append("  {}  {}".format(
            _fmt(_to_unsigned(instr.getAddress().getOffset())), instr))
        instr = instr.getNext()
        count += 1
    return lines


def _make_decompiler():
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    ifc = DecompInterface()
    ifc.setOptions(DecompileOptions())
    ifc.openProgram(currentProgram)
    return ifc


def decompile_function(func, ifc):
    from ghidra.util.task import ConsoleTaskMonitor
    try:
        res = ifc.decompileFunction(func, DECOM_TIMEOUT_SECS, ConsoleTaskMonitor())
        if res.decompileCompleted():
            return res.getDecompiledFunction().getC()
    except Exception:
        pass
    return ""


def decompile_at(addr, ifc):
    ga = _safe_addr(addr)
    if ga is None:
        return ""
    try:
        func = getFunctionAt(ga)
        if func is None:
            disassemble(ga)
            func = createFunction(ga, None)
        if func is None:
            return ""
        return decompile_function(func, ifc)
    except Exception:
        return ""


_FIELD_RE = re.compile(
    r"\((?P<type>[A-Za-z_][A-Za-z0-9_ ]*?)\s*\*\)\s*"
    r"\((?P<var>a1|param_1|arg1|self)\s*\+\s*"
    r"(?P<off>0x[0-9a-fA-F]+|\d+)\)"
)


def extract_field_offsets(code):
    hits = []
    for m in _FIELD_RE.finditer(code):
        try:
            hits.append((int(m.group("off"), 0), m.group("type").strip()))
        except Exception:
            pass
    return hits


def parse_table(addr, count, stride=8):
    entries = []
    for i in range(count):
        e = read_u64(addr + i * stride)
        if e is None:
            break
        entries.append(e)
    return entries


def emit_symbol_table(out, symbols, target_list, section_name):
    out.write("\n=== {} ===\n".format(section_name))
    found = 0
    for name in target_list:
        addr = find_symbol_address(name, symbols)
        if addr is not None:
            tag = "  (json)" if name in symbols else "  (ghidra)"
            line = "{:<45} {}{}".format(name, _fmt(addr), tag)
            found += 1
        else:
            line = "{:<45} NOT_FOUND".format(name)
        out.write(line + "\n")
    out.flush()
    out.write("  --- found: {}/{}\n".format(found, len(target_list)))


def section_syscall_table(out, symbols):
    out.write("\n=== SYSCALL TABLE ===\n")
    for tname in SYSCALL_TABLE_SYMS:
        taddr = find_symbol_address(tname, symbols)
        if taddr is None:
            continue
        out.write("table {} @ {}\n".format(tname, _fmt(taddr)))
        entries = parse_table(taddr, 600, 8)
        for idx in SYSCALL_INTERESTING_IDX:
            if idx < len(entries) and entries[idx]:
                out.write("  sysent[{}] = {}\n".format(idx, _fmt(entries[idx])))
        out.flush()
        return
    out.write("  NOT_FOUND\n")


def section_mach_traps(out, symbols):
    out.write("\n=== MACH TRAP TABLE ===\n")
    for tname in MACH_TRAP_SYMS:
        taddr = find_symbol_address(tname, symbols)
        if taddr is None:
            continue
        out.write("table {} @ {}\n".format(tname, _fmt(taddr)))
        entries = parse_table(taddr, 128, 8)
        for idx in range(min(64, len(entries))):
            if entries[idx]:
                out.write("  trap[{}] = {}\n".format(idx, _fmt(entries[idx])))
        out.flush()
        return
    out.write("  NOT_FOUND\n")


def section_mig_subsystem(out, symbols):
    out.write("\n=== MIG SUBSYSTEM ===\n")
    for tname in MIG_SUBSYS_SYMS:
        taddr = find_symbol_address(tname, symbols)
        if taddr is None:
            continue
        out.write("subsystem {} @ {}\n".format(tname, _fmt(taddr)))

        maxsize = read_u32(taddr + 0x00)
        if maxsize is not None:
            out.write("  maxsize = {}\n".format(maxsize))

        count = None
        routines_ptr = None
        for count_off, ptr_off in ((0x20, 0x28), (0x18, 0x20), (0x24, 0x30)):
            candidate_count = read_u32(taddr + count_off)
            candidate_ptr   = read_u64(taddr + ptr_off)
            if candidate_count and 0 < candidate_count < 2048 and candidate_ptr:
                first = read_u64(candidate_ptr)
                if first and first > 0xFFFFFFF000000000:
                    count = candidate_count
                    routines_ptr = candidate_ptr
                    out.write("  layout offsets: count@+{:#x} ptr@+{:#x}\n".format(
                        count_off, ptr_off))
                    break

        if count is None:
            out.write("  WARNING: could not determine layout — dumping raw words\n")
            for off in range(0, 0x40, 4):
                w = read_u32(taddr + off)
                if w is not None:
                    out.write("    +{:#04x} = {:#010x}\n".format(off, w))
            out.flush()
            return

        out.write("  routine count = {}\n".format(count))
        out.write("  routines table @ {}\n".format(_fmt(routines_ptr)))
        for i in range(min(count, 32)):
            r = read_u64(routines_ptr + i * 0x18)
            if r:
                out.write("    routine[{}] = {}\n".format(i, _fmt(r)))
        out.flush()
        return
    out.write("  NOT_FOUND\n")


def section_string_anchors(out, symbols, strings):
    out.write("\n=== STRING ANCHORS ===\n")
    out.write("total strings: {}\n".format(len(strings)))
    for key in ANCHOR_STRINGS:
        hit = False
        for s, a in strings.items():
            if key in s:
                out.write("  {:<50} {}\n".format(repr(s[:46]), _fmt(a)))
                for x in find_xrefs_to(a)[:20]:
                    out.write("      xref <- {}\n".format(_fmt(x)))
                hit = True
                break
        if not hit:
            out.write("  {:<50} NOT_FOUND\n".format(key))
    out.flush()


def section_accessor_candidates(out):
    out.write("\n=== ACCESSOR CANDIDATES ===\n")
    out.flush()

    ifc = _make_decompiler()
    fm = currentProgram.getFunctionManager()
    total = 0
    candidates = []

    for f in fm.getFunctions(True):
        total += 1
        body = f.getBody()
        if body.getNumAddresses() > FUNC_SIZE_LIMIT:
            continue

        code = decompile_function(f, ifc)
        if not code:
            continue

        hits = extract_field_offsets(code)
        if len(hits) == 1 and 0 < hits[0][0] < FIELD_OFFSET_MAX:
            candidates.append((
                f.getName(),
                _to_unsigned(f.getEntryPoint().getOffset()),
                hits[0][0],
                hits[0][1],
            ))

    out.write("scanned: {}\n".format(total))
    out.write("candidates: {}\n\n".format(len(candidates)))
    for name, addr, off, typ in candidates[:ACCESSOR_CANDIDATE_LIMIT]:
        out.write("  {:<45} {}  +0x{:x}  {}\n".format(name, _fmt(addr), off, typ))
    out.flush()


def section_anchor_disasm(out, strings):
    out.write("\n=== ANCHOR XREF DISASM ===\n")
    keys = ("necp_client", "necp_session", "necp_arena",
            "dlil_ifaddr", "allproc", "proc_info")
    for key in keys:
        for s, a in strings.items():
            if key in s:
                for x in find_xrefs_to(a)[:2]:
                    out.write("\n--- xref of '{}' at {} ---\n".format(key, _fmt(x)))
                    for ln in dump_instructions_from(x, limit=80):
                        out.write(ln + "\n")
                break
    out.flush()


def section_manual_disasm(out):
    out.write("\n=== MANUAL DISASM ===\n")
    manual = os.environ.get("MANUAL_ADDRS", "").split(",")
    for a in manual:
        a = a.strip()
        if not a:
            continue
        try:
            addr = int(a, 0)
        except ValueError:
            continue
        out.write("\n--- {} ---\n".format(_fmt(addr)))
        for ln in dump_instructions_from(addr):
            out.write(ln + "\n")
    out.flush()


def main():
    symbols = load_symbols_json()
    print("[*] Program: " + currentProgram.getName())
    print("[*] Symbols loaded: {}".format(len(symbols)))

    strings = scan_strings()
    print("[*] Defined strings: {}".format(len(strings)))

    with open(OUT_PATH, "w") as out:
        out.write("=== KERNEL OFFSETS REPORT ===\n")
        out.write("Program: {}\n".format(currentProgram.getName()))
        out.write("ImageBase: {}\n".format(
            _fmt(_to_unsigned(currentProgram.getImageBase().getOffset()))))
        out.write("SymbolsLoaded: {}\n".format(len(symbols)))

        emit_symbol_table(out, symbols, TARGET_SYMBOLS, "SYMBOLS")
        section_string_anchors(out, symbols, strings)
        section_syscall_table(out, symbols)
        section_mach_traps(out, symbols)
        section_mig_subsystem(out, symbols)
        section_accessor_candidates(out)
        section_anchor_disasm(out, strings)
        section_manual_disasm(out)

        out.write("\n=== DONE ===\n")

    print("[*] wrote: " + OUT_PATH)


main()
