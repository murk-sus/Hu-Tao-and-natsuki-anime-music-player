# -*- coding: utf-8 -*-

import os
import re
import json

WORKSPACE  = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT_PATH   = os.path.join(WORKSPACE, "necp_decom.txt")
SYMBOLS_JSON = os.path.join(WORKSPACE, "symbols.json")

DECOM_TIMEOUT = 120
INSTR_LIMIT   = 300
MAX_XREFS_PER_STRING = 12

TARGET_SYMS = [
    "necp_client_action",
    "necp_client_copy",
    "necp_client_copy_internal",
    "necp_client_copy_parameters",
    "necp_client_copy_result",
    "necp_client_add_flow",
    "necp_client_remove_flow",
    "necp_session_action",
    "necp_session_add_policy",
    "necp_session_remove_policy",
    "necp_client_update_cache",
    "necp_client_update_flows",
    "necp_client_acquire_agent_token",
    "necp_client_agent_use",
    "necp_arena_initialize",
    "necp_destroy_client_flow_registration",
    "necp_create_client_flow_common",
    "necp_client_map_sysctls",
    "necp_client_qualify_flow",
    "necp_client_collect_stats",
    "necp_request_tcp_netstats",
    "necp_request_udp_netstats",
    "necp_request_quic_netstats",
    "necp_request_aop_tcp_netstats",
    "necp_request_aop_quic_netstats",
    "necp_process_defunct_list",
    "necp_client_copy_agent",
    "necp_update_qos_marking",
    "necp_ip_output_find_policy_match",
    "necp_ip6_output_find_policy_match",
    "necp_flow_registration_release",
]

ANCHORS = [
    "necp_client_action",
    "necp_client_copy",
    "necp_client_copy_parameters",
    "necp_client_copy_result",
    "necp_client_add_flow",
    "necp_client_remove_flow",
    "necp_client_update_cache",
    "necp_client_update_flows",
    "necp_client_acquire_agent_token",
    "necp_client_agent_use",
    "necp_session_action",
    "necp_session_add_policy",
    "necp_session_remove_policy",
    "necp_arena_initialize",
    "necp_destroy_client_flow_registration",
    "necp_create_client_flow_common",
    "necp_flow_registration_release",
    "necp_client_qualify_flow",
    "necp_client_copy_agent",
    "necp_process_defunct_list",
    "necp_client",
    "necp_session",
    "necp_arena",
    "necp_flow",
]

PRIORITY_ADDRS = [
    0xfffffff00a4c9c28,
    0xfffffff00a4cbbe8,
    0xfffffff00a4d66f0,
    0xfffffff00a4a1438,
    0xfffffff00a4a18c4,
    0xfffffff00a4cfd58,
    0xfffffff00a4ceb50,
    0xfffffff00a4ce778,
    0xfffffff00a4cec7c,
    0xfffffff00a4cfa0c,
    0xfffffff00a4ca0dc,
    0xfffffff00a4cb6f4,
    0xfffffff00a4cc0fc,
    0xfffffff00a4cd904,
    0xfffffff00a4ce0b4,
    0xfffffff00a4cc43c,
    0xfffffff00a4cd3c4,
    0xfffffff00a4cf704,
    0xfffffff00a4cfd58,
    0xfffffff00a4d0264,
    0xfffffff00a4d05d8,
    0xfffffff00a4d1170,
]

SYMBOLS_JSON_CANDIDATES = [
    SYMBOLS_JSON,
    os.path.expanduser("~/symbols.json"),
    os.path.expanduser("~/natsuk1/symbols.json"),
    "/tmp/symbols.json",
]


def to_unsigned(v):
    return int(v) & 0xFFFFFFFFFFFFFFFF


def to_java_long(v):
    v = to_unsigned(v)
    if v >= 0x8000000000000000:
        v -= 0x10000000000000000
    return int(v)


def fmt_hex(v):
    return "0x{:016X}".format(to_unsigned(v))


def safe_addr(addr):
    try:
        return toAddr(to_java_long(addr))
    except Exception:
        return None


def get_func_at(addr):
    ga = safe_addr(addr)
    if ga is None:
        return None
    try:
        return getFunctionAt(ga)
    except Exception:
        return None


def get_func_containing(addr):
    ga = safe_addr(addr)
    if ga is None:
        return None
    try:
        return getFunctionContaining(ga)
    except Exception:
        return None


def load_symbols_json():
    result = {}
    for p in SYMBOLS_JSON_CANDIDATES:
        if not os.path.exists(p):
            continue
        try:
            with open(p) as f:
                data = json.load(f)
        except Exception:
            continue

        def add(name, addr):
            if not name or addr is None:
                return
            try:
                if isinstance(addr, str):
                    addr_int = int(addr, 16) if addr.startswith(("0x", "0X")) else int(addr, 0)
                else:
                    addr_int = int(addr)
                result[name] = addr_int & 0xFFFFFFFFFFFFFFFF
                if not name.startswith("_"):
                    result["_" + name] = addr_int & 0xFFFFFFFFFFFFFFFF
            except Exception:
                pass

        def walk(node):
            if isinstance(node, dict):
                n = node.get("name") or node.get("symbol")
                a = node.get("address") or node.get("addr") or node.get("value")
                if n and a is not None:
                    add(n, a)
                    return
                for k, v in node.items():
                    if isinstance(v, str) and (v.startswith("0x") or v.startswith("0X")):
                        add(k, v)
                    else:
                        walk(v)
            elif isinstance(node, list):
                for it in node:
                    walk(it)

        walk(data)
        if result:
            print("[+] loaded {} symbols from {}".format(len(result), p))
            return result
    print("[-] no symbols.json found")
    return {}


def sym_addr(name, symbols):
    candidates = []
    if name in symbols:
        candidates.append(symbols[name])
    if "_" + name in symbols:
        candidates.append(symbols["_" + name])

    st = currentProgram.getSymbolTable()
    for bare in (name, "_" + name):
        try:
            for s in st.getSymbols(bare):
                a = to_unsigned(s.getAddress().getOffset())
                if a not in candidates:
                    candidates.append(a)
        except Exception:
            pass

    if not candidates:
        lower = name.lower()
        try:
            it = st.getSymbolIterator(True)
            while it.hasNext():
                s = it.next()
                n = s.getName().lower()
                if n.endswith(lower) or lower in n:
                    a = to_unsigned(s.getAddress().getOffset())
                    if a not in candidates:
                        candidates.append(a)
                    if len(candidates) >= 8:
                        break
        except Exception:
            pass
    return candidates


def scan_strings_for(keywords):
    result = {}
    listing = currentProgram.getListing()
    it = listing.getDefinedData(True)
    while it.hasNext():
        d = it.next()
        try:
            if not d.hasStringValue():
                continue
            val = d.getValue()
            if val is None:
                continue
            s = str(val)
            if any(kw in s for kw in keywords):
                result[s] = to_unsigned(d.getAddress().getOffset())
        except Exception:
            continue
    return result


def find_bytes_ascii(key):
    from ghidra.util.task import ConsoleTaskMonitor
    mem = currentProgram.getMemory()
    results = []
    try:
        pattern = key.encode("ascii")
    except Exception:
        return results
    monitor = ConsoleTaskMonitor()
    try:
        addr = mem.getMinAddress()
    except Exception:
        return results
    while addr is not None:
        try:
            found = mem.findBytes(addr, pattern, None, True, monitor)
        except Exception:
            break
        if found is None:
            break
        results.append(to_unsigned(found.getOffset()))
        try:
            addr = found.add(1)
        except Exception:
            break
        if len(results) >= 16:
            break
    return results


def xrefs_to(addr):
    refs = []
    ga = safe_addr(addr)
    if ga is None:
        return refs
    rm = currentProgram.getReferenceManager()
    try:
        for r in rm.getReferencesTo(ga):
            refs.append(to_unsigned(r.getFromAddress().getOffset()))
    except Exception:
        pass
    return refs


def make_decompiler():
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    ifc = DecompInterface()
    ifc.setOptions(DecompileOptions())
    ifc.openProgram(currentProgram)
    return ifc


def decom_func(func, ifc):
    from ghidra.util.task import ConsoleTaskMonitor
    try:
        r = ifc.decompileFunction(func, DECOM_TIMEOUT, ConsoleTaskMonitor())
        if r.decompileCompleted():
            return r.getDecompiledFunction().getC()
    except Exception:
        pass
    return ""


def ensure_func_at(addr, ifc):
    f = get_func_at(addr)
    if f is None:
        ga = safe_addr(addr)
        if ga:
            try:
                disassemble(ga)
                f = createFunction(ga, None)
            except Exception:
                pass
    if f is None:
        f = get_func_containing(addr)
    return f


def disasm_at(addr, limit=INSTR_LIMIT):
    lines = []
    ga = safe_addr(addr)
    if ga is None:
        return ["  ERROR: bad addr {}".format(fmt_hex(addr))]
    instr = getInstructionAt(ga)
    if instr is None:
        try:
            disassemble(ga)
            instr = getInstructionAt(ga)
        except Exception:
            pass
    if instr is None:
        return ["  no instruction at {}".format(fmt_hex(addr))]
    count = 0
    while instr is not None and count < limit:
        lines.append("  {}  {}".format(
            fmt_hex(to_unsigned(instr.getAddress().getOffset())), instr))
        instr = instr.getNext()
        count += 1
    return lines


def extract_switch_cases(code):
    cases = set()
    for m in re.finditer(r"case\s+(0x[0-9a-fA-F]+|\d+)\s*:", code):
        try:
            v = int(m.group(1), 0)
            if 0 < v < 0x200:
                cases.add(v)
        except Exception:
            pass
    return sorted(cases)


def extract_ldr_offsets(code):
    hits = {}
    pat = re.compile(
        r"\(\s*([A-Za-z_][\w \*]*?)\s*\*\s*\)\s*\(\s*(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)"
    )
    for m in pat.finditer(code):
        try:
            off = int(m.group(3), 0)
            if 0 < off < 0x4000:
                key = off
                if key not in hits:
                    hits[key] = m.group(1).strip()
        except Exception:
            pass
    return hits


def collect_candidates(symbols):
    candidates = {}

    for addr in PRIORITY_ADDRS:
        candidates[addr] = "priority:hardcoded"

    for name in TARGET_SYMS:
        for addr in sym_addr(name, symbols):
            candidates[addr] = "sym:{}".format(name)

    strings = scan_strings_for(ANCHORS)
    print("[*] string hits in defined data: {}".format(len(strings)))

    for s, saddr in strings.items():
        refs = xrefs_to(saddr)
        for xaddr in refs[:MAX_XREFS_PER_STRING]:
            f = get_func_containing(xaddr)
            if f is not None:
                faddr = to_unsigned(f.getEntryPoint().getOffset())
                if faddr not in candidates:
                    candidates[faddr] = "xref:{}".format(repr(s[:48]))
            else:
                if xaddr not in candidates:
                    candidates[xaddr] = "raw_xref:{}".format(repr(s[:48]))

    for key in ("necp_client_action", "necp_client_copy", "necp_client_update_flows",
                "necp_arena_initialize", "necp_client_add_flow", "necp_client_remove_flow"):
        for saddr in find_bytes_ascii(key)[:4]:
            for xaddr in xrefs_to(saddr)[:MAX_XREFS_PER_STRING]:
                f = get_func_containing(xaddr)
                if f is not None:
                    faddr = to_unsigned(f.getEntryPoint().getOffset())
                    if faddr not in candidates:
                        candidates[faddr] = "memscan:{}".format(key)
                else:
                    if xaddr not in candidates:
                        candidates[xaddr] = "memscan_raw:{}".format(key)

    return candidates


def main():
    print("[*] Program: " + currentProgram.getName())
    symbols = load_symbols_json()
    ifc = make_decompiler()

    candidates = collect_candidates(symbols)
    print("[*] total candidate addrs: {}".format(len(candidates)))

    seen = set()
    entries = []

    for addr in PRIORITY_ADDRS:
        f = ensure_func_at(addr, ifc)
        if f is None:
            continue
        fentry = to_unsigned(f.getEntryPoint().getOffset())
        if fentry in seen:
            continue
        seen.add(fentry)
        code = decom_func(f, ifc)
        if code:
            entries.append((fentry, "priority", f.getName(), code))
        else:
            entries.append((fentry, "priority", f.getName(),
                            "\n".join(disasm_at(fentry, INSTR_LIMIT))))

    for addr, label in sorted(candidates.items()):
        if addr in seen:
            continue
        f = ensure_func_at(addr, ifc)
        if f is not None:
            fentry = to_unsigned(f.getEntryPoint().getOffset())
            if fentry in seen:
                continue
            seen.add(fentry)
            code = decom_func(f, ifc)
            if code:
                entries.append((fentry, label, f.getName(), code))
            else:
                entries.append((fentry, label, f.getName(),
                                "\n".join(disasm_at(fentry, INSTR_LIMIT))))
        else:
            if addr in seen:
                continue
            seen.add(addr)
            entries.append((addr, label, "???",
                            "\n".join(disasm_at(addr, INSTR_LIMIT))))

    print("[*] entries to write: {}".format(len(entries)))

    with open(OUT_PATH, "w") as out:
        out.write("=== NECP DEEP DECOM REPORT ===\n")
        out.write("Program: {}\n".format(currentProgram.getName()))
        out.write("SymbolsLoaded: {}\n".format(len(symbols)))
        out.write("Entries: {}\n\n".format(len(entries)))

        for (addr, label, fname, body) in entries:
            out.write("=" * 16 + " {} ".format(fmt_hex(addr)) + "=" * 16 + "\n")
            out.write("label  : {}\n".format(label))
            out.write("func   : {}\n".format(fname))

            cases = extract_switch_cases(body)
            if cases:
                out.write("switch : " + ", ".join(["0x{:x}".format(c) for c in cases]) + "\n")

            offsets = extract_ldr_offsets(body)
            if offsets:
                out.write("fields :\n")
                for off in sorted(offsets.keys()):
                    out.write("  +0x{:x}  ({})\n".format(off, offsets[off]))

            out.write("-" * 60 + "\n")
            out.write(body)
            if not body.endswith("\n"):
                out.write("\n")
            out.write("\n")
            out.flush()

        out.write("=== DONE ===\n")

    print("[*] wrote: " + OUT_PATH)


main()
