# -*- coding: utf-8 -*-

import os
import re
import json

WORKSPACE = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT_PATH = os.path.join(WORKSPACE, "necp_decom.txt")
SYMBOLS_JSON = os.path.join(WORKSPACE, "symbols.json")

DECOM_TIMEOUT = 60
INSTR_LIMIT = 200
MAX_XREFS_PER_STRING = 4

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
    0xfffffff00a4d0264,
    0xfffffff00a4d05d8,
    0xfffffff00a4d1170,
    0xfffffff00a4ce8a0,
    0xfffffff00a4cf2b4,
    0xfffffff00a4d09ec,
    0xfffffff00a4d0c4c,
    0xfffffff00a4d0e88,
]

TARGET_STRINGS = [
    "necp_client_action",
    "necp_client_copy",
    "necp_client_add_flow",
    "necp_client_remove_flow",
    "necp_client_update_cache",
    "necp_client_update_flows",
    "necp_client_acquire_agent_token",
    "necp_session_action",
    "necp_session_add_policy",
    "necp_arena_initialize",
]

SYMBOLS_JSON_CANDIDATES = [
    SYMBOLS_JSON,
    "/tmp/symbols.json",
    os.path.expanduser("~/symbols.json"),
    "/home/runner/symbols.json",
]


def to_unsigned(v):
    return int(v) & 0xFFFFFFFFFFFFFFFF


def to_java_long(v):
    v = int(v) & 0xFFFFFFFFFFFFFFFF
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
        try:
            if not os.path.exists(p) or os.path.getsize(p) < 1000:
                continue
        except Exception:
            continue
        try:
            with open(p) as f:
                data = json.load(f)
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        for k, v in data.items():
            try:
                if not isinstance(k, str) or not isinstance(v, str):
                    continue
                addr = int(k, 10)
                if addr < 0xfffffff000000000 or addr > 0xffffffffffffffff:
                    continue
                name = v.strip()
                if not name or len(name) > 200:
                    continue
                result[name] = addr & 0xFFFFFFFFFFFFFFFF
                if not name.startswith("_"):
                    result["_" + name] = addr & 0xFFFFFFFFFFFFFFFF
            except Exception:
                continue
        if result:
            print("[+] necp: loaded {} symbols".format(len(result)))
            return result
    return result


def sym_lookup(name, symbols):
    if name in symbols:
        return symbols[name]
    if "_" + name in symbols:
        return symbols["_" + name]
    return None


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


def scan_strings():
    result = {}
    listing = currentProgram.getListing()
    it = listing.getDefinedData(True)
    while it.hasNext():
        d = it.next()
        if d.hasStringValue():
            try:
                val = d.getValue()
                if val is not None:
                    result[str(val)] = to_unsigned(d.getAddress().getOffset())
            except Exception:
                pass
    return result


def find_xrefs_to(addr):
    refs = []
    rm = currentProgram.getReferenceManager()
    ga = safe_addr(addr)
    if ga is None:
        return refs
    try:
        for r in rm.getReferencesTo(ga):
            refs.append(to_unsigned(r.getFromAddress().getOffset()))
    except Exception:
        pass
    return refs


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
            if 0 < off < 0x4000 and off not in hits:
                hits[off] = m.group(1).strip()
        except Exception:
            pass
    return hits


def main():
    print("[*] necp_extract: program " + currentProgram.getName())
    symbols = load_symbols_json()
    ifc = make_decompiler()

    strings = scan_strings()
    print("[*] necp: total strings {}".format(len(strings)))

    candidates = {}

    for addr in PRIORITY_ADDRS:
        candidates[addr] = "priority"

    for name in TARGET_STRINGS:
        a = sym_lookup(name, symbols)
        if a is not None:
            candidates[a] = "sym:{}".format(name)

    for name in TARGET_STRINGS:
        for s, saddr in strings.items():
            if name in s:
                for x in find_xrefs_to(saddr)[:MAX_XREFS_PER_STRING]:
                    f = get_func_containing(x)
                    if f is not None:
                        fa = to_unsigned(f.getEntryPoint().getOffset())
                        candidates[fa] = "str:{}".format(name)
                break

    print("[*] necp: {} candidates".format(len(candidates)))

    seen = set()
    results = []

    for addr, label in sorted(candidates.items()):
        f = ensure_func_at(addr, ifc)
        if f is None:
            continue
        entry = to_unsigned(f.getEntryPoint().getOffset())
        if entry in seen:
            continue
        seen.add(entry)
        code = decom_func(f, ifc)
        if not code:
            continue
        results.append((entry, label, f.getName(), code))

    with open(OUT_PATH, "w") as out:
        out.write("=== NECP DECOM REPORT ===\n")
        out.write("Program: {}\n".format(currentProgram.getName()))
        out.write("Entries: {}\n\n".format(len(results)))

        for entry, label, fname, code in results:
            out.write("=" * 16 + " {} ".format(fmt_hex(entry)) + "=" * 16 + "\n")
            out.write("label : {}\n".format(label))
            out.write("func  : {}\n".format(fname))

            cases = extract_switch_cases(code)
            if cases:
                out.write("switch: " + ", ".join(["0x{:x}".format(c) for c in cases]) + "\n")

            offsets = extract_ldr_offsets(code)
            if offsets:
                out.write("fields:\n")
                for off in sorted(offsets.keys()):
                    out.write("  +0x{:x}  ({})\n".format(off, offsets[off]))

            out.write("-" * 60 + "\n")
            out.write(code)
            if not code.endswith("\n"):
                out.write("\n")
            out.write("\n")

        out.write("=== DONE ===\n")

    print("[*] necp: wrote {} ({})".format(OUT_PATH, len(results)))


main()