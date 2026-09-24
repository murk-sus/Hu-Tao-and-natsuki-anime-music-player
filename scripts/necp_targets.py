# -*- coding: utf-8 -*-

import os
import re
import json

WORKSPACE = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT_PATH = os.path.join(WORKSPACE, "necp_targets.txt")
SYMBOLS_JSON = os.path.join(WORKSPACE, "symbols.json")

DECOM_TIMEOUT = 120

TARGETS = [
    (0xfffffff00a4e5c28, "necp_client_action_dispatcher"),
    (0xfffffff00a4e60dc, "case_1_add_client"),
    (0xfffffff00a4e76f4, "case_2_remove_client"),
    (0xfffffff00a4e7be8, "case_3_4_16_1a_copy"),
    (0xfffffff00a4e80fc, "case_5_copy_list"),
    (0xfffffff00a4e9904, "case_6"),
    (0xfffffff00a4ea0b4, "case_7"),
    (0xfffffff00a4ea778, "case_8_copy_agent"),
    (0xfffffff00a4eac7c, "case_9_copy_interface"),
    (0xfffffff00a4eba0c, "case_b_copy_route_stats"),
    (0xfffffff00a4ebd58, "case_e_update_cache"),
    (0xfffffff00a4e843c, "case_11_add_flow"),
    (0xfffffff00a4e93c4, "case_12_remove_flow"),
    (0xfffffff00a4e7158, "case_13"),
    (0xfffffff00a4eab50, "case_16_acquire_agent_token"),
    (0xfffffff00a4ed170, "case_1b"),
    (0xfffffff00a4d66f0, "necp_client_copy_internal"),
    (0xfffffff00a4f2e70, "necp_client_copy"),
    (0xfffffff00a4db8d4, "necp_find_client_by_uuid"),
    (0xfffffff00a4bf8d4, "necp_find_client_by_uuid_2"),
    (0xfffffff00a4db9f0, "necp_create_flow"),
    (0xfffffff00a4dd078, "necp_flow_alloc"),
    (0xfffffff00a4e19b4, "netagent_flow_install"),
    (0xfffffff00a4daac8, "necp_flow_list_remove"),
    (0xfffffff00a4db38c, "necp_flow_list_add"),
    (0xfffffff00a4e2e0c, "necp_flow_free"),
    (0xfffffff00a4e3278, "necp_flow_registration_release"),
    (0xfffffff00a4e575c, "necp_flow_unregister"),
    (0xfffffff00a200988, "kalloc_type_wrapper"),
    (0xfffffff00a201000, "kfree_type_wrapper"),
    (0xfffffff00a368ec0, "copyin_wrapper"),
    (0xfffffff00a369a3c, "copyout_wrapper"),
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


def load_symbols_json():
    for p in SYMBOLS_JSON_CANDIDATES:
        try:
            if not os.path.exists(p) or os.path.getsize(p) < 1000:
                continue
            with open(p) as f:
                data = json.load(f)
            if not isinstance(data, dict):
                continue
            rev = {}
            for k, v in data.items():
                try:
                    addr = int(k, 10)
                    if 0xfffffff000000000 <= addr <= 0xffffffffffffffff:
                        rev[addr] = v
                except Exception:
                    continue
            if rev:
                print("[+] loaded {} addr->name entries".format(len(rev)))
                return rev
        except Exception:
            continue
    print("[-] symbols.json not found")
    return {}


def safe_addr(addr):
    try:
        return toAddr(to_java_long(addr))
    except Exception:
        return None


def ensure_func(addr):
    ga = safe_addr(addr)
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


def decompile(func):
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.util.task import ConsoleTaskMonitor
    ifc = DecompInterface()
    ifc.setOptions(DecompileOptions())
    ifc.openProgram(currentProgram)
    res = ifc.decompileFunction(func, DECOM_TIMEOUT, ConsoleTaskMonitor())
    if not res.decompileCompleted():
        return ""
    return res.getDecompiledFunction().getC()


def extract_case_values(code):
    cases = set()
    for m in re.finditer(r"case\s+(0x[0-9a-fA-F]+|\d+)\s*:", code):
        try:
            v = int(m.group(1), 0)
            if 0 < v < 0x1000:
                cases.add(v)
        except Exception:
            pass
    return sorted(cases)


def extract_switch_targets(code):
    pairs = []
    for m in re.finditer(
        r"case\s+(0x[0-9a-fA-F]+|\d+)\s*:.*?(?:return|=\s*)"
        r"\s*(?:FUN_|func_)?([0-9a-fA-F]{12,16})",
        code, re.DOTALL
    ):
        try:
            case = int(m.group(1), 0)
            tgt = int(m.group(2), 16)
            if 0 < case < 0x1000 and 0xfffffff000000000 <= tgt <= 0xffffffffffffffff:
                pairs.append((case, tgt))
        except Exception:
            pass
    return pairs


def extract_ldr_offsets(code):
    hits = []
    seen = set()
    pat = re.compile(
        r"\(\s*([A-Za-z_][\w \*]*?)\s*\*\s*\)\s*\(\s*(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)"
    )
    for m in pat.finditer(code):
        try:
            off = int(m.group(3), 0)
            var = m.group(2)
            typ = m.group(1).strip()
            if 0 < off < 0x4000 and off not in seen:
                seen.add(off)
                hits.append((off, var, typ))
        except Exception:
            pass
    return sorted(hits)


def extract_kalloc_calls(code):
    calls = []
    for m in re.finditer(
        r"(FUN_[0-9a-fA-F]{12,16})\s*\(\s*([^)]*)\)",
        code
    ):
        fn = m.group(1)
        args = m.group(2)
        if "DAT_fffffff007c6" in args or "DAT_fffffff007c5" in args:
            calls.append((fn, args.strip()))
    return calls


def extract_string_refs(code):
    refs = set()
    for m in re.finditer(r'"([^"\\]{4,120})"', code):
        s = m.group(1)
        if "necp" in s.lower() or "kalloc" in s.lower() or "zone" in s.lower():
            refs.add(s)
    return sorted(refs)


def main():
    print("[*] program: " + currentProgram.getName())
    rev = load_symbols_json()

    out = open(OUT_PATH, "w")
    try:
        out.write("=== NECP TARGET DECOMP REPORT ===\n")
        out.write("Program: {}\n\n".format(currentProgram.getName()))

        for addr, label in TARGETS:
            func = ensure_func(addr)
            header = "\n" + "=" * 24 + " {}  {} ".format(fmt_hex(addr), label) + "=" * 24 + "\n"
            print(header.strip())
            out.write(header)

            named = None
            for delta in range(-0x20, 0x40, 4):
                k = to_unsigned(addr + delta)
                if k in rev:
                    named = rev[k]
                    break
            if named:
                out.write("symbol : {}\n".format(named))
                print("  symbol: {}".format(named))

            if func is None:
                out.write("function: NOT FOUND\n")
                print("  function: NOT FOUND")
                continue

            entry = to_unsigned(func.getEntryPoint().getOffset())
            out.write("entry  : {}\n".format(fmt_hex(entry)))
            out.write("size   : {} bytes\n".format(func.getBody().getNumAddresses()))

            code = decompile(func)
            if not code:
                out.write("decompile: FAILED\n")
                print("  decompile FAILED")
                continue

            cases = extract_case_values(code)
            if cases:
                out.write("cases  : " + ", ".join("0x{:x}".format(c) for c in cases) + "\n")
                print("  cases: " + ", ".join("0x{:x}".format(c) for c in cases))

            sw = extract_switch_targets(code)
            if sw:
                out.write("switches:\n")
                for c, t in sw:
                    out.write("  0x{:02x} -> {}\n".format(c, fmt_hex(t)))
                    print("  0x{:02x} -> {}".format(c, fmt_hex(t)))

            ldrs = extract_ldr_offsets(code)
            if ldrs:
                out.write("fields :\n")
                for off, var, typ in ldrs[:80]:
                    out.write("  +0x{:x}  [{}]  ({})\n".format(off, var, typ))
                print("  fields: {} unique offsets".format(len(ldrs)))

            kalls = extract_kalloc_calls(code)
            if kalls:
                out.write("alloc_calls:\n")
                for fn, args in kalls[:20]:
                    out.write("  {} ({})\n".format(fn, args))
                print("  alloc calls: {}".format(len(kalls)))

            strings = extract_string_refs(code)
            if strings:
                out.write("strings:\n")
                for s in strings[:40]:
                    out.write("  \"{}\"\n".format(s))

            out.write("--- decompiled ---\n")
            out.write(code)
            if not code.endswith("\n"):
                out.write("\n")
            out.write("\n")
            out.flush()

        out.write("\n=== DONE ===\n")
    finally:
        out.close()

    print("[*] wrote: " + OUT_PATH)


main()
