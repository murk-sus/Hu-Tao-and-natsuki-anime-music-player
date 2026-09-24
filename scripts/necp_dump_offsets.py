# -*- coding: utf-8 -*-

import os
import re
import json

WORKSPACE = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT_PATH = os.path.join(WORKSPACE, "necp_offsets.h")
REPORT_PATH = os.path.join(WORKSPACE, "necp_offsets_report.txt")
SYMBOLS_JSON = os.path.join(WORKSPACE, "symbols.json")

DECOM_TIMEOUT = 120
MAX_OFFSET = 0x1000

TARGETS = [
    (0xfffffff00a4e5c28, "dispatcher", "generic"),
    (0xfffffff00a4e60dc, "necp_client_add", "client"),
    (0xfffffff00a4e76f4, "necp_client_remove", "client"),
    (0xfffffff00a4e7be8, "necp_client_copy_dispatch", "client"),
    (0xfffffff00a4e80fc, "necp_client_list", "client"),
    (0xfffffff00a4e843c, "necp_client_add_flow", "both"),
    (0xfffffff00a4e93c4, "necp_client_remove_flow", "both"),
    (0xfffffff00a4ea0b4, "necp_client_agent_action", "client"),
    (0xfffffff00a4ea778, "necp_client_copy_agent", "generic"),
    (0xfffffff00a4eac7c, "necp_client_copy_interface", "generic"),
    (0xfffffff00a4eba0c, "necp_client_copy_route_stats", "client"),
    (0xfffffff00a4ebd58, "necp_client_update_cache", "both"),
    (0xfffffff00a4ed170, "necp_client_get_flow_statistics", "flow"),
    (0xfffffff00a4d66f0, "necp_client_copy_internal", "client"),
    (0xfffffff00a4f2e70, "necp_client_fillout_flow_tlvs", "flow"),
    (0xfffffff00a4db9f0, "necp_create_flow", "flow"),
    (0xfffffff00a4dd078, "necp_flow_alloc", "generic"),
    (0xfffffff00a4e3278, "necp_flow_registration_release", "client"),
    (0xfffffff00a4e575c, "necp_destroy_client_flow_registration", "flow"),
    (0xfffffff00a4db8d4, "necp_find_client_by_uuid", "client"),
    (0xfffffff00a4daac8, "necp_flow_list_remove", "generic"),
    (0xfffffff00a4db38c, "necp_flow_list_add", "generic"),
]

ACTION_CODES = [
    ("NECP_ACTION_ADD_CLIENT", 0x01),
    ("NECP_ACTION_REMOVE_CLIENT", 0x02),
    ("NECP_ACTION_COPY_RESULT", 0x03),
    ("NECP_ACTION_COPY_PARAMETERS", 0x04),
    ("NECP_ACTION_COPY_LIST", 0x05),
    ("NECP_ACTION_COPY_AGENT", 0x06),
    ("NECP_ACTION_COPY_INTERFACE", 0x07),
    ("NECP_ACTION_COPY_AGENT_2", 0x08),
    ("NECP_ACTION_COPY_INTERFACE_2", 0x09),
    ("NECP_ACTION_COPY_ROUTE_STATS", 0x0b),
    ("NECP_ACTION_UNKNOWN_0C", 0x0c),
    ("NECP_ACTION_UNKNOWN_0D", 0x0d),
    ("NECP_ACTION_UPDATE_CACHE", 0x0e),
    ("NECP_ACTION_UNKNOWN_0F", 0x0f),
    ("NECP_ACTION_COPY_RESULT_16", 0x10),
    ("NECP_ACTION_ADD_FLOW", 0x11),
    ("NECP_ACTION_REMOVE_FLOW", 0x12),
    ("NECP_ACTION_CLAIM", 0x13),
    ("NECP_ACTION_UNKNOWN_14", 0x14),
    ("NECP_ACTION_UNKNOWN_15", 0x15),
    ("NECP_ACTION_ACQUIRE_AGENT_TOKEN", 0x16),
    ("NECP_ACTION_UNKNOWN_17", 0x17),
    ("NECP_ACTION_UNKNOWN_18", 0x18),
    ("NECP_ACTION_UNKNOWN_19", 0x19),
    ("NECP_ACTION_COPY_RESULT_1A", 0x1a),
    ("NECP_ACTION_GET_FLOW_STATS", 0x1b),
]

HANDLERS = {
    0x01: 0xfffffff00a4e60dc,
    0x02: 0xfffffff00a4e76f4,
    0x03: 0xfffffff00a4e7be8,
    0x04: 0xfffffff00a4e7be8,
    0x05: 0xfffffff00a4e80fc,
    0x06: 0xfffffff00a4e9904,
    0x07: 0xfffffff00a4ea0b4,
    0x08: 0xfffffff00a4ea778,
    0x09: 0xfffffff00a4eac7c,
    0x0b: 0xfffffff00a4eba0c,
    0x0c: 0xfffffff00a4ea8a0,
    0x0d: 0xfffffff00a4eb704,
    0x0e: 0xfffffff00a4ebd58,
    0x0f: 0xfffffff00a4ec264,
    0x10: 0xfffffff00a4e7be8,
    0x11: 0xfffffff00a4e843c,
    0x12: 0xfffffff00a4e93c4,
    0x13: 0xfffffff00a4e7158,
    0x14: 0xfffffff00a4ec5d8,
    0x15: 0xfffffff00a4eb2b4,
    0x16: 0xfffffff00a4eab50,
    0x17: 0xfffffff00a4ec9ec,
    0x18: 0xfffffff00a4ecc4c,
    0x19: 0xfffffff00a4ece88,
    0x1a: 0xfffffff00a4e7be8,
    0x1b: 0xfffffff00a4ed170,
}

ZONE_POINTERS = {
    "NCC_ZONE": 0xfffffff007c6a2b0,
    "NCF_REG_ZONE": 0xfffffff007c69ff0,
    "NECP_GEN_ZONE": 0xfffffff007c62e68,
}

KNOWN_CONSTANTS = {
    "NCC_RESULTS_LEN_OFF": 0x5a0,
    "NCC_RESULTS_PTR_OFF": 0x5a8,
    "NCC_FLOWS_ROOT_OFF": 0x4a0,
    "NCC_REFCOUNT_OFF": 0x38,
    "NCC_LOCK_OFF": 0x50,
    "NCC_PID_OFF": 0x4c,
    "NCC_CUR_PID_OFF": 0x58,
    "NCC_FLAGS_OFF": 0x74,
    "NCC_OWNER_PROC_OFF": 0x550,
    "NCC_HEADER_LEN_OFF": 0x68,
    "NCC_NEXUS_COUNT_OFF": 0x538,
    "NCC_GROUP_LEN_OFF": 0x4b0,
    "NCC_GROUP_PTR_OFF": 0x4b8,
    "NCC_NEXUS_STATS_OFF": 0x4c0,
    "NCF_UUID_OFF": 0x5c,
    "NCF_TYPE_OFF": 0x61,
    "NCF_FLAGS_OFF": 0x74,
    "NCF_PARENT_OFF": 0x88,
    "NCF_RESULTS_HEAD_OFF": 0x90,
    "NCF_RESULTS_LEN_OFF": 0xa0,
    "NCF_RESULTS_PTR_OFF": 0xa8,
    "NCF_NEXT_OFF": 0x00,
    "NCF_PREV_OFF": 0x08,
    "NCF_RB_RIGHT_OFF": 0x18,
    "NCF_RB_LEFT_OFF": 0x20,
    "NCF_RB_PARENT_OFF": 0x28,
    "NFR_REFCOUNT_OFF": 0x38,
    "NFR_LOCK_OFF": 0x30,
    "NFR_REG_COUNT_OFF": 0x50,
    "NFR_PARENT_OFF": 0x88,
    "NFR_RESULTS_LEN_OFF": 0x5a0,
    "NFR_RESULTS_PTR_OFF": 0x5a8,
    "NFR_GROUP_LEN_OFF": 0x4b0,
    "NFR_GROUP_PTR_OFF": 0x4b8,
    "NFR_ALLOC_SIZE": 0x2a0,
    "NCC_ALLOC_SIZE": 0x8000,
}

TYPE_TCP = 0x02
TYPE_UDP = 0x1e


def fmt_hex(v):
    return "0x{:016X}".format(v & 0xFFFFFFFFFFFFFFFF)


def to_java_long(v):
    v = int(v) & 0xFFFFFFFFFFFFFFFF
    if v >= 0x8000000000000000:
        v -= 0x10000000000000000
    return v


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


def extract_all_offsets(code):
    hits = {}
    patterns = [
        re.compile(r"\(\s*([A-Za-z_][\w \*]*?)\s*\*\s*\)\s*\(\s*(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)"),
        re.compile(r"\*\s*\(\s*[A-Za-z_][\w \*]*?\s*\*\s*\)\s*\(\s*(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)"),
    ]
    for pat in patterns:
        for m in pat.finditer(code):
            try:
                groups = m.groups()
                if len(groups) == 3:
                    off_str = groups[2]
                    var = groups[1]
                    typ = groups[0].strip()
                elif len(groups) == 2:
                    off_str = groups[1]
                    var = groups[0]
                    typ = "unknown"
                else:
                    continue
                off = int(off_str, 0)
                if 0 < off < MAX_OFFSET:
                    if off not in hits:
                        hits[off] = set()
                    hits[off].add((var, typ))
            except Exception:
                continue
    return hits


def extract_kalloc_sizes(code):
    sizes = []
    for m in re.finditer(r"FUN_fffffff00a(200988|20141c|201000)\s*\(([^)]*)\)", code):
        args = m.group(2)
        for num in re.finditer(r"0x([0-9a-fA-F]{1,6})", args):
            try:
                v = int(num.group(1), 16)
                if 0x10 < v < 0x20000:
                    sizes.append(v)
            except Exception:
                pass
    return sorted(set(sizes))


def main():
    print("[*] program: " + currentProgram.getName())
    print("[*] targets: {}".format(len(TARGETS)))

    all_offsets = {}
    per_function = {}
    alloc_sizes = set()
    decompiled_count = 0

    for addr, label, typ in TARGETS:
        f = ensure_func(addr)
        if f is None:
            print("[-] {} not found".format(label))
            continue
        code = decompile(f)
        if not code:
            print("[-] {} decompile failed".format(label))
            continue
        decompiled_count += 1
        offs = extract_all_offsets(code)
        per_function[label] = offs
        for off, entries in offs.items():
            if off not in all_offsets:
                all_offsets[off] = set()
            for e in entries:
                all_offsets[off].add(e)
        for s in extract_kalloc_sizes(code):
            alloc_sizes.add(s)
        print("[+] {} — {} offsets".format(label, len(offs)))

    print("[*] decompiled {} / {}".format(decompiled_count, len(TARGETS)))

    with open(REPORT_PATH, "w") as rep:
        rep.write("=== NECP OFFSETS REPORT ===\n")
        rep.write("Program: {}\n".format(currentProgram.getName()))
        rep.write("Functions decompiled: {}/{}\n\n".format(decompiled_count, len(TARGETS)))
        rep.write("=== ALL OFFSETS (sorted) ===\n")
        for off in sorted(all_offsets.keys()):
            entries = all_offsets[off]
            vars_seen = set()
            for var, typ in entries:
                if var not in vars_seen:
                    vars_seen.add(var)
            rep.write("+0x{:03x}  ({} hits)  vars: {}\n".format(
                off, len(entries), ", ".join(sorted(vars_seen)[:8])))
        rep.write("\n=== ALLOC SIZES ===\n")
        for s in sorted(alloc_sizes):
            rep.write("0x{:x}  ({})\n".format(s, s))
        rep.write("\n=== PER FUNCTION ===\n")
        for label, offs in per_function.items():
            rep.write("\n-- {} ({} offsets) --\n".format(label, len(offs)))
            for off in sorted(offs.keys()):
                rep.write("  +0x{:03x}\n".format(off))

    with open(OUT_PATH, "w") as out:
        out.write("#pragma once\n\n")
        out.write("// auto-generated for kernelcache.release.iPhone14,5 (iOS 24A437)\n")
        out.write("// program: {}\n".format(currentProgram.getName()))
        out.write("// functions decompiled: {}/{}\n\n".format(decompiled_count, len(TARGETS)))

        out.write("// ===== action codes =====\n")
        for name, val in ACTION_CODES:
            out.write("#define {:<40} 0x{:02x}\n".format(name, val))
        out.write("\n")

        out.write("// ===== handler addresses (unslid) =====\n")
        for code_v, addr in sorted(HANDLERS.items()):
            out.write("#define NECP_HANDLER_0x{:02x}{:<27} {}\n".format(
                code_v, "", fmt_hex(addr)))
        out.write("\n")

        out.write("// ===== zone pointers (unslid) =====\n")
        for name, addr in ZONE_POINTERS.items():
            out.write("#define {:<40} {}\n".format(name, fmt_hex(addr)))
        out.write("\n")

        out.write("// ===== known constants =====\n")
        for name, val in sorted(KNOWN_CONSTANTS.items()):
            if val > 0xff:
                out.write("#define {:<40} 0x{:x}\n".format(name, val))
            else:
                out.write("#define {:<40} 0x{:02x}\n".format(name, val))
        out.write("\n")

        out.write("// ===== flow types =====\n")
        out.write("#define NCF_TYPE_TCP                             0x{:02x}\n".format(TYPE_TCP))
        out.write("#define NCF_TYPE_UDP                             0x{:02x}\n".format(TYPE_UDP))
        out.write("\n")

        out.write("// ===== raw offsets extracted from decompiled functions =====\n")
        out.write("// fields: +0xNN with hit count\n")
        for off in sorted(all_offsets.keys()):
            entries = all_offsets[off]
            out.write("// +0x{:03x}   ({} refs)\n".format(off, len(entries)))
        out.write("\n")

        out.write("// ===== alloc sizes =====\n")
        for s in sorted(alloc_sizes):
            out.write("// 0x{:x}  = {} bytes\n".format(s, s))

    print("[*] wrote: " + OUT_PATH)
    print("[*] wrote: " + REPORT_PATH)


main()
