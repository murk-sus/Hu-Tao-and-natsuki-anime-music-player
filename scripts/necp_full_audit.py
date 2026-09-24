# -*- coding: utf-8 -*-

import os
import re
import json

WORKSPACE = os.environ.get("GITHUB_WORKSPACE", "/tmp")
ZONES_OUT = os.path.join(WORKSPACE, "necp_zones.txt")
SIZE_OUT = os.path.join(WORKSPACE, "necp_sizes.txt")
UAF_OUT = os.path.join(WORKSPACE, "necp_uaf.txt")
STRINGS_OUT = os.path.join(WORKSPACE, "necp_strings.txt")

DECOM_TIMEOUT = 120

ZONE_POINTERS = {
    "NCC_ZONE": 0xfffffff007c6a2b0,
    "NFR_ZONE": 0xfffffff007c69ff0,
    "NECP_GEN": 0xfffffff007c62e68,
    "NECP_AUX": 0xfffffff007c6a0f0,
    "NECP_REG_AUX": 0xfffffff007c6a530,
    "NECP_NAI": 0xfffffff007c6a270,
    "KALLOC_DEF": 0xfffffff007c1ff68,
    "KALLOC_DATA": 0xfffffff007bc27f8,
}

KALLOC_SITES = [
    (0xfffffff00a4e60dc, "necp_client_add"),
    (0xfffffff00a4db9f0, "necp_create_flow"),
    (0xfffffff00a4e843c, "necp_client_add_flow"),
    (0xfffffff00a4e93c4, "necp_client_remove_flow"),
    (0xfffffff00a4e575c, "destroy_client_flow_registration"),
    (0xfffffff00a4e3278, "flow_registration_release"),
]

UAF_TARGETS = [
    (0xfffffff00a4e5284, "necp_client_destroy_internal"),
    (0xfffffff00a4e2e0c, "necp_flow_free"),
    (0xfffffff00a4e2b2c, "necp_nai_release"),
    (0xfffffff00a4e76f4, "necp_client_remove"),
    (0xfffffff00a4e93c4, "necp_client_remove_flow"),
    (0xfffffff00a4e575c, "destroy_client_flow_registration"),
]

KALLOC_FUNCS = [
    ("FUN_fffffff00a20141c", 2),
    ("FUN_fffffff00a200988", 2),
    ("FUN_fffffff00a200b68", 2),
    ("_kalloc_type", 2),
    ("_kalloc_ext", 2),
]

STRLIT_PATTERNS = [
    "necp", "zone", "flow", "client", "nexus", "netagent",
    "kalloc", "kfree", "nai", "registration",
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


def get_xrefs_to(a):
    out = []
    ga = safe_addr(a)
    if ga is None:
        return out
    rm = currentProgram.getReferenceManager()
    try:
        it = rm.getReferencesTo(ga)
        for r in it:
            out.append(to_unsigned(r.getFromAddress().getOffset()))
    except Exception:
        pass
    return out


def to_unsigned(v):
    return int(v) & 0xFFFFFFFFFFFFFFFF


def string_at(a):
    try:
        ga = safe_addr(a)
        d = getDataAt(ga)
        if d is not None and d.hasStringValue():
            v = d.getValue()
            if v is not None:
                return str(v)
    except Exception:
        pass
    return None


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


def scan_zone_pointer(ptr, name, output):
    output.write("\n=== {} @ {} ===\n".format(name, fmt_hex(ptr)))
    refs = get_xrefs_to(ptr)
    output.write("xrefs: {}\n".format(len(refs)))

    candidates = set()

    for ref in refs:
        output.write("  <- {} ".format(fmt_hex(ref)))
        f = None
        try:
            f = getFunctionContaining(safe_addr(ref))
        except Exception:
            pass
        if f is None:
            output.write("(no func)\n")
            continue
        fentry = to_unsigned(f.getEntryPoint().getOffset())
        output.write("in {} ({})\n".format(f.getName(), fmt_hex(fentry)))

        code = decompile(f)
        if not code:
            continue
        for m in re.finditer(r'"([^"\\]{3,120})"', code):
            s = m.group(1)
            low = s.lower()
            if any(p in low for p in STRLIT_PATTERNS):
                candidates.add((fentry, f.getName(), s))

        for m in re.finditer(r"(DAT_[0-9a-f]+|_DAT_[0-9a-f]+)", code):
            pass

    output.write("string candidates:\n")
    for fentry, fname, s in sorted(candidates):
        output.write("  {}  \"{}\"\n".format(fname, s))

    return candidates


def find_zone_names_global(output):
    strings = scan_strings()
    hits = []
    for s, addr in strings.items():
        low = s.lower()
        if "necp" in low and len(s) < 80:
            hits.append((addr, s))
        elif ("client" in low or "flow" in low or "nexus" in low) and "zone" in low:
            hits.append((addr, s))
    output.write("\n=== ALL 'necp' STRINGS IN KERNELCACHE ===\n")
    for addr, s in sorted(hits):
        output.write("  {}  \"{}\"\n".format(fmt_hex(addr), s))
    return hits


def scan_kalloc_sites(output):
    for addr, label in KALLOC_SITES:
        f = ensure_func(addr)
        if f is None:
            output.write("[-] {} not found\n".format(label))
            continue
        code = decompile(f)
        if not code:
            continue
        output.write("\n=== {} ({}) ===\n".format(label, fmt_hex(addr)))

        for line in code.splitlines():
            for func_name, arg_idx in KALLOC_FUNCS:
                if func_name in line:
                    output.write("  call: {}\n".format(line.strip()))

        for m in re.finditer(r"FUN_fffffff00a(20141c|200988|200b68)\s*\(([^;]*?)\)", code):
            output.write("  alloc site: {}\n".format(m.group(0)[:200]))

        insn = getInstructionAt(safe_addr(addr))
        if insn is None:
            continue
        cnt = 0
        while insn is not None and cnt < 5000:
            mn = insn.getMnemonicString()
            if mn == "bl":
                op = insn.toString()
                if any(k[0] in op for k in KALLOC_FUNCS):
                    output.write("  BL {}  (at {})\n".format(
                        op, fmt_hex(to_unsigned(insn.getAddress().getOffset()))))
                    prev = insn.getPrevious()
                    for _ in range(8):
                        if prev is None:
                            break
                        pm = prev.getMnemonicString()
                        if pm in ("mov", "movz", "movk", "orr"):
                            pstr = prev.toString()
                            if "x1" in pstr or "w1" in pstr:
                                output.write("    setup: {}\n".format(pstr))
                        prev = prev.getPrevious()
            insn = insn.getNext()
            cnt += 1


def scan_uaf_targets(output):
    for addr, label in UAF_TARGETS:
        f = ensure_func(addr)
        if f is None:
            output.write("\n=== {} @ {} NOT FOUND ===\n".format(label, fmt_hex(addr)))
            continue
        code = decompile(f)
        if not code:
            continue
        output.write("\n=== {} ({}) ===\n".format(label, fmt_hex(addr)))
        output.write("size: {} bytes\n".format(f.getBody().getNumAddresses()))

        for line in code.splitlines():
            if "kfree" in line.lower() or "FUN_fffffff00a201000" in line or \
               "free" in line.lower() or "release" in line.lower() or "destroy" in line.lower():
                output.write("  {}\n".format(line.strip()))

        output.write("\n--- full decompile ---\n")
        output.write(code)
        output.write("\n")


def main():
    print("[*] program: " + currentProgram.getName())

    with open(ZONES_OUT, "w") as z:
        z.write("=== NECP ZONE NAME SEARCH ===\n")
        z.write("Program: {}\n".format(currentProgram.getName()))
        for name, ptr in ZONE_POINTERS.items():
            scan_zone_pointer(ptr, name, z)
        find_zone_names_global(z)

    with open(SIZE_OUT, "w") as s:
        s.write("=== NECP ALLOC SIZE SEARCH ===\n")
        s.write("Program: {}\n\n".format(currentProgram.getName()))
        scan_kalloc_sites(s)

    with open(UAF_OUT, "w") as u:
        u.write("=== NECP UAF TARGET ANALYSIS ===\n")
        u.write("Program: {}\n".format(currentProgram.getName()))
        scan_uaf_targets(u)

    with open(STRINGS_OUT, "w") as st:
        st.write("=== NECP RELATED STRINGS ===\n")
        strings = scan_strings()
        for s, a in sorted(strings.items(), key=lambda x: x[1]):
            if any(p in s.lower() for p in STRLIT_PATTERNS):
                st.write("  {}  \"{}\"\n".format(fmt_hex(a), s))

    print("[*] wrote: " + ZONES_OUT)
    print("[*] wrote: " + SIZE_OUT)
    print("[*] wrote: " + UAF_OUT)
    print("[*] wrote: " + STRINGS_OUT)


main()
