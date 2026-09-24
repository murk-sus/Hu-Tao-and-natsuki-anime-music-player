# -*- coding: utf-8 -*-
# @runtime Jython

import os
import re
import json

try:
    string_types = (str, unicode)
except NameError:
    string_types = (str,)

WORKSPACE = os.environ.get("GITHUB_WORKSPACE", "/tmp")

OUT_TXT  = os.path.join(WORKSPACE, "sptm_report.txt")
OUT_H    = os.path.join(WORKSPACE, "sptm_offsets.h")
OUT_JSON = os.path.join(WORKSPACE, "sptm_offsets.json")

_sym_cache        = None
_string_map       = None
_string_list      = None
_syms_index       = None
_IFC              = [None]
_valid_addr_cache = {}


def _to_u(v):
    return int(v) & 0xFFFFFFFFFFFFFFFF


def _parse_addr(v):
    if v is None:
        return None
    try:
        if isinstance(v, (int, long)):
            return _to_u(v)
        if not isinstance(v, string_types):
            return None
        s = v.strip()
        if not s:
            return None
        return _to_u(int(s, 16) if s.startswith(("0x", "0X")) else int(s, 10))
    except Exception:
        return None


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


def read_u32(a):
    ga = safe_addr(a)
    if ga is None:
        return None
    try:
        return int(currentProgram.getMemory().getInt(ga)) & 0xFFFFFFFF
    except Exception:
        return None


def _validate_addr(addr):
    if addr in _valid_addr_cache:
        return _valid_addr_cache[addr]
    result = False
    ga = safe_addr(addr)
    if ga is not None:
        blk = currentProgram.getMemory().getBlock(ga)
        if blk is not None and blk.isInitialized():
            result = True
    _valid_addr_cache[addr] = result
    return result


def _build_strings():
    global _string_map, _string_list
    if _string_map is not None:
        return
    _string_map = {}
    _string_list = []
    listing = currentProgram.getListing()
    it = listing.getDefinedData(True)
    while it.hasNext():
        d = it.next()
        try:
            if not d.hasStringValue():
                continue
            v = d.getValue()
            if v is None:
                continue
            s = str(v)
            a = _to_u(d.getAddress().getOffset())
            _string_list.append((a, s))
            if s not in _string_map:
                _string_map[s] = a
        except Exception:
            pass
    print("[+] strings indexed: " + str(len(_string_list)))


def _str_addr(s):
    _build_strings()
    a = _string_map.get(s)
    if a is not None:
        return a
    for a, val in _string_list:
        if s in val:
            return a
    return None


def _build_symidx():
    global _syms_index
    if _syms_index is not None:
        return
    _syms_index = []
    st = currentProgram.getSymbolTable()
    try:
        for sym in st.getAllSymbols(True):
            try:
                _syms_index.append((_to_u(sym.getAddress().getOffset()), sym.getName()))
            except Exception:
                pass
    except Exception:
        pass
    print("[+] symtable indexed: " + str(len(_syms_index)))


def syms_named(pat):
    _build_symidx()
    out = []
    for a, n in _syms_index:
        if pat in n:
            out.append((a, n))
    return out


def func_at(addr):
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
        return getFunctionContaining(ga)
    except Exception:
        return None


def ensure_func(addr):
    f = func_at(addr)
    if f:
        return f
    ga = safe_addr(addr)
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


def decompile(f):
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.util.task import ConsoleTaskMonitor
    if f is None:
        return ""
    if _IFC[0] is None:
        ifc = DecompInterface()
        ifc.setOptions(DecompileOptions())
        ifc.openProgram(currentProgram)
        _IFC[0] = ifc
    try:
        r = _IFC[0].decompileFunction(f, 60, ConsoleTaskMonitor())
        if r.decompileCompleted():
            return r.getDecompiledFunction().getC()
    except Exception:
        pass
    return ""


def xrefs_to(addr):
    ga = safe_addr(addr)
    if ga is None:
        return []
    out = []
    rm = currentProgram.getReferenceManager()
    try:
        for r in rm.getReferencesTo(ga):
            out.append(_to_u(r.getFromAddress().getOffset()))
    except Exception:
        pass
    return out


def write_lines(path, lines):
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        try:
            os.makedirs(d)
        except Exception:
            pass
    with open(path, "w") as fh:
        for l in lines:
            fh.write(l + "\n")


def norm(s):
    return re.sub(r"[^A-Za-z0-9_]", "_", s)


SPTM_STRINGS = {
    "ctrr_lock_boot":              ["ctrr_lock_boot", "CTRR lockdown", "ctrr_lock"],
    "cpu_lock_system_registers":   ["cpu_lock_system_registers"],
    "sptm_determine_kernel_ctrr":  ["sptm_determine_kernel_ctrr", "determine_kernel_ctrr",
                                    "kernel_ctrr"],
    "sptm_map":                    ["sptm_map"],
    "sptm_lock":                   ["sptm_lock"],
    "sptm_panic":                  ["SPTM PANIC", "sptm_panic"],
    "sptm_enter":                  ["sptm_enter"],
    "sptm_exit":                   ["sptm_exit"],
    "pmap_sptm":                   ["pmap_sptm"],
    "sptm_page_table":             ["SPTM page table", "sptm_page_table"],
    "sptm_region":                 ["sptm_region"],
    "sptm_bootstrap":              ["sptm_bootstrap"],
    "sptm_trap":                   ["sptm_trap"],
    "ctrr":                        ["CTRR", "ctrr"],
    "genter":                      ["genter"],
    "gexit":                       ["gexit"],
}

SPTM_SYMBOLS = {
    "sptm_enter":     ["sptm_enter", "_sptm_enter"],
    "sptm_exit":      ["sptm_exit", "_sptm_exit"],
    "sptm_map":       ["sptm_map", "_sptm_map"],
    "sptm_lock":      ["sptm_lock", "_sptm_lock"],
    "sptm_panic":     ["sptm_panic", "_sptm_panic"],
    "sptm_bootstrap": ["sptm_bootstrap", "_sptm_bootstrap"],
    "sptm_main":      ["sptm_main", "_sptm_main"],
    "ctrr_lock_boot": ["ctrr_lock_boot", "_ctrr_lock_boot"],
    "genter":         ["genter", "_genter"],
    "gexit":          ["gexit", "_gexit"],
}


def _find_by_strings():
    found = {}
    for label, strs in SPTM_STRINGS.items():
        for s in strs:
            sa = _str_addr(s)
            if sa is None:
                continue
            for xr in xrefs_to(sa):
                f = func_at(xr)
                if f is None:
                    continue
                ep = _to_u(f.getEntryPoint().getOffset())
                if _validate_addr(ep):
                    found.setdefault(label, set()).add(ep)
    return found


def _find_by_symbols():
    found = {}
    for label, names in SPTM_SYMBOLS.items():
        for n in names:
            for a, sn in syms_named(n):
                if _validate_addr(a):
                    found.setdefault(label, set()).add(a)
    return found


def _find_ctrr_candidates():
    candidates = []
    for a, n in syms_named("ctrr"):
        if _validate_addr(a):
            candidates.append((a, n))
    for s in ("CTRR", "ctrr_lock", "ctrr_lockdown", "CTRR lockdown"):
        sa = _str_addr(s)
        if sa is None:
            continue
        for xr in xrefs_to(sa):
            f = func_at(xr)
            if f is None:
                continue
            candidates.append((_to_u(f.getEntryPoint().getOffset()),
                                "str:" + s))
    seen = set()
    out = []
    for a, n in candidates:
        if a in seen:
            continue
        seen.add(a)
        out.append((a, n))
    return out


def main():
    print("=== sptm_rw.py ===")
    print("[*] program: " + currentProgram.getName())

    report = []
    hdr    = []
    jout   = {}

    img_base = int(currentProgram.getImageBase().getOffset()) & 0xFFFFFFFFFFFFFFFF
    report.append("=== [1] SPTM BASE ===")
    report.append("image_base = " + fmt(img_base))
    hdr.append("#define SPTM_IMAGE_BASE   " + fmt(img_base) + "ULL")
    hdr.append("")
    jout["image_base"] = fmt(img_base)

    print("[*] strings indexing...")
    _build_strings()
    _build_symidx()

    print("[*] finding anchors via strings...")
    by_str = _find_by_strings()
    report.append("")
    report.append("=== [2] SPTM FUNCTIONS (via strings) ===")
    for label, eps in sorted(by_str.items()):
        for ep in sorted(eps):
            report.append("  {:<30} {}".format(label, fmt(ep)))
    hdr.append("// SPTM FUNCTIONS (via strings)")
    for label, eps in sorted(by_str.items()):
        key = norm(label).upper()
        for i, ep in enumerate(sorted(eps)):
            hdr.append("#define SPTM_{:<33} {}ULL".format(
                key + ("_%d" % i if len(eps) > 1 else ""), fmt(ep)))
    hdr.append("")
    jout["sptm_strings"] = {k: [fmt(x) for x in sorted(v)] for k, v in by_str.items()}

    print("[*] finding anchors via symbols...")
    by_sym = _find_by_symbols()
    report.append("")
    report.append("=== [3] SPTM FUNCTIONS (via symbols) ===")
    for label, eps in sorted(by_sym.items()):
        for ep in sorted(eps):
            report.append("  {:<30} {}".format(label, fmt(ep)))
    hdr.append("// SPTM FUNCTIONS (via symbols)")
    for label, eps in sorted(by_sym.items()):
        key = norm(label).upper()
        for i, ep in enumerate(sorted(eps)):
            hdr.append("#define SPTM_SYM_{:<29} {}ULL".format(
                key + ("_%d" % i if len(eps) > 1 else ""), fmt(ep)))
    hdr.append("")
    jout["sptm_symbols"] = {k: [fmt(x) for x in sorted(v)] for k, v in by_sym.items()}

    print("[*] ctrr candidates...")
    ctrr = _find_ctrr_candidates()
    report.append("")
    report.append("=== [4] CTRR CANDIDATES ===")
    for a, n in ctrr:
        report.append("  {:<40} {}".format(n, fmt(a)))
    hdr.append("// CTRR CANDIDATES")
    for i, (a, n) in enumerate(ctrr):
        hdr.append("#define SPTM_CTRR_{:<30} {}ULL".format(
            norm("{:04X}".format(i)), fmt(a)))
    hdr.append("")
    jout["ctrr_candidates"] = [{"addr": fmt(a), "name": n} for a, n in ctrr]

    write_lines(OUT_TXT, report)
    print("[+] wrote " + OUT_TXT)

    header = ["#ifndef SPTM_OFFSETS_H",
              "#define SPTM_OFFSETS_H",
              "",
              "// auto-generated by sptm_rw.py",
              "// program: " + currentProgram.getName(),
              ""] + hdr + ["", "#endif /* SPTM_OFFSETS_H */"]
    write_lines(OUT_H, header)
    print("[+] wrote " + OUT_H)

    try:
        with open(OUT_JSON, "w") as fh:
            fh.write(json.dumps(jout, indent=2, sort_keys=True))
        print("[+] wrote " + OUT_JSON)
    except Exception as e:
        print("[-] json write failed: " + str(e))

    print("")
    print("=============== SUMMARY ===============")
    print("  sptm_strings     : " + str(sum(len(v) for v in by_str.values())))
    print("  sptm_symbols     : " + str(sum(len(v) for v in by_sym.values())))
    print("  ctrr_candidates  : " + str(len(ctrr)))
    print("=======================================")
    print("[+] sptm_rw.py done")


main()