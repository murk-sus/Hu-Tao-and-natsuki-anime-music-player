# -*- coding: utf-8 -*-
# @runtime Jython

import os
import re
import json
import struct
import traceback

try:
    string_types = (str, unicode)
except NameError:
    string_types = (str,)

WORKSPACE = os.environ.get("GITHUB_WORKSPACE", "/tmp")

OUT_TXT   = os.path.join(WORKSPACE, "sptm_report.txt")
OUT_H     = os.path.join(WORKSPACE, "sptm_offsets.h")
OUT_JSON  = os.path.join(WORKSPACE, "sptm_offsets.json")
OUT_PATCH = os.path.join(WORKSPACE, "sptm_patches.json")

_sym_cache        = None
_string_map       = None
_string_list      = None
_syms_index       = None
_IFC              = [None]
_valid_addr_cache = {}


def _write_placeholder():
    try:
        with open(OUT_TXT, "w") as fh:
            fh.write("=== sptm_rw.py placeholder ===\n")
    except Exception:
        pass
    try:
        with open(OUT_H, "w") as fh:
            fh.write("#ifndef SPTM_OFFSETS_H\n#define SPTM_OFFSETS_H\n#endif\n")
    except Exception:
        pass
    try:
        with open(OUT_JSON, "w") as fh:
            fh.write("{}\n")
    except Exception:
        pass
    try:
        with open(OUT_PATCH, "w") as fh:
            fh.write("{}\n")
    except Exception:
        pass


_write_placeholder()


SPTM_STRING_ANCHORS = {
    "ctrr_lock_boot":             ["ctrr_lock_boot", "CTRR lockdown", "ctrr_lock"],
    "cpu_lock_system_registers":  ["cpu_lock_system_registers", "cpu lock system"],
    "sptm_determine_kernel_ctrr": ["sptm_determine_kernel_ctrr", "determine_kernel_ctrr",
                                   "kernel_ctrr", "determine_kernel"],
    "ctrr":                       ["CTRR", "ctrr"],
    "kernel_ctrr_to_be_enabled":  ["kernel-ctrr-to-be-enabled"],
    "xnu_ctrr_dispatch_table":    ["xnu_ctrr_dispatch_table"],
    "amcc_ctrr":                  ["amcc-ctrr", "AMCC"],
    "ctrr_map_lock_group":        ["ctrr_map_lock_group"],
    "ctrr_dt_get_lock_group":     ["ctrr_dt_get_lock_group"],
    "ctrr_dt_get_lock_type":      ["ctrr_dt_get_lock_type"],
    "sptm_map":                   ["sptm_map"],
    "sptm_lock":                  ["sptm_lock"],
    "sptm_panic":                 ["SPTM PANIC", "sptm_panic"],
    "sptm_enter":                 ["sptm_enter"],
    "sptm_exit":                  ["sptm_exit"],
    "sptm_bootstrap":             ["sptm_bootstrap", "sptm boot"],
    "sptm_page_table":            ["SPTM page table", "sptm_page_table"],
    "sptm_region":                ["sptm_region"],
    "sptm_trap":                  ["sptm_trap"],
    "genter":                     ["genter"],
    "gexit":                      ["gexit"],
    "key_sptm_ctrr":              ["key-sptm-ctrr"],
    "key_xnu_ctrr":               ["key-xnu-ctrr"],
    "kernel_ctrr":                ["kernel-ctrr"],
}

SPTM_SYMBOL_ANCHORS = {
    "ctrr_lock_boot":             ["ctrr_lock_boot", "_ctrr_lock_boot"],
    "cpu_lock_system_registers":  ["cpu_lock_system_registers", "_cpu_lock_system_registers"],
    "sptm_determine_kernel_ctrr": ["sptm_determine_kernel_ctrr", "_sptm_determine_kernel_ctrr",
                                   "determine_kernel_ctrr", "_determine_kernel_ctrr"],
    "sptm_enter":                 ["sptm_enter", "_sptm_enter"],
    "sptm_exit":                  ["sptm_exit", "_sptm_exit"],
    "sptm_map":                   ["sptm_map", "_sptm_map"],
    "sptm_lock":                  ["sptm_lock", "_sptm_lock"],
    "sptm_panic":                 ["sptm_panic", "_sptm_panic"],
    "sptm_bootstrap":             ["sptm_bootstrap", "_sptm_bootstrap"],
    "sptm_main":                  ["sptm_main", "_sptm_main"],
    "genter":                     ["genter", "_genter"],
    "gexit":                      ["gexit", "_gexit"],
    "sptm_trap":                  ["sptm_trap", "_sptm_trap"],
}

PATCH_TEMPLATES = {
    "ctrr_lock_boot": {
        "purpose": "Force early return — CTRR stays unlocked",
        "patch_type": "TBNZ→B",
        "encoding": {
            "original_tbnz": "0x36000000",
            "patched_b": "0x14000000",
            "mask": "0x7F000000",
        },
        "validate": "is_ctrr_lock_boot",
    },
    "cpu_lock_system_registers": {
        "purpose": "Stub — system registers stay unlocked",
        "patch_type": "MOV W0, #0; RET",
        "encoding": {
            "mov_w0_0": 0x52800000,
            "ret": 0xD65F03C0,
        },
        "validate": "is_cpu_lock_sysreg",
    },
    "sptm_determine_kernel_ctrr": {
        "purpose": "Stub — no CTRR ranges configured",
        "patch_type": "MOV W0, #0; RET",
        "encoding": {
            "mov_w0_0": 0x52800000,
            "ret": 0xD65F03C0,
        },
        "validate": "is_determine_ctrr",
    },
}

MAX_FUNCTION_SCAN = 0x400


def _to_u(v):
    return int(v) & 0xFFFFFFFFFFFFFFFF


def fmt(v):
    if v is None:
        return "0x0"
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


def read_u64(a):
    ga = safe_addr(a)
    if ga is None:
        return None
    try:
        return int(currentProgram.getMemory().getLong(ga)) & 0xFFFFFFFFFFFFFFFF
    except Exception:
        return None


def read_bytes(a, n):
    ga = safe_addr(a)
    if ga is None:
        return None
    try:
        buf = bytearray(n)
        currentProgram.getMemory().getBytes(ga, buf)
        return bytes(buf)
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
    try:
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
    except Exception:
        pass
    print("[+] strings indexed: {}".format(len(_string_list)))


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
    try:
        st = currentProgram.getSymbolTable()
        for sym in st.getAllSymbols(True):
            try:
                _syms_index.append((_to_u(sym.getAddress().getOffset()), sym.getName()))
            except Exception:
                pass
    except Exception:
        pass
    print("[+] symtable indexed: {}".format(len(_syms_index)))


def syms_named(pat):
    _build_symidx()
    out = []
    for a, n in _syms_index:
        if pat in n:
            out.append((a, n))
    return out


def xrefs_to(addr):
    ga = safe_addr(addr)
    if ga is None:
        return []
    out = []
    try:
        rm = currentProgram.getReferenceManager()
        for r in rm.getReferencesTo(ga):
            out.append(_to_u(r.getFromAddress().getOffset()))
    except Exception:
        pass
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
    if f is None:
        return ""
    try:
        from ghidra.app.decompiler import DecompInterface, DecompileOptions
        from ghidra.util.task import ConsoleTaskMonitor
        if _IFC[0] is None:
            ifc = DecompInterface()
            ifc.setOptions(DecompileOptions())
            ifc.openProgram(currentProgram)
            _IFC[0] = ifc
        r = _IFC[0].decompileFunction(f, 60, ConsoleTaskMonitor())
        if r.decompileCompleted():
            return r.getDecompiledFunction().getC()
    except Exception:
        pass
    return ""


def _scan_function_insns(addr, max_n=MAX_FUNCTION_SCAN):
    out = []
    a = addr
    for _ in range(max_n):
        w = read_u32(a)
        if w is None:
            break
        out.append((a, w))
        a += 4
    return out


def is_ctrr_lock_boot(insns):
    if not insns:
        return False
    has_tbnz = False
    has_mrs_ctrr = False
    has_msr_ctrr = False
    for a, w in insns:
        if (w & 0x7F000000) == 0x36000000:
            has_tbnz = True
        if (w & 0xFFFFFFE0) == 0xD5380000:
            has_mrs_ctrr = True
        if (w & 0xFFFFFFE0) == 0xD5180000:
            has_msr_ctrr = True
    return has_tbnz and (has_mrs_ctrr or has_msr_ctrr)


def is_cpu_lock_sysreg(insns):
    if not insns:
        return False
    has_msr = False
    has_ret = False
    for a, w in insns:
        if (w & 0xFFFFFFE0) == 0xD5180000:
            has_msr = True
        if w == 0xD65F03C0:
            has_ret = True
    return has_msr and has_ret


def is_determine_ctrr(insns):
    if not insns:
        return False
    has_mrs = False
    has_ret = False
    for a, w in insns:
        if (w & 0xFFFFFFE0) == 0xD5380000:
            has_mrs = True
        if w == 0xD65F03C0:
            has_ret = True
    return has_mrs and has_ret


VALIDATORS = {
    "ctrr_lock_boot": is_ctrr_lock_boot,
    "cpu_lock_system_registers": is_cpu_lock_sysreg,
    "sptm_determine_kernel_ctrr": is_determine_ctrr,
}


def _find_by_strings():
    found = {}
    for label, strs in SPTM_STRING_ANCHORS.items():
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
    for label, names in SPTM_SYMBOL_ANCHORS.items():
        for n in names:
            for a, sn in syms_named(n):
                if _validate_addr(a):
                    found.setdefault(label, set()).add(a)
    return found


def _validate_candidates(candidates):
    result = {}
    for label, addrs in candidates.items():
        validator = VALIDATORS.get(label)
        if validator is None:
            continue
        for a in addrs:
            insns = _scan_function_insns(a)
            if validator(insns):
                result.setdefault(label, set()).add(a)
    return result


def _find_ctrr_candidates():
    cands = []
    for a, n in syms_named("ctrr"):
        if _validate_addr(a):
            cands.append((a, n))
    for s in ("CTRR", "ctrr_lock", "ctrr_lockdown", "CTRR lockdown",
              "kernel-ctrr-to-be-enabled", "amcc-ctrr", "xnu_ctrr_dispatch_table"):
        sa = _str_addr(s)
        if sa is None:
            continue
        for xr in xrefs_to(sa):
            f = func_at(xr)
            if f is None:
                continue
            cands.append((_to_u(f.getEntryPoint().getOffset()), "str:" + s))
    seen = set()
    out = []
    for a, n in cands:
        if a in seen:
            continue
        seen.add(a)
        out.append((a, n))
    return out


def _find_sptm_functions():
    cands = {}
    for label, strs in SPTM_STRING_ANCHORS.items():
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
                    cands.setdefault(label, set()).add(ep)
    return cands


def _find_msr_ctrr_count():
    count = 0get
    addrs = []
    try:
        mem = currentProgram.getMemory()
        for b in mem.getBlocks():
            if not b.isInitialized():
                continue
            s = _to_u(b.getStart().Offset())
            e = _to_u(b.getEnd().getOffset())
            if e - s > 0x1000000:
                continue
            a = s
            while a < e:
                w = read_u32(a)
                if w is None:
                    break
                if (w & 0xFFFFFFE0) == 0xD5180000:
                    count += 1
                    if len(addrs) < 16:
                        addrs.append(a)
                a += 4
    except Exception:
        pass
    return count, addrs


def _find_key_functions():
    key_labels = ["sptm_enter", "sptm_exit", "sptm_map", "sptm_lock",
                  "sptm_panic", "sptm_bootstrap", "sptm_main", "genter", "gexit",
                  "sptm_trap", "sptm_page_table", "sptm_region"]
    found = {}
    for label in key_labels:
        for a, n in syms_named(label):
            if _validate_addr(a):
                found.setdefault(label, set()).add(a)
    return found


def _generate_patches(validated):
    patches = {}
    idx = 1
    for label in ("ctrr_lock_boot", "cpu_lock_system_registers",
                  "sptm_determine_kernel_ctrr"):
        addrs = validated.get(label, set())
        for a in sorted(addrs):
            entry = {
                "id": idx,
                "target": label,
                "addr": fmt(a),
                "purpose": PATCH_TEMPLATES[label]["purpose"],
                "patch_type": PATCH_TEMPLATES[label]["patch_type"],
                "encoding": PATCH_TEMPLATES[label]["encoding"],
            }
            patches[str(idx)] = entry
            idx += 1
    return patches


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


def main():
    print("=== sptm_rw.py (iOS 27 SPTM patchfinder) ===")
    try:
        print("[*] program: " + currentProgram.getName())
    except Exception:
        pass

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

    print("[*] SPTM functions via strings...")
    by_str = _find_sptm_functions()
    report.append("")
    report.append("=== [2] SPTM FUNCTIONS (via strings) ===")
    for label, eps in sorted(by_str.items()):
        for ep in sorted(eps):
            report.append("  {:<35} {}".format(label, fmt(ep)))
    hdr.append("// SPTM FUNCTIONS (via strings)")
    for label, eps in sorted(by_str.items()):
        key = norm(label).upper()
        for i, ep in enumerate(sorted(eps)):
            hdr.append("#define SPTM_{:<38} {}ULL".format(
                key + ("_%d" % i if len(eps) > 1 else ""), fmt(ep)))
    hdr.append("")
    jout["sptm_strings"] = {k: [fmt(x) for x in sorted(v)] for k, v in by_str.items()}

    print("[*] SPTM functions via symbols...")
    by_sym = _find_by_symbols()
    report.append("")
    report.append("=== [3] SPTM FUNCTIONS (via symbols) ===")
    for label, eps in sorted(by_sym.items()):
        for ep in sorted(eps):
            report.append("  {:<35} {}".format(label, fmt(ep)))
    hdr.append("// SPTM FUNCTIONS (via symbols)")
    for label, eps in sorted(by_sym.items()):
        key = norm(label).upper()
        for i, ep in enumerate(sorted(eps)):
            hdr.append("#define SPTM_SYM_{:<34} {}ULL".format(
                key + ("_%d" % i if len(eps) > 1 else ""), fmt(ep)))
    hdr.append("")
    jout["sptm_symbols"] = {k: [fmt(x) for x in sorted(v)] for k, v in by_sym.items()}

    print("[*] merging + validating candidates...")
    merged = {}
    for src in (by_str, by_sym):
        for label, eps in src.items():
            merged.setdefault(label, set()).update(eps)
    validated = _validate_candidates(merged)
    report.append("")
    report.append("=== [4] VALIDATED FUNCTIONS ===")
    for label, eps in sorted(validated.items()):
        for ep in sorted(eps):
            report.append("  {:<35} {}".format(label, fmt(ep)))
    hdr.append("// VALIDATED FUNCTIONS")
    for label, eps in sorted(validated.items()):
        key = norm(label).upper()
        for i, ep in enumerate(sorted(eps)):
            hdr.append("#define SPTM_VALID_{:<32} {}ULL".format(
                key + ("_%d" % i if len(eps) > 1 else ""), fmt(ep)))
    hdr.append("")
    jout["validated"] = {k: [fmt(x) for x in sorted(v)] for k, v in validated.items()}

    print("[*] CTRR candidates...")
    ctrr = _find_ctrr_candidates()
    report.append("")
    report.append("=== [5] CTRR CANDIDATES ===")
    for a, n in ctrr:
        report.append("  {:<45} {}".format(n, fmt(a)))
    hdr.append("// CTRR CANDIDATES")
    for i, (a, n) in enumerate(ctrr):
        hdr.append("#define SPTM_CTRR_{:<35} {}ULL".format(
            norm("{:04X}".format(i)), fmt(a)))
    hdr.append("")
    jout["ctrr_candidates"] = [{"addr": fmt(a), "name": n} for a, n in ctrr]

    print("[*] MSR CTRR instructions...")
    msr_count, msr_addrs = _find_msr_ctrr_count()
    report.append("")
    report.append("=== [6] MSR CTRR INSTRUCTIONS ===")
    report.append("count = " + str(msr_count))
    hdr.append("// MSR CTRR INSTRUCTIONS")
    hdr.append("#define SPTM_MSR_CTRR_COUNT       " + str(msr_count))
    for i, a in enumerate(msr_addrs):
        report.append("  [{}] {}".format(i, fmt(a)))
        hdr.append("#define SPTM_MSR_CTRR_{:<28} {}ULL".format(
            norm("{:02X}".format(i)), fmt(a)))
    hdr.append("")
    jout["msr_ctrr_count"] = msr_count
    jout["msr_ctrr_addrs"] = [fmt(a) for a in msr_addrs]

    print("[*] key SPTM functions...")
    key_funcs = _find_key_functions()
    report.append("")
    report.append("=== [7] KEY SPTM FUNCTIONS ===")
    for label, eps in sorted(key_funcs.items()):
        for ep in sorted(eps):
            report.append("  {:<35} {}".format(label, fmt(ep)))
    hdr.append("// KEY SPTM FUNCTIONS")
    for label, eps in sorted(key_funcs.items()):
        key = norm(label).upper()
        for i, ep in enumerate(sorted(eps)):
            hdr.append("#define SPTM_KEY_{:<34} {}ULL".format(
                key + ("_%d" % i if len(eps) > 1 else ""), fmt(ep)))
    hdr.append("")
    jout["key_functions"] = {k: [fmt(x) for x in sorted(v)] for k, v in key_funcs.items()}

    print("[*] generating patches...")
    patches = _generate_patches(validated)
    report.append("")
    report.append("=== [8] GENERATED PATCHES ===")
    for pid, p in sorted(patches.items(), key=lambda x: int(x[0])):
        report.append("  [{}] {:<32} {} {}".format(
            pid, p["target"], p["addr"], p["patch_type"]))
    hdr.append("// GENERATED PATCHES")
    for pid, p in sorted(patches.items(), key=lambda x: int(x[0])):
        hdr.append("// [{}] {} @ {}: {}".format(pid, p["target"], p["addr"], p["patch_type"]))
        hdr.append("#define SPTM_PATCH_{:<30} {}ULL".format(
            norm(p["target"]).upper()[:30], p["addr"]))
    hdr.append("")
    jout["patches"] = patches

    summary = {
        "sptm_strings":   sum(len(v) for v in by_str.values()),
        "sptm_symbols":   sum(len(v) for v in by_sym.values()),
        "validated":      sum(len(v) for v in validated.values()),
        "ctrr_candidates": len(ctrr),
        "msr_ctrr_count": msr_count,
        "key_functions":  sum(len(v) for v in key_funcs.values()),
        "patches":        len(patches),
    }
    jout["summary"] = summary
    report.append("")
    report.append("=== [9] SUMMARY ===")
    for k, v in sorted(summary.items()):
        report.append("  {:<20} {}".format(k, v))

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

    try:
        with open(OUT_PATCH, "w") as fh:
            fh.write(json.dumps(patches, indent=2, sort_keys=True))
        print("[+] wrote " + OUT_PATCH)
    except Exception as e:
        print("[-] patches write failed: " + str(e))

    print("")
    print("=============== SUMMARY ===============")
    for k, v in sorted(summary.items()):
        print("  {:<20} {}".format(k, v))
    print("=======================================")
    print("[+] sptm_rw.py done")


try:
    main()
except Exception as e:
    print("[-] FATAL: {}".format(e))
    traceback.print_exc()
    _write_placeholder()
