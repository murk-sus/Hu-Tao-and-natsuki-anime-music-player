# -*- coding: utf-8 -*-
# @runtime Jython
# validate_all_offsets.py  (v3)

import os
import re
import json
import traceback

from jarray import zeros
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.util.task import TaskMonitor

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WS, "result.txt")
OUT_JSON = os.path.join(WS, "validated_offsets.json")

# Candidate paths for offsets JSON
CANDIDATES = [
    os.path.join(WS, "natsuk1/Offsets/iPhone14,5_iOS27.0_24A437.json"),
    os.path.join(WS, "natsuk1/Offsets/iPhone14,5_iOS27.0_24A437.json"),
    os.path.join(WS, "iPhone14,5_iOS27.0_24A437.json"),
]

KPTR_MIN = 0xFFFFFFF000000000
KPTR_MAX = 0xFFFFFFFFFF000000

# Full offset list extracted from this chat (union of all sources we discussed)
FULL_OFFSETS = {
    # Kernel / sysent / trap
    "off_kernel_base":       "0xFFFFFFF007004000",
    "off_sysent_base":       "0xFFFFFFF007C192A0",
    "off_sysent_count":      "558",
    "off_sysent_stride":     "24",
    "off_mach_trap_table":   "0xFFFFFFF007BE8018",

    # Globals
    "off_g_kernproc":        "0xFFFFFFF007BBF040",
    "off_g_task_list":       "0xFFFFFFF0080D93F0",
    "off_g_allproc":         "0xFFFFFFF007BBF048",
    "off_g_kernel_task":     "0xFFFFFFF00700DC70",
    "off_g_zone_map":        "0xFFFFFFF00AD6A800",
    "off_g_kernel_map":      "0xFFFFFFF007BBE228",

    # Primitives
    "off_fn_copyin":         "0xFFFFFFF00A7B9570",
    "off_fn_copyout":        "0xFFFFFFF00A2C6C28",
    "off_fn_kalloc_ext":     "0xFFFFFFF00A200DCC",
    "off_fn_kfree_ext":      "0xFFFFFFF00A201000",

    # proc
    "off_proc_p_list_next":  "0x0",
    "off_proc_p_pid":        "0x74",
    "off_proc_p_task":       "0x78",
    "off_proc_ro_p_ucred":   "0x98",
    "off_proc_p_csflags":    "0xA8",

    # task
    "off_task_map":          "0x28",
    "off_task_bsd_info":     "0x4E0",
    "off_task_itk_space":    "0x320",
    "off_task_cr_label":     "0xE8",
    "off_thread_task_threads_next": "0x50",

    # ucred
    "off_ucred_cr_uid":      "0x18",
    "off_ucred_cr_svuid":    "0x1C",
    "off_ucred_cr_gid":      "0x20",
    "off_ucred_cr_svgid":    "0x24",

    # NECP
    "off_necp_open":                "0xFFFFFFF00A4E411C",
    "off_necp_client_add_flow":     "0xFFFFFFF00A4E843C",
    "off_necp_client_remove_flow":  "0xFFFFFFF00A4E93C4",
    "off_ncf_assigned":             "0x68",
    "off_ncf_assigned_len":         "0x70",
    "off_ncf_parent":               "0x88",
    "off_ncf_refcnt":               "0x58",
    "off_ncf_struct_sz":            "0x100",

    # Zones
    "off_zone_data_kalloc":         "0xFFFFFFF007C62E70",
    "off_zone_early_kalloc":        "0xFFFFFFF007BBB170",
    "off_zone_kalloc_type_var":     "0xFFFFFFF007BC2800",
    "off_zone_site_struct_task":    "0xFFFFFFF007C64080",
    "off_zone_site_struct_proc":    "0xFFFFFFF007C71240",
    "off_zone_site_struct_thread":  "0xFFFFFFF007C63D00",
    "off_zone_site_struct_ucred":   "0xFFFFFFF007C6F140",
    "off_zone_site_struct_ipc_port":  "0xFFFFFFF007C79248",
    "off_zone_site_struct_ipc_entry": "0xFFFFFFF007C79298",
    "off_zone_site_struct_fileproc":  "0xFFFFFFF007C7CD08",
    "off_zone_site_struct_fileglob":  "0xFFFFFFF007C7D708",
    "off_zone_site_struct_vnode":     "0xFFFFFFF007C660C0",
    "off_zone_site_struct_mount":     "0xFFFFFFF007C662C0",
    "off_zone_site_struct_socket":    "0xFFFFFFF007C70C40",
    "off_zone_site_struct_inpcb":     "0xFFFFFFF007C6D180",
    "off_zone_site_struct_pipe":      "0xFFFFFFF007C6FE80",
    "off_zone_site_struct_vm_page":   "0xFFFFFFF007C64C80",

    # SPTM
    "off_sptm_base":                        "0xFFFFFFF027004000",
    "off_sptm_ctrr_lock_boot":              "0xFFFFFFF027006E62",
    "off_sptm_cpu_lock_system_registers":   "0xFFFFFFF0270B39B4",
    "off_sptm_determine_kernel_ctrr":       "0xFFFFFFF0270B2224",
    "off_sptm_bootstrap":                   "0xFFFFFFF0270D21CC",
    "off_sptm_map":                         "0xFFFFFFF0270E97BC",
    "off_sptm_region":                      "0xFFFFFFF0270ECFF0",
    "off_sptm_panic":                       "0xFFFFFFF0270BEE18",
    "off_sptm_page_table":                  "0xFFFFFFF0270D13D4",
}

# NECP function addrs from prior dumps (corrected)
NECP_FUNCS = [
    ("necp_open",                   0xFFFFFFF00A4E411C),
    ("necp_client_add_flow",        0xFFFFFFF00A4E843C),
    ("necp_client_remove_flow",     0xFFFFFFF00A4E93C4),
    ("necp_client_copy_interface",  0xFFFFFFF00A4EAC7C),
    ("necp_client_copy_update",     0xFFFFFFF00A4EC264),
]

# Also search add_flow / remove_flow bodies for ldr with these imms
WANTED_NCF = {0x20, 0x58, 0x68, 0x70, 0x88, 0x90, 0xCC, 0xD2, 0xD4, 0xD8, 0x100, 0x328}


def _u(v): return int(v) & 0xFFFFFFFFFFFFFFFF


def fmt(v):
    if v is None: return "0x0"
    try: return "0x%016X" % (int(v) & 0xFFFFFFFFFFFFFFFF)
    except Exception: return "0x0"


def sa(a):
    if a is None: return None
    try: return currentProgram.getAddressFactory().getAddress("%X" % (int(a) & 0xFFFFFFFFFFFFFFFF))
    except Exception: return None


_blocks = None
def blocks():
    global _blocks
    if _blocks is not None: return _blocks
    out = []
    try:
        for b in currentProgram.getMemory().getBlocks():
            try:
                if not b.isInitialized(): continue
                out.append((_u(b.getStart().getOffset()),
                            _u(b.getEnd().getOffset()),
                            str(b.getName()), bool(b.isExecute())))
            except Exception: pass
    except Exception: pass
    _blocks = out
    return out


def inblk(a):
    if a is None: return None
    av = _u(a)
    for s, e, n, x in blocks():
        if s <= av < e: return (s, e, n, x)
    return None


def read_u64(addr):
    try:
        ga = sa(addr)
        if ga is None: return None
        return int(currentProgram.getMemory().getLong(ga)) & 0xFFFFFFFFFFFFFFFF
    except Exception: return None


def read_u32(addr):
    try:
        ga = sa(addr)
        if ga is None: return None
        return int(currentProgram.getMemory().getInt(ga)) & 0xFFFFFFFF
    except Exception: return None


def find_func_by_addr(addr):
    try:
        ga = sa(addr)
        if ga is None: return None
        f = getFunctionAt(ga)
        if f is not None: return f
        return getFunctionContaining(ga)
    except Exception: return None


def decompile(f, timeout):
    out = []
    try:
        d = DecompInterface()
        d.openProgram(currentProgram)
        r = d.decompileFunction(f, timeout, ConsoleTaskMonitor())
        if r is None:
            out.append("(no result)"); return out
        if not r.decompileCompleted():
            out.append("(failed: %s)" % str(r.getErrorMessage())); return out
        c = r.getDecompiledFunction()
        if c is None:
            out.append("(empty)"); return out
        for line in c.getC().split("\n"):
            out.append("  " + line.rstrip())
    except Exception as e:
        out.append("(exception: %s)" % str(e))
    return out


def disasm_func(f, maxn):
    out = []
    body = f.getBody()
    if body is None: return out
    try:
        it = body.getAddresses(True)
    except Exception:
        return out
    listing = currentProgram.getListing()
    cnt = 0
    while it.hasNext() and cnt < maxn:
        a = it.next()
        try:
            pc = _u(a.getOffset())
            b = int(currentProgram.getMemory().getInt(a)) & 0xFFFFFFFF
            ins = listing.getInstructionAt(a)
            txt = str(ins) if ins is not None else "?"
            out.append((pc, b, txt))
        except Exception: pass
        cnt += 1
    return out


def extract_mem(raw):
    """Return (kind, base_reg, imm) for ldr/str variants."""
    if (raw & 0xFFC00000) == 0xF9400000: return ("ldr_x", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 8)
    if (raw & 0xFFC00000) == 0xB9400000: return ("ldr_w", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 4)
    if (raw & 0xFFC00000) == 0xF9000000: return ("str_x", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 8)
    if (raw & 0xFFC00000) == 0xB9000000: return ("str_w", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 4)
    if (raw & 0xFFE00000) == 0x39400000: return ("ldrb", (raw >> 5) & 0x1F, (raw >> 10) & 0xFFF)
    if (raw & 0xFFE00000) == 0x39000000: return ("strb", (raw >> 5) & 0x1F, (raw >> 10) & 0xFFF)
    if (raw & 0xFFE00000) == 0x79400000: return ("ldrh", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 2)
    if (raw & 0xFFE00000) == 0x79000000: return ("strh", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 2)
    if (raw & 0xFFC00000) == 0xF8400000:
        i = (raw >> 12) & 0x1FF
        if i & 0x100: i -= 0x200
        return ("ldur_x", (raw >> 5) & 0x1F, i)
    if (raw & 0xFFC00000) == 0xB8400000:
        i = (raw >> 12) & 0x1FF
        if i & 0x100: i -= 0x200
        return ("ldur_w", (raw >> 5) & 0x1F, i)
    if (raw & 0xFFC00000) == 0xF8000000:
        i = (raw >> 12) & 0x1FF
        if i & 0x100: i -= 0x200
        return ("stur_x", (raw >> 5) & 0x1F, i)
    if (raw & 0xFFC00000) == 0xB8000000:
        i = (raw >> 12) & 0x1FF
        if i & 0x100: i -= 0x200
        return ("stur_w", (raw >> 5) & 0x1F, i)
    return None


def scan_for_offset_pattern():
    """Scan whole __text for ldr X0, [X0, #imm]; ret pattern -> struct accessor offsets."""
    out = {}
    try:
        mem = currentProgram.getMemory()
        for s, e, n, ex in blocks():
            if not ex: continue
            if "__text" not in n and "TEXT" not in n: continue
            addr = s
            while addr < e - 8:
                b0 = read_u32(addr)
                b1 = read_u32(addr + 4)
                if b0 is None or b1 is None:
                    addr += 4; continue
                if b1 == 0xD65F03C0:  # ret
                    r = extract_mem(b0)
                    if r is not None:
                        kind, base, imm = r
                        rd = b0 & 0x1F
                        if rd == 0 and base == 0 and kind in ("ldr_x", "ldr_w", "ldrb", "ldrh"):
                            key = (kind, imm)
                            if key not in out:
                                out[key] = addr
                addr += 4
    except Exception:
        pass
    return out


def main():
    print("=== validate_all_offsets v3 ===")
    lines = []

    lines.append("=== PROGRAM ===")
    try:
        lines.append("name = %s" % currentProgram.getName())
        lines.append("min  = %s" % fmt(currentProgram.getMemory().getMinAddress().getOffset()))
        lines.append("max  = %s" % fmt(currentProgram.getMemory().getMaxAddress().getOffset()))
    except Exception as e:
        lines.append("(err: %s)" % str(e))
    lines.append("")

    # try loading any of the candidate offsets JSON
    loaded = {}
    used_path = None
    for p in CANDIDATES:
        if os.path.exists(p):
            try:
                with open(p) as fh:
                    raw = json.load(fh)
                if isinstance(raw, dict) and "defaults" in raw:
                    loaded = raw["defaults"]
                elif isinstance(raw, dict):
                    loaded = raw
                used_path = p
                break
            except Exception:
                pass

    if used_path:
        lines.append("=== LOADED %d OFFSETS FROM %s ===" % (len(loaded), used_path))
    else:
        lines.append("=== offsets.json NOT FOUND, using builtin FULL_OFFSETS (chat history) ===")
        loaded = dict(FULL_OFFSETS)

    # merge: prefer loaded, fallback to builtin
    for k, v in FULL_OFFSETS.items():
        if k not in loaded:
            loaded[k] = v

    lines.append("=== ALL OFFSETS (%d) ===" % len(loaded))
    for k in sorted(loaded.keys()):
        lines.append("  %-38s = %s" % (k, loaded[k]))
    lines.append("")

    # ---------- validate each ----------
    lines.append("=== VALIDATION ===")
    validated = {}
    ok_addr = 0
    ok_numeric = 0
    not_kptr = 0
    not_in_blocks = 0
    zero_or_unknown = 0

    for key in sorted(loaded.keys()):
        val = loaded[key]
        try:
            ival = int(val, 16) if (isinstance(val, str) and val.startswith("0x")) else int(val)
        except Exception:
            lines.append("  %-38s = %-20s  BAD_VALUE" % (key, str(val)))
            validated[key] = {"status": "bad_value"}
            continue

        # Case: zero
        if ival == 0:
            lines.append("  %-38s = 0x0 (unknown / placeholder)" % key)
            validated[key] = {"status": "placeholder"}
            zero_or_unknown += 1
            continue

        # Case: kernel address
        if ival >= 0xFFFFFFF000000000:
            blk = inblk(ival)
            if blk is None:
                lines.append("  %-38s %-20s  NOT_IN_BLOCKS" % (key, fmt(ival)))
                validated[key] = {"status": "not_in_blocks", "addr": fmt(ival)}
                not_in_blocks += 1
                continue
            v64 = read_u64(ival)
            v32 = read_u32(ival)
            kptr = (v64 is not None and KPTR_MIN <= v64 <= KPTR_MAX)
            marker = "KPTR_OK" if kptr else ("ZERO" if (v64 == 0) else "not_kptr")
            lines.append("  %-38s %-20s  [%s]  u64=%s  u32=%s  %s" % (
                key, fmt(ival), blk[2],
                fmt(v64) if v64 is not None else "err",
                fmt(v32) if v32 is not None else "err",
                marker))
            validated[key] = {
                "status": "ok" if kptr else "not_kptr",
                "addr": fmt(ival),
                "value_u64": fmt(v64) if v64 is not None else None,
                "value_u32": fmt(v32) if v32 is not None else None,
                "block": blk[2],
            }
            if kptr: ok_addr += 1
            else: not_kptr += 1
            continue

        # Case: numeric struct offset
        lines.append("  %-38s = 0x%X (numeric struct offset)" % (key, ival))
        validated[key] = {"status": "numeric", "value": ival}
        ok_numeric += 1

    lines.append("")

    # ---------- scan for accessor patterns in text ----------
    lines.append("=== TEXT SCAN: accessor patterns (ldr X0, [X0, #imm]; ret) ===")
    pat = scan_for_offset_pattern()
    # Sort by imm
    sorted_pat = sorted(pat.items(), key=lambda kv: kv[0][1])
    for (kind, imm), addr in sorted_pat:
        blk = inblk(addr)
        lines.append("  %-8s +0x%-4X  @ %s  [%s]" % (
            kind, imm, fmt(addr), blk[2] if blk else "?"))
    lines.append("")

    # Try to match numeric offsets to accessor patterns
    lines.append("=== NUMERIC OFFSET -> ACCESSOR MATCH ===")
    for key in sorted(loaded.keys()):
        v = validated.get(key, {})
        if v.get("status") != "numeric":
            continue
        imm = v["value"]
        matches = [(k, a) for (k, i), a in pat.items() if i == imm]
        if matches:
            lines.append("  %-38s +0x%X  candidates: %s" % (
                key, imm,
                ", ".join("%s@%s" % (k, fmt(a)) for k, a in matches[:4])))
        else:
            lines.append("  %-38s +0x%X  (no direct ldr+ret match)" % (key, imm))
    lines.append("")

    # ---------- NECP disasm ----------
    lines.append("=== NECP FUNCTIONS DISASM ===")
    for name, addr in NECP_FUNCS:
        f = find_func_by_addr(addr)
        if f is None:
            lines.append("--- %s @ %s : NO FUNCTION" % (name, fmt(addr)))
            lines.append("")
            continue
        entry = _u(f.getEntryPoint().getOffset())
        try:
            sz = int(f.getBody().getNumAddresses())
        except Exception:
            sz = 0
        lines.append("--- %s @ %s  size=0x%X ---" % (name, fmt(entry), sz))

        all_imms = []
        for pc, raw, txt in disasm_func(f, 800):
            r = extract_mem(raw)
            if r is None: continue
            kind, base, imm = r
            all_imms.append((pc, kind, base, imm, raw))

        # group by imm
        groups = {}
        for pc, kind, base, imm, raw in all_imms:
            groups.setdefault(imm, []).append((pc, kind, base))

        # print interesting: imm in 0x40..0x300, any base
        lines.append("  offsets (unique, sorted):")
        seen = set()
        for imm in sorted(groups.keys()):
            if imm in seen: continue
            seen.add(imm)
            if not (0x20 <= imm <= 0x300): continue
            pc, kind, base = groups[imm][0]
            tag = " *" if imm in WANTED_NCF else ""
            lines.append("    +0x%-4X  %-8s  base=x%-2d  pc=%s  hits=%d%s" % (
                imm, kind, base, fmt(pc), len(groups[imm]), tag))

        # decompile brief
        lines.append("  decompile (first 60):")
        for l in decompile(f, 60)[:60]:
            lines.append(l)
        lines.append("")

    # ---------- verdict ----------
    lines.append("=== VERDICT ===")
    lines.append("  ok (kernel kptr)    : %d" % ok_addr)
    lines.append("  numeric offsets     : %d" % ok_numeric)
    lines.append("  present but not kptr: %d" % not_kptr)
    lines.append("  not in loaded blocks: %d" % not_in_blocks)
    lines.append("  placeholder (0x0)   : %d" % zero_or_unknown)
    lines.append("  total checked       : %d" % len(validated))
    lines.append("")
    lines.append("Text accessor patterns found: %d" % len(pat))
    lines.append("")

    # write
    try:
        with open(OUT, "w") as fh:
            for l in lines:
                fh.write(l + "\n")
        print("[+] wrote " + OUT)
    except Exception as e:
        print("[-] write: %s" % str(e))

    try:
        with open(OUT_JSON, "w") as fh:
            fh.write(json.dumps(validated, indent=2, sort_keys=True))
        print("[+] wrote " + OUT_JSON)
    except Exception as e:
        print("[-] write json: %s" % str(e))

    print("=== DONE ===")


try:
    main()
except Exception as e:
    print("[-] FATAL: %s" % str(e))
    traceback.print_exc()
    try:
        with open(OUT, "a") as fh:
            fh.write("FATAL: %s\n" % str(e))
            fh.write(traceback.format_exc())
    except Exception:
        pass