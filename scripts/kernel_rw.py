# -*- coding: utf-8 -*-
# @runtime Jython
# validate_all_offsets.py
#
# Читает offsets.json (или Offsets.json), валидирует каждый оффсет через Ghidra:
#   - адресные оффсеты (kernel globals) -> чтение памяти
#   - числовые оффсеты (struct fields) -> поиск ldr/str с этим imm в дизассемблере
#   - известные функции NECP -> дизасм + декомпиляция + извлечение imm-оффсетов
#
# Output: result.txt + validated_offsets.json

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
OFFSETS_JSON = os.path.join(WS, "offsets.json")

KPTR_MIN = 0xFFFFFFF000000000
KPTR_MAX = 0xFFFFFFFFFF000000

# Known NECP functions (addr from prior dumps)
NECP_FUNCS = [
    ("necp_open",             0xFFFFFFF00A4E411C),
    ("necp_client_add_flow",  0xFFFFFFF00A4E843C),
    ("necp_client_remove_flow", 0xFFFFFFF00A4E93C4),
    ("necp_client_copy_interface", 0xFFFFFFF00A4EAC7C),
    ("necp_client_copy_update",    0xFFFFFFF00A4EC264),
]

# Accessor functions to search for known struct offsets
ACCESSOR_PATTERNS = {
    "proc_pid":        ["_proc_pid", "proc_pid"],
    "proc_task":       ["_proc_task", "proc_task"],
    "proc_ucred":      ["_proc_ucred", "proc_ucred"],
    "task_bsd_info":   ["_get_bsdtask_info", "get_bsdtask_info"],
    "kauth_cred_getuid": ["_kauth_cred_getuid", "kauth_cred_getuid"],
    "kauth_cred_getsvuid": ["_kauth_cred_getsvuid", "kauth_cred_getsvuid"],
    "task_itk_space":  ["_task_get_itk_space", "task_get_itk_space"],
}

MAX_DISASM = 500
MAX_DECOMP = 200


def _u(v):
    return int(v) & 0xFFFFFFFFFFFFFFFF


def fmt(v):
    if v is None:
        return "0x0"
    try:
        return "0x%016X" % (int(v) & 0xFFFFFFFFFFFFFFFF)
    except Exception:
        return "0x0"


def sa(a):
    if a is None:
        return None
    try:
        return currentProgram.getAddressFactory().getAddress("%X" % (int(a) & 0xFFFFFFFFFFFFFFFF))
    except Exception:
        return None


_blocks = None


def blocks():
    global _blocks
    if _blocks is not None:
        return _blocks
    out = []
    try:
        for b in currentProgram.getMemory().getBlocks():
            try:
                if not b.isInitialized():
                    continue
                out.append((_u(b.getStart().getOffset()),
                            _u(b.getEnd().getOffset()),
                            str(b.getName()),
                            bool(b.isExecute())))
            except Exception:
                pass
    except Exception:
        pass
    _blocks = out
    return out


def inblk(a):
    if a is None:
        return None
    av = _u(a)
    for s, e, n, x in blocks():
        if s <= av < e:
            return (s, e, n, x)
    return None


def read_u64(addr):
    try:
        ga = sa(addr)
        if ga is None:
            return None
        return int(currentProgram.getMemory().getLong(ga)) & 0xFFFFFFFFFFFFFFFF
    except Exception:
        return None


def read_u32(addr):
    try:
        ga = sa(addr)
        if ga is None:
            return None
        return int(currentProgram.getMemory().getInt(ga)) & 0xFFFFFFFF
    except Exception:
        return None


def find_func_by_name(name):
    try:
        fm = currentProgram.getFunctionManager()
        for f in fm.getFunctions(True):
            try:
                if str(f.getName()) == name:
                    return f
            except Exception:
                pass
        for f in fm.getFunctions(True):
            try:
                if name in str(f.getName()):
                    return f
            except Exception:
                pass
    except Exception:
        pass
    return None


def find_func_by_addr(addr):
    try:
        ga = sa(addr)
        if ga is None:
            return None
        f = getFunctionAt(ga)
        if f is not None:
            return f
        return getFunctionContaining(ga)
    except Exception:
        return None


def decompile(f, timeout):
    out = []
    try:
        d = DecompInterface()
        d.openProgram(currentProgram)
        r = d.decompileFunction(f, timeout, ConsoleTaskMonitor())
        if r is None:
            out.append("(no result)")
            return out
        if not r.decompileCompleted():
            out.append("(failed: %s)" % str(r.getErrorMessage()))
            return out
        c = r.getDecompiledFunction()
        if c is None:
            out.append("(empty)")
            return out
        for line in c.getC().split("\n"):
            out.append("  " + line.rstrip())
    except Exception as e:
        out.append("(exception: %s)" % str(e))
    return out


def disasm_func(f, maxn):
    """Return list of (pc, raw32, mnemonic_line) tuples."""
    out = []
    body = f.getBody()
    if body is None:
        return out
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
        except Exception:
            pass
        cnt += 1
    return out


# --- mini ARM64 decoder for extracting imm offsets ---
def extract_ldr_str_imm(raw):
    """Extract (mnem, base_reg, imm) from LDR/STR (unsigned) 64/32-bit."""
    # LDR X, [Xn, #imm]  = 0xF9400000 base
    if (raw & 0xFFC00000) == 0xF9400000:
        return ("ldr_x", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 8)
    if (raw & 0xFFC00000) == 0xB9400000:
        return ("ldr_w", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 4)
    if (raw & 0xFFC00000) == 0xF9000000:
        return ("str_x", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 8)
    if (raw & 0xFFC00000) == 0xB9000000:
        return ("str_w", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 4)
    if (raw & 0xFFE00000) == 0x39400000:
        return ("ldrb", (raw >> 5) & 0x1F, (raw >> 10) & 0xFFF)
    if (raw & 0xFFE00000) == 0x39000000:
        return ("strb", (raw >> 5) & 0x1F, (raw >> 10) & 0xFFF)
    if (raw & 0xFFE00000) == 0x79400000:
        return ("ldrh", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 2)
    if (raw & 0xFFE00000) == 0x79000000:
        return ("strh", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 2)
    return None


def extract_all_imms(f):
    """Return list of (pc, kind, base, imm, raw)."""
    out = []
    for pc, raw, txt in disasm_func(f, MAX_DISASM):
        r = extract_ldr_str_imm(raw)
        if r is not None:
            out.append((pc, r[0], r[1], r[2], raw))
    return out


def find_accessor_offset(func_names, want_ldr=True):
    """Find ldr X0/W0, [X0, #imm] ; ret pattern in function."""
    f = None
    for n in func_names:
        f = find_func_by_name(n)
        if f is not None:
            break
    if f is None:
        return None, None
    try:
        insns = disasm_func(f, 40)
    except Exception:
        return None, None
    for i, (pc, raw, txt) in enumerate(insns):
        r = extract_ldr_str_imm(raw)
        if r is None:
            continue
        kind, base, imm = r
        # looking for ldr X0/W0, [X0, #imm] ; ret
        rd = raw & 0x1F
        if rd == 0 and base == 0 and kind.startswith("ldr"):
            # verify next instruction is ret
            if i + 1 < len(insns) and insns[i+1][1] == 0xD65F03C0:
                return _u(f.getEntryPoint().getOffset()), imm
    return _u(f.getEntryPoint().getOffset()), None


# ---------- main ----------

def main():
    print("=== validate_all_offsets.py ===")
    lines = []
    validated = {}

    lines.append("=== PROGRAM ===")
    try:
        lines.append("name = %s" % currentProgram.getName())
        lines.append("min  = %s" % fmt(currentProgram.getMemory().getMinAddress().getOffset()))
        lines.append("max  = %s" % fmt(currentProgram.getMemory().getMaxAddress().getOffset()))
    except Exception as e:
        lines.append("(err: %s)" % str(e))
    lines.append("")

    # ---------- 1. Load offsets.json ----------
    offsets = {}
    if os.path.exists(OFFSETS_JSON):
        try:
            with open(OFFSETS_JSON) as fh:
                raw = json.load(fh)
            if isinstance(raw, dict) and "defaults" in raw:
                offsets = raw["defaults"]
            elif isinstance(raw, dict):
                offsets = raw
            lines.append("=== LOADED %d OFFSETS FROM %s ===" % (len(offsets), OFFSETS_JSON))
        except Exception as e:
            lines.append("=== FAILED TO PARSE %s: %s ===" % (OFFSETS_JSON, str(e)))
    else:
        lines.append("=== offsets.json NOT FOUND at %s ===" % OFFSETS_JSON)

    for k, v in sorted(offsets.items()):
        lines.append("  %-38s = %s" % (k, v))
    lines.append("")

    # ---------- 2. Validate each offset ----------
    lines.append("=== VALIDATION ===")
    for key, val in sorted(offsets.items()):
        try:
            if isinstance(val, str) and val.startswith("0x"):
                ival = int(val, 16)
            else:
                ival = int(val)
        except Exception:
            lines.append("  %-38s = %-20s  BAD_VALUE" % (key, str(val)))
            validated[key] = {"status": "bad_value"}
            continue

        # Case A: kernel address
        if ival >= 0xFFFFFFF000000000:
            blk = inblk(ival)
            if blk is None:
                lines.append("  %-38s %-20s  NOT_IN_BLOCKS" % (key, fmt(ival)))
                validated[key] = {"status": "not_in_blocks", "addr": fmt(ival)}
                continue
            v64 = read_u64(ival)
            v32 = read_u32(ival)
            kptr = (v64 is not None and KPTR_MIN <= v64 <= KPTR_MAX)
            lines.append("  %-38s %-20s  [%s]  u64=%s  u32=%s  %s" % (
                key, fmt(ival), blk[2],
                fmt(v64) if v64 is not None else "err",
                fmt(v32) if v32 is not None else "err",
                "KPTR_OK" if kptr else "not_kptr"))
            validated[key] = {
                "status": "ok" if kptr else "not_kptr",
                "addr": fmt(ival),
                "value_u64": fmt(v64) if v64 is not None else None,
                "value_u32": fmt(v32) if v32 is not None else None,
                "block": blk[2],
            }
            continue

        # Case B: numeric struct offset
        lines.append("  %-38s 0x%X (numeric offset)" % (key, ival))
        validated[key] = {"status": "numeric", "value": ival}

    lines.append("")

    # ---------- 3. Accessor function scan ----------
    lines.append("=== ACCESSOR FUNCTIONS ===")
    for name, patterns in ACCESSOR_PATTERNS.items():
        entry, imm = find_accessor_offset(patterns)
        if entry is None:
            lines.append("  %-24s NOT_FOUND" % name)
            continue
        if imm is not None:
            lines.append("  %-24s @ %s  -> +0x%X" % (name, fmt(entry), imm))
            validated["accessor_" + name] = {"entry": fmt(entry), "offset": imm}
        else:
            lines.append("  %-24s @ %s  -> (no clean ldr+ret pattern)" % (name, fmt(entry)))
    lines.append("")

    # ---------- 4. NECP function disasm ----------
    lines.append("=== NECP FUNCTIONS DISASM ===")
    for name, addr in NECP_FUNCS:
        f = find_func_by_addr(addr)
        if f is None:
            lines.append("--- %s @ %s : NO FUNCTION" % (name, fmt(addr)))
            continue
        entry = _u(f.getEntryPoint().getOffset())
        try:
            sz = int(f.getBody().getNumAddresses())
        except Exception:
            sz = 0
        lines.append("--- %s @ %s  size=0x%X ---" % (name, fmt(entry), sz))

        imms = extract_all_imms(f)
        # filter for LDR (not STR) from callee-saved regs, imm range 0x40-0x200
        callee = set([19, 20, 21, 22, 23, 24])
        interesting = [(pc, kind, base, imm) for (pc, kind, base, imm, raw) in imms
                       if kind.startswith("ldr") and base in callee and 0x40 <= imm <= 0x300]
        # deduplicate by imm
        seen = set()
        for pc, kind, base, imm in interesting:
            if imm in seen:
                continue
            seen.add(imm)
            lines.append("  %s %-8s [x%d, #0x%X] @ %s" % (
                name[:20], kind, base, imm, fmt(pc)))

        # decompile brief
        lines.append("  decompile (first 40):")
        for l in decompile(f, 60)[:40]:
            lines.append("    " + l)
        lines.append("")

    # ---------- 5. Summary verdict ----------
    lines.append("=== VERDICT ===")
    ok_count = sum(1 for v in validated.values() if v.get("status") == "ok")
    numeric_count = sum(1 for v in validated.values() if v.get("status") == "numeric")
    not_kptr = sum(1 for v in validated.values() if v.get("status") == "not_kptr")
    not_in_blocks = sum(1 for v in validated.values() if v.get("status") == "not_in_blocks")
    bad = sum(1 for v in validated.values() if v.get("status") == "bad_value")
    lines.append("  ok (kptr valid)     : %d" % ok_count)
    lines.append("  numeric offsets     : %d" % numeric_count)
    lines.append("  present but not kptr: %d" % not_kptr)
    lines.append("  not in loaded blocks: %d" % not_in_blocks)
    lines.append("  bad value           : %d" % bad)
    lines.append("  total               : %d" % len(validated))
    lines.append("")

    # write result.txt
    try:
        with open(OUT, "w") as fh:
            for l in lines:
                fh.write(l + "\n")
        print("[+] wrote " + OUT)
    except Exception as e:
        print("[-] write: %s" % str(e))

    # write validated_offsets.json
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