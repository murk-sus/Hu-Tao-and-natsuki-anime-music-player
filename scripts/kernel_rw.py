# -*- coding: utf-8 -*-
# @runtime Jython
# final_recon.py — full reconnaissance for kread on iOS 27.0 / 24A437

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
OUT_JSON = os.path.join(WS, "final_offsets.json")

KPTR_MIN = 0xFFFFFFF000000000
KPTR_MAX = 0xFFFFFFFFFF000000

NECP_FUNCS = [
    ("necp_open",                 0xFFFFFFF00A4E411C),
    ("necp_client_add_flow",      0xFFFFFFF00A4E843C),
    ("necp_client_remove_flow",   0xFFFFFFF00A4E93C4),
    ("necp_client_copy_interface",0xFFFFFFF00A4EAC7C),
    ("necp_client_copy_update",   0xFFFFFFF00A4EC264),
]

TARGET_STRINGS = {
    "assigned_results_copyout": "necp_client_copy assigned results copyout error",
    "assigned_tlv_header":      "necp_client_copy assigned results tlv_header copyout error",
    "result_copyout":           "necp_client_copy result copyout error",
    "group_members_copyout":    "necp_client_copy group members copyout error",
    "params_copyout":           "necp_client_copy parameters copyout error",
    "flow_divert_tlv_copyout":  "necp_client_copy request flow divert TLV copyout error",
    "copy_interface_copyout":   "necp_client_copy_interface copyout error",
    "copy_update_copyout":      "Copy client update copyout error",
}

IFNET_ARRAY_GLOBALS = [
    ("ifnet_array_base",  0xFFFFFFF00AD75720),
    ("ifnet_array_size",  0xFFFFFFF00AD75718),
    ("ifnet_array_count", 0xFFFFFFF00AD75728),
]

FLOW_KALLOC_TYPE_VAR = 0xFFFFFFF007C62E68

VALIDATE_OFFSETS = {
    "off_kernel_base":       "0xFFFFFFF007004000",
    "off_g_kernproc":        "0xFFFFFFF007BBF040",
    "off_g_task_list":       "0xFFFFFFF0080D93F0",
    "off_g_allproc":         "0xFFFFFFF007BBF048",
    "off_g_kernel_task":     "0xFFFFFFF00700DC70",
    "off_g_zone_map":        "0xFFFFFFF00AD6A800",
    "off_g_kernel_map":      "0xFFFFFFF007BBE228",
    "off_mach_trap_table":   "0xFFFFFFF007BE8018",
    "off_sysent_base":       "0xFFFFFFF007C192A0",
    "off_necp_open":         "0xFFFFFFF00A4E411C",
    "off_necp_client_add_flow": "0xFFFFFFF00A4E843C",
    "off_necp_client_remove_flow": "0xFFFFFFF00A4E93C4",
    "off_fn_copyin":         "0xFFFFFFF00A7B9570",
    "off_fn_copyout":        "0xFFFFFFF00A2C6C28",
    "off_fn_kalloc_ext":     "0xFFFFFFF00A200DCC",
    "off_fn_kfree_ext":      "0xFFFFFFF00A201000",
    "off_zone_data_kalloc":  "0xFFFFFFF007C62E70",
    "off_zone_early_kalloc": "0xFFFFFFF007BBB170",
    "off_zone_kalloc_type_var": "0xFFFFFFF007BC2800",
    "off_zone_site_struct_task": "0xFFFFFFF007C64080",
    "off_zone_site_struct_proc": "0xFFFFFFF007C71240",
    "off_zone_site_struct_thread": "0xFFFFFFF007C63D00",
    "off_zone_site_struct_ucred": "0xFFFFFFF006F140",
}

NUMERIC_OFFSETS = {
    "off_proc_p_pid":        0x74,
    "off_proc_p_task":       0x78,
    "off_proc_ro_p_ucred":   0x98,
    "off_proc_p_csflags":    0xA8,
    "off_task_bsd_info":     0x4E0,
    "off_task_itk_space":    0x320,
    "off_task_cr_label":     0xE8,
    "off_task_map":          0x28,
    "off_ucred_cr_uid":      0x18,
    "off_ucred_cr_svuid":    0x1C,
    "off_ucred_cr_gid":      0x20,
    "off_ucred_cr_svgid":    0x24,
}


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


def read_u32(addr):
    try:
        ga = sa(addr)
        if ga is None:
            return None
        return int(currentProgram.getMemory().getInt(ga)) & 0xFFFFFFFF
    except Exception:
        return None


def read_u64(addr):
    try:
        ga = sa(addr)
        if ga is None:
            return None
        return int(currentProgram.getMemory().getLong(ga)) & 0xFFFFFFFFFFFFFFFF
    except Exception:
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
            return ["(no result)"]
        if not r.decompileCompleted():
            return ["(failed: %s)" % str(r.getErrorMessage())]
        c = r.getDecompiledFunction()
        if c is None:
            return ["(empty)"]
        for line in c.getC().split("\n"):
            out.append("  " + line.rstrip())
    except Exception as e:
        out.append("(exception: %s)" % str(e))
    return out


def disasm_func(f, maxn):
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


def find_string_xrefs(target_addr, max_hits=8):
    out = []
    target = _u(target_addr)
    for s, e, n, is_exec in blocks():
        if not is_exec:
            continue
        addr = s
        while addr < e - 8:
            b0 = read_u32(addr)
            b1 = read_u32(addr + 4)
            if b0 is None or b1 is None:
                addr += 4
                continue
            if (b0 & 0x9F000000) == 0x90000000:
                rd = b0 & 0x1F
                immlo = (b0 >> 29) & 3
                immhi = (b0 >> 5) & 0x7FFFF
                imm = (immhi << 2) | immlo
                if imm & 0x100000:
                    imm -= 0x200000
                page = (addr & ~0xFFF) + (imm << 12)
                if (b1 & 0xFF800000) == 0x91000000:
                    rn = (b1 >> 5) & 0x1F
                    rd2 = b1 & 0x1F
                    imm12 = (b1 >> 10) & 0xFFF
                    if rn == rd and rd2 == rd:
                        resolved = (page + imm12) & 0xFFFFFFFFFFFFFFFF
                        if resolved == target:
                            out.append(addr)
                            if len(out) >= max_hits:
                                return out
            addr += 4
    return out


def find_string_occurrences():
    hits = {}
    mem = currentProgram.getMemory()
    for key, needle in TARGET_STRINGS.items():
        found = []
        try:
            jn = zeros(len(needle), 'b')
            for i in range(len(needle)):
                v = ord(needle[i])
                if v > 127:
                    v -= 256
                jn[i] = v
            addr = mem.getMinAddress()
            mon = TaskMonitor.DUMMY
            while addr is not None:
                try:
                    h = mem.findBytes(addr, jn, None, True, mon)
                except Exception:
                    break
                if h is None:
                    break
                found.append(_u(h.getOffset()))
                if len(found) >= 4:
                    break
                nxt = h.add(1)
                if nxt is None:
                    break
                addr = nxt
        except Exception:
            pass
        hits[key] = found
    return hits


def extract_mem(raw):
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
    if (raw & 0xFFC00000) == 0xF8400000:
        i = (raw >> 12) & 0x1FF
        if i & 0x100:
            i -= 0x200
        return ("ldur_x", (raw >> 5) & 0x1F, i)
    if (raw & 0xFFC00000) == 0xB8400000:
        i = (raw >> 12) & 0x1FF
        if i & 0x100:
            i -= 0x200
        return ("ldur_w", (raw >> 5) & 0x1F, i)
    return None


def main():
    print("=== final_recon.py ===")
    lines = []
    out_json = {}

    lines.append("=== PROGRAM ===")
    lines.append("name = %s" % currentProgram.getName())
    lines.append("min  = %s" % fmt(currentProgram.getMemory().getMinAddress().getOffset()))
    lines.append("max  = %s" % fmt(currentProgram.getMemory().getMaxAddress().getOffset()))
    lines.append("")

    print("[+] locating strings...")
    str_hits = find_string_occurrences()
    lines.append("=== STRING HITS ===")
    for key, hits in str_hits.items():
        lines.append("--- %s ---" % key)
        for a in hits:
            blk = inblk(a)
            lines.append("  str @ %s  [%s]" % (fmt(a), blk[2] if blk else "?"))
    lines.append("")

    print("[+] resolving xrefs via ADRP+ADD...")
    lines.append("=== XREF RESOLUTION (ADRP+ADD) ===")
    func_candidates = {}
    for key, hits in str_hits.items():
        for str_addr in hits:
            xrefs = find_string_xrefs(str_addr, max_hits=8)
            lines.append("--- %s @ %s : %d xrefs ---" % (key, fmt(str_addr), len(xrefs)))
            for pc in xrefs:
                blk = inblk(pc)
                f = find_func_by_addr(pc)
                fn = str(f.getName()) if f is not None else "?"
                fe = _u(f.getEntryPoint().getOffset()) if f is not None else None
                lines.append("    ref @ %s  [%s]  func=%s %s" % (
                    fmt(pc), blk[2] if blk else "?", fn, fmt(fe) if fe else ""))
                if fe is not None:
                    func_candidates.setdefault(fe, set()).add(key)
    lines.append("")

    lines.append("=== CANDIDATE FUNCTIONS (by needle refs) ===")
    ranked = sorted(func_candidates.items(), key=lambda kv: -len(kv[1]))
    for fe, keys in ranked[:12]:
        f = find_func_by_addr(fe)
        nm = str(f.getName()) if f is not None else "?"
        try:
            sz = int(f.getBody().getNumAddresses()) if f is not None else 0
        except Exception:
            sz = 0
        lines.append("  %s  %-28s  size=0x%-6X  needles=%s" % (
            fmt(fe), nm, sz, ",".join(sorted(keys))))
    lines.append("")

    if ranked:
        top_fe = ranked[0][0]
        lines.append("=== TOP CANDIDATE FULL DUMP @ %s ===" % fmt(top_fe))
        f = find_func_by_addr(top_fe)
        if f is not None:
            try:
                sz = int(f.getBody().getNumAddresses())
            except Exception:
                sz = 0
            lines.append("size = 0x%X" % sz)

            lines.append("--- DISASM (interesting ldr/str 0x20..0x400) ---")
            for pc, raw, txt in disasm_func(f, 500):
                r = extract_mem(raw)
                if r is None:
                    continue
                kind, base, imm = r
                if 0x20 <= imm <= 0x400:
                    lines.append("  %s  %-8s  [x%-2d, #0x%X]  %s" % (
                        fmt(pc), kind, base, imm, txt))

            lines.append("")
            lines.append("--- DECOMPILE ---")
            for l in decompile(f, 120):
                lines.append(l)
        lines.append("")

    lines.append("=== KALLOC_TYPE_VAR (flow alloc) @ %s ===" % fmt(FLOW_KALLOC_TYPE_VAR))
    blk = inblk(FLOW_KALLOC_TYPE_VAR)
    if blk:
        lines.append("block = %s" % blk[2])
        for off in range(0, 0x40, 8):
            v = read_u64(FLOW_KALLOC_TYPE_VAR + off)
            lines.append("  +0x%02X: %s" % (off, fmt(v) if v is not None else "err"))
    lines.append("")

    lines.append("=== IFNET ARRAY GLOBALS ===")
    for name, addr in IFNET_ARRAY_GLOBALS:
        v = read_u64(addr)
        blk = inblk(addr)
        lines.append("  %-20s @ %s  [%s]  u64=%s" % (
            name, fmt(addr), blk[2] if blk else "?", fmt(v) if v is not None else "err"))
    lines.append("")

    lines.append("=== NECP FUNCTIONS (mem ops 0x20..0x400) ===")
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
        seen = set()
        for pc, raw, txt in disasm_func(f, 500):
            r = extract_mem(raw)
            if r is None:
                continue
            kind, base, imm = r
            if not (0x20 <= imm <= 0x400):
                continue
            if imm in seen:
                continue
            seen.add(imm)
            lines.append("  %s  %-8s  [x%-2d, #0x%X]" % (fmt(pc), kind, base, imm))
        lines.append("")

    lines.append("=== VALIDATE KERNEL OFFSETS ===")
    ok = 0
    fail = 0
    for name, val in VALIDATE_OFFSETS.items():
        try:
            ival = int(val, 16) if val.startswith("0x") else int(val)
        except Exception:
            continue
        blk = inblk(ival)
        if blk is None:
            lines.append("  %-30s %s  NOT_IN_BLOCKS" % (name, fmt(ival)))
            fail += 1
            continue
        v = read_u64(ival)
        is_kptr = (v is not None and KPTR_MIN <= v <= KPTR_MAX)
        lines.append("  %-30s %s  [%s]  u64=%s  %s" % (
            name, fmt(ival), blk[2], fmt(v) if v is not None else "err",
            "KPTR_OK" if is_kptr else "not_kptr"))
        if is_kptr:
            ok += 1
        else:
            fail += 1

    lines.append("  valid kptr: %d / %d" % (ok, ok + fail))
    lines.append("")

    lines.append("=== NUMERIC STRUCT OFFSETS ===")
    for name, imm in NUMERIC_OFFSETS.items():
        lines.append("  %-30s +0x%X" % (name, imm))
    lines.append("")

    lines.append("=== VERDICT ===")
    if ranked:
        lines.append("Top candidate function: %s" % fmt(ranked[0][0]))
        lines.append("Check disasm section above for ldr [xN, #0x20/0x68/0x70/0x88]")
        lines.append("with base = x19..x24 — these are flow struct field accessors.")
    lines.append("")

    try:
        with open(OUT, "w") as fh:
            for l in lines:
                fh.write(l + "\n")
        print("[+] wrote " + OUT)
    except Exception as e:
        print("[-] write: %s" % str(e))

    try:
        out_json = {
            "candidate_funcs": [{"addr": fmt(fe), "needles": sorted(list(k))}
                                for fe, k in ranked[:12]],
            "valid_kptr_count": ok,
        }
        with open(OUT_JSON, "w") as fh:
            fh.write(json.dumps(out_json, indent=2, sort_keys=True))
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