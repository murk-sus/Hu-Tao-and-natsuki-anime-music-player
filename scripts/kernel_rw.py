# -*- coding: utf-8 -*-
# @runtime Jython
# kernel_rw.py — fast iOS kernel reconnaissance for Ghidra 12+

import os
import json
import traceback
from jarray import zeros
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor, TaskMonitor

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WS, "kernel_rw_report.txt")
OUT_JSON = os.path.join(WS, "kernel_rw_report.json")

KPTR_MIN = 0xFFFFFFF000000000
KPTR_MAX = 0xFFFFFFFFFF000000

TAG_MASKS = [0xFFFFFFFFFFFFFFFF, 0x0000FFFFFFFFFFFF, 0x000000FFFFFFFFFF, 0x00000000FFFFFFFF]

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

COPY_RESULT_NEEDLES = {"assigned_results_copyout", "assigned_tlv_header",
                       "result_copyout", "group_members_copyout",
                       "params_copyout", "flow_divert_tlv_copyout"}

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
    "off_zone_site_struct_ucred": "0xFFFFFFF007C6F140",
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

KTRR_STRINGS = ["KTRR", "KPP", "kernel patch protection", "sptm", "SPTM", "Secure Page Table Monitor", "ctrr", "CTRR"]

def _u(v): return int(v) & 0xFFFFFFFFFFFFFFFF

def fmt(v):
    if v is None: return "0x0"
    try: return "0x%016X" % (int(v) & 0xFFFFFFFFFFFFFFFF)
    except: return "0x0"

def sa(a):
    if a is None: return None
    try: return currentProgram.getAddressFactory().getAddress("%X" % (int(a) & 0xFFFFFFFFFFFFFFFF))
    except: return None

_blocks_cache = None
def blocks():
    global _blocks_cache
    if _blocks_cache is not None: return _blocks_cache
    out = []
    try:
        for b in currentProgram.getMemory().getBlocks():
            try:
                if not b.isInitialized(): continue
                out.append((_u(b.getStart().getOffset()), _u(b.getEnd().getOffset()), str(b.getName()), bool(b.isExecute())))
            except: pass
    except: pass
    _blocks_cache = out
    return out

def inblk(a):
    if a is None: return None
    av = _u(a)
    for s, e, n, x in blocks():
        if s <= av < e: return (s, e, n, x)
    return None

def read_u32(addr):
    try:
        ga = sa(addr)
        if ga is None: return None
        return int(currentProgram.getMemory().getInt(ga)) & 0xFFFFFFFF
    except: return None

def read_u64(addr):
    try:
        ga = sa(addr)
        if ga is None: return None
        return int(currentProgram.getMemory().getLong(ga)) & 0xFFFFFFFFFFFFFFFF
    except: return None

def find_func_by_addr(addr):
    try:
        ga = sa(addr)
        if ga is None: return None
        f = getFunctionAt(ga)
        if f is not None: return f
        return getFunctionContaining(ga)
    except: return None

def decompile(f, timeout):
    out = []
    try:
        d = DecompInterface()
        d.openProgram(currentProgram)
        r = d.decompileFunction(f, timeout, ConsoleTaskMonitor())
        if r is None: return ["(no result)"]
        if not r.decompileCompleted(): return ["(failed: %s)" % str(r.getErrorMessage())]
        c = r.getDecompiledFunction()
        if c is None: return ["(empty)"]
        for line in c.getC().split("\n"): out.append("  " + line.rstrip())
    except Exception as e: out.append("(exception: %s)" % str(e))
    return out

def disasm_func(f, maxn):
    out = []
    body = f.getBody()
    if body is None: return out
    try: it = body.getAddresses(True)
    except: return out
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
        except: pass
        cnt += 1
    return out

def load_exec_buffers():
    buffers = []
    for s, e, n, is_exec in blocks():
        if not is_exec: continue
        sz = e - s
        if sz <= 0 or sz > 64 * 1024 * 1024: continue
        try:
            ga = sa(s)
            jbuf = zeros(sz, 'b')
            currentProgram.getMemory().getBytes(ga, jbuf)
            b = bytearray(sz)
            for i in range(sz):
                v = int(jbuf[i])
                if v < 0: v += 256
                b[i] = v
            buffers.append((s, sz, b, n))
        except Exception as ex: print("[-] load block %s failed: %s" % (n, str(ex)))
    return buffers

def find_oslog_descriptors(string_vas):
    desc_map = {}
    scanned = set()
    stats = {"blocks": 0, "pointers": 0, "rel32": 0}
    for s, e, n, is_exec in blocks():
        if is_exec: continue
        if not any(k in n for k in ("__const", "__data", "__common", "__bss")): continue
        if n in scanned: continue
        scanned.add(n)
        sz = e - s
        if sz <= 8 or sz > 64 * 1024 * 1024: continue
        stats["blocks"] += 1
        try:
            ga = sa(s)
            jbuf = zeros(sz, 'b')
            currentProgram.getMemory().getBytes(ga, jbuf)
            i = 0
            while i + 8 <= sz:
                v = 0
                for k in range(8): v |= (int(jbuf[i + k]) & 0xFF) << (8 * k)
                stats["pointers"] += 1
                for mask in TAG_MASKS:
                    masked = v & mask
                    if masked in string_vas:
                        desc_map[masked] = s + i
                        break
                i += 8
            i = 0
            while i + 4 <= sz:
                rel = 0
                for k in range(4): rel |= (int(jbuf[i + k]) & 0xFF) << (8 * k)
                if rel & 0x80000000: rel -= 0x100000000
                tgt = s + i + rel
                if tgt in string_vas:
                    desc_map[tgt] = s + i
                    stats["rel32"] += 1
                i += 4
        except Exception as ex: print("[-] scan desc block %s failed: %s" % (n, str(ex)))
    return desc_map, stats

def find_all_xrefs_to_targets(target_set, buffers):
    if not target_set: return {}
    results = {}
    for s, sz, buf, name in buffers:
        addr = s
        i = 0
        while i + 8 <= sz:
            b0 = buf[i] | (buf[i+1] << 8) | (buf[i+2] << 16) | (buf[i+3] << 24)
            b1 = buf[i+4] | (buf[i+5] << 8) | (buf[i+6] << 16) | (buf[i+7] << 24)
            if (b0 & 0x9F000000) == 0x90000000:
                rd = b0 & 0x1F
                immlo = (b0 >> 29) & 3
                immhi = (b0 >> 5) & 0x7FFFF
                imm = (immhi << 2) | immlo
                if imm & 0x100000: imm -= 0x200000
                page = (addr & ~0xFFF) + (imm << 12)
                if (b1 & 0xFF800000) == 0x91000000:
                    rn = (b1 >> 5) & 0x1F
                    rd2 = b1 & 0x1F
                    imm12 = (b1 >> 10) & 0xFFF
                    if rn == rd and rd2 == rd:
                        resolved = (page + imm12) & 0xFFFFFFFFFFFFFFFF
                        if resolved in target_set:
                            results.setdefault(resolved, []).append(addr)
                elif (b1 & 0xFFC00000) == 0xF9400000:
                    rn = (b1 >> 5) & 0x1F
                    imm12 = ((b1 >> 10) & 0xFFF) * 8
                    if rn == rd:
                        ptr_addr = page + imm12
                        if ptr_addr in target_set:
                            results.setdefault(ptr_addr, []).append(addr)
            addr += 4
            i += 4
    return results

def find_string_occurrences():
    hits = {}
    mem = currentProgram.getMemory()
    for key, needle in TARGET_STRINGS.items():
        found = []
        try:
            jn = zeros(len(needle), 'b')
            for i in range(len(needle)):
                v = ord(needle[i])
                if v > 127: v -= 256
                jn[i] = v
            addr = mem.getMinAddress()
            mon = TaskMonitor.DUMMY
            while addr is not None:
                try:
                    h = mem.findBytes(addr, jn, None, True, mon)
                except: break
                if h is None: break
                found.append(_u(h.getOffset()))
                if len(found) >= 4: break
                nxt = h.add(1)
                if nxt is None: break
                addr = nxt
        except: pass
        hits[key] = found
    return hits

def extract_mem(raw):
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
    return None

def find_accessor_offsets(buffers):
    results = []
    for s, sz, buf, name in buffers:
        i = 0
        while i + 8 <= sz:
            b0 = buf[i] | (buf[i+1] << 8) | (buf[i+2] << 16) | (buf[i+3] << 24)
            b1 = buf[i+4] | (buf[i+5] << 8) | (buf[i+6] << 16) | (buf[i+7] << 24)
            if (b0 & 0xFFC00000) == 0xF9400000:
                rn = (b0 >> 5) & 0x1F
                rt = b0 & 0x1F
                imm = ((b0 >> 10) & 0xFFF) * 8
                if rn == 0 and rt == 0:
                    if (b1 & 0xFFFFFFFF) == 0xD65F03C0: results.append((s + i, imm, "ldr_x"))
            elif (b0 & 0xFFC00000) == 0xB9400000:
                rn = (b0 >> 5) & 0x1F
                rt = b0 & 0x1F
                imm = ((b0 >> 10) & 0xFFF) * 4
                if rn == 0 and rt == 0:
                    if (b1 & 0xFFFFFFFF) == 0xD65F03C0: results.append((s + i, imm, "ldr_w"))
            i += 4
    return results

def find_pac_gadgets(buffers):
    gadgets = []
    patterns = [(0xD503237F, "pacibsp"), (0xD503233F, "autia1716"), (0xD65F0FFF, "retab"), (0xD50323FF, "autibsp"), (0xD50323BF, "paciasp")]
    for s, sz, buf, name in buffers:
        i = 0
        while i + 4 <= sz:
            raw = buf[i] | (buf[i+1] << 8) | (buf[i+2] << 16) | (buf[i+3] << 24)
            for pat, label in patterns:
                if raw == pat: gadgets.append((s + i, label))
            i += 4
    return gadgets

def detect_ktrr_strings():
    results = {}
    mem = currentProgram.getMemory()
    for needle in KTRR_STRINGS:
        found = []
        try:
            jn = zeros(len(needle), 'b')
            for i in range(len(needle)):
                v = ord(needle[i])
                if v > 127: v -= 256
                jn[i] = v
            addr = mem.getMinAddress()
            mon = TaskMonitor.DUMMY
            while addr is not None:
                try:
                    h = mem.findBytes(addr, jn, None, True, mon)
                except: break
                if h is None: break
                found.append(_u(h.getOffset()))
                if len(found) >= 8: break
                nxt = h.add(1)
                if nxt is None: break
                addr = nxt
        except: pass
        if found: results[needle] = found
    return results

def analyze_mach_traps():
    results = []
    base = 0xFFFFFFF007BE8018
    blk = inblk(base)
    if blk is None: return [("mach_trap_table not in loaded memory",)]
    for i in range(32):
        addr = base + i * 0x18
        a0 = read_u32(addr)
        a1 = read_u32(addr + 4)
        fn = read_u64(addr + 8)
        if a0 is None: break
        results.append((i, a0, a1, fn))
    return results

def main():
    print("=== kernel_rw.py (fast) ===")
    lines = []
    lines.append("=== PROGRAM ===")
    lines.append("name = %s" % currentProgram.getName())
    lines.append("min  = %s" % fmt(currentProgram.getMemory().getMinAddress().getOffset()))
    lines.append("max  = %s" % fmt(currentProgram.getMemory().getMaxAddress().getOffset()))
    lines.append("")

    lines.append("=== BLOCKS (diagnostic) ===")
    for s, e, n, x in blocks():
        if not x: lines.append("  %-24s  %s..%s  size=0x%X" % (n, fmt(s), fmt(e), e - s))
    lines.append("")

    print("[+] locating strings...")
    str_hits = find_string_occurrences()
    lines.append("=== STRING HITS ===")
    string_vas = set()
    for key, hits in str_hits.items():
        lines.append("--- %s ---" % key)
        for a in hits:
            blk = inblk(a)
            lines.append("  str @ %s  [%s]" % (fmt(a), blk[2] if blk else "?"))
            string_vas.add(_u(a))
    lines.append("")

    print("[+] resolving os_log descriptors...")
    desc_map, desc_stats = find_oslog_descriptors(string_vas)
    lines.append("=== OS_LOG DESCRIPTORS ===")
    lines.append("resolved = %d / %d" % (len(desc_map), len(string_vas)))
    lines.append("scanned_blocks = %d, pointers_checked = %d, rel32_hits = %d" % (desc_stats["blocks"], desc_stats["pointers"], desc_stats["rel32"]))
    for sva, dva in desc_map.items():
        blk = inblk(dva)
        lines.append("  str %s -> desc %s  [%s]" % (fmt(sva), fmt(dva), blk[2] if blk else "?"))
    if not desc_map:
        lines.append("")
        lines.append("  WHY: no pointer to any target string was found in __const/__data.")
        lines.append("  POSSIBLE FIXES:")
        lines.append("    - Ensure kernel.raw is a full Mach-O kernelcache, not a truncated dump.")
        lines.append("    - In Ghidra: load as Mach-O image, NOT as raw binary.")
        lines.append("    - Enable auto-analysis (Analysis -> Auto Analyze) before running this script.")
        lines.append("    - Check that __const block exists and is > 1 MB.")
        lines.append("    - Try 'Search -> For Scalars' in Ghidra on one string VA to see if it is referenced anywhere.")
    lines.append("")

    print("[+] loading exec blocks...")
    buffers = load_exec_buffers()
    total_mb = sum(sz for _, sz, _, _ in buffers) / (1024.0 * 1024.0)
    print("[+] loaded %d blocks, %.1f MB" % (len(buffers), total_mb))
    lines.append("=== TEXT BUFFER ===")
    lines.append("blocks = %d, total = %.1f MB" % (len(buffers), total_mb))
    lines.append("")

    if desc_map:
        target_set = set(desc_map.values())
    else:
        target_set = set()

    print("[+] single-pass xref scan over %d targets..." % len(target_set))
    xref_map = find_all_xrefs_to_targets(target_set, buffers)
    print("[+] total refs to targets: %d" % sum(len(v) for v in xref_map.values()))

    lines.append("=== XREFS ===")
    lines.append("target_set_size = %d" % len(target_set))
    lines.append("targets_with_refs = %d" % len(xref_map))
    lines.append("total_refs = %d" % sum(len(v) for v in xref_map.values()))
    lines.append("")

    func_candidates = {}
    for key, hits in str_hits.items():
        lines.append("--- %s ---" % key)
        for str_addr in hits:
            refs = list(xref_map.get(_u(str_addr), []))
            dva = desc_map.get(_u(str_addr))
            if dva is not None: refs.extend(xref_map.get(_u(dva), []))
            lines.append("  str %s -> %d refs" % (fmt(str_addr), len(refs)))
            for pc in refs[:8]:
                blk = inblk(pc)
                f = find_func_by_addr(pc)
                fn = str(f.getName()) if f is not None else "?"
                fe = _u(f.getEntryPoint().getOffset()) if f is not None else None
                lines.append("    ref @ %s  [%s]  func=%s %s" % (fmt(pc), blk[2] if blk else "?", fn, fmt(fe) if fe else ""))
                if fe is not None: func_candidates.setdefault(fe, set()).add(key)
    lines.append("")

    lines.append("=== CANDIDATE FUNCTIONS ===")
    ranked = sorted(func_candidates.items(), key=lambda kv: -len(kv[1]))
    for fe, keys in ranked[:12]:
        f = find_func_by_addr(fe)
        nm = str(f.getName()) if f is not None else "?"
        try: sz = int(f.getBody().getNumAddresses()) if f is not None else 0
        except: sz = 0
        lines.append("  %s  %-28s  size=0x%-6X  needles=%s" % (fmt(fe), nm, sz, ",".join(sorted(keys))))
    lines.append("")

    def rank_score(item):
        fe, keys = item
        return (len(keys & COPY_RESULT_NEEDLES), len(keys))

    ranked_by_copyresult = sorted(func_candidates.items(), key=rank_score, reverse=True)

    for rank_i, (top_fe, top_keys) in enumerate(ranked_by_copyresult[:3]):
        lines.append("=== CANDIDATE #%d @ %s (needles=%s) ===" % (rank_i + 1, fmt(top_fe), ",".join(sorted(top_keys))))
        f = find_func_by_addr(top_fe)
        if f is None:
            lines.append("(function not found)")
            continue
        try: sz = int(f.getBody().getNumAddresses())
        except: sz = 0
        lines.append("size = 0x%X" % sz)
        lines.append("--- INTERNAL STRING REFS ---")
        fn_hits = {}
        for key, hits in str_hits.items():
            for sva in hits:
                refs = list(xref_map.get(_u(sva), []))
                dva = desc_map.get(_u(sva))
                if dva is not None: refs.extend(xref_map.get(_u(dva), []))
                for pc in refs:
                    f2 = find_func_by_addr(pc)
                    if f2 is None: continue
                    if _u(f2.getEntryPoint().getOffset()) == top_fe:
                        fn_hits.setdefault(key, []).append(pc)
        for key in sorted(fn_hits.keys()):
            lines.append("  %s  (%d refs)" % (key, len(fn_hits[key])))
        lines.append("")
        lines.append("--- DISASM (ldr/str 0x20..0x400) ---")
        for pc, raw, txt in disasm_func(f, 800):
            r = extract_mem(raw)
            if r is None: continue
            kind, base, imm = r
            if 0x20 <= imm <= 0x400:
                lines.append("  %s  %-8s  [x%-2d, #0x%X]" % (fmt(pc), kind, base, imm))
        lines.append("")
        lines.append("--- DECOMPILE ---")
        for l in decompile(f, 180):
            lines.append(l)
        lines.append("")

    print("[+] extracting accessor offsets...")
    acc = find_accessor_offsets(buffers)
    lines.append("=== ACCESSOR OFFSETS (ldr X0,[X0,#imm]; ret) ===")
    lines.append("found = %d" % len(acc))
    for func_addr, imm, kind in acc[:120]:
        lines.append("  %s  +0x%X  (%s)" % (fmt(func_addr), imm, kind))
    lines.append("")

    print("[+] finding PAC gadgets...")
    pac = find_pac_gadgets(buffers)
    lines.append("=== PAC GADGETS ===")
    lines.append("found = %d" % len(pac))
    for addr, label in pac[:60]:
        lines.append("  %s  %s" % (fmt(addr), label))
    lines.append("")

    print("[+] detecting KTRR/KPP strings...")
    ktrr = detect_ktrr_strings()
    lines.append("=== KTRR/KPP DETECTION ===")
    for needle, addrs in ktrr.items():
        lines.append("  %-30s -> %d hits" % (needle, len(addrs)))
        for a in addrs[:4]:
            lines.append("    %s" % fmt(a))
    lines.append("")

    print("[+] analyzing mach trap table...")
    mt = analyze_mach_traps()
    lines.append("=== MACH TRAP TABLE ===")
    if mt and len(mt[0]) == 1:
        lines.append("  %s" % mt[0][0])
    else:
        for idx, a0, a1, fn in mt:
            lines.append("  [%2d] argc=%d stack=0x%X fn=%s" % (idx, a0, a1, fmt(fn)))
    lines.append("")

    lines.append("=== KALLOC_TYPE_VAR @ %s ===" % fmt(FLOW_KALLOC_TYPE_VAR))
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
        lines.append("  %-20s @ %s  [%s]  u64=%s" % (name, fmt(addr), blk[2] if blk else "?", fmt(v) if v is not None else "err"))
    lines.append("")

    lines.append("=== NECP FUNCTIONS ===")
    for name, addr in NECP_FUNCS:
        f = find_func_by_addr(addr)
        if f is None:
            lines.append("--- %s : NO FUNCTION" % name)
            continue
        entry = _u(f.getEntryPoint().getOffset())
        try: sz = int(f.getBody().getNumAddresses())
        except: sz = 0
        lines.append("--- %s @ %s  size=0x%X ---" % (name, fmt(entry), sz))
        seen = set()
        for pc, raw, txt in disasm_func(f, 800):
            r = extract_mem(raw)
            if r is None: continue
            kind, base, imm = r
            if not (0x20 <= imm <= 0x400): continue
            if imm in seen: continue
            seen.add(imm)
            lines.append("  %s  %-8s  [x%-2d, #0x%X]" % (fmt(pc), kind, base, imm))
        lines.append("")

    lines.append("=== VALIDATE KERNEL OFFSETS ===")
    ok = 0
    fail = 0
    for name, val in VALIDATE_OFFSETS.items():
        try:
            ival = int(val, 16) if val.startswith("0x") else int(val)
        except: continue
        blk = inblk(ival)
        if blk is None:
            lines.append("  %-30s %s  NOT_IN_BLOCKS" % (name, fmt(ival)))
            fail += 1
            continue
        v = read_u64(ival)
        is_kptr = (v is not None and KPTR_MIN <= v <= KPTR_MAX)
        lines.append("  %-30s %s  [%s]  u64=%s  %s" % (name, fmt(ival), blk[2], fmt(v) if v is not None else "err", "KPTR_OK" if is_kptr else "not_kptr"))
        if is_kptr: ok += 1
        else: fail += 1
    lines.append("  valid kptr: %d / %d" % (ok, ok + fail))
    lines.append("")

    lines.append("=== NUMERIC STRUCT OFFSETS ===")
    for name, imm in NUMERIC_OFFSETS.items():
        lines.append("  %-30s +0x%X" % (name, imm))
    lines.append("")

    try:
        with open(OUT, "w") as fh:
            for l in lines: fh.write(l + "\n")
        print("[+] wrote " + OUT)
    except Exception as e: print("[-] write: %s" % str(e))

    try:
        out_json = {
            "descriptors_resolved": len(desc_map),
            "descriptor_stats": desc_stats,
            "xref_targets": len(xref_map),
            "xref_total_refs": sum(len(v) for v in xref_map.values()),
            "candidate_funcs": [{"addr": fmt(fe), "needles": sorted(list(k))} for fe, k in ranked_by_copyresult[:12]],
            "valid_kptr_count": ok,
            "valid_kptr_total": ok + fail,
            "accessor_count": len(acc),
            "pac_gadget_count": len(pac),
            "ktrr_hits": {k: len(v) for k, v in ktrr.items()},
        }
        with open(OUT_JSON, "w") as fh:
            fh.write(json.dumps(out_json, indent=2, sort_keys=True))
        print("[+] wrote " + OUT_JSON)
    except Exception as e: print("[-] write json: %s" % str(e))

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
    except: pass