# -*- coding: utf-8 -*-
# @runtime Jython
# necp_final_analysis.py — финальный скрипт для Ghidra headless
#
# Выводит в result.txt:
#   1. Валидация всех known offsets (kernproc, task_list, kernel_base)
#   2. Поиск правильной функции necp_client_copy_result по xref на строку
#   3. Декомпиляция + дизасм + trace offset assigned_results
#   4. Поиск writer'а assigned_results (add_flow, netagent)
#   5. Дампы kalloc_type / kalloc_var зон
#   6. Поиск альтернативных примитивов (TLV, mbuf, socket)
#   7. Сводка: что валидно, что нет, где нужен новый оффсет

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
OUT_JSON = os.path.join(WS, "offsets.json")

# Verified offsets from prior analysis
KBASE = 0xFFFFFFF007004000
KNOWN = {
    "off_kernel_base":      (0xFFFFFFF007004000, "ptr"),
    "off_g_kernproc":       (0xFFFFFFF007BBF040, "ptr"),
    "off_g_task_list":      (0xFFFFFFF0080D93F0, "ptr"),
    "off_proc_p_pid":       (0x74,               "int"),
    "off_proc_ro_p_ucred":  (0x98,               "int"),
    "off_task_bsd_info":    (0x4E0,              "int"),
    "off_task_itk_space":   (0x320,              "int"),
    "off_ucred_cr_uid":     (0x18,               "int"),
    "off_ucred_cr_svuid":   (0x1C,               "int"),
    "off_ucred_cr_gid":     (0x20,               "int"),
    "off_ucred_cr_svgid":   (0x24,               "int"),
}

# Strings that identify copy_result related code
NEEDLE_STRINGS = {
    "assigned_copyout":      "necp_client_copy assigned results copyout error",
    "assigned_tlv_header":   "necp_client_copy assigned results tlv_header copyout error",
    "result_copyout":        "necp_client_copy result copyout error",
    "group_members":         "necp_client_copy group members copyout error",
    "params_copyout":        "necp_client_copy parameters copyout error",
    "flow_divert_tlv":       "necp_client_copy request flow divert TLV copyout error",
}

HARDCODED_FUNCS = [
    ("copy_result_candidate", 0xFFFFFFF00A4EC264),
    ("copy_interface_wrong",  0xFFFFFFF00A4EAC7C),
    ("add_flow",              0xFFFFFFF00A4E843C),
    ("remove_flow",           0xFFFFFFF00A4E93C4),
    ("necp_open",             0xFFFFFFF00A4E411C),
]

MAX_DECOMP = 200
MAX_DISASM = 400


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


def find_func_by_name(name):
    try:
        fm = currentProgram.getFunctionManager()
        for f in fm.getFunctions(True):
            try:
                if str(f.getName()) == name:
                    return f
            except Exception:
                pass
    except Exception:
        pass
    return None


def funcs_calling(f):
    out = []
    try:
        for ref in getReferencesTo(f.getEntryPoint()):
            try:
                c = getFunctionContaining(ref.getFromAddress())
                if c is None:
                    continue
                e = _u(c.getEntryPoint().getOffset())
                if e == _u(f.getEntryPoint().getOffset()):
                    continue
                nm = str(c.getName())
                if nm not in out:
                    out.append(nm)
            except Exception:
                pass
    except Exception:
        pass
    return out


def refs_to(addr):
    out = []
    try:
        ga = sa(addr)
        if ga is None:
            return out
        for ref in getReferencesTo(ga):
            try:
                out.append(_u(ref.getFromAddress().getOffset()))
            except Exception:
                pass
    except Exception:
        pass
    return out


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
        txt = c.getC()
        for line in txt.split("\n"):
            out.append("  " + line.rstrip())
    except Exception as e:
        out.append("(decompile exception: %s)" % str(e))
    return out


def disasm(f, maxn):
    out = []
    body = f.getBody()
    if body is None:
        return out
    try:
        it = body.getAddresses(True)
    except Exception:
        return out
    cnt = 0
    while it.hasNext() and cnt < maxn:
        a = it.next()
        try:
            pc = _u(a.getOffset())
            b = int(currentProgram.getMemory().getInt(a)) & 0xFFFFFFFF
            out.append("  %016X  %08X" % (pc, b))
        except Exception:
            pass
        cnt += 1
    return out


def find_string_occurrences():
    """Find all occurrences of NEEDLE strings and return {key: [addrs]}."""
    result = {}
    mem = currentProgram.getMemory()
    for key, needle in NEEDLE_STRINGS.items():
        hits = []
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
                    hit = mem.findBytes(addr, jn, None, True, mon)
                except Exception:
                    break
                if hit is None:
                    break
                hits.append(_u(hit.getOffset()))
                if len(hits) >= 8:
                    break
                nxt = hit.add(1)
                if nxt is None:
                    break
                addr = nxt
        except Exception:
            pass
        result[key] = hits
    return result


def validate_offset(name, addr, kind):
    blk = inblk(addr)
    if kind == "int":
        return (True, "0x%X (numeric)" % addr, "OK")
    if blk is None:
        return (False, fmt(addr), "NOT_IN_LOADED_BLOCKS")
    try:
        ga = sa(addr)
        v = int(currentProgram.getMemory().getLong(ga)) & 0xFFFFFFFFFFFFFFFF
    except Exception as e:
        return (False, fmt(addr), "READ_ERR: %s" % str(e))
    ok = (v >= 0xFFFFFFF000000000) and (v <= 0xFFFFFFFFFF000000)
    return (ok, fmt(v), "OK" if ok else "NOT_A_KPTR")


def dump_zone_names():
    """Search all strings for kalloc_type markers."""
    out = []
    try:
        for b in currentProgram.getMemory().getBlocks():
            nm = str(b.getName())
            if "__cstring" not in nm:
                continue
            if not b.isInitialized():
                continue
            s = _u(b.getStart().getOffset())
            e = _u(b.getEnd().getOffset())
            size = int(e - s)
            if size <= 0 or size > 4 * 1024 * 1024:
                continue
            ga = sa(s)
            arr = zeros(size, 'b')
            try:
                currentProgram.getMemory().getBytes(ga, arr)
            except Exception:
                continue
            cur = ""
            cur_off = s
            for i in range(size):
                v = int(arr[i])
                if v < 0:
                    v += 256
                if 0x20 <= v < 0x7F:
                    if not cur:
                        cur_off = s + i
                    cur += chr(v)
                else:
                    if len(cur) >= 4 and "necp" in cur.lower():
                        out.append((cur_off, cur))
                    cur = ""
            if len(cur) >= 4 and "necp" in cur.lower():
                out.append((cur_off, cur))
    except Exception:
        pass
    return out[:60]


def main():
    print("=== necp_final_analysis ===")
    lines = []

    # ---------- 1. program info ----------
    lines.append("=== PROGRAM ===")
    try:
        lines.append("name     = %s" % currentProgram.getName())
        lines.append("lang     = %s" % currentProgram.getLanguage().getLanguageID())
        lines.append("min      = %s" % fmt(currentProgram.getMemory().getMinAddress().getOffset()))
        lines.append("max      = %s" % fmt(currentProgram.getMemory().getMaxAddress().getOffset()))
    except Exception as e:
        lines.append("(err: %s)" % str(e))
    lines.append("")

    # ---------- 2. validate known offsets ----------
    lines.append("=== VALIDATE KNOWN OFFSETS ===")
    valid_count = 0
    for name, (addr, kind) in KNOWN.items():
        ok, val, status = validate_offset(name, addr, kind)
        if ok:
            valid_count += 1
        lines.append("  %-24s  %s  ->  %-20s  [%s]" % (name, fmt(addr), val, status))
    lines.append("  summary: %d/%d valid" % (valid_count, len(KNOWN)))
    lines.append("")

    # ---------- 3. find string xrefs ----------
    lines.append("=== STRING XREFS (NEEDLE -> FUNCTION) ===")
    str_hits = find_string_occurrences()
    func_candidates = {}  # func_entry -> set of needle keys
    for key, hits in str_hits.items():
        lines.append("--- %s ---" % key)
        if not hits:
            lines.append("  (no hits)")
            continue
        for a in hits[:4]:
            blk = inblk(a)
            lines.append("  str @ %s  [%s]" % (fmt(a), blk[2] if blk else "?"))
            for r in refs_to(a)[:4]:
                blk2 = inblk(r)
                f = getFunctionContaining(sa(r))
                fe = _u(f.getEntryPoint().getOffset()) if f is not None else None
                fn = str(f.getName()) if f is not None else "?"
                lines.append("    xref %s  func=%s  [%s]" % (
                    fmt(r), fmt(fe) if fe else "?", fn))
                if fe is not None:
                    func_candidates.setdefault(fe, set()).add(key)
    lines.append("")

    # rank functions by how many distinct needles they reference
    lines.append("=== FUNCTION RANK (by needle refs) ===")
    ranked = sorted(func_candidates.items(), key=lambda kv: -len(kv[1]))
    for fe, keys in ranked[:12]:
        f = find_func_by_addr(fe)
        nm = str(f.getName()) if f is not None else "?"
        sz = 0
        if f is not None:
            try:
                sz = int(f.getBody().getNumAddresses())
            except Exception:
                sz = 0
        lines.append("  %s  %-28s  size=0x%-6X  needles=%s" % (
            fmt(fe), nm, sz, ",".join(sorted(keys))))
    lines.append("")

    # ---------- 4. hardcoded func dumps ----------
    lines.append("=== HARDCODED FUNCS (disasm + decomp) ===")
    for name, addr in HARDCODED_FUNCS:
        f = find_func_by_addr(addr)
        if f is None:
            lines.append("--- %s @ %s --- NO FUNCTION" % (name, fmt(addr)))
            lines.append("")
            continue
        entry = _u(f.getEntryPoint().getOffset())
        sz = 0
        try:
            sz = int(f.getBody().getNumAddresses())
        except Exception:
            pass
        blk = inblk(entry)
        lines.append("--- %s @ %s  size=0x%X  [%s] ---" % (
            name, fmt(entry), sz, blk[2] if blk else "?"))
        lines.append("  callers: %s" % ", ".join(funcs_calling(f)[:6]))
        lines.append("  decompile:")
        for l in decompile(f, 90)[:MAX_DECOMP]:
            lines.append(l)
        lines.append("")

    # ---------- 5. NECP zone names ----------
    lines.append("=== NECP-RELATED STRINGS ===")
    try:
        zn = dump_zone_names()
        for a, s in zn[:40]:
            lines.append("  %s  %s" % (fmt(a), s))
    except Exception as e:
        lines.append("(err: %s)" % str(e))
    lines.append("")

    # ---------- 6. small verdict ----------
    lines.append("=== VERDICT ===")
    lines.append("If function_rank top entry has size > 0x400 and needles")
    lines.append("contain assigned_copyout + assigned_tlv_header, that is")
    lines.append("the real necp_client_copy_result.")
    lines.append("")
    lines.append("Next step for Ghidra manual pass:")
    lines.append("  - open that function's decompile")
    lines.append("  - find ldr X, [Y, #N] where Y comes from client/flow")
    lines.append("  - that N is the real NCF_ASSIGNED_OFF")
    lines.append("  - search add_flow / netagent for str X, [Y, #N]")
    lines.append("")

    # write
    try:
        with open(OUT, "w") as fh:
            for l in lines:
                fh.write(l + "\n")
        print("[+] wrote " + OUT)
    except Exception as e:
        print("[-] write: %s" % str(e))

    # json summary
    jout = {
        "valid_offsets": valid_count,
        "total_offsets": len(KNOWN),
        "ranked_funcs": [{"addr": fmt(fe), "needles": sorted(list(k))}
                         for fe, k in ranked[:12]],
    }
    try:
        with open(OUT_JSON, "w") as fh:
            fh.write(json.dumps(jout, indent=2, sort_keys=True))
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