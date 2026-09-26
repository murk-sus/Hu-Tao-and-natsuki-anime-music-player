# -*- coding: utf-8 -*-
# @runtime Jython
#
# kernel_rw_step2.py
# Goal: resolve and dump the functions we couldn't see in step 1.
#
# Priority targets (hardcoded, iOS 27.0 / 24A437 / iPhone14,5):
#   P1  FUN_fffffff00a4f26f0  copy_result_inner  (called from copy_result)
#   P2  FUN_fffffff00a4e7158  op=0x13            (probable add_update)
#   P3  FUN_fffffff00a4ec5d8  op=0x14
#   P4  FUN_fffffff00a4e60dc  default handler
#   Ref FUN_fffffff00a368ec0  copyin
#   Ref FUN_fffffff00a369a3c  copyout
#
# For each: mem-op dump (dedup by imm) + full decompile.
# For P1 and P2 also: callee list with quick mem-op dump (top 12).
#
# Output:  result_step2.txt
#          offsets_step2.json

import os
import json
import traceback
from jarray import zeros
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor, TaskMonitor

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WS, "result_step2.txt")
OUT_OFF = os.path.join(WS, "offsets_step2.json")

TARGETS = [
    ("P1_copy_result_inner",  0xFFFFFFF00A4F26F0, True),
    ("P2_op0x13_add_update",  0xFFFFFFF00A4E7158, True),
    ("P3_op0x14_unknown",     0xFFFFFFF00A4EC5D8, False),
    ("P4_default_handler",    0xFFFFFFF00A4E60DC, False),
    ("REF_copyin",            0xFFFFFFF00A368EC0, False),
    ("REF_copyout",           0xFFFFFFF00A369A3C, False),
]

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
        return currentProgram.getAddressFactory().getAddress(
            "%X" % (int(a) & 0xFFFFFFFFFFFFFFFF))
    except Exception:
        return None

def get_func(addr):
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

def disasm_mem_ops(f, maxn):
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
            raw = int(currentProgram.getMemory().getInt(a)) & 0xFFFFFFFF
            out.append((pc, raw))
        except Exception:
            pass
        cnt += 1
    return out

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
        out.append("(exception: %s)" % e)
    return out

def callees(f):
    try:
        cf = f.getCalledFunctions(ConsoleTaskMonitor())
    except Exception:
        return []
    out = []
    if not cf:
        return out
    try:
        for c in cf:
            try:
                e = _u(c.getEntryPoint().getOffset())
                n = str(c.getName())
                sz = 0
                try:
                    sz = int(c.getBody().getNumAddresses())
                except Exception:
                    pass
                out.append((e, n, sz, c))
            except Exception:
                pass
    except Exception:
        pass
    out.sort(key=lambda x: x[0])
    return out

def dump_mem(f, lines, cap=0x2000, dedup=True):
    seen = set()
    for pc, raw in disasm_mem_ops(f, 6000):
        r = extract_mem(raw)
        if r is None:
            continue
        kind, base, imm = r
        if imm < 0 or imm > cap:
            continue
        key = (kind, base, imm)
        if dedup and key in seen:
            continue
        seen.add(key)
        lines.append("  %s  %-8s  [x%-2d, #0x%X]" % (fmt(pc), kind, base, imm))

def main():
    lines = []
    offsets_out = {}
    print("=== kernel_rw_step2.py v1 ===")

    lines.append("=== PROGRAM ===")
    lines.append("name = %s" % currentProgram.getName())
    try:
        lines.append("min  = %s" % fmt(currentProgram.getMemory().getMinAddress().getOffset()))
        lines.append("max  = %s" % fmt(currentProgram.getMemory().getMaxAddress().getOffset()))
    except Exception:
        pass
    lines.append("")

    for label, addr, want_callees in TARGETS:
        lines.append("=" * 68)
        lines.append("=== %s @ %s ===" % (label, fmt(addr)))
        lines.append("=" * 68)

        f = get_func(addr)
        if not f:
            lines.append("  NO FUNCTION OBJECT at this address")
            lines.append("")
            continue

        entry = _u(f.getEntryPoint().getOffset())
        sz = 0
        try:
            sz = int(f.getBody().getNumAddresses())
        except Exception:
            pass
        lines.append("  entry = %s" % fmt(entry))
        lines.append("  size  = 0x%X" % sz)
        lines.append("")

        offsets_out[label] = fmt(entry)

        lines.append("--- MEM OPS (dedup, imm <= 0x2000) ---")
        dump_mem(f, lines, cap=0x2000, dedup=True)
        lines.append("")

        if want_callees:
            lines.append("--- CALLEES ---")
            cs = callees(f)
            if not cs:
                lines.append("  (none)")
            for e, n, sz2, cf in cs:
                lines.append("  %s  %-28s size=0x%X" % (fmt(e), n, sz2))
                lines.append("      mem ops:")
                sub = []
                dump_mem(cf, sub, cap=0x1000, dedup=True)
                for s in sub[:40]:
                    lines.append("    " + s)
                if len(sub) > 40:
                    lines.append("    ... (%d more)" % (len(sub) - 40))
            lines.append("")

        lines.append("--- DECOMPILE %s ---" % label)
        for l in decompile(f, 300):
            lines.append(l)
        lines.append("")

    # Bonus: scan for string xrefs that hint at copy_result_inner
    lines.append("=== STRING XREF SCAN ===")
    needles = [
        "assigned results copyout error",
        "assigned results tlv_header copyout error",
        "copy result copyout error",
        "group members copyout error",
        "parameters copyout error",
    ]
    for needle in needles:
        found_at = None
        try:
            mem = currentProgram.getMemory()
            jn = zeros(len(needle), 'b')
            for i in range(len(needle)):
                v = ord(needle[i])
                if v > 127:
                    v -= 256
                jn[i] = v
            h = mem.findBytes(mem.getMinAddress(), jn, None, True, TaskMonitor.DUMMY)
            if h is not None:
                found_at = _u(h.getOffset())
        except Exception:
            pass
        if found_at is None:
            lines.append("  %-45s : (not found)" % needle)
            continue
        lines.append("  %-45s : %s" % (needle, fmt(found_at)))
        try:
            ga = sa(found_at)
            refs = getReferencesTo(ga)
            if refs is None or refs.size() == 0:
                lines.append("      (no xrefs)")
            else:
                i = 0
                for r in refs:
                    if i >= 8:
                        break
                    try:
                        fa = r.getFromAddress()
                        fpc = _u(fa.getOffset())
                        fn = getFunctionContaining(fa)
                        fname = str(fn.getName()) if fn else "?"
                        fent = _u(fn.getEntryPoint().getOffset()) if fn else 0
                        lines.append("      xref @ %s in %s (%s)" % (fmt(fpc), fname, fmt(fent)))
                    except Exception:
                        pass
                    i += 1
        except Exception as e:
            lines.append("      xref error: %s" % e)
    lines.append("")

    try:
        fh = open(OUT, "w")
        for l in lines:
            fh.write(l + "\n")
        fh.close()
        print("[+] wrote " + OUT)
    except Exception as e:
        print("[-] result: %s" % e)

    try:
        fh = open(OUT_OFF, "w")
        fh.write(json.dumps(offsets_out, indent=2, sort_keys=True))
        fh.close()
        print("[+] wrote " + OUT_OFF)
    except Exception as e:
        print("[-] offsets: %s" % e)

    print("=== DONE ===")

try:
    main()
except Exception as e:
    print("[-] FATAL: %s" % e)
    traceback.print_exc()