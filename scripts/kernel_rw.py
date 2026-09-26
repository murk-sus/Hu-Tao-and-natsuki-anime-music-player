# -*- coding: utf-8 -*-
# @runtime Jython
#
# kernel_rw.py v17 — единый скрипт.
#
# Добавлено относительно v16:
#   - EXTRA TARGETS: copy_result_inner, op=0x13, op=0x14, default, copyin, copyout
#   - для copy_result_inner и op=0x13 — дамп callee-функций с их mem-ops
#   - STRING XREF SCAN по строкам вокруг copy_result (независимая проверка адреса)
#
# Всё остальное (NECP fallback, KALLOC_TYPE_VAR, KTRR/SPTM) — как было.

import os
import json
import traceback
from jarray import zeros
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor, TaskMonitor

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WS, "result.txt")
OUT_OFF = os.path.join(WS, "offsets.json")
SYMBOLS_JSON = os.environ.get("SYMBOLS_JSON", os.path.join(WS, "symbols.json"))

# ---------- N E C P   B A S E   T A R G E T S ----------
NECP_FALLBACK = {}
NECP_FALLBACK["necp_open"]                    = 0xFFFFFFF00A4E411C
NECP_FALLBACK["necp_client_add_flow"]         = 0xFFFFFFF00A4E843C
NECP_FALLBACK["necp_client_remove_flow"]      = 0xFFFFFFF00A4E93C4
NECP_FALLBACK["necp_client_copy_interface"]   = 0xFFFFFFF00A4EAC7C
NECP_FALLBACK["necp_client_copy_update"]      = 0xFFFFFFF00A4EC264
NECP_FALLBACK["necp_client_action"]           = 0xFFFFFFF00A4E5C28
NECP_FALLBACK["necp_client_copy_result"]      = 0xFFFFFFF00A4E7BE8
NECP_FALLBACK["necp_client_remove_client"]    = 0xFFFFFFF00A4E76F4
NECP_FALLBACK["necp_client_copy_list"]        = 0xFFFFFFF00A4E80FC

NECP_TARGET_NAMES = list(NECP_FALLBACK.keys())

# ---------- E X T R A   T A R G E T S  (step 2) ----------
# name, addr, want_callees
EXTRA_TARGETS = [
    ("P1_copy_result_inner", 0xFFFFFFF00A4F26F0, True),
    ("P2_op0x13_add_update", 0xFFFFFFF00A4E7158, True),
    ("P3_op0x14_unknown",    0xFFFFFFF00A4EC5D8, False),
    ("P4_default_handler",   0xFFFFFFF00A4E60DC, False),
    ("REF_copyin",           0xFFFFFFF00A368EC0, False),
    ("REF_copyout",          0xFFFFFFF00A369A3C, False),
]

# ---------- helpers ----------
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

_blocks_cache = None
def blocks():
    global _blocks_cache
    if _blocks_cache is not None:
        return _blocks_cache
    out = []
    try:
        for b in currentProgram.getMemory().getBlocks():
            try:
                if not b.isInitialized():
                    continue
                s = _u(b.getStart().getOffset())
                e = _u(b.getEnd().getOffset())
                n = str(b.getName())
                x = bool(b.isExecute())
                out.append((s, e, n, x))
            except Exception:
                pass
    except Exception:
        pass
    _blocks_cache = out
    return out

def inblk(a):
    if a is None:
        return None
    av = _u(a)
    for s, e, n, x in blocks():
        if s <= av < e:
            return (s, e, n, x)
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

def load_symbols(path):
    print("[+] symbols: %s" % path)
    if not os.path.exists(path):
        print("[!] symbols.json not found")
        return {}
    try:
        fh = open(path)
        data = json.load(fh)
        fh.close()
    except Exception as e:
        print("[!] parse failed: %s" % e)
        return {}
    syms = {}
    if isinstance(data, list):
        for e in data:
            if not isinstance(e, dict):
                continue
            if "name" not in e or "addr" not in e:
                continue
            try:
                a = e["addr"]
                if isinstance(a, str):
                    syms[e["name"]] = int(a, 16)
                else:
                    syms[e["name"]] = int(a)
            except Exception:
                pass
    elif isinstance(data, dict):
        for k, v in data.items():
            if not isinstance(v, (int, str)):
                continue
            try:
                if isinstance(v, str) and v.startswith("0x"):
                    syms[k] = int(v, 16)
                else:
                    syms[k] = int(v)
            except Exception:
                pass
    print("[+] symbols loaded: %d" % len(syms))
    if syms:
        items = list(syms.items())[:5]
        for k, v in items:
            print("    %s = %s" % (k, fmt(v)))
    return syms

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

# ---------- main ----------
def main():
    lines = []
    offsets_out = {}
    print("=== kernel_rw.py v17 (unified, single-file) ===")

    lines.append("=== PROGRAM ===")
    lines.append("name = %s" % currentProgram.getName())
    try:
        lines.append("min  = %s" % fmt(currentProgram.getMemory().getMinAddress().getOffset()))
        lines.append("max  = %s" % fmt(currentProgram.getMemory().getMaxAddress().getOffset()))
    except Exception:
        pass
    lines.append("")

    syms = load_symbols(SYMBOLS_JSON)
    lines.append("=== SYMBOLS ===")
    lines.append("loaded = %d" % len(syms))
    if not syms:
        lines.append("using hardcoded NECP addresses")
    lines.append("")

    # ---------- SECTION A: NECP base targets ----------
    resolved = {}
    lines.append("=== RESOLVED NECP TARGETS ===")
    for name in NECP_TARGET_NAMES:
        found = None
        for k in syms:
            if k.lstrip("_") == name or k == name:
                found = syms[k]
                break
        if found is None and name in NECP_FALLBACK:
            found = NECP_FALLBACK[name]
            lines.append("  %-30s %s (FALLBACK)" % (name, fmt(found)))
        elif found:
            lines.append("  %-30s %s (symbol)" % (name, fmt(found)))
        else:
            lines.append("  %-30s NOT FOUND" % name)
        if found:
            resolved[name] = found
            offsets_out[name] = fmt(found)
    lines.append("")

    lines.append("=== NECP FUNCTION DUMPS ===")
    for name, addr in resolved.items():
        f = get_func(addr)
        if not f:
            lines.append("--- %s @ %s : NO FUNCTION OBJECT ---" % (name, fmt(addr)))
            continue
        entry = _u(f.getEntryPoint().getOffset())
        sz = 0
        try:
            sz = int(f.getBody().getNumAddresses())
        except Exception:
            pass
        lines.append("--- %s @ %s  size=0x%X ---" % (name, fmt(entry), sz))
        dump_mem(f, lines, cap=0x800, dedup=True)
        lines.append("")
        lines.append("--- DECOMPILE %s ---" % name)
        for l in decompile(f, 240):
            lines.append(l)
        lines.append("")

    # ---------- SECTION B: extra targets (step 2) ----------
    lines.append("")
    lines.append("#" * 68)
    lines.append("###  EXTRA TARGETS (copy_result_inner / op13 / op14 / default / copyin / copyout)")
    lines.append("#" * 68)
    lines.append("")

    for label, addr, want_callees in EXTRA_TARGETS:
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

    # ---------- SECTION C: string xref scan ----------
    lines.append("### STRING XREF SCAN (independent check for copy_result_inner) ###")
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

    # ---------- SECTION D: KTRR/SPTM + kalloc_type ----------
    lines.append("=== KTRR/SPTM ===")
    for needle in ["SPTM", "sptm", "ctrr", "KTRR"]:
        va = None
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
                va = _u(h.getOffset())
        except Exception:
            pass
        if va:
            lines.append("  %-8s -> %s" % (needle, fmt(va)))
    lines.append("")

    lines.append("=== KALLOC_TYPE_VAR (necp_client_flow) @ 0xFFFFFFF007C62E68 ===")
    blk = inblk(0xFFFFFFF007C62E68)
    if blk:
        lines.append("  block = %s" % blk[2])
        try:
            ga = sa(0xFFFFFFF007C62E68)
            for off in range(0, 0x40, 8):
                v = int(currentProgram.getMemory().getLong(ga.add(off))) & 0xFFFFFFFFFFFFFFFF
                lines.append("  +0x%02X: %s" % (off, fmt(v)))
        except Exception as e:
            lines.append("  read error: %s" % e)
    lines.append("")

    # ---------- write outputs ----------
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