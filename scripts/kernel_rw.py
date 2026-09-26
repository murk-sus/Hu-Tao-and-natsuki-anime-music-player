# -*- coding: utf-8 -*-
# @runtime Jython
#
# kernel_rw.py v18 — comprehensive kread-hunt.
#
# Дампы:
#   1. BASE NECP opcodes       — resolve only (уже разобраны)
#   2. ALREADY_DUMPED          — mem ops only (sanity check)
#   3. PRIORITY                — kread кандидаты + callees + decompile
#   4. OPCODES                 — все неразобранные case'ы dispatcher'а
#   5. TLV / strings           — декодеры TLV и xref на ключевые строки
#   6. KTRR/SPTM + kalloc_type
#
# Output: result.txt, offsets.json

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

# ---------- NECP BASE (resolve only) ----------
NECP_BASE = {
    "necp_open":                  0xFFFFFFF00A4E411C,
    "necp_client_action":         0xFFFFFFF00A4E5C28,
    "necp_client_add_flow":       0xFFFFFFF00A4E843C,
    "necp_client_copy_list":      0xFFFFFFF00A4E80FC,
    "necp_client_copy_update":    0xFFFFFFF00A4EC264,
    "necp_client_copy_interface": 0xFFFFFFF00A4EAC7C,
    "necp_client_copy_result":    0xFFFFFFF00A4E7BE8,
    "necp_client_remove_client":  0xFFFFFFF00A4E76F4,
    "necp_client_remove_flow":    0xFFFFFFF00A4E93C4,
}

# ---------- ALREADY DUMPED (mem ops only) ----------
ALREADY_DUMPED = {
    "copy_result_inner":   0xFFFFFFF00A4F26F0,
    "op13_claim":          0xFFFFFFF00A4E7158,
    "op14_sign":           0xFFFFFFF00A4EC5D8,
    "default_add_client":  0xFFFFFFF00A4E60DC,
    "copyin":              0xFFFFFFF00A368EC0,
    "copyout":             0xFFFFFFF00A369A3C,
}

# ---------- PRIORITY: kread кандидаты ----------
# name, addr, want_callees
PRIORITY = [
    ("add_update_helper",  0xFFFFFFF00A4DD078, True),
    ("group_builder",      0xFFFFFFF00A4E19B4, True),
    ("assigned_results",   0xFFFFFFF00A501454, True),
    ("per_flow_copy",      0xFFFFFFF00A4F2E70, True),
    ("destroy_flow",       0xFFFFFFF00A4E2E0C, False),
    ("find_client_uuid",   0xFFFFFFF00A4DB8D4, False),
    ("find_client_alt",    0xFFFFFFF00A4DC948, False),
    ("params_writer",      0xFFFFFFF00A4F709C, False),
    ("after_params",       0xFFFFFFF00A4F7044, False),
    ("tlv_decoder_a",      0xFFFFFFF00AA40D30, True),
    ("tlv_decoder_b",      0xFFFFFFF00A4C2ACC, False),
    ("set_tlv_writer",     0xFFFFFFF00A4C3558, False),
]

# ---------- OPCODES (не разобраны) ----------
OPCODES = [
    ("op0x06",  0xFFFFFFF00A4E9904),
    ("op0x07",  0xFFFFFFF00A4EA0B4),
    ("op0x08",  0xFFFFFFF00A4EA778),
    ("op0x0B",  0xFFFFFFF00A4EBA0C),
    ("op0x0C",  0xFFFFFFF00A4EA8A0),
    ("op0x0D",  0xFFFFFFF00A4EB704),
    ("op0x0E",  0xFFFFFFF00A4EBD58),
    ("op0x15",  0xFFFFFFF00A4EB2B4),
    ("op0x16",  0xFFFFFFF00A4EAB50),
    ("op0x17",  0xFFFFFFF00A4EC9EC),
    ("op0x18",  0xFFFFFFF00A4ECC4C),
    ("op0x19",  0xFFFFFFF00A4ECE88),
    ("op0x1B",  0xFFFFFFF00A4ED170),
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

def collect_refs(ga, limit=8):
    out = []
    try:
        refs = getReferencesTo(ga)
    except Exception:
        return out
    if refs is None:
        return out
    n = 0
    try:
        for r in refs:
            if n >= limit:
                break
            out.append(r)
            n += 1
    except Exception:
        pass
    return out

# ---------- main ----------
def main():
    lines = []
    offsets_out = {}
    print("=== kernel_rw.py v18 (kread-hunt) ===")

    # --- program ---
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
    lines.append("")

    # --- 1. NECP BASE (resolve only) ---
    lines.append("=== RESOLVED NECP BASE ===")
    for name, addr in NECP_BASE.items():
        found = None
        for k in syms:
            if k.lstrip("_") == name or k == name:
                found = syms[k]
                break
        if found is None:
            found = addr
            lines.append("  %-30s %s (fallback)" % (name, fmt(found)))
        else:
            lines.append("  %-30s %s (symbol)" % (name, fmt(found)))
        offsets_out[name] = fmt(found)
    lines.append("")

    # --- 2. ALREADY_DUMPED (mem ops only) ---
    lines.append("### ALREADY-DUMPED FUNCTIONS (mem ops sanity) ###")
    for name, addr in ALREADY_DUMPED.items():
        f = get_func(addr)
        if not f:
            lines.append("--- %s @ %s : NO FUNCTION ---" % (name, fmt(addr)))
            continue
        entry = _u(f.getEntryPoint().getOffset())
        sz = 0
        try:
            sz = int(f.getBody().getNumAddresses())
        except Exception:
            pass
        lines.append("--- %s @ %s  size=0x%X ---" % (name, fmt(entry), sz))
        dump_mem(f, lines, cap=0x1000, dedup=True)
        lines.append("")
        offsets_out[name] = fmt(entry)
    lines.append("")

    # --- 3. PRIORITY ---
    lines.append("#" * 68)
    lines.append("###  PRIORITY: KREAD CANDIDATES")
    lines.append("#" * 68)
    lines.append("")

    for label, addr, want_callees in PRIORITY:
        lines.append("=" * 68)
        lines.append("=== %s @ %s ===" % (label, fmt(addr)))
        lines.append("=" * 68)

        f = get_func(addr)
        if not f:
            lines.append("  NO FUNCTION OBJECT")
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

        lines.append("--- MEM OPS (dedup) ---")
        dump_mem(f, lines, cap=0x2000, dedup=True)
        lines.append("")

        if want_callees:
            lines.append("--- CALLEES ---")
            cs = callees(f)
            if not cs:
                lines.append("  (none)")
            for e, n, sz2, cf in cs:
                lines.append("  %s  %-28s size=0x%X" % (fmt(e), n, sz2))
                sub = []
                dump_mem(cf, sub, cap=0x1000, dedup=True)
                for s in sub[:30]:
                    lines.append("    " + s)
                if len(sub) > 30:
                    lines.append("    ... (%d more)" % (len(sub) - 30))
            lines.append("")

        lines.append("--- DECOMPILE %s ---" % label)
        for l in decompile(f, 300):
            lines.append(l)
        lines.append("")

    # --- 4. OPCODES ---
    lines.append("#" * 68)
    lines.append("###  REMAINING OPCODE HANDLERS")
    lines.append("#" * 68)
    lines.append("")

    for label, addr in OPCODES:
        lines.append("=" * 68)
        lines.append("=== %s @ %s ===" % (label, fmt(addr)))
        lines.append("=" * 68)

        f = get_func(addr)
        if not f:
            lines.append("  NO FUNCTION OBJECT")
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

        lines.append("--- MEM OPS (dedup) ---")
        dump_mem(f, lines, cap=0x2000, dedup=True)
        lines.append("")

        lines.append("--- DECOMPILE %s ---" % label)
        for l in decompile(f, 300):
            lines.append(l)
        lines.append("")

    # --- 5. STRING XREF SCAN ---
    lines.append("### STRING XREF SCAN ###")
    needles = [
        "assigned results copyout error",
        "assigned results tlv_header copyout error",
        "copy result copyout error",
        "group members copyout error",
        "parameters copyout error",
        "tlv_header copyout error",
        "necp_get_tlv_at_offset",
        "necp_client_copy_result",
        "necp_client_copy_update",
        "necp_client_update",
        "Copy_client_update_copyout",
        "necp_client_sign_copyout",
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
            rs = collect_refs(ga, limit=6)
            if not rs:
                lines.append("      (no xrefs)")
            for r in rs:
                try:
                    fa = r.getFromAddress()
                    fpc = _u(fa.getOffset())
                    fn = getFunctionContaining(fa)
                    fname = str(fn.getName()) if fn else "?"
                    fent = _u(fn.getEntryPoint().getOffset()) if fn else 0
                    lines.append("      xref @ %s in %s (%s)" % (fmt(fpc), fname, fmt(fent)))
                except Exception:
                    pass
        except Exception as e:
            lines.append("      xref error: %s" % e)
    lines.append("")

    # --- 6. KTRR/SPTM + kalloc_type ---
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
    try:
        ga = sa(0xFFFFFFF007C62E68)
        for off in range(0, 0x40, 8):
            v = int(currentProgram.getMemory().getLong(ga.add(off))) & 0xFFFFFFFFFFFFFFFF
            lines.append("  +0x%02X: %s" % (off, fmt(v)))
    except Exception as e:
        lines.append("  read error: %s" % e)
    lines.append("")

    # --- write outputs ---
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
