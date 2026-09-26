# -*- coding: utf-8 -*-
# @runtime Jython

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

NECP_BASE = {
    "necp_open":                     0xFFFFFFF00A4E411C,
    "necp_client_action":            0xFFFFFFF00A4E5C28,
    "necp_client_add_flow":          0xFFFFFFF00A4E843C,
    "necp_client_copy_list":         0xFFFFFFF00A4E80FC,
    "necp_client_copy_update":       0xFFFFFFF00A4EC264,
    "necp_client_copy_interface":    0xFFFFFFF00A4EAC7C,
    "necp_client_copy_result":       0xFFFFFFF00A4E7BE8,
    "necp_client_remove_client":     0xFFFFFFF00A4E76F4,
    "necp_client_remove_flow":       0xFFFFFFF00A4E93C4,
    "necp_client_copy_result_inner": 0xFFFFFFF00A4F26F0,
    "necp_client_sysctl_arena":      0xFFFFFFF00A4EB704,
    "necp_get_tlv_at_offset":        0xFFFFFFF00A4C2034,
    "copyin":                        0xFFFFFFF00A368EC0,
    "copyout":                       0xFFFFFFF00A369A3C,
    "kalloc_type":                   0xFFFFFFF00A200988,
    "kfree_type":                    0xFFFFFFF00A201000,
    "kalloc_type_necp_flow":         0xFFFFFFF007C62E68,
}

TARGETS = [
    ("sooptcopyin",             0xFFFFFFF00A77FD2C),
    ("sbappendcontrol",         0xFFFFFFF00A788A24),
    ("sbappendstream",          0xFFFFFFF00A78811C),
    ("sbappendrecord",          0xFFFFFFF00A7873B8),
    ("necp_get_tlv_at_offset",  0xFFFFFFF00A4C2034),
    ("necp_client_add_flow",    0xFFFFFFF00A4E843C),
    ("necp_update_cache",       0xFFFFFFF00A4EBD58),
    ("necp_per_flow_copy",      0xFFFFFFF00A4F2E70),
    ("necp_flow_alloc",         0xFFFFFFF00A346E70),
    ("necp_handler_big",        0xFFFFFFF00A3D91B4),
    ("copyin_hot_1",            0xFFFFFFF00A6CEB84),
    ("copyout_hot_1",           0xFFFFFFF00A6F18AC),
    ("copyout_hot_2",           0xFFFFFFF00A6F318C),
    ("copyin_hot_2",            0xFFFFFFF00A753850),
]

PATTERNS = [
    "copyout",
    "copyin",
    "kalloc_type",
    "kfree_type",
    "memcpy",
    "memmove",
    "bcopy",
    "bzero",
    "panic",
    "overflow",
    "len",
    "length",
    "size",
    "bound",
    "limit",
    "alloc",
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


def find_string_bytes(needle):
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
            return _u(h.getOffset())
    except Exception:
        pass
    return None


def decompile(f, timeout=300):
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
            out.append(line.rstrip())
    except Exception as e:
        out.append("(exception: %s)" % e)
    return out


def callees(f, maxn=40):
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
                out.append((e, n, sz))
            except Exception:
                pass
    except Exception:
        pass
    out.sort(key=lambda x: x[0])
    return out[:maxn]


def keyword_scan(declines):
    hits = []
    for idx, line in enumerate(declines):
        low = line.lower()
        for pat in PATTERNS:
            if pat in low:
                hits.append((idx, line))
                break
    return hits


def dump_mem_ops(f, lines, cap=0x2000):
    seen = set()
    body = f.getBody()
    if body is None:
        return
    try:
        it = body.getAddresses(True)
    except Exception:
        return
    cnt = 0
    while it.hasNext() and cnt < 8000:
        a = it.next()
        try:
            pc = _u(a.getOffset())
            raw = int(currentProgram.getMemory().getInt(a)) & 0xFFFFFFFF
        except Exception:
            cnt += 1
            continue
        cnt += 1
        kind = None
        base = 0
        imm = 0
        if (raw & 0xFFC00000) == 0xF9400000:
            kind, base, imm = "ldr_x", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 8
        elif (raw & 0xFFC00000) == 0xB9400000:
            kind, base, imm = "ldr_w", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 4
        elif (raw & 0xFFC00000) == 0xF9000000:
            kind, base, imm = "str_x", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 8
        elif (raw & 0xFFC00000) == 0xB9000000:
            kind, base, imm = "str_w", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 4
        elif (raw & 0xFFE00000) == 0x39400000:
            kind, base, imm = "ldrb", (raw >> 5) & 0x1F, (raw >> 10) & 0xFFF
        elif (raw & 0xFFE00000) == 0x39000000:
            kind, base, imm = "strb", (raw >> 5) & 0x1F, (raw >> 10) & 0xFFF
        elif (raw & 0xFFE00000) == 0x79400000:
            kind, base, imm = "ldrh", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 2
        elif (raw & 0xFFE00000) == 0x79000000:
            kind, base, imm = "strh", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 2
        elif (raw & 0xFFC00000) == 0xF8400000:
            i = (raw >> 12) & 0x1FF
            if i & 0x100:
                i -= 0x200
            kind, base, imm = "ldur_x", (raw >> 5) & 0x1F, i
        elif (raw & 0xFFC00000) == 0xB8400000:
            i = (raw >> 12) & 0x1FF
            if i & 0x100:
                i -= 0x200
            kind, base, imm = "ldur_w", (raw >> 5) & 0x1F, i
        else:
            continue
        if imm < 0 or imm > cap:
            continue
        key = (kind, base, imm)
        if key in seen:
            continue
        seen.add(key)
        lines.append("  %s  %-8s  [x%-2d, #0x%X]" % (fmt(pc), kind, base, imm))


def main():
    lines = []
    offsets_out = {}
    print("=== kernel_rw.py v20 (targets) ===")

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

    lines.append("=" * 68)
    lines.append("### NECP SANITY")
    lines.append("=" * 68)
    for name, addr in NECP_BASE.items():
        f = get_func(addr)
        if f:
            ent = _u(f.getEntryPoint().getOffset())
            sz = 0
            try:
                sz = int(f.getBody().getNumAddresses())
            except Exception:
                pass
            lines.append("  %-32s %s  size=0x%X" % (name, fmt(ent), sz))
            offsets_out[name] = fmt(ent)
        else:
            lines.append("  %-32s %s  (no func)" % (name, fmt(addr)))
            offsets_out[name] = fmt(addr)
    lines.append("")

    lines.append("=" * 68)
    lines.append("### TARGET DECOMPILE + KEYWORD SCAN")
    lines.append("=" * 68)

    for label, addr in TARGETS:
        f = get_func(addr)
        if not f:
            lines.append("")
            lines.append("=== %s @ %s : NO FUNCTION ===" % (label, fmt(addr)))
            continue
        ent = _u(f.getEntryPoint().getOffset())
        sz = 0
        try:
            sz = int(f.getBody().getNumAddresses())
        except Exception:
            pass
        lines.append("")
        lines.append("=" * 68)
        lines.append("=== %s @ %s  size=0x%X ===" % (label, fmt(ent), sz))
        lines.append("=" * 68)
        offsets_out[label] = fmt(ent)

        lines.append("--- CALLEES ---")
        cs = callees(f, maxn=30)
        for e, n, sz2 in cs:
            lines.append("  %s  %-40s size=0x%X" % (fmt(e), n[:40], sz2))
        lines.append("")

        lines.append("--- MEM OPS ---")
        dump_mem_ops(f, lines, cap=0x2000)
        lines.append("")

        body = decompile(f, 300)

        lines.append("--- KEYWORD SCAN (line_no: text) ---")
        hits = keyword_scan(body)
        if not hits:
            lines.append("  (no hits)")
        for idx, hl in hits[:200]:
            lines.append("  %4d: %s" % (idx, hl))
        lines.append("")

        lines.append("--- DECOMPILE ---")
        for l in body:
            lines.append("  " + l)
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