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

NECP_FALLBACK = {}
NECP_FALLBACK["necp_open"] = 0xFFFFFFF00A4E411C
NECP_FALLBACK["necp_client_add_flow"] = 0xFFFFFFF00A4E843C
NECP_FALLBACK["necp_client_remove_flow"] = 0xFFFFFFF00A4E93C4
NECP_FALLBACK["necp_client_copy_interface"] = 0xFFFFFFF00A4EAC7C
NECP_FALLBACK["necp_client_copy_update"] = 0xFFFFFFF00A4EC264
NECP_FALLBACK["necp_client_action"] = 0xFFFFFFF00A4E5C28
NECP_FALLBACK["necp_client_copy_result"] = 0xFFFFFFF00A4E7BE8
NECP_FALLBACK["necp_client_remove_client"] = 0xFFFFFFF00A4E76F4
NECP_FALLBACK["necp_client_copy_list"] = 0xFFFFFFF00A4E80FC

NECP_TARGET_NAMES = list(NECP_FALLBACK.keys())

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
        txt = c.getC()
        for line in txt.split("\n"):
            out.append("  " + line.rstrip())
    except Exception as e:
        out.append("(exception: %s)" % e)
    return out

def main():
    lines = []
    offsets_out = {}
    print("=== kernel_rw.py v16 ===")

    lines.append("=== PROGRAM ===")
    lines.append("name = %s" % currentProgram.getName())
    lines.append("min  = %s" % fmt(currentProgram.getMemory().getMinAddress().getOffset()))
    lines.append("max  = %s" % fmt(currentProgram.getMemory().getMaxAddress().getOffset()))
    lines.append("")

    syms = load_symbols(SYMBOLS_JSON)
    lines.append("=== SYMBOLS ===")
    lines.append("loaded = %d" % len(syms))
    if not syms:
        lines.append("using hardcoded NECP addresses")
    lines.append("")

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

    lines.append("=== FUNCTION DUMPS ===")
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
        seen = set()
        for pc, raw in disasm_mem_ops(f, 1500):
            r = extract_mem(raw)
            if r is None:
                continue
            kind, base, imm = r
            if 0x20 <= imm <= 0x800:
                if imm in seen:
                    continue
                seen.add(imm)
                lines.append("  %s  %-8s  [x%-2d, #0x%X]" % (fmt(pc), kind, base, imm))
        lines.append("")
        lines.append("--- DECOMPILE %s ---" % name)
        for l in decompile(f, 240):
            lines.append(l)
        lines.append("")

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