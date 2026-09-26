# -*- coding: utf-8 -*-
# @runtime Jython
# kernel_rw.py — v5 (symbols-first, fast, fallback-aware)

import os, json, traceback
from jarray import zeros
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor, TaskMonitor

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WS, "result.txt")
OUT_OFF = os.path.join(WS, "offsets.json")
SYMBOLS_JSON = os.environ.get("SYMBOLS_JSON", os.path.join(WS, "symbols.json"))

KPTR_MIN = 0xFFFFFFF000000000
KPTR_MAX = 0xFFFFFFFFFF000000

# Fallback addresses (только если symbols.json пуст)
NECP_FALLBACK = {
    "necp_open":                   0xFFFFFFF00A4E411C,
    "necp_client_add_flow":        0xFFFFFFF00A4E843C,
    "necp_client_remove_flow":     0xFFFFFFF00A4E93C4,
    "necp_client_copy_interface":  0xFFFFFFF00A4EAC7C,
    "necp_client_copy_update":     0xFFFFFFF00A4EC264,
}

# Целевые функции для поиска в symbols.json
NECP_TARGET_NAMES = [
    "necp_open",
    "necp_client_add_flow",
    "necp_client_remove_flow",
    "necp_client_copy_interface",
    "necp_client_copy_update",
    "necp_client_copy_result",
    "necp_get_tlv_at_offset",
    "necp_client_action",
]

def _u(v): return int(v) & 0xFFFFFFFFFFFFFFFF
def fmt(v):
    if v is None: return "0x0"
    try: return "0x%016X" % (int(v) & 0xFFFFFFFFFFFFFFFF)
    except: return "0x0"
def sa(a):
    if a is None: return None
    try: return currentProgram.getAddressFactory().getAddress("%X" % (int(a) & 0xFFFFFFFFFFFFFFFF))
    except: return None

_bc = None
def blocks():
    global _bc
    if _bc is not None: return _bc
    out = []
    try:
        for b in currentProgram.getMemory().getBlocks():
            try:
                if not b.isInitialized(): continue
                out.append((_u(b.getStart().getOffset()), _u(b.getEnd().getOffset()), str(b.getName()), bool(b.isExecute())))
            except: pass
    except: pass
    _bc = out
    return out

def inblk(a):
    if a is None: return None
    av = _u(a)
    for s, e, n, x in blocks():
        if s <= av < e: return (s, e, n, x)
    return None

def get_func(addr):
    try:
        ga = sa(addr)
        if ga is None: return None
        f = getFunctionAt(ga)
        return f if f is not None else getFunctionContaining(ga)
    except: return None

def load_symbols(path):
    """Загружает symbols.json от ipsw. Формат: список объектов {addr, name} или dict."""
    if not os.path.exists(path):
        print("[!] symbols.json not found")
        return {}
    try:
        with open(path) as f: data = json.load(f)
    except Exception as e:
        print("[!] parse failed: %s" % e)
        return {}

    syms = {}
    if isinstance(data, list):
        for e in data:
            if isinstance(e, dict) and "name" in e and "addr" in e:
                try: syms[e["name"]] = int(e["addr"], 16) if isinstance(e["addr"], str) else int(e["addr"])
                except: pass
    elif isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, (int, str)):
                try: syms[k] = int(v, 16) if isinstance(v, str) and v.startswith("0x") else int(v)
                except: pass
    print("[+] symbols loaded: %d" % len(syms))
    return syms

def find_string_va(needle):
    mem = currentProgram.getMemory()
    try:
        jn = zeros(len(needle), 'b')
        for i in range(len(needle)):
            v = ord(needle[i])
            if v > 127: v -= 256
            jn[i] = v
        h = mem.findBytes(mem.getMinAddress(), jn, None, True, TaskMonitor.DUMMY)
        if h is None: return None
        return _u(h.getOffset())
    except: return None

def disasm_mem_ops(f, maxn=800):
    out = []
    body = f.getBody()
    if body is None: return out
    try: it = body.getAddresses(True)
    except: return out
    cnt = 0
    while it.hasNext() and cnt < maxn:
        a = it.next()
        try:
            pc = _u(a.getOffset())
            raw = int(currentProgram.getMemory().getInt(a)) & 0xFFFFFFFF
            out.append((pc, raw))
        except: pass
        cnt += 1
    return out

def extract_mem(raw):
    if (raw & 0xFFC00000) == 0xF9400000: return ("ldr_x", (raw>>5)&0x1F, ((raw>>10)&0xFFF)*8)
    if (raw & 0xFFC00000) == 0xB9400000: return ("ldr_w", (raw>>5)&0x1F, ((raw>>10)&0xFFF)*4)
    if (raw & 0xFFC00000) == 0xF9000000: return ("str_x", (raw>>5)&0x1F, ((raw>>10)&0xFFF)*8)
    if (raw & 0xFFC00000) == 0xB9000000: return ("str_w", (raw>>5)&0x1F, ((raw>>10)&0xFFF)*4)
    if (raw & 0xFFE00000) == 0x39400000: return ("ldrb", (raw>>5)&0x1F, (raw>>10)&0xFFF)
    if (raw & 0xFFE00000) == 0x39000000: return ("strb", (raw>>5)&0x1F, (raw>>10)&0xFFF)
    if (raw & 0xFFE00000) == 0x79400000: return ("ldrh", (raw>>5)&0x1F, ((raw>>10)&0xFFF)*2)
    if (raw & 0xFFE00000) == 0x79000000: return ("strh", (raw>>5)&0x1F, ((raw>>10)&0xFFF)*2)
    if (raw & 0xFFC00000) == 0xF8400000:
        i = (raw>>12)&0x1FF
        if i & 0x100: i -= 0x200
        return ("ldur_x", (raw>>5)&0x1F, i)
    return None

def decompile(f, timeout=180):
    out = []
    try:
        d = DecompInterface()
        d.openProgram(currentProgram)
        r = d.decompileFunction(f, timeout, ConsoleTaskMonitor())
        if r is None or not r.decompileCompleted():
            return ["(decompile failed)"]
        c = r.getDecompiledFunction()
        if c is None: return ["(empty)"]
        for line in c.getC().split("\n"):
            out.append("  " + line.rstrip())
    except Exception as e:
        out.append("(exception: %s)" % e)
    return out

def main():
    lines = []
    offsets_out = {}
    print("=== kernel_rw.py v5 ===")

    lines.append("=== PROGRAM ===")
    lines.append("name = %s" % currentProgram.getName())
    lines.append("min  = %s" % fmt(currentProgram.getMemory().getMinAddress().getOffset()))
    lines.append("max  = %s" % fmt(currentProgram.getMemory().getMaxAddress().getOffset()))
    lines.append("")

    # 1) Загружаем symbols.json от ipsw
    syms = load_symbols(SYMBOLS_JSON)
    lines.append("=== SYMBOLS ===")
    lines.append("loaded = %d" % len(syms))
    if not syms:
        lines.append("WHY: ipsw kernel sym failed or produced empty JSON.")
        lines.append("FIX: ensure blacktop/symbolicator is cloned and --signatures path is correct.")
    lines.append("")

    # 2) Резолвим NECP-функции
    resolved = {}
    lines.append("=== RESOLVED NECP TARGETS ===")
    for name in NECP_TARGET_NAMES:
        found = None
        # Ищем по имени (с учётом возможного префикса _)
        for k in syms:
            if k.lstrip("_") == name or k == name:
                found = syms[k]; break
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

    # 3) Dump найденных функций
    lines.append("=== FUNCTION DUMPS ===")
    for name, addr in resolved.items():
        f = get_func(addr)
        if not f:
            lines.append("--- %s @ %s : NO FUNCTION OBJECT ---" % (name, fmt(addr)))
            continue
        entry = _u(f.getEntryPoint().getOffset())
        sz = 0
        try: sz = int(f.getBody().getNumAddresses())
        except: pass
        lines.append("--- %s @ %s  size=0x%X ---" % (name, fmt(entry), sz))
        seen = set()
        for pc, raw in disasm_mem_ops(f, 800):
            r = extract_mem(raw)
            if r is None: continue
            kind, base, imm = r
            if 0x20 <= imm <= 0x600 and imm not in seen:
                seen.add(imm)
                lines.append("  %s  %-8s  [x%-2d, #0x%X]" % (fmt(pc), kind, base, imm))
        lines.append("")
        lines.append("--- DECOMPILE %s ---" % name)
        for l in decompile(f, 180):
            lines.append(l)
        lines.append("")

    # 4) KTRR/SPTM
    lines.append("=== KTRR/SPTM ===")
    for needle in ["SPTM", "sptm", "ctrr", "KTRR"]:
        va = find_string_va(needle)
        if va: lines.append("  %-8s -> %s" % (needle, fmt(va)))
    lines.append("")

    # 5) kalloc_type_var для flow
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

    # Write
    try:
        with open(OUT, "w") as fh:
            for l in lines: fh.write(l + "\n")
        print("[+] wrote " + OUT)
    except Exception as e:
        print("[-] result write: %s" % e)

    try:
        with open(OUT_OFF, "w") as fh:
            fh.write(json.dumps(offsets_out, indent=2, sort_keys=True))
        print("[+] wrote " + OUT_OFF)
    except Exception as e:
        print("[-] offsets write: %s" % e)

    print("=== DONE ===")

try:
    main()
except Exception as e:
    print("[-] FATAL: %s" % e)
    traceback.print_exc()
    try:
        with open(OUT, "a") as fh:
            fh.write("FATAL: %s\n%s" % (e, traceback.format_exc()))
        with open(OUT_OFF, "a") as fh:
            fh.write("{}")
    except: pass