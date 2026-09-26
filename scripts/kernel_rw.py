# -*- coding: utf-8 -*-
# @runtime Jython
# kernel_rw.py — v3 (symbols-first, os_log descriptor resolver, tag masking)

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

# Tag masks for iOS tagged pointers (order matters)
TAG_MASKS = [0xFFFFFFFFFFFFFFFF, 0x0000FFFFFFFFFFFF, 0x000000FFFFFFFFFF, 0x00000000FFFFFFFF]

NECP_TARGETS = {
    "necp_open": ["necp_open", "_necp_open"],
    "necp_client_add_flow": ["necp_client_add_flow"],
    "necp_client_remove_flow": ["necp_client_remove_flow"],
    "necp_client_copy_interface": ["necp_client_copy_interface"],
    "necp_client_copy_update": ["necp_client_copy_update"],
    "necp_client_copy_result": ["necp_client_copy_result"],
    "necp_get_tlv_at_offset": ["necp_get_tlv_at_offset"],
    "necp_client_action": ["necp_client_action"],
}

# Fallback addresses (только если symbols.json пуст)
NECP_FALLBACK = {
    "necp_open": 0xFFFFFFF00A4E411C,
    "necp_client_add_flow": 0xFFFFFFF00A4E843C,
    "necp_client_remove_flow": 0xFFFFFFF00A4E93C4,
    "necp_client_copy_interface": 0xFFFFFFF00A4EAC7C,
    "necp_client_copy_update": 0xFFFFFFF00A4EC264,
}

def _u(v): return int(v) & 0xFFFFFFFFFFFFFFFF
def fmt(v):
    if v is None: return "0x0"
    try: return "0x%016X" % (int(v) & 0xFFFFFFFFFFFFFFFF)
    except: return "0x0"
def sa(a):
    if a is None: return None
    try: return currentProgram.getAddressFactory().getAddress("%X" % (int(a) & 0xFFFFFFFFFFFFFFFF))
    except: return None

_blocks = None
def blocks():
    global _blocks
    if _blocks is not None: return _blocks
    out = []
    try:
        for b in currentProgram.getMemory().getBlocks():
            try:
                if not b.isInitialized(): continue
                out.append((_u(b.getStart().getOffset()), _u(b.getEnd().getOffset()), str(b.getName()), bool(b.isExecute())))
            except: pass
    except: pass
    _blocks = out
    return out

def inblk(a):
    if a is None: return None
    av = _u(a)
    for s, e, n, x in blocks():
        if s <= av < e: return (s, e, n, x)
    return None

def read_u64(addr):
    try:
        ga = sa(addr)
        if ga is None: return None
        return int(currentProgram.getMemory().getLong(ga)) & 0xFFFFFFFFFFFFFFFF
    except: return None

def get_func_at(addr):
    try:
        ga = sa(addr)
        if ga is None: return None
        f = getFunctionAt(ga)
        return f if f is not None else getFunctionContaining(ga)
    except: return None

def load_symbols(path):
    if not os.path.exists(path):
        print("[!] symbols.json missing")
        return {}
    try:
        with open(path) as f: data = json.load(f)
    except Exception as e:
        print("[!] parse failed: %s" % e)
        return {}
    syms = {}
    # ipsw kernel sym --json produces a list of {name, addr} or dict
    if isinstance(data, list):
        for e in data:
            if isinstance(e, dict) and "name" in e and "addr" in e:
                try: syms[e["name"]] = int(e["addr"], 16) if isinstance(e["addr"], str) else int(e["addr"])
                except: pass
    elif isinstance(data, dict):
        # symbol map format: {"addr": "name"} or {"name": addr}
        for k, v in data.items():
            if isinstance(v, str) and v.startswith("0x"):
                try: syms[k] = int(v, 16)
                except: pass
            elif isinstance(v, int):
                syms[k] = v
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
        addr = mem.getMinAddress()
        mon = TaskMonitor.DUMMY
        while addr is not None:
            try: h = mem.findBytes(addr, jn, None, True, mon)
            except: return None
            if h is None: return None
            return _u(h.getOffset())
    except: pass
    return None

def find_oslog_descriptors(string_vas):
    """
    Scan __const / __data / __common / __bss for pointers to string VAs.
    Handles iOS tagged pointers. Does NOT scan __TEXT (false positives).
    """
    desc_map = {}
    scanned = set()
    for s, e, n, is_exec in blocks():
        if is_exec: continue
        if not any(k in n for k in ("__const", "__data", "__common", "__bss")): continue
        if n in scanned: continue
        scanned.add(n)
        sz = e - s
        if sz <= 8 or sz > 64 * 1024 * 1024: continue
        try:
            ga = sa(s)
            jbuf = zeros(sz, 'b')
            currentProgram.getMemory().getBytes(ga, jbuf)
            i = 0
            while i + 8 <= sz:
                v = 0
                for k in range(8): v |= (int(jbuf[i+k]) & 0xFF) << (8*k)
                for mask in TAG_MASKS:
                    masked = v & mask
                    if masked in string_vas:
                        desc_map[masked] = s + i
                        break
                i += 8
        except Exception as ex:
            print("[-] scan %s: %s" % (n, ex))
    return desc_map

def find_adrp_add_to(targets):
    hits = {}
    for s, e, n, is_exec in blocks():
        if not is_exec: continue
        sz = e - s
        if sz <= 0 or sz > 64 * 1024 * 1024: continue
        try:
            ga = sa(s)
            jbuf = zeros(sz, 'b')
            currentProgram.getMemory().getBytes(ga, jbuf)
            buf = bytearray(sz)
            for i in range(sz):
                v = int(jbuf[i])
                if v < 0: v += 256
                buf[i] = v
            addr = s; i = 0
            while i + 8 <= sz:
                b0 = buf[i] | (buf[i+1]<<8) | (buf[i+2]<<16) | (buf[i+3]<<24)
                b1 = buf[i+4] | (buf[i+5]<<8) | (buf[i+6]<<16) | (buf[i+7]<<24)
                if (b0 & 0x9F000000) == 0x90000000:
                    rd = b0 & 0x1F
                    immlo = (b0>>29)&3; immhi = (b0>>5)&0x7FFFF
                    imm = (immhi<<2)|immlo
                    if imm & 0x100000: imm -= 0x200000
                    page = (addr & ~0xFFF) + (imm<<12)
                    if (b1 & 0xFF800000) == 0x91000000:
                        rn = (b1>>5)&0x1F; rd2 = b1&0x1F; imm12 = (b1>>10)&0xFFF
                        if rn == rd and rd2 == rd:
                            resolved = (page + imm12) & 0xFFFFFFFFFFFFFFFF
                            if resolved in targets:
                                hits.setdefault(resolved, []).append(addr)
                    elif (b1 & 0xFFC00000) == 0xF9400000:
                        rn = (b1>>5)&0x1F; imm12 = ((b1>>10)&0xFFF)*8
                        if rn == rd:
                            ptr_addr = page + imm12
                            if ptr_addr in targets:
                                hits.setdefault(ptr_addr, []).append(addr)
                addr += 4; i += 4
        except Exception as ex:
            print("[-] block %s: %s" % (n, ex))
    return hits

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

def main():
    lines = []
    offsets_out = {}
    print("=== kernel_rw.py v3 ===")

    lines.append("=== PROGRAM ===")
    lines.append("name = %s" % currentProgram.getName())
    lines.append("min  = %s" % fmt(currentProgram.getMemory().getMinAddress().getOffset()))
    lines.append("max  = %s" % fmt(currentProgram.getMemory().getMaxAddress().getOffset()))
    lines.append("")

    lines.append("=== BLOCKS (non-exec) ===")
    for s, e, n, x in blocks():
        if not x: lines.append("  %-24s %s..%s size=0x%X" % (n, fmt(s), fmt(e), e-s))
    lines.append("")

    # 1) Symbols
    syms = load_symbols(SYMBOLS_JSON)
    lines.append("=== SYMBOLS ===")
    lines.append("loaded = %d" % len(syms))
    if not syms:
        lines.append("WHY: ipsw kernel sym failed or produced empty JSON.")
        lines.append("FIX: check workflow step 'Symbolicate' — ensure ipsw kernel sym --json works.")
    lines.append("")

    # 2) Resolve NECP targets
    resolved = {}
    lines.append("=== RESOLVED NECP TARGETS ===")
    for name, variants in NECP_TARGETS.items():
        found = None
        for v in variants:
            for k in syms:
                if k.lstrip("_") == v.lstrip("_") or k == v:
                    found = syms[k]; break
            if found: break
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

    # 3) If copy_result not in symbols, try string xref fallback
    if "necp_client_copy_result" not in resolved:
        lines.append("=== STRING XREF FALLBACK ===")
        needles = {
            "assigned_results": "necp_client_copy assigned results copyout error",
            "result": "necp_client_copy result copyout error",
            "group_members": "necp_client_copy group members copyout error",
        }
        string_vas = set()
        for k, needle in needles.items():
            va = find_string_va(needle)
            if va:
                lines.append("  str[%s] = %s" % (k, fmt(va)))
                string_vas.add(va)
        if string_vas:
            desc_map = find_oslog_descriptors(string_vas)
            lines.append("  descriptors found: %d" % len(desc_map))
            for sva, dva in desc_map.items():
                lines.append("    str %s -> desc %s" % (fmt(sva), fmt(dva)))
            if desc_map:
                xrefs = find_adrp_add_to(set(desc_map.values()))
                lines.append("  xrefs to descriptors: %d" % len(xrefs))
                for tgt, pcs in xrefs.items():
                    for pc in pcs[:4]:
                        f = get_func_at(pc)
                        if f:
                            fe = _u(f.getEntryPoint().getOffset())
                            lines.append("    ref @ %s -> func %s @ %s" % (fmt(pc), f.getName(), fmt(fe)))
                            if fe not in resolved.values():
                                resolved["necp_client_copy_result"] = fe
                                offsets_out["necp_client_copy_result"] = fmt(fe)
            else:
                lines.append("  NO descriptors found — os_log format may differ.")
        else:
            lines.append("  NO string VAs found.")
        lines.append("")

    # 4) Dump resolved functions (disasm + decompile)
    lines.append("=== FUNCTION DUMPS ===")
    for name, addr in resolved.items():
        f = get_func_at(addr)
        if not f: continue
        lines.append("--- %s @ %s ---" % (name, fmt(addr)))
        seen = set()
        body = f.getBody()
        if body:
            it = body.getAddresses(True)
            listing = currentProgram.getListing()
            cnt = 0
            while it.hasNext() and cnt < 600:
                a = it.next()
                try:
                    pc = _u(a.getOffset())
                    raw = int(currentProgram.getMemory().getInt(a)) & 0xFFFFFFFF
                    r = extract_mem(raw)
                    if r:
                        kind, base, imm = r
                        if 0x20 <= imm <= 0x600 and imm not in seen:
                            seen.add(imm)
                            lines.append("  %s %-8s [x%-2d, #0x%X]" % (fmt(pc), kind, base, imm))
                except: pass
                cnt += 1
        lines.append("")
        lines.append("--- DECOMPILE %s ---" % name)
        try:
            d = DecompInterface()
            d.openProgram(currentProgram)
            r = d.decompileFunction(f, 120, ConsoleTaskMonitor())
            if r and r.decompileCompleted():
                for l in r.getDecompiledFunction().getC().split("\n"):
                    lines.append("  " + l.rstrip())
        except Exception as e: lines.append("(decompile fail: %s)" % e)
        lines.append("")

    # 5) kalloc_type_var (necp_client_flow zone)
    lines.append("=== KALLOC_TYPE_VAR (necp_client_flow) @ 0xFFFFFFF007C62E68 ===")
    blk = inblk(0xFFFFFFF007C62E68)
    if blk:
        lines.append("block = %s" % blk[2])
        for off in range(0, 0x40, 8):
            lines.append("  +0x%02X: %s" % (off, fmt(read_u64(0xFFFFFFF007C62E68 + off))))
    lines.append("")

    # 6) KTRR/SPTM detection
    lines.append("=== KTRR/SPTM ===")
    for needle in ["SPTM", "sptm", "ctrr", "KTRR"]:
        va = find_string_va(needle)
        if va: lines.append("  %-8s -> %s" % (needle, fmt(va)))
    lines.append("")

    # 7) Accessor offsets (top 100)
    lines.append("=== ACCESSOR OFFSETS (ldr X0,[X0,#imm]; ret) ===")
    acc = []
    for s, e, n, is_exec in blocks():
        if not is_exec: continue
        sz = e - s
        if sz <= 0 or sz > 32*1024*1024: continue
        try:
            ga = sa(s)
            jbuf = zeros(min(sz, 32*1024*1024), 'b')
            currentProgram.getMemory().getBytes(ga, jbuf)
            limit = min(sz, 32*1024*1024)
            i = 0
            while i + 8 <= limit and len(acc) < 100:
                b0 = (int(jbuf[i])&0xFF)|((int(jbuf[i+1])&0xFF)<<8)|((int(jbuf[i+2])&0xFF)<<16)|((int(jbuf[i+3])&0xFF)<<24)
                b1 = (int(jbuf[i+4])&0xFF)|((int(jbuf[i+5])&0xFF)<<8)|((int(jbuf[i+6])&0xFF)<<16)|((int(jbuf[i+7])&0xFF)<<24)
                if (b0 & 0xFFC00000) == 0xF9400000 and (b1 & 0xFFFFFFFF) == 0xD65F03C0:
                    rn = (b0>>5)&0x1F; rt = b0&0x1F
                    if rn == 0 and rt == 0:
                        imm = ((b0>>10)&0xFFF)*8
                        acc.append((s+i, imm, "ldr_x"))
                elif (b0 & 0xFFC00000) == 0xB9400000 and (b1 & 0xFFFFFFFF) == 0xD65F03C0:
                    rn = (b0>>5)&0x1F; rt = b0&0x1F
                    if rn == 0 and rt == 0:
                        imm = ((b0>>10)&0xFFF)*4
                        acc.append((s+i, imm, "ldr_w"))
                i += 4
        except: pass
    for a, imm, kind in acc: lines.append("  %s +0x%X (%s)" % (fmt(a), imm, kind))
    lines.append("  total = %d" % len(acc))
    lines.append("")

    # Write
    try:
        with open(OUT, "w") as fh:
            for l in lines: fh.write(l + "\n")
    except: pass
    try:
        with open(OUT_OFF, "w") as fh:
            fh.write(json.dumps(offsets_out, indent=2, sort_keys=True))
    except: pass
    print("=== DONE ===")

try:
    main()
except Exception as e:
    print("[-] FATAL: %s" % e)
    traceback.print_exc()
    try:
        with open(OUT, "a") as fh: fh.write("FATAL: %s\n" % e + traceback.format_exc())
        with open(OUT_OFF, "a") as fh: fh.write("{}")
    except: pass