# -*- coding: utf-8 -*-
# @runtime Jython
# kernel_rw.py — fast, symbols-first iOS kernel recon for Ghidra 12+

import os, json, traceback
from jarray import zeros
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor, TaskMonitor

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WS, "result.txt")
OUT_OFF = os.path.join(WS, "offsets.json")
SYMBOLS_JSON = os.environ.get("SYMBOLS_JSON", os.path.join(WS, "symbols.json"))
VERIFIED_JSON = os.environ.get("VERIFIED_JSON", os.path.join(WS, "verified_all_92.json"))

KPTR_MIN = 0xFFFFFFF000000000
KPTR_MAX = 0xFFFFFFFFFF000000

# Load-bearing NECP functions — fallback addresses if symbols missing
NECP_FUNCS = [
    ("necp_open",                   0xFFFFFFF00A4E411C, ["necp_open"]),
    ("necp_client_add_flow",        0xFFFFFFF00A4E843C, ["necp_client_add_flow"]),
    ("necp_client_remove_flow",     0xFFFFFFF00A4E93C4, ["necp_client_remove_flow"]),
    ("necp_client_copy_interface",  0xFFFFFFF00A4EAC7C, ["necp_client_copy_interface"]),
    ("necp_client_copy_update",     0xFFFFFFF00A4EC264, ["necp_client_copy_update"]),
]

# Primary targets: find these by symbol name
PRIMARY_TARGETS = {
    "necp_client_copy_result":     ["necp_client_copy_result", "_necp_client_copy_result"],
    "necp_client_copy_interface":  ["necp_client_copy_interface"],
    "necp_client_copy_update":     ["necp_client_copy_update"],
    "necp_get_tlv_at_offset":      ["necp_get_tlv_at_offset"],
    "necp_client_action":          ["necp_client_action"],
    "necp_open":                   ["necp_open"],
    "necp_client_add_flow":        ["necp_client_add_flow"],
    "necp_client_remove_flow":     ["necp_client_remove_flow"],
}

FLOW_KALLOC_TYPE_VAR = 0xFFFFFFF007C62E68
IFNET_ARRAY_GLOBALS = [
    ("ifnet_array_base",  0xFFFFFFF00AD75720),
    ("ifnet_array_size",  0xFFFFFFF00AD75718),
    ("ifnet_array_count", 0xFFFFFFF00AD75728),
]

STRING_FALLBACK = {
    "assigned_results_copyout": "necp_client_copy assigned results copyout error",
    "assigned_tlv_header":      "necp_client_copy assigned results tlv_header copyout error",
    "result_copyout":           "necp_client_copy result copyout error",
    "group_members_copyout":    "necp_client_copy group members copyout error",
    "params_copyout":           "necp_client_copy parameters copyout error",
    "flow_divert_tlv_copyout":  "necp_client_copy request flow divert TLV copyout error",
}

KTRR_STRINGS = ["KTRR", "kpp_init", "sptm", "SPTM", "ctrr"]

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

def get_func_at_or_containing(addr):
    try:
        ga = sa(addr)
        if ga is None: return None
        f = getFunctionAt(ga)
        if f is not None: return f
        return getFunctionContaining(ga)
    except: return None

def get_func_by_name(name):
    try:
        fm = currentProgram.getFunctionManager()
        for f in fm.getFunctions(True):
            if str(f.getName()) == name: return f
    except: pass
    return None

def decompile(f, timeout=120):
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

def disasm_range(start, end, maxn=800):
    out = []
    try:
        listing = currentProgram.getListing()
        a = sa(start)
        if a is None: return out
        ins = listing.getInstructionAt(a)
        cnt = 0
        while ins is not None and cnt < maxn:
            pc = _u(ins.getAddress().getOffset())
            if pc >= end: break
            try: raw = int(currentProgram.getMemory().getInt(ins.getAddress())) & 0xFFFFFFFF
            except: raw = 0
            out.append((pc, raw, str(ins)))
            ins = ins.getNext()
            cnt += 1
    except: pass
    return out

def load_symbols(path):
    """Returns dict name -> addr, and set of all addrs."""
    syms = {}
    if not os.path.exists(path):
        print("[!] symbols.json missing at %s" % path)
        return syms
    try:
        with open(path, 'r') as f: data = json.load(f)
    except Exception as e:
        print("[!] symbols.json parse failed: %s" % e)
        return syms
    entries = []
    if isinstance(data, list):
        entries = data
    elif isinstance(data, dict):
        if isinstance(data.get("symbols"), list):
            entries = data["symbols"]
        else:
            for k, v in data.items():
                if isinstance(v, (int, str)):
                    try:
                        syms[k] = int(v, 16) if isinstance(v, str) and v.startswith("0x") else int(v)
                    except: pass
            if syms:
                print("[+] symbols loaded (dict format): %d entries" % len(syms))
                return syms
    for e in entries:
        if not isinstance(e, dict): continue
        name = e.get("name") or e.get("n") or e.get("symbol") or ""
        addr = e.get("addr") or e.get("address") or e.get("a") or e.get("value")
        if not name or addr is None: continue
        try:
            if isinstance(addr, str):
                addr = int(addr, 16) if addr.startswith("0x") else int(addr)
            syms[name] = int(addr)
        except: pass
    print("[+] symbols loaded: %d entries" % len(syms))
    return syms

def load_verified(path):
    if not os.path.exists(path):
        print("[!] verified_all_92.json missing")
        return {}
    try:
        with open(path, 'r') as f: data = json.load(f)
    except Exception as e:
        print("[!] verified parse failed: %s" % e)
        return {}
    out = {}
    if isinstance(data, dict):
        for k, v in data.items():
            try:
                if isinstance(v, str) and v.startswith("0x"):
                    out[k] = int(v, 16)
                elif isinstance(v, int):
                    out[k] = v
                elif isinstance(v, dict) and "addr" in v:
                    out[k] = int(v["addr"], 16) if isinstance(v["addr"], str) else int(v["addr"])
            except: pass
    print("[+] verified offsets loaded: %d entries" % len(out))
    return out

def resolve_target(syms, name_variants, fallback):
    """Look up symbol; return (addr, source)."""
    for v in name_variants:
        for k in syms:
            kk = k.lstrip("_")
            vv = v.lstrip("_")
            if kk == vv or k == v:
                return syms[k], "symbol:" + k
    return fallback, "fallback"

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
    return None

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
            try:
                h = mem.findBytes(addr, jn, None, True, mon)
            except: return None
            if h is None: return None
            return _u(h.getOffset())
    except: pass
    return None

def find_adrp_add_to(target_set):
    """Scan __text for ADRP+ADD refs to target_set. Fast: raw bytes."""
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
                                hits.setdefault(resolved, []).append(addr)
                addr += 4
                i += 4
        except Exception as ex:
            print("[-] block scan failed %s: %s" % (n, ex))
    return hits

def dump_function(lines, f, name, max_ins=600):
    try:
        entry = _u(f.getEntryPoint().getOffset())
        body = f.getBody()
        end = _u(body.getMaxAddress().getOffset()) if body else entry + 0x400
    except:
        return
    lines.append("--- %s @ %s ---" % (name, fmt(entry)))
    seen = set()
    for pc, raw, txt in disasm_range(entry, end + 4, max_ins):
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

def main():
    print("=== kernel_rw.py (symbols-first) ===")
    lines = []
    offsets_out = {}

    lines.append("=== PROGRAM ===")
    lines.append("name = %s" % currentProgram.getName())
    lines.append("min  = %s" % fmt(currentProgram.getMemory().getMinAddress().getOffset()))
    lines.append("max  = %s" % fmt(currentProgram.getMemory().getMaxAddress().getOffset()))
    lines.append("")

    lines.append("=== BLOCKS ===")
    for s, e, n, x in blocks():
        lines.append("  %-24s  %s..%s  size=0x%X  exec=%s" % (n, fmt(s), fmt(e), e - s, x))
    lines.append("")

    # 1) Symbols
    print("[+] loading symbols...")
    syms = load_symbols(SYMBOLS_JSON)
    lines.append("=== SYMBOLS ===")
    lines.append("loaded = %d" % len(syms))
    if not syms:
        lines.append("WHY: symbols.json not found or empty.")
        lines.append("FIX: ensure 'ipsw kernel sym' step succeeds and produces symbols.json.")
    lines.append("")

    # 2) Verified offsets
    print("[+] loading verified offsets...")
    verified = load_verified(VERIFIED_JSON)
    lines.append("=== VERIFIED OFFSETS ===")
    lines.append("loaded = %d" % len(verified))
    for k in sorted(verified.keys())[:60]:
        lines.append("  %-40s %s" % (k, fmt(verified[k])))
    if len(verified) > 60:
        lines.append("  ... (%d more)" % (len(verified) - 60))
    lines.append("")

    # 3) Resolve primary targets via symbols
    print("[+] resolving primary targets...")
    resolved = {}
    lines.append("=== RESOLVED TARGETS ===")
    for name, variants in PRIMARY_TARGETS.items():
        addr, src = resolve_target(syms, variants, None)
        if addr is not None:
            resolved[name] = addr
            offsets_out[name] = fmt(addr)
            lines.append("  %-30s %s  (%s)" % (name, fmt(addr), src))
        else:
            lines.append("  %-30s NOT FOUND" % name)
    lines.append("")

    # 4) Fallback for NECP funcs without symbols
    for name, fallback, variants in NECP_FUNCS:
        if name in resolved: continue
        addr, src = resolve_target(syms, variants, fallback)
        resolved[name] = addr
        offsets_out[name] = fmt(addr)

    # 5) If copy_result still unknown, try string xref
    if "necp_client_copy_result" not in offsets_out:
        print("[+] copy_result not in symbols, trying string xref...")
        target_vas = set()
        for k, needle in STRING_FALLBACK.items():
            va = find_string_va(needle)
            if va is not None:
                lines.append("  str[%s] = %s" % (k, fmt(va)))
                target_vas.add(va)
        if target_vas:
            refs = find_adrp_add_to(target_vas)
            lines.append("=== STRING XREFS ===")
            lines.append("targets = %d, hit_targets = %d" % (len(target_vas), len(refs)))
            for tva in sorted(refs.keys()):
                lines.append("  %s -> %d refs" % (fmt(tva), len(refs[tva])))
                for pc in refs[tva][:6]:
                    lines.append("    ref @ %s" % fmt(pc))
                    f = get_func_at_or_containing(pc)
                    if f is not None:
                        lines.append("      func = %s @ %s" % (str(f.getName()), fmt(_u(f.getEntryPoint().getOffset()))))
        else:
            lines.append("  no string VAs found in binary")
        lines.append("")

    # 6) Dump disasm+decompile of key resolved functions
    print("[+] dumping NECP functions...")
    lines.append("=== NECP FUNCTION DUMPS ===")
    for name in ["necp_open", "necp_client_add_flow", "necp_client_remove_flow",
                 "necp_client_copy_interface", "necp_client_copy_update",
                 "necp_client_copy_result", "necp_get_tlv_at_offset", "necp_client_action"]:
        if name not in resolved: continue
        addr = resolved[name]
        f = get_func_at_or_containing(addr)
        if f is None:
            lines.append("--- %s @ %s : NO FUNCTION OBJECT ---" % (name, fmt(addr)))
            lines.append("")
            continue
        dump_function(lines, f, name)

    # 7) kalloc_type_var
    lines.append("=== KALLOC_TYPE_VAR @ %s ===" % fmt(FLOW_KALLOC_TYPE_VAR))
    blk = inblk(FLOW_KALLOC_TYPE_VAR)
    if blk:
        lines.append("block = %s" % blk[2])
        for off in range(0, 0x40, 8):
            v = read_u64(FLOW_KALLOC_TYPE_VAR + off)
            lines.append("  +0x%02X: %s" % (off, fmt(v) if v is not None else "err"))
    else:
        lines.append("  NOT IN BLOCKS")
    lines.append("")

    # 8) ifnet globals
    lines.append("=== IFNET ARRAY GLOBALS ===")
    for name, addr in IFNET_ARRAY_GLOBALS:
        v = read_u64(addr)
        blk = inblk(addr)
        lines.append("  %-20s @ %s  [%s]  u64=%s" % (name, fmt(addr), blk[2] if blk else "?", fmt(v) if v is not None else "err"))
    lines.append("")

    # 9) KTRR
    lines.append("=== KTRR/KPP DETECTION ===")
    for needle in KTRR_STRINGS:
        va = find_string_va(needle)
        if va is not None:
            lines.append("  %-20s -> %s" % (needle, fmt(va)))
    lines.append("")

    # 10) Accessor offsets — only over exec blocks
    print("[+] extracting accessor offsets...")
    acc_count = 0
    lines.append("=== ACCESSOR OFFSETS (ldr X0,[X0,#imm]; ret) ===")
    for s, e, n, is_exec in blocks():
        if not is_exec: continue
        sz = e - s
        if sz <= 0 or sz > 64 * 1024 * 1024: continue
        try:
            ga = sa(s)
            jbuf = zeros(min(sz, 32 * 1024 * 1024), 'b')
            currentProgram.getMemory().getBytes(ga, jbuf)
            limit = min(sz, 32 * 1024 * 1024)
            i = 0
            while i + 8 <= limit and acc_count < 200:
                b0 = (int(jbuf[i]) & 0xFF) | ((int(jbuf[i+1]) & 0xFF) << 8) | ((int(jbuf[i+2]) & 0xFF) << 16) | ((int(jbuf[i+3]) & 0xFF) << 24)
                b1 = (int(jbuf[i+4]) & 0xFF) | ((int(jbuf[i+5]) & 0xFF) << 8) | ((int(jbuf[i+6]) & 0xFF) << 16) | ((int(jbuf[i+7]) & 0xFF) << 24)
                if (b0 & 0xFFC00000) == 0xF9400000 and (b1 & 0xFFFFFFFF) == 0xD65F03C0:
                    rn = (b0 >> 5) & 0x1F; rt = b0 & 0x1F
                    if rn == 0 and rt == 0:
                        imm = ((b0 >> 10) & 0xFFF) * 8
                        lines.append("  %s  +0x%X  (ldr_x)" % (fmt(s + i), imm))
                        acc_count += 1
                elif (b0 & 0xFFC00000) == 0xB9400000 and (b1 & 0xFFFFFFFF) == 0xD65F03C0:
                    rn = (b0 >> 5) & 0x1F; rt = b0 & 0x1F
                    if rn == 0 and rt == 0:
                        imm = ((b0 >> 10) & 0xFFF) * 4
                        lines.append("  %s  +0x%X  (ldr_w)" % (fmt(s + i), imm))
                        acc_count += 1
                i += 4
        except Exception as ex:
            print("[-] accessor scan %s: %s" % (n, ex))
    lines.append("  total = %d" % acc_count)
    lines.append("")

    # 11) Validate offsets from verified + our own
    lines.append("=== OFFSET VALIDATION ===")
    all_offs = dict(verified)
    for name, addr in resolved.items():
        all_offs["NECP_" + name] = addr
    ok = 0; fail = 0
    for name in sorted(all_offs.keys()):
        addr = all_offs[name]
        blk = inblk(addr)
        if blk is None:
            lines.append("  %-40s %s  NOT_IN_BLOCKS" % (name, fmt(addr)))
            fail += 1
            continue
        v = read_u64(addr)
        is_kptr = (v is not None and KPTR_MIN <= v <= KPTR_MAX)
        if is_kptr: ok += 1
        else: fail += 1
        lines.append("  %-40s %s  [%s]  u64=%s  %s" % (name, fmt(addr), blk[2], fmt(v) if v is not None else "err", "KPTR_OK" if is_kptr else "not_kptr"))
    lines.append("  valid kptr: %d / %d" % (ok, ok + fail))
    lines.append("")

    # Write outputs
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
    print("[-] FATAL: %s" % str(e))
    traceback.print_exc()
    try:
        with open(OUT, "a") as fh:
            fh.write("FATAL: %s\n" % str(e))
            fh.write(traceback.format_exc())
        with open(OUT_OFF, "a") as fh:
            fh.write("{}")
    except: pass