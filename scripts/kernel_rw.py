# -*- coding: utf-8 -*-
# @runtime Jython
#
# FIX v2: O(1) dedup, external symbols.json FIRST, capped Ghidra table.

import os, re, json, traceback, time

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
SYM = os.environ.get("SYMBOLS_JSON", os.path.join(WS, "symbols.json"))
OUT = os.path.join(WS, "result.txt")
OUT_JSON = os.path.join(WS, "offsets.json")

NAME = "necp_client_copy_result"
HINT = 0xFFFFFFF0070D61C6
MASK48 = 0x0000FFFFFFFFFFFF
KTEXT_LO = 0xFFF007004000
KTEXT_HI = 0xFFF200000000
MAX_GHIDRA_SYMS = 60000
MAX_XREFS = 40

def _u(v): return int(v) & 0xFFFFFFFFFFFFFFFF
def fmt(v):
    if v is None: return "0x0"
    try: return "0x%016X" % (int(v) & 0xFFFFFFFFFFFFFFFF)
    except: return "0x0"
def sa(a):
    if a is None: return None
    try: return currentProgram.getAddressFactory().getAddress("%X" % (int(a) & 0xFFFFFFFFFFFFFFFF))
    except: return None
def r32(a):
    ga = sa(a)
    if ga is None: return None
    try: return int(currentProgram.getMemory().getInt(ga)) & 0xFFFFFFFF
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
                out.append((_u(b.getStart().getOffset()), _u(b.getEnd().getOffset()),
                            b.getName(), b.isExecute()))
            except: pass
    except: pass
    _blocks = out
    return out

def inblk(a):
    if a is None: return None
    for s, e, n, x in blocks():
        if s <= a < e: return (s, e, n, x)
    return None

def is_ktext(p):
    if p is None or p == 0: return False
    return KTEXT_LO <= (p & MASK48) < KTEXT_HI

# ---------- symbols ----------
_symidx = None
_symset = None

def _add(a, n):
    """O(1) dedup via set."""
    global _symidx, _symset
    if _symidx is None:
        _symidx = []
        _symset = set()
    try:
        av = _u(a)
        key = (av, n)
        if key in _symset: return
        _symset.add(key)
        _symidx.append(key)
    except: pass

def _walk_entry(it, fallback_addr=None):
    if isinstance(it, dict):
        n = it.get("name") or it.get("symbol") or it.get("n") or it.get("s")
        a = it.get("address") or it.get("addr") or it.get("value") or it.get("a") or fallback_addr
        try:
            if n and a is not None:
                av = int(a, 0) if isinstance(a, str) else int(a)
                if av >= 0xFFFF000000000000: _add(av, n)
        except: pass
    elif isinstance(it, (list, tuple)) and len(it) == 2:
        try:
            a = int(it[0], 0) if isinstance(it[0], str) else int(it[0])
            n = it[1]
            if a >= 0xFFFF000000000000 and isinstance(n, str): _add(a, n)
        except: pass

def build_idx():
    global _symidx, _symset
    if _symidx is not None: return
    _symidx = []
    _symset = set()

    # ---------- 1. external symbols.json (fast, first) ----------
    if os.path.exists(SYM):
        print("[+] loading %s" % SYM)
        t0 = time.time()
        try:
            with open(SYM) as fh: raw = fh.read()
            print("[+] raw size: %d bytes" % len(raw))
            data = json.loads(raw)
            print("[+] parsed: %s" % type(data).__name__)
            n_before = 0
            if isinstance(data, dict):
                n_items = len(data)
                print("[+] dict keys: %d" % n_items)
                for k, v in data.items():
                    # format A: { "0xADDR": "name" }
                    try:
                        a = int(k, 0)
                        if isinstance(v, str) and a >= 0xFFFF000000000000:
                            _add(a, v); continue
                    except: pass
                    # format B: { "name": "0xADDR" or int }
                    try:
                        a = int(v, 0) if isinstance(v, str) else int(v)
                        if a >= 0xFFFF000000000000:
                            _add(a, k); continue
                    except: pass
                    # format C: { "0xADDR": {"name": ...} }
                    if isinstance(v, dict):
                        nn = v.get("name") or v.get("symbol")
                        if nn:
                            try:
                                a = int(k, 0)
                                if a >= 0xFFFF000000000000: _add(a, nn)
                            except: pass
                for key in ("symbols", "addrs", "entries", "items", "data"):
                    v = data.get(key)
                    if isinstance(v, list):
                        for it in v: _walk_entry(it)
                    elif isinstance(v, dict):
                        for k2, it in v.items(): _walk_entry(it, fallback_addr=k2)
            elif isinstance(data, list):
                print("[+] list len: %d" % len(data))
                for it in data: _walk_entry(it)
            print("[+] external added: %d (%.1fs)" % (len(_symidx), time.time() - t0))
        except Exception as e:
            print("[-] external err: %s" % str(e))

    # ---------- 2. Ghidra symbol table (fallback, capped) ----------
    n_ext = len(_symidx)
    if n_ext < 1000:
        print("[+] external small (%d), falling back to Ghidra table" % n_ext)
        t0 = time.time()
        try:
            count = 0
            for sym in currentProgram.getSymbolTable().getAllSymbols(False):
                try:
                    _add(sym.getAddress().getOffset(), sym.getName())
                    count += 1
                    if count % 10000 == 0:
                        print("[+]   ghidra syms: %d" % count)
                    if count >= MAX_GHIDRA_SYMS: break
                except: pass
            print("[+] ghidra added: %d (%.1fs)" % (count, time.time() - t0))
        except Exception as e:
            print("[-] ghidra err: %s" % str(e))
    else:
        print("[+] external sufficient (%d), skipping Ghidra table" % n_ext)

    print("[+] total symbols: %d" % len(_symidx))

def names_match(substr, exec_only=None):
    build_idx()
    out = []
    for a, n in _symidx:
        if substr not in n: continue
        blk = inblk(a)
        is_exec = bool(blk and blk[3])
        if exec_only is True and not is_exec: continue
        if exec_only is False and is_exec: continue
        out.append((a, n, blk[2] if blk else "NO_BLOCK", is_exec))
    return out

def name_at(a):
    build_idx()
    best = None
    for aa, n in _symidx:
        if not is_ktext(aa): continue
        if aa <= a < aa + 0x1000:
            d = a - aa
            if d == 0: return n
            if best is None or d < best[0]: best = (d, n)
    return ("%s+0x%X" % (best[1], best[0])) if best else None

def func_containing(a):
    try:
        ga = sa(a)
        if ga is None: return None
        f = getFunctionContaining(ga)
        if f is None: return None
        return _u(f.getEntryPoint().getOffset())
    except: return None

def xrefs_to(a):
    out = []
    try:
        ga = sa(a)
        if ga is None: return out
        cnt = 0
        for ref in getReferencesTo(ga):
            try:
                out.append(_u(ref.getFromAddress().getOffset()))
                cnt += 1
                if cnt >= MAX_XREFS: break
            except: pass
    except: pass
    return out

# ---------- decoder ----------
def dec(b, pc):
    if b == 0xD503237F: return "pacibsp"
    if b == 0xD50323FF: return "autibsp"
    if b == 0xD503233F: return "paciasp"
    if b == 0xD50323BF: return "autiasp"
    if b == 0xD5033BBF: return "autiasp"
    if b == 0xD65F03C0: return "ret"
    if b == 0xD503201F: return "nop"
    if b == 0xD65F0FFF: return "ret"
    if (b & 0xFF800000) == 0x0F000000: return "movi v%d.16b, #0x%X" % (b & 0x1F, (b >> 5) & 0xFF)
    if (b & 0xFFE00000) == 0x6F00E400: return "movi v%d.2d, #0" % (b & 0x1F)
    if (b & 0x7FE00000) == 0x6A000000: return "tst w%d, w%d" % ((b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0xEA000000: return "tst x%d, x%d" % ((b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0xFFC00000) == 0xA9800000:
        i = (b >> 15) & 0x7F
        if i & 0x40: i -= 0x80
        return "stp x%d, x%d, [x%d, #%d]!" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, i * 8)
    if (b & 0xFFC00000) == 0xA9C00000:
        i = (b >> 15) & 0x7F
        if i & 0x40: i -= 0x80
        return "ldp x%d, x%d, [x%d, #%d]!" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, i * 8)
    if (b & 0xFFC00000) == 0xA9000000:
        return "stp x%d, x%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, ((b >> 15) & 0x7F) * 8)
    if (b & 0xFFC00000) == 0xA9400000:
        return "ldp x%d, x%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, ((b >> 15) & 0x7F) * 8)
    if (b & 0xFFC00000) == 0x29000000:
        return "stp w%d, w%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, ((b >> 15) & 0x7F) * 4)
    if (b & 0xFFC00000) == 0x29400000:
        return "ldp w%d, w%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, ((b >> 15) & 0x7F) * 4)
    if (b & 0xFFC00000) == 0xAD800000:
        i = (b >> 15) & 0x7F
        if i & 0x40: i -= 0x80
        return "stp q%d, q%d, [x%d, #%d]!" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, i * 16)
    if (b & 0xFFC00000) == 0xADC00000:
        i = (b >> 15) & 0x7F
        if i & 0x40: i -= 0x80
        return "ldp q%d, q%d, [x%d, #%d]!" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, i * 16)
    if (b & 0xFFC00000) == 0xAD000000:
        return "stp q%d, q%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, ((b >> 15) & 0x7F) * 16)
    if (b & 0xFFC00000) == 0xAD400000:
        return "ldp q%d, q%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, ((b >> 15) & 0x7F) * 16)
    if (b & 0xFFC00000) == 0x3D800000:
        return "str q%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 5) & 0x1F, ((b >> 10) & 0xFFF) * 16)
    if (b & 0xFFC00000) == 0x3DC00000:
        return "ldr q%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 5) & 0x1F, ((b >> 10) & 0xFFF) * 16)
    if (b & 0xFFC00000) == 0xF9400000:
        return "ldr x%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 5) & 0x1F, ((b >> 10) & 0xFFF) * 8)
    if (b & 0xFFC00000) == 0xB9400000:
        return "ldr w%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 5) & 0x1F, ((b >> 10) & 0xFFF) * 4)
    if (b & 0xFFC00000) == 0xF9000000:
        return "str x%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 5) & 0x1F, ((b >> 10) & 0xFFF) * 8)
    if (b & 0xFFC00000) == 0xB9000000:
        return "str w%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 5) & 0x1F, ((b >> 10) & 0xFFF) * 4)
    if (b & 0xFFE00000) == 0x39400000:
        return "ldrb w%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 10) & 0xFFF)
    if (b & 0xFFE00000) == 0x39000000:
        return "strb w%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 10) & 0xFFF)
    if (b & 0xFFE00000) == 0x79400000:
        return "ldrh w%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 5) & 0x1F, ((b >> 10) & 0xFFF) * 2)
    if (b & 0xFFE00000) == 0x79000000:
        return "strh w%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 5) & 0x1F, ((b >> 10) & 0xFFF) * 2)
    if (b & 0xFFC00000) == 0xF8400000:
        i = (b >> 12) & 0x1FF
        if i & 0x100: i -= 0x200
        return "ldur x%d, [x%d, #%d]" % (b & 0x1F, (b >> 5) & 0x1F, i)
    if (b & 0xFFC00000) == 0xB8400000:
        i = (b >> 12) & 0x1FF
        if i & 0x100: i -= 0x200
        return "ldur w%d, [x%d, #%d]" % (b & 0x1F, (b >> 5) & 0x1F, i)
    if (b & 0xFFC00000) == 0xF8000000:
        i = (b >> 12) & 0x1FF
        if i & 0x100: i -= 0x200
        return "stur x%d, [x%d, #%d]" % (b & 0x1F, (b >> 5) & 0x1F, i)
    if (b & 0xFFC00000) == 0xB8000000:
        i = (b >> 12) & 0x1FF
        if i & 0x100: i -= 0x200
        return "stur w%d, [x%d, #%d]" % (b & 0x1F, (b >> 5) & 0x1F, i)
    if (b & 0x7F800000) == 0x52800000:
        return "movz w%d, #0x%X, lsl #%d" % (b & 0x1F, (b >> 5) & 0xFFFF, ((b >> 21) & 3) * 16)
    if (b & 0x7F800000) == 0xD2800000:
        return "movz x%d, #0x%X, lsl #%d" % (b & 0x1F, (b >> 5) & 0xFFFF, ((b >> 21) & 3) * 16)
    if (b & 0x7F800000) == 0x72800000:
        return "movk w%d, #0x%X, lsl #%d" % (b & 0x1F, (b >> 5) & 0xFFFF, ((b >> 21) & 3) * 16)
    if (b & 0x7F800000) == 0xF2800000:
        return "movk x%d, #0x%X, lsl #%d" % (b & 0x1F, (b >> 5) & 0xFFFF, ((b >> 21) & 3) * 16)
    if (b & 0x7F800000) == 0x12800000:
        return "movn w%d, #0x%X, lsl #%d" % (b & 0x1F, (b >> 5) & 0xFFFF, ((b >> 21) & 3) * 16)
    if (b & 0x7F800000) == 0x92800000:
        return "movn x%d, #0x%X, lsl #%d" % (b & 0x1F, (b >> 5) & 0xFFFF, ((b >> 21) & 3) * 16)
    if (b & 0x7F800000) == 0x11000000:
        sh = (b >> 22) & 1; i = (b >> 10) & 0xFFF
        if sh: i <<= 12
        return "add w%d, w%d, #0x%X" % (b & 0x1F, (b >> 5) & 0x1F, i)
    if (b & 0x7F800000) == 0x91000000:
        sh = (b >> 22) & 1; i = (b >> 10) & 0xFFF
        if sh: i <<= 12
        return "add x%d, x%d, #0x%X" % (b & 0x1F, (b >> 5) & 0x1F, i)
    if (b & 0x7F800000) == 0x51000000:
        sh = (b >> 22) & 1; i = (b >> 10) & 0xFFF
        if sh: i <<= 12
        return "sub w%d, w%d, #0x%X" % (b & 0x1F, (b >> 5) & 0x1F, i)
    if (b & 0x7F800000) == 0xD1000000:
        sh = (b >> 22) & 1; i = (b >> 10) & 0xFFF
        if sh: i <<= 12
        return "sub x%d, x%d, #0x%X" % (b & 0x1F, (b >> 5) & 0x1F, i)
    if (b & 0x7FE00000) == 0x0B000000: return "add w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x8B000000: return "add x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x4B000000: return "sub w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0xCB000000: return "sub x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x2A000000: return "orr w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0xAA000000: return "orr x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x0A000000: return "and w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x8A000000: return "and x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x6B000000: return "subs w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0xEB000000: return "subs x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7F800000) == 0x53000000: return "ubfm w%d, w%d, #%d, #%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x3F, (b >> 10) & 0x3F)
    if (b & 0x7F800000) == 0xD3000000: return "ubfm x%d, x%d, #%d, #%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x3F, (b >> 10) & 0x3F)
    if (b & 0x9F000000) == 0x90000000:
        il = (b >> 29) & 3; ih = (b >> 5) & 0x7FFFF
        i = (ih << 2) | il
        if i & 0x100000: i -= 0x200000
        page = (pc & ~0xFFF) + (i << 12)
        return "adrp x%d, 0x%016X" % (b & 0x1F, page & 0xFFFFFFFFFFFFFFFF)
    if (b & 0x9F000000) == 0x10000000:
        il = (b >> 29) & 3; ih = (b >> 5) & 0x7FFFF
        i = (ih << 2) | il
        if i & 0x100000: i -= 0x200000
        return "adr x%d, 0x%016X" % (b & 0x1F, (pc + i) & 0xFFFFFFFFFFFFFFFF)
    if (b & 0x7C000000) == 0x14000000:
        o = b & 0x03FFFFFF
        if o & 0x02000000: o -= 0x04000000
        return "b #0x%X (-> 0x%016X)" % (o * 4, (pc + o * 4) & 0xFFFFFFFFFFFFFFFF)
    if (b & 0x7C000000) == 0x94000000:
        o = b & 0x03FFFFFF
        if o & 0x02000000: o -= 0x04000000
        return "bl #0x%X (-> 0x%016X)" % (o * 4, (pc + o * 4) & 0xFFFFFFFFFFFFFFFF)
    if (b & 0xFF000010) == 0x54000000:
        o = (b >> 5) & 0x7FFFF
        if o & 0x40000: o -= 0x80000
        N = ["eq","ne","cs","cc","mi","pl","vs","vc","hi","ls","ge","lt","gt","le","al","nv"]
        return "b.%s #0x%X" % (N[b & 0xF], o * 4)
    if (b & 0x7E000000) == 0x34000000:
        o = (b >> 5) & 0x7FFFF
        if o & 0x40000: o -= 0x80000
        return "cbz w%d, #0x%X" % (b & 0x1F, o * 4)
    if (b & 0x7E000000) == 0x35000000:
        o = (b >> 5) & 0x7FFFF
        if o & 0x40000: o -= 0x80000
        return "cbnz w%d, #0x%X" % (b & 0x1F, o * 4)
    if (b & 0x7E000000) == 0xB4000000:
        o = (b >> 5) & 0x7FFFF
        if o & 0x40000: o -= 0x80000
        return "cbz x%d, #0x%X" % (b & 0x1F, o * 4)
    if (b & 0x7E000000) == 0xB5000000:
        o = (b >> 5) & 0x7FFFF
        if o & 0x40000: o -= 0x80000
        return "cbnz x%d, #0x%X" % (b & 0x1F, o * 4)
    if (b & 0x7F800000) == 0x71000000: return "cmp w%d, #0x%X" % ((b >> 5) & 0x1F, (b >> 10) & 0xFFF)
    if (b & 0x7F800000) == 0xF1000000: return "cmp x%d, #0x%X" % ((b >> 5) & 0x1F, (b >> 10) & 0xFFF)
    if (b & 0x7FE00C00) == 0x1A800000: return "csel w%d, w%d, w%d, #%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F, b & 0xF)
    if (b & 0x7FE00C00) == 0x9A800000: return "csel x%d, x%d, x%d, #%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F, b & 0xF)
    return "?? (0x%08X)" % b

def disasm(a, count):
    if a is None: return ["(addr is None)"]
    blk = inblk(a)
    if blk is None: return ["(addr %s NOT IN ANY LOADED BLOCK)" % fmt(a)]
    if not blk[3]: return ["(addr %s in NON-EXEC block %s)" % (fmt(a), blk[2])]
    ga = sa(a)
    if ga is None: return ["(cannot toAddr %s)" % fmt(a)]
    mem = currentProgram.getMemory()
    out = []
    for i in range(count):
        aa = a + i * 4
        gaa = sa(aa)
        if gaa is None: break
        try:
            b = mem.getInt(gaa) & 0xFFFFFFFF
        except: break
        out.append("%016X  %08X  %s" % (aa, b, dec(b, aa)))
    return out if out else ["(no readable code at %s)" % fmt(a)]

def parse_instr(line):
    m = re.match(r"([0-9A-F]{16})\s+([0-9A-F]{8})\s+(.*)", line)
    if not m: return None
    return int(m.group(1), 16), m.group(3).split(" ", 1)[0].lower(), m.group(3)

def extract_mem(body):
    m = re.search(r"\[(x\d+|sp|x31),\s*#(0x[0-9A-Fa-f]+|-?\d+)\]", body)
    if not m: return None
    try:
        i = int(m.group(2), 0)
        if i < 0: i += 0x1000
        return m.group(1), i
    except: return None

def extract_call(body):
    m = re.search(r"->\s*0x([0-9A-F]+)", body)
    return int(m.group(1), 16) if m else None

# ---------- resolve ----------
def resolve_target():
    hits = names_match(NAME, exec_only=True)
    if hits:
        a, n, blk, _ = hits[0]
        return a, "exec symbol '%s' @ %s [%s]" % (n, fmt(a), blk)
    blk = inblk(HINT)
    if blk and blk[3]:
        return HINT, "hint %s (exec %s)" % (fmt(HINT), blk[2])
    hits_ne = names_match(NAME, exec_only=False)
    for a, n, blkname, _ in hits_ne[:6]:
        refs = xrefs_to(a)
        for r in refs:
            f = func_containing(r)
            if f:
                return f, "func of xref to str '%s' @ %s (ref@%s)" % (n, fmt(a), fmt(r))
    return None, "no exec symbol, hint not exec, no xrefs to strings"

# ---------- main ----------
def main():
    print("=== necp_client_copy_result focused ===")
    t0 = time.time()
    build_idx()
    print("[+] idx built in %.1fs" % (time.time() - t0))

    lines = []
    lines.append("=== SYMBOL DIAG ===")
    lines.append("total symbols: %d" % len(_symidx or []))
    lines.append("symbols.json: %s (%s)" % (SYM, "exists" if os.path.exists(SYM) else "MISSING"))
    try:
        if os.path.exists(SYM): lines.append("size: %d" % os.path.getsize(SYM))
    except: pass
    lines.append("")

    all_exec = names_match(NAME, exec_only=True)
    all_none = names_match(NAME, exec_only=False)
    lines.append("=== MATCHES ===")
    lines.append("exec (%d):" % len(all_exec))
    for a, n, blk, _ in all_exec[:20]:
        lines.append("  %s  %-40s  [%s]" % (fmt(a), n, blk))
    lines.append("non-exec (%d):" % len(all_none))
    for a, n, blk, _ in all_none[:20]:
        lines.append("  %s  %-40s  [%s]" % (fmt(a), n, blk))
    lines.append("")

    target, how = resolve_target()
    lines.append("=== RESOLVED TARGET ===")
    if target is None:
        lines.append("FAIL: %s" % how)
        lines.append("")
        lines.append("xref dump:")
        for a, n, blkname, _ in all_none[:4]:
            lines.append("  str @ %s  '%s'  [%s]" % (fmt(a), n, blkname))
            refs = xrefs_to(a)
            lines.append("    xrefs: %d" % len(refs))
            for r in refs[:8]:
                f = func_containing(r)
                lines.append("      %s -> func %s" % (fmt(r), fmt(f) if f else "?"))
        write(lines, {})
        return

    lines.append("target = %s" % fmt(target))
    lines.append("how    = %s" % how)
    blk = inblk(target)
    lines.append("block  = %s (exec=%s)" % (blk[2], blk[3]))
    lines.append("")

    lines.append("=== DISASM ===")
    dis = disasm(target, 400)
    for l in dis:
        r = parse_instr(l)
        note = ""
        if r:
            pc, mn, body = r
            if mn in ("b", "bl"):
                t = extract_call(body)
                if t and is_ktext(t):
                    nn = name_at(t)
                    if nn: note = "    ; => " + nn
        lines.append("  " + l + note)
    lines.append("")

    ldr = {}
    strm = {}
    calls = []
    for l in dis:
        r = parse_instr(l)
        if not r: continue
        pc, mn, body = r
        e = extract_mem(body)
        if mn in ("ldr", "ldrb", "ldrh", "ldur"):
            if e: ldr.setdefault(e, []).append((pc, body))
        elif mn in ("str", "strb", "strh", "stur"):
            if e: strm.setdefault(e, []).append((pc, body))
        if mn in ("b", "bl"):
            t = extract_call(body)
            if t: calls.append((pc, mn, t))

    lines.append("=== LDR [base, #imm] ===")
    for (b, i), ent in sorted(ldr.items(), key=lambda kv: kv[0][1]):
        lines.append("  [%s, #0x%X]  hits=%d" % (b, i, len(ent)))
        for pc, body in ent[:3]:
            lines.append("      %016X  %s" % (pc, body))
    lines.append("")

    lines.append("=== STR [base, #imm] ===")
    for (b, i), ent in sorted(strm.items(), key=lambda kv: kv[0][1]):
        lines.append("  [%s, #0x%X]  hits=%d" % (b, i, len(ent)))
    lines.append("")

    lines.append("=== CALLS ===")
    seen = set()
    for pc, mn, t in calls:
        if t in seen: continue
        seen.add(t)
        nn = name_at(t) or "?"
        lines.append("  %s -> %s  %s" % (mn, fmt(t), nn))
    lines.append("")

    flowregs = ("x19","x20","x21","x22","x23","x24")
    lines.append("=== FLOW-REG LDRs (x19..x24, imm 0x40..0x300) ===")
    seq = []
    for (b, i), ent in ldr.items():
        if b in flowregs and 0x40 <= i <= 0x300:
            for pc, body in ent:
                seq.append((pc, b, i, body))
    seq.sort()
    for pc, b, i, body in seq:
        lines.append("  %016X  %s" % (pc, body))
    lines.append("")

    lines.append("=== VERDICT ===")
    if seq:
        lines.append("flow-reg LDRs found:")
        lines.append("  candidate pair (assigned_results, length):")
        lines.append("    %s" % seq[0][3])
        if len(seq) > 1: lines.append("    %s" % seq[1][3])
    else:
        lines.append("NO flow-reg LDRs. necp_client_copy_result does NOT")
        lines.append("read flow->assigned_results on this build.")

    jout = {
        "target": fmt(target),
        "how": how,
        "flow_ldrs": ["%s+0x%X" % (b, i) for _, b, i, _ in seq],
        "all_ldr": sorted(set(i for _, i in ldr.keys())),
        "all_str": sorted(set(i for _, i in strm.keys())),
    }
    write(lines, jout)

def write(lines, jout):
    try:
        with open(OUT, "w") as fh:
            for l in lines: fh.write(l + "\n")
        print("[+] wrote " + OUT)
    except Exception as e:
        print("[-] " + str(e))
    try:
        with open(OUT_JSON, "w") as fh:
            fh.write(json.dumps(jout, indent=2, sort_keys=True))
        print("[+] wrote " + OUT_JSON)
    except Exception as e:
        print("[-] " + str(e))

try:
    main()
except Exception as e:
    print("[-] FATAL: " + str(e))
    traceback.print_exc()
    try:
        with open(OUT, "w") as fh: fh.write("FATAL: " + str(e) + "\n")
    except: pass