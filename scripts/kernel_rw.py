# -*- coding: utf-8 -*-
# @runtime Jython
#
# FOCUSED ANALYSIS: necp_client_copy_result
# Отвечает на вопросы:
#   Q1: читает ли necp_client_copy_result поле flow->assigned_results?
#   Q2: если да — на каком offset (NCF_ASSIGNED_OFF)?
#   Q3: куда уходит результат (memcpy / copyout / TLV build)?
#
# Output: result.txt + offsets.json
# Символы: $SYMBOLS_JSON (default $GITHUB_WORKSPACE/symbols.json)

import os
import re
import json
import traceback

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
SYM = os.environ.get("SYMBOLS_JSON", os.path.join(WS, "symbols.json"))
OUT = os.path.join(WS, "result.txt")
OUT_JSON = os.path.join(WS, "offsets.json")

MASK48 = 0x0000FFFFFFFFFFFF
KTEXT_LO = 0xFFF007004000
KTEXT_HI = 0xFFF200000000

TARGET_NAMES = [
    "_necp_client_copy_result",
    "necp_client_copy_result",
    "___necp_client_copy_result",
]
TARGET_HINT = 0xFFFFFFF0070D61C6

MAX_DISASM = 700
MAX_CALLEE = 40

# registry symbols / blocks
_sym = None
_symidx = None
_blocks = None


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
        v = int(a) & 0xFFFFFFFFFFFFFFFF
        return currentProgram.getAddressFactory().getAddress("%X" % v)
    except Exception:
        return None


def r32(a):
    ga = sa(a)
    if ga is None:
        return None
    try:
        return int(currentProgram.getMemory().getInt(ga)) & 0xFFFFFFFF
    except Exception:
        return None


def r64(a):
    ga = sa(a)
    if ga is None:
        return None
    try:
        return int(currentProgram.getMemory().getLong(ga)) & 0xFFFFFFFFFFFFFFFF
    except Exception:
        return None


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
                            b.getName(), b.isExecute()))
            except Exception:
                pass
    except Exception:
        pass
    _blocks = out
    return out


def inblk(a):
    if a is None:
        return None
    for s, e, n, x in blocks():
        if s <= a < e:
            return (s, e, n, x)
    return None


def is_ktext(p):
    if p is None or p == 0:
        return False
    lo = p & MASK48
    return KTEXT_LO <= lo < KTEXT_HI


# ------------- symbol loading -------------

def _add_sym(name, addr):
    if not name or addr is None:
        return
    try:
        if not isinstance(name, str):
            name = str(name)
        name = name.strip()
        if not name:
            return
        addr = _u(int(addr))
        if addr < 0xFFFF000000000000:
            return
        _sym[name] = addr
        if name.startswith("_"):
            _sym[name[1:]] = addr
        else:
            _sym["_" + name] = addr
    except Exception:
        pass


def _load_sym():
    global _sym
    if _sym is not None:
        return
    _sym = {"__diag__": "init"}

    if not os.path.exists(SYM):
        _sym["__diag__"] = "NOT FOUND " + SYM
        return

    try:
        with open(SYM) as fh:
            raw = fh.read()
    except Exception as e:
        _sym["__diag__"] = "read err: " + str(e)
        return

    size = len(raw)
    if size == 0:
        _sym["__diag__"] = "empty file"
        return

    try:
        data = json.loads(raw.strip() or "{}")
    except Exception as e:
        _sym["__diag__"] = "json err: %s size=%d" % (str(e), size)
        return

    added = 0
    if isinstance(data, dict):
        for k, v in data.items():
            if not isinstance(v, str):
                continue
            try:
                addr = int(k)
            except Exception:
                continue
            if addr < 0xFFFF000000000000:
                continue
            _add_sym(v.strip(), addr)
            added += 1

    if added == 0 and isinstance(data, dict):
        def walk(node, depth=0):
            if depth > 6:
                return
            try:
                if isinstance(node, dict):
                    nm = node.get("name") or node.get("symbol")
                    ad = node.get("address") or node.get("addr") or node.get("value")
                    if nm and ad is not None:
                        _add_sym(nm, ad)
                        return
                    for _, v in node.items():
                        if isinstance(v, (dict, list)):
                            walk(v, depth + 1)
                elif isinstance(node, list):
                    for it in node:
                        walk(it, depth + 1)
            except Exception:
                pass
        walk(data)

    if added == 0 and isinstance(data, list):
        for it in data:
            try:
                if isinstance(it, dict):
                    nm = it.get("name") or it.get("symbol")
                    ad = it.get("address") or it.get("addr") or it.get("value")
                    if nm and ad is not None:
                        _add_sym(nm, ad)
            except Exception:
                pass

    real = len([k for k in _sym.keys() if not k.startswith("__")])
    _sym["__diag__"] = "size=%d parsed=%d" % (size, real)


def _build_idx():
    global _symidx
    if _symidx is not None:
        return
    _symidx = []
    seen = set()
    try:
        for sym in currentProgram.getSymbolTable().getAllSymbols(True):
            try:
                a = _u(sym.getAddress().getOffset())
                n = sym.getName()
                k = (a, n)
                if k in seen:
                    continue
                _symidx.append(k)
                seen.add(k)
            except Exception:
                pass
    except Exception:
        pass
    _load_sym()
    for n, a in _sym.items():
        if n.startswith("__"):
            continue
        k = (a, n)
        if k in seen:
            continue
        _symidx.append(k)
        seen.add(k)


def snamed(p):
    _build_idx()
    return [(a, n) for a, n in _symidx if p in n]


def snamed_exact(p):
    _build_idx()
    return [(a, n) for a, n in _symidx
            if n == p or n == "_" + p or n == "s_" + p]


def _is_func_sym(nm):
    for pre in ("s_", "str_", "a_", "unk_", "DAT_", "LAB_",
                "PTR_", "off_", "d_"):
        if nm.startswith(pre):
            return False
    return True


def sget(n):
    _load_sym()
    if n in _sym:
        return _sym[n]
    b = n.lstrip("_")
    if b in _sym:
        return _sym[b]
    if ("_" + n) in _sym:
        return _sym["_" + n]
    for a, _ in snamed_exact(n):
        if is_ktext(a):
            return a
    for a, _ in snamed_exact(b):
        if is_ktext(a):
            return a
    best = None
    for a, nm in snamed(b):
        if not is_ktext(a):
            continue
        if best is None or len(nm) < len(best[1]):
            best = (a, nm)
    return best[0] if best else None


def name_at(addr):
    """Best symbol name for addr, else +offset from nearest known func."""
    if addr is None:
        return None
    _build_idx()
    for a, n in _symidx:
        if a == addr and _is_func_sym(n):
            return n
    best = None
    for a, n in _symidx:
        if a <= addr < a + 0x1000 and _is_func_sym(n):
            d = addr - a
            if d == 0:
                return n
            if best is None or d < best[0]:
                best = (d, n)
    if best:
        return "%s+0x%X" % (best[1], best[0])
    return None


# ------------- ARM64 mini-decoder (unchanged) -------------

def decode_one(b, pc):
    if b == 0xD503237F: return "pacibsp"
    if b == 0xD50323FF: return "autibsp"
    if b == 0xD503233F: return "paciasp"
    if b == 0xD50323BF: return "autiasp"
    if b == 0xD5033BBF: return "autiasp"
    if b == 0xD65F03C0: return "ret"
    if b == 0xD503201F: return "nop"
    if b == 0xD65F0FFF: return "ret"

    if (b & 0xFF800000) == 0x0F000000:
        return "movi v%d.16b, #0x%X" % (b & 0x1F, (b >> 5) & 0xFF)
    if (b & 0xFFE00000) == 0x6F00E400:
        return "movi v%d.2d, #0" % (b & 0x1F)

    if (b & 0x7FE00000) == 0x6A000000:
        return "tst w%d, w%d" % ((b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0xEA000000:
        return "tst x%d, x%d" % ((b >> 5) & 0x1F, (b >> 16) & 0x1F)

    if (b & 0xFFC00000) == 0xA9800000:
        imm = (b >> 15) & 0x7F
        if imm & 0x40: imm -= 0x80
        return "stp x%d, x%d, [x%d, #%d]!" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, imm * 8)
    if (b & 0xFFC00000) == 0xA9C00000:
        imm = (b >> 15) & 0x7F
        if imm & 0x40: imm -= 0x80
        return "ldp x%d, x%d, [x%d, #%d]!" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, imm * 8)
    if (b & 0xFFC00000) == 0xA8800000:
        imm = (b >> 15) & 0x7F
        return "stp x%d, x%d, [x%d], #%d" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, imm * 8)
    if (b & 0xFFC00000) == 0xA8C00000:
        imm = (b >> 15) & 0x7F
        return "ldp x%d, x%d, [x%d], #%d" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, imm * 8)
    if (b & 0xFFC00000) == 0xA9000000:
        return "stp x%d, x%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, ((b >> 15) & 0x7F) * 8)
    if (b & 0xFFC00000) == 0xA9400000:
        return "ldp x%d, x%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, ((b >> 15) & 0x7F) * 8)
    if (b & 0xFFC00000) == 0x29000000:
        return "stp w%d, w%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, ((b >> 15) & 0x7F) * 4)
    if (b & 0xFFC00000) == 0x29400000:
        return "ldp w%d, w%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, ((b >> 15) & 0x7F) * 4)

    if (b & 0xFFC00000) == 0xAD800000:
        imm = (b >> 15) & 0x7F
        if imm & 0x40: imm -= 0x80
        return "stp q%d, q%d, [x%d, #%d]!" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, imm * 16)
    if (b & 0xFFC00000) == 0xADC00000:
        imm = (b >> 15) & 0x7F
        if imm & 0x40: imm -= 0x80
        return "ldp q%d, q%d, [x%d, #%d]!" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, imm * 16)
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
        imm = (b >> 12) & 0x1FF
        if imm & 0x100: imm -= 0x200
        return "ldur x%d, [x%d, #%d]" % (b & 0x1F, (b >> 5) & 0x1F, imm)
    if (b & 0xFFC00000) == 0xB8400000:
        imm = (b >> 12) & 0x1FF
        if imm & 0x100: imm -= 0x200
        return "ldur w%d, [x%d, #%d]" % (b & 0x1F, (b >> 5) & 0x1F, imm)
    if (b & 0xFFC00000) == 0xF8000000:
        imm = (b >> 12) & 0x1FF
        if imm & 0x100: imm -= 0x200
        return "stur x%d, [x%d, #%d]" % (b & 0x1F, (b >> 5) & 0x1F, imm)
    if (b & 0xFFC00000) == 0xB8000000:
        imm = (b >> 12) & 0x1FF
        if imm & 0x100: imm -= 0x200
        return "stur w%d, [x%d, #%d]" % (b & 0x1F, (b >> 5) & 0x1F, imm)

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
        sh = (b >> 22) & 1
        imm = (b >> 10) & 0xFFF
        if sh: imm <<= 12
        return "add w%d, w%d, #0x%X" % (b & 0x1F, (b >> 5) & 0x1F, imm)
    if (b & 0x7F800000) == 0x91000000:
        sh = (b >> 22) & 1
        imm = (b >> 10) & 0xFFF
        if sh: imm <<= 12
        return "add x%d, x%d, #0x%X" % (b & 0x1F, (b >> 5) & 0x1F, imm)
    if (b & 0x7F800000) == 0x51000000:
        sh = (b >> 22) & 1
        imm = (b >> 10) & 0xFFF
        if sh: imm <<= 12
        return "sub w%d, w%d, #0x%X" % (b & 0x1F, (b >> 5) & 0x1F, imm)
    if (b & 0x7F800000) == 0xD1000000:
        sh = (b >> 22) & 1
        imm = (b >> 10) & 0xFFF
        if sh: imm <<= 12
        return "sub x%d, x%d, #0x%X" % (b & 0x1F, (b >> 5) & 0x1F, imm)

    if (b & 0x7FE00000) == 0x0B000000: return "add w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x8B000000: return "add x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x4B000000: return "sub w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0xCB000000: return "sub x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x2A000000: return "orr w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0xAA000000: return "orr x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x0A000000: return "and w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x8A000000: return "and x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x4A000000: return "eor w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0xCA000000: return "eor x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x6B000000: return "subs w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0xEB000000: return "subs x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)

    if (b & 0x7FE0FC00) == 0x1AC02000: return "lsl w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE0FC00) == 0x9AC02000: return "lsl x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)

    if (b & 0x7F800000) == 0x53000000:
        return "ubfm w%d, w%d, #%d, #%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x3F, (b >> 10) & 0x3F)
    if (b & 0x7F800000) == 0xD3000000:
        return "ubfm x%d, x%d, #%d, #%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x3F, (b >> 10) & 0x3F)

    if (b & 0x9F000000) == 0x90000000:
        immlo = (b >> 29) & 3
        immhi = (b >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & 0x100000: imm -= 0x200000
        page = (pc & ~0xFFF) + (imm << 12)
        return "adrp x%d, 0x%016X" % (b & 0x1F, page & 0xFFFFFFFFFFFFFFFF)
    if (b & 0x9F000000) == 0x10000000:
        immlo = (b >> 29) & 3
        immhi = (b >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & 0x100000: imm -= 0x200000
        return "adr x%d, 0x%016X" % (b & 0x1F, (pc + imm) & 0xFFFFFFFFFFFFFFFF)

    if (b & 0x7C000000) == 0x14000000:
        off = b & 0x03FFFFFF
        if off & 0x02000000: off -= 0x04000000
        return "b #0x%X (-> 0x%016X)" % (off * 4, (pc + off * 4) & 0xFFFFFFFFFFFFFFFF)
    if (b & 0x7C000000) == 0x94000000:
        off = b & 0x03FFFFFF
        if off & 0x02000000: off -= 0x04000000
        return "bl #0x%X (-> 0x%016X)" % (off * 4, (pc + off * 4) & 0xFFFFFFFFFFFFFFFF)

    if (b & 0xFF000010) == 0x54000000:
        off = (b >> 5) & 0x7FFFF
        if off & 0x40000: off -= 0x80000
        names = ["eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
                 "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"]
        return "b.%s #0x%X" % (names[b & 0xF], off * 4)

    if (b & 0x7E000000) == 0x34000000:
        off = (b >> 5) & 0x7FFFF
        if off & 0x40000: off -= 0x80000
        return "cbz w%d, #0x%X" % (b & 0x1F, off * 4)
    if (b & 0x7E000000) == 0x35000000:
        off = (b >> 5) & 0x7FFFF
        if off & 0x40000: off -= 0x80000
        return "cbnz w%d, #0x%X" % (b & 0x1F, off * 4)
    if (b & 0x7E000000) == 0xB4000000:
        off = (b >> 5) & 0x7FFFF
        if off & 0x40000: off -= 0x80000
        return "cbz x%d, #0x%X" % (b & 0x1F, off * 4)
    if (b & 0x7E000000) == 0xB5000000:
        off = (b >> 5) & 0x7FFFF
        if off & 0x40000: off -= 0x80000
        return "cbnz x%d, #0x%X" % (b & 0x1F, off * 4)

    if (b & 0x7F800000) == 0x71000000:
        return "cmp w%d, #0x%X" % ((b >> 5) & 0x1F, (b >> 10) & 0xFFF)
    if (b & 0x7F800000) == 0xF1000000:
        return "cmp x%d, #0x%X" % ((b >> 5) & 0x1F, (b >> 10) & 0xFFF)

    if (b & 0x7FE00C00) == 0x1A800000:
        return "csel w%d, w%d, w%d, #%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F, b & 0xF)
    if (b & 0x7FE00C00) == 0x9A800000:
        return "csel x%d, x%d, x%d, #%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F, b & 0xF)

    return "?? (0x%08X)" % b


def dis_raw(addr, count):
    if addr is None:
        return ["(addr is None)"]
    blk = inblk(addr)
    if blk is None:
        return ["(addr %s NOT IN ANY LOADED BLOCK)" % fmt(addr)]
    ga = sa(addr)
    if ga is None:
        return ["(cannot toAddr %s)" % fmt(addr)]
    mem = currentProgram.getMemory()
    try:
        _ = mem.getInt(ga) & 0xFFFFFFFF
    except Exception as e:
        return ["(read err at %s: %s)" % (fmt(addr), str(e))]
    out = []
    i = 0
    while i < count:
        a = addr + i * 4
        gaa = sa(a)
        if gaa is None:
            break
        try:
            b = mem.getInt(gaa) & 0xFFFFFFFF
        except Exception:
            break
        out.append("%016X  %08X  %s" % (a, b, decode_one(b, a)))
        i += 1
    if not out:
        out.append("(no readable code at %s)" % fmt(addr))
    return out


def find_target():
    for n in TARGET_NAMES:
        a = sget(n)
        if a is not None and is_ktext(a):
            return a, n
    if inblk(TARGET_HINT):
        return TARGET_HINT, "(hardcoded 0x%X)" % TARGET_HINT
    return None, None


def parse_instr(line):
    m = re.match(r"([0-9A-F]{16})\s+([0-9A-F]{8})\s+(.*)", line)
    if not m:
        return None
    pc = int(m.group(1), 16)
    body = m.group(3)
    mn = body.split(" ", 1)[0].lower()
    return pc, mn, body


def extract_mem_imm(body):
    """Return (base_reg, imm) from [xN, #imm] or [xN], else None."""
    m = re.search(r"\[(x\d+|sp|x31),\s*#(0x[0-9A-Fa-f]+|-?\d+)\]", body)
    if not m:
        return None
    base = m.group(1)
    try:
        imm = int(m.group(2), 0)
    except Exception:
        return None
    if imm < 0:
        imm += 0x1000
    return base, imm


def extract_call_target(body):
    m = re.search(r"->\s*0x([0-9A-F]+)", body)
    if not m:
        return None
    try:
        return int(m.group(1), 16)
    except Exception:
        return None


def analyze(a, name):
    lines = []
    lines.append("================================================================")
    lines.append("TARGET: %s @ %s" % (name, fmt(a)))
    blk = inblk(a)
    lines.append("BLOCK:  %s" % (blk[2] if blk else "NOT_FOUND"))
    lines.append("================================================================")
    lines.append("")

    dis = dis_raw(a, MAX_DISASM)
    if not dis or dis[0].startswith("("):
        lines.append("NO DISASM: %s" % (dis[0] if dis else "(empty)"))
        return lines, {}

    # ---- 1. full disasm ----
    lines.append("---- 1. FULL DISASM (%d instrs) ----" % len(dis))
    for l in dis:
        nm = ""
        pc, mn, body = parse_instr(l)
        if mn in ("b", "bl"):
            t = extract_call_target(body)
            if t is not None and is_ktext(t):
                tn = name_at(t)
                if tn:
                    nm = "    ; => " + tn
        lines.append("  " + l + nm)
    lines.append("")

    # ---- 2. all memory accesses ----
    ldr_map = {}   # (base, imm) -> [(pc, body)]
    str_map = {}
    other_mem = {}
    call_targets = []

    for l in dis:
        r = parse_instr(l)
        if not r:
            continue
        pc, mn, body = r

        if mn in ("ldr", "ldrb", "ldrh", "ldur", "ldar", "ldaxr",
                  "ldpsw", "ldursb", "ldursh", "ldursw"):
            e = extract_mem_imm(body)
            if e:
                ldr_map.setdefault(e, []).append((pc, body))
        elif mn in ("str", "strb", "strh", "stur", "stlr", "stlxr"):
            e = extract_mem_imm(body)
            if e:
                str_map.setdefault(e, []).append((pc, body))
        elif mn in ("ldp", "stp") or mn.startswith("ld") or mn.startswith("st"):
            e = extract_mem_imm(body)
            if e:
                other_mem.setdefault(e, []).append((pc, body))

        if mn in ("b", "bl"):
            t = extract_call_target(body)
            if t is not None:
                call_targets.append((pc, mn, t))

    lines.append("---- 2. LDR [base, #imm] (sorted by offset) ----")
    for (base, imm), entries in sorted(ldr_map.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        lines.append("  [%s, #0x%X]  hits=%d" % (base, imm, len(entries)))
        for pc, body in entries[:4]:
            lines.append("      %016X  %s" % (pc, body))
    lines.append("")

    lines.append("---- 2b. STR [base, #imm] ----")
    for (base, imm), entries in sorted(str_map.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        lines.append("  [%s, #0x%X]  hits=%d" % (base, imm, len(entries)))
        for pc, body in entries[:4]:
            lines.append("      %016X  %s" % (pc, body))
    lines.append("")

    if other_mem:
        lines.append("---- 2c. OTHER MEM (ldp/stp/etc) ----")
        for (base, imm), entries in sorted(other_mem.items(), key=lambda kv: (kv[0][1], kv[0][0])):
            lines.append("  [%s, #0x%X]  hits=%d" % (base, imm, len(entries)))
            for pc, body in entries[:3]:
                lines.append("      %016X  %s" % (pc, body))
        lines.append("")

    # ---- 3. call targets with names ----
    lines.append("---- 3. CALL TARGETS (b/bl) ----")
    seen = set()
    unique_calls = []
    for pc, mn, t in call_targets:
        if t in seen:
            continue
        seen.add(t)
        unique_calls.append((mn, t))
    for mn, t in unique_calls:
        nm = name_at(t) or "?"
        blk2 = inblk(t)
        loc = blk2[2] if blk2 else "OUT_OF_BLOCK"
        lines.append("  %s -> %s  [%s]  (%s)" % (mn, fmt(t), nm, loc))
    lines.append("")

    # ---- 4. callee brief disasm ----
    lines.append("---- 4. CALLEES (brief disasm, top %d) ----" % len(unique_calls))
    for _, t in unique_calls:
        if not is_ktext(t):
            continue
        nm = name_at(t) or "?"
        lines.append("")
        lines.append("  --- %s @ %s ---" % (nm, fmt(t)))
        for l in dis_raw(t, MAX_CALLEE):
            lines.append("      " + l)
    lines.append("")

    # ---- 5. CANDIDATE NCF_ASSIGNED_OFF ----
    # flow struct likely held in callee-saved regs after prologue.
    # In necp_client_add_flow earlier we saw ldr x19, [x1, #0x28] — X19=flow list head.
    # So for copy_result, we look for x19-x24 as flow base.
    flow_regs = ("x19", "x20", "x21", "x22", "x23", "x24")

    lines.append("---- 5. FLOW-STRUCT-LIKE OFFSETS (base in x19..x24, imm in 0x40..0x300) ----")
    candidates = []
    for (base, imm), entries in sorted(ldr_map.items(), key=lambda kv: kv[0][1]):
        if base in flow_regs and 0x40 <= imm <= 0x300:
            lines.append("  [%s, #0x%X] hits=%d" % (base, imm, len(entries)))
            for pc, body in entries:
                lines.append("      %016X  %s" % (pc, body))
            candidates.append((base, imm))

    lines.append("")
    lines.append("---- 5b. LDR [x?, #0x??] on ANY base, imm in 0x40..0x200, sorted unique ----")
    seen_offs = set()
    for (base, imm), entries in sorted(ldr_map.items(), key=lambda kv: kv[0][1]):
        if 0x40 <= imm <= 0x200 and imm not in seen_offs:
            seen_offs.add(imm)
            lines.append("  +0x%03X  bases=%s  hits=%d" % (
                imm, ",".join(sorted(set(b for b, _ in entries))), len(entries)))
    lines.append("")

    # ---- 6. VERDICT ----
    lines.append("---- 6. VERDICT ----")
    if candidates:
        lines.append("  flow-struct-like offsets found on x19..x24:")
        for base, imm in candidates:
            lines.append("    +0x%X  (base=%s)" % (imm, base))
        lines.append("")
        lines.append("  HINT: first LDR on flow reg (typically right after prologue)")
        lines.append("        that loads a POINTER (dst is xN) is probably assigned_results.")
        lines.append("        Next LDR with same base at +8 is assigned_results_len.")
        # print first few flow-reg LDRs in pc order
        seq = []
        for (base, imm), entries in ldr_map.items():
            if base in flow_regs and 0x40 <= imm <= 0x300:
                for pc, body in entries:
                    seq.append((pc, base, imm, body))
        seq.sort()
        lines.append("")
        lines.append("  flow-reg LDRs in PC order:")
        for pc, base, imm, body in seq[:12]:
            lines.append("      %016X  %s" % (pc, body))
    else:
        lines.append("  NO flow-reg LDRs found. Function likely does NOT")
        lines.append("  read flow->assigned_results (result comes from elsewhere).")

    jout = {
        "target_addr": fmt(a),
        "target_name": name,
        "flow_candidates": ["%s+0x%X" % (b, i) for b, i in candidates],
        "all_ldr_offsets": sorted(set(i for _, i in ldr_map.keys())),
        "all_str_offsets": sorted(set(i for _, i in str_map.keys())),
        "call_targets": [fmt(t) for _, t in unique_calls],
    }
    return lines, jout


def main():
    print("=== necp_client_copy_result focused analysis ===")
    _load_sym()
    _build_idx()
    sym_count = len([k for k in (_sym or {}).keys() if not k.startswith("__")])
    diag = (_sym or {}).get("__diag__", "(no diag)")
    print("[+] sym=%d diag=%s" % (sym_count, diag))

    a, nm = find_target()
    if a is None:
        lines = [
            "TARGET NOT FOUND",
            "tried: " + ", ".join(TARGET_NAMES),
            "hint: " + fmt(TARGET_HINT),
        ]
        jout = {}
    else:
        lines, jout = analyze(a, nm)

    header = [
        "=== SYMBOLS DIAG ===",
        diag,
        "sym_count = %d" % sym_count,
        "workspace = %s" % WS,
        "symbols_json = %s" % SYM,
        "",
    ]
    final = header + lines

    try:
        with open(OUT, "w") as fh:
            for l in final:
                fh.write(l + "\n")
        print("[+] wrote " + OUT)
    except Exception as e:
        print("[-] write: " + str(e))

    try:
        with open(OUT_JSON, "w") as fh:
            fh.write(json.dumps(jout, indent=2, sort_keys=True))
        print("[+] wrote " + OUT_JSON)
    except Exception as e:
        print("[-] write json: " + str(e))

    print("=== DONE ===")


try:
    main()
except Exception as e:
    print("[-] FATAL: " + str(e))
    traceback.print_exc()
    try:
        with open(OUT, "w") as fh:
            fh.write("FATAL: " + str(e) + "\n")
    except Exception:
        pass