# -*- coding: utf-8 -*-
# @runtime Jython
# necp_full_dump.py — dump everything for NECP-kread

import os
import re
import json
import traceback

from jarray import zeros
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.util.task import TaskMonitor

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WS, "result.txt")

HARDCODED = [
    ("necp_client_copy_result", 0xFFFFFFF00A4EAC7C),
    ("necp_client_add_flow",    0xFFFFFFF00A4E843C),
    ("necp_client_remove_flow", 0xFFFFFFF00A4E93C4),
    ("necp_open",               0xFFFFFFF00A4E411C),
    ("necp_client_find_flow",   0x0),
]

BY_NAME = [
    "necp_client_copy_result",
    "necp_client_add_flow",
    "necp_client_remove_flow",
    "necp_client_find_flow",
    "necp_client_find_eligible_flow",
    "necp_client_copy_result_common",
    "necp_client_flow_alloc",
    "necp_flow_alloc",
    "necp_open",
    "necp_client_action",
    "necp_get_tlv",
    "necp_get_tlv_at_offset",
    "necp_set_tlv_at_offset",
    "ipc_kmsg_alloc",
    "ipc_kmsg_zone_init",
    "ipc_kmsg_destroy",
    "soalloc",
    "socreate",
    "socket_alloc",
    "mbuf_alloc",
    "mbuf_zone_init",
    "kalloc",
    "kalloc_ext",
    "kalloc_canblock",
    "kalloc_type",
    "zalloc",
    "zalloc_canblock",
    "zone_create",
    "zone_alloc_item",
    "task_zone_init",
    "proc_zone_init",
    "thread_zone_init",
    "ipc_port_alloc",
    "ipc_entry_alloc",
    "copyout",
    "copyin",
    "os_ref_release",
    "os_ref_retain",
    "proc_ucred",
    "kauth_cred_getuid",
]

STRING_KEYWORDS = [
    "ipc_kmsg",
    "necp_client",
    "necp_flow",
    "kalloc_type",
    "zone_create",
    "zone_init",
    "socket_zone",
    "mbuf_zone",
    "necp_tlv",
    "copy result",
    "copyout error",
    "necp_client_flow",
    "invalid client id",
    "assigned results",
    "assigned_results",
]

# immediate values that look like allocation sizes
SIZE_RANGE_LO = 64
SIZE_RANGE_HI = 16384

MAX_DISASM = 400
MAX_DECOMP = 400


def _u(v): return int(v) & 0xFFFFFFFFFFFFFFFF


def fmt(v):
    if v is None: return "0x0"
    try: return "0x%016X" % (int(v) & 0xFFFFFFFFFFFFFFFF)
    except: return "0x0"


def sa(a):
    if a is None: return None
    try: return currentProgram.getAddressFactory().getAddress("%X" % (int(a) & 0xFFFFFFFFFFFFFFFF))
    except: return None


def inblk(a):
    try:
        ga = sa(a)
        if ga is None: return None
        b = currentProgram.getMemory().getBlock(ga)
        if b is None: return None
        return (str(b.getName()), bool(b.isExecute()))
    except: return None


def find_func_by_name(name):
    try:
        fm = currentProgram.getFunctionManager()
        for f in fm.getFunctions(True):
            try:
                if str(f.getName()) == name: return f
            except: pass
        for f in fm.getFunctions(True):
            try:
                if name in str(f.getName()): return f
            except: pass
    except: pass
    return None


def find_func_by_addr(addr):
    try:
        ga = sa(addr)
        if ga is None: return None
        f = getFunctionAt(ga)
        if f is not None: return f
        return getFunctionContaining(ga)
    except: return None


def funcs_calling(f):
    out = []
    try:
        for ref in getReferencesTo(f.getEntryPoint()):
            try:
                c = getFunctionContaining(ref.getFromAddress())
                if c is None: continue
                if _u(c.getEntryPoint().getOffset()) == _u(f.getEntryPoint().getOffset()):
                    continue
                nm = str(c.getName())
                if nm not in out: out.append(nm)
            except: pass
    except: pass
    return out


def func_size(f):
    try:
        body = f.getBody()
        if body is None: return 0
        return int(body.getNumAddresses())
    except: return 0


def dec(b, pc):
    if b == 0xD503237F: return "pacibsp"
    if b == 0xD50323FF: return "autibsp"
    if b == 0xD503233F: return "paciasp"
    if b == 0xD50323BF: return "autiasp"
    if b == 0xD5033BBF: return "autiasp"
    if b == 0xD65F03C0: return "ret"
    if b == 0xD503201F: return "nop"
    if b == 0xD65F0FFF: return "ret"
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
    if (b & 0x9F000000) == 0x90000000:
        il = (b >> 29) & 3; ih = (b >> 5) & 0x7FFFF
        i = (ih << 2) | il
        if i & 0x100000: i -= 0x200000
        return "adrp x%d, 0x%016X" % (b & 0x1F, ((pc & ~0xFFF) + (i << 12)) & 0xFFFFFFFFFFFFFFFF)
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
    if (b & 0x7FE00000) == 0x0B000000: return "add w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x8B000000: return "add x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x4B000000: return "sub w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0xCB000000: return "sub x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x2A000000: return "orr w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0xAA000000: return "orr x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x6B000000: return "subs w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0xEB000000: return "subs x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7F800000) == 0x71000000: return "cmp w%d, #0x%X" % ((b >> 5) & 0x1F, (b >> 10) & 0xFFF)
    if (b & 0x7F800000) == 0xF1000000: return "cmp x%d, #0x%X" % ((b >> 5) & 0x1F, (b >> 10) & 0xFFF)
    if (b & 0x7FE00C00) == 0x1A800000: return "csel w%d, w%d, w%d, #%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F, b & 0xF)
    if (b & 0x7FE00C00) == 0x9A800000: return "csel x%d, x%d, x%d, #%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F, b & 0xF)
    return "?? (0x%08X)" % b


def disasm(f, maxn):
    out = []
    body = f.getBody()
    if body is None: return out
    try:
        it = body.getAddresses(True)
    except Exception:
        return out
    cnt = 0
    while it.hasNext() and cnt < maxn:
        a = it.next()
        try:
            pc = _u(a.getOffset())
            b = int(currentProgram.getMemory().getInt(a)) & 0xFFFFFFFF
            out.append("  %016X  %08X  %s" % (pc, b, dec(b, pc)))
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
            out.append("(no result)")
            return out
        if not r.decompileCompleted():
            out.append("(failed: %s)" % str(r.getErrorMessage()))
            return out
        c = r.getDecompiledFunction()
        if c is None:
            out.append("(empty)")
            return out
        txt = c.getC()
        for line in txt.split("\n"):
            out.append("  " + line.rstrip())
    except Exception as e:
        out.append("(decompile exception: %s)" % str(e))
    return out


def jbytes(s):
    jb = zeros(len(s), 'b')
    for i in range(len(s)):
        v = ord(s[i])
        if v > 127: v -= 256
        jb[i] = v
    return jb


def all_strings():
    strings = []
    try:
        for b in currentProgram.getMemory().getBlocks():
            nm = str(b.getName())
            low = nm.lower()
            if "cstring" not in low and "os_log" not in low and "__const" not in low:
                continue
            if not b.isInitialized():
                continue
            s = _u(b.getStart().getOffset())
            e = _u(b.getEnd().getOffset())
            sz = e - s
            if sz <= 0 or sz > 16 * 1024 * 1024:
                continue
            ga = sa(s)
            arr = zeros(sz, 'b')
            try:
                currentProgram.getMemory().getBytes(ga, arr)
            except Exception:
                continue
            cur = ""
            cur_off = s
            for i in range(sz):
                v = int(arr[i])
                if v < 0: v += 256
                if 0x20 <= v < 0x7F:
                    if not cur:
                        cur_off = s + i
                    cur += chr(v)
                else:
                    if len(cur) >= 6:
                        strings.append((cur_off, cur))
                    cur = ""
            if len(cur) >= 6:
                strings.append((cur_off, cur))
    except Exception:
        pass
    return strings


def find_string_hits(kw, strings, cap=40):
    out = []
    for a, s in strings:
        if kw in s:
            blk = inblk(a)
            out.append((a, s, blk[0] if blk else "?"))
            if len(out) >= cap:
                break
    return out


def xrefs_to(a, cap=64):
    out = []
    try:
        ga = sa(a)
        if ga is None: return out
        for ref in getReferencesTo(ga):
            try:
                out.append(_u(ref.getFromAddress().getOffset()))
                if len(out) >= cap: break
            except: pass
    except: pass
    return out


def preceding_mov_imms(addr, maxback=24):
    out = []
    try:
        listing = currentProgram.getListing()
        a = sa(addr)
        if a is None: return out
        ins = listing.getInstructionAt(a)
        if ins is None: ins = listing.getInstructionContaining(a)
        if ins is None: return out
        cur = ins.getPrevious()
        i = 0
        while cur is not None and i < maxback:
            try:
                mnem = str(cur.getMnemonicString()).lower()
                if mnem.startswith("mov"):
                    n_ops = int(cur.getNumOperands())
                    ops = []
                    for k in range(n_ops):
                        ops.append(str(cur.getDefaultOperandRepresentation(k)))
                    out.append((_u(cur.getAddress().getOffset()), mnem, ops))
            except Exception:
                pass
            cur = cur.getPrevious()
            i += 1
    except Exception:
        pass
    out.reverse()
    return out


def callers_with_imm(f):
    """Return list of (caller_name, call_addr, preceding_movs)."""
    out = []
    try:
        for ref in getReferencesTo(f.getEntryPoint()):
            try:
                ra = _u(ref.getFromAddress().getOffset())
                caller = getFunctionContaining(ref.getFromAddress())
                cn = str(caller.getName()) if caller else "?"
                imms = preceding_mov_imms(ra, 20)
                out.append((cn, ra, imms))
            except Exception:
                pass
    except Exception:
        pass
    return out


def extract_size_from_movs(movs):
    """Heuristic: find last w0/x0/x1 movz/mov with imm in SIZE_RANGE."""
    cand = []
    for addr, mnem, ops in movs:
        if not ops: continue
        reg = ops[0] if len(ops) > 0 else ""
        val = ops[1] if len(ops) > 1 else ""
        m = re.search(r"#0x([0-9A-Fa-f]+)", val)
        if not m:
            m = re.search(r"#(\d+)", val)
        if not m:
            continue
        try:
            v = int(m.group(1), 0) if not m.group(1).isdigit() or "0x" in val.lower() else int(m.group(1))
        except Exception:
            try:
                v = int(m.group(1), 0)
            except Exception:
                continue
        if SIZE_RANGE_LO <= v <= SIZE_RANGE_HI:
            cand.append((addr, reg, v, mnem))
    return cand


def main():
    print("=== necp_full_dump ===")
    lines = []

    lines.append("=== PROGRAM ===")
    try:
        lines.append("name     = %s" % currentProgram.getName())
        lines.append("language = %s" % currentProgram.getLanguage().getLanguageID())
        lines.append("min      = %s" % fmt(currentProgram.getMemory().getMinAddress().getOffset()))
        lines.append("max      = %s" % fmt(currentProgram.getMemory().getMaxAddress().getOffset()))
    except Exception as e:
        lines.append("(err: %s)" % str(e))
    lines.append("")

    lines.append("=== BLOCKS ===")
    try:
        for b in currentProgram.getMemory().getBlocks():
            try:
                nm = str(b.getName())
                s = _u(b.getStart().getOffset())
                e = _u(b.getEnd().getOffset())
                ex = bool(b.isExecute())
                init = bool(b.isInitialized())
                lines.append("  %-32s 0x%08X  init=%d exec=%d  %s..%s" % (
                    nm, int(e - s), init, ex, fmt(s), fmt(e)))
            except Exception:
                pass
    except Exception as e:
        lines.append("(err: %s)" % str(e))
    lines.append("")

    print("[+] collecting strings...")
    strings = all_strings()
    lines.append("=== STRING COUNT = %d ===" % len(strings))
    lines.append("")

    print("[+] strings by keyword...")
    lines.append("=== STRINGS BY KEYWORD ===")
    for kw in STRING_KEYWORDS:
        hits = find_string_hits(kw, strings, cap=20)
        lines.append("--- '%s'  (%d hits) ---" % (kw, len(hits)))
        for a, s, blk in hits:
            lines.append("  %s  [%s]  %s" % (fmt(a), blk, s[:140]))
        lines.append("")

    print("[+] functions by name...")
    lines.append("=== FUNCTIONS BY NAME ===")
    for name in BY_NAME:
        f = find_func_by_name(name)
        if f is None:
            lines.append("--- %s --- NOT FOUND" % name)
            continue
        entry = _u(f.getEntryPoint().getOffset())
        sz = func_size(f)
        blk = inblk(entry)
        lines.append("--- %s @ %s  size=0x%X  [%s] ---" % (
            str(f.getName()), fmt(entry), sz, blk[0] if blk else "?"))
        callers = funcs_calling(f)
        lines.append("  callers(%d): %s" % (len(callers), ", ".join(callers[:20])))
        lines.append("")

    print("[+] functions by addr...")
    lines.append("=== FUNCTIONS BY ADDR ===")
    for name, addr in HARDCODED:
        if addr == 0: continue
        f = find_func_by_addr(addr)
        if f is None:
            lines.append("--- %s @ %s --- NO FUNCTION" % (name, fmt(addr)))
            continue
        entry = _u(f.getEntryPoint().getOffset())
        sz = func_size(f)
        blk = inblk(entry)
        lines.append("--- %s @ %s  size=0x%X  [%s] ---" % (
            str(f.getName()), fmt(entry), sz, blk[0] if blk else "?"))
        callers = funcs_calling(f)
        lines.append("  callers(%d): %s" % (len(callers), ", ".join(callers[:20])))
        lines.append("")

    print("[+] disasm hardcoded...")
    lines.append("=== DISASM (hardcoded) ===")
    for name, addr in HARDCODED:
        if addr == 0: continue
        f = find_func_by_addr(addr)
        if f is None: continue
        lines.append("--- %s ---" % name)
        for l in disasm(f, MAX_DISASM):
            lines.append(l)
        lines.append("")

    print("[+] decompile hardcoded...")
    lines.append("=== DECOMPILE (hardcoded) ===")
    for name, addr in HARDCODED:
        if addr == 0: continue
        f = find_func_by_addr(addr)
        if f is None: continue
        lines.append("--- %s @ %s ---" % (name, fmt(_u(f.getEntryPoint().getOffset()))))
        for l in decompile(f, 120):
            lines.append(l)
        lines.append("")

    print("[+] kalloc callers with sizes...")
    lines.append("=== KALLOC CALLERS WITH SIZES ===")
    for fn in ("kalloc", "kalloc_ext", "kalloc_canblock", "kalloc_type",
               "zalloc", "zalloc_canblock", "zone_alloc_item"):
        f = find_func_by_name(fn)
        if f is None: continue
        lines.append("--- %s @ %s ---" % (fn, fmt(_u(f.getEntryPoint().getOffset()))))
        cs = callers_with_imm(f)
        lines.append("  total callers: %d" % len(cs))
        for cn, ra, movs in cs[:80]:
            sizes = extract_size_from_movs(movs)
            lines.append("    %s @ %s" % (cn, fmt(ra)))
            for a, reg, v, mn in sizes:
                lines.append("        %s  %s %s, #0x%X" % (fmt(a), mn, reg, v))
        lines.append("")

    print("[+] writing...")
    try:
        with open(OUT, "w") as fh:
            for l in lines:
                fh.write(l + "\n")
        print("[+] wrote " + OUT)
    except Exception as e:
        print("[-] write: " + str(e))
    print("=== DONE ===")


try:
    main()
except Exception as e:
    print("[-] FATAL: " + str(e))
    traceback.print_exc()
    try:
        with open(OUT, "a") as fh:
            fh.write("FATAL: " + str(e) + "\n")
            fh.write(traceback.format_exc())
    except Exception:
        pass