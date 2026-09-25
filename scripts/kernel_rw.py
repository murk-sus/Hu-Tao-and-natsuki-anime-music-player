# -*- coding: utf-8 -*-
# @runtime Jython

import os
import re
import json
import traceback

try:
    _STR_TYPES = (str, unicode)
except NameError:
    _STR_TYPES = (str,)

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
SYM = os.environ.get("SYMBOLS_JSON", os.path.join(WS, "symbols.json"))
KEXTS = os.environ.get("KEXTS_DIR", os.path.join(WS, "kexts"))
OUT = os.path.join(WS, "result.txt")
OUT_JSON = os.path.join(WS, "offsets.json")

KBASE = 0xFFFFFFF007004000
MASK48 = 0x0000FFFFFFFFFFFF
KTEXT_LO = 0xFFF007004000
KTEXT_HI = 0xFFF200000000

_sym = None
_symidx = None
_blocks = None
_text_range = [None, None]
_offsets_repo = None

BAD_PREFIX = ("s_", "str_", "a_", "unk_", "DAT_", "LAB_", "PTR_", "off_", "d_")

FALLBACK_24A437 = {}
FALLBACK_24A437["proc_p_ucred_off"] = 0x84
FALLBACK_24A437["ucred_cr_uid_off"] = 0xC
FALLBACK_24A437["ucred_cr_svuid_off"] = 0x14
FALLBACK_24A437["NCF_ASSIGNED_OFF"] = 0x68
FALLBACK_24A437["NCF_STRUCT_SZ"] = 0x100

TARGETS = []
TARGETS.append(("proc_ucred", ["_proc_ucred", "proc_ucred"]))
TARGETS.append(("kauth_cred_getuid", ["_kauth_cred_getuid", "kauth_cred_getuid"]))
TARGETS.append(("kauth_cred_getsvuid", ["_kauth_cred_getsvuid", "kauth_cred_getsvuid"]))
TARGETS.append(("necp_client_add_flow", ["_necp_client_add_flow", "necp_client_add_flow"]))
TARGETS.append(("necp_flow_alloc", ["_necp_flow_alloc", "necp_flow_alloc"]))
TARGETS.append(("necp_open", ["_necp_open", "necp_open"]))
TARGETS.append(("amfi_get_out_of_my_way", ["_amfi_get_out_of_my_way", "amfi_get_out_of_my_way"]))

VALIDATE_GROUPS = [
    ("Kernel", [
        ("off_kernel_base", "addr", 0xFFFFFFF007004000),
        ("off_sysent_base", "addr", None),
        ("off_sysent_count", "int", 558),
        ("off_sysent_stride", "int", 24),
        ("off_mach_trap_table", "addr", 0xFFFFFFF007BE8018),
    ]),
    ("Globals", [
        ("off_g_kernproc", "addr", 0xFFFFFFF007BBF040),
        ("off_g_kernel_task", "addr", 0xFFFFFFF00700DC70),
        ("off_g_zone_map", "addr", 0xFFFFFFF00AD6A800),
        ("off_g_task_list", "addr", 0xFFFFFFF0080D93F0),
        ("off_g_kernel_map", "addr", 0xFFFFFFF007BBE228),
        ("off_g_allproc", "addr", 0xFFFFFFF007BBF048),
    ]),
    ("Primitives", [
        ("off_fn_copyin", "addr", 0xFFFFFFF00A7B9570),
        ("off_fn_copyout", "addr", 0xFFFFFFF00A2C6C28),
        ("off_fn_kalloc_ext", "addr", 0xFFFFFFF00A200DCC),
        ("off_fn_kfree_ext", "addr", 0xFFFFFFF00A201000),
    ]),
    ("proc", [
        ("off_proc_p_pid", "int", 0x74),
        ("off_proc_ro_p_ucred", "int", 0xB8),
    ]),
    ("task / thread", [
        ("off_task_map", "int", 0x28),
        ("off_task_bsd_info", "int", 0x3A0),
        ("off_task_itk_space", "int", 0x320),
        ("off_thread_task_threads_next", "int", 0x50),
    ]),
    ("NECP", [
        ("off_necp_open", "addr", 0xFFFFFFF00A4E411C),
        ("off_necp_client_add_flow", "addr", 0xFFFFFFF00A4E843C),
        ("off_necp_client_remove_flow", "addr", 0xFFFFFFF00A4E93C4),
    ]),
    ("Zones", [
        ("off_zone_data_kalloc", "addr", 0xFFFFFFF007C62E70),
        ("off_zone_early_kalloc", "addr", 0xFFFFFFF007BBB170),
        ("off_zone_kalloc_type_var", "addr", 0xFFFFFFF007BC2800),
        ("off_zone_site_struct_task", "addr", 0xFFFFFFF007C64080),
        ("off_zone_site_struct_proc", "addr", 0xFFFFFFF007C71240),
        ("off_zone_site_struct_thread", "addr", 0xFFFFFFF007C63D00),
        ("off_zone_site_struct_ucred", "addr", 0xFFFFFFF007C6F140),
        ("off_zone_site_struct_ipc_port", "addr", 0xFFFFFFF007C79248),
        ("off_zone_site_struct_ipc_entry", "addr", 0xFFFFFFF007C79298),
        ("off_zone_site_struct_fileproc", "addr", 0xFFFFFFF007C7CD08),
        ("off_zone_site_struct_fileglob", "addr", 0xFFFFFFF007C7D708),
        ("off_zone_site_struct_vnode", "addr", 0xFFFFFFF007C660C0),
        ("off_zone_site_struct_mount", "addr", 0xFFFFFFF007C662C0),
        ("off_zone_site_struct_socket", "addr", 0xFFFFFFF007C70C40),
        ("off_zone_site_struct_inpcb", "addr", 0xFFFFFFF007C6D180),
        ("off_zone_site_struct_pipe", "addr", 0xFFFFFFF007C6FE80),
        ("off_zone_site_struct_vm_page", "addr", 0xFFFFFFF007C64C80),
    ]),
]


def _u(v):
    return int(v) & 0xFFFFFFFFFFFFFFFF


def fmt(v):
    if v is None:
        return "0x0"
    try:
        return "0x" + ("%016X" % (int(v) & 0xFFFFFFFFFFFFFFFF))
    except Exception:
        return "0x0"


def sa(a):
    if a is None:
        return None
    try:
        v = int(a) & 0xFFFFFFFFFFFFFFFF
        hexstr = "%X" % v
        factory = currentProgram.getAddressFactory()
        return factory.getAddress(hexstr)
    except Exception:
        return None


def r32(a):
    if a is None:
        return None
    ga = sa(a)
    if ga is None:
        return None
    try:
        return int(currentProgram.getMemory().getInt(ga)) & 0xFFFFFFFF
    except Exception:
        return None


def r64(a):
    if a is None:
        return None
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


def text_range():
    if _text_range[0] is not None:
        return _text_range[0], _text_range[1]
    lo = None
    hi = None
    for s, e, n, x in blocks():
        if "__text" in n and x:
            lo = s
            hi = e
            break
    if lo is None:
        for s, e, n, x in blocks():
            if x:
                lo = s if lo is None else min(lo, s)
                hi = e if hi is None else max(hi, e)
    _text_range[0] = lo
    _text_range[1] = hi
    return lo, hi


def is_ktext(p):
    if p is None or p == 0:
        return False
    lo = p & MASK48
    return KTEXT_LO <= lo < KTEXT_HI


def inblk(a):
    if a is None:
        return None
    for s, e, n, x in blocks():
        if s <= a < e:
            return (s, e, n, x)
    return None


def _add_sym(name, addr):
    if not name or addr is None:
        return
    try:
        if not isinstance(name, _STR_TYPES):
            name = str(name)
        name = name.strip()
        if not name:
            return
        addr = _u(int(addr))
        if addr < 0xFFFF000000000000:
            return
        _sym[name] = addr
        if not name.startswith("_"):
            _sym["_" + name] = addr
        else:
            _sym[name[1:]] = addr
    except Exception:
        pass


def _load_sym():
    global _sym
    if _sym is not None:
        return
    _sym = {}
    _sym["__diag__"] = "init"

    if not os.path.exists(SYM):
        _sym["__diag__"] = "NOT FOUND " + SYM
        return

    try:
        fh = open(SYM)
        raw = fh.read()
        fh.close()
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
        _sym["__diag__"] = "json err: " + str(e) + " size=" + str(size)
        return

    added = 0

    if isinstance(data, dict):
        for k, v in data.items():
            if not isinstance(v, _STR_TYPES):
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
        def _walk2(node, depth=0):
            if depth > 6:
                return
            try:
                if isinstance(node, dict):
                    nm = node.get("name") or node.get("symbol")
                    ad = node.get("address") or node.get("addr") or node.get("value")
                    if nm and ad is not None:
                        _add_sym(nm, ad)
                        return
                    for k, v in node.items():
                        if isinstance(v, dict) or isinstance(v, list):
                            _walk2(v, depth + 1)
                elif isinstance(node, list):
                    for it in node:
                        _walk2(it, depth + 1)
            except Exception:
                pass
        _walk2(data)

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

    real_count = len([k for k in _sym.keys() if not k.startswith("__")])
    _sym["__diag__"] = "size=%d parsed=%d" % (size, real_count)


def sget(n):
    _load_sym()
    if n in _sym:
        return _sym[n]
    b = n.lstrip("_")
    if b in _sym:
        return _sym[b]
    if ("_" + n) in _sym:
        return _sym["_" + n]

    for a, nm in snamed_exact(n):
        if is_ktext(a):
            return a
    for a, nm in snamed_exact(b):
        if is_ktext(a):
            return a

    best = None
    for a, nm in snamed(b):
        if not is_ktext(a):
            continue
        if best is None or len(nm) < len(best[1]):
            best = (a, nm)
    if best is not None:
        return best[0]
    return None


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
    out = []
    for a, n in _symidx:
        if p in n:
            out.append((a, n))
    return out


def snamed_exact(p):
    _build_idx()
    out = []
    for a, n in _symidx:
        if n == p or n == "_" + p or n == "s_" + p:
            out.append((a, n))
    return out


def _is_func_sym(nm):
    for p in BAD_PREFIX:
        if nm.startswith(p):
            return False
    return True


def fat(a):
    if a is None:
        return None
    try:
        ga = sa(a)
        if ga is None:
            return None
        f = getFunctionAt(ga)
        if f:
            return f
        return getFunctionContaining(ga)
    except Exception:
        return None


def decode_one(b, pc):
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
        if imm & 0x100:
            imm -= 0x200
        return "ldur x%d, [x%d, #%d]" % (b & 0x1F, (b >> 5) & 0x1F, imm)
    if (b & 0xFFC00000) == 0xB8400000:
        imm = (b >> 12) & 0x1FF
        if imm & 0x100:
            imm -= 0x200
        return "ldur w%d, [x%d, #%d]" % (b & 0x1F, (b >> 5) & 0x1F, imm)
    if (b & 0xFFC00000) == 0xF8000000:
        imm = (b >> 12) & 0x1FF
        if imm & 0x100:
            imm -= 0x200
        return "stur x%d, [x%d, #%d]" % (b & 0x1F, (b >> 5) & 0x1F, imm)
    if (b & 0xFFC00000) == 0xB8000000:
        imm = (b >> 12) & 0x1FF
        if imm & 0x100:
            imm -= 0x200
        return "stur w%d, [x%d, #%d]" % (b & 0x1F, (b >> 5) & 0x1F, imm)
    if (b & 0xFFC00000) == 0xA9400000:
        return "ldp x%d, x%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, ((b >> 15) & 0x7F) * 8)
    if (b & 0xFFC00000) == 0xA9000000:
        return "stp x%d, x%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, ((b >> 15) & 0x7F) * 8)
    if (b & 0xFFC00000) == 0x29400000:
        return "ldp w%d, w%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, ((b >> 15) & 0x7F) * 4)
    if (b & 0xFFC00000) == 0x29000000:
        return "stp w%d, w%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, ((b >> 15) & 0x7F) * 4)
    if (b & 0x7F800000) == 0x52800000:
        hw = (b >> 21) & 3
        return "movz w%d, #0x%X, lsl #%d" % (b & 0x1F, (b >> 5) & 0xFFFF, hw * 16)
    if (b & 0x7F800000) == 0xD2800000:
        hw = (b >> 21) & 3
        return "movz x%d, #0x%X, lsl #%d" % (b & 0x1F, (b >> 5) & 0xFFFF, hw * 16)
    if (b & 0x7F800000) == 0x72800000:
        hw = (b >> 21) & 3
        return "movk w%d, #0x%X, lsl #%d" % (b & 0x1F, (b >> 5) & 0xFFFF, hw * 16)
    if (b & 0x7F800000) == 0xF2800000:
        hw = (b >> 21) & 3
        return "movk x%d, #0x%X, lsl #%d" % (b & 0x1F, (b >> 5) & 0xFFFF, hw * 16)
    if (b & 0x7F800000) == 0x12800000:
        hw = (b >> 21) & 3
        return "movn w%d, #0x%X, lsl #%d" % (b & 0x1F, (b >> 5) & 0xFFFF, hw * 16)
    if (b & 0x7F800000) == 0x92800000:
        hw = (b >> 21) & 3
        return "movn x%d, #0x%X, lsl #%d" % (b & 0x1F, (b >> 5) & 0xFFFF, hw * 16)
    if (b & 0x7F800000) == 0x11000000:
        sh = (b >> 22) & 1
        imm = (b >> 10) & 0xFFF
        if sh:
            imm <<= 12
        return "add w%d, w%d, #0x%X" % (b & 0x1F, (b >> 5) & 0x1F, imm)
    if (b & 0x7F800000) == 0x91000000:
        sh = (b >> 22) & 1
        imm = (b >> 10) & 0xFFF
        if sh:
            imm <<= 12
        return "add x%d, x%d, #0x%X" % (b & 0x1F, (b >> 5) & 0x1F, imm)
    if (b & 0x7F800000) == 0x51000000:
        sh = (b >> 22) & 1
        imm = (b >> 10) & 0xFFF
        if sh:
            imm <<= 12
        return "sub w%d, w%d, #0x%X" % (b & 0x1F, (b >> 5) & 0x1F, imm)
    if (b & 0x7F800000) == 0xD1000000:
        sh = (b >> 22) & 1
        imm = (b >> 10) & 0xFFF
        if sh:
            imm <<= 12
        return "sub x%d, x%d, #0x%X" % (b & 0x1F, (b >> 5) & 0x1F, imm)
    if (b & 0x7FE00000) == 0x0B000000:
        return "add w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x8B000000:
        return "add x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x4B000000:
        return "sub w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0xCB000000:
        return "sub x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x2A000000:
        return "orr w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0xAA000000:
        return "orr x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x0A000000:
        return "and w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x8A000000:
        return "and x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x4A000000:
        return "eor w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0xCA000000:
        return "eor x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x6B000000:
        return "subs w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0xEB000000:
        return "subs x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE0FC00) == 0x1AC02000:
        return "lsl w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE0FC00) == 0x9AC02000:
        return "lsl x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7F800000) == 0x53000000:
        return "ubfm w%d, w%d, #%d, #%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x3F, (b >> 10) & 0x3F)
    if (b & 0x7F800000) == 0xD3000000:
        return "ubfm x%d, x%d, #%d, #%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x3F, (b >> 10) & 0x3F)
    if (b & 0x9F000000) == 0x90000000:
        immlo = (b >> 29) & 3
        immhi = (b >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm -= 0x200000
        page = (pc & ~0xFFF) + (imm << 12)
        return "adrp x%d, 0x%016X" % (b & 0x1F, page & 0xFFFFFFFFFFFFFFFF)
    if (b & 0x9F000000) == 0x10000000:
        immlo = (b >> 29) & 3
        immhi = (b >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm -= 0x200000
        return "adr x%d, 0x%016X" % (b & 0x1F, (pc + imm) & 0xFFFFFFFFFFFFFFFF)
    if (b & 0x7C000000) == 0x14000000:
        off = b & 0x03FFFFFF
        if off & 0x02000000:
            off -= 0x04000000
        return "b #0x%X (-> 0x%016X)" % (off * 4, (pc + off * 4) & 0xFFFFFFFFFFFFFFFF)
    if (b & 0x7C000000) == 0x94000000:
        off = b & 0x03FFFFFF
        if off & 0x02000000:
            off -= 0x04000000
        return "bl #0x%X (-> 0x%016X)" % (off * 4, (pc + off * 4) & 0xFFFFFFFFFFFFFFFF)
    if (b & 0x7E000000) == 0x34000000:
        off = (b >> 5) & 0x7FFFF
        if off & 0x40000:
            off -= 0x80000
        return "cbz w%d, #0x%X" % (b & 0x1F, off * 4)
    if (b & 0x7E000000) == 0x35000000:
        off = (b >> 5) & 0x7FFFF
        if off & 0x40000:
            off -= 0x80000
        return "cbnz w%d, #0x%X" % (b & 0x1F, off * 4)
    if (b & 0x7E000000) == 0xB4000000:
        off = (b >> 5) & 0x7FFFF
        if off & 0x40000:
            off -= 0x80000
        return "cbz x%d, #0x%X" % (b & 0x1F, off * 4)
    if (b & 0x7E000000) == 0xB5000000:
        off = (b >> 5) & 0x7FFFF
        if off & 0x40000:
            off -= 0x80000
        return "cbnz x%d, #0x%X" % (b & 0x1F, off * 4)
    if (b & 0x7F800000) == 0x71000000:
        return "cmp w%d, #0x%X" % ((b >> 5) & 0x1F, (b >> 10) & 0xFFF)
    if (b & 0x7F800000) == 0xF1000000:
        return "cmp x%d, #0x%X" % ((b >> 5) & 0x1F, (b >> 10) & 0xFFF)
    if (b & 0x7FE00C00) == 0x1A800000:
        return "csel w%d, w%d, w%d, #%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F, b & 0xF)
    if (b & 0x7FE00C00) == 0x9A800000:
        return "csel x%d, x%d, x%d, #%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F, b & 0xF)
    if b == 0xD65F03C0:
        return "ret"
    if b == 0xD503201F:
        return "nop"
    if b == 0xD503233F:
        return "paciasp"
    if b == 0xD50323BF:
        return "autiasp"
    if b == 0xD5033BBF:
        return "autiasp"
    return "?? (0x%08X)" % b


def dis_raw(addr, count):
    if addr is None:
        return ["(addr is None)"]

    blk = inblk(addr)
    if blk is None:
        return ["(addr %s NOT IN ANY LOADED BLOCK)" % fmt(addr)]

    ga = sa(addr)
    if ga is None:
        return ["(cannot toAddr %s — AddressFactory refused)" % fmt(addr)]

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
        insn = decode_one(b, a)
        out.append("%016X  %08X  %s" % (a, b, insn))
        i += 1
    if not out:
        out.append("(no readable code at %s)" % fmt(addr))
    return out


def find_imm_ops(func_addr, maxn):
    """Возвращает список (mnem, val, body)."""
    out = []
    for line in dis_raw(func_addr, maxn):
        m = re.match(r"([0-9A-F]{16})  ([0-9A-F]{8})  (.*)", line)
        if not m:
            continue
        body = m.group(3)
        mn = body.split(" ", 1)[0].lower()
        for im in re.finditer(r"#(0x[0-9A-Fa-f]+|\d+)", body):
            try:
                val = int(im.group(1), 0)
            except Exception:
                continue
            if 0 < val < 0x8000:
                out.append((mn, val, body))
    return out


def find_call_targets(addr, maxn=400):
    out = []
    for line in dis_raw(addr, maxn):
        m = re.match(r"([0-9A-F]{16})  ([0-9A-F]{8})  (.*)", line)
        if not m:
            continue
        body = m.group(3)
        if body.startswith("bl "):
            m2 = re.search(r"-> 0x([0-9A-F]+)", body)
            if m2:
                try:
                    out.append(int(m2.group(1), 16))
                except Exception:
                    pass
    return out


def find_func(names):
    for n in names:
        a = sget(n)
        if a is not None and is_ktext(a):
            return a, n
    for n in names:
        for a, nm in snamed_exact(n):
            if is_ktext(a) and _is_func_sym(nm):
                return a, nm
    for n in names:
        b = n.lstrip("_")
        best = None
        for a, nm in snamed(b):
            if not is_ktext(a):
                continue
            if not _is_func_sym(nm):
                continue
            if best is None or len(nm) < len(best[1]):
                best = (a, nm)
        if best is not None:
            return best
    return None, None


def scan_getter(imm_min, imm_max, reg_width):
    lo, hi = text_range()
    if lo is None:
        return None, None
    if reg_width == "x":
        base_op = 0xF9400000
        shift = 3
    else:
        base_op = 0xB9400000
        shift = 2
    addr = lo
    while addr < hi - 8:
        b0 = r32(addr)
        b1 = r32(addr + 4)
        if b0 is None or b1 is None:
            addr += 4
            continue
        if (b0 & 0xFFC00000) == base_op and b1 == 0xD65F03C0:
            rd = b0 & 0x1F
            rn = (b0 >> 5) & 0x1F
            imm = ((b0 >> 10) & 0xFFF) << shift
            if rd == 0 and rn == 0 and imm_min <= imm <= imm_max:
                return addr, imm
        addr += 4
    return None, None


def find_offsets_json():
    candidates = []
    for root, dirs, files in os.walk(WS):
        if ".git" in root or "node_modules" in root:
            continue
        for f in files:
            if f == "offsets.json":
                candidates.append(os.path.join(root, f))
        if len(candidates) > 5:
            break
    for root, dirs, files in os.walk(WS):
        if ".git" in root or "node_modules" in root:
            continue
        for f in files:
            if f == "index.json" and "Offsets" in root:
                candidates.append(os.path.join(root, f))
    return candidates


def load_offsets_repo():
    global _offsets_repo
    if _offsets_repo is not None:
        return _offsets_repo
    _offsets_repo = {}

    candidates = find_offsets_json()
    for path in candidates:
        try:
            fh = open(path)
            raw = fh.read()
            fh.close()
            data = json.loads(raw)
            if isinstance(data, dict) and ("defaults" in data or "globals" in data or "kernel_base" in data):
                _offsets_repo = data
                _offsets_repo["__source__"] = path
                return _offsets_repo
        except Exception:
            pass
    return _offsets_repo


def validate_offsets():
    repo = load_offsets_repo()
    lines = []
    lines.append("=== OFFSETS.JSON VALIDATION ===")
    if not repo:
        found = find_offsets_json()
        if found:
            lines.append("  found candidates but none parsed:")
            for p in found[:5]:
                lines.append("    " + p)
        else:
            lines.append("  (offsets.json not found in workspace)")
        lines.append("")
        return lines

    src = repo.get("__source__", "?")
    lines.append("  source = %s" % src)
    lines.append("")

    defaults = repo.get("defaults", {})
    if not defaults:
        lines.append("  (no 'defaults' key in offsets.json)")
        lines.append("")
        return lines

    total_ok = 0
    total_bad = 0

    for group_name, items in VALIDATE_GROUPS:
        lines.append("  --- %s ---" % group_name)
        for key, kind, expected in items:
            raw = defaults.get(key)
            if raw is None:
                lines.append("    %-40s MISSING in json" % key)
                total_bad += 1
                continue

            if kind == "int":
                try:
                    ival = int(raw, 0) if isinstance(raw, _STR_TYPES) else int(raw)
                except Exception as e:
                    lines.append("    %-40s %s PARSE ERR: %s" % (key, raw, str(e)))
                    total_bad += 1
                    continue
                exp_ok = (expected is None) or (ival == expected)
                if exp_ok:
                    total_ok += 1
                else:
                    total_bad += 1
                lines.append("    %-40s 0x%X (%d) %s" % (key, ival, ival, "OK" if exp_ok else "MISMATCH expected 0x%X" % expected))
                continue

            try:
                aval = int(raw, 16) if isinstance(raw, _STR_TYPES) else int(raw)
            except Exception as e:
                lines.append("    %-40s %s PARSE ERR: %s" % (key, raw, str(e)))
                total_bad += 1
                continue

            exp_ok = (expected is None) or (aval == expected)
            blk = inblk(aval)
            if blk is None:
                kexts_hint = ""
                if os.path.isdir(KEXTS):
                    kexts_hint = " (run 'ipsw kernel extract --all')"
                lines.append("    %-40s %s NOT IN LOADED BLOCKS%s" % (key, fmt(aval), kexts_hint))
                total_bad += 1
                continue

            val = r64(aval)
            val_str = fmt(val) if val is not None else "read_err"
            if exp_ok:
                total_ok += 1
            else:
                total_bad += 1
            lines.append("    %-40s %s in %s %s val=%s" % (
                key, fmt(aval), blk[2], "OK" if exp_ok else "MISMATCH expected %s" % fmt(expected), val_str))

        lines.append("")

    kb = repo.get("kernel_base")
    if kb:
        try:
            kb_int = int(kb, 16) if isinstance(kb, _STR_TYPES) else int(kb)
            lines.append("  kernel_base = %s %s" % (kb, "OK" if kb_int == KBASE else "MISMATCH expected %s" % fmt(KBASE)))
        except Exception:
            lines.append("  kernel_base = %s PARSE ERR" % kb)
    lines.append("")

    lines.append("  summary: OK=%d BAD=%d" % (total_ok, total_bad))
    lines.append("")

    return lines


def diag_not_found(name, names, lines):
    lines.append("  --- diagnostic: why '%s' not found ---" % name)

    for n in names:
        found_exact = snamed_exact(n)
        if found_exact:
            lines.append("    exact '%s': %d hits" % (n, len(found_exact)))
            for a, nm in found_exact[:5]:
                blk = inblk(a)
                where = blk[2] if blk else "NO_BLOCK"
                lines.append("      %s @ %s (%s)" % (nm, fmt(a), where))
        else:
            lines.append("    exact '%s': none" % n)

    b = names[0].lstrip("_")
    partial = snamed(b)
    if partial:
        lines.append("    partial '%s': %d hits (showing first 8)" % (b, len(partial)))
        for a, nm in partial[:8]:
            blk = inblk(a)
            where = blk[2] if blk else "NO_BLOCK"
            lines.append("      %s @ %s (%s)" % (nm, fmt(a), where))
    else:
        lines.append("    partial '%s': none" % b)

    _load_sym()
    if b in _sym:
        a = _sym[b]
        blk = inblk(a)
        where = blk[2] if blk else "NO_BLOCK"
        lines.append("    in symbols.json: %s (%s)" % (fmt(a), where))
    else:
        lines.append("    in symbols.json: NOT PRESENT")

    if os.path.isdir(KEXTS):
        try:
            klist = sorted(os.listdir(KEXTS))
            hits = [k for k in klist if "necp" in k.lower() or "amfi" in k.lower() or "bsd" in k.lower() or "kernel" in k.lower()]
            if hits:
                lines.append("    relevant kexts: %s" % ", ".join(hits[:8]))
        except Exception:
            pass
    lines.append("")


def main():
    print("=== kernel_offsets.py ===")
    _load_sym()
    _build_idx()

    sym_count = len([k for k in (_sym or {}).keys() if not k.startswith("__")])
    diag = (_sym or {}).get("__diag__", "(no diag)")
    print("[+] sym: %d" % sym_count)
    print("[+] diag: %s" % diag)

    fb = FALLBACK_24A437

    lines = []
    lines.append("=== SYMBOLS DIAG ===")
    lines.append(diag)
    lines.append("sym_count = %d" % sym_count)
    lines.append("workspace = %s" % WS)
    lines.append("symbols_json = %s" % SYM)
    lines.append("kexts_dir = %s (%s)" % (KEXTS, "present" if os.path.isdir(KEXTS) else "missing"))
    lines.append("")

    lines.extend(validate_offsets())

    lo, hi = text_range()
    lines.append("=== TEXT RANGE ===")
    lines.append("  __text: %s - %s (%d MB)" % (fmt(lo), fmt(hi), ((hi - lo) // (1024*1024)) if lo and hi else 0))
    lines.append("  total blocks: %d" % len(blocks()))
    lines.append("")

    lines.append("=== TARGET OFFSETS ===")
    lines.append("kernel_base = " + fmt(KBASE))
    lines.append("")

    lines.append("=== proc_p_ucred_off ===")
    p_off = None
    p_src = "NOT_FOUND"

    a = sget("_proc_ucred") or sget("proc_ucred")
    if a is not None and is_ktext(a):
        lines.append("  _proc_ucred @ %s" % fmt(a))
        for mn, val, ops in find_imm_ops(a, 30):
            if mn == "ldr" and 0x70 <= val <= 0x110:
                p_off = val
                p_src = "_proc_ucred -> %s" % ops
                break

    if p_off is None:
        addr, imm = scan_getter(0x70, 0x110, "x")
        if addr is not None:
            p_off = imm
            p_src = "pattern LDR X0, [X0, #0x%X]; RET @ %s" % (imm, fmt(addr))

    if p_off is None:
        p_off = fb["proc_p_ucred_off"]
        p_src = "FALLBACK 24A437"
        diag_not_found("proc_ucred", ["_proc_ucred", "proc_ucred"], lines)

    lines.append("  value  = " + (fmt(p_off) if p_off else "NOT_FOUND"))
    lines.append("  source = " + p_src)
    lines.append("")

    lines.append("=== ucred ids ===")
    u_uid = None
    u_svuid = None

    a = sget("_kauth_cred_getuid") or sget("kauth_cred_getuid")
    if a is not None and is_ktext(a):
        lines.append("  kauth_cred_getuid @ %s" % fmt(a))
        for mn, val, ops in find_imm_ops(a, 20):
            if mn in ("ldr", "ldrb", "ldrh") and 0x08 <= val <= 0x20:
                u_uid = val
                lines.append("    %s" % ops)
                break
    if u_uid is None:
        addr, imm = scan_getter(0x08, 0x20, "w")
        if addr is not None:
            u_uid = imm
            lines.append("  kauth_cred_getuid pattern @ %s -> 0x%X" % (fmt(addr), imm))

    a = sget("_kauth_cred_getsvuid") or sget("kauth_cred_getsvuid") or sget("_kauth_cred_getsavuid")
    if a is not None and is_ktext(a):
        lines.append("  kauth_cred_getsvuid @ %s" % fmt(a))
        for mn, val, ops in find_imm_ops(a, 20):
            if mn in ("ldr", "ldrb", "ldrh") and 0x08 <= val <= 0x30:
                u_svuid = val
                lines.append("    %s" % ops)
                break
    if u_svuid is None:
        addr, imm = scan_getter(0x08, 0x30, "w")
        if addr is not None:
            u_svuid = imm
            lines.append("  kauth_cred_getsvuid pattern @ %s -> 0x%X" % (fmt(addr), imm))

    if u_uid is None:
        u_uid = fb["ucred_cr_uid_off"]
        lines.append("  ucred_cr_uid_off FALLBACK -> 0x%X" % u_uid)
        diag_not_found("kauth_cred_getuid", ["_kauth_cred_getuid", "kauth_cred_getuid"], lines)
    if u_svuid is None:
        u_svuid = fb["ucred_cr_svuid_off"]
        lines.append("  ucred_cr_svuid_off FALLBACK -> 0x%X" % u_svuid)
        diag_not_found("kauth_cred_getsvuid", ["_kauth_cred_getsvuid", "kauth_cred_getsvuid", "_kauth_cred_getsavuid"], lines)

    lines.append("  ucred_cr_uid_off    = 0x%X" % (u_uid or 0))
    lines.append("  ucred_cr_svuid_off  = 0x%X" % (u_svuid or 0))
    lines.append("")

    lines.append("=== NECP flow struct ===")
    ncf_assigned = None
    ncf_size = None

    a_add = sget("_necp_client_add_flow") or sget("necp_client_add_flow")
    if a_add is not None:
        blk = inblk(a_add)
        if blk is not None:
            lines.append("  necp_client_add_flow @ %s in %s exec=%s" % (fmt(a_add), blk[2], blk[3]))
            lines.append("  disasm first 10:")
            for l in dis_raw(a_add, 10):
                lines.append("    " + l)
            for mn, val, ops in find_imm_ops(a_add, 500):
                if mn in ("str", "stp", "stur") and 0x40 <= val <= 0xA0:
                    ncf_assigned = val
                    lines.append("  STR match: %s" % ops)
                    break
            if ncf_assigned is None:
                lines.append("  no STR in range 0x40-0xA0 found")
                for mn, val, ops in find_imm_ops(a_add, 500):
                    if mn in ("str", "stp", "stur"):
                        lines.append("    candidate STR: %s" % ops)

            call_targets = find_call_targets(a_add, 500)
            lines.append("  BL targets: %d" % len(call_targets))
            for t in call_targets[:5]:
                blk_t = inblk(t)
                lines.append("    -> %s (%s)" % (fmt(t), blk_t[2] if blk_t else "NO_BLOCK"))
                for mn, val, ops in find_imm_ops(t, 300):
                    if mn in ("mov", "movz") and 0x80 <= val <= 0x400:
                        ncf_size = val
                        lines.append("      necp_flow_alloc candidate: %s" % ops)
                        break
                if ncf_size is not None:
                    break
        else:
            lines.append("  necp_client_add_flow @ %s NOT IN LOADED BLOCKS" % fmt(a_add))
    else:
        lines.append("  necp_client_add_flow not in symbols")
        diag_not_found("necp_client_add_flow", ["_necp_client_add_flow", "necp_client_add_flow"], lines)

    if ncf_assigned is None:
        ncf_assigned = fb["NCF_ASSIGNED_OFF"]
        lines.append("  NCF_ASSIGNED_OFF FALLBACK -> 0x%X" % ncf_assigned)
    if ncf_size is None:
        ncf_size = fb["NCF_STRUCT_SZ"]
        lines.append("  NCF_STRUCT_SZ FALLBACK -> 0x%X" % ncf_size)

    lines.append("  NCF_ASSIGNED_OFF    = 0x%X" % ncf_assigned)
    lines.append("  NCF_STRUCT_SZ       = 0x%X" % ncf_size)
    lines.append("")

    lines.append("=== amfi_get_out_of_my_way ===")
    a_amfi = sget("_amfi_get_out_of_my_way") or sget("amfi_get_out_of_my_way")
    if a_amfi is None:
        diag_not_found("amfi_get_out_of_my_way", ["_amfi_get_out_of_my_way", "amfi_get_out_of_my_way"], lines)
    lines.append("  value  = " + (fmt(a_amfi) if a_amfi else "NOT_FOUND"))
    lines.append("")

    lines.append("=== DISASM ===")
    for key, names in TARGETS:
        a, nm = find_func(names)
        if a is None:
            lines.append("")
            lines.append("--- %s : NOT FOUND ---" % key)
            continue
        lines.append("")
        lines.append("--- %s @ %s ---" % (nm, fmt(a)))
        for l in dis_raw(a, 40):
            lines.append(l)

    if os.path.isdir(KEXTS):
        lines.append("")
        lines.append("=== KEXTS ===")
        try:
            klist = sorted(os.listdir(KEXTS))
            lines.append("  count = %d" % len(klist))
            for k in klist[:30]:
                lines.append("  " + k)
            if len(klist) > 30:
                lines.append("  ... and %d more" % (len(klist) - 30))
        except Exception as e:
            lines.append("  list err: %s" % str(e))

    jout = {}
    jout["kernel_base"] = fmt(KBASE)
    jout["proc_p_ucred_off"] = p_off
    jout["ucred_cr_uid_off"] = u_uid
    jout["ucred_cr_svuid_off"] = u_svuid
    jout["NCF_ASSIGNED_OFF"] = ncf_assigned
    jout["NCF_STRUCT_SZ"] = ncf_size
    jout["amfi_get_out_of_my_way"] = a_amfi
    jout["symbols_loaded"] = sym_count
    try:
        fh = open(OUT_JSON, "w")
        fh.write(json.dumps(jout, indent=2, sort_keys=True))
        fh.close()
    except Exception:
        pass

    try:
        fh = open(OUT, "w")
        for l in lines:
            fh.write(l + "\n")
        fh.close()
        print("[+] wrote " + OUT)
    except Exception as e:
        print("[-] write: " + str(e))

    print("=== SUMMARY ===")
    print("  symbols_loaded     %d" % sym_count)
    print("  proc_p_ucred_off   " + (fmt(p_off) if p_off else "NOT_FOUND"))
    print("  ucred_cr_uid_off   0x%X" % (u_uid or 0))
    print("  ucred_cr_svuid_off 0x%X" % (u_svuid or 0))
    print("  NCF_ASSIGNED_OFF   0x%X" % ncf_assigned)
    print("  NCF_STRUCT_SZ      0x%X" % ncf_size)
    print("  amfi_get_out_of_my_way " + (fmt(a_amfi) if a_amfi else "NOT_FOUND"))
    print("=== DONE ===")


try:
    main()
except Exception as e:
    print("[-] FATAL: " + str(e))
    traceback.print_exc()
    try:
        fh = open(OUT, "w")
        fh.write("FATAL: " + str(e) + "\n")
        fh.close()
    except Exception:
        pass