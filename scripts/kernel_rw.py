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
    """Возвращает min/max по ВСЕМ блокам с __text в имени."""
    if _text_range[0] is not None:
        return _text_range[0], _text_range[1]
    lo = None
    hi = None
    for s, e, n, x in blocks():
        if x and ("__text" in n or n == "__TEXT_EXEC"):
            if lo is None:
                lo = s
            if hi is None:
                hi = e
            else:
                lo = min(lo, s)
                hi = max(hi, e)
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


def decode_one(b, pc):
    # hint / pac / aut
    if b == 0xD503237F:
        return "pacibsp"
    if b == 0xD50323FF:
        return "autibsp"
    if b == 0xD503233F:
        return "paciasp"
    if b == 0xD50323BF:
        return "autiasp"
    if b == 0xD5033BBF:
        return "autiasp"
    if b == 0xD65F03C0:
        return "ret"
    if b == 0xD503201F:
        return "nop"
    if b == 0xD65F0FFF:
        return "ret"
    # MOVI
    if (b & 0xFF800000) == 0x0F000000:
        return "movi v%d.16b, #0x%X" % (b & 0x1F, (b >> 5) & 0xFF)
    if (b & 0xFFE00000) == 0x6F00E400:
        return "movi v%d.2d, #0" % (b & 0x1F)
    # TST
    if (b & 0x7FE00000) == 0x6A000000:
        return "tst w%d, w%d" % ((b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0xEA000000:
        return "tst x%d, x%d" % ((b >> 5) & 0x1F, (b >> 16) & 0x1F)
    # STP/LDP pre-index (A9Ax/A9Bx)
    if (b & 0xFFC00000) == 0xA9800000:
        imm = (b >> 15) & 0x7F
        if imm & 0x40:
            imm -= 0x80
        return "stp x%d, x%d, [x%d, #%d]!" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, imm * 8)
    if (b & 0xFFC00000) == 0xA9C00000:
        imm = (b >> 15) & 0x7F
        if imm & 0x40:
            imm -= 0x80
        return "ldp x%d, x%d, [x%d, #%d]!" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, imm * 8)
    if (b & 0xFFC00000) == 0xA8800000:
        imm = (b >> 15) & 0x7F
        return "stp x%d, x%d, [x%d], #%d" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, imm * 8)
    if (b & 0xFFC00000) == 0xA8C00000:
        imm = (b >> 15) & 0x7F
        return "ldp x%d, x%d, [x%d], #%d" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, imm * 8)
    # STP/LDP unsigned offset
    if (b & 0xFFC00000) == 0xA9000000:
        return "stp x%d, x%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, ((b >> 15) & 0x7F) * 8)
    if (b & 0xFFC00000) == 0xA9400000:
        return "ldp x%d, x%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, ((b >> 15) & 0x7F) * 8)
    if (b & 0xFFC00000) == 0x29000000:
        return "stp w%d, w%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, ((b >> 15) & 0x7F) * 4)
    if (b & 0xFFC00000) == 0x29400000:
        return "ldp w%d, w%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, ((b >> 15) & 0x7F) * 4)
    # STP Q / LDP Q pre-index
    if (b & 0xFFC00000) == 0xAD800000:
        imm = (b >> 15) & 0x7F
        if imm & 0x40:
            imm -= 0x80
        return "stp q%d, q%d, [x%d, #%d]!" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, imm * 16)
    if (b & 0xFFC00000) == 0xADC00000:
        imm = (b >> 15) & 0x7F
        if imm & 0x40:
            imm -= 0x80
        return "ldp q%d, q%d, [x%d, #%d]!" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, imm * 16)
    if (b & 0xFFC00000) == 0xAD000000:
        return "stp q%d, q%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, ((b >> 15) & 0x7F) * 16)
    if (b & 0xFFC00000) == 0xAD400000:
        return "ldp q%d, q%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, ((b >> 15) & 0x7F) * 16)
    # STR Q unsigned offset (3C80)
    if (b & 0xFFC00000) == 0x3D800000:
        return "str q%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 5) & 0x1F, ((b >> 10) & 0xFFF) * 16)
    if (b & 0xFFC00000) == 0x3DC00000:
        return "ldr q%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 5) & 0x1F, ((b >> 10) & 0xFFF) * 16)
    # LDR/STR (unsigned offset) x/w
    if (b & 0xFFC00000) == 0xF9400000:
        return "ldr x%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 5) & 0x1F, ((b >> 10) & 0xFFF) * 8)
    if (b & 0xFFC00000) == 0xB9400000:
        return "ldr w%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 5) & 0x1F, ((b >> 10) & 0xFFF) * 4)
    if (b & 0xFFC00000) == 0xF9000000:
        return "str x%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 5) & 0x1F, ((b >> 10) & 0xFFF) * 8)
    if (b & 0xFFC00000) == 0xB9000000:
        return "str w%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 5) & 0x1F, ((b >> 10) & 0xFFF) * 4)
    # byte/halfword
    if (b & 0xFFE00000) == 0x39400000:
        return "ldrb w%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 10) & 0xFFF)
    if (b & 0xFFE00000) == 0x39000000:
        return "strb w%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 10) & 0xFFF)
    if (b & 0xFFE00000) == 0x79400000:
        return "ldrh w%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 5) & 0x1F, ((b >> 10) & 0xFFF) * 2)
    if (b & 0xFFE00000) == 0x79000000:
        return "strh w%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 5) & 0x1F, ((b >> 10) & 0xFFF) * 2)
    # LDUR/STUR signed
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
    # MOVZ/MOVK/MOVN
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
    # ADD/SUB imm
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
    # ORR/AND/EOR shifted
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
    # LSL/LSR
    if (b & 0x7FE0FC00) == 0x1AC02000:
        return "lsl w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE0FC00) == 0x9AC02000:
        return "lsl x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    # UBFM/SBFM
    if (b & 0x7F800000) == 0x53000000:
        return "ubfm w%d, w%d, #%d, #%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x3F, (b >> 10) & 0x3F)
    if (b & 0x7F800000) == 0xD3000000:
        return "ubfm x%d, x%d, #%d, #%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x3F, (b >> 10) & 0x3F)
    # ADRP/ADR
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
    # B / BL
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
    # B.cond (54xxxxxx)
    if (b & 0xFF000010) == 0x54000000:
        off = (b >> 5) & 0x7FFFF
        if off & 0x40000:
            off -= 0x80000
        cond = b & 0xF
        names = ["eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
                 "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"]
        return "b.%s #0x%X" % (names[cond], off * 4)
    # CBZ/CBNZ
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
    # CMP
    if (b & 0x7F800000) == 0x71000000:
        return "cmp w%d, #0x%X" % ((b >> 5) & 0x1F, (b >> 10) & 0xFFF)
    if (b & 0x7F800000) == 0xF1000000:
        return "cmp x%d, #0x%X" % ((b >> 5) & 0x1F, (b >> 10) & 0xFFF)
    # CSEL/CSINC
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
    """Возвращает список адресов из b/bl с их целью (включая tail calls)."""
    out = []
    for line in dis_raw(addr, maxn):
        m = re.match(r"([0-9A-F]{16})  ([0-9A-F]{8})  (.*)", line)
        if not m:
            continue
        body = m.group(3)
        if body.startswith("b ") or body.startswith("bl "):
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
    """Сканирует __text на LDR X0/W0, [X0, #imm]; RET."""
    lo, hi = text_range()
    if lo is None or hi is None:
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


def validate_offsets():
    """Валидация hardcoded offsets из VALIDATE_GROUPS по загруженной памяти."""
    lines = []
    lines.append("=== OFFSETS.JSON VALIDATION (hardcoded) ===")
    lines.append("")

    total_ok = 0
    total_bad = 0
    total_missing = 0

    for group_name, items in VALIDATE_GROUPS:
        lines.append("  --- %s ---" % group_name)
        for key, kind, expected in items:
            if kind == "int":
                total_ok += 1
                lines.append("    %-40s 0x%X (numeric offset)" % (key, expected))
                continue

            aval = expected
            blk = inblk(aval)
            if blk is None:
                kexts_hint = ""
                if os.path.isdir(KEXTS):
                    kexts_hint = " (likely in KEXT, not loaded)"
                lines.append("    %-40s %s NOT IN LOADED BLOCKS%s" % (key, fmt(aval), kexts_hint))
                total_bad += 1
                continue

            val = r64(aval)
            val_str = fmt(val) if val is not None else "read_err"
            lines.append("    %-40s %s in %s val=%s" % (key, fmt(aval), blk[2], val_str))
            if val is not None and val != 0:
                total_ok += 1
            else:
                total_bad += 1

        lines.append("")

    lines.append("  summary: OK=%d BAD=%d" % (total_ok, total_bad))
    lines.append("")
    return lines


def analyze_necp():
    """Анализирует _necp_client_add_flow и его b/bl-таргеты."""
    a_add = sget("_necp_client_add_flow") or sget("necp_client_add_flow")
    if a_add is None:
        return None, None, "necp_client_add_flow not in symbols"

    if inblk(a_add) is None:
        return None, None, "necp_client_add_flow not in loaded blocks"

    lines_all = dis_raw(a_add, 200)
    if not lines_all or lines_all[0].startswith("("):
        return None, None, "no disasm for necp_client_add_flow"

    # NCF_ASSIGNED_OFF: пропускаем пролог, ищем str w / stur w в диапазоне 0x40-0x200
    ncf_assigned = None
    for i, line in enumerate(lines_all):
        if i < 30:
            continue
        m = re.match(r"[0-9A-F]+\s+[0-9A-F]+\s+str\s+w\d+,\s*\[x\d+,\s*#(0x[0-9A-Fa-f]+|\d+)\]", line)
        if m:
            try:
                val = int(m.group(1), 0)
            except Exception:
                continue
            if 0x40 <= val <= 0x200:
                ncf_assigned = val
                break
        m2 = re.match(r"[0-9A-F]+\s+[0-9A-F]+\s+stur\s+w\d+,\s*\[x\d+,\s*#(-?\d+)\]", line)
        if m2:
            try:
                val = abs(int(m2.group(1)))
            except Exception:
                continue
            if 0x40 <= val <= 0x200:
                ncf_assigned = val
                break

    # NCF_STRUCT_SZ: ищем b/bl-target и его movz с размером
    ncf_size = None
    targets = find_call_targets(a_add, 400)
    for t in targets:
        if not is_ktext(t):
            continue
        blk_t = inblk(t)
        if blk_t is None:
            continue
        for mn, val, ops in find_imm_ops(t, 150):
            if mn in ("movz", "mov") and 0x80 <= val <= 0x400:
                # фильтруем «очевидно не размер» значения
                if val in (0x100, 0x200, 0x300, 0x400) or (0x80 <= val <= 0x180):
                    ncf_size = val
                    break
        if ncf_size is not None:
            break

    return ncf_assigned, ncf_size, "ok"


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
    if lo is not None and hi is not None:
        lines.append("  __text: %s - %s (%d MB)" % (fmt(lo), fmt(hi), (hi - lo) // (1024*1024)))
    else:
        lines.append("  __text: not found")
    lines.append("  total blocks: %d" % len(blocks()))
    lines.append("")

    lines.append("=== TARGET OFFSETS ===")
    lines.append("kernel_base = " + fmt(KBASE))
    lines.append("")

    # proc_p_ucred_off
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
        lines.append("  symbol not found, scanning __text failed, using fallback")

    lines.append("  value  = " + (fmt(p_off) if p_off else "NOT_FOUND"))
    lines.append("  source = " + p_src)
    lines.append("")

    # ucred ids
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
    if u_svuid is None:
        u_svuid = fb["ucred_cr_svuid_off"]
        lines.append("  ucred_cr_svuid_off FALLBACK -> 0x%X" % u_svuid)

    lines.append("  ucred_cr_uid_off    = 0x%X" % (u_uid or 0))
    lines.append("  ucred_cr_svuid_off  = 0x%X" % (u_svuid or 0))
    lines.append("")

    # NECP
    lines.append("=== NECP flow struct ===")
    ncf_assigned, ncf_size, ncf_status = analyze_necp()
    lines.append("  analyze_necp status: %s" % ncf_status)

    if ncf_assigned is not None:
        lines.append("  NCF_ASSIGNED_OFF found in disasm: 0x%X" % ncf_assigned)
    if ncf_size is not None:
        lines.append("  NCF_STRUCT_SZ found in disasm: 0x%X" % ncf_size)

    # Дизасм добавим для отладки
    a_add = sget("_necp_client_add_flow") or sget("necp_client_add_flow")
    if a_add is not None and inblk(a_add) is not None:
        lines.append("  disasm of _necp_client_add_flow (first 40):")
        for l in dis_raw(a_add, 40):
            lines.append("    " + l)

        targets = find_call_targets(a_add, 400)
        lines.append("  b/bl-targets from _necp_client_add_flow: %d" % len(targets))
        for t in targets[:8]:
            blk_t = inblk(t)
            lines.append("    -> %s (%s)" % (fmt(t), blk_t[2] if blk_t else "NO_BLOCK"))

    if ncf_assigned is None:
        ncf_assigned = fb["NCF_ASSIGNED_OFF"]
        lines.append("  NCF_ASSIGNED_OFF FALLBACK -> 0x%X" % ncf_assigned)
    if ncf_size is None:
        ncf_size = fb["NCF_STRUCT_SZ"]
        lines.append("  NCF_STRUCT_SZ FALLBACK -> 0x%X" % ncf_size)

    lines.append("  NCF_ASSIGNED_OFF    = 0x%X" % ncf_assigned)
    lines.append("  NCF_STRUCT_SZ       = 0x%X" % ncf_size)
    lines.append("")

    # AMFI
    lines.append("=== amfi_get_out_of_my_way ===")
    a_amfi = sget("_amfi_get_out_of_my_way") or sget("amfi_get_out_of_my_way")
    if a_amfi is None:
        hits = snamed("amfi")
        for a, nm in hits[:6]:
            blk = inblk(a)
            where = blk[2] if blk else "NO_BLOCK"
            lines.append("  partial: %s @ %s (%s)" % (nm, fmt(a), where))
    lines.append("  value  = " + (fmt(a_amfi) if a_amfi else "NOT_FOUND"))
    lines.append("")

    # DISASM
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