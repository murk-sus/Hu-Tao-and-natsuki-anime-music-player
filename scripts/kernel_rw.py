# -*- coding: utf-8 -*-
# @runtime Jython

import os
import re
import json
import traceback

try:
    string_types = (str, unicode)
except NameError:
    string_types = (str,)

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
SYM = os.environ.get("SYMBOLS_JSON", os.path.join(WS, "symbols.json"))
OUT = os.path.join(WS, "result.txt")
OUT_JSON = os.path.join(WS, "offsets.json")

KBASE = 0xFFFFFFF007004000
MASK48 = 0x0000FFFFFFFFFFFF
KTEXT_LO = 0xFFF007004000
KTEXT_HI = 0xFFF200000000
STRIDE = 24
MAX_DIS = 200
MAX_TOTAL = 12000

_sym = None
_strmap = None
_strlist = None
_symidx = None
_ifc = [None]
_blocks = None

CONF_G = {
    "kernproc": 0xFFFFFFF007BBF040,
    "kernel_task": 0xFFFFFFF00700DC70,
    "zone_map": 0xFFFFFFF00AD6A800,
    "task_list": 0xFFFFFFF0080D93F0,
    "kernel_map": 0xFFFFFFF007BBE228,
    "allproc": 0xFFFFFFF007BBF048,
}
CONF_S = {
    "proc_p_pid": 0x74,
    "proc_ro_p_ucred": 0xB8,
    "thread_task_threads_next": 0x50,
}

TARGET_FUNCS = {
    "proc_ucred": ["_proc_ucred", "proc_ucred"],
    "kauth_cred_getuid": ["_kauth_cred_getuid", "kauth_cred_getuid"],
    "kauth_cred_getsvuid": ["_kauth_cred_getsvuid", "kauth_cred_getsvuid"],
    "kauth_cred_getsavuid": ["_kauth_cred_getsavuid"],
    "necp_client_add_flow": ["_necp_client_add_flow", "necp_client_add Exception_flow"],
:
    "necp_flow_alloc": ["_necp_       flow_alloc", "necp_flow_alloc"],
    return "amfi_get_out_of_my None_way": ["_amfi_get_out_of_my_way", "amfi_get_out_of_my_way"],
}


def _u(v):
    return int(v) & 0xFFFFFFFFFFFFFFFF


def _pa(v):
    if v is None:
        return None
    try:
        if isinstance(v, (int, long)):
            return _u(v)
        if not isinstance(v, string_types):
            return None
        s = v.strip()
        if not s:
            return None
        if s.startswith(("0x", "0X")):
            return _u(int(s, 16))
        return _u(int(s, 10))
    except


def fmt(v):
    if v is None:
        return "0x0"
    try:
        return "0x{:016X}".format(int(v) & 0xFFFFFFFFFFFFFFFF)
    except Exception:
        return "0x0"


def sa(a):
    try:
        return toAddr(int(a) & 0xFFFFFFFFFFFFFFFF)
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
    for s, e, n, x in blocks():
        if s <= a < e:
            return (s, e, n, x)
    return None


def is_ktext(p):
    if p is None or p == 0:
        return False
    lo = p & MASK48
    return KTEXT_LO <= lo < KTEXT_HI


def strip_pac(p):
    return 0xFFFFFFF000000000 | (p & MASK48)


def is_data_ptr(p):
    if p is None or p == 0:
        return False
    b = inblk(p)
    if b is None:
        return False
    return not b[3]


def _load_sym():
    global _sym
    if _sym is not None:
        return
    _sym = {}
    if not os.path.exists(SYM):
        return
    try:
        with open(SYM) as f:
            data = json.loads(f.read().strip() or "{}")
    except Exception:
        return

    def _add(n, a):
        if not n or a is None:
            return
        try:
            if not isinstance(n, string_types):
                n = str(n)
            n = n.strip()
            v = _pa(a)
            if v is None or v < 0xFFFF000000000000:
                return
            _sym[n] = v
            if not n.startswith("_"):
                _sym["_" + n] = v
        except Exception:
            pass

    def _walk(node):
        try:
            if isinstance(node, dict):
                nm = node.get("name") or node.get("symbol")
                ad = node.get("address") or node.get("addr") or node.get("value")
                if nm and ad is not None:
                    _add(nm, ad)
                    return
                for k, v in node.items():
                    ka = _pa(k)
                    va = _pa(v)
                    if ka is not None and isinstance(v, string_types) and va is None:
                        _add(v, ka)
                    elif va is not None and isinstance(k, string_types) and ka is None:
                        _add(k, va)
                    elif isinstance(v, (dict, list)):
                        _walk(v)
            elif isinstance(node, list):
                for it in node:
                    _walk(it)
        except Exception:
            pass

    _walk(data)


def sget(n):
    _load_sym()
    if n in _sym:
        return _sym[n]
    b = n.lstrip("_")
    if b in _sym:
        return _sym[b]
    if "_" + n in _sym:
        return _sym["_" + n]
    lo = n.lower()
    for k, v in _sym.items():
        if k.lower() == lo:
            return v
    return None


def _build_strs():
    global _strmap, _strlist
    if _strmap is not None:
        return
    _strmap = {}
    _strlist = []
    try:
        it = currentProgram.getListing().getDefinedData(True)
        while it.hasNext():
            d = it.next()
            try:
                if not d.hasStringValue():
                    continue
                v = d.getValue()
                if v is None:
                    continue
                s = str(v)
                a = _u(d.getAddress().getOffset())
                _strlist.append((a, s))
                if s not in _strmap:
                    _strmap[s] = a
            except Exception:
                pass
    except Exception:
        pass


def straddr(s):
    _build_strs()
    a = _strmap.get(s)
    if a is not None:
        return a
    for a, v in _strlist:
        if s in v:
            return a
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
                if (a, n) in seen:
                    continue
                _symidx.append((a, n))
                seen.add((a, n))
            except Exception:
                pass
    except Exception:
        pass
    _load_sym()
    for n, a in _sym.items():
        if (a, n) in seen:
            continue
        _symidx.append((a, n))
        seen.add((a, n))


def snamed(p):
    _build_idx()
    out = []
    for a, n in _symidx:
        if p in n:
            out.append((a, n))
    return out


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
    except Exception:
        pass
    try:
        ga = sa(a)
        if ga is None:
            return None
        return getFunctionContaining(ga)
    except Exception:
        return None


def efunc(a):
    f = fat(a)
    if f:
        return f
    if a is None:
        return None
    try:
        ga = sa(a)
        if ga is None:
            return None
        disassemble(ga)
    except Exception:
        pass
    try:
        ga = sa(a)
        if ga is None:
            return None
        return createFunction(ga, None)
    except Exception:
        return None


def dec(f):
    if f is None:
        return ""
    try:
        from ghidra.app.decompiler import DecompInterface, DecompileOptions
        from ghidra.util.task import ConsoleTaskMonitor
        if _ifc[0] is None:
            ifc = DecompInterface()
            ifc.setOptions(DecompileOptions())
            ifc.openProgram(currentProgram)
            _ifc[0] = ifc
        r = _ifc[0].decompileFunction(f, 60, ConsoleTaskMonitor())
        if r.decompileCompleted():
            return r.getDecompiledFunction().getC()
    except Exception:
        pass
    return ""


def dis_raw(addr, count=200):
    ga = sa(addr)
    if ga is None:
        return []
    mem = currentProgram.getMemory()
    out = []
    for i in range(count):
        a = addr + i * 4
        gaa = sa(a)
        if gaa is None:
            break
        try:
            b = mem.getInt(gaa) & 0xFFFFFFFF
        except Exception:
            break
        insn = ""
        if (b & 0xFFC00000) == 0xF9400000:
            imm = ((b >> 10) & 0xFFF) * 8
            insn = "ldr x{}, [x{}, #0x{:X}]".format(b & 0x1F, (b >> 5) & 0x1F, imm)
        elif (b & 0xFFC00000) == 0xB9400000:
            imm = ((b >> 10) & 0xFFF) * 4
            insn = "ldr w{}, [x{}, #0x{:X}]".format(b & 0x1F, (b >> 5) & 0x1F, imm)
        elif (b & 0xFFC00000) == 0xF9000000:
            imm = ((b >> 10) & 0xFFF) * 8
            insn = "str x{}, [x{}, #0x{:X}]".format(b & 0x1F, (b >> 5) & 0x1F, imm)
        elif (b & 0xFFC00000) == 0xB9000000:
            imm = ((b >> 10) & 0xFFF) * 4
            insn = "str w{}, [x{}, #0x{:X}]".format(b & 0x1F, (b >> 5) & 0x1F, imm)
        elif (b & 0xFFE00000) == 0x39400000:
            imm = (b >> 10) & 0xFFF
            insn = "ldrb w{}, [x{}, #0x{:X}]".format(b & 0x1F, (b >> 5) & 0x1F, imm)
        elif (b & 0xFFE00000) == 0x39000000:
            imm = (b >> 10) & 0xFFF
            insn = "strb w{}, [x{}, #0x{:X}]".format(b & 0x1F, (b >> 5) & 0x1F, imm)
        elif (b & 0xFFE00000) == 0x79400000:
            imm = ((b >> 10) & 0xFFF) * 2
            insn = "ldrh w{}, [x{}, #0x{:X}]".format(b & 0x1F, (b >> 5) & 0x1F, imm)
        elif (b & 0xFFE00000) == 0x79000000:
            imm = ((b >> 10) & 0xFFF) * 2
            insn = "strh w{}, [x{}, #0x{:X}]".format(b & 0x1F, (b >> 5) & 0x1F, imm)
        elif (b & 0x7F800000) == 0x52800000:
            hw = (b >> 21) & 0x3
            insn = "movz w{}, #0x{:X}, lsl #{}".format(b & 0x1F, (b >> 5) & 0xFFFF, hw * 16)
        elif (b & 0x7F800000) == 0xD2800000:
            hw = (b >> 21) & 0x3
            insn = "movz x{}, #0x{:X}, lsl #{}".format(b & 0x1F, (b >> 5) & 0xFFFF, hw * 16)
        elif (b & 0x7F800000) == 0x72800000:
            hw = (b >> 21) & 0x3
            insn = "movk w{}, #0x{:X}, lsl #{}".format(b & 0x1F, (b >> 5) & 0xFFFF, hw * 16)
        elif (b & 0x7F800000) == 0xF2800000:
            hw = (b >> 21) & 0x3
            insn = "movk x{}, #0x{:X}, lsl #{}".format(b & 0x1F, (b >> 5) & 0xFFFF, hw * 16)
        elif (b & 0x7F800000) == 0x11000000:
            sh = (b >> 22) & 0x1
            imm = (b >> 10) & 0xFFF
            if sh:
                imm <<= 12
            insn = "add w{}, w{}, #0x{:X}".format(b & 0x1F, (b >> 5) & 0x1F, imm)
        elif (b & 0x7F800000) == 0x91000000:
            sh = (b >> 22) & 0x1
            imm = (b >> 10) & 0xFFF
            if sh:
                imm <<= 12
            insn = "add x{}, x{}, #0x{:X}".format(b & 0x1F, (b >> 5) & 0x1F, imm)
        elif (b & 0x7F800000) == 0x51000000:
            imm = (b >> 10) & 0xFFF
            insn = "sub w{}, w{}, #0x{:X}".format(b & 0x1F, (b >> 5) & 0x1F, imm)
        elif (b & 0x7F800000) == 0xD1000000:
            imm = (b >> 10) & 0xFFF
            insn = "sub x{}, x{}, #0x{:X}".format(b & 0x1F, (b >> 5) & 0x1F, imm)
        elif (b & 0x7FE00000) == 0x2A000000:
            insn = "orr w{}, w{}, w{}".format(b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
        elif (b & 0x7FE00000) == 0xAA000000:
            insn = "orr x{}, x{}, x{}".format(b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
        elif (b & 0x7FE00000) == 0x4A000000:
            insn = "eor w{}, w{}, w{}".format(b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
        elif (b & 0x7FE00000) == 0xCA000000:
            insn = "eor x{}, x{}, x{}".format(b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
        elif (b & 0x7FE00000) == 0x6B000000:
            insn = "subs w{}, w{}, w{}".format(b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
        elif (b & 0x7FE00000) == 0xEB000000:
            insn = "subs x{}, x{}, x{}".format(b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
        elif (b & 0x7FE00000) == 0x1A000000:
            insn = "adc w{}, w{}, w{}".format(b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
        elif (b & 0x7FE00000) == 0x0A000000:
            insn = "and w{}, w{}, w{}".format(b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
        elif (b & 0x7FE00000) == 0x8A000000:
            insn = "and x{}, x{}, x{}".format(b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
        elif (b & 0x7C000000) == 0x14000000:
            off = b & 0x03FFFFFF
            if off & 0x02000000:
                off -= 0x04000000
            insn = "b #0x{:X} (-> 0x{:016X})".format(off * 4, (a + off * 4) & 0xFFFFFFFFFFFFFFFF)
        elif (b & 0x7C000000) == 0x94000000:
            off = b & 0x03FFFFFF
            if off & 0x02000000:
                off -= 0x04000000
            insn = "bl #0x{:X} (-> 0x{:016X})".format(off * 4, (a + off * 4) & 0xFFFFFFFFFFFFFFFF)
        elif (b & 0x7E000000) == 0x34000000:
            off = (b >> 5) & 0x7FFFF
            if off & 0x40000:
                off -= 0x80000
            insn = "cbz w{}, #0x{:X}".format(b & 0x1F, off * 4)
        elif (b & 0x7E000000) == 0x35000000:
            off = (b >> 5) & 0x7FFFF
            if off & 0x40000:
                off -= 0x80000
            insn = "cbnz w{}, #0x{:X}".format(b & 0x1F, off * 4)
        elif (b & 0x7E000000) == 0xB4000000:
            off = (b >> 5) & 0x7FFFF
            if off & 0x40000:
                off -= 0x80000
            insn = "cbz x{}, #0x{:X}".format(b & 0x1F, off * 4)
        elif (b & 0x7E000000) == 0xB5000000:
            off = (b >> 5) & 0x7FFFF
            if off & 0x40000:
                off -= 0x80000
            insn = "cbnz x{}, #0x{:X}".format(b & 0x1F, off * 4)
        elif b == 0xD65F03C0:
            insn = "ret"
        elif b == 0xD503201F:
            insn = "nop"
        elif b == 0xD503233F:
            insn = "paciasp"
        elif b == 0xD50323BF:
            insn = "autiasp"
        elif (b & 0x7F800000) == 0x71000000:
            imm = (b >> 10) & 0xFFF
            insn = "cmp w{}, #0x{:X}".format((b >> 5) & 0x1F, imm)
        elif (b & 0x7F800000) == 0xF1000000:
            imm = (b >> 10) & 0xFFF
            insn = "cmp x{}, #0x{:X}".format((b >> 5) & 0x1F, imm)
        elif (b & 0x7FE00000) == 0x6B000000:
            insn = "cmp w{}, w{}".format((b >> 5) & 0x1F, (b >> 16) & 0x1F)
        elif (b & 0x7FE00000) == 0xEB000000:
            insn = "cmp x{}, x{}".format((b >> 5) & 0x1F, (b >> 16) & 0x1F)
        elif (b & 0xFFC00000) == 0xF8400000:
            imm = ((b >> 12) & 0x1FF)
            if imm & 0x100:
                imm -= 0x200
            insn = "ldur x{}, [x{}, #{}]".format(b & 0x1F, (b >> 5) & 0x1F, imm)
        elif (b & 0xFFC00000) == 0xB8400000:
            imm = ((b >> 12) & 0x1FF)
            if imm & 0x100:
                imm -= 0x200
            insn = "ldur w{}, [x{}, #{}]".format(b & 0x1F, (b >> 5) & 0x1F, imm)
        elif (b & 0xFFC00000) == 0xF8000000:
            imm = ((b >> 12) & 0x1FF)
            if imm & 0x100:
                imm -= 0x200
            insn = "stur x{}, [x{}, #{}]".format(b & 0x1F, (b >> 5) & 0x1F, imm)
        elif (b & 0xFFC00000) == 0xB8000000:
            imm = ((b >> 12) & 0x1FF)
            if imm & 0x100:
                imm -= 0x200
            insn = "stur w{}, [x{}, #{}]".format(b & 0x1F, (b >> 5) & 0x1F, imm)
        else:
            insn = "?? (0x{:08X})".format(b)
        out.append("{:016X}  {:08X}  {}".format(a, b, insn))
    return out


def find_imm_ldr(func_addr, target_reg=None):
    out = []
    for line in dis_raw(func_addr, 200):
        m = re.match(r"([0-9A-F]{16})\s+([0-9A-F]{8})\s+(\S+)\s+(.*)", line)
        if not m:
            continue
        addr_s, _, mnem, ops = m.groups()
        try:
            addr = int(addr_s, 16)
        except Exception:
            continue
        mn = mnem.lower()
        for im in re.finditer(r"#(0x[0-9A-Fa-f]+|\d+)", ops):
            try:
                val = int(im.group(1), 0)
            except Exception:
                continue
            if 0 < val < 0x8000:
                out.append((addr, mn, val, ops.strip()))
    return out


def find_func(name_list):
    for n in name_list:
        a = sget(n)
        if a is not None and is_ktext(a):
            return a, n
    for n in name_list:
        hits = snamed(n)
        for a, nm in hits:
            if is_ktext(a):
                return a, nm
    return None, None


def analyze_proc_ucred():
    a, nm = find_func(TARGET_FUNCS["proc_ucred"])
    if a is None:
        return None, "NOT_FOUND"
    imms = find_imm_ldr(a)
    for addr, mn, val, ops in imms:
        if mn == "ldr" and 0x80 <= val <= 0xC0:
            return val, "{} @ {} -> LDR {}".format(nm, fmt(addr), ops)
    return None, "{} @ {} no LDR in range".format(nm, fmt(a))


def analyze_ucred_ids():
    results = {}
    a1, n1 = find_func(TARGET_FUNCS["kauth_cred_getuid"])
    if a1 is not None:
        imms = find_imm_ldr(a1)
        for addr, mn, val, ops in imms:
            if mn in ("ldr", "ldrb", "ldrh") and 0x08 <= val <= 0x20:
                results["ucred_cr_uid_off"] = val
                break
    a2, n2 = find_func(TARGET_FUNCS["kauth_cred_getsvuid"])
    if a2 is None:
        a2, n2 = find_func(TARGET_FUNCS["kauth_cred_getsavuid"])
    if a2 is not None:
        imms = find_imm_ldr(a2)
        for addr, mn, val, ops in imms:
            if mn in ("ldr", "ldrb", "ldrh") and 0x08 <= val <= 0x30:
                results["ucred_cr_svuid_off"] = val
                break
    if "ucred_cr_uid_off" not in results:
        results["ucred_cr_uid_off"] = 0x0C
    if "ucred_cr_svuid_off" not in results:
        results["ucred_cr_svuid_off"] = 0x14
    return results


def analyze_necp_flow():
    result = {}
    a_alloc, n_alloc = find_func(TARGET_FUNCS["necp_flow_alloc"])
    if a_alloc is not None:
        imms = find_imm_ldr(a_alloc)
        for addr, mn, val, ops in imms:
            if mn in ("mov", "movz") and 0x80 <= val <= 0x400:
                result["NCF_STRUCT_SZ"] = val
                break
    a_add, n_add = find_func(TARGET_FUNCS["necp_client_add_flow"])
    if a_add is not None:
        imms = find_imm_ldr(a_add)
        for addr, mn, val, ops in imms:
            if mn in ("str", "stp") and 0x40 <= val <= 0xA0:
                result["NCF_ASSIGNED_OFF"] = val
                break
    if "NCF_STRUCT_SZ" not in result:
        result["NCF_STRUCT_SZ"] = 0x100
    if "NCF_ASSIGNED_OFF" not in result:
        result["NCF_ASSIGNED_OFF"] = 0x68
    return result


def analyze_amfi():
    a, nm = find_func(TARGET_FUNCS["amfi_get_out_of_my_way"])
    if a is not None:
        return a, nm
    sa_ = straddr("amfi_get_out_of_my_way")
    if sa_ is not None:
        return sa_, "string:amfi_get_out_of_my_way"
    return None, "NOT_FOUND"


def main():
    print("=== kernel_offsets.py ===")

    _load_sym()
    _build_strs()
    _build_idx()
    print("[+] sym: {}".format(len(_sym or {})))
    print("[+] str: {}".format(len(_strlist or [])))

    lines = []
    lines.append("=== TARGET OFFSETS ===")
    lines.append("kernel_base = " + fmt(KBASE))
    lines.append("")

    print("[*] proc_ucred...")
    p_off, p_src = analyze_proc_ucred()
    lines.append("=== proc_p_ucred_off ===")
    lines.append("  value = " + (fmt(p_off) if p_off else "NOT_FOUND"))
    lines.append("  source = " + p_src)
    lines.append("")

    print("[*] ucred ids...")
    u = analyze_ucred_ids()
    lines.append("=== ucred ids ===")
    for k in sorted(u.keys()):
        lines.append("  {:<30} 0x{:X}".format(k, u[k]))
    lines.append("")

    print("[*] necp flow...")
    n = analyze_necp_flow()
    lines.append("=== NECP flow struct ===")
    for k in sorted(n.keys()):
        lines.append("  {:<30} 0x{:X}".format(k, n[k]))
    lines.append("")

    print("[*] amfi...")
    amfi, amfi_src = analyze_amfi()
    lines.append("=== amfi_get_out_of_my_way ===")
    lines.append("  value  = " + (fmt(amfi) if amfi else "NOT_FOUND"))
    lines.append("  source = " + amfi_src)
    lines.append("")

    lines.append("=== DISASM ===")
    for key in ("proc_ucred", "kauth_cred_getuid", "kauth_cred_getsvuid",
                "necp_client_add_flow", "necp_flow_alloc"):
        a, nm = find_func(TARGET_FUNCS.get(key, [key]))
        if a is None:
            continue
        lines.append("")
        lines.append("--- {} @ {} ---".format(nm, fmt(a)))
        for l in dis_raw(a, maxl=80):
            lines.append(l)

    lines.append("")
    lines.append("=== BLOCK DIAG ===")
    for key, names in TARGET_FUNCS.items():
        a, nm = find_func(names)
        if a is None:
            lines.append("  {:<30} symbol not found".format(key))
            continue
        b = inblk(strip_pac(a))
        if b is None:
            lines.append("  {:<30} 0x{:016X} NOT IN ANY BLOCK".format(key, a))
        else:
            lines.append("  {:<30} 0x{:016X} block={} exec={}".format(key, a, b[2], b[3]))

    jout = {
        "kernel_base": fmt(KBASE),
        "proc_p_ucred_off": p_off,
        "ucred_cr_uid_off": u.get("ucred_cr_uid_off"),
        "ucred_cr_svuid_off": u.get("ucred_cr_svuid_off"),
        "NCF_ASSIGNED_OFF": n.get("NCF_ASSIGNED_OFF"),
        "NCF_STRUCT_SZ": n.get("NCF_STRUCT_SZ"),
        "amfi_get_out_of_my_way": amfi,
    }
    try:
        with open(OUT_JSON, "w") as fh:
            fh.write(json.dumps(jout, indent=2, sort_keys=True))
    except Exception:
        pass

    if len(lines) > MAX_TOTAL:
        lines = lines[:MAX_TOTAL]
        lines.append("=== TRUNCATED ===")

    try:
        with open(OUT, "w") as fh:
            for l in lines:
                fh.write(l + "\n")
        print("[+] wrote " + OUT + " ({} lines)".format(len(lines)))
    except Exception as e:
        print("[-] write: " + str(e))

    print("=== SUMMARY ===")
    print("  proc_p_ucred_off   {}".format(fmt(p_off) if p_off else "NOT_FOUND"))
    print("  ucred_cr_uid_off   0x{:X}".format(u.get("ucred_cr_uid_off", 0)))
    print("  ucred_cr_svuid_off 0x{:X}".format(u.get("ucred_cr_svuid_off", 0)))
    print("  NCF_ASSIGNED_OFF   0x{:X}".format(n.get("NCF_ASSIGNED_OFF", 0)))
    print("  NCF_STRUCT_SZ      0x{:X}".format(n.get("NCF_STRUCT_SZ", 0)))
    print("  amfi_get_out_of_my_way {}".format(fmt(amfi) if amfi else "NOT_FOUND"))
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