#@runtime Jython

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
OUT = os.path.join(WS, "result.txt")
OUT_JSON = os.path.join(WS, "offsets.json")

KBASE = 0xFFFFFFF007004000
MASK48 = 0x0000FFFFFFFFFFFF
KTEXT_LO = 0xFFF007004000
KTEXT_HI = 0xFFF200000000

_sym = None
_strmap = None
_strlist = None
_symidx = None
_ifc = [None]
_blocks = None

# Список целевых функций: (имя_в_отчёте, [возможные_имена_символов])
TARGETS = []
TARGETS.append(("proc_ucred", ["_proc_ucred", "proc_ucred"]))
TARGETS.append(("kauth_cred_getuid", ["_kauth_cred_getuid", "kauth_cred_getuid"]))
TARGETS.append(("kauth_cred_getsvuid", ["_kauth_cred_getsvuid", "kauth_cred_getsvuid"]))
TARGETS.append(("kauth_cred_getsavuid", ["_kauth_cred_getsavuid"]))
TARGETS.append(("necp_client_add_flow", ["_necp_client_add_flow", "necp_client_add_flow"]))
TARGETS.append(("necp_flow_alloc", ["_necp_flow_alloc", "necp_flow_alloc"]))
TARGETS.append(("amfi_get_out_of_my_way", ["_amfi_get_out_of_my_way", "amfi_get_out_of_my_way"]))


def _u(v):
    return int(v) & 0xFFFFFFFFFFFFFFFF


def _pa(v):
    if v is None:
        return None
    try:
        if isinstance(v, (int, long)):
            return _u(v)
        if not isinstance(v, _STR_TYPES):
            return None
        s = v.strip()
        if not s:
            return None
        if s.startswith("0x") or s.startswith("0X"):
            return _u(int(s, 16))
        return _u(int(s, 10))
    except Exception:
        return None


def fmt(v):
    if v is None:
        return "0x0"
    try:
        return "0x" + ("%016X" % (int(v) & 0xFFFFFFFFFFFFFFFF))
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
                out.append((_u(b.getStart().getOffset()), _u(b.getEnd().getOffset()), b.getName(), b.isExecute()))
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


def _load_sym():
    global _sym
    if _sym is not None:
        return
    _sym = {}
    if not os.path.exists(SYM):
        return
    try:
        fh = open(SYM)
        raw = fh.read()
        fh.close()
        data = json.loads(raw.strip() or "{}")
    except Exception:
        return

    def _add(n, a):
        if not n or a is None:
            return
        try:
            if not isinstance(n, _STR_TYPES):
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
                    if ka is not None and isinstance(v, _STR_TYPES) and va is None:
                        _add(v, ka)
                    elif va is not None and isinstance(k, _STR_TYPES) and ka is None:
                        _add(k, va)
                    elif isinstance(v, dict) or isinstance(v, list):
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
    if ("_" + n) in _sym:
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


def dis_raw(addr, count):
    ga = sa(addr)
    if ga is None:
        return []
    mem = currentProgram.getMemory()
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
    return out


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
        return "sub w%d, w%d, #0x%X" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 10) & 0xFFF)
    if (b & 0x7F800000) == 0xD1000000:
        return "sub x%d, x%d, #0x%X" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 10) & 0xFFF)
    if (b & 0x7FE00000) == 0x2A000000:
        return "orr w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0xAA000000:
        return "orr x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x0A000000:
        return "and w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x8A000000:
        return "and x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x6B000000:
        return "subs w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0xEB000000:
        return "subs x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7F800000) == 0x71000000:
        return "cmp w%d, #0x%X" % ((b >> 5) & 0x1F, (b >> 10) & 0xFFF)
    if (b & 0x7F800000) == 0xF1000000:
        return "cmp x%d, #0x%X" % ((b >> 5) & 0x1F, (b >> 10) & 0xFFF)
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
    if b == 0xD65F03C0:
        return "ret"
    if b == 0xD503201F:
        return "nop"
    if b == 0xD503233F:
        return "paciasp"
    if b == 0xD50323BF:
        return "autiasp"
    return "?? (0x%08X)" % b


def find_imm_ops(func_addr, maxn):
    out = []
    lines = dis_raw(func_addr, maxn)
    for line in lines:
        m = re.match(r"([0-9A-F]{16})  ([0-9A-F]{8})  (.*)", line)
        if not m:
            continue
        try:
            addr = int(m.group(1), 16)
        except Exception:
            continue
        body = m.group(3)
        mn = body.split(" ", 1)[0].lower()
        for im in re.finditer(r"#(0x[0-9A-Fa-f]+|\d+)", body):
            try:
                val = int(im.group(1), 0)
            except Exception:
                continue
            if 0 < val < 0x8000:
                out.append((addr, mn, val, body))
    return out


def find_func(names):
    for n in names:
        a = sget(n)
        if a is not None and is_ktext(a):
            return a, n
    for n in names:
        hits = snamed(n)
        for a, nm in hits:
            if is_ktext(a):
                return a, nm
    return None, None


def main():
    print("=== kernel_offsets.py ===")

    _load_sym()
    _build_strs()
    _build_idx()

    sym_count = len(_sym or {})
    str_count = len(_strlist or [])
    print("[+] sym: %d" % sym_count)
    print("[+] str: %d" % str_count)

    lines = []
    lines.append("=== TARGET OFFSETS ===")
    lines.append("kernel_base = " + fmt(KBASE))
    lines.append("symbols_json = " + SYM)
    lines.append("symbols_loaded = %d" % sym_count)
    lines.append("")

    if sym_count == 0:
        lines.append("!! symbols.json EMPTY or missing — most values below are FALLBACK defaults")
        lines.append("")

    lines.append("=== proc_p_ucred_off ===")
    a, nm = find_func(["_proc_ucred", "proc_ucred"])
    p_off = None
    p_src = "NOT_FOUND"
    if a is not None:
        p_src = "%s @ %s" % (nm, fmt(a))
        for addr, mn, val, ops in find_imm_ops(a, 200):
            if mn == "ldr" and 0x80 <= val <= 0xC0:
                p_off = val
                p_src = "%s @ %s -> %s" % (nm, fmt(addr), ops)
                break
    lines.append("  value  = " + (fmt(p_off) if p_off else "NOT_FOUND"))
    lines.append("  source = " + p_src)
    lines.append("")

    lines.append("=== ucred ids ===")
    u_uid = None
    u_svuid = None
    a, nm = find_func(["_kauth_cred_getuid", "kauth_cred_getuid"])
    if a is not None:
        for addr, mn, val, ops in find_imm_ops(a, 200):
            if mn in ("ldr", "ldrb", "ldrh") and 0x08 <= val <= 0x20:
                u_uid = val
                break
    a, nm = find_func(["_kauth_cred_getsvuid", "kauth_cred_getsvuid", "_kauth_cred_getsavuid"])
    if a is not None:
        for addr, mn, val, ops in find_imm_ops(a, 200):
            if mn in ("ldr", "ldrb", "ldrh") and 0x08 <= val <= 0x30:
                u_svuid = val
                break
    lines.append("  ucred_cr_uid_off    = " + (("0x%X" % u_uid) if u_uid else "FALLBACK 0xC"))
    lines.append("  ucred_cr_svuid_off  = " + (("0x%X" % u_svuid) if u_svuid else "FALLBACK 0x14"))
    lines.append("")

    lines.append("=== NECP flow struct ===")
    ncf_assigned = None
    ncf_size = None
    a, nm = find_func(["_necp_flow_alloc", "necp_flow_alloc"])
    if a is not None:
        for addr, mn, val, ops in find_imm_ops(a, 300):
            if mn in ("mov", "movz") and 0x80 <= val <= 0x400:
                ncf_size = val
                break
    a, nm = find_func(["_necp_client_add_flow", "necp_client_add_flow"])
    if a is not None:
        for addr, mn, val, ops in find_imm_ops(a, 300):
            if mn in ("str", "stp") and 0x40 <= val <= 0xA0:
                ncf_assigned = val
                break
    lines.append("  NCF_ASSIGNED_OFF    = " + (("0x%X" % ncf_assigned) if ncf_assigned else "FALLBACK 0x68"))
    lines.append("  NCF_STRUCT_SZ       = " + (("0x%X" % ncf_size) if ncf_size else "FALLBACK 0x100"))
    lines.append("")

    lines.append("=== amfi_get_out_of_my_way ===")
    a, nm = find_func(["_amfi_get_out_of_my_way", "amfi_get_out_of_my_way"])
    amfi = a
    amfi_src = nm if a is not None else "NOT_FOUND"
    if amfi is None:
        sa_ = straddr("amfi_get_out_of_my_way")
        if sa_ is not None:
            amfi = sa_
            amfi_src = "string:" + fmt(sa_)
    lines.append("  value  = " + (fmt(amfi) if amfi else "NOT_FOUND"))
    lines.append("  source = " + amfi_src)
    lines.append("")

    lines.append("=== DISASM ===")
    for key, names in TARGETS:
        a, nm = find_func(names)
        if a is None:
            continue
        lines.append("")
        lines.append("--- %s @ %s ---" % (nm, fmt(a)))
        for l in dis_raw(a, 80):
            lines.append(l)

    lines.append("")
    lines.append("=== BLOCK DIAG ===")
    for key, names in TARGETS:
        a, nm = find_func(names)
        if a is None:
            lines.append("  %-30s symbol not found" % key)
            continue
        b = inblk(strip_pac(a))
        if b is None:
            lines.append("  %-30s 0x%016X NOT IN ANY BLOCK" % (key, a))
        else:
            lines.append("  %-30s 0x%016X block=%s exec=%s" % (key, a, b[2], b[3]))

    jout = {}
    jout["kernel_base"] = fmt(KBASE)
    jout["proc_p_ucred_off"] = p_off
    jout["ucred_cr_uid_off"] = u_uid
    jout["ucred_cr_svuid_off"] = u_svuid
    jout["NCF_ASSIGNED_OFF"] = ncf_assigned
    jout["NCF_STRUCT_SZ"] = ncf_size
    jout["amfi_get_out_of_my_way"] = amfi
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
        print("[+] wrote " + OUT + " (%d lines)" % len(lines))
    except Exception as e:
        print("[-] write: " + str(e))

    print("=== SUMMARY ===")
    print("  proc_p_ucred_off   " + (fmt(p_off) if p_off else "NOT_FOUND"))
    print("  ucred_cr_uid_off   " + (("0x%X" % u_uid) if u_uid else "FALLBACK"))
    print("  ucred_cr_svuid_off " + (("0x%X" % u_svuid) if u_svuid else "FALLBACK"))
    print("  NCF_ASSIGNED_OFF   " + (("0x%X" % ncf_assigned) if ncf_assigned else "FALLBACK"))
    print("  NCF_STRUCT_SZ      " + (("0x%X" % ncf_size) if ncf_size else "FALLBACK"))
    print("  amfi_get_out_of_my_way " + (fmt(amfi) if amfi else "NOT_FOUND"))
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