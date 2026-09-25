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
MAX_TOTAL = 8000

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

# Целевые функции для дизасма
TARGET_FUNCS = {
    "proc_ucred": ["_proc_ucred", "proc_ucred"],
    "kauth_cred_getuid": ["_kauth_cred_getuid", "kauth_cred_getuid"],
    "kauth_cred_getsvuid": ["_kauth_cred_getsvuid", "kauth_cred_getsvuid"],
    "kauth_cred_getsavuid": ["_kauth_cred_getsavuid"],
    "necp_client_add_flow": ["_necp_client_add_flow", "necp_client_add_flow"],
    "necp_flow_alloc": ["_necp_flow_alloc", "necp_flow_alloc"],
    "amfi_get_out_of_my_way": ["_amfi_get_out_of_my_way", "amfi_get_out_of_my_way"],
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
    except Exception:
        return None


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


def r16(a):
    if a is None:
        return None
    ga = sa(a)
    if ga is None:
        return None
    try:
        return int(currentProgram.getMemory().getShort(ga)) & 0xFFFF
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


def is_exec(p):
    if p is None:
        return False
    b = inblk(strip_pac(p))
    if b is None:
        return False
    return b[3]


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


def dis(a, maxl=MAX_DIS):
    out = []
    f = fat(a)
    if f is None:
        f = efunc(a)
    if f is None:
        return out
    try:
        listing = currentProgram.getListing()
        body = f.getBody()
        if body is None:
            return out
        insn = listing.getInstructionAt(body.getMinAddress())
        c = 0
        while insn is not None and body.contains(insn.getAddress()) and c < maxl:
            try:
                aa = _u(insn.getAddress().getOffset())
                w = r32(aa) or 0
                mn = insn.getMnemonicString().lower()
                tx = insn.toString()
                out.append("{:016X}  {:08X}  {:<10} {}".format(aa, w, mn, tx))
            except Exception:
                pass
            insn = insn.getNext()
            c += 1
    except Exception:
        pass
    return out


def find_func(name_list):
    """Ищет функцию по списку имён символов."""
    for n in name_list:
        a = sget(n)
        if a is not None and is_ktext(a):
            return a, n
    # fallback: поиск по частичному имени в таблице символов Ghidra
    for n in name_list:
        hits = snamed(n)
        for a, nm in hits:
            if is_ktext(a):
                return a, nm
    return None, None


def find_imm_ldr(func_addr, target_reg=None):
    """Ищет в дизасме инструкции LDR/ADD с иммедиатом, возвращает список (addr, mnem, imm)."""
    out = []
    dis_lines = dis(func_addr, maxl=100)
    for line in dis_lines:
        m = re.match(r"([0-9A-F]{16})\s+([0-9A-F]{8})\s+(\w+)\s+(.*)", line)
        if not m:
            continue
        addr_s, _, mnem, ops = m.groups()
        try:
            addr = int(addr_s, 16)
        except Exception:
            continue
        mn = mnem.lower()
        if mn not in ("ldr", "ldrb", "ldrh", "str", "add", "mov", "movz", "movw", "movk"):
            continue
        # ищем иммедиат в операндах: #0x...
        for im in re.finditer(r"#(0x[0-9a-fA-F]+|\d+)", ops):
            try:
                val = int(im.group(1), 0)
            except Exception:
                continue
            if 0 < val < 0x4000:
                out.append((addr, mn, val, ops.strip()))
    return out


def analyze_proc_ucred():
    """Ищет смещение p_ucred в proc через дизасм _proc_ucred."""
    a, nm = find_func(TARGET_FUNCS["proc_ucred"])
    if a is None:
        return None, "NOT_FOUND"
    imms = find_imm_ldr(a)
    # Ищем LDR с иммедиатом в диапазоне 0x80-0xC0
    for addr, mn, val, ops in imms:
        if mn == "ldr" and 0x80 <= val <= 0xC0:
            return val, "{} @ {} -> LDR {}".format(nm, fmt(addr), ops)
    return None, "{} @ {} no LDR in range".format(nm, fmt(a))


def analyze_ucred_ids():
    """Ищет cr_uid / cr_svuid через дизасм kauth_cred_getuid / getsavuid."""
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
    # Fallback: стандартные смещения из XNU
    if "ucred_cr_uid_off" not in results:
        results["ucred_cr_uid_off"] = 0x0C
    if "ucred_cr_svuid_off" not in results:
        results["ucred_cr_svuid_off"] = 0x14
    return results


def analyze_necp_flow():
    """Ищет NCF_ASSIGNED_OFF и NCF_STRUCT_SZ через дизасм necp_client_add_flow / necp_flow_alloc."""
    result = {}
    # Ищем necp_flow_alloc — там malloc с размером структуры
    a_alloc, n_alloc = find_func(TARGET_FUNCS["necp_flow_alloc"])
    if a_alloc is not None:
        imms = find_imm_ldr(a_alloc)
        # Ищем MOV/MOVZ с размером в диапазоне 0x80-0x400
        for addr, mn, val, ops in imms:
            if mn in ("mov", "movz") and 0x80 <= val <= 0x400:
                result["NCF_STRUCT_SZ"] = val
                break
    # Ищем necp_client_add_flow — там запись assigned
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
    """Ищет amfi_get_out_of_my_way."""
    a, nm = find_func(TARGET_FUNCS["amfi_get_out_of_my_way"])
    if a is not None:
        return a, nm
    # fallback: поиск по строке
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

    # 1. proc_p_ucred_off
    print("[*] proc_ucred...")
    p_off, p_src = analyze_proc_ucred()
    lines.append("=== proc_p_ucred_off ===")
    lines.append("  value = " + (fmt(p_off) if p_off else "NOT_FOUND"))
    lines.append("  source = " + p_src)
    lines.append("")

    # 2. ucred ids
    print("[*] ucred ids...")
    u = analyze_ucred_ids()
    lines.append("=== ucred ids ===")
    for k in sorted(u.keys()):
        lines.append("  {:<30} 0x{:X}".format(k, u[k]))
    lines.append("")

    # 3. NECP flow
    print("[*] necp flow...")
    n = analyze_necp_flow()
    lines.append("=== NECP flow struct ===")
    for k in sorted(n.keys()):
        lines.append("  {:<30} 0x{:X}".format(k, n[k]))
    lines.append("")

    # 4. AMFI
    print("[*] amfi...")
    amfi, amfi_src = analyze_amfi()
    lines.append("=== amfi_get_out_of_my_way ===")
    lines.append("  value  = " + (fmt(amfi) if amfi else "NOT_FOUND"))
    lines.append("  source = " + amfi_src)
    lines.append("")

    # Дизасм всех найденных функций
    lines.append("=== DISASM ===")
    for key in ("proc_ucred", "kauth_cred_getuid", "kauth_cred_getsvuid",
                "necp_client_add_flow", "necp_flow_alloc"):
        a, nm = find_func(TARGET_FUNCS.get(key, [key]))
        if a is None:
            continue
        lines.append("")
        lines.append("--- {} @ {} ---".format(nm, fmt(a)))
        for l in dis(a, maxl=80):
            lines.append(l)

    # Итоговый JSON
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