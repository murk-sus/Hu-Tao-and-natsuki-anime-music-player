# -*- coding: utf-8 -*-
import os
import json

try:
    string_types = (str, unicode)
except NameError:
    string_types = (str,)

WORKSPACE = os.environ.get("GITHUB_WORKSPACE", "/tmp")
SYMBOLS_JSON = os.environ.get("SYMBOLS_JSON",
                os.path.join(WORKSPACE, "symbols.json"))

_sym_cache = None
_string_map = None
_string_list = None
_syms_index = None
IFC = [None]


def _to_unsigned(v):
    return int(v) & 0xFFFFFFFFFFFFFFFF


def _parse_addr(v):
    if v is None:
        return None
    try:
        if isinstance(v, (int, long)):
            return _to_unsigned(v)
        if not isinstance(v, string_types):
            return None
        s = v.strip()
        if not s:
            return None
        if s.startswith(("0x", "0X")):
            return _to_unsigned(int(s, 16))
        return _to_unsigned(int(s, 10))
    except Exception:
        return None


def _load_symbols():
    global _sym_cache
    if _sym_cache is not None:
        return
    _sym_cache = {}

    if not os.path.exists(SYMBOLS_JSON):
        print("[-] symbols.json not found: " + SYMBOLS_JSON)
        return
    try:
        with open(SYMBOLS_JSON) as f:
            raw = f.read().strip()
        if not raw:
            print("[-] symbols.json is empty")
            return
        data = json.loads(raw)
    except Exception as e:
        print("[-] symbols.json parse error: " + str(e))
        return

    def _add(name, addr):
        if name is None or addr is None:
            return
        if not isinstance(name, string_types):
            name = str(name)
        name = name.strip()
        if not name:
            return
        v = _parse_addr(addr)
        if v is None:
            return
        if v < 0xFFFF000000000000:
            return
        _sym_cache[name] = v
        if not name.startswith("_"):
            _sym_cache["_" + name] = v

    def _walk(node):
        if isinstance(node, dict):
            nm = node.get("name") or node.get("symbol")
            ad = node.get("address") or node.get("addr") or node.get("value")
            if nm and ad is not None:
                _add(nm, ad)
                return
            for k, v in node.items():
                k_addr = _parse_addr(k)
                v_addr = _parse_addr(v)
                if k_addr is not None and isinstance(v, string_types) and v_addr is None:
                    _add(v, k_addr)
                elif v_addr is not None and isinstance(k, string_types) and k_addr is None:
                    _add(k, v_addr)
                elif isinstance(v, (dict, list)):
                    _walk(v)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(data)
    print("[+] symbols loaded: " + str(len(_sym_cache)))


def sym_get(name):
    _load_symbols()
    if name in _sym_cache:
        return _sym_cache[name]
    bare = name.lstrip("_")
    if bare in _sym_cache:
        return _sym_cache[bare]
    if "_" + name in _sym_cache:
        return _sym_cache["_" + name]
    lower = name.lower()
    for k, v in _sym_cache.items():
        if k.lower() == lower:
            return v
    return None


def sym_all():
    _load_symbols()
    return dict(_sym_cache)


def fmt(v):
    return "0x{:016X}".format(v & 0xFFFFFFFFFFFFFFFF)


def to_long(v):
    v = int(v) & 0xFFFFFFFFFFFFFFFF
    if v >= 0x8000000000000000:
        v -= 0x10000000000000000
    return v


def safe_addr(a):
    try:
        return toAddr(to_long(a))
    except Exception:
        return None


def read_u64(a):
    ga = safe_addr(a)
    if ga is None:
        return None
    try:
        return int(currentProgram.getMemory().getLong(ga)) & 0xFFFFFFFFFFFFFFFF
    except Exception:
        return None


def read_u32(a):
    ga = safe_addr(a)
    if ga is None:
        return None
    try:
        return int(currentProgram.getMemory().getInt(ga)) & 0xFFFFFFFF
    except Exception:
        return None


def is_kva(v):
    return v is not None and 0xFFFFFFF000000000 <= v < 0xFFFFFFF200000000


def _build_string_map():
    global _string_map, _string_list
    if _string_map is not None:
        return
    _string_map = {}
    _string_list = []
    listing = currentProgram.getListing()
    it = listing.getDefinedData(True)
    while it.hasNext():
        d = it.next()
        try:
            if not d.hasStringValue():
                continue
            v = d.getValue()
            if v is None:
                continue
            s = str(v)
            a = _to_unsigned(d.getAddress().getOffset())
            _string_list.append((a, s))
            if s not in _string_map:
                _string_map[s] = a
        except Exception:
            pass
    print("[+] strings indexed: " + str(len(_string_list)))


def find_str_exact(s):
    _build_string_map()
    return _string_map.get(s)


def find_str_contains(sub):
    _build_string_map()
    out = []
    for a, s in _string_list:
        if sub in s:
            out.append((a, s))
    return out


def _build_sym_index():
    global _syms_index
    if _syms_index is not None:
        return
    _syms_index = []
    st = currentProgram.getSymbolTable()
    try:
        for sym in st.getAllSymbols(True):
            try:
                _syms_index.append(
                    (_to_unsigned(sym.getAddress().getOffset()), sym.getName()))
            except Exception:
                pass
    except Exception:
        pass
    print("[+] symtable indexed: " + str(len(_syms_index)))


def _is_junk_sym(name):
    if name.startswith("s_") and "_" in name[3:]:
        tail = name.rsplit("_", 1)[-1]
        try:
            int(tail, 16)
            return True
        except Exception:
            pass
    for pfx in ("DAT_", "LAB_", "UNK_", "SUB_", "OFF_", "ADJ_", "EXTERNAL_"):
        if name.startswith(pfx):
            return True
    return False


def syms_named(pat, include_junk=False):
    _build_sym_index()
    out = []
    for a, n in _syms_index:
        if not include_junk and _is_junk_sym(n):
            continue
        if pat in n:
            out.append((a, n))
    return out


def funcs_named(pat):
    _build_sym_index()
    out = []
    for a, n in _syms_index:
        if _is_junk_sym(n):
            continue
        if pat not in n:
            continue
        f = func_at(a)
        if f is not None:
            ep = int(f.getEntryPoint().getOffset()) & 0xFFFFFFFFFFFFFFFF
            if ep == a:
                out.append((a, n))
    return out


def xrefs_to(addr):
    refs = []
    ga = safe_addr(addr)
    if ga is None:
        return refs
    rm = currentProgram.getReferenceManager()
    try:
        for r in rm.getReferencesTo(ga):
            refs.append(int(r.getFromAddress().getOffset()) & 0xFFFFFFFFFFFFFFFF)
    except Exception:
        pass
    return refs


def func_at(addr):
    ga = safe_addr(addr)
    if ga is None:
        return None
    try:
        f = getFunctionAt(ga)
        if f:
            return f
    except Exception:
        pass
    try:
        return getFunctionContaining(ga)
    except Exception:
        return None


def ensure_func(addr):
    f = func_at(addr)
    if f:
        return f
    ga = safe_addr(addr)
    if ga is None:
        return None
    try:
        disassemble(ga)
    except Exception:
        pass
    try:
        return createFunction(ga, None)
    except Exception:
        return None


def decompile(f):
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.util.task import ConsoleTaskMonitor
    if f is None:
        return ""
    if IFC[0] is None:
        ifc = DecompInterface()
        ifc.setOptions(DecompileOptions())
        ifc.openProgram(currentProgram)
        IFC[0] = ifc
    try:
        r = IFC[0].decompileFunction(f, 120, ConsoleTaskMonitor())
        if r.decompileCompleted():
            return r.getDecompiledFunction().getC()
    except Exception:
        pass
    return ""


def write_lines(path, lines):
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        try:
            os.makedirs(d)
        except Exception:
            pass
    with open(path, "w") as fh:
        for line in lines:
            fh.write(line + "\n")


def resolve_adrp_pairs(func,
                       want_lo=0xFFFFFFF000000000,
                       want_hi=0xFFFFFFF200000000):
    """
    Walk instructions of `func`, resolve ADRP+ADD / ADRP+LDR / ADRP+STR pairs.
    Returns list of (insn_addr, target_kva, kind).
    """
    if func is None:
        return []
    listing = currentProgram.getListing()
    body = func.getBody()
    if body is None:
        return []
    insn = listing.getInstructionAt(body.getMinAddress())
    out = []
    prev = None
    while insn is not None and body.contains(insn.getAddress()):
        mn = insn.getMnemonicString().lower()
        txt = insn.toString()
        if mn == "adrp":
            try:
                toks = txt.replace(",", " ").split()
                page = int(toks[-1], 16) & 0xFFFFFFFFFFFFFFFF
                prev = (toks[1], page)
            except Exception:
                prev = None
        elif prev is not None and mn in ("add", "ldr", "str", "ldrb", "strb",
                                          "ldrh", "strh"):
            try:
                toks = txt.replace(",", " ").replace("[", " ").replace("]", " ").split()
                imm = 0
                for t in toks:
                    if t.startswith("#0x"):
                        imm = int(t[3:], 16)
                        break
                base_reg = toks[2] if len(toks) > 2 else ""
                if base_reg == prev[0]:
                    tgt = (prev[1] + imm) & 0xFFFFFFFFFFFFFFFF
                    if want_lo <= tgt < want_hi:
                        out.append((
                            int(insn.getAddress().getOffset()) & 0xFFFFFFFFFFFFFFFF,
                            tgt, mn))
            except Exception:
                pass
            prev = None
        else:
            if mn not in ("nop", "bti", "pacibsp", "hint"):
                prev = None
        insn = insn.getNext()
    return out