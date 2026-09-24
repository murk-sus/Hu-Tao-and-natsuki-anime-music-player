# -*- coding: utf-8 -*-
import os
import json

WORKSPACE   = os.environ.get("GITHUB_WORKSPACE", "/tmp")
SYMBOLS_JSON = os.environ.get("SYMBOLS_JSON",
                os.path.join(WORKSPACE, "symbols.json"))

_sym_cache = {}

def _load():
    global _sym_cache
    if _sym_cache:
        return
    if not os.path.exists(SYMBOLS_JSON):
        print("[-] symbols.json not found: " + SYMBOLS_JSON)
        return
    try:
        with open(SYMBOLS_JSON) as f:
            raw = f.read().strip()
        if not raw:
            return
        data = json.loads(raw)
    except Exception as e:
        print("[-] symbols.json parse error: " + str(e))
        return

    def _add(name, addr):
        if not name or addr is None:
            return
        try:
            if isinstance(addr, str):
                v = int(addr, 16) if addr.startswith(("0x","0X")) else int(addr, 0)
            else:
                v = int(addr)
            u = v & 0xFFFFFFFFFFFFFFFF
            _sym_cache[name] = u
            if not name.startswith("_"):
                _sym_cache["_" + name] = u
        except Exception:
            pass

    def _walk(node):
        if isinstance(node, dict):
            name = node.get("name") or node.get("symbol")
            addr = node.get("address") or node.get("addr") or node.get("value")
            if name and addr is not None:
                _add(name, addr)
                return
            for k, v in node.items():
                if isinstance(v, str) and v.startswith(("0x","0X")):
                    _add(k, v)
                else:
                    _walk(v)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(data)
    print("[+] symbols loaded: " + str(len(_sym_cache)))

_load()

def sym_get(name):
    _load()
    if name in _sym_cache:
        return _sym_cache[name]
    bare = name.lstrip("_")
    for cand in (bare, "_" + name):
        if cand in _sym_cache:
            return _sym_cache[cand]
    lower = name.lower()
    for k, v in _sym_cache.items():
        if k.lower() == lower:
            return v
    return None

def sym_all():
    _load()
    return dict(_sym_cache)

def fmt(v):
    return "0x{:016X}".format(v & 0xFFFFFFFFFFFFFFFF)

def to_long(v):
    v = int(v) & 0xFFFFFFFFFFFFFFFF
    if v >= 0x8000000000000000:
        v -= 0x10000000000000000
    return int(v)

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

def syms_named(pat):
    out = []
    st = currentProgram.getSymbolTable()
    try:
        for sym in st.getAllSymbols(True):
            n = sym.getName()
            if pat in n:
                try:
                    out.append((int(sym.getAddress().getOffset()) & 0xFFFFFFFFFFFFFFFF, n))
                except Exception:
                    pass
    except Exception:
        pass
    return out

def find_str_exact(s):
    listing = currentProgram.getListing()
    it = listing.getDefinedData(True)
    while it.hasNext():
        d = it.next()
        try:
            if d.hasStringValue() and str(d.getValue()) == s:
                return int(d.getAddress().getOffset()) & 0xFFFFFFFFFFFFFFFF
        except Exception:
            pass
    return None

def find_str_contains(sub):
    results = []
    listing = currentProgram.getListing()
    it = listing.getDefinedData(True)
    while it.hasNext():
        d = it.next()
        try:
            if d.hasStringValue():
                val = str(d.getValue())
                if sub in val:
                    results.append((int(d.getAddress().getOffset()) & 0xFFFFFFFFFFFFFFFF, val))
        except Exception:
            pass
    return results

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

IFC = [None]

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
    with open(path, "w") as fh:
        for line in lines:
            fh.write(line + "\n")

print("[+] 00_load_symbols.py done")
