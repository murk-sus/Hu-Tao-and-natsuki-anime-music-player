# -*- coding: utf-8 -*-
# @runtime Jython

import os
import json
import traceback
from jarray import zeros
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor, TaskMonitor

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WS, "result.txt")
OUT_OFF = os.path.join(WS, "offsets.json")
SYMBOLS_JSON = os.environ.get("SYMBOLS_JSON", os.path.join(WS, "symbols.json"))

COPYIN_ADDR  = 0xFFFFFFF00A368EC0
COPYOUT_ADDR = 0xFFFFFFF00A369A3C

NECP_BASE = {
    "necp_open":                     0xFFFFFFF00A4E411C,
    "necp_client_action":            0xFFFFFFF00A4E5C28,
    "necp_client_add_flow":          0xFFFFFFF00A4E843C,
    "necp_client_copy_list":         0xFFFFFFF00A4E80FC,
    "necp_client_copy_update":       0xFFFFFFF00A4EC264,
    "necp_client_copy_interface":    0xFFFFFFF00A4EAC7C,
    "necp_client_copy_result":       0xFFFFFFF00A4E7BE8,
    "necp_client_remove_client":     0xFFFFFFF00A4E76F4,
    "necp_client_remove_flow":       0xFFFFFFF00A4E93C4,
    "necp_client_copy_result_inner": 0xFFFFFFF00A4F26F0,
    "necp_client_sysctl_arena":      0xFFFFFFF00A4EB704,
    "necp_get_tlv_at_offset":        0xFFFFFFF00A4C2034,
    "copyin":                        COPYIN_ADDR,
    "copyout":                       COPYOUT_ADDR,
    "kalloc_type":                   0xFFFFFFF00A200988,
    "kfree_type":                    0xFFFFFFF00A201000,
    "kalloc_type_necp_flow":         0xFFFFFFF007C62E68,
}

TARGETS = [
    ("sooptcopyin",             0xFFFFFFF00A77FD2C),
    ("sbappendcontrol",         0xFFFFFFF00A788A24),
    ("sbappendstream",          0xFFFFFFF00A78811C),
    ("sbappendrecord",          0xFFFFFFF00A7873B8),
    ("necp_get_tlv_at_offset",  0xFFFFFFF00A4C2034),
    ("necp_client_add_flow",    0xFFFFFFF00A4E843C),
    ("necp_update_cache",       0xFFFFFFF00A4EBD58),
    ("necp_per_flow_copy",      0xFFFFFFF00A4F2E70),
    ("necp_flow_alloc",         0xFFFFFFF00A346E70),
    ("necp_handler_big",        0xFFFFFFF00A3D91B4),
    ("copyin_hot_1",            0xFFFFFFF00A6CEB84),
    ("copyout_hot_1",           0xFFFFFFF00A6F18AC),
    ("copyout_hot_2",           0xFFFFFFF00A6F318C),
    ("copyin_hot_2",            0xFFFFFFF00A753850),
]

PATTERNS = [
    "copyout", "copyin", "kalloc_type", "kfree_type",
    "memcpy", "memmove", "bcopy", "bzero",
    "panic", "overflow", "len", "length", "size",
    "bound", "limit", "alloc",
]


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
        return currentProgram.getAddressFactory().getAddress(
            "%X" % (int(a) & 0xFFFFFFFFFFFFFFFF))
    except Exception:
        return None


def _try_int(v):
    if v is None:
        return None
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, long):
        return int(v)
    if isinstance(v, float):
        return int(v)
    if isinstance(v, str):
        s = v.strip()
        try:
            if s.startswith("0x") or s.startswith("0X"):
                return int(s, 16)
            if s.startswith("$"):
                return None
            return int(s)
        except Exception:
            return None
    return None


def _is_kernel_addr(v):
    i = _try_int(v)
    if i is None:
        return None
    if i < 0xFFFFFFF000000000:
        return None
    if i > 0xFFFFFFFFFFFFFFFF:
        return None
    return i


def load_symbols(path):
    print("[+] symbols.json: %s" % path)
    if not os.path.exists(path):
        print("[!] not found")
        return {}
    try:
        fh = open(path)
        data = json.load(fh)
        fh.close()
    except Exception as e:
        print("[!] parse failed: %s" % e)
        return {}

    syms = {}
    diag = {"dict": 0, "list": 0, "pairs": 0, "skip": 0}

    def add(name, addr):
        if not isinstance(name, str):
            diag["skip"] += 1
            return
        n = name.strip()
        if not n:
            diag["skip"] += 1
            return
        a = _try_int(addr)
        if a is None:
            diag["skip"] += 1
            return
        syms[n] = a
        diag["pairs"] += 1

    def walk(node, depth=0):
        if depth > 8:
            return
        if isinstance(node, dict):
            diag["dict"] += 1
            n = None
            a = None
            for nk in ("name", "symbol", "sym", "n"):
                if nk in node and isinstance(node[nk], str):
                    n = node[nk]
                    break
            for ak in ("addr", "address", "value", "v"):
                if ak in node:
                    a = node[ak]
                    break
            if n is not None and a is not None:
                add(n, a)
                return
            for k, v in node.items():
                ka = _is_kernel_addr(k)
                if ka is not None:
                    if isinstance(v, str):
                        add(v, ka)
                        continue
                    if isinstance(v, dict):
                        nn = None
                        for nk in ("name", "symbol", "sym"):
                            if nk in v and isinstance(v[nk], str):
                                nn = v[nk]
                                break
                        if nn is not None:
                            add(nn, ka)
                            continue
                    diag["skip"] += 1
                    continue
                kv = _is_kernel_addr(v)
                if kv is not None and isinstance(k, str):
                    add(k, kv)
                    continue
                walk(v, depth + 1)
        elif isinstance(node, list):
            diag["list"] += 1
            for item in node:
                walk(item, depth + 1)

    walk(data)

    print("[+] symbols loaded: %d" % len(syms))
    print("[+] diag: dict=%d list=%d pairs=%d skip=%d" % (
        diag["dict"], diag["list"], diag["pairs"], diag["skip"]))

    if len(syms) == 0:
        print("[!] first-level keys sample:")
        if isinstance(data, dict):
            cnt = 0
            for k in data.keys():
                v = data[k]
                print("    key=%r type=%s val_type=%s val=%r" % (
                    k, type(k).__name__, type(v).__name__, str(v)[:60]))
                cnt += 1
                if cnt >= 5:
                    break
        elif isinstance(data, list):
            print("    list len=%d" % len(data))
            if data:
                print("    item[0]=%r" % (data[0],))
    else:
        cnt = 0
        for name in sorted(syms.keys()):
            print("    %s = %s" % (name, fmt(syms[name])))
            cnt += 1
            if cnt >= 15:
                break
    return syms


_blocks_cache = None


def blocks():
    global _blocks_cache
    if _blocks_cache is not None:
        return _blocks_cache
    out = []
    try:
        for b in currentProgram.getMemory().getBlocks():
            try:
                if not b.isInitialized():
                    continue
                s = _u(b.getStart().getOffset())
                e = _u(b.getEnd().getOffset())
                n = str(b.getName())
                x = bool(b.isExecute())
                out.append((s, e, n, x))
            except Exception:
                pass
    except Exception:
        pass
    _blocks_cache = out
    return out


def inblk(a):
    if a is None:
        return None
    av = _u(a)
    for s, e, n, x in blocks():
        if s <= av < e:
            return (s, e, n, x)
    return None


def get_func(addr):
    try:
        ga = sa(addr)
        if ga is None:
            return None
        f = getFunctionAt(ga)
        if f is not None:
            return f
        return getFunctionContaining(ga)
    except Exception:
        return None


def find_string_bytes(needle):
    try:
        mem = currentProgram.getMemory()
        jn = zeros(len(needle), 'b')
        for i in range(len(needle)):
            v = ord(needle[i])
            if v > 127:
                v -= 256
            jn[i] = v
        h = mem.findBytes(mem.getMinAddress(), jn, None, True, TaskMonitor.DUMMY)
        if h is not None:
            return _u(h.getOffset())
    except Exception:
        pass
    return None


def decompile(f, timeout=300):
    out = []
    try:
        d = DecompInterface()
        d.openProgram(currentProgram)
        r = d.decompileFunction(f, timeout, ConsoleTaskMonitor())
        if r is None:
            return ["(no result)"]
        if not r.decompileCompleted():
            return ["(failed: %s)" % str(r.getErrorMessage())]
        c = r.getDecompiledFunction()
        if c is None:
            return ["(empty)"]
        for line in c.getC().split("\n"):
            out.append(line.rstrip())
    except Exception as e:
        out.append("(exception: %s)" % e)
    return out


def callees(f, maxn=25):
    try:
        cf = f.getCalledFunctions(ConsoleTaskMonitor())
    except Exception:
        return []
    out = []
    if not cf:
        return out
    try:
        for c in cf:
            try:
                e = _u(c.getEntryPoint().getOffset())
                n = str(c.getName())
                sz = 0
                try:
                    sz = int(c.getBody().getNumAddresses())
                except Exception:
                    pass
                out.append((e, n, sz))
            except Exception:
                pass
    except Exception:
        pass
    out.sort(key=lambda x: x[0])
    return out[:maxn]


def collect_xrefs(ga, limit=24):
    out = []
    try:
        refs = getReferencesTo(ga)
    except Exception:
        return out
    if refs is None:
        return out
    by_func = {}
    try:
        for r in refs:
            try:
                fa = r.getFromAddress()
                fn = getFunctionContaining(fa)
                if fn is None:
                    continue
                ent = _u(fn.getEntryPoint().getOffset())
                nm = str(fn.getName())
                if ent not in by_func:
                    by_func[ent] = (nm, 0)
                by_func[ent] = (nm, by_func[ent][1] + 1)
            except Exception:
                pass
    except Exception:
        pass
    items = sorted(by_func.items(), key=lambda kv: -kv[1][1])[:limit]
    for ent, (nm, cnt) in items:
        out.append((ent, nm, cnt))
    return out


def dump_mem_ops(f, lines, cap=0x2000):
    seen = set()
    body = f.getBody()
    if body is None:
        return
    try:
        it = body.getAddresses(True)
    except Exception:
        return
    cnt = 0
    while it.hasNext() and cnt < 8000:
        a = it.next()
        try:
            pc = _u(a.getOffset())
            raw = int(currentProgram.getMemory().getInt(a)) & 0xFFFFFFFF
        except Exception:
            cnt += 1
            continue
        cnt += 1
        kind = None
        base = 0
        imm = 0
        if (raw & 0xFFC00000) == 0xF9400000:
            kind, base, imm = "ldr_x", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 8
        elif (raw & 0xFFC00000) == 0xB9400000:
            kind, base, imm = "ldr_w", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 4
        elif (raw & 0xFFC00000) == 0xF9000000:
            kind, base, imm = "str_x", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 8
        elif (raw & 0xFFC00000) == 0xB9000000:
            kind, base, imm = "str_w", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 4
        elif (raw & 0xFFE00000) == 0x39400000:
            kind, base, imm = "ldrb", (raw >> 5) & 0x1F, (raw >> 10) & 0xFFF
        elif (raw & 0xFFE00000) == 0x39000000:
            kind, base, imm = "strb", (raw >> 5) & 0x1F, (raw >> 10) & 0xFFF
        elif (raw & 0xFFE00000) == 0x79400000:
            kind, base, imm = "ldrh", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 2
        elif (raw & 0xFFE00000) == 0x79000000:
            kind, base, imm = "strh", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 2
        elif (raw & 0xFFC00000) == 0xF8400000:
            i = (raw >> 12) & 0x1FF
            if i & 0x100:
                i -= 0x200
            kind, base, imm = "ldur_x", (raw >> 5) & 0x1F, i
        elif (raw & 0xFFC00000) == 0xB8400000:
            i = (raw >> 12) & 0x1FF
            if i & 0x100:
                i -= 0x200
            kind, base, imm = "ldur_w", (raw >> 5) & 0x1F, i
        else:
            continue
        if imm < 0 or imm > cap:
            continue
        key = (kind, base, imm)
        if key in seen:
            continue
        seen.add(key)
        lines.append("  %s  %-8s  [x%-2d, #0x%X]" % (fmt(pc), kind, base, imm))


def keyword_scan(declines):
    hits = []
    for idx, line in enumerate(declines):
        low = line.lower()
        for pat in PATTERNS:
            if pat in low:
                hits.append((idx, line))
                break
    return hits


def resolve_target(name, hardcoded, syms):
    if name in syms:
        return syms[name], "symbol"
    for k in syms:
        if k == name or k.lstrip("_") == name:
            return syms[k], "symbol"
    return hardcoded, "hardcoded"


def main():
    lines = []
    offsets_out = {}
    print("=== kernel_rw.py v22 ===")

    lines.append("=== PROGRAM ===")
    lines.append("name = %s" % currentProgram.getName())
    try:
        lines.append("min  = %s" % fmt(currentProgram.getMemory().getMinAddress().getOffset()))
        lines.append("max  = %s" % fmt(currentProgram.getMemory().getMaxAddress().getOffset()))
    except Exception:
        pass
    lines.append("")

    syms = load_symbols(SYMBOLS_JSON)

    lines.append("=== SYMBOLS ===")
    lines.append("loaded = %d" % len(syms))
    if syms:
        cnt = 0
        for name in sorted(syms.keys()):
            if cnt >= 30:
                break
            lines.append("  %s = %s" % (name, fmt(syms[name])))
            cnt += 1
    lines.append("")

    lines.append("=" * 68)
    lines.append("### NECP SANITY")
    lines.append("=" * 68)
    for name, addr in NECP_BASE.items():
        real, src = resolve_target(name, addr, syms)
        f = get_func(real)
        if f:
            ent = _u(f.getEntryPoint().getOffset())
            sz = 0
            try:
                sz = int(f.getBody().getNumAddresses())
            except Exception:
                pass
            lines.append("  %-32s %s (%s) size=0x%X" % (name, fmt(ent), src, sz))
            offsets_out[name] = fmt(ent)
        else:
            lines.append("  %-32s %s (%s, no func)" % (name, fmt(real), src))
            offsets_out[name] = fmt(real)
    lines.append("")

    lines.append("=" * 68)
    lines.append("### TARGETS")
    lines.append("=" * 68)

    for label, addr in TARGETS:
        real, src = resolve_target(label, addr, syms)
        f = get_func(real)
        if not f:
            lines.append("")
            lines.append("=== %s @ %s (%s) : NO FUNCTION ===" % (label, fmt(real), src))
            continue
        ent = _u(f.getEntryPoint().getOffset())
        sz = 0
        try:
            sz = int(f.getBody().getNumAddresses())
        except Exception:
            pass
        lines.append("")
        lines.append("=" * 68)
        lines.append("=== %s @ %s (%s) size=0x%X ===" % (label, fmt(ent), src, sz))
        lines.append("=" * 68)
        offsets_out[label] = fmt(ent)

        lines.append("--- CALLEES ---")
        cs = callees(f, maxn=25)
        for e, n, sz2 in cs:
            lines.append("  %s  %-40s size=0x%X" % (fmt(e), n[:40], sz2))
        lines.append("")

        lines.append("--- MEM OPS ---")
        dump_mem_ops(f, lines, cap=0x2000)
        lines.append("")

        body = decompile(f, 300)

        lines.append("--- KEYWORD SCAN ---")
        hits = keyword_scan(body)
        if not hits:
            lines.append("  (no hits)")
        for idx, hl in hits[:120]:
            lines.append("  %4d: %s" % (idx, hl))
        lines.append("")

        lines.append("--- DECOMPILE ---")
        for l in body:
            lines.append("  " + l)
        lines.append("")

    lines.append("=" * 68)
    lines.append("### STRING XREF")
    lines.append("=" * 68)
    needles = [
        "assigned results copyout error",
        "copy result copyout error",
        "group members copyout error",
        "parameters copyout error",
        "necp_get_tlv_at_offset",
        "sock_getsockopt",
        "sooptcopyin",
        "sbappendcontrol",
    ]
    for needle in needles:
        found_at = find_string_bytes(needle)
        if found_at is None:
            lines.append("  %-45s : not found" % needle)
            continue
        lines.append("  %-45s : %s" % (needle, fmt(found_at)))
        xrefs = collect_xrefs(sa(found_at), limit=8)
        if not xrefs:
            lines.append("      no xrefs")
            continue
        for ent, nm, cnt in xrefs:
            lines.append("      %-30s @ %s (%d refs)" % (nm[:30], fmt(ent), cnt))
    lines.append("")

    try:
        fh = open(OUT, "w")
        for l in lines:
            fh.write(l + "\n")
        fh.close()
        print("[+] wrote " + OUT)
    except Exception as e:
        print("[-] result: %s" % e)

    try:
        fh = open(OUT_OFF, "w")
        fh.write(json.dumps(offsets_out, indent=2, sort_keys=True))
        fh.close()
        print("[+] wrote " + OUT_OFF)
    except Exception as e:
        print("[-] offsets: %s" % e)

    print("=== DONE ===")


try:
    main()
except Exception as e:
    print("[-] FATAL: %s" % e)
    traceback.print_exc()