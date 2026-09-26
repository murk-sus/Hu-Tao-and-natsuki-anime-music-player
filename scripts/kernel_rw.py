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
    "necp_open":                  0xFFFFFFF00A4E411C,
    "necp_client_action":         0xFFFFFFF00A4E5C28,
    "necp_client_add_flow":       0xFFFFFFF00A4E843C,
    "necp_client_copy_list":      0xFFFFFFF00A4E80FC,
    "necp_client_copy_update":    0xFFFFFFF00A4EC264,
    "necp_client_copy_interface": 0xFFFFFFF00A4EAC7C,
    "necp_client_copy_result":    0xFFFFFFF00A4E7BE8,
    "necp_client_remove_client":  0xFFFFFFF00A4E76F4,
    "necp_client_remove_flow":    0xFFFFFFF00A4E93C4,
    "necp_client_copy_result_inner": 0xFFFFFFF00A4F26F0,
    "necp_client_sysctl_arena":   0xFFFFFFF00A4EB704,
    "necp_get_tlv_at_offset":     0xFFFFFFF00A4C2034,
    "copyin":                     COPYIN_ADDR,
    "copyout":                    COPYOUT_ADDR,
    "kalloc_type":                0xFFFFFFF00A200988,
    "kfree_type":                 0xFFFFFFF00A201000,
    "kalloc_type_necp_flow":      0xFFFFFFF007C62E68,
}

SOCKET_STRINGS = [
    "sock_getsockopt", "sock_setsockopt", "sock_getopt", "sock_setopt",
    "sooptcopyin", "sooptcopyout", "sbappendcontrol", "sbappendstream",
    "sbappendrecord", "m_copydata", "m_pullup", "mbuf_copydata", "mbuf_copym",
    "getsockopt error", "setsockopt error", "invalid socket option",
    "invalid option level", "socket buffer too small",
]

IOKIT_STRINGS = [
    "IOSurfaceRoot", "IOSurface", "IOConnectCallMethod", "io_connect_method",
    "IOHIDEventSystemClient", "IOMemoryDescriptor", "IOMemoryMap",
    "IOUserClient",
]

NECP_STRINGS = [
    "assigned results copyout error",
    "assigned results tlv_header copyout error",
    "copy result copyout error",
    "group members copyout error",
    "parameters copyout error",
    "necp_get_tlv_at_offset",
    "necp_client_copy_result",
]

SYMBOL_TARGETS = [
    "sock_getsockopt", "sock_setsockopt", "sooptcopyin", "sooptcopyout",
    "sbappendcontrol", "sbappendstream", "m_copydata", "m_pullup",
    "mbuf_copydata", "mbuf_copym", "sock_getopt", "sock_setopt",
    "getsockopt", "setsockopt", "sendmsg", "recvmsg",
    "IOConnectCallMethod", "IOSurfaceRoot", "io_connect_method",
    "bsd_syscall_table", "mach_trap_table",
    "kalloc_type", "kfree_type",
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


def load_symbols(path):
    print("[+] symbols: %s" % path)
    if not os.path.exists(path):
        print("[!] symbols.json not found")
        return {}
    try:
        fh = open(path)
        data = json.load(fh)
        fh.close()
    except Exception as e:
        print("[!] parse failed: %s" % e)
        return {}
    syms = {}
    if isinstance(data, list):
        for e in data:
            if not isinstance(e, dict):
                continue
            if "name" not in e or "addr" not in e:
                continue
            try:
                a = e["addr"]
                if isinstance(a, str):
                    syms[e["name"]] = int(a, 16)
                else:
                    syms[e["name"]] = int(a)
            except Exception:
                pass
    elif isinstance(data, dict):
        for k, v in data.items():
            if not isinstance(v, (int, str)):
                continue
            try:
                if isinstance(v, str) and v.startswith("0x"):
                    syms[k] = int(v, 16)
                else:
                    syms[k] = int(v)
            except Exception:
                pass
    print("[+] symbols loaded: %d" % len(syms))
    return syms


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
            out.append("  " + line.rstrip())
    except Exception as e:
        out.append("(exception: %s)" % e)
    return out


def callees(f, maxn=30):
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


def dump_zone(addr, name, lines):
    try:
        ga = sa(addr)
        if ga is None:
            lines.append("  [%s] cannot resolve" % name)
            return
        lines.append("  [%s] @ %s" % (name, fmt(addr)))
        for off in range(0, 0x40, 8):
            try:
                v = int(currentProgram.getMemory().getLong(ga.add(off))) & 0xFFFFFFFFFFFFFFFF
                lines.append("    +0x%02X: %s" % (off, fmt(v)))
            except Exception as e:
                lines.append("    +0x%02X: err %s" % (off, e))
                break
    except Exception as e:
        lines.append("  [%s] exception: %s" % (name, e))


def main():
    lines = []
    offsets_out = {}
    print("=== kernel_rw.py v19 (mbuf+io+necp) ===")

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
    lines.append("### A. NECP SANITY")
    lines.append("=" * 68)
    for name, addr in NECP_BASE.items():
        f = get_func(addr)
        if f:
            ent = _u(f.getEntryPoint().getOffset())
            sz = 0
            try:
                sz = int(f.getBody().getNumAddresses())
            except Exception:
                pass
            lines.append("  %-30s %s  size=0x%X" % (name, fmt(ent), sz))
            offsets_out[name] = fmt(ent)
        else:
            lines.append("  %-30s %s  (no function)" % (name, fmt(addr)))
            offsets_out[name] = fmt(addr)
    lines.append("")

    lines.append("=" * 68)
    lines.append("### B. STRING XREF SCAN")
    lines.append("=" * 68)

    def scan_strings(label, needles):
        lines.append("")
        lines.append("--- %s ---" % label)
        for needle in needles:
            found_at = find_string_bytes(needle)
            if found_at is None:
                lines.append("  %-45s : not found" % needle)
                continue
            lines.append("  %-45s : %s" % (needle, fmt(found_at)))
            ga = sa(found_at)
            xrefs = collect_xrefs(ga, limit=12)
            if not xrefs:
                lines.append("      no xrefs")
                continue
            for ent, nm, cnt in xrefs:
                lines.append("      %-30s @ %s  (%d refs)" % (nm[:30], fmt(ent), cnt))
                offsets_out["str_%s_%s" % (label, nm[:24])] = fmt(ent)

    scan_strings("SOCKET", SOCKET_STRINGS)
    scan_strings("IOKIT", IOKIT_STRINGS)
    scan_strings("NECP", NECP_STRINGS)
    lines.append("")

    lines.append("=" * 68)
    lines.append("### C. SYMBOL LOOKUPS")
    lines.append("=" * 68)
    for name in SYMBOL_TARGETS:
        if name in syms:
            addr = syms[name]
            f = get_func(addr)
            sz = 0
            if f:
                try:
                    sz = int(f.getBody().getNumAddresses())
                except Exception:
                    pass
            lines.append("  %-32s %s  size=0x%X" % (name, fmt(addr), sz))
            offsets_out[name] = fmt(addr)
    lines.append("")

    lines.append("=" * 68)
    lines.append("### D. COPYIN / COPYOUT CALL SITES")
    lines.append("=" * 68)
    for label, addr in [("copyin", COPYIN_ADDR), ("copyout", COPYOUT_ADDR)]:
        lines.append("")
        lines.append("--- %s @ %s ---" % (label, fmt(addr)))
        ga = sa(addr)
        xrefs = collect_xrefs(ga, limit=30)
        if not xrefs:
            lines.append("  no xrefs")
            continue
        for ent, nm, cnt in xrefs:
            lines.append("  %s  %-40s  calls=%d" % (fmt(ent), nm[:40], cnt))
            offsets_out["%s_callsite_%s" % (label, nm[:20])] = fmt(ent)
    lines.append("")

    lines.append("=" * 68)
    lines.append("### E. KALLOC_TYPE zone")
    lines.append("=" * 68)
    dump_zone(0xFFFFFFF007C62E68, "necp_client_flow", lines)
    lines.append("")

    lines.append("=" * 68)
    lines.append("### F. DECOMPILE")
    lines.append("=" * 68)

    decompile_set = set()

    for group, needles in [("SOCKET", SOCKET_STRINGS),
                           ("IOKIT", IOKIT_STRINGS),
                           ("NECP", NECP_STRINGS)]:
        for needle in needles:
            at = find_string_bytes(needle)
            if at is None:
                continue
            xrefs = collect_xrefs(sa(at), limit=4)
            for ent, nm, cnt in xrefs:
                decompile_set.add((ent, nm))

    for name in SYMBOL_TARGETS:
        if name in syms:
            f = get_func(syms[name])
            if f:
                ent = _u(f.getEntryPoint().getOffset())
                decompile_set.add((ent, name))

    for label, addr in [("copyin", COPYIN_ADDR), ("copyout", COPYOUT_ADDR)]:
        xrefs = collect_xrefs(sa(addr), limit=20)
        for ent, nm, cnt in xrefs:
            decompile_set.add((ent, nm))

    targets = sorted(decompile_set)
    lines.append("total targets: %d" % len(targets))
    lines.append("")

    for ent, nm in targets:
        f = get_func(ent)
        if not f:
            lines.append("=== %s @ %s : no func ===" % (nm, fmt(ent)))
            continue
        sz = 0
        try:
            sz = int(f.getBody().getNumAddresses())
        except Exception:
            pass
        lines.append("=" * 68)
        lines.append("=== %s @ %s  size=0x%X ===" % (nm, fmt(ent), sz))
        lines.append("=" * 68)

        lines.append("--- CALLEES ---")
        cs = callees(f, maxn=30)
        for e, n, sz2 in cs:
            lines.append("  %s  %-40s size=0x%X" % (fmt(e), n[:40], sz2))
        lines.append("")

        lines.append("--- DECOMPILE %s ---" % nm)
        for l in decompile(f, 300):
            lines.append(l)
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