# -*- coding: utf-8 -*-
# @runtime Jython
# kernel_rw.py v54 - full sysent dump with symbol resolution

import os
import sys
import json
import traceback

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WS, "result.txt")
SYMBOLS_JSON = os.environ.get("SYMBOLS_JSON", os.path.join(WS, "symbols.json"))
SEP = "=" * 72

SYSENT_BASE = int("FFFFFFF007C192A0", 16)
SYSENT_STRIDE = 24
SYSENT_COUNT = 558
KERNEL_BASE = int("FFFFFFF007004000", 16)

NECP_LO = int("FFFFFFF00A300000", 16)
NECP_HI = int("FFFFFFF00A520000", 16)

L = []


def log(m):
    print(m)
    sys.stdout.flush()


def w(s):
    L.append(s)


def _u(v):
    return int(v) & 0xFFFFFFFFFFFFFFFF


def fmt(v):
    try:
        return "0x%016X" % (int(v) & 0xFFFFFFFFFFFFFFFF)
    except Exception:
        return "0x0"


def sa(a):
    try:
        return currentProgram.getAddressFactory().getAddress(
            "%X" % (int(a) & 0xFFFFFFFFFFFFFFFF))
    except Exception:
        return None


def read_u16(addr):
    try:
        ga = sa(addr)
        if ga is None:
            return None
        b = getBytes(ga, 2)
        if b is None:
            return None
        return (b[0] & 0xFF) | ((b[1] & 0xFF) << 8)
    except Exception:
        return None


def read_u32(addr):
    try:
        ga = sa(addr)
        if ga is None:
            return None
        b = getBytes(ga, 4)
        if b is None:
            return None
        return (b[0] & 0xFF) | ((b[1] & 0xFF) << 8) | ((b[2] & 0xFF) << 16) | ((b[3] & 0xFF) << 24)
    except Exception:
        return None


def read_u64(addr):
    try:
        ga = sa(addr)
        if ga is None:
            return None
        b = getBytes(ga, 8)
        if b is None:
            return None
        r = 0
        for i in range(8):
            r = r | ((b[i] & 0xFF) << (i * 8))
        return r
    except Exception:
        return None


def unpack(raw):
    if raw is None or raw == 0:
        return None
    low = raw & 0xFFFFFFFF
    if low < 0x1000:
        return None
    if low > 0x4000000:
        return None
    return KERNEL_BASE + low


def load_symbols(path):
    if not os.path.exists(path):
        log("[!] symbols missing")
        return {}
    try:
        fh = open(path)
        data = json.load(fh)
        fh.close()
    except Exception as e:
        log("[!] parse fail %s" % e)
        return {}
    out = {}
    if isinstance(data, dict):
        for k, v in data.items():
            try:
                a = int(k)
                if isinstance(v, str):
                    out[a] = v
            except Exception:
                pass
    log("[+] symbols loaded: %d" % len(out))
    return out


def resolve_name(addr, syms):
    if addr is None:
        return "?"
    n = syms.get(addr)
    if n is not None:
        return n
    # try function container
    try:
        ga = sa(addr)
        if ga is None:
            return "?"
        f = getFunctionAt(ga) or getFunctionContaining(ga)
        if f is not None:
            return str(f.getName())
    except Exception:
        pass
    return "?"


def main():
    log("=== kernel_rw.py v54 sysent dump ===")

    syms = load_symbols(SYMBOLS_JSON)

    w("natsuk1 sysent full dump v54")
    w("base=%s stride=%d count=%d" % (fmt(SYSENT_BASE), SYSENT_STRIDE, SYSENT_COUNT))
    w("kernel_base=%s" % fmt(KERNEL_BASE))
    w("symbols_loaded=%d" % len(syms))
    w("")

    necp_hits = []
    other_hits = []
    rows = []

    for i in range(SYSENT_COUNT):
        base = SYSENT_BASE + i * SYSENT_STRIDE
        raw = read_u64(base)
        addr = unpack(raw)
        narg = read_u16(base + 0x14)
        flags = read_u32(base + 0x10)
        name = resolve_name(addr, syms)
        rows.append((i, raw, addr, narg, flags, name))
        if addr is not None and NECP_LO <= addr < NECP_HI:
            necp_hits.append((i, addr, name))
        if addr is not None and name != "?":
            low = name.lower()
            if "necp" in low:
                other_hits.append((i, addr, name))

    w(SEP)
    w("### NECP-RANGE ENTRIES (addr in [%s, %s))" % (fmt(NECP_LO), fmt(NECP_HI)))
    w(SEP)
    if not necp_hits:
        w("  (none)")
    for h in necp_hits:
        w("  sysent[%d] = %s  %s" % (h[0], fmt(h[1]), h[2]))
    w("")

    w(SEP)
    w("### ANY ENTRY WITH 'necp' IN NAME")
    w(SEP)
    if not other_hits:
        w("  (none)")
    for h in other_hits:
        w("  sysent[%d] = %s  %s" % (h[0], fmt(h[1]), h[2]))
    w("")

    w(SEP)
    w("### FULL TABLE [%d..%d]" % (SYSENT_COUNT - 30, SYSENT_COUNT - 1))
    w(SEP)
    w("%-5s %-20s %-20s %-6s %-10s %s" % ("idx", "raw_low32", "unwrapped", "narg", "flags", "name"))
    for r in rows[-30:]:
        i = r[0]
        raw = r[1]
        addr = r[2]
        narg = r[3]
        flags = r[4]
        name = r[5]
        low32 = raw & 0xFFFFFFFF if raw is not None else 0
        w("%-5d 0x%08X           %-20s %-6s %-10s %s" % (
            i, low32, fmt(addr) if addr else "?", narg if narg is not None else "?",
            fmt(flags) if flags is not None else "?", name))
    w("")

    w(SEP)
    w("### FULL TABLE [490..520]")
    w(SEP)
    w("%-5s %-20s %-20s %-6s %-10s %s" % ("idx", "raw_low32", "unwrapped", "narg", "flags", "name"))
    for r in rows:
        i = r[0]
        if i < 490 or i > 520:
            continue
        raw = r[1]
        addr = r[2]
        narg = r[3]
        flags = r[4]
        name = r[5]
        low32 = raw & 0xFFFFFFFF if raw is not None else 0
        w("%-5d 0x%08X           %-20s %-6s %-10s %s" % (
            i, low32, fmt(addr) if addr else "?", narg if narg is not None else "?",
            fmt(flags) if flags is not None else "?", name))
    w("")

    w(SEP)
    w("### ALL NAMED ENTRIES [0..557] (only where name != ?)")
    w(SEP)
    for r in rows:
        if r[5] == "?":
            continue
        w("  sysent[%d] = %s  %s  narg=%s" % (r[0], fmt(r[2]) if r[2] else "?",
                                              r[5], r[3] if r[3] is not None else "?"))

    try:
        fh = open(OUT, "w")
        for l in L:
            fh.write(l + "\n")
        fh.close()
        log("[+] wrote %s (%d lines)" % (OUT, len(L)))
    except Exception as e:
        log("[-] write fail %s" % e)

    log("=== DONE ===")


try:
    main()
except Exception as e:
    log("[-] FATAL %s" % e)
    traceback.print_exc()
    try:
        fh = open(OUT, "w")
        fh.write("FATAL: %s\n" % e)
        fh.write(traceback.format_exc())
        fh.close()
    except Exception:
        pass