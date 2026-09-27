# -*- coding: utf-8 -*-
# @runtime Jython
# kernel_rw.py v55 - sysent dump with working symbols (basestring fix)

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

L = []


def log(m):
    print(m)
    sys.stdout.flush()


def w(s):
    L.append(s)


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


def is_str(x):
    try:
        if isinstance(x, unicode):
            return True
    except Exception:
        pass
    try:
        if isinstance(x, str):
            return True
    except Exception:
        pass
    return False


def load_symbols(path):
    if not os.path.exists(path):
        log("[!] symbols missing: %s" % path)
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
            except Exception:
                continue
            if is_str(v):
                name = v.strip()
                if name:
                    out[a] = name
    log("[+] symbols loaded: %d" % len(out))
    return out


def resolve_name(addr, syms):
    if addr is None:
        return "?"
    n = syms.get(addr)
    if n is not None:
        return n
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
    log("=== kernel_rw.py v55 ===")

    syms = load_symbols(SYMBOLS_JSON)

    w("natsuk1 sysent dump v55")
    w("base=%s stride=%d count=%d" % (fmt(SYSENT_BASE), SYSENT_STRIDE, SYSENT_COUNT))
    w("kernel_base=%s" % fmt(KERNEL_BASE))
    w("symbols_loaded=%d" % len(syms))
    w("")

    rows = []
    for i in range(SYSENT_COUNT):
        base = SYSENT_BASE + i * SYSENT_STRIDE
        raw = read_u64(base)
        addr = unpack(raw)
        narg = read_u16(base + 0x14)
        flags = read_u32(base + 0x10)
        name = resolve_name(addr, syms)
        rows.append((i, raw, addr, narg, flags, name))

    # NECP cluster
    w(SEP)
    w("### NECP CLUSTER (expected 503/504)")
    w(SEP)
    w("%-5s %-20s %-6s %-10s %s" % ("idx", "unwrapped", "narg", "flags", "name"))
    for r in rows:
        i = r[0]
        if i < 495 or i > 510:
            continue
        addr = r[2]
        name = r[5]
        narg = r[3]
        flags = r[4]
        w("%-5d %-20s %-6s %-10s %s" % (
            i, fmt(addr) if addr else "?", narg if narg is not None else "?",
            fmt(flags) if flags is not None else "?", name))
    w("")

    # All entries with names (like "necp")
    w(SEP)
    w("### ENTRIES WITH 'necp' IN NAME")
    w(SEP)
    hits = []
    for r in rows:
        if r[5] == "?":
            continue
        if "necp" in r[5].lower():
            hits.append(r)
    if not hits:
        w("  (none)")
    for r in hits:
        w("  sysent[%d] = %s  %s" % (r[0], fmt(r[2]) if r[2] else "?", r[5]))
    w("")

    # All entries with names (any)
    w(SEP)
    w("### NAMED SYSCALLS (name != '?')")
    w(SEP)
    for r in rows:
        if r[5] == "?":
            continue
        w("  %-5d %-20s narg=%-3s flags=%-8s %s" % (
            r[0], fmt(r[2]) if r[2] else "?",
            r[3] if r[3] is not None else "?",
            fmt(r[4]) if r[4] is not None else "?",
            r[5]))
    w("")

    # Full table 0..557, one line each
    w(SEP)
    w("### FULL TABLE 0..557")
    w(SEP)
    w("%-5s %-20s %-6s %-10s %s" % ("idx", "unwrapped", "narg", "flags", "name"))
    for r in rows:
        w("%-5d %-20s %-6s %-10s %s" % (
            r[0], fmt(r[2]) if r[2] else "?",
            r[3] if r[3] is not None else "?",
            fmt(r[4]) if r[4] is not None else "?",
            r[5]))

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