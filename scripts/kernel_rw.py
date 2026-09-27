# -*- coding: utf-8 -*-
# @runtime Jython
# iokit_scan.py v2 - strings + xrefs based vtable finder with diagnostics

import os
import sys
import time
import traceback
from jarray import zeros
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

try:
    from ghidra.app.cmd.disassemble import DisassembleCommand as _DC
    HAS_DISASM = True
except Exception:
    HAS_DISASM = False

try:
    from ghidra.app.cmd.function import CreateFunctionCmd as _CFC
    HAS_CREATE = True
except Exception:
    HAS_CREATE = False

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WS, "result.txt")
SEP = "=" * 72

KERNEL_BASE = int("FFFFFFF007004000", 16)
KERNEL_END  = KERNEL_BASE + 0x20000000

MAX_SYMBOLS = 2000000
MAX_STRINGS = 800000
STR_FILTER = ["IOUserClient", "IOExternalMethod", "externalMethod", "IOKit"]

DEC = None
MONITOR = ConsoleTaskMonitor()
START_TS = time.time()
L = []
_DECOMP_CACHE = {}


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
        s = "%X" % (int(a) & 0xFFFFFFFFFFFFFFFF)
        return currentProgram.getAddressFactory().getAddress(s)
    except Exception:
        return None


def get_dec():
    global DEC
    if DEC is not None:
        return DEC
    d = DecompInterface()
    d.openProgram(currentProgram)
    DEC = d
    return DEC


def decompile_text(f, sec=60):
    try:
        ent = _u(f.getEntryPoint().getOffset())
    except Exception:
        ent = 0
    if ent in _DECOMP_CACHE:
        return _DECOMP_CACHE[ent]
    try:
        r = get_dec().decompileFunction(f, sec, MONITOR)
        if r is None or not r.decompileCompleted():
            out = ["(decompile failed)"]
        else:
            c = r.getDecompiledFunction()
            out = ["(empty)"] if c is None else [l.rstrip() for l in c.getC().split("\n")]
    except Exception as e:
        out = ["(exception %s)" % e]
    _DECOMP_CACHE[ent] = out
    return out


def ensure_function(addr):
    ga = sa(addr)
    if ga is None:
        return None
    f = getFunctionAt(ga)
    if f is not None:
        return f
    f = getFunctionContaining(ga)
    if f is not None:
        return f
    if HAS_DISASM:
        try:
            _DC(ga, None, True).applyTo(currentProgram)
        except Exception:
            pass
    f = getFunctionContaining(ga)
    if f is not None:
        return f
    if HAS_CREATE:
        try:
            _CFC(ga).applyTo(currentProgram)
        except Exception:
            pass
    return getFunctionAt(ga) or getFunctionContaining(ga)


def pac_target(raw):
    """Kernelcache stores function pointers as offsets from KERNEL_BASE."""
    if raw is None or raw == 0:
        return None
    v = KERNEL_BASE + (raw & 0xFFFFFFFF)
    if KERNEL_BASE <= v <= KERNEL_END:
        return v
    if KERNEL_BASE <= raw <= KERNEL_END:
        return raw
    return None


def read_u64(addr):
    try:
        ga = sa(addr)
        if ga is None:
            return None
        return _u(currentProgram.getMemory().getLong(ga))
    except Exception:
        return None


def diag_symbols():
    w("")
    w(SEP)
    w("### DIAG: SYMBOL TABLE")
    w(SEP)
    sym = currentProgram.getSymbolTable()
    total = 0
    sample = []
    io_user = []
    vtable_syms = []
    ztv_syms = []
    try:
        it = sym.getSymbolIterator()
        while it.hasNext():
            s = it.next()
            total += 1
            if total > MAX_SYMBOLS:
                break
            if total % 100000 == 0:
                log("[*] symbols: %d" % total)
            try:
                nm = str(s.getName())
            except Exception:
                continue
            if total <= 30:
                sample.append(nm)
            if "IOUser" in nm:
                io_user.append((_u(s.getAddress().getOffset()), nm))
            if "vtable" in nm.lower():
                vtable_syms.append((_u(s.getAddress().getOffset()), nm))
            if "__ZTV" in nm:
                ztv_syms.append((_u(s.getAddress().getOffset()), nm))
    except Exception as e:
        w("  symtab iter EXC: %s" % e)
    w("  total symbols: %d" % total)
    w("  with 'IOUser': %d" % len(io_user))
    w("  with 'vtable': %d" % len(vtable_syms))
    w("  with '__ZTV': %d" % len(ztv_syms))
    w("  sample (first 30):")
    for nm in sample:
        w("    %s" % nm)
    w("  IOUser symbols (up to 20):")
    for a, nm in io_user[:20]:
        w("    %s  %s" % (fmt(a), nm))
    w("  vtable symbols (up to 20):")
    for a, nm in vtable_syms[:20]:
        w("    %s  %s" % (fmt(a), nm))
    w("  __ZTV symbols (up to 20):")
    for a, nm in ztv_syms[:20]:
        w("    %s  %s" % (fmt(a), nm))
    log("[*] diag: total=%d io_user=%d vtable=%d ztv=%d" % (
        total, len(io_user), len(vtable_syms), len(ztv_syms)))


def find_strings():
    w("")
    w(SEP)
    w("### DIAG: STRINGS")
    w(SEP)
    hits = []
    total_str = 0
    listing = currentProgram.getListing()
    try:
        di = listing.getDefinedData(True)
    except Exception as e:
        w("  getDefinedData EXC: %s" % e)
        return hits
    cnt = 0
    while di.hasNext():
        cnt += 1
        if cnt > MAX_STRINGS:
            break
        if cnt % 100000 == 0:
            log("[*] data items: %d, strings: %d, hits: %d" % (cnt, total_str, len(hits)))
        try:
            d = di.next()
            if not d.hasStringValue():
                continue
            total_str += 1
            sval = str(d.getValue())
        except Exception:
            continue
        for f in STR_FILTER:
            if f in sval:
                a = _u(d.getAddress().getOffset())
                hits.append((a, sval[:80]))
                break
    w("  total strings: %d" % total_str)
    w("  filtered hits: %d" % len(hits))
    for a, sval in hits[:60]:
        w("    %s  %s" % (fmt(a), sval))
    if len(hits) > 60:
        w("    ... (%d more)" % (len(hits) - 60))
    log("[*] strings: total=%d hits=%d" % (total_str, len(hits)))
    return hits


def find_xrefs(addr):
    out = []
    ga = sa(addr)
    if ga is None:
        return out
    try:
        rm = currentProgram.getReferenceManager()
        refs = rm.getReferencesTo(ga)
        it = refs.iterator()
        while it.hasNext():
            r = it.next()
            try:
                fa = _u(r.getFromAddress().getOffset())
                out.append(fa)
            except Exception:
                continue
    except Exception as e:
        log("[!] xref exc @ %s: %s" % (fmt(addr), e))
    return out


def looks_like_vtable(addr, min_entries=5):
    """Count slots that resolve to a valid function; require min_entries."""
    hits = 0
    checked = 0
    for i in range(16):
        raw = read_u64(addr + i * 8)
        if raw is None or raw == 0:
            break
        checked += 1
        t = pac_target(raw)
        if t is None:
            break
        f = getFunctionContaining(sa(t))
        if f is not None:
            hits += 1
    return hits >= min_entries and checked >= min_entries


def vtable_dump(addr, max_entries=64):
    out = []
    for i in range(max_entries):
        raw = read_u64(addr + i * 8)
        if raw is None or raw == 0:
            break
        t = pac_target(raw)
        name = "?"
        if t is not None:
            f = getFunctionContaining(sa(t))
            if f is not None:
                try:
                    name = str(f.getName())
                except Exception:
                    pass
        out.append((i, raw, t or 0, name))
    return out


def count_sinks(text):
    joined = "\n".join(text).lower()
    out = {}
    for name in ("copyin", "copyout", "memmove", "memset", "kalloc_type", "kalloc_zone"):
        out[name] = joined.count(name)
    return out


def dump_one(addr, label, extra=""):
    w("")
    w(SEP)
    w("### %s @ %s %s" % (label, fmt(addr), extra))
    w(SEP)
    f = ensure_function(addr)
    if f is None:
        w("  no function")
        return None
    try:
        w("  name = %s" % f.getName())
        w("  size = 0x%X" % int(f.getBody().getNumAddresses()))
    except Exception:
        pass
    text = decompile_text(f)
    c = count_sinks(text)
    parts = []
    for k in sorted(c.keys()):
        if c[k] > 0:
            parts.append("%s=%d" % (k, c[k]))
    w("  sinks: %s" % (" ".join(parts) if parts else "(none)"))
    w("")
    w("-- decompile --")
    for l in text:
        w("  " + l)
    return {"addr": addr, "name": str(f.getName()), "sinks": c, "text": text}


def main():
    global START_TS
    START_TS = time.time()

    log("=== iokit_scan v2 ===")
    w("natsuk1 iokit_scan v2 diag")
    w("kernel base %s" % fmt(KERNEL_BASE))
    w("kernel end  %s" % fmt(KERNEL_END))
    w("")

    diag_symbols()

    strs = find_strings()

    w("")
    w(SEP)
    w("### XREFS TO STRINGS")
    w(SEP)

    candidate_data_addrs = []
    for s_addr, s_val in strs[:60]:
        xrefs = find_xrefs(s_addr)
        w("")
        w("  string @ %s = %s" % (fmt(s_addr), s_val))
        if not xrefs:
            w("    (no xrefs)")
            continue
        for xa in xrefs[:20]:
            w("    xref from %s" % fmt(xa))
            candidate_data_addrs.append(xa)

    candidate_data_addrs = sorted(set(candidate_data_addrs))
    log("[*] candidate data addrs: %d" % len(candidate_data_addrs))

    w("")
    w(SEP)
    w("### VTABLE CANDIDATES FROM XREFS")
    w(SEP)

    vtables = []
    for ca in candidate_data_addrs:
        if time.time() - START_TS > 2400:
            w("BUDGET EXCEEDED while scanning xrefs")
            break
        for delta in range(-0x100, 0x400, 8):
            addr = ca + delta
            if addr < KERNEL_BASE:
                continue
            if looks_like_vtable(addr, min_entries=5):
                vtables.append(addr)
                break

    vtables = sorted(set(vtables))

    w("  vtable candidates: %d" % len(vtables))
    for v in vtables[:60]:
        w("    %s" % fmt(v))

    log("[*] vtables: %d" % len(vtables))

    w("")
    w(SEP)
    w("### VTABLE DUMPS")
    w(SEP)

    methods_found = []
    for vt in vtables:
        if time.time() - START_TS > 2400:
            w("BUDGET EXCEEDED during vtable dump")
            break
        entries = vtable_dump(vt, 64)
        w("")
        w("  vtable @ %s" % fmt(vt))
        for idx, raw, target, name in entries:
            w("    [%3d] %s -> %s  %s" % (idx, fmt(raw), fmt(target), name))
            for sig in ("externalMethod", "getTargetAndMethodForIndex", "externalMethodOverride"):
                if sig.lower() in name.lower():
                    methods_found.append((vt, idx, target, name))
                    break

    log("[*] methods of interest: %d" % len(methods_found))

    w("")
    w(SEP)
    w("### METHOD DUMPS")
    w(SEP)

    results = []
    for vt, idx, target, name in methods_found:
        if time.time() - START_TS > 2400:
            w("BUDGET EXCEEDED during method dump")
            break
        r = dump_one(target, "ext_method", extra="vtable=%s slot=%d name=%s" % (fmt(vt), idx, name))
        if r is not None:
            r["vtable"] = vt
            r["slot"] = idx
            results.append(r)

    w("")
    w(SEP)
    w("### SUMMARY")
    w(SEP)
    w("elapsed %.1f sec" % (time.time() - START_TS))
    w("methods dumped: %d" % len(results))

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