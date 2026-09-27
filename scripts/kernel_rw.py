# -*- coding: utf-8 -*-
# @runtime Jython
# iokit_scan.py v1 - IOUserClient externalMethod scanner

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

USER_CLIENT_VTABLE_NAMES = [
    "IOUserClient",
    "IOUserClient_vtable",
]

EXT_METHOD_SIGS = [
    "externalMethod",
    "getTargetAndMethodForIndex",
    "externalMethodOverride",
]

SINK_ADDRS = {
    "copyin":      int("FFFFFFF00A368EC0", 16),
    "copyout":     int("FFFFFFF00A369A3C", 16),
    "memmove":     int("FFFFFFF00AA40D30", 16),
    "memset":      int("FFFFFFF00AA40EE0", 16),
    "kalloc_type": int("FFFFFFF00A200988", 16),
    "kalloc_zone": int("FFFFFFF00A20141C", 16),
    "kfree_type":  int("FFFFFFF00A201000", 16),
    "is_io_service_open_extended": int("FFFFFFF00A988758", 16),
    "iokit_user_client_trap":      int("FFFFFFF00A98C2E8", 16),
    "io_connect_method":           int("FFFFFFF00A9AD62C", 16),
}

STRUCT_CHECK_NAMES = [
    "checkScalarInputCount",
    "checkStructureInputSize",
    "checkScalarOutputCount",
    "checkStructureOutputSize",
]

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


def find_user_client_vtables():
    """Find vtables whose first entries match IOUserClient method names."""
    hits = []
    sym = currentProgram.getSymbolTable()
    try:
        it = sym.getAllSymbols(True)
        while it.hasNext():
            s = it.next()
            nm = str(s.getName())
            for pat in USER_CLIENT_VTABLE_NAMES:
                if pat in nm:
                    hits.append((_u(s.getAddress().getOffset()), nm))
    except Exception as e:
        log("[!] symtab: %s" % e)

    # Fallback: scan data for "IOUserClient" string and follow xrefs
    if not hits:
        try:
            mem = currentProgram.getMemory()
            for block in mem.getBlocks():
                if not block.isInitialized():
                    continue
                if block.isExecute():
                    continue
                start = _u(block.getStart().getOffset())
                end = _u(block.getEnd().getOffset())
                size = end - start
                if size <= 0 or size > 0x1000000:
                    continue
                buf = zeros(size, 'b')
                try:
                    mem.getBytes(block.getStart(), buf)
                except Exception:
                    continue
                for i in range(0, size - 16, 8):
                    val = int(buf[i]) & 0xFF
                    if val == 0:
                        continue
                del buf
        except Exception as e:
            log("[!] memscan: %s" % e)
    return hits


def vtable_entries(addr, max_entries=256):
    out = []
    for i in range(max_entries):
        raw = None
        try:
            ga = sa(addr + i * 8)
            raw = _u(currentProgram.getMemory().getLong(ga))
        except Exception:
            break
        if raw == 0:
            break
        target = KERNEL_BASE + (raw & 0xFFFFFFFF)
        if target < KERNEL_BASE or target > KERNEL_BASE + 0x20000000:
            break
        out.append((i, raw, target))
    return out


def resolve_name(addr):
    f = getFunctionContaining(sa(addr))
    if f is not None:
        try:
            return str(f.getName())
        except Exception:
            pass
    return "?"


def find_methods_in_vtable(vt_addr):
    """Return indices and names where vtable slot resolves to ext method sig."""
    out = []
    for idx, raw, target in vtable_entries(vt_addr):
        nm = resolve_name(target)
        for sig in EXT_METHOD_SIGS:
            if sig in nm:
                out.append((idx, target, nm))
                break
    return out


def extract_dispatch_table(fn_addr):
    """Decompile and look for stack / const dispatch structs."""
    f = ensure_function(fn_addr)
    if f is None:
        return None, None
    text = decompile_text(f)
    lines = [l.strip() for l in text]

    # find array-ish patterns
    dispatch_hits = []
    for i, line in enumerate(lines):
        for sname in STRUCT_CHECK_NAMES:
            if sname in line:
                dispatch_hits.append((i, line))
                break

    return f, {"lines": lines, "dispatch_hits": dispatch_hits}


def count_sinks(text):
    joined = "\n".join(text).lower()
    out = {}
    for name, addr in SINK_ADDRS.items():
        tok = ("%x" % (addr & 0xFFFFFFFFFFFFFFFF))
        out[name] = joined.count(tok)
    for name in ("copyin", "copyout", "memmove", "memset"):
        out[name] = out.get(name, 0) + joined.count(name)
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

    log("=== iokit_scan v1 ===")
    w("natsuk1 iokit_scan v1")
    w("kernel base %s" % fmt(KERNEL_BASE))
    w("")

    log("[*] finding IOUserClient vtables")
    vtables = find_user_client_vtables()
    log("[*] vtable candidates: %d" % len(vtables))

    w("")
    w(SEP)
    w("### VTABLE CANDIDATES")
    w(SEP)
    for a, nm in vtables:
        w("  %s  %s" % (fmt(a), nm))

    results = []
    for vt_addr, vt_name in vtables:
        if time.time() - START_TS > 2400:
            w("BUDGET EXCEEDED")
            break
        log("[*] vtable %s @ %s" % (vt_name, fmt(vt_addr)))
        methods = find_methods_in_vtable(vt_addr)

        w("")
        w(SEP)
        w("### VTABLE @ %s (%s)" % (fmt(vt_addr), vt_name))
        w(SEP)
        for idx, raw, target in vtable_entries(vt_addr):
            nm = resolve_name(target)
            w("  [%3d] %s -> %s  %s" % (idx, fmt(raw), fmt(target), nm))

        for idx, target, nm in methods:
            log("[*] method %s @ %s (vtable slot %d)" % (nm, fmt(target), idx))
            r = dump_one(target, "ext_method", extra="slot=%d name=%s" % (idx, nm))
            if r is not None:
                r["vtable"] = vt_addr
                r["slot"] = idx
                results.append(r)

    w("")
    w(SEP)
    w("### SUMMARY")
    w(SEP)
    w("vtables: %d" % len(vtables))
    w("methods dumped: %d" % len(results))
    w("")
    for r in results:
        parts = []
        for k in sorted(r["sinks"].keys()):
            if r["sinks"][k] > 0:
                parts.append("%s=%d" % (k, r["sinks"][k]))
        w("  %s %s vtable=%s slot=%d  %s" % (
            fmt(r["addr"]), r["name"], fmt(r["vtable"]),
            r["slot"], " ".join(parts)))
    w("")
    w("elapsed %.1f sec" % (time.time() - START_TS))

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