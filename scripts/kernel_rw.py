# -*- coding: utf-8 -*-
# @runtime Jython
# mig_scan.py v2 - stride-aware mach_trap_table scanner

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
MACH_TRAP_TABLE = int("FFFFFFF007BE8018", 16)

MACH_TRAP_STRIDE = 24
OFF_ARGS = 0
OFF_FN = 8
OFF_FILT = 16
MAX_TRAPS = 220
MAX_DECOMPILE_SEC = 60
BUDGET_SEC = 2700

SINKS_COPYIN  = ["copyin", "copyinstr"]
SINKS_COPYOUT = ["copyout", "copyoutstr"]
SINKS_ALLOC   = ["kalloc_type", "kalloc_zone", "kalloc", "zalloc", "IOMalloc", "IOMallocAligned"]
SINKS_FREE    = ["kfree", "kfree_type", "zfree", "IOFree"]
MIG_FILTER    = ["mig_filter", "ipc_filter", "filter_msg", "port_filter"]
MACH_PORT     = ["mach_port_", "ipc_port_", "MACH_PORT_"]
MACH_VM       = ["mach_vm_", "vm_map_", "vm_object_", "vm_entry_"]

DEC = None
MONITOR = ConsoleTaskMonitor()
START_TS = time.time()
L = []
_DECOMPILE_CACHE = {}


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


def disassemble(addr):
    if not HAS_DISASM:
        return
    try:
        ga = sa(addr)
        if ga is None:
            return
        _DC(ga, None, True).applyTo(currentProgram)
    except Exception:
        pass


def ensure_function(addr):
    try:
        ga = sa(addr)
        if ga is None:
            return None
        f = getFunctionAt(ga)
        if f is not None:
            return f
        f = getFunctionContaining(ga)
        if f is not None:
            return f
        disassemble(ga)
        if HAS_CREATE:
            try:
                _CFC(ga).applyTo(currentProgram)
            except Exception:
                pass
        try:
            fm = currentProgram.getFunctionManager()
            nm = "mig_%X" % addr
            f = fm.createFunction(ga, nm)
            if f is not None:
                return f
        except Exception:
            pass
        return getFunctionAt(ga) or getFunctionContaining(ga)
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


def decompile_text(f, sec=MAX_DECOMPILE_SEC):
    try:
        ent = _u(f.getEntryPoint().getOffset())
    except Exception:
        ent = 0
    if ent in _DECOMPILE_CACHE:
        return _DECOMPILE_CACHE[ent]
    try:
        r = get_dec().decompileFunction(f, sec, MONITOR)
        if r is None or not r.decompileCompleted():
            out = ["(decompile failed)"]
        else:
            c = r.getDecompiledFunction()
            out = ["(empty)"] if c is None else [l.rstrip() for l in c.getC().split("\n")]
    except Exception as e:
        out = ["(exception %s)" % e]
    _DECOMPILE_CACHE[ent] = out
    return out


def pac_unwrap(raw):
    return KERNEL_BASE + (raw & 0xFFFFFFFF)


def read_u64(addr):
    try:
        ga = sa(addr)
        if ga is None:
            return None
        return _u(currentProgram.getMemory().getLong(ga))
    except Exception:
        return None


def classify_text(text):
    joined = "\n".join(text)
    def any_in(lst):
        for s in lst:
            if s in joined:
                return True
        return False
    return (
        any_in(SINKS_COPYIN),
        any_in(SINKS_COPYOUT),
        any_in(SINKS_ALLOC),
        any_in(SINKS_FREE),
        any_in(MIG_FILTER),
        any_in(MACH_PORT),
        any_in(MACH_VM),
    )


def dump_one(addr, name, note):
    w("")
    w(SEP)
    w("### %s @ %s" % (name, fmt(addr)))
    w("note: %s" % note)
    w(SEP)

    f = get_func(addr)
    if f is None:
        f = ensure_function(addr)
    if f is None:
        w("  no function")
        return None

    try:
        ent = _u(f.getEntryPoint().getOffset())
        sz = int(f.getBody().getNumAddresses())
        w("  func=%s entry=%s size=0x%X" % (str(f.getName()), fmt(ent), sz))
    except Exception:
        pass

    text = decompile_text(f, MAX_DECOMPILE_SEC)
    has_in, has_out, has_alloc, has_free, has_filter, has_port, has_vm = classify_text(text)

    w("")
    w("-- sinks --")
    w("  copyin=%s copyout=%s alloc=%s free=%s filter=%s port=%s vm=%s" % (
        has_in, has_out, has_alloc, has_free, has_filter, has_port, has_vm))

    w("")
    w("-- decompile --")
    for l in text:
        w("  " + l)

    return {
        "addr": addr,
        "name": name,
        "has_in": has_in,
        "has_out": has_out,
        "has_alloc": has_alloc,
        "has_free": has_free,
        "has_filter": has_filter,
        "has_port": has_port,
        "has_vm": has_vm,
    }


def read_mach_trap(idx):
    base = MACH_TRAP_TABLE + idx * MACH_TRAP_STRIDE
    a = read_u64(base + OFF_ARGS)
    f = read_u64(base + OFF_FN)
    x = read_u64(base + OFF_FILT)
    return (a, f, x)


def main():
    global START_TS
    START_TS = time.time()

    log("=== mig_scan.py v2 ===")
    w("natsuk1 mig_scan v2")
    w("kernel base %s" % fmt(KERNEL_BASE))
    w("mach_trap_table %s stride %d" % (fmt(MACH_TRAP_TABLE), MACH_TRAP_STRIDE))
    w("")

    traps = []
    for i in range(MAX_TRAPS):
        if time.time() - START_TS > BUDGET_SEC:
            w("BUDGET EXCEEDED while reading table at i=%d" % i)
            break
        args, fn_raw, filt_raw = read_mach_trap(i)
        if fn_raw is None:
            break
        if fn_raw == 0:
            continue
        fn_addr = pac_unwrap(fn_raw)
        if fn_addr == KERNEL_BASE:
            continue
        if fn_addr < KERNEL_BASE or fn_addr > KERNEL_BASE + 0x20000000:
            continue
        filt_addr = 0
        if filt_raw and filt_raw != 0:
            fa = pac_unwrap(filt_raw)
            if fa != KERNEL_BASE and fa >= KERNEL_BASE and fa <= KERNEL_BASE + 0x20000000:
                filt_addr = fa
        traps.append((i, args, fn_raw, fn_addr, filt_addr))

    log("[*] traps read: %d" % len(traps))

    w("")
    w(SEP)
    w("### TABLE")
    w(SEP)
    for i, args, fn_raw, fn_addr, filt_addr in traps:
        f = get_func(fn_addr)
        nm = "?"
        if f is not None:
            try:
                nm = str(f.getName())
            except Exception:
                pass
        filt_s = ""
        if filt_addr:
            filt_s = " filter=%s" % fmt(filt_addr)
        w("  [%3d] args=0x%X fn=%s %s%s" % (i, args or 0, fmt(fn_addr), nm, filt_s))

    by_fn = {}
    for i, args, fn_raw, fn_addr, filt_addr in traps:
        by_fn.setdefault(fn_addr, []).append(i)

    w("")
    w(SEP)
    w("### UNIQUE HANDLERS: %d" % len(by_fn))
    w(SEP)

    interesting = []
    for fn_addr, idxs in sorted(by_fn.items()):
        if time.time() - START_TS > BUDGET_SEC:
            w("BUDGET EXCEEDED while classifying")
            break
        f = get_func(fn_addr)
        if f is None:
            f = ensure_function(fn_addr)
        if f is None:
            continue
        text = decompile_text(f, MAX_DECOMPILE_SEC)
        has_in, has_out, has_alloc, has_free, has_filter, has_port, has_vm = classify_text(text)
        if has_in or has_out or has_alloc or (has_port and has_vm):
            interesting.append((fn_addr, idxs, f))

    log("[*] interesting handlers: %d" % len(interesting))

    results = []
    for fn_addr, idxs, f in interesting:
        if time.time() - START_TS > BUDGET_SEC:
            w("BUDGET EXCEEDED while dumping")
            break
        try:
            nm = str(f.getName())
        except Exception:
            nm = "?"
        log("[*] dumping fn %s traps=%s" % (fmt(fn_addr), idxs))
        r = dump_one(fn_addr, "trap_fn %s traps=%s" % (nm, idxs), "unique handler")
        if r is not None:
            r["traps"] = idxs
            results.append(r)

    w("")
    w(SEP)
    w("### SUMMARY")
    w(SEP)
    w("total traps: %d" % len(traps))
    w("unique handlers: %d" % len(by_fn))
    w("interesting: %d" % len(interesting))
    w("dumped: %d" % len(results))
    w("")
    for r in results:
        w("  %s traps=%s in=%s out=%s alloc=%s free=%s filter=%s port=%s vm=%s" % (
            fmt(r["addr"]), r["traps"],
            r["has_in"], r["has_out"], r["has_alloc"], r["has_free"],
            r["has_filter"], r["has_port"], r["has_vm"]))

    w("")
    w("elapsed: %.1f sec" % (time.time() - START_TS))

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