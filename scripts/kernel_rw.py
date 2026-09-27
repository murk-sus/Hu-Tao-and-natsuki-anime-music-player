# -*- coding: utf-8 -*-
# @runtime Jython
# mig_scan.py v1 - mach_trap_table MIG handler scanner for iOS 27 / 24A437

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

MAX_ENTRIES = 256
MAX_DECOMPILE_SEC = 60
BUDGET_SEC = 2700
MAX_TAINT_DEPTH = 12

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
        r = get_dec().decompileFunction(f, sec, MONITOR)
        if r is None:
            return ["(decompile failed)"]
        if not r.decompileCompleted():
            return ["(decompile failed)"]
        c = r.getDecompiledFunction()
        if c is None:
            return ["(empty)"]
        raw = c.getC()
        return [line.rstrip() for line in raw.split("\n")]
    except Exception as e:
        return ["(exception %s)" % e]


def pac_unwrap(raw):
    """iOS 16+ arm64e PAC unwrap: lower 32 bits + KERNEL_BASE."""
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
    """Return (has_copyin, has_copyout, has_alloc, has_free, has_filter, has_port, has_vm)."""
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
        "size": int(f.getBody().getNumAddresses()),
        "has_in": has_in,
        "has_out": has_out,
        "has_alloc": has_alloc,
        "has_free": has_free,
        "has_filter": has_filter,
        "has_port": has_port,
        "has_vm": has_vm,
    }


def main():
    global START_TS
    START_TS = time.time()

    log("=== mig_scan.py v1 ===")
    w("natsuk1 mig_scan v1")
    w("kernel base %s" % fmt(KERNEL_BASE))
    w("mach_trap_table %s" % fmt(MACH_TRAP_TABLE))
    w("")

    table = []
    for i in range(MAX_ENTRIES):
        if time.time() - START_TS > BUDGET_SEC:
            w("BUDGET EXCEEDED while reading table at i=%d" % i)
            break
        raw = read_u64(MACH_TRAP_TABLE + i * 8)
        if raw is None:
            break
        if raw == 0:
            continue
        addr = pac_unwrap(raw)
        if addr == KERNEL_BASE:
            continue
        table.append((i, addr))

    log("[*] table entries: %d" % len(table))

    w("")
    w(SEP)
    w("### TABLE")
    w(SEP)
    for i, addr in table:
        f = get_func(addr)
        nm = "?"
        if f is not None:
            try:
                nm = str(f.getName())
            except Exception:
                pass
        w("  [%3d] %s  %s" % (i, fmt(addr), nm))

    interesting = []
    for i, addr in table:
        if time.time() - START_TS > BUDGET_SEC:
            w("BUDGET EXCEEDED at trap %d" % i)
            break
        f = get_func(addr)
        if f is None:
            f = ensure_function(addr)
        if f is None:
            continue
        text = decompile_text(f, MAX_DECOMPILE_SEC)
        has_in, has_out, has_alloc, has_free, has_filter, has_port, has_vm = classify_text(text)
        if has_in or has_out or has_alloc or (has_port and has_vm):
            interesting.append((i, addr, f))

    log("[*] interesting traps: %d" % len(interesting))

    results = []
    for i, addr, f in interesting:
        if time.time() - START_TS > BUDGET_SEC:
            w("BUDGET EXCEEDED while dumping trap %d" % i)
            break
        try:
            nm = str(f.getName())
        except Exception:
            nm = "?"
        log("[*] dumping trap %d %s" % (i, fmt(addr)))
        r = dump_one(addr, "mach_trap[%d] %s" % (i, nm), "MIG candidate")
        if r is not None:
            r["index"] = i
            results.append(r)

    w("")
    w(SEP)
    w("### SUMMARY")
    w(SEP)
    w("total traps: %d" % len(table))
    w("interesting: %d" % len(interesting))
    w("dumped: %d" % len(results))
    w("")
    for r in results:
        w("  [%3d] %s %s in=%s out=%s alloc=%s free=%s filter=%s port=%s vm=%s" % (
            r["index"], fmt(r["addr"]), r["name"],
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