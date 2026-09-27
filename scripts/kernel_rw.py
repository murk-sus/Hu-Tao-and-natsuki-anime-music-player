# -*- coding: utf-8 -*-
# @runtime Jython
# mig_scan.py v4 - full ensure+classify

import os
import sys
import time
import traceback
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
STRIDE = 24
OFF_FN = 8
OFF_FILT = 16
MAX_TRAPS = 220
MAX_DECOMPILE_SEC = 60
BUDGET_SEC = 2400

KERN_INVALID = int("FFFFFFF00A23CB1C", 16)

SINKS_COPYIN  = ["copyin", "copyinstr"]
SINKS_COPYOUT = ["copyout", "copyoutstr"]
SINKS_ALLOC   = ["kalloc_type", "kalloc_zone", "kalloc", "zalloc", "IOMalloc"]
SINKS_FREE    = ["kfree", "kfree_type", "zfree", "IOFree"]
MIG_FILTER    = ["mig_filter", "ipc_filter"]
MACH_PORT     = ["mach_port_", "ipc_port_"]
MACH_VM       = ["mach_vm_", "vm_map_", "vm_object_"]

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
    f = getFunctionAt(ga)
    if f is not None:
        return f
    return getFunctionContaining(ga)


def decompile_text(f, sec=MAX_DECOMPILE_SEC):
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


def read_u64(addr):
    try:
        ga = sa(addr)
        if ga is None:
            return None
        return _u(currentProgram.getMemory().getLong(ga))
    except Exception:
        return None


def count_sinks(text):
    joined = "\n".join(text)
    def cnt(lst):
        n = 0
        for s in lst:
            n += joined.count(s)
        return n
    return {
        "in": cnt(SINKS_COPYIN),
        "out": cnt(SINKS_COPYOUT),
        "alloc": cnt(SINKS_ALLOC),
        "free": cnt(SINKS_FREE),
        "filter": cnt(MIG_FILTER),
        "port": cnt(MACH_PORT),
        "vm": cnt(MACH_VM),
    }


def dump_one(fn_addr, idxs, args_list, filt_list, f, text, c):
    w("")
    w(SEP)
    w("### trap_fn @ %s" % fmt(fn_addr))
    w("  name  = %s" % f.getName())
    w("  traps = %s" % idxs)
    w("  args  = %s" % args_list)
    w("  filters = %s" % filt_list)
    try:
        sz = int(f.getBody().getNumAddresses())
        w("  size  = 0x%X" % sz)
    except Exception:
        pass
    w("  counts: in=%d out=%d alloc=%d free=%d filter=%d port=%d vm=%d" % (
        c["in"], c["out"], c["alloc"], c["free"], c["filter"], c["port"], c["vm"]))
    w("")
    w("-- decompile --")
    for l in text:
        w("  " + l)


def main():
    global START_TS
    START_TS = time.time()

    log("=== mig_scan v4 ===")
    w("natsuk1 mig_scan v4")
    w("kernel base %s" % fmt(KERNEL_BASE))
    w("mach_trap_table %s stride %d" % (fmt(MACH_TRAP_TABLE), STRIDE))
    w("")

    entries = []
    for i in range(MAX_TRAPS):
        base = MACH_TRAP_TABLE + i * STRIDE
        args_raw = read_u64(base)
        fn_raw = read_u64(base + OFF_FN)
        filt_raw = read_u64(base + OFF_FILT)
        if fn_raw is None:
            break
        if fn_raw == 0:
            continue
        fn_addr = KERNEL_BASE + (fn_raw & 0xFFFFFFFF)
        if fn_addr < KERNEL_BASE or fn_addr > KERNEL_BASE + 0x20000000:
            continue
        filt_addr = 0
        if filt_raw and filt_raw != 0:
            fa = KERNEL_BASE + (filt_raw & 0xFFFFFFFF)
            if fa >= KERNEL_BASE and fa <= KERNEL_BASE + 0x20000000:
                filt_addr = fa
        entries.append((i, args_raw or 0, fn_addr, filt_addr))

    log("[*] entries: %d" % len(entries))

    by_fn = {}
    for i, args, fn_addr, filt_addr in entries:
        if fn_addr == KERN_INVALID:
            continue
        by_fn.setdefault(fn_addr, {"traps": [], "args": [], "filters": []})
        by_fn[fn_addr]["traps"].append(i)
        by_fn[fn_addr]["args"].append(args)
        by_fn[fn_addr]["filters"].append(filt_addr)

    log("[*] unique fn: %d" % len(by_fn))

    results = []
    for fn_addr, meta in sorted(by_fn.items()):
        if time.time() - START_TS > BUDGET_SEC:
            w("BUDGET EXCEEDED")
            break
        f = ensure_function(fn_addr)
        if f is None:
            w("  BAD %s (no function)" % fmt(fn_addr))
            continue
        text = decompile_text(f)
        c = count_sinks(text)
        has_any = c["in"] > 0 or c["out"] > 0 or c["alloc"] > 0 or (c["port"] > 0 and c["vm"] > 0)
        if not has_any:
            continue
        # high priority: copyin without filter
        no_filter = all(x == 0 for x in meta["filters"])
        hp = "HIGH" if (c["in"] > 0 and no_filter) else ""
        # medium: copyin + alloc
        mp = "ALLOC" if (c["in"] > 0 and c["alloc"] > 0) else ""
        results.append({
            "addr": fn_addr,
            "meta": meta,
            "f": f,
            "text": text,
            "c": c,
            "hp": hp,
            "mp": mp,
        })

    log("[*] interesting: %d" % len(results))

    # HIGH priority first
    results.sort(key=lambda r: (0 if r["hp"] else 1 if r["mp"] else 2, r["addr"]))

    for r in results:
        if time.time() - START_TS > BUDGET_SEC:
            w("BUDGET EXCEEDED during dump")
            break
        dump_one(r["addr"], r["meta"]["traps"],
                 ["0x%X" % a for a in r["meta"]["args"]],
                 [fmt(x) for x in r["meta"]["filters"]],
                 r["f"], r["text"], r["c"])

    w("")
    w(SEP)
    w("### SUMMARY")
    w(SEP)
    w("total entries: %d" % len(entries))
    w("unique handlers: %d" % len(by_fn))
    w("interesting: %d" % len(results))
    w("")
    for r in results:
        w("  [%s%s] %s traps=%s in=%d out=%d alloc=%d free=%d filter=%d port=%d vm=%d" % (
            r["hp"] or "-", r["mp"] or "", fmt(r["addr"]),
            r["meta"]["traps"],
            r["c"]["in"], r["c"]["out"], r["c"]["alloc"], r["c"]["free"],
            r["c"]["filter"], r["c"]["port"], r["c"]["vm"]))
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