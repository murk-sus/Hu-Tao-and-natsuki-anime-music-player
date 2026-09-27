# -*- coding: utf-8 -*-
# @runtime Jython
# mig_scan.py v5 - sink search by hex address

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

SINKS = {
    "copyin":      [0xFFFFFFF00A368EC0],
    "copyout":     [0xFFFFFFF00A369A3C],
    "memmove":     [0xFFFFFFF00AA40D30],
    "memset":      [0xFFFFFFF00AA40EE0],
    "kalloc_type": [0xFFFFFFF00A200988],
    "kalloc_zone": [0xFFFFFFF00A20141C],
    "kfree_type":  [0xFFFFFFF00A201000],
    "ref_dec":     [0xFFFFFFF00A4E3278],
}

FILTER_NAMES = ["mig_filter", "ipc_filter", "filter_msg", "ip_filter"]
PORT_NAMES   = ["mach_port_", "ipc_port_", "mach_vm_", "vm_map_", "vm_object_"]

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
        r = get_dec().decompileFunction(f, sec, MONITOR)
        if r is None or not r.decompileCompleted():
            return ["(decompile failed)"]
        c = r.getDecompiledFunction()
        if c is None:
            return ["(empty)"]
        return [l.rstrip() for l in c.getC().split("\n")]
    except Exception as e:
        return ["(exception %s)" % e]


def read_u64(addr):
    try:
        ga = sa(addr)
        if ga is None:
            return None
        return _u(currentProgram.getMemory().getLong(ga))
    except Exception:
        return None


def addr_token(addr):
    return ("%X" % (addr & 0xFFFFFFFFFFFFFFFF)).lower()


def count_sinks(text):
    joined = "\n".join(text).lower()
    out = {}
    for name, addrs in SINKS.items():
        n = 0
        for a in addrs:
            n += joined.count(addr_token(a))
        out[name] = n
    for name in FILTER_NAMES:
        out[name] = joined.count(name)
    for name in PORT_NAMES:
        out[name] = joined.count(name)
    return out


def dump_one(fn_addr, idxs, args_list, filt_list, f, text, c):
    w("")
    w(SEP)
    w("### trap_fn @ %s" % fmt(fn_addr))
    w("  name = %s" % f.getName())
    w("  traps = %s" % idxs)
    w("  args = %s" % args_list)
    w("  filters = %s" % filt_list)
    try:
        w("  size = 0x%X" % int(f.getBody().getNumAddresses()))
    except Exception:
        pass
    parts = []
    for k in sorted(c.keys()):
        if c[k] > 0:
            parts.append("%s=%d" % (k, c[k]))
    w("  counts: %s" % (" ".join(parts) if parts else "(none)"))
    w("")
    w("-- decompile --")
    for l in text:
        w("  " + l)


def main():
    global START_TS
    START_TS = time.time()

    log("=== mig_scan v5 ===")
    w("natsuk1 mig_scan v5")
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
    no_func = 0
    decomp_fail = 0
    for fn_addr, meta in sorted(by_fn.items()):
        if time.time() - START_TS > BUDGET_SEC:
            w("BUDGET EXCEEDED")
            break
        f = ensure_function(fn_addr)
        if f is None:
            no_func += 1
            continue
        text = decompile_text(f)
        if text and text[0] and text[0].startswith("(decompile"):
            decomp_fail += 1
        c = count_sinks(text)
        has_in = c.get("copyin", 0) > 0
        has_out = c.get("copyout", 0) > 0
        has_alloc = c.get("kalloc_type", 0) + c.get("kalloc_zone", 0) > 0
        has_filter = sum(c.get(n, 0) for n in FILTER_NAMES) > 0
        has_portvm = sum(c.get(n, 0) for n in PORT_NAMES) > 0
        has_any = has_in or has_out or has_alloc or has_portvm
        if not has_any:
            continue
        hp = "HIGH" if (has_in and not has_filter) else ""
        mp = "ALLOC" if (has_in and has_alloc) else ""
        results.append({
            "addr": fn_addr,
            "meta": meta,
            "f": f,
            "text": text,
            "c": c,
            "hp": hp,
            "mp": mp,
        })

    log("[*] interesting: %d (no_func=%d decomp_fail=%d)" % (len(results), no_func, decomp_fail))

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
    w("no function: %d" % no_func)
    w("decompile failed: %d" % decomp_fail)
    w("interesting: %d" % len(results))
    w("")
    for r in results:
        parts = []
        for k in sorted(r["c"].keys()):
            if r["c"][k] > 0:
                parts.append("%s=%d" % (k, r["c"][k]))
        w("  [%s%s] %s traps=%s  %s" % (
            r["hp"] or "-", r["mp"] or "", fmt(r["addr"]),
            r["meta"]["traps"], " ".join(parts)))
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