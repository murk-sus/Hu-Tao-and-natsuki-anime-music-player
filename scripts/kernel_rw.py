# -*- coding: utf-8 -*-
# @runtime Jython
# mig_scan.py v3 - diagnostic

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
MAX_TRAPS = 220
MAX_DECOMPILE_SEC = 60

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


def diag(addr, label):
    w("")
    w(SEP)
    w("### DIAG %s @ %s" % (label, fmt(addr)))
    w(SEP)
    ga = sa(addr)
    w("  addr_obj = %s" % repr(ga))
    if ga is None:
        return
    try:
        w("  getInstructionAt = %s" % repr(getInstructionAt(ga)))
    except Exception as e:
        w("  getInstructionAt EXC: %s" % e)
    try:
        w("  getFunctionAt = %s" % repr(getFunctionAt(ga)))
    except Exception as e:
        w("  getFunctionAt EXC: %s" % e)
    try:
        w("  getFunctionContaining = %s" % repr(getFunctionContaining(ga)))
    except Exception as e:
        w("  getFunctionContaining EXC: %s" % e)
    if HAS_DISASM:
        try:
            _DC(ga, None, True).applyTo(currentProgram)
            w("  disasm applied")
        except Exception as e:
            w("  disasm EXC: %s" % e)
    try:
        w("  getInstructionAt post-disasm = %s" % repr(getInstructionAt(ga)))
    except Exception as e:
        w("  post-disasm EXC: %s" % e)
    try:
        w("  getFunctionContaining post-disasm = %s" % repr(getFunctionContaining(ga)))
    except Exception as e:
        w("  post-disasm EXC: %s" % e)
    if HAS_CREATE:
        try:
            _CFC(ga).applyTo(currentProgram)
            w("  create func applied")
        except Exception as e:
            w("  create func EXC: %s" % e)
    f = None
    try:
        f = getFunctionAt(ga)
    except Exception:
        pass
    if f is None:
        try:
            f = getFunctionContaining(ga)
        except Exception:
            pass
    w("  final func = %s" % repr(f))
    if f is not None:
        try:
            w("    name = %s" % f.getName())
            w("    entry = %s" % fmt(_u(f.getEntryPoint().getOffset())))
            w("    size = 0x%X" % int(f.getBody().getNumAddresses()))
        except Exception as e:
            w("    info EXC: %s" % e)
        try:
            r = get_dec().decompileFunction(f, MAX_DECOMPILE_SEC, MONITOR)
            if r is None:
                w("  decompile: None result")
            elif not r.decompileCompleted():
                w("  decompile: not completed")
            else:
                c = r.getDecompiledFunction()
                if c is None:
                    w("  decompile: empty")
                else:
                    lines = c.getC().split("\n")
                    w("  decompile: %d lines" % len(lines))
                    for l in lines[:15]:
                        w("    | " + l.rstrip())
        except Exception as e:
            w("  decompile EXC: %s" % e)


def read_u64(addr):
    try:
        ga = sa(addr)
        if ga is None:
            return None
        return _u(currentProgram.getMemory().getLong(ga))
    except Exception:
        return None


def main():
    global START_TS
    START_TS = time.time()

    w("natsuk1 mig_scan v3 diag")
    w("kernel base %s" % fmt(KERNEL_BASE))
    w("HAS_DISASM=%s HAS_CREATE=%s" % (HAS_DISASM, HAS_CREATE))

    w("")
    w(SEP)
    w("### KNOWN ADDRESS TEST")
    w(SEP)

    diag(int("FFFFFFF00A98C2E8", 16), "iokit_user_client_trap")
    diag(int("FFFFFFF00A4F75D8", 16), "necp_match_policy")

    w("")
    w(SEP)
    w("### TABLE HANDLERS")
    w(SEP)

    seen = set()
    for i in range(MAX_TRAPS):
        if time.time() - START_TS > 900:
            w("budget exceeded reading table")
            break
        base = MACH_TRAP_TABLE + i * STRIDE
        fn_raw = read_u64(base + OFF_FN)
        if fn_raw is None or fn_raw == 0:
            continue
        fn_addr = KERNEL_BASE + (fn_raw & 0xFFFFFFFF)
        if fn_addr < KERNEL_BASE or fn_addr > KERNEL_BASE + 0x20000000:
            continue
        seen.add(fn_addr)

    w("unique fn addr candidates: %d" % len(seen))

    ok = 0
    bad = 0
    for fn_addr in sorted(seen):
        if time.time() - START_TS > 1200:
            w("budget exceeded in ensure loop")
            break
        ga = sa(fn_addr)
        f = None
        try:
            f = getFunctionAt(ga)
        except Exception:
            pass
        if f is None:
            try:
                f = getFunctionContaining(ga)
            except Exception:
                pass
        if f is None and HAS_DISASM:
            try:
                _DC(ga, None, True).applyTo(currentProgram)
            except Exception:
                pass
            try:
                f = getFunctionContaining(ga)
            except Exception:
                pass
        if f is None and HAS_CREATE:
            try:
                _CFC(ga).applyTo(currentProgram)
            except Exception:
                pass
            try:
                f = getFunctionAt(ga)
            except Exception:
                pass
            if f is None:
                try:
                    f = getFunctionContaining(ga)
                except Exception:
                    pass
        if f is not None:
            ok += 1
            w("  OK  %s -> %s @ %s" % (fmt(fn_addr), f.getName(), fmt(_u(f.getEntryPoint().getOffset()))))
        else:
            bad += 1
            w("  BAD %s" % fmt(fn_addr))

    w("")
    w("OK=%d BAD=%d" % (ok, bad))
    w("elapsed %.1f sec" % (time.time() - START_TS))

    try:
        fh = open(OUT, "w")
        for l in L:
            fh.write(l + "\n")
        fh.close()
        log("[+] wrote %s (%d lines)" % (OUT, len(L)))
    except Exception as e:
        log("[-] write fail %s" % e)


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