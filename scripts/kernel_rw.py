# -*- coding: utf-8 -*-
# @runtime Jython
# kernel_rw.py v71 - necp_session_action surface + callers

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

DUMP_TARGETS = [
    (int("FFFFFFF00A4BFAB8", 16), "sess_copyin_a",     "INT_OVERFLOW copyin d=1 from necp_session_action"),
    (int("FFFFFFF00A4C0024", 16), "sess_copyin_b",     "INT_OVERFLOW copyin d=1 from necp_session_action"),
    (int("FFFFFFF00A4BDAEC", 16), "sess_copyout_a",    "COPYOUT_LEAK d=1"),
    (int("FFFFFFF00A4BDF70", 16), "sess_copyout_b",    "COPYOUT_LEAK d=1"),
    (int("FFFFFFF00A4BE40C", 16), "sess_copyout_c",    "COPYOUT_LEAK d=1"),
    (int("FFFFFFF00A4BD438", 16), "necp_session_action","sysent[525] entry"),
    (int("FFFFFFF00A4B4C3C", 16), "necp_session_open",  "sysent[524] entry"),
    (int("FFFFFFF00A4E60DC", 16), "add_client_recheck", "add_client - verify INT_OVERFLOW"),
    (int("FFFFFFF00A4E93C4", 16), "remove_flow_recheck","remove_flow - verify INT_OVERFLOW"),
    (int("FFFFFFF00A4F75D8", 16), "match_policy",       "copyin d=0 from v70"),
]

MAX_DECOMPILE_SEC = 90
BUDGET_SEC = 600

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
            nm = "nk_%X" % addr
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


def sign26(x):
    if x & 0x02000000:
        return x - 0x04000000
    return x


_blocks = None


def blocks():
    global _blocks
    if _blocks is not None:
        return _blocks
    out = []
    try:
        for b in currentProgram.getMemory().getBlocks():
            if not b.isInitialized():
                continue
            if not b.isExecute():
                continue
            s = _u(b.getStart().getOffset())
            e = _u(b.getEnd().getOffset())
            out.append((s, e))
    except Exception:
        pass
    _blocks = out
    return out


def bl_callers(target, max_hits=30, budget=40):
    hits = []
    mem = currentProgram.getMemory()
    ts = time.time()
    for pair in blocks():
        if time.time() - ts > budget:
            break
        s = pair[0]
        e = pair[1]
        size = e - s + 1
        if size <= 0:
            continue
        if size > 0x1000000:
            continue
        try:
            jbuf = zeros(size, 'b')
            ga = sa(s)
            if ga is None:
                continue
            mem.getBytes(ga, jbuf)
        except Exception:
            continue
        pc = s
        i = 0
        while i + 4 <= size:
            b0 = int(jbuf[i]) & 0xFF
            b1 = int(jbuf[i + 1]) & 0xFF
            b2 = int(jbuf[i + 2]) & 0xFF
            b3 = int(jbuf[i + 3]) & 0xFF
            raw = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
            op = raw & 0xFC000000
            if op == 0x94000000 or op == 0x14000000:
                imm = sign26(raw & 0x03FFFFFF) << 2
                dst = (pc + imm) & 0xFFFFFFFFFFFFFFFF
                if dst == target:
                    kind = "BL"
                    if op == 0x14000000:
                        kind = "B"
                    hits.append((pc, kind))
                    if len(hits) >= max_hits:
                        del jbuf
                        return hits
            i += 4
            pc += 4
        del jbuf
    return hits


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
        return

    try:
        ent = _u(f.getEntryPoint().getOffset())
        sz = int(f.getBody().getNumAddresses())
        w("  func=%s entry=%s size=0x%X" % (str(f.getName()), fmt(ent), sz))
    except Exception:
        pass

    w("")
    w("-- BL callers --")
    try:
        hits = bl_callers(addr, 30, 40)
    except Exception:
        hits = []
    if not hits:
        w("  (none)")
    for pair in hits:
        pc = pair[0]
        kind = pair[1]
        cf = getFunctionContaining(sa(pc))
        nm = "?"
        if cf is not None:
            nm = str(cf.getName())
        cfe = 0
        if cf is not None:
            cfe = _u(cf.getEntryPoint().getOffset())
        w("  %s %s in %s @ %s" % (fmt(pc), kind, nm, fmt(cfe)))

    w("")
    w("-- decompile --")
    for l in decompile_text(f, MAX_DECOMPILE_SEC):
        w("  " + l)


def main():
    global START_TS
    START_TS = time.time()

    log("=== kernel_rw.py v71 ===")

    w("natsuk1 v71 necp_session_action surface")
    w("targets=%d" % len(DUMP_TARGETS))
    w("")

    for entry in DUMP_TARGETS:
        addr = entry[0]
        name = entry[1]
        note = entry[2]
        log("[*] %s @ %s" % (name, fmt(addr)))
        if time.time() - START_TS > BUDGET_SEC:
            w("BUDGET EXCEEDED at %s" % name)
            break
        try:
            dump_one(addr, name, note)
        except Exception as e:
            w("  exception: %s" % e)

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