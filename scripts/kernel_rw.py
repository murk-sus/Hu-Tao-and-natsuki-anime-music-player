# -*- coding: utf-8 -*-
# @runtime Jython
# kernel_rw.py v39 - caller trace for tier1/tier2 candidates

import os
import sys
import time
import traceback
from jarray import zeros
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WS, "result.txt")
SEP = "=" * 72
MAX_DECOMPILE_SEC = 90

TRACE_TARGETS = [
    ("fun_3187f4",  0xFFFFFFF00A3187F4, "param->kalloc+copyin"),
    ("fun_734ba0",  0xFFFFFFF00A734BA0, "param->kalloc+copyin"),
    ("fun_78a39c",  0xFFFFFFF00A78A39C, "param->kalloc"),
    ("fun_6c4b10",  0xFFFFFFF00A6C4B10, "count*24+44 / count*24"),
    ("fun_3cd8b0",  0xFFFFFFF00A3CD8B0, "other+1 / param*param"),
    ("fun_78e070",  0xFFFFFFF00A78E070, "load*56 / load*32"),
]

MAX_DEPTH = 3

DEC = None
MONITOR = ConsoleTaskMonitor()


def log(msg):
    print(msg)
    sys.stdout.flush()


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


def sign26(x):
    if x & 0x02000000:
        return x - 0x04000000
    return x


def get_dec():
    global DEC
    if DEC is not None:
        return DEC
    d = DecompInterface()
    d.openProgram(currentProgram)
    DEC = d
    return DEC


def decompile(f, seconds=MAX_DECOMPILE_SEC):
    try:
        d = get_dec()
        r = d.decompileFunction(f, seconds, MONITOR)
        if r is None:
            return ["(no result)"]
        if not r.decompileCompleted():
            return ["(failed)"]
        c = r.getDecompiledFunction()
        if c is None:
            return ["(empty)"]
        return [line.rstrip() for line in c.getC().split("\n")]
    except Exception as e:
        return ["(exception %s)" % e]


_blocks = None


def blocks():
    global _blocks
    if _blocks is not None:
        return _blocks
    out = []
    try:
        for b in currentProgram.getMemory().getBlocks():
            try:
                if not b.isInitialized():
                    continue
                if not b.isExecute():
                    continue
                s = _u(b.getStart().getOffset())
                e = _u(b.getEnd().getOffset())
                out.append((s, e, str(b.getName())))
            except Exception:
                pass
    except Exception:
        pass
    _blocks = out
    return out


def bl_callers_global(target, max_hits=60, budget=120):
    hits = []
    mem = currentProgram.getMemory()
    start_ts = time.time()
    for s, e, name in blocks():
        if time.time() - start_ts > budget:
            log("  budget exceeded")
            break
        size = e - s + 1
        if size <= 0 or size > 0x1000000:
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
            raw = (int(jbuf[i]) & 0xFF) | ((int(jbuf[i+1]) & 0xFF) << 8) | \
                  ((int(jbuf[i+2]) & 0xFF) << 16) | ((int(jbuf[i+3]) & 0xFF) << 24)
            op = raw & 0xFC000000
            if op == 0x94000000 or op == 0x14000000:
                imm = sign26(raw & 0x03FFFFFF) << 2
                dst = (pc + imm) & 0xFFFFFFFFFFFFFFFF
                if dst == target:
                    hits.append((pc, "BL" if op == 0x94000000 else "B"))
                    if len(hits) >= max_hits:
                        del jbuf
                        return hits
            i += 4
            pc += 4
        del jbuf
    return hits


def collect_bl_targets(func):
    found = set()
    try:
        body = func.getBody()
        if body is None:
            return found
        it = body.getAddresses(True)
    except Exception:
        return found
    cnt = 0
    while it.hasNext() and cnt < 80000:
        try:
            a = it.next()
            pc = _u(a.getOffset())
            raw = int(currentProgram.getMemory().getInt(a)) & 0xFFFFFFFF
        except Exception:
            cnt += 1
            continue
        cnt += 1
        if (raw & 0xFC000000) == 0x94000000:
            imm = sign26(raw & 0x03FFFFFF) << 2
            dst = (pc + imm) & 0xFFFFFFFFFFFFFFFF
            found.add(dst)
    return found


(def walk_callers(f, depth, visited, w):
    if depth > MAX_DEPTH:
        return
    try:
        ent = _u(f.getEntryPoint().getOffset())
    except Exception:
        return
    if ent in visited:
        return
    visited.addent)
    try:
        callees = f.getCalledFunctions(MONITOR)
    except Exception:
        callees = None
    if not callees:
        return
    for cf in callees:
        try:
            cfe = _u(cf.getEntryPoint().getOffset())
        except Exception:
            continue
        if cfe in visited:
            continue
        # every callee: emit and recurse
        try:
            cfname = str(cf.getName())
            cfsz = int(cf.getBody().getNumAddresses())
        except Exception:
            cfname = "?"
            cfsz = 0
        indent = "  " * depth
        w("%s[%d] callee %s @ %s size=0x%X" % (indent, depth, cfname, fmt(cfe), cfsz))
        walk_callers(cf, depth + 1, visited, w)


def main():
    L = []
    def w(s):
        L.append(s)

    log("=== kernel_rw.py v39 ===")
    log("program: %s" % currentProgram.getName())

    w("=== PROGRAM ===")
    w("name = %s" % currentProgram.getName())
    w("")

    for label, addr, note in TRACE_TARGETS:
        log("[*] tracing %s @ %s (%s)" % (label, fmt(addr), note))
        w("")
        w(SEP)
        w("### TARGET %s @ %s" % (label, fmt(addr)))
        w("note: %s" % note)
        w(SEP)

        # direct global BL callers of the target
        w("")
        w("-- global BL callers --")
        try:
            hits = bl_callers_global(addr, 60)
        except Exception as ex:
            w("  exception %s" % ex)
            hits = []
        if not hits:
            w("  (none — indirect or via sysent)")
        callers = []
        for pc, kind in hits:
            cf = getFunctionContaining(sa(pc))
            if cf is None:
                continue
            cfe = _u(cf.getEntryPoint().getOffset())
            cfname = str(cf.getName())
            try:
                cfsz = int(cf.getBody().getNumAddresses())
            except Exception:
                cfsz = 0
            w("  %s  %s  @  %s  size=0x%X" % (fmt(pc), kind, cfname, cfsz))
            callers.append((cfe, cfname, cf))

        # decompile each unique caller, one level
        seen_callers = set()
        for cfe, cfname, cf in callers:
            if cfe in seen_callers:
                continue
            seen_callers.add(cfe)
            w("")
            w("-- caller %s @ %s --" % (cfname, fmt(cfe)))
            try:
                for l in decompile(cf, 60):
                    w("  %s" % l)
            except Exception as ex:
                w("  exception %s" % ex)

        # direct decompile of target itself for reference
        tf = get_func(addr)
        if tf is not None:
            w("")
            w("-- target decompile --")
            try:
                for l in decompile(tf, 90):
                    w("  %s" % l)
            except Exception as ex:
                w("  exception %s" % ex)

    try:
        fh = open(OUT, "w")
        for l in L:
            fh.write(l + "\n")
        fh.close()
        log("[+] wrote %s" % OUT)
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