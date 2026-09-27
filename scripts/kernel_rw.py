# -*- coding: utf-8 -*-
# @runtime Jython
# kernel_rw.py v73 - match_policy + raw_lookup callers

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

MATCH_POLICY = int("FFFFFFF00A4F75D8", 16)
RAW_LOOKUP   = int("FFFFFFF00A4DB8D4", 16)
SESS_LOOKUP  = int("FFFFFFF00A4ED864", 16)

MAX_DECOMPILE_SEC = 90
BUDGET_SEC = 600
MAX_CALLERS = 40

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


def bl_callers(target, max_hits=MAX_CALLERS, budget=40):
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


def collect_callees_with_target(f, target):
    """Return list of (pc, kind) where f calls target directly."""
    hits = []
    try:
        listing = currentProgram.getListing()
        body = f.getBody()
        it = body.getAddresses(True)
    except Exception:
        return hits
    cnt = 0
    while it.hasNext() and cnt < 40000:
        a = it.next()
        cnt += 1
        try:
            insn = listing.getInstructionAt(a)
            if insn is None:
                continue
            pcode = insn.getPcode()
            if pcode is None:
                continue
            for p in pcode:
                if p.getOpcode() != 1:
                    continue
                inp0 = p.getInput(0)
                tgt = None
                if inp0.isAddress():
                    tgt = _u(inp0.getAddress().getOffset())
                elif inp0.isConstant():
                    tgt = _u(inp0.getOffset())
                if tgt == target:
                    hits.append(_u(a.getOffset()))
        except Exception:
            pass
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
        hits = bl_callers(addr, MAX_CALLERS, 40)
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

    log("=== kernel_rw.py v73 ===")

    w("natsuk1 v73 match_policy + raw_lookup callers")
    w("")

    # 1. Full dump of necp_match_policy
    dump_one(MATCH_POLICY, "necp_match_policy", "sysent[462] entry - d=0 copyin from v70")

    # 2. Full dump of raw_lookup itself (for reference)
    dump_one(RAW_LOOKUP, "raw_lookup", "lookup without ref")

    # 3. All direct callers of raw_lookup
    if time.time() - START_TS < BUDGET_SEC:
        log("[*] scanning direct callers of raw_lookup")
        try:
            hits = bl_callers(RAW_LOOKUP, MAX_CALLERS, 40)
        except Exception:
            hits = []

        w("")
        w(SEP)
        w("### RAW_LOOKUP CALLERS (%d)" % len(hits))
        w(SEP)

        seen_fns = set()
        for pair in hits:
            pc = pair[0]
            kind = pair[1]
            cf = getFunctionContaining(sa(pc))
            if cf is None:
                continue
            cfe = _u(cf.getEntryPoint().getOffset())
            if cfe in seen_fns:
                continue
            seen_fns.add(cfe)
            w("  caller: %s @ %s  (call pc=%s %s)" % (str(cf.getName()), fmt(cfe), fmt(pc), kind))

        w("")
        w("### RAW_LOOKUP CALLER BODIES")

        for cfe in sorted(seen_fns):
            if time.time() - START_TS > BUDGET_SEC:
                w("BUDGET EXCEEDED")
                break
            cf = get_func(cfe)
            if cf is None:
                continue
            nm = "?"
            try:
                nm = str(cf.getName())
            except Exception:
                pass
            log("[*] caller body: %s @ %s" % (nm, fmt(cfe)))
            w("")
            w(SEP)
            w("### caller_%s @ %s" % (nm[:40], fmt(cfe)))
            w(SEP)
            try:
                sz = int(cf.getBody().getNumAddresses())
                w("  size=0x%X" % sz)
            except Exception:
                pass
            # find where raw_lookup is called and print context
            call_pcs = collect_callees_with_target(cf, RAW_LOOKUP)
            if call_pcs:
                w("  raw_lookup called at: %s" % ", ".join([fmt(p) for p in call_pcs]))
            w("  decompile:")
            for l in decompile_text(cf, MAX_DECOMPILE_SEC):
                w("  " + l)

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