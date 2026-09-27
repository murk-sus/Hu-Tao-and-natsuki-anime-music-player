# -*- coding: utf-8 -*-
# @runtime Jython
# kernel_rw.py v52 - dump the 5 remaining targets

import os
import sys
import time
import traceback
from jarray import zeros
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.pcode import PcodeOp

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

A_78A39C  = int("FFFFFFF00A78A39C", 16)
A_8BBF38  = int("FFFFFFF00A8BBF38", 16)
A_8BBD20  = int("FFFFFFF00A8BBD20", 16)
A_755BC4  = int("FFFFFFF00A755BC4", 16)
A_398DBC  = int("FFFFFFF00A398DBC", 16)

DUMP_TARGETS = [
    (A_78A39C,  "fun_78a39c",  "called from sysent_100/106 when >= 0x81"),
    (A_8BBF38,  "fun_8bbf38",  "IOKit target from sysent_69"),
    (A_8BBD20,  "fun_8bbd20",  "IOKit target from sysent_70"),
    (A_755BC4,  "sysent_501",  "sy_call[501]"),
    (A_398DBC,  "sysent_502",  "sy_call[502]"),
]

A_KALLOC   = int("FFFFFFF00A200988", 16)
A_KALLOC_Z = int("FFFFFFF00A20141C", 16)
A_COPYIN   = int("FFFFFFF00A368EC0", 16)
A_COPYOUT  = int("FFFFFFF00A369A3C", 16)
A_MEMMOVE  = int("FFFFFFF00AA40D30", 16)
A_MEMSET   = int("FFFFFFF00AA40EE0", 16)

SINK_LIST = [
    ("kalloc_type", A_KALLOC, 1),
    ("kalloc_zone", A_KALLOC_Z, 1),
    ("copyin", A_COPYIN, 3),
    ("copyout", A_COPYOUT, 3),
    ("memmove", A_MEMMOVE, 3),
    ("memset", A_MEMSET, 3),
]
SINK_MAP = {}
for sk in SINK_LIST:
    SINK_MAP[sk[1]] = (sk[0], sk[2])

DEC = None
MONITOR = ConsoleTaskMonitor()
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
            name = "nk_%X" % addr
            f = fm.createFunction(ga, name)
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


def decompile_hf(f, sec=60):
    try:
        r = get_dec().decompileFunction(f, sec, MONITOR)
        if r is None:
            return None
        if not r.decompileCompleted():
            return None
        return r.getHighFunction()
    except Exception:
        return None


def decompile_text(f, sec=90):
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


def vn_key(vn):
    if vn is None:
        return None
    try:
        a = vn.getAddress()
        if a is None:
            return None
        return a.toString() + ":" + str(vn.getSize())
    except Exception:
        return None


def get_param_keys(hf):
    result = {}
    try:
        lsm = hf.getLocalSymbolMap()
        if lsm is None:
            return result
        syms = lsm.getSymbols()
        if syms is None:
            return result
        cnt = 0
        while syms.hasNext():
            cnt += 1
            if cnt > 500:
                break
            sym = syms.next()
            ok = False
            try:
                ok = sym.isParameter()
            except Exception:
                ok = False
            if not ok:
                continue
            cat = 0
            try:
                cat = sym.getCategoryIndex()
            except Exception:
                cat = 0
            hv = None
            try:
                hv = sym.getHighVariable()
            except Exception:
                hv = None
            if hv is None:
                continue
            insts = None
            try:
                insts = hv.getInstances()
            except Exception:
                insts = None
            if insts is None:
                continue
            try:
                for vn in insts:
                    k = vn_key(vn)
                    if k is None:
                        continue
                    cur = result.get(cat)
                    if cur is None:
                        cur = set()
                        result[cat] = cur
                    cur.add(k)
            except Exception:
                pass
    except Exception:
        pass
    return result


def propagate(hf, tainted_idx):
    pm = get_param_keys(hf)
    tainted = set()
    for i in tainted_idx:
        cur = pm.get(i)
        if cur is None:
            continue
        for k in cur:
            tainted.add(k)
    if not tainted:
        return tainted
    try:
        all_ops = list(hf.getPcodeOps())
    except Exception:
        return tainted
    changed = True
    iters = 0
    while changed and iters < 200:
        changed = False
        iters += 1
        for op in all_ops:
            try:
                out = op.getOutput()
                if out is None:
                    continue
                ok = vn_key(out)
                if ok is None:
                    continue
                if ok in tainted:
                    continue
                hit = False
                for i in range(op.getNumInputs()):
                    ik = vn_key(op.getInput(i))
                    if ik is None:
                        continue
                    if ik in tainted:
                        hit = True
                        break
                if hit:
                    tainted.add(ok)
                    changed = True
            except Exception:
                pass
    return tainted


def call_target(op):
    try:
        inp0 = op.getInput(0)
        if inp0.isAddress():
            return _u(inp0.getAddress().getOffset())
        if inp0.isConstant():
            return _u(inp0.getOffset())
    except Exception:
        pass
    return None


def collect_sinks_local(f):
    """Find all sink calls in one function with taint info; also list callees."""
    sinks = []
    callees = []
    hf = decompile_hf(f, 60)
    if hf is None:
        return sinks, callees
    tainted = propagate(hf, frozenset(range(8)))
    try:
        all_ops = list(hf.getPcodeOps())
    except Exception:
        return sinks, callees
    seen_calls = {}
    for op in all_ops:
        is_call = False
        try:
            is_call = op.getOpcode() == PcodeOp.CALL
        except Exception:
            is_call = False
        if not is_call:
            continue
        target = call_target(op)
        if target is None:
            continue
        v = SINK_MAP.get(target)
        if v is not None:
            sname = v[0]
            sidx = v[1]
            taint_hit = False
            try:
                if sidx < op.getNumInputs():
                    sk = vn_key(op.getInput(sidx))
                    if sk is not None and sk in tainted:
                        taint_hit = True
            except Exception:
                pass
            pc = 0
            try:
                pc = _u(op.getSeqnum().getTarget().getOffset())
            except Exception:
                pc = 0
            sinks.append((sname, fmt(pc), taint_hit))
        else:
            # record callee
            if target not in seen_calls:
                seen_calls[target] = 0
            seen_calls[target] = seen_calls[target] + 1
    for target, cnt in seen_calls.items():
        cf = getFunctionContaining(sa(target))
        nm = "?"
        cfe = target
        if cf is not None:
            nm = str(cf.getName())
            cfe = _u(cf.getEntryPoint().getOffset())
        callees.append((target, nm, cfe, cnt))
    callees.sort(key=lambda x: x[0])
    return sinks, callees


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


def sign26(x):
    if x & 0x02000000:
        return x - 0x04000000
    return x


def bl_callers(target, max_hits=15, budget=45):
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


def main():
    log("=== kernel_rw.py v52 dump 5 ===")

    w("natsuk1 dump-5 targets v52")
    w("has_disasm=%s has_create=%s" % (HAS_DISASM, HAS_CREATE))
    w("")

    for entry in DUMP_TARGETS:
        addr = entry[0]
        name = entry[1]
        note = entry[2]
        log("[*] %s @ %s" % (name, fmt(addr)))

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
            continue

        try:
            ent = _u(f.getEntryPoint().getOffset())
            sz = int(f.getBody().getNumAddresses())
            w("  func=%s entry=%s size=0x%X" % (str(f.getName()), fmt(ent), sz))
        except Exception:
            pass

        w("")
        w("-- BL callers --")
        try:
            hits = bl_callers(addr, 15, 45)
        except Exception as e:
            hits = []
            w("  exception %s" % e)
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
        w("-- sink calls + taint --")
        try:
            sinks, callees = collect_sinks_local(f)
        except Exception as e:
            sinks, callees = [], []
            w("  exception %s" % e)
        if not sinks:
            w("  no sink calls in body")
        for snk in sinks:
            w("  %s @ %s tainted=%s" % (snk[0], snk[1], snk[2]))

        w("")
        w("-- callees --")
        for ce in callees[:40]:
            w("  %s  %s  @ %s  x%d" % (fmt(ce[0]), ce[1], fmt(ce[2]), ce[3]))

        w("")
        w("-- decompile --")
        for l in decompile_text(f, 90):
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