# -*- coding: utf-8 -*-
# @runtime Jython
# kernel_rw.py v38 - fixed pcode API

import os
import sys
import time
import traceback
from jarray import zeros
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.pcode import PcodeOp

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WS, "result.txt")
SEP = "=" * 72

SCAN_RANGES = [
    (0xFFFFFFF00A300000, 0xFFFFFFF00A520000),
    (0xFFFFFFF00A6C0000, 0xFFFFFFF00A780000),
    (0xFFFFFFF00A780000, 0xFFFFFFF00A800000),
]

KALLOC   = 0xFFFFFFF00A200988
KALLOC_Z = 0xFFFFFFF00A20141C
COPYIN   = 0xFFFFFFF00A368EC0
COPYOUT  = 0xFFFFFFF00A369A3C

SINKS = [
    ("kalloc_type", KALLOC, 1),
    ("kalloc_zone", KALLOC_Z, 1),
    ("copyin",      COPYIN, 2),
    ("copyout",     COPYOUT, 2),
]

ARITH = set()
for nm in ["INT_ADD","INT_SUB","INT_MULT","INT_DIV","INT_REM",
           "INT_LEFT","INT_RIGHT","INT_AND","INT_OR","INT_XOR",
           "INT_ZEXT","INT_SEXT","INT_2COMP"]:
    v = getattr(PcodeOp, nm, None)
    if v is not None:
        ARITH.add(v)

CMP = set()
for nm in ["INT_LESS","INT_LESSEQUAL","INT_SLESS","INT_SLESSEQUAL",
           "INT_EQUAL","INT_NOTEQUAL","INT_CARRY","INT_SCARRY"]:
    v = getattr(PcodeOp, nm, None)
    if v is not None:
        CMP.add(v)

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


def in_ranges(addr):
    a = _u(addr)
    for lo, hi in SCAN_RANGES:
        if lo <= a < hi:
            return True
    return False


def bl_scan_func(func):
    found = set()
    try:
        body = func.getBody()
        if body is None:
            return found
        it = body.getAddresses(True)
    except Exception:
        return found
    cnt = 0
    while it.hasNext() and cnt < 100000:
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
            for nm, addr, arg in SINKS:
                if dst == addr:
                    found.add(nm)
    return found


def vn_key(vn):
    try:
        a = vn.getAddress()
        return "%s_%d" % (a.toString(), vn.getSize())
    except Exception:
        return "?"


def vn_reg_name(vn):
    try:
        a = vn.getAddress()
        if a is None:
            return None
        if a.isRegister():
            return a.toString()
    except Exception:
        pass
    return None


def classify(vn, depth, seen):
    if depth > 12:
        return ("depth", None)
    k = vn_key(vn)
    if k in seen:
        return ("cycle", None)
    seen2 = set(seen)
    seen2.add(k)

    try:
        if vn.isConstant():
            return ("const", vn.getOffset())
    except Exception:
        pass
    try:
        if vn.isInput():
            return ("param", vn_reg_name(vn))
    except Exception:
        pass

    try:
        defop = vn.getDef()
    except Exception:
        defop = None
    if defop is None:
        return ("undef", None)

    try:
        oc = defop.getOpcode()
    except Exception:
        return ("op_err", None)

    if oc in ARITH:
        parts = []
        for i in range(defop.getNumInputs()):
            try:
                sub = classify(defop.getInput(i), depth + 1, seen2)
                parts.append(sub)
            except Exception:
                parts.append(("err", None))
        try:
            mn = defop.getMnemonic()
        except Exception:
            mn = "?"
        return ("arith", (mn, parts))

    if oc == PcodeOp.LOAD:
        try:
            off = defop.getInput(1)
            if off.isConstant():
                return ("load_off", off.getOffset())
        except Exception:
            pass
        return ("load_dyn", None)

    if oc == PcodeOp.CALL:
        try:
            tgt = defop.getInput(0)
            if tgt.isAddress():
                return ("call_ret", _u(tgt.getAddress().getOffset()))
            if tgt.isConstant():
                return ("call_ret", _u(tgt.getOffset()))
        except Exception:
            pass
        return ("call_ret", None)

    if oc == PcodeOp.MULTIEQUAL:
        parts = []
        for i in range(defop.getNumInputs()):
            try:
                parts.append(classify(defop.getInput(i), depth + 1, seen2))
            except Exception:
                parts.append(("err", None))
        return ("phi", parts)

    return ("other", None)


def collect_tags(node, out_tags, out_arith, out_params):
    tag, val = node
    out_tags.add(tag)
    if tag == "arith":
        mn, parts = val
        if mn:
            out_arith.add(mn)
        for p in parts:
            collect_tags(p, out_tags, out_arith, out_params)
    elif tag == "phi":
        for p in val:
            collect_tags(p, out_tags, out_arith, out_params)
    elif tag == "param":
        if val:
            out_params.append(val)
    elif tag == "load_off":
        out_arith.add("LOAD@0x%X" % (int(val) & 0xFFFFFFFFFFFFFFFF))
    elif tag == "call_ret":
        if val is not None:
            out_arith.add("CALL@%s" % fmt(val))


def has_bounds_check(hf, size_vn):
    try:
        reg = vn_reg_name(size_vn)
        if reg is None:
            return False
        ops = hf.getPcodeOps()
        while ops.hasNext():
            op = ops.next()
            try:
                oc = op.getOpcode()
            except Exception:
                continue
            if oc not in CMP:
                continue
            for i in range(op.getNumInputs()):
                try:
                    rn = vn_reg_name(op.getInput(i))
                    if rn is not None and rn == reg:
                        return True
                except Exception:
                    pass
        return False
    except Exception:
        return False


def analyze_func(func, w):
    name = str(func.getName())
    ent = _u(func.getEntryPoint().getOffset())
    try:
        sz = int(func.getBody().getNumAddresses())
    except Exception:
        sz = 0
    w("")
    w(SEP)
    w("### %s  entry=%s  size=0x%X" % (name, fmt(ent), sz))
    w(SEP)

    try:
        res = get_dec().decompileFunction(func, 90, MONITOR)
        if res is None or not res.decompileCompleted():
            w("  (decompile failed)")
            return 0
        hf = res.getHighFunction()
        if hf is None:
            w("  (no high function)")
            return 0
    except Exception as e:
        w("  (decompile exception %s)" % e)
        return 0

    found = 0
    try:
        ops = hf.getPcodeOps()
    except Exception as e:
        w("  (no pcode ops: %s)" % e)
        return 0

    while ops.hasNext():
        op = ops.next()
        try:
            oc = op.getOpcode()
        except Exception:
            continue
        if oc != PcodeOp.CALL:
            continue
        try:
            target = op.getInput(0)
        except Exception:
            continue
        tgt_addr = None
        try:
            if target.isAddress():
                tgt_addr = _u(target.getAddress().getOffset())
            elif target.isConstant():
                tgt_addr = _u(target.getOffset())
        except Exception:
            tgt_addr = None
        if tgt_addr is None:
            continue

        for sink_name, sink_addr, size_idx in SINKS:
            if tgt_addr != sink_addr:
                continue
            found += 1
            ninputs = op.getNumInputs()
            if 1 + size_idx >= ninputs:
                continue
            try:
                size_vn = op.getInput(1 + size_idx)
            except Exception:
                continue

            try:
                pc = _u(op.getSeqnum().getTarget().getOffset())
            except Exception:
                pc = 0

            tags = set()
            arith = set()
            params = []
            node = classify(size_vn, 0, set())
            collect_tags(node, tags, arith, params)

            verdict = "unknown"
            if "const" in tags and not arith and not params:
                verdict = "SAFE_const"
            elif "param" in tags:
                verdict = "PARAM_SIZE"
            elif any(m in arith for m in ("INT_MULT", "INT_LEFT", "INT_ADD", "INT_SUB")):
                verdict = "ARITH_SIZE"
            elif "load_off" in tags or "load_dyn" in tags:
                verdict = "FIELD_SIZE"
            elif "call_ret" in tags:
                verdict = "CALL_RET_SIZE"
            elif "phi" in tags:
                verdict = "PHI_SIZE"
            elif "undef" in tags:
                verdict = "UNDEF_SIZE"

            bounded = has_bounds_check(hf, size_vn)

            w("  CALL %s @ %s" % (sink_name, fmt(pc)))
            try:
                w("    size_arg: %s" % size_vn.toString())
            except Exception:
                w("    size_arg: ?")
            w("    trace: %s" % repr(node))
            w("    tags: %s" % ",".join(sorted(tags)))
            if arith:
                w("    arith: %s" % ",".join(sorted(arith)))
            if params:
                w("    params: %s" % ",".join(params))
            w("    bounds_seen: %s" % bounded)
            w("    verdict: %s" % verdict)
            w("")
    return found


def main():
    L = []
    def w(s):
        L.append(s)

    log("=== kernel_rw.py v38 ===")
    log("program: %s" % currentProgram.getName())

    w("=== PROGRAM ===")
    w("name = %s" % currentProgram.getName())
    w("")
    w("SCAN_RANGES:")
    for lo, hi in SCAN_RANGES:
        w("  %s - %s" % (fmt(lo), fmt(hi)))
    w("")

    fm = currentProgram.getFunctionManager()
    all_funcs = list(fm.getFunctions(True))
    log("total functions: %d" % len(all_funcs))

    candidates = []
    for f in all_funcs:
        try:
            ent = _u(f.getEntryPoint().getOffset())
        except Exception:
            continue
        if not in_ranges(ent):
            continue
        found = bl_scan_func(f)
        if not found:
            continue
        has_alloc = ("kalloc_type" in found) or ("kalloc_zone" in found)
        has_copy = ("copyin" in found) or ("copyout" in found)
        if has_alloc and has_copy:
            candidates.append((f, found))

    log("candidates (alloc+copy): %d" % len(candidates))

    w(SEP)
    w("### CANDIDATES")
    w(SEP)
    for f, found in candidates:
        try:
            ent = _u(f.getEntryPoint().getOffset())
            w("  %s  %s  %s" % (fmt(ent), str(f.getName()), ",".join(sorted(found))))
        except Exception:
            pass
    w("")

    log("[*] analyzing")
    total = len(candidates)
    for idx, (f, found) in enumerate(candidates):
        try:
            log("  [%d/%d] %s" % (idx + 1, total, f.getName()))
        except Exception:
            pass
        try:
            analyze_func(f, w)
        except Exception as e:
            w("  ANALYSIS EXCEPTION: %s" % e)

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