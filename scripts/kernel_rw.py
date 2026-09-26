# -*- coding: utf-8 -*-
# @runtime Jython
# kernel_rw.py v44 - taint via LocalSymbolMap, high limits

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

MAX_DECOMPILE_SEC = 45
MAX_ANALYZED = 20000
MAX_WORKLIST = 50000
TOTAL_BUDGET_SEC = 14400
MAX_DEPTH = 12

SINKS = [
    ("kalloc_type", 0xFFFFFFF00A200988, 1),
    ("kalloc_zone", 0xFFFFFFF00A20141C, 1),
    ("copyin",      0xFFFFFFF00A368EC0, 3),
    ("copyout",     0xFFFFFFF00A369A3C, 3),
    ("memmove",     0xFFFFFFF00AA40D30, 3),
    ("memset",      0xFFFFFFF00AA40EE0, 3),
]
SINK_BY_ADDR = {}
for n, a, i in SINKS:
    SINK_BY_ADDR[a] = (n, i)

SOURCES = [
    (0xFFFFFFF00A4E5C28, "necp_client_action"),
    (0xFFFFFFF00A4E843C, "necp_client_add_flow"),
    (0xFFFFFFF00A4E60DC, "necp_client_add_client"),
    (0xFFFFFFF00A4E93C4, "necp_client_remove_flow"),
    (0xFFFFFFF00A4E76F4, "necp_client_remove_client"),
    (0xFFFFFFF00A4E7BE8, "necp_client_copy_result"),
    (0xFFFFFFF00A4E80FC, "necp_client_copy_list"),
    (0xFFFFFFF00A4EAC7C, "necp_client_copy_interface"),
    (0xFFFFFFF00A4EB704, "necp_client_sysctl_arena"),
    (0xFFFFFFF00A4EBD58, "necp_client_update_cache"),
    (0xFFFFFFF00A4EC264, "necp_client_copy_update"),
    (0xFFFFFFF00A4E9904, "necp_client_request_nexus"),
    (0xFFFFFFF00A4EA0B4, "necp_client_agent_action"),
    (0xFFFFFFF00A4EA778, "necp_client_copy_agent"),
    (0xFFFFFFF00A4EBA0C, "necp_client_copy_route_stats"),
    (0xFFFFFFF00A4EA8A0, "necp_client_copy_parameters"),
    (0xFFFFFFF00A4E7158, "necp_client_claim"),
    (0xFFFFFFF00A4EC5D8, "necp_client_sign"),
    (0xFFFFFFF00A4EB2B4, "necp_client_get_iface_addr"),
    (0xFFFFFFF00A4EAB50, "necp_client_copy_agent_alt"),
    (0xFFFFFFF00A4EC9EC, "necp_client_validate"),
    (0xFFFFFFF00A4ECC4C, "necp_client_get_signed_id"),
    (0xFFFFFFF00A4ECE88, "necp_client_set_signed_id"),
    (0xFFFFFFF00A4ED170, "necp_client_get_flow_stats"),
]

DEC = None
MONITOR = ConsoleTaskMonitor()
START_TS = time.time()


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


def disassemble(addr):
    if not HAS_DISASM:
        return
    try:
        ga = sa(addr)
        if ga is None:
            return
        cmd = _DC(ga, None, True)
        cmd.applyTo(currentProgram)
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
                ccmd = _CFC(ga)
                ccmd.applyTo(currentProgram)
            except Exception:
                pass
        try:
            fm = currentProgram.getFunctionManager()
            f = fm.createFunction(ga, "nk_%X" % addr)
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


def decompile(f, seconds=MAX_DECOMPILE_SEC):
    try:
        r = get_dec().decompileFunction(f, seconds, MONITOR)
        if r is None or not r.decompileCompleted():
            return None
        return r.getHighFunction()
    except Exception:
        return None


def vn_key(vn):
    if vn is None:
        return None
    try:
        a = vn.getAddress()
        if a is None:
            return None
        return "%s:%d" % (a.toString(), vn.getSize())
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
        count = 0
        while syms.hasNext():
            count += 1
            if count > 500:
                break
            sym = syms.next()
            try:
                if not sym.isParameter():
                    continue
            except Exception:
                continue
            try:
                cat = sym.getCategoryIndex()
            except Exception:
                cat = 0
            try:
                hv = sym.getHighVariable()
            except Exception:
                hv = None
            if hv is None:
                continue
            try:
                insts = hv.getInstances()
            except Exception:
                insts = None
            if insts is None:
                continue
            try:
                for vn in insts:
                    k = vn_key(vn)
                    if k is not None:
                        result.setdefault(cat, set()).add(k)
            except Exception:
                pass
    except Exception:
        pass
    return result


def propagate_taint(hf, tainted_param_idx, diag):
    param_map = get_param_keys(hf)
    diag["params_found"] = sum(len(v) for v in param_map.values())
    diag["param_cats"] = sorted(param_map.keys())

    tainted = set()
    for i in tainted_param_idx:
        for k in param_map.get(i, set()):
            tainted.add(k)

    if not tainted:
        diag["seed_count"] = 0
        return tainted

    diag["seed_count"] = len(tainted)

    try:
        all_ops = list(hf.getPcodeOps())
    except Exception:
        return tainted

    diag["op_count"] = len(all_ops)

    changed = True
    iters = 0
    while changed and iters < 300:
        changed = False
        iters += 1
        for op in all_ops:
            try:
                out = op.getOutput()
                if out is None:
                    continue
                ok = vn_key(out)
                if ok is None or ok in tainted:
                    continue
                hit = False
                for i in range(op.getNumInputs()):
                    try:
                        inp = op.getInput(i)
                        ik = vn_key(inp)
                        if ik is not None and ik in tainted:
                            hit = True
                            break
                    except Exception:
                        pass
                if hit:
                    tainted.add(ok)
                    changed = True
            except Exception:
                pass
    diag["prop_iters"] = iters
    return tainted


def resolve_call_target(op):
    try:
        inp0 = op.getInput(0)
        if inp0.isAddress():
            return _u(inp0.getAddress().getOffset())
        if inp0.isConstant():
            return _u(inp0.getOffset())
    except Exception:
        pass
    return None


def analyze_source(start_addr, start_name, L):
    worklist = [(start_addr, frozenset([0, 1, 2, 3, 4, 5, 6, 7]), 0)]
    findings = []
    local_analyzed = set()

    while worklist:
        if len(local_analyzed) >= MAX_ANALYZED:
            L.append("    analyzed limit reached")
            break
        if time.time() - START_TS > TOTAL_BUDGET_SEC:
            L.append("    budget exceeded")
            break

        addr, tainted_idx, depth = worklist.pop(0)
        key = (addr, tainted_idx)
        if key in local_analyzed:
            continue
        local_analyzed.add(key)

        f = get_func(addr)
        if f is None:
            f = ensure_function(addr)
        if f is None:
            continue

        hf = decompile(f)
        if hf is None:
            continue

        diag = {}
        tainted = propagate_taint(hf, tainted_idx, diag)

        try:
            fname = str(f.getName())
        except Exception:
            fname = "?"

        L.append("    [%s @ %s d=%d] params=%s cats=%s ops=%s seed=%s tainted=%d iters=%s" % (
            fname, fmt(addr), depth,
            diag.get("params_found", "?"),
            diag.get("param_cats", "?"),
            diag.get("op_count", "?"),
            diag.get("seed_count", 0),
            len(tainted),
            diag.get("prop_iters", "?"),
        ))

        if not tainted:
            continue

        try:
            all_ops = list(hf.getPcodeOps())
        except Exception:
            continue

        for op in all_ops:
            try:
                oc = op.getOpcode()
            except Exception:
                continue
            if oc != PcodeOp.CALL:
                continue

            target = resolve_call_target(op)
            if target is None:
                continue

            if target in SINK_BY_ADDR:
                sink_name, input_idx = SINK_BY_ADDR[target]
                try:
                    if input_idx < op.getNumInputs():
                        size_arg = op.getInput(input_idx)
                        sk = vn_key(size_arg)
                        if sk is not None and sk in tainted:
                            try:
                                pc = _u(op.getSeqnum().getTarget().getOffset())
                            except Exception:
                                pc = 0
                            findings.append({
                                "sink": sink_name,
                                "pc": fmt(pc),
                                "in_func": fname,
                                "in_func_addr": fmt(addr),
                                "depth": depth,
                                "via": start_name,
                            })
                except Exception:
                    pass
                continue

            new_tainted = set()
            try:
                num_args = op.getNumInputs() - 1
                for i in range(num_args):
                    arg = op.getInput(1 + i)
                    ak = vn_key(arg)
                    if ak is not None and ak in tainted:
                        new_tainted.add(i)
            except Exception:
                pass
            if new_tainted and depth < MAX_DEPTH:
                callee = get_func(target)
                if callee is not None:
                    worklist.append((target, frozenset(new_tainted), depth + 1))
                    if len(worklist) > MAX_WORKLIST:
                        L.append("    worklist limit")
                        break

    return findings


def main():
    global START_TS
    START_TS = time.time()

    L = []
    def w(s):
        L.append(s)

    log("=== kernel_rw.py v44 ===")
    log("program: %s" % currentProgram.getName())

    w("=== PROGRAM ===")
    w("name = %s" % currentProgram.getName())
    w("has_disasm=%s has_create=%s" % (HAS_DISASM, HAS_CREATE))
    w("SOURCES: %d" % len(SOURCES))
    w("SINKS: %s" % ",".join([s[0] for s in SINKS]))
    w("LIMITS: depth=%d analyzed=%d worklist=%d budget=%ds" % (
        MAX_DEPTH, MAX_ANALYZED, MAX_WORKLIST, TOTAL_BUDGET_SEC))
    w("")

    all_findings = []

    for idx, (addr, name) in enumerate(SOURCES):
        log("[%d/%d] %s" % (idx + 1, len(SOURCES), name))
        w("")
        w(SEP)
        w("### SOURCE %s @ %s" % (name, fmt(addr)))
        w(SEP)

        try:
            f = get_func(addr)
            if f is None:
                f = ensure_function(addr)
            if f is None:
                w("  no function")
                continue
            findings = analyze_source(addr, name, L)
        except Exception as ex:
            findings = []
            L.append("  exception %s" % ex)

        if not findings:
            w("  no tainted sinks reached")
        else:
            for fd in findings:
                w("  SINK %-12s @ %s  in %s (%s)  depth=%d" % (
                    fd["sink"], fd["pc"], fd["in_func"], fd["in_func_addr"], fd["depth"]))
                all_findings.append(fd)

    w("")
    w(SEP)
    w("### SUMMARY")
    w(SEP)
    w("total findings: %d" % len(all_findings))
    w("")
    by_sink = {}
    for fd in all_findings:
        by_sink.setdefault(fd["sink"], []).append(fd)
    for sk in sorted(by_sink.keys()):
        w("  %s: %d" % (sk, len(by_sink[sk])))
        for fd in by_sink[sk]:
            w("    %-28s -> sink @ %s in %s d=%d" % (
                fd["via"], fd["pc"], fd["in_func"], fd["depth"]))

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