# -*- coding: utf-8 -*-
# @runtime Jython
# kernel_rw.py v41 - taint graph from syscall sources to memory sinks

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

MAX_DECOMPILE_SEC = 30
MAX_ANALYZED = 500
MAX_WORKLIST = 2000
TOTAL_BUDGET_SEC = 1800

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
    try:
        a = vn.getAddress()
        return "%s_%d" % (a.toString(), vn.getSize())
    except Exception:
        return "?"


def get_param_vns(hf):
    result = []
    try:
        proto = hf.getFunctionPrototype()
        if proto is None:
            return result
        n = proto.getNumParams()
        for i in range(n):
            try:
                p = proto.getParam(i)
                if p is None:
                    continue
                storage = p.getStorage()
                if storage is None:
                    continue
                for vn in storage:
                    if vn is not None:
                        result.append((i, vn))
            except Exception:
                pass
    except Exception:
        pass
    return result


def propagate_taint(hf, tainted_param_idx, param_vns):
    tainted = set()
    for idx, vn in param_vns:
        if idx in tainted_param_idx:
            tainted.add(vn)
    if not tainted:
        return tainted
    try:
        all_ops = list(hf.getPcodeOps())
    except Exception:
        return tainted
    changed = True
    iters = 0
    while changed and iters < 60:
        changed = False
        iters += 1
        for op in all_ops:
            try:
                out = op.getOutput()
                if out is None:
                    continue
                if out in tainted:
                    continue
                hit = False
                for i in range(op.getNumInputs()):
                    try:
                        inp = op.getInput(i)
                        if inp in tainted:
                            hit = True
                            break
                    except Exception:
                        pass
                if hit:
                    tainted.add(out)
                    changed = True
            except Exception:
                pass
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


def analyze_source(start_addr, start_name, L, seen_states, seen_analyzed):
    worklist = [(start_addr, frozenset(range(8)), 0)]
    findings = []

    while worklist:
        if len(seen_analyzed) >= MAX_ANALYZED:
            break
        if time.time() - START_TS > TOTAL_BUDGET_SEC:
            L.append("")
            L.append("budget exceeded, stopping")
            break

        addr, tainted_idx, depth = worklist.pop(0)
        key = (addr, tainted_idx)
        if key in seen_states:
            continue
        seen_states.add(key)
        seen_analyzed.add(key)

        f = get_func(addr)
        if f is None:
            continue

        hf = decompile(f)
        if hf is None:
            continue

        param_vns = get_param_vns(hf)
        tainted = propagate_taint(hf, tainted_idx, param_vns)
        if not tainted:
            continue

        try:
            fname = str(f.getName())
        except Exception:
            fname = "?"

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

            # sink check
            if target in SINK_BY_ADDR:
                sink_name, input_idx = SINK_BY_ADDR[target]
                try:
                    if input_idx < op.getNumInputs():
                        size_arg = op.getInput(input_idx)
                        if size_arg in tainted:
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
                                "via_param": start_name,
                            })
                except Exception:
                    pass
                continue

            # recurse into callees if any arg tainted
            new_tainted = set()
            try:
                num_args = op.getNumInputs() - 1
                for i in range(num_args):
                    arg = op.getInput(1 + i)
                    if arg in tainted:
                        new_tainted.add(i)
            except Exception:
                pass
            if new_tainted and depth < 6:
                callee_addr = target
                # check callee exists
                if get_func(callee_addr) is not None:
                    worklist.append((callee_addr, frozenset(new_tainted), depth + 1))
                    if len(worklist) > MAX_WORKLIST:
                        break

    return findings


START_TS = time.time()


def main():
    global START_TS
    START_TS = time.time()

    L = []
    def w(s):
        L.append(s)

    log("=== kernel_rw.py v41 ===")
    log("program: %s" % currentProgram.getName())

    w("=== PROGRAM ===")
    w("name = %s" % currentProgram.getName())
    w("")
    w("SOURCES: %d" % len(SOURCES))
    w("SINKS: %s" % ",".join([s[0] for s in SINKS]))
    w("")

    all_findings = []
    seen_states = set()
    seen_analyzed = set()

    for idx, (addr, name) in enumerate(SOURCES):
        log("[%d/%d] %s @ %s" % (idx + 1, len(SOURCES), name, fmt(addr)))
        try:
            f = get_func(addr)
            if f is None:
                w("")
                w(SEP)
                w("### SOURCE %s @ %s" % (name, fmt(addr)))
                w("no function")
                continue
        except Exception as ex:
            continue

        try:
            findings = analyze_source(addr, name, L, seen_states, seen_analyzed)
        except Exception as ex:
            findings = []
            log("  exception %s" % ex)

        w("")
        w(SEP)
        w("### SOURCE %s @ %s" % (name, fmt(addr)))
        w(SEP)
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
            w("    from %-28s sink @ %s  in %s" % (
                fd["via_param"], fd["pc"], fd["in_func"]))

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