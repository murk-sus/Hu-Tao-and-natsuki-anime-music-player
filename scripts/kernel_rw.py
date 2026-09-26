# -*- coding: utf-8 -*-
# @runtime Jython
# kernel_rw.py v46 - compact: sinks + hot decompiles into one result.txt

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

TAINT_SEC = 900
DUMP_SEC = 300
MAX_ANALYZED = 20000
MAX_WORKLIST = 50000
MAX_DEPTH = 12
MAX_DECOMPILE_SEC = 45

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
            f = currentProgram.getFunctionManager().createFunction(ga, "nk_%X" % addr)
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


def decompile_hf(f, sec=MAX_DECOMPILE_SEC):
    try:
        r = get_dec().decompileFunction(f, sec, MONITOR)
        if r is None or not r.decompileCompleted():
            return None
        return r.getHighFunction()
    except Exception:
        return None


def decompile_text(f, sec=60):
    try:
        r = get_dec().decompileFunction(f, sec, MONITOR)
        if r is None or not r.decompileCompleted():
            return ["(decompile failed)"]
        c = r.getDecompiledFunction()
        if c is None:
            return ["(empty)"]
        return [line.rstrip() for line in c.getC().split("\n")]
    except Exception as e:
        return ["(exception %s)" % e]


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
        cnt = 0
        while syms.hasNext():
            cnt += 1
            if cnt > 500:
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


def propagate(hf, tainted_idx, diag):
    pm = get_param_keys(hf)
    diag["params"] = sum(len(v) for v in pm.values())
    diag["cats"] = sorted(pm.keys())
    tainted = set()
    for i in tainted_idx:
        for k in pm.get(i, set()):
            tainted.add(k)
    if not tainted:
        diag["seed"] = 0
        return tainted
    diag["seed"] = len(tainted)
    try:
        all_ops = list(hf.getPcodeOps())
    except Exception:
        return tainted
    diag["ops"] = len(all_ops)
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
                        ik = vn_key(op.getInput(i))
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
    diag["iters"] = iters
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


def analyze_source(start_addr, start_name):
    worklist = [(start_addr, frozenset(range(8)), 0)]
    findings = []
    local = set()
    while worklist:
        if len(local) >= MAX_ANALYZED:
            break
        if time.time() - START_TS > TAINT_SEC:
            break
        addr, tidx, depth = worklist.pop(0)
        key = (addr, tidx)
        if key in local:
            continue
        local.add(key)
        f = get_func(addr) or ensure_function(addr)
        if f is None:
            continue
        hf = decompile_hf(f)
        if hf is None:
            continue
        diag = {}
        tainted = propagate(hf, tidx, diag)
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
                if op.getOpcode() != PcodeOp.CALL:
                    continue
            except Exception:
                continue
            target = call_target(op)
            if target is None:
                continue
            if target in SINK_BY_ADDR(s:
                sname,idx sidx = SINK_BY))
_AD                       DR[target]
                try if sk:
                    if sidx < op.getNumInputs():
                        sk = vn_key(op.getInput is not None and sk in tainted:
                            try:
                                pc = _u(op.getSeqnum().getTarget().getOffset())
                            except Exception:
                                pc = 0
                            findings.append({
                                "sink": sname,
                                "pc": fmt(pc),
                                "in_func": fname,
                                "in_func_addr": fmt(addr),
                                "depth": depth,
                                "via": start_name,
                            })
                except Exception:
                    pass
                continue
            nt = set()
            try:
                for i in range(op.getNumInputs() - 1):
                    ak = vn_key(op.getInput(1 + i))
                    if ak is not None and ak in tainted:
                        nt.add(i)
            except Exception:
                pass
            if nt and depth < MAX_DEPTH:
                if get_func(target) is not None:
                    worklist.append((target, frozenset(nt), depth + 1))
                    if len(worklist) > MAX_WORKLIST:
                        break
    return findings


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
            out.append((_u(b.getStart().getOffset()), _u(b.getEnd().getOffset())))
    except Exception:
        pass
    _blocks = out
    return out


def bl_callers(target, max_hits=20, budget=40):
    hits = []
    mem = currentProgram.getMemory()
    ts = time.time()
    for s, e in blocks():
        if time.time() - ts > budget:
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


def pick_dump_targets(findings):
    seen = set()
    picks = []
    for fd in findings:
        if fd["depth"] != 0:
            continue
        if fd["sink"] not in ("kalloc_type", "copyin"):
            continue
        a = fd["in_func_addr"]
        if a in seen:
            continue
        seen.add(a)
        picks.append((a, fd["in_func"], fd["sink"] + " d=0"))
    kalloc = sorted([f for f in findings if f["sink"] == "kalloc_type"],
                    key=lambda x: x["depth"])
    for fd in kalloc[:5]:
        a = fd["in_func_addr"]
        if a in seen:
            continue
        seen.add(a)
        picks.append((a, fd["in_func"], "kalloc_type d=%d" % fd["depth"]))
    cin = [f for f in findings if f["sink"] == "copyin" and f["depth"] <= 2]
    for fd in cin[:6]:
        a = fd["in_func_addr"]
        if a in seen:
            continue
        seen.add(a)
        picks.append((a, fd["in_func"], "copyin d=%d" % fd["depth"]))
    return picks[:16]


def main():
    global START_TS
    START_TS = time.time()

    log("=== kernel_rw.py v46 ===")

    w("natsuk1 taint scan")
    w("sources=%d sinks=%s depth=%d budget=%ds" % (
        len(SOURCES),
        ",".join([s[0] for s in SINKS]),
        MAX_DEPTH, TAINT_SEC))
    w("")

    all_findings = []

    for idx, (addr, name) in enumerate(SOURCES):
        log("[%d/%d] %s" % (idx + 1, len(SOURCES), name))
        try:
            f = get_func(addr) or ensure_function(addr)
            if f is None:
                w("SRC %-32s no function" % name)
                continue
            findings = analyze_source(addr, name)
        except Exception as ex:
            findings = []
            w("SRC %-32s exception %s" % (name, ex))
            continue
        if not findings:
            w("SRC %-32s (no tainted sinks)" % name)
        else:
            w("SRC %-32s findings=%d" % (name, len(findings)))
            for fd in findings:
                w("  %-12s @ %s  %s  d=%d" % (
                    fd["sink"], fd["pc"], fd["in_func"], fd["depth"]))
                all_findings.append(fd)

    w("")
    w(SEP)
    w("SUMMARY")
    w(SEP)
    w("total findings: %d" % len(all_findings))
    by_sink = {}
    for fd in all_findings:
        by_sink.setdefault(fd["sink"], []).append(fd)
    for sk in sorted(by_sink.keys()):
        w("%s: %d" % (sk, len(by_sink[sk])))
    w("")
    w("unique in_func per sink (top 20):")
    for sk in sorted(by_sink.keys()):
        uniq = {}
        for fd in by_sink[sk]:
            k = (fd["in_func_addr"], fd["in_func"])
            uniq.setdefault(k, []).append(fd["depth"])
        w("  %s:" % sk)
        for (a, n), depths in sorted(uniq.items(), key=lambda x: min(x[1]))[:20]:
            w("    %s  %s  d=%s" % (a, n, sorted(set(depths))))

    # auto-dump
    START_TS = time.time()
    picks = pick_dump_targets(all_findings)
    log("[*] dump targets: %d" % len(picks))

    w("")
    w(SEP)
    w("HOT TARGETS DECOMPILE")
    w(SEP)

    for name, addr_s, note in picks:
        if time.time() - START_TS > DUMP_SEC:
            w("BUDGET EXCEEDED at %s" % name)
            break
        try:
            addr = int(addr_s, 16)
        except Exception:
            continue
        log("  dump %s @ %s (%s)" % (name, addr_s, note))
        w("")
        w("--- %s @ %s  (%s)" % (name, addr_s, note))
        f = get_func(addr) or ensure_function(addr)
        if f is None:
            w("  no function")
            continue
        try:
            ent = _u(f.getEntryPoint().getOffset())
            sz = int(f.getBody().getNumAddresses())
            w("  entry=%s size=0x%X" % (fmt(ent), sz))
        except Exception:
            pass
        try:
            hits = bl_callers(addr, 20, 40)
        except Exception:
            hits = []
        if hits:
            w("  BL callers:")
            for pc, kind in hits:
                cf = getFunctionContaining(sa(pc))
                nm = str(cf.getName()) if cf else "?"
                cfe = _u(cf.getEntryPoint().getOffset()) if cf else 0
                w("    %s %s in %s @ %s" % (fmt(pc), kind, nm, fmt(cfe)))
        else:
            w("  BL callers: (none)")
        w("  decompile:")
        for l in decompile_text(f, 60):
            w("    " + l)

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