# -*- coding: utf-8 -*-
# @runtime Jython
# kernel_rw.py v48 - no literal 0x at tuple start

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

A_KALLOC   = int("FFFFFFF00A200988", 16)
A_KALLOC_Z = int("FFFFFFF00A20141C", 16)
A_COPYIN   = int("FFFFFFF00A368EC0", 16)
A_COPYOUT  = int("FFFFFFF00A369A3C", 16)
A_MEMMOVE  = int("FFFFFFF00AA40D30", 16)
A_MEMSET   = int("FFFFFFF00AA40EE0", 16)

A_ACTION       = int("FFFFFFF00A4E5C28", 16)
A_ADD_FLOW     = int("FFFFFFF00A4E843C", 16)
A_ADD_CLIENT   = int("FFFFFFF00A4E60DC", 16)
A_RM_FLOW      = int("FFFFFFF00A4E93C4", 16)
A_RM_CLIENT    = int("FFFFFFF00A4E76F4", 16)
A_COPY_RESULT  = int("FFFFFFF00A4E7BE8", 16)
A_COPY_LIST    = int("FFFFFFF00A4E80FC", 16)
A_COPY_IFACE   = int("FFFFFFF00A4EAC7C", 16)
A_ARENA        = int("FFFFFFF00A4EB704", 16)
A_UPD_CACHE    = int("FFFFFFF00A4EBD58", 16)
A_COPY_UPDATE  = int("FFFFFFF00A4EC264", 16)
A_REQ_NEXUS    = int("FFFFFFF00A4E9904", 16)
A_AGENT_ACT    = int("FFFFFFF00A4EA0B4", 16)
A_COPY_AGENT   = int("FFFFFFF00A4EA778", 16)
A_COPY_ROUTE   = int("FFFFFFF00A4EBA0C", 16)
A_COPY_PARAM   = int("FFFFFFF00A4EA8A0", 16)
A_CLAIM        = int("FFFFFFF00A4E7158", 16)
A_SIGN         = int("FFFFFFF00A4EC5D8", 16)
A_GET_IFACE    = int("FFFFFFF00A4EB2B4", 16)
A_COPY_AG_ALT  = int("FFFFFFF00A4EAB50", 16)
A_VALIDATE     = int("FFFFFFF00A4EC9EC", 16)
A_GET_SIGNED   = int("FFFFFFF00A4ECC4C", 16)
A_SET_SIGNED   = int("FFFFFFF00A4ECE88", 16)
A_FLOW_STATS   = int("FFFFFFF00A4ED170", 16)

SINK_KALLOC    = (0, "kalloc_type", A_KALLOC, 1)
SINK_KALLOC_Z  = (1, "kalloc_zone", A_KALLOC_Z, 1)
SINK_COPYIN    = (2, "copyin", A_COPYIN, 3)
SINK_COPYOUT   = (3, "copyout", A_COPYOUT, 3)
SINK_MEMMOVE   = (4, "memmove", A_MEMMOVE, 3)
SINK_MEMSET    = (5, "memset", A_MEMSET, 3)

SINK_LIST = [
    SINK_KALLOC,
    SINK_KALLOC_Z,
    SINK_COPYIN,
    SINK_COPYOUT,
    SINK_MEMMOVE,
    SINK_MEMSET,
]

SINK_MAP = {}
for sk in SINK_LIST:
    SINK_MAP[sk[2]] = (sk[1], sk[3])

SRC_ACTION     = (A_ACTION, "necp_client_action")
SRC_ADD_FLOW   = (A_ADD_FLOW, "necp_client_add_flow")
SRC_ADD_CLIENT = (A_ADD_CLIENT, "necp_client_add_client")
SRC_RM_FLOW    = (A_RM_FLOW, "necp_client_remove_flow")
SRC_RM_CLIENT  = (A_RM_CLIENT, "necp_client_remove_client")
SRC_COPY_RES   = (A_COPY_RESULT, "necp_client_copy_result")
SRC_COPY_LST   = (A_COPY_LIST, "necp_client_copy_list")
SRC_COPY_IFACE = (A_COPY_IFACE, "necp_client_copy_interface")
SRC_ARENA      = (A_ARENA, "necp_client_sysctl_arena")
SRC_UPD_CACHE  = (A_UPD_CACHE, "necp_client_update_cache")
SRC_COPY_UPD   = (A_COPY_UPDATE, "necp_client_copy_update")
SRC_REQ_NEXUS  = (A_REQ_NEXUS, "necp_client_request_nexus")
SRC_AGENT_ACT  = (A_AGENT_ACT, "necp_client_agent_action")
SRC_COPY_AGENT = (A_COPY_AGENT, "necp_client_copy_agent")
SRC_COPY_RT    = (A_COPY_ROUTE, "necp_client_copy_route_stats")
SRC_COPY_PRM   = (A_COPY_PARAM, "necp_client_copy_parameters")
SRC_CLAIM      = (A_CLAIM, "necp_client_claim")
SRC_SIGN       = (A_SIGN, "necp_client_sign")
SRC_GET_IFACE  = (A_GET_IFACE, "necp_client_get_iface_addr")
SRC_COPY_AGALT = (A_COPY_AG_ALT, "necp_client_copy_agent_alt")
SRC_VALIDATE   = (A_VALIDATE, "necp_client_validate")
SRC_GET_SIGNED = (A_GET_SIGNED, "necp_client_get_signed_id")
SRC_SET_SIGNED = (A_SET_SIGNED, "necp_client_set_signed_id")
SRC_FLOW_STATS = (A_FLOW_STATS, "necp_client_get_flow_stats")

SOURCES = [
    SRC_ACTION,
    SRC_ADD_FLOW,
    SRC_ADD_CLIENT,
    SRC_RM_FLOW,
    SRC_RM_CLIENT,
    SRC_COPY_RES,
    SRC_COPY_LST,
    SRC_COPY_IFACE,
    SRC_ARENA,
    SRC_UPD_CACHE,
    SRC_COPY_UPD,
    SRC_REQ_NEXUS,
    SRC_AGENT_ACT,
    SRC_COPY_AGENT,
    SRC_COPY_RT,
    SRC_COPY_PRM,
    SRC_CLAIM,
    SRC_SIGN,
    SRC_GET_IFACE,
    SRC_COPY_AGALT,
    SRC_VALIDATE,
    SRC_GET_SIGNED,
    SRC_SET_SIGNED,
    SRC_FLOW_STATS,
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


def decompile_hf(f, sec=MAX_DECOMPILE_SEC):
    try:
        r = get_dec().decompileFunction(f, sec, MONITOR)
        if r is None:
            return None
        if not r.decompileCompleted():
            return None
        return r.getHighFunction()
    except Exception:
        return None


def decompile_text(f, sec=60):
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
        s = a.toString()
        sz = vn.getSize()
        return s + ":" + str(sz)
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
    while changed and iters < 300:
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
                    try:
                        ik = vn_key(op.getInput(i))
                        if ik is None:
                            continue
                        if ik in tainted:
                            hit = True
                            break
                    except Exception:
                        pass
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


def analyze_source(start_addr, start_name):
    worklist = [(start_addr, frozenset(range(8)), 0)]
    findings = []
    local = set()
    while worklist:
        if len(local) >= MAX_ANALYZED:
            break
        if time.time() - START_TS > TAINT_SEC:
            break
        entry = worklist.pop(0)
        addr = entry[0]
        tidx = entry[1]
        depth = entry[2]
        key = (addr, tidx)
        if key in local:
            continue
        local.add(key)
        f = get_func(addr)
        if f is None:
            f = ensure_function(addr)
        if f is None:
            continue
        hf = decompile_hf(f)
        if hf is None:
            continue
        tainted = propagate(hf, tidx)
        if not tainted:
            continue
        fname = "?"
        try:
            fname = str(f.getName())
        except Exception:
            fname = "?"
        try:
            all_ops = list(hf.getPcodeOps())
        except Exception:
            continue
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
                try:
                    if sidx < op.getNumInputs():
                        sk = vn_key(op.getInput(sidx))
                        if sk is not None:
                            if sk in tainted:
                                pc = 0
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
                num = op.getNumInputs() - 1
                for i in range(num):
                    ak = vn_key(op.getInput(1 + i))
                    if ak is None:
                        continue
                    if ak in tainted:
                        nt.add(i)
            except Exception:
                pass
            if not nt:
                continue
            if depth >= MAX_DEPTH:
                continue
            if get_func(target) is None:
                continue
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
            s = _u(b.getStart().getOffset())
            e = _u(b.getEnd().getOffset())
            out.append((s, e))
    except Exception:
        pass
    _blocks = out
    return out


def bl_callers(target, max_hits=20, budget=40):
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


def pick_dump_targets(findings):
    seen = set()
    picks = []
    for fd in findings:
        d = fd.get("depth")
        if d != 0:
            continue
        sk = fd.get("sink")
        if sk != "kalloc_type" and sk != "copyin":
            continue
        a = fd.get("in_func_addr")
        if a in seen:
            continue
        seen.add(a)
        picks.append((a, fd.get("in_func"), sk + " d=0"))
    kalloc = []
    for fd in findings:
        if fd.get("sink") == "kalloc_type":
            kalloc.append(fd)
    kalloc.sort(key=lambda x: x.get("depth", 99))
    for fd in kalloc[:5]:
        a = fd.get("in_func_addr")
        if a in seen:
            continue
        seen.add(a)
        note = "kalloc_type d=%d" % fd.get("depth", 0)
        picks.append((a, fd.get("in_func"), note))
    cin = []
    for fd in findings:
        if fd.get("sink") != "copyin":
            continue
        if fd.get("depth", 99) > 2:
            continue
        cin.append(fd)
    for fd in cin[:6]:
        a = fd.get("in_func_addr")
        if a in seen:
            continue
        seen.add(a)
        note = "copyin d=%d" % fd.get("depth", 0)
        picks.append((a, fd.get("in_func"), note))
    return picks[:16]


def main():
    global START_TS
    START_TS = time.time()

    log("=== kernel_rw.py v48 ===")

    w("natsuk1 taint scan v48")
    w("sources=%d sinks=%d depth=%d budget=%ds" % (
        len(SOURCES), len(SINK_LIST), MAX_DEPTH, TAINT_SEC))
    w("")

    all_findings = []

    for idx in range(len(SOURCES)):
        addr = SOURCES[idx][0]
        name = SOURCES[idx][1]
        log("[%d/%d] %s" % (idx + 1, len(SOURCES), name))
        try:
            f = get_func(addr)
            if f is None:
                f = ensure_function(addr)
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
                    fd.get("sink"), fd.get("pc"),
                    fd.get("in_func"), fd.get("depth")))
                all_findings.append(fd)

    w("")
    w(SEP)
    w("SUMMARY")
    w(SEP)
    w("total findings: %d" % len(all_findings))
    by_sink = {}
    for fd in all_findings:
        sk = fd.get("sink")
        cur = by_sink.get(sk)
        if cur is None:
            cur = []
            by_sink[sk] = cur
        cur.append(fd)
    for sk in sorted(by_sink.keys()):
        w("%s: %d" % (sk, len(by_sink.get(sk, []))))
    w("")
    w("unique in_func per sink:")
    for sk in sorted(by_sink.keys()):
        uniq = {}
        for fd in by_sink.get(sk, []):
            k = fd.get("in_func_addr") + " " + fd.get("in_func")
            cur = uniq.get(k)
            if cur is None:
                cur = []
                uniq[k] = cur
            cur.append(fd.get("depth"))
        w("  %s:" % sk)
        items = sorted(uniq.items(), key=lambda x: min(x[1]))
        for pair in items[:20]:
            w("    %s  d=%s" % (pair[0], sorted(set(pair[1]))))

    START_TS = time.time()
    picks = pick_dump_targets(all_findings)
    log("[*] dump targets: %d" % len(picks))

    w("")
    w(SEP)
    w("HOT TARGETS DECOMPILE")
    w(SEP)

    for pick in picks:
        if time.time() - START_TS > DUMP_SEC:
            w("BUDGET EXCEEDED at %s" % pick[1])
            break
        name = pick[1]
        addr_s = pick[0]
        note = pick[2]
        try:
            addr = int(addr_s, 16)
        except Exception:
            continue
        log("  dump %s @ %s" % (name, addr_s))
        w("")
        w("--- %s @ %s  (%s)" % (name, addr_s, note))
        f = get_func(addr)
        if f is None:
            f = ensure_function(addr)
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