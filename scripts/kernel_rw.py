# -*- coding: utf-8 -*-
# @runtime Jython
# kernel_rw.py v70 - expanded scanner (fixed constants + dedup + gated categories)

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

KERNEL_BASE = int("FFFFFFF007004000", 16)
SYSENT_BASE = int("FFFFFFF007C192D0", 16)
SYSENT_STRIDE = 24
SYSENT_COUNT = 558

A_KALLOC      = int("FFFFFFF00A200988", 16)
A_KALLOC_ZONE = int("FFFFFFF00A20141C", 16)
A_COPYIN      = int("FFFFFFF00A368EC0", 16)
A_COPYOUT     = int("FFFFFFF00A369A3C", 16)
A_MEMMOVE     = int("FFFFFFF00AA40D30", 16)
A_MEMSET      = int("FFFFFFF00AA40EE0", 16)
A_KFREE       = int("FFFFFFF00A201000", 16)
A_REF_DEC     = int("FFFFFFF00A4E3278", 16)

SINK_MAP = {}
SINK_MAP[A_KALLOC] = ("kalloc_type", 1)
SINK_MAP[A_KALLOC_ZONE] = ("kalloc_zone", 1)
SINK_MAP[A_COPYIN] = ("copyin", 3)
SINK_MAP[A_COPYOUT] = ("copyout", 3)
SINK_MAP[A_MEMMOVE] = ("memmove", 3)
SINK_MAP[A_MEMSET] = ("memset", 3)

# real NECP op-handler addresses
NECP_HANDLERS = [
    (int("FFFFFFF00A4E5C28", 16), "necp_client_action"),
    (int("FFFFFFF00A4E60DC", 16), "necp_add_client"),
    (int("FFFFFFF00A4E7158", 16), "necp_claim"),
    (int("FFFFFFF00A4E76F4", 16), "necp_remove_client"),
    (int("FFFFFFF00A4E7BE8", 16), "necp_copy_result"),
    (int("FFFFFFF00A4E80FC", 16), "necp_copy_list"),
    (int("FFFFFFF00A4E843C", 16), "necp_add_flow"),
    (int("FFFFFFF00A4E93C4", 16), "necp_remove_flow"),
    (int("FFFFFFF00A4E9904", 16), "necp_request_nexus"),
    (int("FFFFFFF00A4EA0B4", 16), "necp_agent_action"),
    (int("FFFFFFF00A4EA778", 16), "necp_copy_agent"),
    (int("FFFFFFF00A4EA8A0", 16), "necp_copy_parameters"),
    (int("FFFFFFF00A4EAB50", 16), "necp_copy_agent_alt"),
    (int("FFFFFFF00A4EAC7C", 16), "necp_copy_interface"),
    (int("FFFFFFF00A4EB2B4", 16), "necp_get_iface_addr"),
    (int("FFFFFFF00A4EB704", 16), "necp_sysctl_arena"),
    (int("FFFFFFF00A4EBA0C", 16), "necp_copy_route_stats"),
    (int("FFFFFFF00A4EBD58", 16), "necp_update_cache"),
    (int("FFFFFFF00A4EC264", 16), "necp_copy_update"),
    (int("FFFFFFF00A4EC5D8", 16), "necp_sign"),
    (int("FFFFFFF00A4EC9EC", 16), "necp_validate"),
    (int("FFFFFFF00A4ECC4C", 16), "necp_get_signed_id"),
    (int("FFFFFFF00A4ECE88", 16), "necp_set_signed_id"),
    (int("FFFFFFF00A4ED170", 16), "necp_get_flow_stats"),
]

SOURCES = list(NECP_HANDLERS)
SOURCES.append((int("FFFFFFF00A4E411C", 16), "necp_open"))
SOURCES.append((int("FFFFFFF00A4F75D8", 16), "necp_match_policy"))
SOURCES.append((int("FFFFFFF00A4B4C3C", 16), "necp_session_open"))
SOURCES.append((int("FFFFFFF00A4BD438", 16), "necp_session_action"))
SOURCES.append((int("FFFFFFF00A98C2E8", 16), "iokit_user_client_trap"))
SOURCES.append((int("FFFFFFF00A988758", 16), "is_io_service_open_extended"))
SOURCES.append((int("FFFFFFF00A802220", 16), "nexus_open"))
SOURCES.append((int("FFFFFFF00A803FE8", 16), "nexus_set_opt"))
SOURCES.append((int("FFFFFFF00A7DACEC", 16), "channel_open"))
SOURCES.append((int("FFFFFFF00A7DCF00", 16), "channel_set_opt"))
SOURCES.append((int("FFFFFFF00A754778", 16), "ulock_wait"))
SOURCES.append((int("FFFFFFF00A755798", 16), "ulock_wake"))
SOURCES.append((int("FFFFFFF00A7547C0", 16), "ulock_wait2"))

MAX_DEPTH = 12
MAX_ANALYZED = 20000
MAX_WORKLIST = 40000
TAINT_SEC = 1800
MAX_DECOMPILE_SEC = 30
OUT_CAP_BYTES = 100 * 1024

DEC = None
MONITOR = ConsoleTaskMonitor()
START_TS = time.time()
L = []
FINDINGS = []
CAND_COUNTS = {}
FINDING_KEYS = set()
STACK_STR = []


def w(s):
    L.append(s)


def log(s):
    print(s)
    sys.stdout.flush()


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
        if HAS_DISASM:
            try:
                _DC(ga, None, True).applyTo(currentProgram)
            except Exception:
                pass
        if HAS_CREATE:
            try:
                _CFC(ga).applyTo(currentProgram)
            except Exception:
                pass
        try:
            fm = currentProgram.getFunctionManager()
            f = fm.createFunction(ga, "nk")
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
            cnt = cnt + 1
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
    while changed and iters < 100:
        changed = False
        iters = iters + 1
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
            return int(inp0.getAddress().getOffset()) & 0xFFFFFFFFFFFFFFFF
        if inp0.isConstant():
            return int(inp0.getOffset()) & 0xFFFFFFFFFFFFFFFF
    except Exception:
        pass
    return None


def op_pc(op):
    try:
        return int(op.getSeqnum().getTarget().getOffset()) & 0xFFFFFFFFFFFFFFFF
    except Exception:
        return 0


def is_arith_op(op):
    try:
        oc = op.getOpcode()
        if oc == PcodeOp.INT_MULT:
            return True
        if oc == PcodeOp.INT_ADD:
            return True
        if oc == PcodeOp.INT_SUB:
            return True
        if oc == PcodeOp.INT_LEFT:
            return True
    except Exception:
        pass
    return False


def is_compare_op(op):
    try:
        oc = op.getOpcode()
        if oc == PcodeOp.INT_LESS:
            return True
        if oc == PcodeOp.INT_LESSEQUAL:
            return True
        if oc == PcodeOp.INT_SLESS:
            return True
        if oc == PcodeOp.INT_SLESSEQUAL:
            return True
    except Exception:
        pass
    return False


def add_finding(cat, sink, pc, func_name, func_addr, depth, via, extra):
    key = cat + "|" + fmt(pc) + "|" + sink + "|" + fmt(func_addr)
    if key in FINDING_KEYS:
        return
    FINDING_KEYS.add(key)
    fd = {}
    fd["cat"] = cat
    fd["sink"] = sink
    fd["pc"] = fmt(pc)
    fd["func"] = func_name
    fd["func_addr"] = fmt(func_addr)
    fd["depth"] = depth
    fd["via"] = via
    fd["extra"] = extra
    FINDINGS.append(fd)
    k = func_name + "@" + fmt(func_addr)
    cur = CAND_COUNTS.get(k)
    if cur is None:
        CAND_COUNTS[k] = 1
    else:
        CAND_COUNTS[k] = cur + 1


def check_taint(hf, tainted, fname, faddr, via, depth):
    cnt = 0
    try:
        all_ops = list(hf.getPcodeOps())
    except Exception:
        return cnt
    for op in all_ops:
        try:
            if op.getOpcode() != PcodeOp.CALL:
                continue
        except Exception:
            continue
        target = call_target(op)
        if target is None:
            continue
        v = SINK_MAP.get(target)
        if v is None:
            continue
        sname = v[0]
        sidx = v[1]
        try:
            if sidx >= op.getNumInputs():
                continue
            sk = vn_key(op.getInput(sidx))
            if sk is None:
                continue
            if sk not in tainted:
                continue
            pc = op_pc(op)
            add_finding("TAINT", sname, pc, fname, faddr, depth, via, "arg=" + str(sidx))
            cnt = cnt + 1
        except Exception:
            pass
    return cnt


def check_overflow(hf, tainted, fname, faddr, via, depth):
    cnt = 0
    try:
        ops = list(hf.getPcodeOps())
    except Exception:
        return cnt
    # collect all compare-targets (varnode keys used in INT_LESS/SLESS/LESSEQUAL)
    checked_keys = set()
    for op in ops:
        if is_compare_op(op):
            for i in range(op.getNumInputs()):
                k = vn_key(op.getInput(i))
                if k is not None:
                    checked_keys.add(k)
    for op in ops:
        try:
            if op.getOpcode() != PcodeOp.CALL:
                continue
        except Exception:
            continue
        t = call_target(op)
        if t is None:
            continue
        v = SINK_MAP.get(t)
        if v is None:
            continue
        sname = v[0]
        sidx = v[1]
        if sidx >= op.getNumInputs():
            continue
        sk = vn_key(op.getInput(sidx))
        if sk is None or sk not in tainted:
            continue
        # walk def chain of size varnode
        has_arith = False
        arith_src = set()
        stack = [op.getInput(sidx)]
        seen = set()
        while stack:
            vn = stack.pop()
            vk = vn_key(vn)
            if vk is None or vk in seen:
                continue
            seen.add(vk)
            try:
                defop = vn.getDef()
            except Exception:
                defop = None
            if defop is None:
                continue
            if is_arith_op(defop):
                has_arith = True
                try:
                    arith_src.add(vn_key(defop.getOutput()))
                except Exception:
                    pass
            try:
                for i in range(defop.getNumInputs()):
                    stack.append(defop.getInput(i))
            except Exception:
                pass
        if not has_arith:
            continue
        # is the top-level size key in checked_keys?
        if sk in checked_keys:
            continue
        pc = op_pc(op)
        add_finding("INT_OVERFLOW", sname, pc, fname, faddr, depth, via,
                    "tainted size via arith without INT_LESS/LESSEQUAL check")
        cnt = cnt + 1
    return cnt


def check_double_free(hf, fname, faddr, via, depth):
    cnt = 0
    try:
        ops = list(hf.getPcodeOps())
    except Exception:
        return cnt
    seen = {}
    for op in ops:
        try:
            if op.getOpcode() != PcodeOp.CALL:
                continue
        except Exception:
            continue
        if call_target(op) != A_KFREE:
            continue
        if op.getNumInputs() < 2:
            continue
        k = vn_key(op.getInput(1))
        if k is None:
            continue
        pc = op_pc(op)
        prev = seen.get(k)
        if prev is not None:
            add_finding("DOUBLE_FREE", "kfree_type", pc, fname, faddr, depth, via,
                        "second free of same varnode, first at %s" % fmt(prev))
            cnt = cnt + 1
        else:
            seen[k] = pc
    return cnt


def check_uninit(hf, fname, faddr, via, depth):
    cnt = 0
    try:
        ops = list(hf.getPcodeOps())
    except Exception:
        return cnt
    for idx in range(len(ops)):
        op = ops[idx]
        try:
            if op.getOpcode() != PcodeOp.CALL:
                continue
        except Exception:
            continue
        t = call_target(op)
        if t != A_KALLOC and t != A_KALLOC_ZONE:
            continue
        # check flag arg for Z_ZERO 0x8000 anywhere in inputs
        has_zero = False
        for i in range(op.getNumInputs()):
            try:
                vn = op.getInput(i)
                if vn.isConstant():
                    if int(vn.getOffset()) & 0x8000:
                        has_zero = True
            except Exception:
                pass
        if has_zero:
            continue
        try:
            outk = vn_key(op.getOutput())
        except Exception:
            outk = None
        if outk is None:
            continue
        pc = op_pc(op)
        # find init after allocation
        init_found = False
        for j in range(idx + 1, min(idx + 12, len(ops))):
            o2 = ops[j]
            try:
                oc2 = o2.getOpcode()
            except Exception:
                continue
            if oc2 == PcodeOp.CALL:
                t2 = call_target(o2)
                if t2 == A_MEMSET or t2 == A_COPYIN or t2 == A_MEMMOVE:
                    if o2.getNumInputs() > 1:
                        if vn_key(o2.getInput(1)) == outk:
                            init_found = True
                            break
            if oc2 == PcodeOp.STORE:
                try:
                    if vn_key(o2.getInput(2)) == outk:
                        init_found = True
                        break
                except Exception:
                    pass
        if init_found:
            continue
        # check if allocation is loaded from before init
        for j in range(idx + 1, min(idx + 12, len(ops))):
            o2 = ops[j]
            try:
                if o2.getOpcode() == PcodeOp.LOAD:
                    addr_vn = o2.getInput(1)
                    if vn_key(addr_vn) == outk:
                        add_finding("UNINIT_READ", "kalloc_type", pc, fname, faddr, depth, via,
                                    "kalloc without Z_ZERO, LOAD before init")
                        cnt = cnt + 1
                        break
            except Exception:
                pass
    return cnt


def check_stack_leak(hf, tainted, fname, faddr, via, depth):
    cnt = 0
    try:
        ops = list(hf.getPcodeOps())
    except Exception:
        return cnt
    # find copyout where source is a stack var not fully initialized
    # heuristic: file has copyout but no memset to the source pointer
    for op in ops:
        try:
            if op.getOpcode() != PcodeOp.CALL:
                continue
        except Exception:
            continue
        if call_target(op) != A_COPYOUT:
            continue
        if op.getNumInputs() < 3:
            continue
        # check size arg is tainted
        sk = vn_key(op.getInput(3))
        if sk is None or sk not in tainted:
            continue
        # check source arg (index 0) for memset before
        src_key = vn_key(op.getInput(0))
        if src_key is None:
            continue
        has_memset = False
        for o2 in ops:
            try:
                if o2.getOpcode() == PcodeOp.CALL and call_target(o2) == A_MEMSET:
                    if o2.getNumInputs() > 0 and vn_key(o2.getInput(0)) == src_key:
                        has_memset = True
                        break
            except Exception:
                pass
        if not has_memset:
            pc = op_pc(op)
            add_finding("COPYOUT_LEAK", "copyout", pc, fname, faddr, depth, via,
                        "tainted copyout from buffer without preceding memset")
            cnt = cnt + 1
    return cnt


def analyze_source_all(start_addr, start_name):
    worklist = [(start_addr, frozenset(range(6)), 0)]
    local = set()
    root_checked = set()
    while worklist:
        if len(local) >= MAX_ANALYZED:
            break
        if time.time() - START_TS > TAINT_SEC:
            break
        if len(worklist) > MAX_WORKLIST:
            worklist = worklist[:MAX_WORKLIST]
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
        fname = "?"
        try:
            fname = str(f.getName())
        except Exception:
            fname = "?"
        tainted = propagate(hf, tidx)
        if tainted:
            try:
                check_taint(hf, tainted, fname, addr, start_name, depth)
            except Exception:
                pass
            try:
                check_overflow(hf, tainted, fname, addr, start_name, depth)
            except Exception:
                pass
            try:
                check_stack_leak(hf, tainted, fname, addr, start_name, depth)
            except Exception:
                pass
        # non-taint categories run ONCE per function, not per worklist entry
        fkey = "%X" % addr
        if fkey in root_checked:
            continue
        root_checked.add(fkey)
        try:
            check_double_free(hf, fname, addr, start_name, depth)
        except Exception:
            pass
        try:
            check_uninit(hf, fname, addr, start_name, depth)
        except Exception:
            pass
        # propagate into callees
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
            if target in SINK_MAP:
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


def main():
    global START_TS
    START_TS = time.time()
    log("=== start ===")
    try:
        if os.path.exists(OUT):
            os.remove(OUT)
    except Exception:
        pass
    w(SEP)
    w("iOS 27.0 kernel_rw scanner v70")
    w("kernel_base=%s sysent_base=%s stride=%d count=%d" % (
        fmt(KERNEL_BASE), fmt(SYSENT_BASE), SYSENT_STRIDE, SYSENT_COUNT))
    w("MAX_DEPTH=%d MAX_ANALYZED=%d TAINT_SEC=%d" % (MAX_DEPTH, MAX_ANALYZED, TAINT_SEC))
    w(SEP)
    w("")
    w("[SOURCES]")
    for s in SOURCES:
        f = get_func(s[0])
        if f is None:
            f = ensure_function(s[0])
        st = "ok" if f is not None else "no_func"
        w("  %-32s @ %s %s" % (s[1], fmt(s[0]), st))
    w("")
    w("[SINKS]")
    for k in SINK_MAP:
        v = SINK_MAP.get(k)
        w("  %-12s @ %s arg=%s" % (v[0], fmt(k), str(v[1])))
    w("  %-12s @ %s" % ("kfree_type", fmt(A_KFREE)))
    w("  %-12s @ %s" % ("ref_dec", fmt(A_REF_DEC)))
    w("")

    for s in SOURCES:
        if time.time() - START_TS > TAINT_SEC:
            log("time budget exhausted before %s" % s[1])
            break
        try:
            log("[*] %s @ %s" % (s[1], fmt(s[0])))
            analyze_source_all(s[0], s[1])
        except Exception as e:
            log("[-] %s fail %s" % (s[1], e))

    # FINDINGS
    w(SEP)
    w("[FINDINGS] total=%d" % len(FINDINGS))
    w(SEP)
    sev = {}
    sev["kalloc_type"] = 0
    sev["kalloc_zone"] = 1
    sev["copyin"] = 2
    sev["copyout"] = 3
    sev["memmove"] = 4
    sev["memset"] = 5
    sev["kfree_type"] = 6
    def sev_key(fd):
        sk = fd.get("sink")
        v = sev.get(sk)
        if v is None:
            v = 99
        return (v, fd.get("depth"), fd.get("pc"))
    try:
        FINDINGS.sort(key=sev_key)
    except Exception:
        pass
    cat_counts = {}
    depth_counts = {}
    sink_counts = {}
    for fd in FINDINGS:
        c = fd.get("cat")
        cat_counts[c] = cat_counts.get(c, 0) + 1
        d = fd.get("depth")
        depth_counts[d] = depth_counts.get(d, 0) + 1
        sk = fd.get("sink")
        sink_counts[sk] = sink_counts.get(sk, 0) + 1

    size_est = 0
    shown = 0
    for fd in FINDINGS:
        line = "%s | %s @ %s | %s @ %s d=%s via=%s | %s" % (
            fd.get("cat"), fd.get("sink"), fd.get("pc"),
            fd.get("func"), fd.get("func_addr"),
            str(fd.get("depth")), fd.get("via"), fd.get("extra"))
        if size_est + len(line) > 60000:
            w("... truncated findings ...")
            break
        w(line)
        size_est = size_est + len(line) + 1
        shown = shown + 1

    w("")
    w(SEP)
    w("[CANDIDATES]")
    w(SEP)
    cand_list = []
    for k in CAND_COUNTS:
        cand_list.append((CAND_COUNTS.get(k), k))
    try:
        cand_list.sort(reverse=True)
    except Exception:
        pass
    top30 = cand_list[:30]
    for item in top30:
        w("  %4d  %s" % (item[0], item[1]))
    if not top30:
        w("  (none)")
    w("")

    w(SEP)
    w("[DECOMPILE] top candidates")
    w(SEP)
    top10 = top30[:10]
    size_est = len("\n".join(L))
    for item in top10:
        name = item[1]
        try:
            parts = name.split("@")
            addr = int(parts[len(parts) - 1], 16)
        except Exception:
            continue
        if size_est > 85000:
            w("... decompile truncated ...")
            break
        w("--- %s cnt=%d ---" % (name, item[0]))
        try:
            f = get_func(addr)
            if f is None:
                f = ensure_function(addr)
            if f is None:
                w("(no function)")
                continue
            lines = decompile_text(f, MAX_DECOMPILE_SEC)
            cap = 400
            for ln in lines[:cap]:
                w(ln)
                size_est = size_est + len(ln) + 1
                if size_est > 95000:
                    w("... cut ...")
                    break
        except Exception as e:
            w("(decompile fail %s)" % e)
        w("")

    w(SEP)
    w("[SUMMARY]")
    w(SEP)
    w("findings_total=%d shown=%d" % (len(FINDINGS), shown))
    for k in sorted(cat_counts.keys()):
        w("  cat %s: %d" % (k, cat_counts.get(k)))
    for k in sorted(sink_counts.keys()):
        w("  sink %s: %d" % (k, sink_counts.get(k)))
    for k in sorted(depth_counts.keys()):
        w("  depth %s: %d" % (str(k), depth_counts.get(k)))
    w("candidates=%d" % len(cand_list))
    w("elapsed=%.1fs" % (time.time() - START_TS))
    w(SEP)

    try:
        txt = "\n".join(L)
        if len(txt) > OUT_CAP_BYTES:
            txt = txt[:OUT_CAP_BYTES]
            idx = txt.rfind("\n")
            if idx > 0:
                txt = txt[:idx]
        fh = open(OUT, "w")
        fh.write(txt)
        if not txt.endswith("\n"):
            fh.write("\n")
        fh.close()
        log("[+] wrote %s (%d bytes)" % (OUT, len(txt)))
    except Exception as e:
        log("[-] write fail %s" % e)
        try:
            fh = open(OUT, "w")
            fh.write("FATAL write: %s\n" % e)
            fh.write(traceback.format_exc())
            fh.close()
        except Exception:
            pass
    log("=== done elapsed %.1f ===" % (time.time() - START_TS))


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