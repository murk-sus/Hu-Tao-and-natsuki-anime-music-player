# -*- coding: utf-8 -*-
# @runtime Jython
# kernel_rw.py v51 - all 558 BSD syscalls taint scan

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

SYSENT_BASE = int("FFFFFFF007C192A0", 16)
SYSENT_STRIDE = 24
SYSENT_COUNT = 558
KERNEL_BASE = int("FFFFFFF007004000", 16)

TAINT_SEC = 1800
DUMP_SEC = 600
MAX_ANALYZED = 20000
MAX_WORKLIST = 40000
MAX_DEPTH = 8
MAX_DECOMPILE_SEC = 40
MAX_SOURCES = 300

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
            name = "sys_%X" % addr
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


def read_u8(addr):
    try:
        ga = sa(addr)
        if ga is None:
            return None
        b = getBytes(ga, 1)
        if b is None:
            return None
        return b[0] & 0xFF
    except Exception:
        return None


def read_u16(addr):
    try:
        ga = sa(addr)
        if ga is None:
            return None
        b = getBytes(ga, 2)
        if b is None:
            return None
        return (b[0] & 0xFF) | ((b[1] & 0xFF) << 8)
    except Exception:
        return None


def read_u32(addr):
    try:
        ga = sa(addr)
        if ga is None:
            return None
        b = getBytes(ga, 4)
        if b is None:
            return None
        return (b[0] & 0xFF) | ((b[1] & 0xFF) << 8) | ((b[2] & 0xFF) << 16) | ((b[3] & 0xFF) << 24)
    except Exception:
        return None


def read_u64(addr):
    try:
        ga = sa(addr)
        if ga is None:
            return None
        b = getBytes(ga, 8)
        if b is None:
            return None
        r = 0
        for i in range(8):
            r = r | ((b[i] & 0xFF) << (i * 8))
        return r
    except Exception:
        return None


def unpack_sy_call(raw):
    """Unpack ptrauth-signed sy_call. low32 = offset from KERNEL_BASE."""
    if raw is None or raw == 0:
        return None
    low = raw & 0xFFFFFFFF
    if low < 0x1000:
        return None
    if low > 0x4000000:
        return None
    return KERNEL_BASE + low


def parse_sysent():
    """Return list of (idx, sy_call_addr, n_arg) unique by sy_call."""
    seen = set()
    out = []
    diag = {"total": 0, "unpacked": 0, "zero": 0, "out_of_range": 0, "dup": 0}
    for i in range(SYSENT_COUNT):
        base = SYSENT_BASE + i * SYSENT_STRIDE
        raw = read_u64(base)
        diag["total"] += 1
        if raw is None or raw == 0:
            diag["zero"] += 1
            continue
        addr = unpack_sy_call(raw)
        if addr is None:
            diag["out_of_range"] += 1
            continue
        diag["unpacked"] += 1
        if addr in seen:
            diag["dup"] += 1
            continue
        seen.add(addr)
        # n_arg at +0x14 (int16)
        narg = read_u16(base + 0x14)
        if narg is None:
            narg = 0
        out.append((i, addr, narg))
    return out, diag


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


def bl_callers(target, max_hits=15, budget=30):
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
    # priority 1: depth<=1 kalloc/copyin
    for fd in findings:
        d = fd.get("depth", 99)
        if d > 1:
            continue
        sk = fd.get("sink")
        if sk != "kalloc_type" and sk != "copyin":
            continue
        a = fd.get("in_func_addr")
        if a in seen:
            continue
        seen.add(a)
        picks.append((a, fd.get("in_func"), sk + " d=" + str(d)))
    # priority 2: depth==2 kalloc/copyin
    for fd in findings:
        d = fd.get("depth", 99)
        if d != 2:
            continue
        sk = fd.get("sink")
        if sk != "kalloc_type" and sk != "copyin":
            continue
        a = fd.get("in_func_addr")
        if a in seen:
            continue
        seen.add(a)
        picks.append((a, fd.get("in_func"), sk + " d=" + str(d)))
    # priority 3: unique kalloc
    rest = []
    for fd in findings:
        if fd.get("sink") != "kalloc_type":
            continue
        a = fd.get("in_func_addr")
        if a in seen:
            continue
        rest.append(fd)
    rest.sort(key=lambda x: x.get("depth", 99))
    for fd in rest[:10]:
        a = fd.get("in_func_addr")
        if a in seen:
            continue
        seen.add(a)
        picks.append((a, fd.get("in_func"), "kalloc_type d=" + str(fd.get("depth"))))
    return picks[:20]


def main():
    global START_TS
    START_TS = time.time()

    log("=== kernel_rw.py v51 syscalls ===")

    entries, diag = parse_sysent()
    log("[+] sysent parsed: %s" % repr(diag))
    log("[+] unique sy_call: %d" % len(entries))

    # sanity
    sanity = []
    for pair in entries[:5]:
        sanity.append(pair)
    for idx in (500, 501, 502, 503, 504):
        for pair in entries:
            if pair[0] == idx:
                sanity.append(pair)
                break

    w("natsuk1 syscall taint scan v51")
    w("sysent_base=%s stride=%d count=%d" % (fmt(SYSENT_BASE), SYSENT_STRIDE, SYSENT_COUNT))
    w("kernel_base=%s" % fmt(KERNEL_BASE))
    w("")
    w("PARSE DIAG: %s" % repr(diag))
    w("unique sy_call: %d" % len(entries))
    w("")
    w("SANITY (first 5 + 500..504):")
    for pair in sanity:
        w("  sysent[%d] sy_call=%s narg=%d" % (pair[0], fmt(pair[1]), pair[2]))
    w("")

    if not entries:
        w("NO SYSCALLS PARSED")
        try:
            fh = open(OUT, "w")
            for l in L:
                fh.write(l + "\n")
            fh.close()
        except Exception:
            pass
        return

    # filter: only with narg > 0
    filtered = []
    for pair in entries:
        idx = pair[0]
        addr = pair[1]
        narg = pair[2]
        if narg <= 0:
            continue
        f = get_func(addr)
        if f is None:
            f = ensure_function(addr)
        if f is None:
            continue
        filtered.append(pair)
        if len(filtered) >= MAX_SOURCES:
            break
    log("[+] filtered sources: %d" % len(filtered))

    w("SOURCES TO SCAN: %d (narg>0, resolvable)" % len(filtered))
    w("")

    all_findings = []
    per_source_interesting = []

    total = len(filtered)
    for i in range(total):
        pair = filtered[i]
        idx = pair[0]
        addr = pair[1]
        narg = pair[2]
        name = "sysent_%d" % idx
        log("[%d/%d] %s @ %s narg=%d" % (i + 1, total, name, fmt(addr), narg))
        try:
            findings = analyze_source(addr, name)
        except Exception as ex:
            findings = []
            w("SRC %-20s @ %s narg=%d exception %s" % (name, fmt(addr), narg, ex))
            continue
        if not findings:
            w("SRC %-20s @ %s narg=%d (no tainted sinks)" % (name, fmt(addr), narg))
            continue
        uniq = {}
        for fd in findings:
            k = fd.get("sink") + "|" + fd.get("pc") + "|" + fd.get("in_func_addr")
            if k not in uniq:
                uniq[k] = fd
        uf = list(uniq.values())
        w("SRC %-20s @ %s narg=%d findings=%d uniq=%d" % (
            name, fmt(addr), narg, len(findings), len(uf)))
        for fd in uf:
            w("  %-12s @ %s  %s  d=%d" % (
                fd.get("sink"), fd.get("pc"),
                fd.get("in_func"), fd.get("depth")))
            all_findings.append(fd)
        for fd in uf:
            d = fd.get("depth", 99)
            if d > 2:
                continue
            sk = fd.get("sink")
            if sk != "copyin" and sk != "kalloc_type":
                continue
            per_source_interesting.append((fd.get("in_func_addr"), fd.get("in_func")))

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
        for pair2 in items[:50]:
            w("    %s  d=%s" % (pair2[0], sorted(set(pair2[1]))))

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
            hits = bl_callers(addr, 15, 30)
        except Exception:
            hits = []
        if hits:
            w("  BL callers:")
            for pair3 in hits:
                pc = pair3[0]
                kind = pair3[1]
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