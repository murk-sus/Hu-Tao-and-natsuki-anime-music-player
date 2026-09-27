# -*- coding: utf-8 -*-
# @runtime Jython
# kernel_rw.py v64 - IOKit dispatch scanner (strict filter)

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
KTEXT_LO = int("FFFFFFF007000000", 16)
KTEXT_HI = int("FFFFFFF010000000", 16)

DISPATCH_SIZE = 24
MAX_BLOCK_SIZE = 0x10000000
MAX_SOURCES = 400
TAINT_SEC = 1200
MAX_ANALYZED = 4000
MAX_WORKLIST = 8000
MAX_DEPTH = 6
MAX_DECOMPILE_SEC = 30

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


def clean_ptr(raw):
    if raw is None or raw == 0:
        return None
    if raw >= KTEXT_LO and raw < KTEXT_HI:
        return raw
    low40 = raw & 0xFFFFFFFFFF
    cand = low40 | 0xFFFFFFF000000000
    if cand >= KTEXT_LO and cand < KTEXT_HI:
        return cand
    low32 = raw & 0xFFFFFFFF
    cand2 = KERNEL_BASE + low32
    if cand2 >= KTEXT_LO and cand2 < KTEXT_HI:
        return cand2
    return None


def is_func_entry(addr):
    try:
        ga = sa(addr)
        if ga is None:
            return False
        f = getFunctionAt(ga)
        return f is not None
    except Exception:
        return False


def read_u32_at(buf, off):
    return (int(buf[off]) & 0xFF) | ((int(buf[off + 1]) & 0xFF) << 8) | \
           ((int(buf[off + 2]) & 0xFF) << 16) | ((int(buf[off + 3]) & 0xFF) << 24)


def read_u64_at(buf, off):
    r = 0
    for i in range(8):
        r = r | ((int(buf[off + i]) & 0xFF) << (i * 8))
    return r


def valid_counts(si, sti, so, sto):
    counts = [si, sti, so, sto]
    # All under 1 MB
    for c in counts:
        if c >= 0x100000:
            return False
    # At least 3 under 0x10000 (typical IOKit method sizes)
    small = 0
    for c in counts:
        if c < 0x10000:
            small = small + 1
    if small < 3:
        return False
    return True


def parse_entry(buf, pos):
    """Return (fn, si, sti, so, sto) or None."""
    fn_raw = read_u64_at(buf, pos)
    fn = clean_ptr(fn_raw)
    if fn is None:
        return None
    if not is_func_entry(fn):
        return None
    si = read_u32_at(buf, pos + 8)
    sti = read_u32_at(buf, pos + 12)
    so = read_u32_at(buf, pos + 16)
    sto = read_u32_at(buf, pos + 20)
    if not valid_counts(si, sti, so, sto):
        return None
    return (fn, si, sti, so, sto)


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
            return _u(inp0.getAddress().getOffset())
        if inp0.isConstant():
            return _u(inp0.getOffset())
    except Exception:
        pass
    return None


def analyze_source(start_addr, start_name):
    worklist = [(start_addr, frozenset([0, 1, 2]), 0)]
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


def main():
    global START_TS
    START_TS = time.time()

    log("=== kernel_rw.py v64 ===")

    w("natsuk1 v64 IOKit dispatch scanner (strict)")
    w("kernel_base=%s ktext=[%s, %s)" % (fmt(KERNEL_BASE), fmt(KTEXT_LO), fmt(KTEXT_HI)))
    w("dispatch_size=%d max_block=%d" % (DISPATCH_SIZE, MAX_BLOCK_SIZE))
    w("")

    # Single-block assumption
    all_blocks = []
    try:
        for b in currentProgram.getMemory().getBlocks():
            try:
                s = _u(b.getStart().getOffset())
                e = _u(b.getEnd().getOffset())
                nm = str(b.getName())
                in_ = bool(b.isInitialized())
                sz = e - s + 1
                all_blocks.append((s, e, nm, in_, sz))
            except Exception:
                pass
    except Exception as ex:
        log("[!] enum fail: %s" % ex)

    w(SEP)
    w("### ALL BLOCKS")
    w(SEP)
    for b in all_blocks:
        w("  %s %s size=%d init=%s name=%s" % (fmt(b[0]), fmt(b[1]), b[4], str(b[3]), b[2]))
    w("")

    scan_targets = []
    for b in all_blocks:
        if not b[3]:
            continue
        if b[4] <= 0 or b[4] > MAX_BLOCK_SIZE:
            continue
        scan_targets.append(b)

    log("[+] scan targets: %d" % len(scan_targets))

    all_entries = []

    for t in scan_targets:
        start = t[0]
        end = t[1]
        size = t[4]
        log("[*] scan @ %s size=%d" % (fmt(start), size))

        try:
            jbuf = zeros(size, 'b')
            ga = sa(start)
            if ga is None:
                continue
            currentProgram.getMemory().getBytes(ga, jbuf)
        except Exception as ex:
            log("  [skip] %s" % ex)
            continue

        # Pass 1: identify all positions where parse_entry succeeds
        valid_positions = []
        pos = 0
        log("  pass1: scanning for valid entries...")
        while pos + DISPATCH_SIZE <= size:
            e = parse_entry(jbuf, pos)
            if e is not None:
                valid_positions.append((pos, e))
            pos = pos + 8
        log("  pass1: %d valid entry positions" % len(valid_positions))

        # Pass 2: keep only entries that have an adjacent valid entry
        # (real tables have multiple entries in a row at +24 offsets)
        vp_set = set()
        for pair in valid_positions:
            vp_set.add(pair[0])

        kept = []
        for pair in valid_positions:
            p = pair[0]
            left = p - DISPATCH_SIZE
            right = p + DISPATCH_SIZE
            if (left in vp_set) or (right in vp_set):
                kept.append(pair)
        log("  pass2: %d entries with adjacent valid entry" % len(kept))

        for pair in kept:
            p = pair[0]
            e = pair[1]
            struct_addr = start + p
            all_entries.append((struct_addr, e[0], e[1], e[2], e[3], e[4], t[2]))

        try:
            del jbuf
        except Exception:
            pass

    by_fn = {}
    for e in all_entries:
        fn = e[1]
        if fn not in by_fn:
            by_fn[fn] = []
        by_fn[fn].append(e)

    w(SEP)
    w("### DISPATCH ENTRIES (unique fnptr: %d, total: %d)" % (len(by_fn), len(all_entries)))
    w(SEP)
    w("%-20s %-10s %-10s %-10s %-10s %s" % (
        "fnptr", "scalarIn", "structIn", "scalarOut", "structOut", "section"))
    for fn, lst in by_fn.items():
        first = lst[0]
        w("%-20s %-10d %-10d %-10d %-10d %s x%d" % (
            fmt(fn), first[2], first[3], first[4], first[5], first[6], len(lst)))
    w("")

    def priority(item):
        e = item[1][0]
        sti = e[3]
        if sti == 0:
            return 0
        return 1

    sorted_items = sorted(by_fn.items(), key=priority)

    all_findings = []
    analyzed_fn = 0

    for fn, lst in sorted_items:
        if analyzed_fn >= MAX_SOURCES:
            break
        if time.time() - START_TS > TAINT_SEC:
            log("[!] taint budget exhausted")
            break

        f = get_func(fn)
        if f is None:
            f = ensure_function(fn)
        if f is None:
            continue

        analyzed_fn = analyzed_fn + 1
        name = "iokit_%X" % fn

        if analyzed_fn % 25 == 0:
            log("[*] analyzed %d / %d, findings: %d" % (analyzed_fn, len(by_fn), len(all_findings)))

        try:
            findings = analyze_source(fn, name)
        except Exception:
            continue
        if findings:
            for fd in findings:
                all_findings.append(fd)
            w("FUNC %-40s @ %s entries=%d findings=%d" % (
                str(f.getName())[:40], fmt(fn), len(lst), len(findings)))
            for fd in findings:
                w("  %-12s @ %s  %s  d=%d" % (
                    fd.get("sink"), fd.get("pc"),
                    fd.get("in_func"), fd.get("depth")))

    w("")
    w(SEP)
    w("SUMMARY")
    w(SEP)
    w("scan targets: %d" % len(scan_targets))
    w("total entries: %d" % len(all_entries))
    w("unique fnptr: %d" % len(by_fn))
    w("analyzed: %d" % analyzed_fn)
    w("total findings: %d" % len(all_findings))
    w("")

    by_sink = {}
    for fd in all_findings:
        sk = fd.get("sink")
        cur = by_sink.get(sk)
        if cur is None:
            cur = []
            by_sink[sk] = cur
        cur.append(fd)
    for sk in sorted(by_sink.keys()):
        w("  %s: %d" % (sk, len(by_sink.get(sk, []))))
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
        for pair in items[:40]:
            w("    %s  d=%s" % (pair[0], sorted(set(pair[1]))))

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