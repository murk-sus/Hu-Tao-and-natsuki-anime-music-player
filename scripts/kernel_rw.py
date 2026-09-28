# -*- coding: utf-8 -*-
# @runtime Jython
# kernel_rw.py v80

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

KERNEL_BASE = int("FFFFFFF007004000", 16)

MATCH_POLICY = int("FFFFFFF00A4F75D8", 16)
RAW_LOOKUP   = int("FFFFFFF00A4DB8D4", 16)
SESS_LOOKUP  = int("FFFFFFF00A4ED864", 16)

FIELD_10C_ANCHOR = int("FFFFFFF009A68314", 16)
IOHID_VTABLE     = int("FFFFFFF007FF9F60", 16)
LOCK_ADDR        = int("FFFFFFF00A1EA000", 16)
IOMFB_VTABLE     = int("FFFFFFF008016370", 16)

MAX_DECOMPILE_SEC = 60
BUDGET_SEC = 1500
MAX_CALLERS = 40

DEC = None
MONITOR = ConsoleTaskMonitor()
START_TS = time.time()
L = []
DECOMP_CACHE = {}


def log(m):
    print(m)
    sys.stdout.flush()


def w(s):
    L.append(s)


def u(v):
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


def rd_u64(addr):
    try:
        ga = sa(addr)
        if ga is None:
            return None
        return u(currentProgram.getMemory().getLong(ga))
    except Exception:
        return None


def pac(raw):
    return KERNEL_BASE + (raw & 0xFFFFFFFF)


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


def disasm(addr):
    if not HAS_DISASM:
        return
    try:
        ga = sa(addr)
        if ga is None:
            return
        _DC(ga, None, True).applyTo(currentProgram)
    except Exception:
        pass


def ensure_func(addr):
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
        disasm(ga)
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


def decomp(f, sec=MAX_DECOMPILE_SEC):
    try:
        ent = u(f.getEntryPoint().getOffset())
    except Exception:
        ent = 0
    if ent in DECOMP_CACHE:
        return DECOMP_CACHE[ent]
    try:
        r = get_dec().decompileFunction(f, sec, MONITOR)
        if r is None or not r.decompileCompleted():
            out = ["(decompile failed)"]
        else:
            c = r.getDecompiledFunction()
            out = ["(empty)"] if c is None else [ln.rstrip() for ln in c.getC().split("\n")]
    except Exception as e:
        out = ["(exception %s)" % e]
    DECOMP_CACHE[ent] = out
    return out


def fn_name(f):
    try:
        return str(f.getName())
    except Exception:
        return "?"


def blocks():
    out = []
    try:
        for b in currentProgram.getMemory().getBlocks():
            if not b.isInitialized():
                continue
            if not b.isExecute():
                continue
            s = u(b.getStart().getOffset())
            e = u(b.getEnd().getOffset())
            out.append((s, e))
    except Exception:
        pass
    return out


BLOCKS = None


def get_blocks():
    global BLOCKS
    if BLOCKS is None:
        BLOCKS = blocks()
    return BLOCKS


def sign26(x):
    if x & 0x02000000:
        return x - 0x04000000
    return x


def scan_calls_to(target, max_hits=MAX_CALLERS, budget=40):
    hits = []
    mem = currentProgram.getMemory()
    ts = time.time()
    for pair in get_blocks():
        if time.time() - ts > budget:
            break
        s = pair[0]
        e = pair[1]
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
                    kind = "BL" if op == 0x94000000 else "B"
                    hits.append((pc, kind))
                    if len(hits) >= max_hits:
                        del jbuf
                        return hits
            i += 4
            pc += 4
        del jbuf
    return hits


def dump_fn(addr, label, note):
    w("")
    w(SEP)
    w("### %s @ %s" % (label, fmt(addr)))
    w("note: %s" % note)
    w(SEP)
    f = get_func(addr) or ensure_func(addr)
    if f is None:
        w("  no function")
        return
    try:
        ent = u(f.getEntryPoint().getOffset())
        sz = int(f.getBody().getNumAddresses())
        w("  name=%s entry=%s size=0x%X" % (fn_name(f), fmt(ent), sz))
    except Exception:
        pass
    w("")
    w("-- BL callers --")
    try:
        hits = scan_calls_to(addr, MAX_CALLERS, 40)
    except Exception:
        hits = []
    if not hits:
        w("  (none)")
    for pc, kind in hits:
        cf = getFunctionContaining(sa(pc))
        nm = fn_name(cf) if cf is not None else "?"
        cfe = u(cf.getEntryPoint().getOffset()) if cf is not None else 0
        w("  %s %s in %s @ %s" % (fmt(pc), kind, nm, fmt(cfe)))
    w("")
    w("-- decompile --")
    for ln in decomp(f):
        w("  " + ln)


def task1_field_10c():
    w("")
    w(SEP)
    w("### TASK 1: LDR/STR with offset 0x10C")
    w(SEP)
    listing = currentProgram.getListing()
    it = listing.getInstructions(True)
    count = 0
    while it.hasNext() and not monitor_cancelled():
        ins = it.next()
        mnem = ins.getMnemonicString()
        if not mnem.startswith("LDR") and not mnem.startswith("STR"):
            continue
        for i in range(ins.getNumOperands()):
            for op in ins.getOpObjects(i):
                try:
                    val = op.getUnsignedValue()
                except Exception:
                    continue
                if val == 0x10C:
                    kind = "READ " if mnem.startswith("LDR") else "WRITE"
                    f = getFunctionContaining(ins.getAddress())
                    nm = fn_name(f) if f is not None else "?"
                    w("[%s] %s  in %s  |  %s" % (
                        kind, ins.getAddress(), nm, ins.toString()))
                    count += 1
    w("total hits: %d" % count)


def monitor_cancelled():
    try:
        return MONITOR.isCancelled()
    except Exception:
        return False


def task2_vtable(vtable_ptr, label):
    w("")
    w(SEP)
    w("### TASK 2: vtable %s @ %s" % (label, fmt(vtable_ptr)))
    w(SEP)
    for i in range(64):
        if time.time() - START_TS > BUDGET_SEC:
            w("budget exceeded")
            return
        raw = rd_u64(vtable_ptr + i * 8)
        if raw is None or raw == 0:
            break
        ptr = pac(raw)
        if ptr < KERNEL_BASE or ptr > KERNEL_BASE + 0x20000000:
            break
        f = get_func(ptr) or ensure_func(ptr)
        nm = fn_name(f) if f is not None else "?"
        w("  slot %d: %s @ %s" % (i, nm, fmt(ptr)))
        if f is not None:
            sinks = detect_sinks(f)
            if sinks:
                w("    sinks: %s" % sinks)


def detect_sinks(f):
    out = []
    try:
        text = "\n".join(decomp(f)).lower()
    except Exception:
        return out
    for name in ("copyin", "copyout", "iomalloc", "memcpy", "memset", "kalloc"):
        if name in text:
            out.append(name)
    return out


def task3_lock_type(addr):
    w("")
    w(SEP)
    w("### TASK 3: lock type @ %s" % fmt(addr))
    w(SEP)
    ins = None
    try:
        ins = getInstructionAt(sa(addr))
    except Exception:
        pass
    if ins is None:
        disasm(addr)
        try:
            ins = getInstructionAt(sa(addr))
        except Exception:
            ins = None
    if ins is None:
        w("  no instruction")
        return
    w("  first: %s" % ins.toString())
    mnem = ins.getMnemonicString()
    if mnem == "B":
        try:
            flows = ins.getFlows()
            if flows and len(flows) > 0:
                tgt = u(flows[0].getOffset())
                w("  thunk -> %s" % fmt(tgt))
                f = get_func(tgt) or ensure_func(tgt)
                if f is not None:
                    w("  func: %s" % fn_name(f))
                    text = "\n".join(decomp(f)).lower()
                    if "_lck_mtx_lock" in text or "iolocklock" in text:
                        w("  type: mutex")
                    elif "iocommandgate" in text:
                        w("  type: IOCommandGate serialized")
                    elif "_lck_spin_lock" in text or "ldaxr" in text:
                        w("  type: spinlock")
                    elif "_thread_block" in text:
                        w("  type: mutex via thread_block")
                    else:
                        w("  type: unknown")
        except Exception as e:
            w("  flow error: %s" % e)
    else:
        f = get_func(addr)
        if f is not None:
            text = "\n".join(decomp(f)).lower()
            if "_lck_mtx_lock" in text:
                w("  type: mutex")
            elif "iocommandgate" in text:
                w("  type: IOCommandGate")
            else:
                w("  type: unknown")


def task4_dispatch_table(vtable_ptr, label):
    w("")
    w(SEP)
    w("### TASK 4: dispatch table for %s" % label)
    w(SEP)
    f = get_func(vtable_ptr) or ensure_func(vtable_ptr)
    if f is None:
        w("  no function at vtable ptr")
        return
    text = "\n".join(decomp(f))
    for i, ln in enumerate(text.split("\n")):
        if i > 60:
            break
    w("  decompile preview:")
    for i, ln in enumerate(text.split("\n")):
        if i > 40:
            break
        w("    " + ln)
    w("")
    w("  externalMethod search by name:")
    fm = currentProgram.getFunctionManager()
    found = 0
    it = fm.getFunctions(True)
    while it.hasNext() and found < 10:
        cf = it.next()
        nm = fn_name(cf)
        if "externalMethod" in nm or "ExternalMethod" in nm:
            ent = u(cf.getEntryPoint().getOffset())
            if ent >= 0xFFFFFFF009A00000 and ent <= 0xFFFFFFF009B00000:
                w("    %s @ %s" % (nm, fmt(ent)))
                found += 1


def main():
    global START_TS
    START_TS = time.time()

    log("=== kernel_rw.py v80 ===")
    w("natsuk1 kernel_rw v80")
    w("kernel base %s" % fmt(KERNEL_BASE))
    w("")

    dump_fn(MATCH_POLICY, "necp_match_policy", "sysent[462]")

    dump_fn(RAW_LOOKUP, "raw_lookup", "internal")

    if time.time() - START_TS < BUDGET_SEC:
        log("[*] scanning raw_lookup callers")
        hits = scan_calls_to(RAW_LOOKUP, MAX_CALLERS, 40)
        w("")
        w(SEP)
        w("### raw_lookup callers (%d)" % len(hits))
        w(SEP)
        seen = set()
        for pc, kind in hits:
            cf = getFunctionContaining(sa(pc))
            if cf is None:
                continue
            cfe = u(cf.getEntryPoint().getOffset())
            if cfe in seen:
                continue
            seen.add(cfe)
            w("  %s @ %s  (call at %s %s)" % (fn_name(cf), fmt(cfe), fmt(pc), kind))
        for cfe in sorted(seen):
            if time.time() - START_TS > BUDGET_SEC:
                w("budget exceeded")
                break
            cf = get_func(cfe)
            if cf is None:
                continue
            w("")
            w(SEP)
            w("### caller %s @ %s" % (fn_name(cf), fmt(cfe)))
            w(SEP)
            for ln in decomp(cf):
                w("  " + ln)

    if time.time() - START_TS < BUDGET_SEC:
        try:
            task1_field_10c()
        except Exception as e:
            w("task1 error: %s" % e)

    if time.time() - START_TS < BUDGET_SEC:
        try:
            task2_vtable(IOHID_VTABLE, "IOHIDOOBReportDescriptor")
        except Exception as e:
            w("task2 error: %s" % e)

    if time.time() - START_TS < BUDGET_SEC:
        try:
            task3_lock_type(LOCK_ADDR)
        except Exception as e:
            w("task3 error: %s" % e)

    if time.time() - START_TS < BUDGET_SEC:
        try:
            task4_dispatch_table(IOMFB_VTABLE, "IOMobileFramebufferUserClient")
        except Exception as e:
            w("task4 error: %s" % e)

    try:
        fh = open(OUT, "w")
        for ln in L:
            fh.write(ln + "\n")
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