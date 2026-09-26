# -*- coding: utf-8 -*-
# @runtime Jython
# kernel_rw.py v34 - no string concat, only percent format

import os
import sys
import time
import traceback
from jarray import zeros
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WS, "result.txt")

SEP = "=" * 72
MAX_DECOMPILE_SEC = 60
MAX_BLOCK_SIZE = 0x1000000
GLOBAL_SCAN_BUDGET_SEC = 120

SYSENT_BASE = 0xFFFFFFF007C192A0
SYSENT_STRIDE = 24
NECP_OPEN_IDX = 501
NECP_ACTION_IDX = 502

COPYIN = 0xFFFFFFF00A368EC0
COPYOUT = 0xFFFFFFF00A369A3C
KALLOC = 0xFFFFFFF00A200988
KFREE = 0xFFFFFFF00A201000

SINKS = [
    (COPYIN, "copyin"),
    (COPYOUT, "copyout"),
    (KALLOC, "kalloc_type"),
    (KFREE, "kfree_type"),
]

TARGETS = [
    ("necp_client_action",        0xFFFFFFF00A4E5C28),
    ("necp_client_add_flow",      0xFFFFFFF00A4E843C),
    ("necp_client_add_client",    0xFFFFFFF00A4E60DC),
    ("necp_client_remove_flow",   0xFFFFFFF00A4E93C4),
    ("necp_client_remove_client", 0xFFFFFFF00A4E76F4),
    ("necp_client_copy_result",   0xFFFFFFF00A4E7BE8),
    ("necp_client_copy_list",     0xFFFFFFF00A4E80FC),
    ("necp_client_copy_interface",0xFFFFFFF00A4EAC7C),
    ("necp_client_sysctl_arena",  0xFFFFFFF00A4EB704),
    ("necp_client_update_cache",  0xFFFFFFF00A4EBD58),
    ("necp_client_copy_update",   0xFFFFFFF00A4EC264),
    ("necp_get_tlv_at_offset",    0xFFFFFFF00A4C2034),
    ("necp_flow_alloc",           0xFFFFFFF00A346E70),
    ("necp_handler_big",          0xFFFFFFF00A3D91B4),
    ("necp_per_flow_copy",        0xFFFFFFF00A4F2E70),
    ("necp_copy_result_inner",    0xFFFFFFF00A4F26F0),
    ("fun_4ee24c",                0xFFFFFFF00A4EE24C),
    ("fun_501454",                0xFFFFFFF00A501454),
    ("fun_aa40d30",               0xFFFFFFF00AA40D30),
    ("fun_4edf3c",                0xFFFFFFF00A4EDF3C),
    ("fun_4edd74",                0xFFFFFFF00A4EDD74),
    ("fun_4f1aa4",                0xFFFFFFF00A4F1AA4),
    ("fun_4db9f0",                0xFFFFFFF00A4DB9F0),
    ("fun_700f94",                0xFFFFFFF00A700F94),
    ("fun_4ed864",                0xFFFFFFF00A4ED864),
    ("fun_4ed8bc",                0xFFFFFFF00A4ED8BC),
]

GLOBAL_CALLERS = [
    ("necp_client_action",        0xFFFFFFF00A4E5C28),
    ("necp_client_add_flow",      0xFFFFFFF00A4E843C),
    ("fun_4ee24c",                0xFFFFFFF00A4EE24C),
    ("fun_501454",                0xFFFFFFF00A501454),
    ("fun_aa40d30",               0xFFFFFFF00AA40D30),
    ("fun_4ed8bc",                0xFFFFFFF00A4ED8BC),
]

DEC = None
HAS_DISASM = False
HAS_CREATE = False

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
        return (b[0] & 0xFF) | ((b[1] & 0xFF) << 8) | ((b[2] & 0xFF) << 16) | ((b[3] & 0xFF) << 24) | \
               ((b[4] & 0xFF) << 32) | ((b[5] & 0xFF) << 40) | ((b[6] & 0xFF) << 48) | ((b[7] & 0xFF) << 56)
    except Exception:
        return None


def strip_pac(p):
    if p is None:
        return None
    p = p & 0xFFFFFFFFFFFFFFFF
    if (p & 0xFFFFFFF000000000) == 0xFFFFFFF000000000:
        return p
    return (p & 0x0000000FFFFFFFFF) | 0xFFFFFFF000000000


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
    except Exception as e:
        log("  disasm fail %s" % e)


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
            except Exception as e:
                log("  createFunctionCmd fail %s" % e)
        try:
            fm = currentProgram.getFunctionManager()
            f = fm.createFunction(ga, "nk_%X" % addr)
            if f is not None:
                return f
        except Exception as e:
            log("  fm.createFunction fail %s" % e)
        return getFunctionAt(ga) or getFunctionContaining(ga)
    except Exception as e:
        log("  ensure_function fail %s err=%s" % (fmt(addr), e))
        return None


_blocks = None


def blocks():
    global _blocks
    if _blocks is not None:
        return _blocks
    out = []
    try:
        for b in currentProgram.getMemory().getBlocks():
            try:
                if not b.isInitialized():
                    continue
                if not b.isExecute():
                    continue
                s = _u(b.getStart().getOffset())
                e = _u(b.getEnd().getOffset())
                out.append((s, e, str(b.getName())))
            except Exception:
                pass
    except Exception:
        pass
    _blocks = out
    return out


def sign26(x):
    if x & 0x02000000:
        return x - 0x04000000
    return x


def get_decompiler():
    global DEC
    if DEC is not None:
        return DEC
    d = DecompInterface()
    d.openProgram(currentProgram)
    DEC = d
    return DEC


def decompile(f, seconds=MAX_DECOMPILE_SEC):
    try:
        d = get_decompiler()
        r = d.decompileFunction(f, seconds, ConsoleTaskMonitor())
        if r is None:
            return ["(no result)"]
        if not r.decompileCompleted():
            return ["(failed timeout or error)"]
        c = r.getDecompiledFunction()
        if c is None:
            return ["(empty)"]
        return [line.rstrip() for line in c.getC().split("\n")]
    except Exception as e:
        return ["(exception %s)" % e]


def raw_disasm(addr, max_insn=400):
    out = []
    try:
        ga = sa(addr)
        if ga is None:
            return out
        listing = currentProgram.getListing()
        if listing is None:
            return out
        insn = listing.getInstructionAt(ga)
        if insn is None:
            return out
        cnt = 0
        while insn is not None and cnt < max_insn:
            out.append("  %s  %s" % (insn.getAddress(), insn))
            insn = insn.getNext()
            cnt += 1
    except Exception as e:
        out.append("(raw_disasm exception %s)" % e)
    return out


def callees(f, maxn=100):
    try:
        cf = f.getCalledFunctions(ConsoleTaskMonitor())
    except Exception:
        return []
    if not cf:
        return []
    out = []
    for c in cf:
        try:
            e = _u(c.getEntryPoint().getOffset())
            n = str(c.getName())
            try:
                sz = int(c.getBody().getNumAddresses())
            except Exception:
                sz = 0
            out.append((e, n, sz))
        except Exception:
            pass
    out.sort(key=lambda x: x[0])
    return out[:maxn]


def bl_to(f, target):
    hits = []
    try:
        body = f.getBody()
        if body is None:
            return hits
        it = body.getAddresses(True)
    except Exception:
        return hits
    cnt = 0
    while it.hasNext() and cnt < 80000:
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
            if dst == target:
                hits.append(pc)
    return hits


def mem_ops(f):
    out = []
    try:
        body = f.getBody()
        if body is None:
            return out
        it = body.getAddresses(True)
    except Exception:
        return out
    cnt = 0
    while it.hasNext() and cnt < 80000:
        try:
            a = it.next()
            pc = _u(a.getOffset())
            raw = int(currentProgram.getMemory().getInt(a)) & 0xFFFFFFFF
        except Exception:
            cnt += 1
            continue
        cnt += 1
        kind = None
        base = 0
        imm = 0
        if (raw & 0xFFC00000) == 0xF9400000:
            kind, base, imm = "ldr_x", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 8
        elif (raw & 0xFFC00000) == 0xB9400000:
            kind, base, imm = "ldr_w", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 4
        elif (raw & 0xFFC00000) == 0xF9000000:
            kind, base, imm = "str_x", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 8
        elif (raw & 0xFFC00000) == 0xB9000000:
            kind, base, imm = "str_w", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 4
        elif (raw & 0xFFE00000) == 0x39400000:
            kind, base, imm = "ldrb", (raw >> 5) & 0x1F, (raw >> 10) & 0xFFF
        elif (raw & 0xFFE00000) == 0x39000000:
            kind, base, imm = "strb", (raw >> 5) & 0x1F, (raw >> 10) & 0xFFF
        elif (raw & 0xFFE00000) == 0x79400000:
            kind, base, imm = "ldrh", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 2
        elif (raw & 0xFFE00000) == 0x79000000:
            kind, base, imm = "strh", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 2
        else:
            continue
        if base in (19, 20, 21, 22, 23, 24, 25, 26, 27, 28) and imm > 0x100:
            out.append((fmt(pc), kind, base, imm))
        elif imm > 0x800:
            out.append((fmt(pc), kind, base, imm))
    return out


def global_bl_callers(target, max_hits=100, budget=GLOBAL_SCAN_BUDGET_SEC):
    hits = []
    mem = currentProgram.getMemory()
    start_ts = time.time()
    for s, e, name in blocks():
        if time.time() - start_ts > budget:
            log("    global scan budget exceeded, stopping")
            break
        size = e - s + 1
        if size <= 0 or size > MAX_BLOCK_SIZE:
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
                        return hits
            i += 4
            pc += 4
        del jbuf
    return hits


def dump_sysent(w):
    w(SEP)
    w("### SYSENT LOOKUP")
    w(SEP)
    w("base = %s stride = %d" % (fmt(SYSENT_BASE), SYSENT_STRIDE))
    w("")
    for idx in [NECP_OPEN_IDX, NECP_ACTION_IDX, 500, 503]:
        entry = SYSENT_BASE + idx * SYSENT_STRIDE
        w("--- sysent[%d] @ %s" % (idx, fmt(entry)))
        for off in range(0, SYSENT_STRIDE, 8):
            v = read_u64(entry + off)
            if v is None:
                w("  +0x%02X : <no data>" % off)
            else:
                w("  +0x%02X : %s" % (off, fmt(v)))
        p0 = read_u64(entry)
        if p0 is not None:
            func = strip_pac(p0)
            w("  entry0 stripped = %s" % fmt(func))
            f = get_func(func)
            if f:
                ent = _u(f.getEntryPoint().getOffset())
                try:
                    sz = int(f.getBody().getNumAddresses())
                except Exception:
                    sz = 0
                w("  func = %s size=0x%X" % (fmt(ent), sz))
            else:
                w("  func = no function at %s" % fmt(func))
    w("")


def main():
    L = []

    def w(s):
        L.append(s)

    log("=== kernel_rw.py v34 ===")
    log("program: %s" % currentProgram.getName())
    log("disasm available: %s" % HAS_DISASM)
    log("create cmd available: %s" % HAS_CREATE)

    w("=== PROGRAM ===")
    w("name = %s" % currentProgram.getName())
    w("has_disasm=%s has_create=%s" % (HAS_DISASM, HAS_CREATE))
    w("")

    log("[0/4] sysent lookup")
    try:
        dump_sysent(w)
    except Exception as ex:
        w("SYSENT EXCEPTION %s" % ex)

    log("[1/4] NECP sanity + ensure functions")
    w(SEP)
    w("### NECP SANITY")
    w(SEP)
    for name, addr in TARGETS:
        try:
            f = get_func(addr)
            if f is None:
                f = ensure_function(addr)
            if f:
                ent = _u(f.getEntryPoint().getOffset())
                try:
                    sz = int(f.getBody().getNumAddresses())
                except Exception:
                    sz = 0
                w("  %-32s %s size=0x%X OK" % (name, fmt(ent), sz))
            else:
                w("  %-32s %s no func" % (name, fmt(addr)))
        except Exception as ex:
            w("  %-32s EXCEPTION %s" % (name, str(ex)))
    w("")

    log("[2/4] per-function analysis")
    total = len(TARGETS)
    for idx, (name, addr) in enumerate(TARGETS):
        log("  [%d/%d] %s" % (idx + 1, total, name))
        try:
            f = get_func(addr)
            if f is None:
                f = ensure_function(addr)
            ent = _u(f.getEntryPoint().getOffset()) if f else addr
            try:
                sz = int(f.getBody().getNumAddresses()) if f else 0
            except Exception:
                sz = 0
            w("")
            w(SEP)
            w("### %s  entry=%s  size=0x%X" % (name, fmt(ent), sz))
            w(SEP)
            if not f:
                w("NO FUNCTION, raw disasm fallback:")
                for l in raw_disasm(addr, 200):
                    w(l)
                w("")
                continue

            try:
                w("CALLEES:")
                for e, n, s2 in callees(f, 100):
                    mark = ""
                    for sa2, sn in SINKS:
                        if e == sa2:
                            mark = "  <== %s" % sn
                            break
                    w("  %s  %-40s size=0x%X%s" % (fmt(e), n[:40], s2, mark))
                w("")
            except Exception as ex:
                w("CALLEES EXCEPTION %s" % ex)

            try:
                w("BL CALLS IN BODY:")
                any_hit = False
                for sa2, sn in SINKS:
                    hits = bl_to(f, sa2)
                    if hits:
                        any_hit = True
                        w("  %s x%d:" % (sn, len(hits)))
                        for pc in hits:
                            w("    %s" % fmt(pc))
                if not any_hit:
                    w("  (none)")
                w("")
            except Exception as ex:
                w("BL CALLS EXCEPTION %s" % ex)

            try:
                susp = mem_ops(f)
                if susp:
                    w("SUSPICIOUS MEM OPS:")
                    for pc, kind, base, imm in susp[:120]:
                        w("    %s  %-8s  [x%-2d, #0x%X]" % (pc, kind, base, imm))
                    w("")
            except Exception as ex:
                w("MEM OPS EXCEPTION %s" % ex)

            try:
                w("DECOMPILE:")
                body = decompile(f)
                for l in body:
                    w("  %s" % l)
                w("")
                if len(body) <= 1 and body[0].startswith("(failed"):
                    w("RAW DISASM FALLBACK:")
                    for l in raw_disasm(ent, 300):
                        w(l)
                    w("")
            except Exception as ex:
                w("DECOMPILE EXCEPTION %s" % ex)
        except Exception as ex:
            w("FUNC EXCEPTION %s %s" % (name, ex))
            continue

    log("[3/4] global BL callers")
    w(SEP)
    w("### GLOBAL BL CALLERS")
    w(SEP)
    for name, addr in GLOBAL_CALLERS:
        log("  %s" % name)
        w("")
        w("--- callers of %s @ %s" % (name, fmt(addr)))
        try:
            hits = global_bl_callers(addr, 100)
        except Exception as ex:
            w("  exception %s" % ex)
            continue
        if not hits:
            w("  (none)")
            continue
        for pc, kind in hits:
            f = getFunctionContaining(sa(pc))
            nm = str(f.getName()) if f else "?"
            fent = _u(f.getEntryPoint().getOffset()) if f else 0
            w("  %s  %-4s in %-30s @ %s" % (fmt(pc), kind, nm[:30], fmt(fent)))

    log("[4/4] write result")
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