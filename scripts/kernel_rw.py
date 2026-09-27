# -*- coding: utf-8 -*-
# @runtime Jython
# kernel_rw.py v58 - dump NECP internals from v56 findings

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

SYSENT_BASE = int("FFFFFFF007C192D0", 16)
SYSENT_STRIDE = 24
KERNEL_BASE = int("FFFFFFF007004000", 16)

# NECP cluster (correct indices for base 0x...D0)
NECP_ANCHOR_INDICES = [501, 502]

# Functions to dump (from v56 findings)
DUMP_TARGETS = [
    (int("FFFFFFF00A501454", 16), "necp_handler_core",   "core of necp_client_action"),
    (int("FFFFFFF00A4E479C", 16), "necp_memmove_1",     "memmove d=1 in necp_open"),
    (int("FFFFFFF00A4E45F8", 16), "necp_memmove_2",     "memmove d=1..3 in necp_open"),
    (int("FFFFFFF00A4F3840", 16), "necp_hot_d2",        "memmove d=2 from client_action"),
    (int("FFFFFFF00A4ED864", 16), "necp_lookup_sess",   "session lookup"),
    (int("FFFFFFF00A4ED8BC", 16), "necp_copy_state",    "copy state"),
    (int("FFFFFFF00A4DB9F0", 16), "necp_sess_alloc",    "session alloc"),
    (int("FFFFFFF00A4F2E70", 16), "necp_per_flow",      "per-flow copy"),
    (int("FFFFFFF00A4F26F0", 16), "necp_res_inner",     "copy_result_inner"),
    (int("FFFFFFF00A4E843C", 16), "necp_add_flow",      "add_flow"),
    (int("FFFFFFF00A4E60DC", 16), "necp_add_client",    "add_client"),
    (int("FFFFFFF00A4E411C", 16), "necp_open",          "necp_open itself"),
    (int("FFFFFFF00A4E5C28", 16), "necp_client_action", "necp_client_action itself"),
]

MAX_DECOMPILE_SEC = 90
BUDGET_SEC = 600

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


def unpack(raw):
    if raw is None or raw == 0:
        return None
    low = raw & 0xFFFFFFFF
    if low < 0x1000:
        return None
    if low > 0x4000000:
        return None
    return KERNEL_BASE + low


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


def decompile_text(f, sec=MAX_DECOMPILE_SEC):
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


def dump_sysent_anchors():
    w(SEP)
    w("### SYSENT ANCHORS (base=%s)" % fmt(SYSENT_BASE))
    w(SEP)
    w("%-5s %-20s %-6s %-10s" % ("idx", "unwrapped", "narg", "flags"))
    for idx in NECP_ANCHOR_INDICES:
        base = SYSENT_BASE + idx * SYSENT_STRIDE
        raw = read_u64(base)
        addr = unpack(raw)
        narg = read_u16(base + 0x14)
        flags = read_u32(base + 0x10)
        w("%-5d %-20s %-6s %-10s" % (
            idx, fmt(addr) if addr else "?", narg if narg is not None else "?",
            fmt(flags) if flags is not None else "?"))
    w("  expected: 501 = 0xA4E411C (necp_open), 502 = 0xA4E5C28 (necp_client_action)")
    w("")


def dump_one(addr, name, note):
    w("")
    w(SEP)
    w("### %s @ %s" % (name, fmt(addr)))
    w("note: %s" % note)
    w(SEP)

    f = get_func(addr)
    if f is None:
        f = ensure_function(addr)
    if f is None:
        w("  no function")
        return

    try:
        ent = _u(f.getEntryPoint().getOffset())
        sz = int(f.getBody().getNumAddresses())
        w("  func=%s entry=%s size=0x%X" % (str(f.getName()), fmt(ent), sz))
    except Exception:
        pass

    w("")
    w("-- BL callers --")
    try:
        hits = bl_callers(addr, 20, 40)
    except Exception:
        hits = []
    if not hits:
        w("  (none)")
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
        w("  %s %s in %s @ %s" % (fmt(pc), kind, nm, fmt(cfe)))

    w("")
    w("-- decompile --")
    for l in decompile_text(f, MAX_DECOMPILE_SEC):
        w("  " + l)


def main():
    global START_TS
    START_TS = time.time()

    log("=== kernel_rw.py v58 ===")

    w("natsuk1 v58 NECP internals dump")
    w("sysent_base=%s kernel_base=%s" % (fmt(SYSENT_BASE), fmt(KERNEL_BASE)))
    w("targets=%d" % len(DUMP_TARGETS))
    w("")

    dump_sysent_anchors()

    for entry in DUMP_TARGETS:
        addr = entry[0]
        name = entry[1]
        note = entry[2]
        log("[*] %s @ %s" % (name, fmt(addr)))
        if time.time() - START_TS > BUDGET_SEC:
            w("BUDGET EXCEEDED at %s" % name)
            break
        try:
            dump_one(addr, name, note)
        except Exception as e:
            w("  exception: %s" % e)

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