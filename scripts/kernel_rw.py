# -*- coding: utf-8 -*-
# @runtime Jython
# kernel_rw.py v65 - NECP client lifetime UAF hunt

import os
import sys
import json
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
SYMBOLS_JSON = os.environ.get("SYMBOLS_JSON", os.path.join(WS, "symbols.json"))
SEP = "=" * 72

# NECP cluster range
NECP_LO = int("FFFFFFF00A4D0000", 16)
NECP_HI = int("FFFFFFF00A520000", 16)

# Explicit targets for full dump (client lifetime)
DUMP_TARGETS = [
    (int("FFFFFFF00A4E60DC", 16), "add_client"),
    (int("FFFFFFF00A4E76F4", 16), "remove_client"),
    (int("FFFFFFF00A4ED864", 16), "session_lookup"),
    (int("FFFFFFF00A4ED8BC", 16), "copy_state"),
    (int("FFFFFFF00A4DB9F0", 16), "session_alloc"),
    (int("FFFFFFF00A4E575C", 16), "remove_flow_1"),
    (int("FFFFFFF00A4DAAC8", 16), "remove_list_1"),
    (int("FFFFFFF00A4DB38C", 16), "remove_list_2"),
    (int("FFFFFFF00A4DB8D4", 16), "lookup_or_alloc"),
    (int("FFFFFFF00A4E3278", 16), "ref_release_or_free"),
    (int("FFFFFFF00A4F7044", 16), "add_client_tail_1"),
    (int("FFFFFFF00A4F709C", 16), "add_client_tail_2"),
    (int("FFFFFFF00A4D9940", 16), "add_client_tail_3"),
    (int("FFFFFFF00A4DA2B8", 16), "add_client_tail_4"),
    (int("FFFFFFF00A4F516C", 16), "update_arena_state"),
    (int("FFFFFFF00A4E93C4", 16), "remove_flow"),
    (int("FFFFFFF00A4E843C", 16), "add_flow"),
    (int("FFFFFFF00A4E5C28", 16), "client_action"),
    (int("FFFFFFF00A4E411C", 16), "necp_open"),
]

# Functions we want to look up by name (symbol resolution)
LOOKUP_NAMES = [
    "lck_mtx_lock",
    "lck_mtx_unlock",
    "lck_mtx_lock_spin",
    "lck_mtx_unlock_spin",
    "lck_rw_lock_shared",
    "lck_rw_unlock_shared",
    "lck_rw_lock_exclusive",
    "lck_rw_unlock_exclusive",
    "lck_rw_lock",
    "lck_rw_unlock",
    "lck_rw_done",
    "os_ref_retain",
    "os_ref_release",
    "os_ref_release_locked",
    "os_ref_release_barrier",
    "os_ref_retain_try",
    "os_atomic_inc_orig",
    "os_atomic_dec_orig",
    "os_atomic_add_orig",
    "os_atomic_sub_orig",
    "iolock_alloc",
    "iolock_lock",
    "iolock_unlock",
    "iolock_free",
    "mtx_lock",
    "mtx_unlock",
    "kfree_type",
    "kfree_data",
    "kfree_ext",
    "zone_free",
    "zfree",
    "thread_call_enter",
    "thread_call_enter_delayed",
    "wakeup",
    "wakeup_one",
    "_wakeup",
    "_wakeup_one",
    "panic",
    "SoftwareBreakpoint",
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


def is_str(x):
    try:
        if isinstance(x, unicode):
            return True
    except Exception:
        pass
    try:
        if isinstance(x, str):
            return True
    except Exception:
        pass
    return False


def load_symbols(path):
    out = {}
    if not os.path.exists(path):
        return out
    try:
        fh = open(path)
        data = json.load(fh)
        fh.close()
    except Exception:
        return out
    if isinstance(data, dict):
        for k, v in data.items():
            try:
                a = int(k)
            except Exception:
                continue
            if is_str(v):
                nm = v.strip()
                if nm:
                    out[nm] = a
    return out


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


def decompile_text(f, sec=90):
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


def bl_callers(target, max_hits=30, budget=45):
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


def collect_calls(func):
    """Return dict: callee_addr -> count, plus list of kfree call sites."""
    calls = {}
    kfree_sites = []
    mem_after = []
    try:
        listing = currentProgram.getListing()
        body = func.getBody()
        it = body.getAddresses(True)
    except Exception:
        return calls, kfree_sites
    kfree_addr = None
    global KFREE_ADDR
    try:
        kfree_addr = KFREE_ADDR
    except Exception:
        kfree_addr = int("FFFFFFF00A201000", 16)
    cnt = 0
    while it.hasNext() and cnt < 40000:
        a = it.next()
        cnt += 1
        try:
            insn = listing.getInstructionAt(a)
            if insn is None:
                continue
            pcode = insn.getPcode()
            if pcode is None:
                continue
            for p in pcode:
                if p.getOpcode() != 1:
                    continue
                inp0 = p.getInput(0)
                tgt = None
                if inp0.isAddress():
                    tgt = _u(inp0.getAddress().getOffset())
                elif inp0.isConstant():
                    tgt = _u(inp0.getOffset())
                if tgt is None:
                    continue
                if tgt in calls:
                    calls[tgt] = calls[tgt] + 1
                else:
                    calls[tgt] = 1
                if tgt == kfree_addr:
                    kfree_sites.append(_u(a.getOffset()))
        except Exception:
            pass
    return calls, kfree_sites


def main():
    global START_TS
    START_TS = time.time()

    log("=== kernel_rw.py v65 ===")

    syms = load_symbols(SYMBOLS_JSON)
    log("[+] symbols: %d" % len(syms))

    w("natsuk1 v65 NECP client lifetime UAF hunt")
    w("symbols_loaded=%d" % len(syms))
    w("necp_range=[%s, %s)" % (fmt(NECP_LO), fmt(NECP_HI)))
    w("")

    # Resolve interesting symbols
    resolved = {}
    w(SEP)
    w("### LOCK / REFCOUNT / FREE PRIMITIVES")
    w(SEP)
    for nm in LOOKUP_NAMES:
        a = syms.get(nm)
        if a is None:
            # try with underscore prefix
            a = syms.get("_" + nm)
        if a is None:
            continue
        resolved[nm] = a
        w("  %-40s %s" % (nm, fmt(a)))
    w("")

    # Any addresses we couldn't resolve - list them for the reader
    missing = []
    for nm in LOOKUP_NAMES:
        if nm not in resolved:
            missing.append(nm)
    if missing:
        w("  UNRESOLVED: %s" % ", ".join(missing))
        w("")

    # Dump each target
    for entry in DUMP_TARGETS:
        addr = entry[0]
        name = entry[1]
        log("[*] %s @ %s" % (name, fmt(addr)))
        if time.time() - START_TS > 900:
            w("BUDGET EXCEEDED at %s" % name)
            break
        f = get_func(addr)
        if f is None:
            f = ensure_function(addr)
        if f is None:
            w("--- %s @ %s NO FUNCTION" % (name, fmt(addr)))
            continue

        w("")
        w(SEP)
        w("### %s @ %s" % (name, fmt(addr)))
        w(SEP)
        try:
            ent = _u(f.getEntryPoint().getOffset())
            sz = int(f.getBody().getNumAddresses())
            w("  func=%s entry=%s size=0x%X" % (str(f.getName()), fmt(ent), sz))
        except Exception:
            pass

        # Calls summary
        calls, kfree_sites = collect_calls(f)
        if kfree_sites:
            w("  kfree sites: %s" % ", ".join([fmt(a) for a in kfree_sites]))

        # Match calls to known locks/refcount
        hits = {}
        for nm, a in resolved.items():
            if a in calls:
                hits[nm] = calls[a]
        if hits:
            w("  lock/ref/free calls:")
            for nm in sorted(hits.keys()):
                w("    %-40s x%d" % (nm, hits[nm]))

        # BL callers
        w("  BL callers:")
        hits = bl_callers(addr, 25, 40)
        if not hits:
            w("    (none)")
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

        # Full decompile
        w("  decompile:")
        for l in decompile_text(f, 90):
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