# -*- coding: utf-8 -*-
# @runtime Jython
# kernel_rw.py v50 - IOKit deep scan

import os
import sys
import json
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
SYMBOLS_JSON = os.environ.get("SYMBOLS_JSON", os.path.join(WS, "symbols.json"))
SEP = "=" * 72

TAINT_SEC = 1200
DUMP_SEC = 600
MAX_ANALYZED = 30000
MAX_WORKLIST = 60000
MAX_DEPTH = 14
MAX_DECOMPILE_SEC = 45
MAX_SOURCES = 80

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

# exact names first
IOKIT_EXACT = [
    "iokit_user_client_trap",
    "is_io_service_open_extended",
    "io_connect_method",
    "io_connect_method_scalarI_scalarO",
    "io_connect_method_scalarI_structureO",
    "io_connect_method_scalarI_structureI",
    "io_connect_method_structureI_structureO",
    "is_io_connect_method",
    "io_connect_set_notification_port",
    "is_io_connect_set_notification_port",
    "io_connect_add_client",
    "is_io_connect_add_client",
    "io_connect_map_memory_into_task",
    "io_connect_unmap_memory_from_task",
    "io_connect_set_properties",
    "io_connect_get_service",
    "io_connect_get_notification_semaphore",
    "io_service_open_extended",
    "io_service_get_matching_services",
    "io_service_get_matching_service",
    "io_service_add_notification",
    "io_service_get_matching_services_bin",
    "io_service_get_matching_service_bin",
    "io_service_match_property_table",
    "io_service_add_interest_notification",
    "io_registry_entry_create_iterator",
    "io_registry_entry_get_child_iterator",
    "io_registry_entry_get_parent_iterator",
    "io_registry_entry_get_property",
    "io_registry_entry_get_property_bytes",
    "io_registry_entry_get_properties",
    "io_registry_entry_from_path",
    "io_iterator_next",
    "io_iterator_reset",
    "io_object_get_class_name",
    "io_object_conforms_to",
    "io_object_get_retain_count",
]

# substrings for prefix/substring match
IOKIT_SUBSTR = [
    "io_connect",
    "ioconnect",
    "io_service",
    "ioservice",
    "io_registry",
    "ioregistry",
    "io_iterator",
    "io_iterator",
    "is_io_",
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


def _is_str(x):
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
    result = {}
    if not os.path.exists(path):
        log("[!] symbols.json missing: %s" % path)
        return result
    try:
        fh = open(path)
        data = json.load(fh)
        fh.close()
    except Exception as e:
        log("[!] symbols parse fail: %s" % e)
        return result

    if isinstance(data, dict):
        for k, v in data.items():
            try:
                a = int(k)
                if _is_str(v):
                    name = v.strip()
                    if name:
                        result[name] = a
                    continue
            except Exception:
                pass
            try:
                a = int(v)
                if _is_str(k):
                    name = k.strip()
                    if name:
                        result[name] = a
                    continue
            except Exception:
                pass
    log("[+] symbols loaded: %d" % len(result))
    return result


def find_iokit_sources(syms):
    found = []
    seen = set()
    # 1. exact names
    for name in IOKIT_EXACT:
        addr = syms.get(name)
        if addr is None:
            continue
        if addr in seen:
            continue
        seen.add(addr)
        found.append((addr, name))
    log("[+] exact matches: %d" % len(found))
    # 2. substring
    matched_sub = 0
    for name in syms.keys():
        if len(found) >= MAX_SOURCES:
            break
        low = name.lower()
        hit = False
        for sub in IOKIT_SUBSTR:
            if sub in low:
                hit = True
                break
        if not hit:
            continue
        addr = syms[name]
        if addr in seen:
            continue
        seen.add(addr)
        found.append((addr, name))
        matched_sub += 1
    log("[+] substring matches: %d" % matched_sub)
    return found[:MAX_SOURCES]


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
    while changed and iters < 400:
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


def pick_dump_targets(findings, hard_targets):
    """Extended picker: depth<=2 copyin, depth<=1 kalloc, hard targets from caller."""
    seen = set()
    picks = []
    # priority 0: hard targets
    for pair in hard_targets:
        a = pair[0]
        if a in seen:
            continue
        seen.add(a)
        picks.append((a, pair[1], "hard"))
    # priority 1: depth<=1 kalloc/copyin
    for fd in findings:
        d = fd.get("depth", 99)
        if d > 1:
            continue
        sk = fd.get("sink")
        if sk != "kalloc_type" and sk != "copyin" and sk != "copyout":
            continue
        a = fd.get("in_func_addr")
        if a in seen:
            continue
        seen.add(a)
        picks.append((a, fd.get("in_func"), sk + " d=" + str(d)))
    # priority 2: depth<=2 copyin/kalloc
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
    # priority 3: all unique kalloc/copyin sorted by depth
    rest = []
    for fd in findings:
        sk = fd.get("sink")
        if sk != "kalloc_type" and sk != "copyin":
            continue
        a = fd.get("in_func_addr")
        if a in seen:
            continue
        rest.append(fd)
    rest.sort(key=lambda x: x.get("depth", 99))
    for fd in rest[:8]:
        a = fd.get("in_func_addr")
        if a in seen:
            continue
        seen.add(a)
        picks.append((a, fd.get("in_func"), fd.get("sink") + " d=" + str(fd.get("depth"))))
    return picks[:24]


def main():
    global START_TS
    START_TS = time.time()

    log("=== kernel_rw.py v50 IOKit deep ===")

    syms = load_symbols(SYMBOLS_JSON)
    sources = find_iokit_sources(syms)
    log("[+] IOKit sources: %d" % len(sources))

    w("natsuk1 IOKit taint scan v50")
    w("symbols_loaded=%d iokit_sources=%d" % (len(syms), len(sources)))
    w("sinks=%d depth=%d budget=%ds" % (len(SINK_LIST), MAX_DEPTH, TAINT_SEC))
    w("")

    if not sources:
        w("NO IOKIT SOURCES FOUND")
        try:
            fh = open(OUT, "w")
            for l in L:
                fh.write(l + "\n")
            fh.close()
        except Exception:
            pass
        return

    w("SOURCES (%d):" % len(sources))
    for pair in sources:
        w("  %s  %s" % (fmt(pair[0]), pair[1]))
    w("")

    all_findings = []
    per_source_interesting = []

    for idx in range(len(sources)):
        addr = sources[idx][0]
        name = sources[idx][1]
        log("[%d/%d] %s" % (idx + 1, len(sources), name))
        try:
            f = get_func(addr)
            if f is None:
                f = ensure_function(addr)
            if f is None:
                w("SRC %-48s no function" % name[:48])
                continue
            findings = analyze_source(addr, name)
        except Exception as ex:
            findings = []
            w("SRC %-48s exception %s" % (name[:48], ex))
            continue
        if not findings:
            w("SRC %-48s (no tainted sinks)" % name[:48])
            continue
        # dedupe findings for compact display
        uniq = {}
        for fd in findings:
            k = fd.get("sink") + "|" + fd.get("pc") + "|" + fd.get("in_func_addr")
            if k not in uniq:
                uniq[k] = fd
        uf = uniq.values()
        w("SRC %-48s findings=%d uniq=%d" % (name[:48], len(findings), len(uf)))
        for fd in uf:
            w("  %-12s @ %s  %s  d=%d" % (
                fd.get("sink"), fd.get("pc"),
                fd.get("in_func"), fd.get("depth")))
            all_findings.append(fd)
        # hard target: if a copyin/kalloc at depth 1-2
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
    w("unique in_func per sink (top):")
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

    START_TS = time.time()
    picks = pick_dump_targets(all_findings, per_source_interesting)
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