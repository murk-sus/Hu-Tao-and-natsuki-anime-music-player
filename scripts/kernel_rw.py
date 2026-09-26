# -*- coding: utf-8 -*-
# @runtime Jython
# kernel_rw.py v25 — primitive hunter for iOS 27.0 / 24A437
# Focus: NECP integer overflow (necp_flow_alloc), UAF, AirLift sandbox paths

import os
import json
import traceback
from jarray import zeros
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor, TaskMonitor

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WS, "result.txt")
OUT_OFF = os.path.join(WS, "offsets.json")
OUT_PRIM = os.path.join(WS, "primitives.json")
SYMBOLS_JSON = os.environ.get("SYMBOLS_JSON", os.path.join(WS, "symbols.json"))

# === TARGET ADDRESSES (iOS 27.0 / 24A437) ===
COPYIN_ADDR  = 0xFFFFFFF00A368EC0
COPYOUT_ADDR = 0xFFFFFFF00A369A3C
KALLOC_ADDR  = 0xFFFFFFF00A200988
KFREE_ADDR   = 0xFFFFFFF00A201000
KALLOC_NECP  = 0xFFFFFFF007C62E68

NECP_BASE = {
    "necp_open":                     0xFFFFFFF00A4E411C,
    "necp_client_action":            0xFFFFFFF00A4E5C28,
    "necp_client_add_flow":          0xFFFFFFF00A4E843C,
    "necp_client_copy_list":         0xFFFFFFF00A4E80FC,
    "necp_client_copy_update":       0xFFFFFFF00A4EC264,
    "necp_client_copy_interface":    0xFFFFFFF00A4EAC7C,
    "necp_client_copy_result":       0xFFFFFFF00A4E7BE8,
    "necp_client_remove_client":     0xFFFFFFF00A4E76F4,
    "necp_client_remove_flow":       0xFFFFFFF00A4E93C4,
    "necp_client_copy_result_inner": 0xFFFFFFF00A4F26F0,
    "necp_client_sysctl_arena":      0xFFFFFFF00A4EB704,
    "necp_get_tlv_at_offset":        0xFFFFFFF00A4C2034,
    "necp_flow_alloc":               0xFFFFFFF00A346E70,
    "necp_handler_big":              0xFFFFFFF00A3D91B4,
    "necp_update_cache":             0xFFFFFFF00A4EBD58,
    "necp_per_flow_copy":            0xFFFFFFF00A4F2E70,
    "copyin":                        COPYIN_ADDR,
    "copyout":                       COPYOUT_ADDR,
    "kalloc_type":                   KALLOC_ADDR,
    "kfree_type":                    KFREE_ADDR,
    "kalloc_type_necp_flow":         KALLOC_NECP,
}

# === PRIMITIVE HUNT TARGETS ===
# Priority 1: integer overflow in flow_alloc
PRIM_FLOW_ALLOC_CALLERS = [
    ("flow_alloc_caller_1", 0xFFFFFFF00A346474),
    ("flow_alloc_caller_2", 0xFFFFFFF00A348180),
    ("handler_big_caller",  0xFFFFFFF00A3D9174),
    ("tlv_wrapper",         0xFFFFFFF00A4C113C),
]

# Priority 2: NECP double-free / UAF
PRIM_UAF_TARGETS = [
    ("necp_client_remove_flow",  0xFFFFFFF00A4E93C4),
    ("necp_client_remove_client",0xFFFFFFF00A4E76F4),
    ("necp_client_copy_result_inner", 0xFFFFFFF00A4F26F0),
    ("necp_per_flow_copy",       0xFFFFFFF00A4F2E70),
]

# Priority 3: AirLift / socket copyin/copyout size mismatch
PRIM_AIRLIFT_TARGETS = [
    ("sooptcopyin",      0xFFFFFFF00A77FD2C),
    ("sbappendcontrol",  0xFFFFFFF00A788A24),
    ("sbappendrecord",   0xFFFFFFF00A7873B8),
    ("sbappendstream",   0xFFFFFFF00A78811C),
]

# Priority 4: copyin/copyout sinks reachable from NECP
PRIM_COPY_SINKS = [
    ("copyin_hot_1",    0xFFFFFFF00A6CEB84),
    ("copyout_hot_1",   0xFFFFFFF00A6F18AC),
    ("copyout_hot_2",   0xFFFFFFF00A6F318C),
    ("copyin_hot_2",    0xFFFFFFF00A753850),
]

TARGETS = []
for lst in [PRIM_FLOW_ALLOC_CALLERS, PRIM_UAF_TARGETS, PRIM_AIRLIFT_TARGETS, PRIM_COPY_SINKS]:
    TARGETS.extend(lst)

# === HELPERS ===
def _u(v):
    return int(v) & 0xFFFFFFFFFFFFFFFF

def fmt(v):
    if v is None:
        return "0x0"
    try:
        return "0x%016X" % (int(v) & 0xFFFFFFFFFFFFFFFF)
    except Exception:
        return "0x0"

def sa(a):
    if a is None:
        return None
    try:
        return currentProgram.getAddressFactory().getAddress(
            "%X" % (int(a) & 0xFFFFFFFFFFFFFFFF))
    except Exception:
        return None

def _try_int(v):
    if v is None:
        return None
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, long)):
        return int(v)
    if isinstance(v, float):
        return int(v)
    if isinstance(v, basestring):
        s = v.strip()
        try:
            if s.startswith("0x") or s.startswith("0X"):
                return int(s, 16)
            return int(s)
        except Exception:
            return None
    return None

def _is_kernel_addr(v):
    i = _try_int(v)
    if i is None:
        return None
    if i < 0xFFFFFFF000000000:
        return None
    if i > 0xFFFFFFFFFFFFFFFF:
        return None
    return i

def load_symbols(path):
    print("[+] symbols.json: %s" % path)
    if not os.path.exists(path):
        print("[!] not found")
        return {}
    try:
        fh = open(path)
        data = json.load(fh)
        fh.close()
    except Exception as e:
        print("[!] parse failed: %s" % e)
        return {}
    syms = {}
    diag = {"dict": 0, "list": 0, "pairs": 0, "skip": 0}

    def add(name, addr):
        if not isinstance(name, basestring):
            diag["skip"] += 1
            return
        n = name.strip()
        if not n:
            diag["skip"] += 1
            return
        a = _try_int(addr)
        if a is None:
            diag["skip"] += 1
            return
        syms[n] = a
        diag["pairs"] += 1

    def walk(node, depth=0):
        if depth > 8:
            return
        if isinstance(node, dict):
            diag["dict"] += 1
            n = None
            a = None
            for nk in ("name", "symbol", "sym", "n"):
                if nk in node and isinstance(node[nk], basestring):
                    n = node[nk]
                    break
            for ak in ("addr", "address", "value", "v"):
                if ak in node:
                    a = node[ak]
                    break
            if n is not None and a is not None:
                add(n, a)
                return
            for k, v in node.items():
                ka = _is_kernel_addr(k)
                if ka is not None:
                    if isinstance(v, basestring):
                        add(v, ka)
                        continue
                    if isinstance(v, dict):
                        nn = None
                        for nk in ("name", "symbol", "sym"):
                            if nk in v and isinstance(v[nk], basestring):
                                nn = v[nk]
                                break
                        if nn is not None:
                            add(nn, ka)
                            continue
                    diag["skip"] += 1
                    continue
                kv = _is_kernel_addr(v)
                if kv is not None and isinstance(k, basestring):
                    add(k, kv)
                    continue
                walk(v, depth + 1)
        elif isinstance(node, list):
            diag["list"] += 1
            for item in node:
                walk(item, depth + 1)

    walk(data)
    print("[+] symbols loaded: %d" % len(syms))
    print("[+] diag: dict=%d list=%d pairs=%d skip=%d" % (
        diag["dict"], diag["list"], diag["pairs"], diag["skip"]))
    return syms

_blocks_cache = None

def blocks():
    global _blocks_cache
    if _blocks_cache is not None:
        return _blocks_cache
    out = []
    try:
        for b in currentProgram.getMemory().getBlocks():
            try:
                if not b.isInitialized():
                    continue
                s = _u(b.getStart().getOffset())
                e = _u(b.getEnd().getOffset())
                n = str(b.getName())
                x = bool(b.isExecute())
                out.append((s, e, n, x))
            except Exception:
                pass
    except Exception:
        pass
    _blocks_cache = out
    return out

def inblk(a):
    if a is None:
        return None
    av = _u(a)
    for s, e, n, x in blocks():
        if s <= av < e:
            return (s, e, n, x)
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

def _sign_extend_26(x):
    if x & 0x02000000:
        return x - 0x04000000
    return x

def find_callers_by_bl(target_addr, max_hits=64):
    hits = []
    target_addr = _u(target_addr)
    mem = currentProgram.getMemory()
    for s, e, name, is_exec in blocks():
        if not is_exec:
            continue
        size = e - s + 1
        if size <= 0 or size > 0x4000000:
            continue
        try:
            jbuf = zeros(size, 'b')
            ga = sa(s)
            if ga is None:
                continue
            mem.getBytes(ga, jbuf)
        except Exception as ex:
            print("[-] getBytes fail on %s: %s" % (name, ex))
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
                imm26 = raw & 0x03FFFFFF
                imm = _sign_extend_26(imm26) << 2
                dst = (pc + imm) & 0xFFFFFFFFFFFFFFFF
                if dst == target_addr:
                    hits.append((pc, "BL" if op == 0x94000000 else "B"))
                    if len(hits) >= max_hits:
                        return hits
            i += 4
            pc += 4
    return hits

def decompile(f, timeout=300):
    out = []
    try:
        d = DecompInterface()
        d.openProgram(currentProgram)
        r = d.decompileFunction(f, timeout, ConsoleTaskMonitor())
        if r is None:
            return ["(no result)"]
        if not r.decompileCompleted():
            return ["(failed: %s)" % str(r.getErrorMessage())]
        c = r.getDecompiledFunction()
        if c is None:
            return ["(empty)"]
        for line in c.getC().split("\n"):
            out.append(line.rstrip())
    except Exception as e:
        out.append("(exception: %s)" % e)
    return out

def callees(f, maxn=40):
    try:
        cf = f.getCalledFunctions(ConsoleTaskMonitor())
    except Exception:
        return []
    out = []
    if not cf:
        return out
    try:
        for c in cf:
            try:
                e = _u(c.getEntryPoint().getOffset())
                n = str(c.getName())
                sz = 0
                try:
                    sz = int(c.getBody().getNumAddresses())
                except Exception:
                    pass
                out.append((e, n, sz))
            except Exception:
                pass
    except Exception:
        pass
    out.sort(key=lambda x: x[0])
    return out[:maxn]

# === PRIMITIVE ANALYSIS ===

def analyze_mem_ops_for_overflow(f, lines):
    """Find ldr/str with potentially user-controlled offsets into heap buffers."""
    suspicious = []
    body = f.getBody()
    if body is None:
        return suspicious
    try:
        it = body.getAddresses(True)
    except Exception:
        return suspicious
    cnt = 0
    # track reg that received copyin result (x0 return value)
    copyin_result_regs = set()
    while it.hasNext() and cnt < 12000:
        a = it.next()
        try:
            pc = _u(a.getOffset())
            raw = int(currentProgram.getMemory().getInt(a)) & 0xFFFFFFFF
        except Exception:
            cnt += 1
            continue
        cnt += 1
        # detect BL to copyin — result in x0
        if (raw & 0xFC000000) == 0x94000000:
            imm26 = raw & 0x03FFFFFF
            imm = _sign_extend_26(imm26) << 2
            dst = (pc + imm) & 0xFFFFFFFFFFFFFFFF
            if dst in (COPYIN_ADDR, 0xFFFFFFF00A368EC0):
                copyin_result_regs.add(0)
        # ldr/str with user-controlled index register
        kind = None
        base = 0
        imm = 0
        idx_reg = None
        if (raw & 0xFFC00000) == 0xF9400000:
            kind, base, imm = "ldr_x", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 8
        elif (raw & 0xFFC00000) == 0xB9400000:
            kind, base, imm = "ldr_w", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 4
        elif (raw & 0xFFC00000) == 0xF9000000:
            kind, base, imm = "str_x", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 8
        elif (raw & 0xFFC00000) == 0xB9000000:
            kind, base, imm = "str_w", (raw >> 5) & 0x1F, ((raw >> 10) & 0xFFF) * 4
        elif (raw & 0xFFC00000) == 0xF8400000:
            i = (raw >> 12) & 0x1FF
            if i & 0x100:
                i -= 0x200
            kind, base, imm = "ldur_x", (raw >> 5) & 0x1F, i
        elif (raw & 0xFFC00000) == 0xB8400000:
            i = (raw >> 12) & 0x1FF
            if i & 0x100:
                i -= 0x200
            kind, base, imm = "ldur_w", (raw >> 5) & 0x1F, i
        else:
            continue
        # suspicious if base reg is one of x19-x28 (callee-saved, often heap ptr)
        # or offset register is x8-x15 (computed index)
        if base in (19, 20, 21, 22, 23, 24, 25, 26, 27, 28) and imm > 0x100:
            suspicious.append((fmt(pc), kind, base, imm))
        if imm > 0x800:
            suspicious.append((fmt(pc), kind, base, imm))
    return suspicious

def find_kfree_pattern(f):
    """Look for two kfree_type calls without kalloc between them (double-free signal)."""
    body = f.getBody()
    if body is None:
        return []
    try:
        it = body.getAddresses(True)
    except Exception:
        return []
    events = []
    cnt = 0
    while it.hasNext() and cnt < 12000:
        a = it.next()
        try:
            pc = _u(a.getOffset())
            raw = int(currentProgram.getMemory().getInt(a)) & 0xFFFFFFFF
        except Exception:
            cnt += 1
            continue
        cnt += 1
        if (raw & 0xFC000000) == 0x94000000:
            imm26 = raw & 0x03FFFFFF
            imm = _sign_extend_26(imm26) << 2
            dst = (pc + imm) & 0xFFFFFFFFFFFFFFFF
            if dst == KFREE_ADDR:
                events.append(("kfree", pc))
            elif dst == KALLOC_ADDR or dst == KALLOC_NECP:
                events.append(("kalloc", pc))
            elif dst == COPYIN_ADDR:
                events.append(("copyin", pc))
    # find two kfree with no kalloc between
    result = []
    last_kfree = None
    for kind, pc in events:
        if kind == "kfree":
            if last_kfree is not None:
                result.append((last_kfree, pc))
            last_kfree = pc
        elif kind == "kalloc":
            last_kfree = None
    return result

def find_copyin_size_mismatch(f, lines):
    """Look for copyin with size arg that differs from a nearby buffer size."""
    # Heuristic: copyin call with size in x2, followed by mem op with larger offset
    body = f.getBody()
    if body is None:
        return []
    try:
        it = body.getAddresses(True)
    except Exception:
        return []
    result = []
    cnt = 0
    last_copyin_pc = None
    last_max_offset = 0
    while it.hasNext() and cnt < 12000:
        a = it.next()
        try:
            pc = _u(a.getOffset())
            raw = int(currentProgram.getMemory().getInt(a)) & 0xFFFFFFFF
        except Exception:
            cnt += 1
            continue
        cnt += 1
        if (raw & 0xFC000000) == 0x94000000:
            imm26 = raw & 0x03FFFFFF
            imm = _sign_extend_26(imm26) << 2
            dst = (pc + imm) & 0xFFFFFFFFFFFFFFFF
            if dst == COPYIN_ADDR:
                last_copyin_pc = pc
                last_max_offset = 0
        # track max offset after copyin
        if last_copyin_pc is not None:
            if (raw & 0xFFC00000) == 0xF9400000:
                off = ((raw >> 10) & 0xFFF) * 8
                if off > last_max_offset:
                    last_max_offset = off
            elif (raw & 0xFFC00000) == 0xB9400000:
                off = ((raw >> 10) & 0xFFF) * 4
                if off > last_max_offset:
                    last_max_offset = off
    return result

# === MAIN ===
def main():
    lines = []
    offsets_out = {}
    primitives = {"integer_overflow": [], "uaf_double_free": [], "copy_size_mismatch": [], "notes": []}

    print("=== kernel_rw.py v25 — primitive hunter ===")

    lines.append("=== PROGRAM ===")
    lines.append("name = %s" % currentProgram.getName())
    lines.append("")

    syms = load_symbols(SYMBOLS_JSON)

    # --- SECTION 1: NECP sanity + addresses ---
    lines.append("=" * 68)
    lines.append("### NECP SANITY")
    lines.append("=" * 68)
    for name, addr in NECP_BASE.items():
        real, src = (syms.get(name, addr), "symbol") if name in syms else (addr, "hardcoded")
        f = get_func(real)
        if f:
            ent = _u(f.getEntryPoint().getOffset())
            sz = 0
            try:
                sz = int(f.getBody().getNumAddresses())
            except Exception:
                pass
            lines.append("  %-32s %s (%s) size=0x%X" % (name, fmt(ent), src, sz))
            offsets_out[name] = fmt(ent)
        else:
            lines.append("  %-32s %s (%s, no func)" % (name, fmt(real), src))
            offsets_out[name] = fmt(real)
    lines.append("")

    # --- SECTION 2: PRIORITY 1 — flow_alloc caller chain ---
    lines.append("=" * 68)
    lines.append("### PRIORITY 1: necp_flow_alloc integer overflow")
    lines.append("=" * = 68)
    lines.append("Target: 0xFFFFFFF00A346E70")
    lines.append("Hypothesis: iVar1 = (uVar6 + param_3) * 0x14|0x18 wraps int32")
    lines.append("Goal: find where param_3 comes from user input")
    lines.append("")

    for label, addr in PRIM_FLOW_ALLOC_CALLERS:
        lines.append("")
        lines.append("--- " + label + " @ " + fmt(addr) + " ---")
        f = get_func(addr)
        if not f:
            lines.append("  (no function)")
            continue
        ent = _u(f.getEntryPoint().getOffset())
        lines.append("  entry = " + fmt(ent))
        offsets_out[label] = fmt(ent)

        # callees
        lines.append("  callees:")
        for e, n, sz2 in callees(f, 30):
            mark = ""
            if e in (0xFFFFFFF00A346E70,):
                mark = "  <== FLOW_ALLOC"
            if e in (COPYIN_ADDR,):
                mark = "  <== COPYIN"
            lines.append("    %s  %-45s size=0x%X%s" % (fmt(e), n[:45], sz2, mark))

        # mem ops suspicious
        susp = analyze_mem_ops_for_overflow(f, lines)
        if susp:
            lines.append("  SUSPICIOUS MEM OPS (possible user-controlled offset):")
            for pc, kind, base, imm in susp[:40]:
                lines.append("    %s  %-8s  [x%-2d, #0x%X]" % (pc, kind, base, imm))
        else:
            lines.append("  (no suspicious mem ops)")

        # decompile
        lines.append("")
        lines.append("  DECOMPILE:")
        body = decompile(f, 300)
        for l in body:
            lines.append("    " + l)
        lines.append("")

    # --- SECTION 3: PRIORITY 2 — UAF / double-free ---
    lines.append("=" * 68)
    lines.append("### PRIORITY 2: NECP UAF / double-free")
    lines.append("=" * 68)
    for label, addr in PRIM_UAF_TARGETS:
        lines.append("")
        lines.append("--- " + label + " @ " + fmt(addr) + " ---")
        f get_func(addr)
        if not f:
            lines.append("  (no function)")
            continue
        ent = _u(f.getEntryPoint().getOffset())
        offsets_out[label] = fmt(ent)
        dbl = find_kfree_pattern(f)
        if dbl:
            lines.append("  POTENTIAL DOUBLE-FREE:")
            for p1, p2 in dbl[:10]:
                lines.append("    kfree %s ... kfree %s" % (fmt(p1), fmt(p2)))
            primitives["uaf_double_free"].append({"func": label, "addr": fmt(ent), "pairs": [(fmt(a), fmt(b)) for a, b in dbl[:10]]})
        else:
            lines.append("  (no double-free pattern detected)")
        body = decompile(f, 200)
        lines.append("  DECOMPILE (first 80 lines):")
        for l in body[:80]:
            lines.append("    " + l)
        lines.append("")

    # --- SECTION 4: PRIORITY 3 — AirLift socket paths ---
    lines.append("=" * 68)
    lines.append("### PRIORITY 3: AirLift socket copyin/copyout")
    lines.append("=" * 68)
    for label, addr in PRIM_AIRLIFT_TARGETS:
        lines.append("")
        lines.append("--- " + label + " @ " + fmt(addr) + " ---")
        f = get_func(addr)
        if not f:
            lines.append("  (no function)")
            continue
        ent = _u(f.getEntryPoint().getOffset())
        offsets_out[label] = fmt(ent)
        susp = analyze_mem_ops_for_overflow(f, lines)
        if susp:
            lines.append("  SUSPICIOUS MEM OPS:")
            for pc, kind, base, imm in susp[:20]:
                lines.append("    %s  %-8s  [x%-2d, #0x%X]" % (pc, kind, base, imm))
        body = decompile(f, 200)
        lines.append("  DECOMPILE (first 80 lines):")
        for l in body[:80]:
            lines.append("    " + l)
        lines.append("")

    # --- SECTION 5: PRIORITY 4 — copyin/copyout sinks ---
    lines.append("=" * 68)
    lines.append("### PRIORITY 4: copyin/copyout sinks")
    lines.append("=" * 68)
    for label, addr in PRIM_COPY_SINKS:
        lines.append("")
        lines.append("--- " + label + " @ " + fmt(addr) + " ---")
        f = get_func(addr)
        if not f:
            lines.append("  (no function)")
            continue
        ent = _u(f.getEntryPoint().getOffset())
        offsets_out[label] = fmt(ent)
        body = decompile(f, 200)
        lines.append("  DECOMPILE (first 60 lines):")
        for l in body[:60]:
            lines.append("    " + l)
        lines.append("")

    # --- SECTION 6: BL callers of flow_alloc (find indirect callers) ---
    lines.append("=" * 68)
    lines.append("### BL CALLERS OF necp_flow_alloc")
    lines.append("=" * 68)
    try:
        hits = find_callers_by_bl(0xFFFFFFF00A346E70, max_hits=64)
    except Exception as e:
        lines.append("  exception: %s" % e)
        hits = []
    if not hits:
        lines.append("  (no BL/B found — dispatcher uses BR/BLR)")
    for pc, kind in hits:
        f = getFunctionContaining(sa(pc))
        nm = str(f.getName()) if f else "?"
        fent = _u(f.getEntryPoint().getOffset()) if f else 0
        lines.append("  %s  %-4s in %-30s @ %s" % (fmt(pc), kind, nm[:30], fmt(fent)))
    lines.append("")

    # --- NOTES ---
    primitives["notes"].append("Public kernel R/W for 27.0 release: NOT available (bexploit only 27b1-b4)")
    primitives["notes"].append("Confirmed KASLR leak: NECP op=0x0D returns user VA")
    primitives["notes"].append("Confirmed sandbox escape: AirLift (AirTraffic, works on 24A437)")
    primitives["notes"].append("Hypothesis: necp_flow_alloc int32 wrap -> heap overflow -> potential kernel R/W")
    primitives["notes"].append("Check caller FUN_fffffff00a346474 for user-controlled param_3")

    # --- WRITE OUTPUTS ---
    try:
        fh = open(OUT, "w")
        for l in lines:
            fh.write(l + "\n")
        fh.close()
        print("[+] wrote " + OUT)
    except Exception as e:
        print("[-] result: %s" % e)

    try:
        fh = open(OUT_OFF, "w")
        fh.write(json.dumps(offsets_out, indent=2, sort_keys=True))
        fh.close()
        print("[+] wrote " + OUT_OFF)
    except Exception as e:
        print("[-] offsets: %s" % e)

    try:
        fh = open(OUT_PRIM, "w")
        fh.write(json.dumps(primitives, indent=2, sort_keys=True))
        fh.close()
        print("[+] wrote " + OUT_PRIM)
    except Exception as e:
        print("[-] primitives: %s" % e)

    print("=== DONE ===")

try:
    main()
except Exception as e:
    print("[-] FATAL: %s" % e)
    traceback.print_exc()