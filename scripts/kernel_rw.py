# -*- coding: utf-8 -*-
# @runtime Jython

import os, re, json, traceback, time

from jarray import zeros
from ghidra.util.task import TaskMonitor
try:
    from ghidra.program.model.address import Address
except:
    Address = None

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WS, "result.txt")
OUT_JSON = os.path.join(WS, "offsets.json")

NEEDLE = b"necp_client_copy_result"
MAX_HITS = 60
MAX_FUNCS = 6
MAX_DISASM = 500
HINT_ADDR = 0xFFFFFFF0070D2AC8  # where we saw the string last run

def _u(v): return int(v) & 0xFFFFFFFFFFFFFFFF
def fmt(v):
    if v is None: return "0x0"
    try: return "0x%016X" % (int(v) & 0xFFFFFFFFFFFFFFFF)
    except: return "0x0"
def sa(a):
    if a is None: return None
    try: return currentProgram.getAddressFactory().getAddress("%X" % (int(a) & 0xFFFFFFFFFFFFFFFF))
    except: return None

_blocks = None
def blocks():
    global _blocks
    if _blocks is not None: return _blocks
    out = []
    try:
        for b in currentProgram.getMemory().getBlocks():
            try:
                if not b.isInitialized(): continue
                out.append((_u(b.getStart().getOffset()),
                            _u(b.getEnd().getOffset()),
                            b.getName(), b.isExecute(), b))
            except: pass
    except: pass
    _blocks = out
    return out

def inblk(a):
    if a is None: return None
    for s, e, n, x, b in blocks():
        if s <= a < e: return (s, e, n, x)
    return None

# ---------- find string via native findBytes ----------
def find_string_occurrences():
    hits = []
    mem = currentProgram.getMemory()

    # convert Python bytes to Java byte[] (signed)
    jneedle = zeros(len(NEEDLE), 'b')
    for i, c in enumerate(NEEDLE):
        jneedle[i] = c if c < 128 else c - 256

    start = mem.getMinAddress()
    if start is None:
        return hits
    monitor = TaskMonitor.DUMMY
    addr = start
    while True:
        try:
            hit = mem.findBytes(addr, jneedle, None, True, monitor)
        except Exception as ex:
            print("[-] findBytes err: %s" % str(ex))
            break
        if hit is None: break
        hits.append(_u(hit.getOffset()))
        if len(hits) >= MAX_HITS: break
        nxt = hit.add(1)
        if nxt is None: break
        addr = nxt
    return hits

# ---------- decoder ----------
def dec(b, pc):
    if b == 0xD503237F: return "pacibsp"
    if b == 0xD50323FF: return "autibsp"
    if b == 0xD503233F: return "paciasp"
    if b == 0xD50323BF: return "autiasp"
    if b == 0xD5033BBF: return "autiasp"
    if b == 0xD65F03C0: return "ret"
    if b == 0xD503201F: return "nop"
    if b == 0xD65F0FFF: return "ret"
    if (b & 0xFF800000) == 0x0F000000: return "movi v%d.16b, #0x%X" % (b & 0x1F, (b >> 5) & 0xFF)
    if (b & 0xFFE00000) == 0x6F00E400: return "movi v%d.2d, #0" % (b & 0x1F)
    if (b & 0x7FE00000) == 0x6A000000: return "tst w%d, w%d" % ((b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0xEA000000: return "tst x%d, x%d" % ((b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0xFFC00000) == 0xA9800000:
        i = (b >> 15) & 0x7F
        if i & 0x40: i -= 0x80
        return "stp x%d, x%d, [x%d, #%d]!" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, i * 8)
    if (b & 0xFFC00000) == 0xA9C00000:
        i = (b >> 15) & 0x7F
        if i & 0x40: i -= 0x80
        return "ldp x%d, x%d, [x%d, #%d]!" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, i * 8)
    if (b & 0xFFC00000) == 0xA9000000:
        return "stp x%d, x%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, ((b >> 15) & 0x7F) * 8)
    if (b & 0xFFC00000) == 0xA9400000:
        return "ldp x%d, x%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, ((b >> 15) & 0x7F) * 8)
    if (b & 0xFFC00000) == 0x29000000:
        return "stp w%d, w%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, ((b >> 15) & 0x7F) * 4)
    if (b & 0xFFC00000) == 0x29400000:
        return "ldp w%d, w%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, ((b >> 15) & 0x7F) * 4)
    if (b & 0xFFC00000) == 0xAD800000:
        i = (b >> 15) & 0x7F
        if i & 0x40: i -= 0x80
        return "stp q%d, q%d, [x%d, #%d]!" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, i * 16)
    if (b & 0xFFC00000) == 0xADC00000:
        i = (b >> 15) & 0x7F
        if i & 0x40: i -= 0x80
        return "ldp q%d, q%d, [x%d, #%d]!" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, i * 16)
    if (b & 0xFFC00000) == 0xAD000000:
        return "stp q%d, q%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, ((b >> 15) & 0x7F) * 16)
    if (b & 0xFFC00000) == 0xAD400000:
        return "ldp q%d, q%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 10) & 0x1F, (b >> 5) & 0x1F, ((b >> 15) & 0x7F) * 16)
    if (b & 0xFFC00000) == 0x3D800000:
        return "str q%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 5) & 0x1F, ((b >> 10) & 0xFFF) * 16)
    if (b & 0xFFC00000) == 0x3DC00000:
        return "ldr q%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 5) & 0x1F, ((b >> 10) & 0xFFF) * 16)
    if (b & 0xFFC00000) == 0xF9400000:
        return "ldr x%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 5) & 0x1F, ((b >> 10) & 0xFFF) * 8)
    if (b & 0xFFC00000) == 0xB9400000:
        return "ldr w%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 5) & 0x1F, ((b >> 10) & 0xFFF) * 4)
    if (b & 0xFFC00000) == 0xF9000000:
        return "str x%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 5) & 0x1F, ((b >> 10) & 0xFFF) * 8)
    if (b & 0xFFC00000) == 0xB9000000:
        return "str w%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 5) & 0x1F, ((b >> 10) & 0xFFF) * 4)
    if (b & 0xFFE00000) == 0x39400000:
        return "ldrb w%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 10) & 0xFFF)
    if (b & 0xFFE00000) == 0x39000000:
        return "strb w%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 10) & 0xFFF)
    if (b & 0xFFE00000) == 0x79400000:
        return "ldrh w%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 5) & 0x1F, ((b >> 10) & 0xFFF) * 2)
    if (b & 0xFFE00000) == 0x79000000:
        return "strh w%d, [x%d, #0x%X]" % (b & 0x1F, (b >> 5) & 0x1F, ((b >> 10) & 0xFFF) * 2)
    if (b & 0xFFC00000) == 0xF8400000:
        i = (b >> 12) & 0x1FF
        if i & 0x100: i -= 0x200
        return "ldur x%d, [x%d, #%d]" % (b & 0x1F, (b >> 5) & 0x1F, i)
    if (b & 0xFFC00000) == 0xB8400000:
        i = (b >> 12) & 0x1FF
        if i & 0x100: i -= 0x200
        return "ldur w%d, [x%d, #%d]" % (b & 0x1F, (b >> 5) & 0x1F, i)
    if (b & 0xFFC00000) == 0xF8000000:
        i = (b >> 12) & 0x1FF
        if i & 0x100: i -= 0x200
        return "stur x%d, [x%d, #%d]" % (b & 0x1F, (b >> 5) & 0x1F, i)
    if (b & 0xFFC00000) == 0xB8000000:
        i = (b >> 12) & 0x1FF
        if i & 0x100: i -= 0x200
        return "stur w%d, [x%d, #%d]" % (b & 0x1F, (b >> 5) & 0x1F, i)
    if (b & 0x7F800000) == 0x52800000:
        return "movz w%d, #0x%X, lsl #%d" % (b & 0x1F, (b >> 5) & 0xFFFF, ((b >> 21) & 3) * 16)
    if (b & 0x7F800000) == 0xD2800000:
        return "movz x%d, #0x%X, lsl #%d" % (b & 0x1F, (b >> 5) & 0xFFFF, ((b >> 21) & 3) * 16)
    if (b & 0x7F800000) == 0x72800000:
        return "movk w%d, #0x%X, lsl #%d" % (b & 0x1F, (b >> 5) & 0xFFFF, ((b >> 21) & 3) * 16)
    if (b & 0x7F800000) == 0xF2800000:
        return "movk x%d, #0x%X, lsl #%d" % (b & 0x1F, (b >> 5) & 0xFFFF, ((b >> 21) & 3) * 16)
    if (b & 0x7F800000) == 0x12800000:
        return "movn w%d, #0x%X, lsl #%d" % (b & 0x1F, (b >> 5) & 0xFFFF, ((b >> 21) & 3) * 16)
    if (b & 0x7F800000) == 0x92800000:
        return "movn x%d, #0x%X, lsl #%d" % (b & 0x1F, (b >> 5) & 0xFFFF, ((b >> 21) & 3) * 16)
    if (b & 0x7F800000) == 0x11000000:
        sh = (b >> 22) & 1; i = (b >> 10) & 0xFFF
        if sh: i <<= 12
        return "add w%d, w%d, #0x%X" % (b & 0x1F, (b >> 5) & 0x1F, i)
    if (b & 0x7F800000) == 0x91000000:
        sh = (b >> 22) & 1; i = (b >> 10) & 0xFFF
        if sh: i <<= 12
        return "add x%d, x%d, #0x%X" % (b & 0x1F, (b >> 5) & 0x1F, i)
    if (b & 0x7F800000) == 0x51000000:
        sh = (b >> 22) & 1; i = (b >> 10) & 0xFFF
        if sh: i <<= 12
        return "sub w%d, w%d, #0x%X" % (b & 0x1F, (b >> 5) & 0x1F, i)
    if (b & 0x7F800000) == 0xD1000000:
        sh = (b >> 22) & 1; i = (b >> 10) & 0xFFF
        if sh: i <<= 12
        return "sub x%d, x%d, #0x%X" % (b & 0x1F, (b >> 5) & 0x1F, i)
    if (b & 0x7FE00000) == 0x0B000000: return "add w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x8B000000: return "add x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x4B000000: return "sub w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0xCB000000: return "sub x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x2A000000: return "orr w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0xAA000000: return "orr x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x0A000000: return "and w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x8A000000: return "and x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0x6B000000: return "subs w%d, w%d, w%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7FE00000) == 0xEB000000: return "subs x%d, x%d, x%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F)
    if (b & 0x7F800000) == 0x53000000: return "ubfm w%d, w%d, #%d, #%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x3F, (b >> 10) & 0x3F)
    if (b & 0x7F800000) == 0xD3000000: return "ubfm x%d, x%d, #%d, #%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x3F, (b >> 10) & 0x3F)
    if (b & 0x9F000000) == 0x90000000:
        il = (b >> 29) & 3; ih = (b >> 5) & 0x7FFFF
        i = (ih << 2) | il
        if i & 0x100000: i -= 0x200000
        return "adrp x%d, 0x%016X" % (b & 0x1F, ((pc & ~0xFFF) + (i << 12)) & 0xFFFFFFFFFFFFFFFF)
    if (b & 0x9F000000) == 0x10000000:
        il = (b >> 29) & 3; ih = (b >> 5) & 0x7FFFF
        i = (ih << 2) | il
        if i & 0x100000: i -= 0x200000
        return "adr x%d, 0x%016X" % (b & 0x1F, (pc + i) & 0xFFFFFFFFFFFFFFFF)
    if (b & 0x7C000000) == 0x14000000:
        o = b & 0x03FFFFFF
        if o & 0x02000000: o -= 0x04000000
        return "b #0x%X (-> 0x%016X)" % (o * 4, (pc + o * 4) & 0xFFFFFFFFFFFFFFFF)
    if (b & 0x7C000000) == 0x94000000:
        o = b & 0x03FFFFFF
        if o & 0x02000000: o -= 0x04000000
        return "bl #0x%X (-> 0x%016X)" % (o * 4, (pc + o * 4) & 0xFFFFFFFFFFFFFFFF)
    if (b & 0xFF000010) == 0x54000000:
        o = (b >> 5) & 0x7FFFF
        if o & 0x40000: o -= 0x80000
        N = ["eq","ne","cs","cc","mi","pl","vs","vc","hi","ls","ge","lt","gt","le","al","nv"]
        return "b.%s #0x%X" % (N[b & 0xF], o * 4)
    if (b & 0x7E000000) == 0x34000000:
        o = (b >> 5) & 0x7FFFF
        if o & 0x40000: o -= 0x80000
        return "cbz w%d, #0x%X" % (b & 0x1F, o * 4)
    if (b & 0x7E000000) == 0x35000000:
        o = (b >> 5) & 0x7FFFF
        if o & 0x40000: o -= 0x80000
        return "cbnz w%d, #0x%X" % (b & 0x1F, o * 4)
    if (b & 0x7E000000) == 0xB4000000:
        o = (b >> 5) & 0x7FFFF
        if o & 0x40000: o -= 0x80000
        return "cbz x%d, #0x%X" % (b & 0x1F, o * 4)
    if (b & 0x7E000000) == 0xB5000000:
        o = (b >> 5) & 0x7FFFF
        if o & 0x40000: o -= 0x80000
        return "cbnz x%d, #0x%X" % (b & 0x1F, o * 4)
    if (b & 0x7F800000) == 0x71000000: return "cmp w%d, #0x%X" % ((b >> 5) & 0x1F, (b >> 10) & 0xFFF)
    if (b & 0x7F800000) == 0xF1000000: return "cmp x%d, #0x%X" % ((b >> 5) & 0x1F, (b >> 10) & 0xFFF)
    if (b & 0x7FE00C00) == 0x1A800000: return "csel w%d, w%d, w%d, #%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F, b & 0xF)
    if (b & 0x7FE00C00) == 0x9A800000: return "csel x%d, x%d, x%d, #%d" % (b & 0x1F, (b >> 5) & 0x1F, (b >> 16) & 0x1F, b & 0xF)
    return "?? (0x%08X)" % b

def disasm(a, count):
    if a is None: return []
    blk = inblk(a)
    if blk is None: return []
    ga = sa(a)
    if ga is None: return []
    mem = currentProgram.getMemory()
    out = []
    for i in range(count):
        aa = a + i * 4
        gaa = sa(aa)
        if gaa is None: break
        try:
            b = mem.getInt(gaa) & 0xFFFFFFFF
        except: break
        out.append("%016X  %08X  %s" % (aa, b, dec(b, aa)))
    return out

def parse_instr(line):
    m = re.match(r"([0-9A-F]{16})\s+([0-9A-F]{8})\s+(.*)", line)
    if not m: return None
    return int(m.group(1), 16), m.group(3).split(" ", 1)[0].lower(), m.group(3)

def extract_mem(body):
    m = re.search(r"\[(x\d+|sp|x31),\s*#(0x[0-9A-Fa-f]+|-?\d+)\]", body)
    if not m: return None
    try:
        i = int(m.group(2), 0)
        if i < 0: i += 0x1000
        return m.group(1), i
    except: return None

def extract_call(body):
    m = re.search(r"->\s*0x([0-9A-F]+)", body)
    return int(m.group(1), 16) if m else None

def get_refs_to(a):
    out = []
    try:
        ga = sa(a)
        if ga is None: return out
        for ref in getReferencesTo(ga):
            try: out.append(_u(ref.getFromAddress().getOffset()))
            except: pass
    except: pass
    return out

def func_containing(a):
    try:
        ga = sa(a)
        if ga is None: return None
        f = getFunctionContaining(ga)
        if f is None: return None
        return _u(f.getEntryPoint().getOffset())
    except: return None

def dump_bytes(a, n=64):
    out = []
    blk = inblk(a)
    if blk is None: return ["(not in block)"]
    ga = sa(a)
    if ga is None: return ["(no addr)"]
    mem = currentProgram.getMemory()
    try:
        jbuf = zeros(n, 'b')
        mem.getBytes(ga, jbuf)
        s = ""
        for i in range(n):
            c = (jbuf[i] + 256) & 0xFF
            s += chr(c) if 0x20 <= c < 0x7F else "."
        return [s]
    except Exception as e:
        return ["(err: %s)" % str(e)]

def main():
    print("=== necp_client_copy_result native findBytes ===")
    t0 = time.time()

    lines = []
    lines.append("=== SCAN ===")
    lines.append("needle: %s" % NEEDLE)
    lines.append("blocks: %d" % len(blocks()))
    try:
        mem = currentProgram.getMemory()
        lines.append("mem range: %s - %s" % (
            fmt(mem.getMinAddress().getOffset()),
            fmt(mem.getMaxAddress().getOffset())))
    except: pass
    lines.append("")

    # sanity: dump bytes at HINT to confirm string is present
    lines.append("=== HINT DUMP (0x%X) ===" % HINT_ADDR)
    for l in dump_bytes(HINT_ADDR, 64):
        lines.append("  " + l)
    lines.append("")

    print("[+] findBytes scan...")
    hits = find_string_occurrences()
    print("[+] hits: %d (%.1fs)" % (len(hits), time.time() - t0))
    lines.append("=== HITS ===")
    lines.append("count: %d" % len(hits))
    for h in hits[:20]:
        blk = inblk(h)
        lines.append("  %s  [%s]" % (fmt(h), blk[2] if blk else "?"))
    lines.append("")

    if not hits:
        lines.append("VERDICT: findBytes found nothing. String may be in")
        lines.append("    a compressed/uninitialized segment, OR split across blocks.")
        write(lines, {})
        return

    # xrefs
    print("[+] resolving xrefs...")
    func_set = {}
    for h in hits:
        for r in get_refs_to(h):
            f = func_containing(r)
            if f:
                func_set[f] = func_set.get(f, 0) + 1
    lines.append("=== REFS -> FUNCS ===")
    lines.append("unique funcs: %d" % len(func_set))
    for f in sorted(func_set.keys()):
        blk = inblk(f)
        lines.append("  func %s  hits=%d  [%s]" % (fmt(f), func_set[f], blk[2] if blk else "?"))
    lines.append("")

    if not func_set:
        lines.append("VERDICT: no funcs found via xrefs. Dumping raw xrefs:")
        for h in hits[:4]:
            refs = get_refs_to(h)
            lines.append("  str %s xrefs=%d" % (fmt(h), len(refs)))
            for r in refs[:8]:
                f = func_containing(r)
                lines.append("    ref %s -> func %s" % (fmt(r), fmt(f) if f else "?"))
        write(lines, {})
        return

    top = sorted(func_set.items(), key=lambda kv: -kv[1])[:MAX_FUNCS]
    print("[+] disassembling %d funcs" % len(top))
    seq_all = []
    for f, cnt in top:
        lines.append("=== FUNC %s (hits=%d) ===" % (fmt(f), cnt))
        dis = disasm(f, MAX_DISASM)
        lines.append("  disasm count: %d" % len(dis))
        ldr = {}
        calls = []
        for l in dis:
            r = parse_instr(l)
            if not r: continue
            pc, mn, body = r
            e = extract_mem(body)
            if mn in ("ldr", "ldrb", "ldrh", "ldur") and e:
                ldr.setdefault(e, []).append((pc, body))
            if mn in ("b", "bl"):
                t = extract_call(body)
                if t: calls.append((pc, mn, t))
        flowregs = ("x19","x20","x21","x22","x23","x24")
        cand = []
        for (b, i), ent in ldr.items():
            if b in flowregs and 0x40 <= i <= 0x300:
                for pc, body in ent:
                    cand.append((pc, b, i, body))
        cand.sort()
        lines.append("  flow-reg LDRs (x19..x24, 0x40..0x300): %d" % len(cand))
        for pc, b, i, body in cand[:20]:
            lines.append("    %016X  %s" % (pc, body))
            seq_all.append((f, pc, b, i, body))
        lines.append("  all LDR offsets:")
        seen = set()
        for (b, i), ent in sorted(ldr.items(), key=lambda kv: kv[0][1]):
            if i in seen: continue
            seen.add(i)
            lines.append("    +0x%03X bases=%s n=%d" % (i, ",".join(sorted(set(x for x,_ in ent))), len(ent)))
        lines.append("  calls (b/bl) unique:")
        seen_t = set()
        for pc, mn, t in calls:
            if t in seen_t: continue
            seen_t.add(t)
            lines.append("    %s -> %s" % (mn, fmt(t)))
        lines.append("  --- disasm (first 100) ---")
        for l in dis[:100]:
            lines.append("  " + l)
        lines.append("")

    lines.append("=== VERDICT ===")
    if seq_all:
        lines.append("flow-reg LDRs found (candidates for NCF_ASSIGNED_OFF):")
        for f, pc, b, i, body in seq_all[:8]:
            lines.append("  func=%s  %s" % (fmt(f), body))
    else:
        lines.append("No flow-reg LDRs in top funcs.")
        lines.append("Likely necp_client_copy_result does not read")
        lines.append("flow->assigned_results directly.")

    jout = {
        "string_hits": [fmt(h) for h in hits],
        "funcs": [fmt(f) for f, _ in top],
        "flow_ldrs": ["%s+0x%X" % (b, i) for _, _, b, i, _ in seq_all],
    }
    write(lines, jout)

def write(lines, jout):
    try:
        with open(OUT, "w") as fh:
            for l in lines: fh.write(l + "\n")
        print("[+] wrote " + OUT)
    except Exception as e:
        print("[-] " + str(e))
    try:
        with open(OUT_JSON, "w") as fh:
            fh.write(json.dumps(jout, indent=2, sort_keys=True))
        print("[+] wrote " + OUT_JSON)
    except Exception as e:
        print("[-] " + str(e))

try:
    main()
except Exception as e:
    print("[-] FATAL: " + str(e))
    traceback.print_exc()
    try:
        with open(OUT, "w") as fh: fh.write("FATAL: " + str(e) + "\n")
    except: pass