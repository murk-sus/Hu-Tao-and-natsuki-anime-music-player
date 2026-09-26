# -*- coding: utf-8 -*-
# @runtime Jython

import os
import re
import json
import traceback
import time

from jarray import zeros
from ghidra.util.task import TaskMonitor

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WS, "result.txt")
OUT_JSON = os.path.join(WS, "offsets.json")

TARGET = 0xFFFFFFF00A4EAC7C
MAX_DISASM = 800
FLOW_REGS = ["x19", "x20", "x21", "x22", "x23", "x24"]
BAD_CALLS = [0xFFFFFFF00A8BB3B0]


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
        return currentProgram.getAddressFactory().getAddress("%X" % (int(a) & 0xFFFFFFFFFFFFFFFF))
    except Exception:
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
                out.append((_u(b.getStart().getOffset()),
                            _u(b.getEnd().getOffset()),
                            b.getName(), bool(b.isExecute())))
            except Exception:
                pass
    except Exception:
        pass
    _blocks = out
    return out


def inblk(a):
    if a is None:
        return None
    av = _u(a)
    for s, e, nm, ex in blocks():
        if s <= av < e:
            return (s, e, nm, ex)
    return None


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
    if a is None:
        return []
    if inblk(a) is None:
        return []
    ga = sa(a)
    if ga is None:
        return []
    mem = currentProgram.getMemory()
    out = []
    for i in range(int(count)):
        aa = a + i * 4
        gaa = sa(aa)
        if gaa is None:
            break
        try:
            b = int(mem.getInt(gaa)) & 0xFFFFFFFF
        except Exception:
            break
        out.append("%016X  %08X  %s" % (aa, b, dec(b, aa)))
    return out


def parse_instr(line):
    m = re.match(r"([0-9A-F]{16})\s+([0-9A-F]{8})\s+(.*)", line)
    if not m:
        return None
    return (int(m.group(1), 16), m.group(3).split(" ", 1)[0].lower(), m.group(3))


def extract_mem(body):
    m = re.search(r"\[(x\d+|sp|x31),\s*#(0x[0-9A-Fa-f]+|-?\d+)\]", body)
    if not m:
        return None
    try:
        i = int(m.group(2), 0)
        if i < 0:
            i += 0x1000
        return (m.group(1), i)
    except Exception:
        return None


def extract_call(body):
    m = re.search(r"->\s*0x([0-9A-F]+)", body)
    if not m:
        return None
    return int(m.group(1), 16)


def func_name_at(a):
    try:
        ga = sa(a)
        if ga is None:
            return None
        f = getFunctionAt(ga)
        if f is None:
            return None
        return str(f.getName())
    except Exception:
        return None


def analyze(faddr):
    out = []
    dis = disasm(faddr, MAX_DISASM)
    out.append("DISASM count=%d" % len(dis))

    ldr_by_reg = {}
    ldr_by_off = {}
    qmem = []
    calls = []

    for line in dis:
        r = parse_instr(line)
        if not r:
            continue
        pc, mn, body = r
        e = extract_mem(body)
        if e is not None:
            base, imm = e
            if mn in ("ldr", "ldrb", "ldrh", "ldur"):
                if base not in ldr_by_reg:
                    ldr_by_reg[base] = []
                ldr_by_reg[base].append((pc, imm, mn, body))
                if imm not in ldr_by_off:
                    ldr_by_off[imm] = []
                ldr_by_off[imm].append((pc, base, mn, body))
            if mn in ("ldp", "stp") and "q" in body:
                qmem.append((pc, body))
            if mn == "str" and "q" in body:
                qmem.append((pc, body))
            if mn == "ldr" and "q" in body:
                qmem.append((pc, body))
        if mn in ("b", "bl"):
            t = extract_call(body)
            if t is not None:
                calls.append((pc, mn, t))

    out.append("")
    out.append("FLOW-REG LDRs:")
    for reg in FLOW_REGS:
        if reg in ldr_by_reg:
            for pc, imm, mn, body in ldr_by_reg[reg]:
                out.append("  %016X  %s" % (pc, body))

    out.append("")
    out.append("ALL LDR OFFSETS sorted:")
    for imm in sorted(ldr_by_off.keys()):
        entries = ldr_by_off[imm]
        bases = []
        for pc, base, mn, body in entries:
            if base not in bases:
                bases.append(base)
        bases.sort()
        out.append("  +0x%03X  bases=%s  n=%d" % (imm, ",".join(bases), len(entries)))

    out.append("")
    out.append("Q-REGISTER MEM OPS (candidates for TLV writes):")
    for pc, body in qmem:
        out.append("  %016X  %s" % (pc, body))

    out.append("")
    out.append("CALLS:")
    seen = []
    for pc, mn, t in calls:
        if t in seen:
            continue
        seen.append(t)
        nm = func_name_at(t) or "?"
        out.append("  %016X  %s -> %s  %s" % (pc, mn, fmt(t), nm))

    out.append("")
    out.append("FULL DISASM:")
    for l in dis:
        out.append("  " + l)

    return out, ldr_by_off, qmem, calls


def main():
    print("=== target analysis 0x%X ===" % TARGET)
    t0 = time.time()

    lines = []
    lines.append("=== TARGET ===")
    lines.append("addr = %s" % fmt(TARGET))
    blk = inblk(TARGET)
    lines.append("block = %s" % (blk[2] if blk else "?"))
    lines.append("name = %s" % (func_name_at(TARGET) or "?"))
    lines.append("")

    body, ldr_by_off, qmem, calls = analyze(TARGET)
    for l in body:
        lines.append(l)

    write(lines, {})

    print("[+] done in %.1fs" % (time.time() - t0))


def write(lines, jout):
    try:
        with open(OUT, "w") as fh:
            for l in lines:
                fh.write(l + "\n")
        print("[+] wrote " + OUT)
    except Exception as e:
        print("[-] %s" % str(e))
    try:
        with open(OUT_JSON, "w") as fh:
            fh.write(json.dumps(jout, indent=2, sort_keys=True))
        print("[+] wrote " + OUT_JSON)
    except Exception as e:
        print("[-] %s" % str(e))


try:
    main()
except Exception as e:
    print("[-] FATAL: %s" % str(e))
    traceback.print_exc()
    try:
        with open(OUT, "a") as fh:
            fh.write("FATAL: %s\n" % str(e))
            fh.write(traceback.format_exc())
    except Exception:
        pass