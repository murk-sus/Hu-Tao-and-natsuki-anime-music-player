# -*- coding: utf-8 -*-
# Ghidra headless post-script: iOS kernelcache symbol and instruction dump
# Runtime: Jython 2.7 (Ghidra built-in interpreter)
# Invoked by: analyzeHeadless ... -postScript decompile.py -scriptPath <dir>
#
# Globals injected by GhidraScript: currentProgram, toAddr, getInstructionAt

import os

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Base address for offset calculations
BASE = 0xFFFFFFF00710B098

TARGET_SYMBOLS = [
    "_allproc",
    "_kernproc",
    "_cs_enforcement_disable",
    "_amfi_get_out_of_my_way",
    "_necp_client_action",
    "_necp_client_copy_result",
    "_necp_client_add_flow",
    "_necp_client_remove_flow",
    "_proc_ucred",
    "_proc_pid",
    "_kauth_cred_getuid",
    "_task_for_pid",
]

# Addresses to disassemble (unsigned 64-bit Python longs)
TARGET_FUNCS = [
    0xFFFFFFF0070D2AC4,
    0xFFFFFFF0070951D9,
]

INSTR_LIMIT = 200

# ---------------------------------------------------------------------------
# 64-bit signed/unsigned conversion
#
# Ghidra Address.getOffset() returns a Java long (signed 64-bit).
# Kernel virtual addresses like 0xFFFFFFF0... exceed Long.MAX_VALUE, so they
# arrive in Python as negative integers.  Conversely, toAddr(long) expects a
# signed Java long; passing an unsigned Python long > Long.MAX_VALUE raises an
# overflow in Jython.  These two helpers bridge the gap.
# ---------------------------------------------------------------------------

def to_java_long(v):
    """Unsigned Python 64-bit int -> signed Java long (same bit pattern)."""
    v = int(v) & 0xFFFFFFFFFFFFFFFF
    if v >= 0x8000000000000000:
        v = v - 0x10000000000000000
    return int(v)

def to_unsigned(v):
    """Signed Java long -> unsigned Python 64-bit int (same bit pattern)."""
    return int(v) & 0xFFFFFFFFFFFFFFFF

def fmt_delta(delta):
    """Format a signed offset relative to BASE."""
    if delta < 0:
        return "base-0x{:X}".format(-delta)
    return "base+0x{:X}".format(delta)

# ---------------------------------------------------------------------------
# Symbol lookup
# ---------------------------------------------------------------------------

def get_symbol_address(name):
    """
    Return the unsigned 64-bit address of the first symbol named 'name',
    or None if not found.  Does not raise on lookup failure.
    """
    try:
        st = currentProgram.getSymbolTable()
        for sym in st.getSymbols(name):
            return to_unsigned(sym.getAddress().getOffset())
        return None
    except Exception as exc:
        print("WARN: lookup '{}' raised: {}".format(name, exc))
        return None

# ---------------------------------------------------------------------------
# Instruction dump
# ---------------------------------------------------------------------------

def dump_instructions(func_addr_unsigned, out_file):
    """
    Walk up to INSTR_LIMIT instructions from func_addr_unsigned using
    getInstructionAt() + Instruction.getNext().  Writes each instruction to
    out_file and mirrors to stdout for live CI log visibility.
    Falls back gracefully if the address is not analysed or out of range.
    """
    try:
        ghidra_addr = toAddr(to_java_long(func_addr_unsigned))
    except Exception as exc:
        msg = "  ERROR toAddr(0x{:016X}): {}".format(func_addr_unsigned, exc)
        print(msg)
        out_file.write(msg + "\n")
        out_file.flush()
        return

    instr = getInstructionAt(ghidra_addr)
    if instr is None:
        msg = ("  No instruction at 0x{:016X}"
               " (address not analysed or not a code location)").format(func_addr_unsigned)
        print(msg)
        out_file.write(msg + "\n")
        out_file.flush()
        return

    count = 0
    while instr is not None and count < INSTR_LIMIT:
        instr_addr = to_unsigned(instr.getAddress().getOffset())
        line = "  {:016X}  {}".format(instr_addr, instr)
        out_file.write(line + "\n")
        out_file.flush()
        print(line)
        instr = instr.getNext()
        count += 1

    note = "  [+] {} instruction(s) written".format(count)
    print(note)
    out_file.write(note + "\n")
    out_file.flush()

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    workspace = os.environ.get("GITHUB_WORKSPACE", "/tmp")
    out_path = os.path.join(workspace, "offsets.txt")

    print("[*] Program   : " + currentProgram.getName())
    print("[*] Output    : " + out_path)

    out = open(out_path, "w")
    try:
        # --- Symbol section ---
        out.write("=== SYMBOLS ===\n")
        out.write("BASE : 0x{:016X}\n".format(BASE))
        out.write("Image: {}\n\n".format(currentProgram.getName()))
        out.flush()

        for sym_name in TARGET_SYMBOLS:
            addr = get_symbol_address(sym_name)
            if addr is None:
                line = "{:<38} NOT_FOUND".format(sym_name)
            else:
                delta = addr - BASE
                line = "{:<38} 0x{:016X}  ({})".format(sym_name, addr, fmt_delta(delta))
            print(line)
            out.write(line + "\n")
            out.flush()

        # --- Disassembly section ---
        out.write("\n=== DISASSEMBLY (first {} instructions per function) ===\n".format(
            INSTR_LIMIT))
        out.flush()

        for func_addr in TARGET_FUNCS:
            header = "\n--- 0x{:016X} ---".format(func_addr)
            print(header)
            out.write(header + "\n")
            out.flush()
            dump_instructions(func_addr, out)

        out.write("\n=== DONE ===\n")
        out.flush()

    finally:
        out.close()

    print("[*] Script complete -> " + out_path)

main()
