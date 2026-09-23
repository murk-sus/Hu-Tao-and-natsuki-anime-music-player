# -*- coding: utf-8 -*-

import os
import re

WORKSPACE = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT_PATH = os.path.join(WORKSPACE, "offsets.txt")
INSTR_LIMIT = 300

TARGET_SYMBOLS = [
    "_allproc",
    "_kernproc",
    "_nprocs",
    "_proc_pid",
    "_proc_task",
    "_proc_ucred",
    "_proc_fd",
    "_proc_textvp",
    "_proc_list_entry",
    "_kauth_cred_getuid",
    "_kauth_cred_getruid",
    "_kauth_cred_getsvuid",
    "_kauth_cred_getgid",
    "_kauth_cred_getrgid",
    "_kauth_cred_getsvgid",
    "_cs_enforcement_disable",
    "_amfi_get_out_of_my_way",
    "_necp_client_action",
    "_necp_client_copy_result",
    "_necp_client_add_flow",
    "_necp_client_remove_flow",
    "_task_for_pid",
    "_task_map",
    "_get_task_ipcspace",
    "_vm_map_pmap",
    "_pmap_enter_options",
    "_vnode_mount",
    "_vnode_data",
    "_vnode_vtype",
    "_fd_ofiles",
    "_fileproc_fglob",
    "_socket_so_rcv",
    "_socket_so_snd",
    "_rootvnode",
    "_kernel_map",
    "_host_priv_self",
]

ANCHOR_STRINGS = [
    "allproc",
    "kernproc",
    "necp_client",
    "cs_enforcement",
    "amfi_get_out_of_my_way",
    "task_for_pid",
    "kern.osversion",
]


def to_unsigned(v):
    return int(v) & 0xFFFFFFFFFFFFFFFF


def to_java_long(v):
    v = int(v) & 0xFFFFFFFFFFFFFFFF
    if v >= 0x8000000000000000:
        v -= 0x10000000000000000
    return int(v)


def fmt_hex(v):
    return "0x{:016X}".format(to_unsigned(v))


def find_symbol_address(name):
    st = currentProgram.getSymbolTable()
    try:
        for sym in st.getSymbols(name):
            return to_unsigned(sym.getAddress().getOffset())
    except Exception:
        pass
    return None


def scan_strings():
    result = {}
    listing = currentProgram.getListing()
    it = listing.getDefinedData(True)
    while it.hasNext():
        d = it.next()
        if d.hasStringValue():
            try:
                val = d.getValue()
                if val is not None:
                    result[str(val)] = to_unsigned(d.getAddress().getOffset())
            except Exception:
                pass
    return result


def find_xrefs_to(addr):
    refs = []
    rm = currentProgram.getReferenceManager()
    try:
        it = rm.getReferencesTo(toAddr(to_java_long(addr)))
        for r in it:
            refs.append(to_unsigned(r.getFromAddress().getOffset()))
    except Exception:
        pass
    return refs


def dump_instructions_from(addr, limit=INSTR_LIMIT):
    lines = []
    try:
        gaddr = toAddr(to_java_long(addr))
    except Exception as exc:
        return ["  ERROR toAddr({}): {}".format(fmt_hex(addr), exc)]
    instr = getInstructionAt(gaddr)
    if instr is None:
        try:
            disassemble(gaddr)
            instr = getInstructionAt(gaddr)
        except Exception:
            pass
    if instr is None:
        return ["  No instruction at {}".format(fmt_hex(addr))]
    count = 0
    while instr is not None and count < limit:
        lines.append("  {}  {}".format(
            fmt_hex(to_unsigned(instr.getAddress().getOffset())), instr))
        instr = instr.getNext()
        count += 1
    return lines


def decompile_function(func):
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.util.task import ConsoleTaskMonitor
    ifc = DecompInterface()
    ifc.setOptions(DecompileOptions())
    ifc.openProgram(currentProgram)
    res = ifc.decompileFunction(func, 60, ConsoleTaskMonitor())
    if not res.decompileCompleted():
        return ""
    return res.getDecompiledFunction().getC()


def extract_field_offsets(code):
    hits = []
    pattern = re.compile(
        r"\((?P<type>[A-Za-z_][A-Za-z0-9_ ]*?)\s*\*\)\s*"
        r"\((?P<var>a1|param_1|arg1)\s*\+\s*"
        r"(?P<off>0x[0-9a-fA-F]+|\d+)\)"
    )
    for m in pattern.finditer(code):
        hits.append((int(m.group("off"), 0), m.group("type").strip()))
    return hits


def disasm_field_load(func):
    listing = currentProgram.getListing()
    body = func.getBody()
    it = listing.getInstructions(body, True)
    while it.hasNext():
        insn = it.next()
        mnem = insn.getMnemonicString()
        if mnem not in ("ldr", "ldrb", "ldrh", "ldrsw", "str", "strb", "strh"):
            continue
        reg = insn.getRegister(0)
        if reg is None:
            continue
        if reg.getName() not in ("x0", "w0", "x1", "w1"):
            continue
        scalars = []
        for i in range(insn.getNumOperands()):
            for obj in insn.getOpObjects(i):
                if hasattr(obj, "getValue"):
                    scalars.append(obj.getValue())
        if scalars:
            off = scalars[-1] & 0xFFFFFFFF
            if 0 < off < 0x2000:
                return off, mnem
    return None, None


def main():
    print("[*] Program: " + currentProgram.getName())
    out = open(OUT_PATH, "w")
    try:
        out.write("=== KERNEL OFFSETS ===\n")
        out.write("Program: {}\n".format(currentProgram.getName()))
        out.write("ImageBase: {}\n\n".format(
            fmt_hex(to_unsigned(currentProgram.getImageBase().getOffset()))))

        out.write("=== SYMBOLS ===\n")
        for name in TARGET_SYMBOLS:
            addr = find_symbol_address(name)
            if addr is not None:
                line = "{:<40} {}".format(name, fmt_hex(addr))
            else:
                line = "{:<40} NOT_FOUND".format(name)
            print(line)
            out.write(line + "\n")
        out.flush()

        out.write("\n=== STRING ANCHORS ===\n")
        strings = scan_strings()
        out.write("total strings: {}\n".format(len(strings)))
        for key in ANCHOR_STRINGS:
            for s, a in strings.items():
                if key in s:
                    out.write("  {:<45} {}\n".format(repr(s[:40]), fmt_hex(a)))
                    for x in find_xrefs_to(a)[:20]:
                        out.write("      xref <- {}\n".format(fmt_hex(x)))
                    break
        out.flush()

        out.write("\n=== ACCESSOR CANDIDATES ===\n")
        fm = currentProgram.getFunctionManager()
        total = 0
        candidates = []
        for f in fm.getFunctions(True):
            total += 1
            body = f.getBody()
            if body.getNumAddresses() > 48:
                continue
            code = decompile_function(f)
            if not code:
                continue
            hits = extract_field_offsets(code)
            if len(hits) == 1 and 0 < hits[0][0] < 0x2000:
                candidates.append(
                    (f.getName(),
                     to_unsigned(f.getEntryPoint().getOffset()),
                     hits[0][0],
                     hits[0][1]))
        out.write("scanned: {}\n".format(total))
        out.write("candidates: {}\n\n".format(len(candidates)))
        for name, addr, off, typ in candidates[:2000]:
            out.write("  {:<40} {}  +0x{:x}  {}\n".format(
                name, fmt_hex(addr), off, typ))
        out.flush()

        manual = os.environ.get("MANUAL_ADDRS", "").split(",")
        if manual:
            out.write("\n=== MANUAL DISASM ===\n")
            for a in manual:
                a = a.strip()
                if not a:
                    continue
                try:
                    addr = int(a, 0)
                except ValueError:
                    continue
                out.write("\n--- {} ---\n".format(fmt_hex(addr)))
                for ln in dump_instructions_from(addr):
                    out.write(ln + "\n")
            out.flush()

        out.write("\n=== DONE ===\n")
    finally:
        out.close()
    print("[*] wrote: " + OUT_PATH)


main()
