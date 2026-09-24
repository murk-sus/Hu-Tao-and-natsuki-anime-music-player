# -*- coding: utf-8 -*-

import os
import re
import json

WORKSPACE = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT_PATH = os.path.join(WORKSPACE, "offsets.txt")
SYMBOLS_JSON = os.path.join(WORKSPACE, "symbols.json")

TARGET_SYMBOLS = [
    "_allproc", "_kernproc", "_nprocs",
    "_proc_pid", "_proc_task", "_proc_ucred", "_proc_fd", "_proc_textvp",
    "_proc_ppid", "_proc_list_entry",
    "_kauth_cred_getuid", "_kauth_cred_getruid", "_kauth_cred_getsvuid",
    "_kauth_cred_getgid", "_kauth_cred_getrgid", "_kauth_cred_getsvgid",
    "_cs_enforcement_disable", "_amfi_get_out_of_my_way",
    "_necp_client_action", "_necp_client_copy_result",
    "_necp_client_add_flow", "_necp_client_remove_flow",
    "_necp_client_copy", "_necp_client_copy_internal",
    "_necp_client_update_cache", "_necp_client_update_flows",
    "_necp_client_acquire_agent_token", "_necp_arena_initialize",
    "_necp_session_action", "_necp_session_add_policy",
    "_task_for_pid", "_task_map", "_get_task_ipcspace",
    "_vm_map_pmap", "_vm_map_lookup_entry", "_pmap_enter_options",
    "_vnode_mount", "_vnode_data", "_vnode_vtype",
    "_fd_ofiles", "_fileproc_fglob",
    "_socket_so_rcv", "_socket_so_snd",
    "_rootvnode", "_kernel_map", "_host_priv_self",
    "_bsd_syscall_table", "_mach_trap_table", "_mig_kern_subsystem",
    "_vm_kernel_slide", "_procs_tree",
    "_kalloc_init", "_kalloc_large",
    "_dlil_ifaddr_bytes", "_route_output", "_rtinit_locked",
    "_pmap_enter_pte", "_pmap_expand",
    "_resolve_kernel_task", "_task_info",
    "_proc_info_internal",
    "_sptm_get_page_table_refcnt",
]

ANCHOR_STRINGS = [
    "allproc", "kernproc",
    "necp_client", "necp_session", "necp_arena",
    "cs_enforcement",
    "task_for_pid", "proc_info",
    "kalloc_type",
    "dlil_ifaddr", "rtm_scrub",
    "vm_kernel_slide",
]

SYSCALL_TABLE_SYMS = ["_bsd_syscall_table", "bsd_syscall_table"]
MACH_TRAP_SYMS = ["_mach_trap_table", "mach_trap_table"]
MIG_SUBSYS_SYMS = ["_mig_kern_subsystem", "mig_kern_subsystem"]


def to_unsigned(v):
    return int(v) & 0xFFFFFFFFFFFFFFFF


def to_java_long(v):
    v = int(v) & 0xFFFFFFFFFFFFFFFF
    if v >= 0x8000000000000000:
        v -= 0x10000000000000000
    return int(v)


def fmt_hex(v):
    return "0x{:016X}".format(to_unsigned(v))


def load_symbols_json():
    result = {}
    candidates = [
        SYMBOLS_JSON,
        "/tmp/symbols.json",
        os.path.expanduser("~/symbols.json"),
        "/home/runner/symbols.json",
    ]

    found = None
    for p in candidates:
        try:
            if os.path.exists(p) and os.path.getsize(p) > 1000:
                found = p
                break
        except Exception:
            continue

    if not found:
        print("[-] symbols.json not found")
        return result

    print("[+] using {}".format(found))
    try:
        with open(found) as f:
            data = json.load(f)
    except Exception as e:
        print("[-] parse fail: {}".format(e))
        return result

    if not isinstance(data, dict):
        return result

    for k, v in data.items():
        try:
            if not isinstance(k, str) or not isinstance(v, str):
                continue
            addr = int(k, 10)
            if addr < 0xfffffff000000000 or addr > 0xffffffffffffffff:
                continue
            name = v.strip()
            if not name or len(name) > 200:
                continue
            if name.startswith("vtable for ") or name.startswith("site.struct "):
                continue
            result[name] = addr & 0xFFFFFFFFFFFFFFFF
            if not name.startswith("_"):
                result["_" + name] = addr & 0xFFFFFFFFFFFFFFFF
        except Exception:
            continue

    print("[+] parsed {} symbols".format(len(result)))
    return result


def find_symbol_address(name, symbols):
    if name in symbols:
        return symbols[name]
    bare = name.lstrip("_")
    if bare in symbols:
        return symbols[bare]
    if "_" + name in symbols:
        return symbols["_" + name]
    lower = name.lower()
    for k, v in symbols.items():
        if k.lower() == lower:
            return v
    for k, v in symbols.items():
        if k.lower().endswith(lower):
            return v
    st = currentProgram.getSymbolTable()
    try:
        for sym in st.getSymbols(name):
            return to_unsigned(sym.getAddress().getOffset())
    except Exception:
        pass
    return None


def read_u64(addr):
    try:
        return to_unsigned(getLong(toAddr(to_java_long(addr))))
    except Exception:
        return None


def read_u32(addr):
    try:
        return to_unsigned(getInt(toAddr(to_java_long(addr))) & 0xFFFFFFFF)
    except Exception:
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
        for r in rm.getReferencesTo(toAddr(to_java_long(addr))):
            refs.append(to_unsigned(r.getFromAddress().getOffset()))
    except Exception:
        pass
    return refs


def dump_instructions_from(addr, limit=100):
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


def parse_table(addr, count, stride=8):
    entries = []
    for i in range(count):
        e = read_u64(addr + i * stride)
        if e is None:
            break
        entries.append(e)
    return entries


def emit_symbol_table(out, symbols, target_list, section_name):
    out.write("\n=== {} ===\n".format(section_name))
    found = 0
    for name in target_list:
        addr = find_symbol_address(name, symbols)
        if addr is not None:
            line = "{:<45} {}".format(name, fmt_hex(addr))
            if name in symbols:
                line += "  (json)"
            found += 1
        else:
            line = "{:<45} NOT_FOUND".format(name)
        out.write(line + "\n")
    out.write("  --- total found: {}/{}\n".format(found, len(target_list)))


def scan_accessor_patterns(out):
    out.write("\n=== ACCESSOR PATTERNS (disasm scan) ===\n")
    fm = currentProgram.getFunctionManager()
    total = 0
    hits = []
    for f in fm.getFunctions(True):
        total += 1
        body = f.getBody()
        if body.getNumAddresses() > 24:
            continue
        entry = to_unsigned(f.getEntryPoint().getOffset())
        instr = getInstructionAt(toAddr(to_java_long(entry)))
        if instr is None:
            continue
        mn = instr.getMnemonicString()
        if mn not in ("ldr", "ldrb", "ldrh"):
            continue
        op = instr.toString()
        if "[x0" not in op and "[w0" not in op:
            continue
        m = re.search(r"#0x([0-9a-fA-F]+)", op)
        if not m:
            continue
        off = int(m.group(1), 16)
        if not (0 < off < 0x2000):
            continue
        nxt = instr.getNext()
        if nxt is None:
            continue
        if nxt.getMnemonicString() != "ret":
            continue
        hits.append((f.getName(), entry, off, mn))

    out.write("scanned funcs: {}\n".format(total))
    out.write("accessor hits: {}\n".format(len(hits)))
    for name, addr, off, mn in hits[:3000]:
        out.write("  {:<40} {}  +0x{:x}  {}\n".format(name, fmt_hex(addr), off, mn))
    out.flush()


def main():
    symbols = load_symbols_json()
    print("[*] Program: " + currentProgram.getName())
    print("[*] Symbols loaded: {}".format(len(symbols)))

    out = open(OUT_PATH, "w")
    try:
        out.write("=== KERNEL OFFSETS REPORT ===\n")
        out.write("Program: {}\n".format(currentProgram.getName()))
        out.write("ImageBase: {}\n".format(
            fmt_hex(to_unsigned(currentProgram.getImageBase().getOffset()))))
        out.write("SymbolsLoaded: {}\n".format(len(symbols)))

        emit_symbol_table(out, symbols, TARGET_SYMBOLS, "SYMBOLS")
        out.flush()

        out.write("\n=== STRING ANCHORS ===\n")
        strings = scan_strings()
        out.write("total strings: {}\n".format(len(strings)))
        for key in ANCHOR_STRINGS:
            hit = False
            for s, a in strings.items():
                if key in s:
                    out.write("  {:<50} {}\n".format(repr(s[:46]), fmt_hex(a)))
                    for x in find_xrefs_to(a)[:20]:
                        out.write("      xref <- {}\n".format(fmt_hex(x)))
                    hit = True
                    break
            if not hit:
                out.write("  {:<50} NOT_FOUND\n".format(key))
        out.flush()

        out.write("\n=== SYSCALL TABLE ===\n")
        for tname in SYSCALL_TABLE_SYMS:
            taddr = find_symbol_address(tname, symbols)
            if taddr is None:
                continue
            out.write("table {} @ {}\n".format(tname, fmt_hex(taddr)))
            entries = parse_table(taddr, 600, 8)
            for idx in (0, 1, 2, 3, 4, 5, 6, 20, 27, 32, 33, 47, 49, 50,
                        65, 66, 97, 116, 128, 144, 147, 149, 154, 170,
                        202, 220, 224, 226, 250, 286, 294, 301, 302, 322,
                        336, 337, 501, 502):
                if idx < len(entries):
                    e = entries[idx]
                    if e != 0:
                        out.write("  sysent[{}] = {}\n".format(idx, fmt_hex(e)))
            break
        out.flush()

        out.write("\n=== MACH TRAP TABLE ===\n")
        for tname in MACH_TRAP_SYMS:
            taddr = find_symbol_address(tname, symbols)
            if taddr is None:
                continue
            out.write("table {} @ {}\n".format(tname, fmt_hex(taddr)))
            entries = parse_table(taddr, 128, 8)
            for idx in range(min(64, len(entries))):
                e = entries[idx]
                if e:
                    out.write("  trap[{}] = {}\n".format(idx, fmt_hex(e)))
            break
        out.flush()

        out.write("\n=== MIG SUBSYSTEM ===\n")
        for tname in MIG_SUBSYS_SYMS:
            taddr = find_symbol_address(tname, symbols)
            if taddr is None:
                continue
            out.write("subsystem {} @ {}\n".format(tname, fmt_hex(taddr)))
            maxsize = read_u32(taddr + 0x00)
            count = read_u32(taddr + 0x20)
            if maxsize is not None:
                out.write("  maxsize = {}\n".format(maxsize))
            if count is not None:
                out.write("  routines count = {}\n".format(count))
                routines_table = read_u64(taddr + 0x28)
                if routines_table:
                    out.write("  routines @ {}\n".format(fmt_hex(routines_table)))
                    for i in range(min(count, 32)):
                        r = read_u64(routines_table + i * 0x18)
                        if r:
                            out.write("    routine[{}] = {}\n".format(i, fmt_hex(r)))
            break
        out.flush()

        scan_accessor_patterns(out)

        out.write("\n=== ANCHOR XREF DISASM ===\n")
        for key in ("necp_client", "necp_session", "dlil_ifaddr",
                    "allproc", "proc_info"):
            for s, a in strings.items():
                if key in s:
                    for x in find_xrefs_to(a)[:1]:
                        out.write("\n--- xref of {} at {} ---\n".format(key, fmt_hex(x)))
                        for ln in dump_instructions_from(x, limit=60):
                            out.write(ln + "\n")
                    break
        out.flush()

        out.write("\n=== DONE ===\n")
    finally:
        out.close()
    print("[*] wrote: " + OUT_PATH)


main()