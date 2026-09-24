# -*- coding: utf-8 -*-
# @runtime Jython

import os
import re
import json

try:
    string_types = (str, unicode)
except NameError:
    string_types = (str,)

WORKSPACE    = os.environ.get("GITHUB_WORKSPACE", "/tmp")
SYMBOLS_JSON = os.environ.get("SYMBOLS_JSON", os.path.join(WORKSPACE, "symbols.json"))

OUT_TXT  = os.path.join(WORKSPACE, "nk_kernel_rw.txt")
OUT_H    = os.path.join(WORKSPACE, "offsets.h")
OUT_JSON = os.path.join(WORKSPACE, "offsets.json")

KERNEL_UNSLID_BASE = 0xFFFFFFF007004000
MASK48             = 0x0000FFFFFFFFFFFF
KTEXT_LO           = 0xFFF007004000
KTEXT_HI           = 0xFFF200000000
SYSENT_STRIDE      = 24

_sym_cache        = None
_string_map       = None
_string_list      = None
_syms_index       = None
_IFC              = [None]
_valid_addr_cache = {}


def _to_u(v):
    return int(v) & 0xFFFFFFFFFFFFFFFF


def _parse_addr(v):
    if v is None:
        return None
    try:
        if isinstance(v, (int, long)):
            return _to_u(v)
        if not isinstance(v, string_types):
            return None
        s = v.strip()
        if not s:
            return None
        return _to_u(int(s, 16) if s.startswith(("0x", "0X")) else int(s, 10))
    except Exception:
        return None


def fmt(v):
    return "0x{:016X}".format(v & 0xFFFFFFFFFFFFFFFF)


def to_long(v):
    v = int(v) & 0xFFFFFFFFFFFFFFFF
    if v >= 0x8000000000000000:
        v -= 0x10000000000000000
    return v


def safe_addr(a):
    try:
        return toAddr(to_long(a))
    except Exception:
        return None


def read_u64(a):
    ga = safe_addr(a)
    if ga is None:
        return None
    try:
        return int(currentProgram.getMemory().getLong(ga)) & 0xFFFFFFFFFFFFFFFF
    except Exception:
        return None


def read_u32(a):
    ga = safe_addr(a)
    if ga is None:
        return None
    try:
        return int(currentProgram.getMemory().getInt(ga)) & 0xFFFFFFFF
    except Exception:
        return None


def read_u16(a):
    ga = safe_addr(a)
    if ga is None:
        return None
    try:
        return int(currentProgram.getMemory().getShort(ga)) & 0xFFFF
    except Exception:
        return None


def _validate_addr(addr, expected_type="any"):
    if addr in _valid_addr_cache:
        return _valid_addr_cache[addr]
    result = False
    ga = safe_addr(addr)
    if ga is not None:
        blk = currentProgram.getMemory().getBlock(ga)
        if blk is not None and blk.isInitialized():
            if expected_type == "ktext":
                result = blk.isExecute()
            elif expected_type == "data":
                result = not blk.isExecute()
            else:
                result = True
    _valid_addr_cache[addr] = result
    return result


def _load_symbols():
    global _sym_cache
    if _sym_cache is not None:
        return
    _sym_cache = {}
    if not os.path.exists(SYMBOLS_JSON):
        print("[-] symbols.json not found: " + SYMBOLS_JSON)
        return
    try:
        with open(SYMBOLS_JSON) as f:
            data = json.loads(f.read().strip() or "{}")
    except Exception as e:
        print("[-] symbols.json parse error: " + str(e))
        return

    def _add(name, addr):
        if not name or addr is None:
            return
        if not isinstance(name, string_types):
            name = str(name)
        name = name.strip()
        v = _parse_addr(addr)
        if v is None or v < 0xFFFF000000000000:
            return
        _sym_cache[name] = v
        if not name.startswith("_"):
            _sym_cache["_" + name] = v

    def _walk(node):
        if isinstance(node, dict):
            nm = node.get("name") or node.get("symbol")
            ad = node.get("address") or node.get("addr") or node.get("value")
            if nm and ad is not None:
                _add(nm, ad)
                return
            for k, v in node.items():
                ka = _parse_addr(k)
                va = _parse_addr(v)
                if ka is not None and isinstance(v, string_types) and va is None:
                    _add(v, ka)
                elif va is not None and isinstance(k, string_types) and ka is None:
                    _add(k, va)
                elif isinstance(v, (dict, list)):
                    _walk(v)
        elif isinstance(node, list):
            for it in node:
                _walk(it)

    _walk(data)
    print("[+] symbols loaded: " + str(len(_sym_cache)))


def sym_get(name):
    _load_symbols()
    if name in _sym_cache:
        return _sym_cache[name]
    b = name.lstrip("_")
    if b in _sym_cache:
        return _sym_cache[b]
    if "_" + name in _sym_cache:
        return _sym_cache["_" + name]
    low = name.lower()
    for k, v in _sym_cache.items():
        if k.lower() == low:
            return v
    return None


def _build_strings():
    global _string_map, _string_list
    if _string_map is not None:
        return
    _string_map = {}
    _string_list = []
    listing = currentProgram.getListing()
    it = listing.getDefinedData(True)
    while it.hasNext():
        d = it.next()
        try:
            if not d.hasStringValue():
                continue
            v = d.getValue()
            if v is None:
                continue
            s = str(v)
            a = _to_u(d.getAddress().getOffset())
            _string_list.append((a, s))
            if s not in _string_map:
                _string_map[s] = a
        except Exception:
            pass
    print("[+] strings indexed: " + str(len(_string_list)))


def find_str_exact(s):
    _build_strings()
    return _string_map.get(s)


def _str_addr(s):
    a = find_str_exact(s)
    if a is not None:
        return a
    for a, val in _string_list:
        if s in val:
            return a
    return None


def _build_symidx():
    global _syms_index
    if _syms_index is not None:
        return
    _syms_index = []
    st = currentProgram.getSymbolTable()
    try:
        for sym in st.getAllSymbols(True):
            try:
                _syms_index.append((_to_u(sym.getAddress().getOffset()), sym.getName()))
            except Exception:
                pass
    except Exception:
        pass
    print("[+] symtable indexed: " + str(len(_syms_index)))


def _is_junk(n):
    if n.startswith("s_") and "_" in n[3:]:
        t = n.rsplit("_", 1)[-1]
        try:
            int(t, 16)
            return True
        except Exception:
            pass
    for p in ("DAT_", "LAB_", "UNK_", "SUB_", "OFF_", "ADJ_", "EXTERNAL_"):
        if n.startswith(p):
            return True
    return False


def syms_named(pat):
    _build_symidx()
    out = []
    for a, n in _syms_index:
        if _is_junk(n):
            continue
        if pat in n:
            out.append((a, n))
    return out


def funcs_named(pat):
    _build_symidx()
    out = []
    for a, n in _syms_index:
        if _is_junk(n) or pat not in n:
            continue
        f = func_at(a)
        if f is not None:
            if (int(f.getEntryPoint().getOffset()) & 0xFFFFFFFFFFFFFFFF) == a:
                out.append((a, n))
    return out


def xrefs_to(addr):
    ga = safe_addr(addr)
    if ga is None:
        return []
    out = []
    rm = currentProgram.getReferenceManager()
    try:
        for r in rm.getReferencesTo(ga):
            out.append(_to_u(r.getFromAddress().getOffset()))
    except Exception:
        pass
    return out


def func_at(addr):
    ga = safe_addr(addr)
    if ga is None:
        return None
    try:
        f = getFunctionAt(ga)
        if f:
            return f
    except Exception:
        pass
    try:
        return getFunctionContaining(ga)
    except Exception:
        return None


def ensure_func(addr):
    f = func_at(addr)
    if f:
        return f
    ga = safe_addr(addr)
    if ga is None:
        return None
    try:
        disassemble(ga)
    except Exception:
        pass
    try:
        return createFunction(ga, None)
    except Exception:
        return None


def decompile(f):
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.util.task import ConsoleTaskMonitor
    if f is None:
        return ""
.contains    if _(IFC[0] is None:
        ifc =ins DecompInterface()
       n ifc.setOptions(DecompileOptions.get())
        ifc.openProgram(currentProgram)
        _IFC[0] = ifc
    try:
        r = _IFC[0].decompileFunction(f, 120, ConsoleTaskMonitor())
        if r.decompileCompleted():
            return r.getDecompiledFunction().getC()
    except Exception:
        pass
    return ""


def resolve_adrp_pairs(func, lo=0xFFFFFFF000000000, hi=0xFFFFFFF200000000):
    if func is None:
        return []
    listing = currentProgram.getListing()
    body = func.getBody()
    if body is None:
        return []
    insn = listing.getInstructionAt(body.getMinAddress())
    out = []
    prev = None
    while insn is not None and bodyAddress()):
        mn = insn.getMnemonicString().lower()
        txt = insn.toString()
        if mn == "adrp":
            try:
                toks = txt.replace(",", " ").split()
                page = int(toks[-1], 16) & 0xFFFFFFFFFFFFFFFF
                prev = (toks[1], page)
            except Exception:
                prev = None
        elif prev is not None and mn in ("add", "ldr", "str", "ldrb", "strb",
                                          "ldrh", "strh", "ldrsw", "ldur", "stur",
                                          "ldp", "stp"):
            try:
                toks = txt.replace(",", " ").replace("[", " ").replace("]", " ").split()
                imm = 0
                for t in toks:
                    if t.startswith("#0x"):
                        imm = int(t[3:], 16)
                        break
                base_reg = toks[2] if len(toks) > 2 else ""
                if base_reg == prev[0]:
                    tgt = (prev[1] + imm) & 0xFFFFFFFFFFFFFFFF
                    if lo <= tgt < hi:
                        out.append((_to_u(insn.getAddress().getOffset()), tgt, mn))
            except Exception:
                pass
            prev = None
        else:
            if mn not in ("nop", "bti", "pacibsp", "hint"):
                prev = None
        insn = insn.getNext()
    return out


def write_lines(path, lines):
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        try:
            os.makedirs(d)
        except Exception:
            pass
    with open(path, "w") as fh:
        for l in lines:
            fh.write(l + "\n")


def norm(s):
    return re.sub(r"[^A-Za-z0-9_]", "_", s)


def _is_ktext(p):
    if p is None or p == 0:
        return False
    lo = p & MASK48
    return KTEXT_LO <= lo < KTEXT_HI


def _strip_pac(p):
    return 0xFFFFFFF000000000 | (p & MASK48)


def _is_exec(p):
    ga = safe_addr(_strip_pac(p))
    if ga is None:
        return False
    blk = currentProgram.getMemory().getBlock(ga)
    if blk is None:
        return False
    try:
        return blk.isExecute()
    except Exception:
        return False


def _decode_sysent_ptr(raw):
    if raw is None:
        return None
    if raw >= 0xFFFF000000000000:
        return _strip_pac(raw)
    low = raw & 0xFFFFFFFF
    if low < 0x10000000:
        return (KERNEL_UNSLID_BASE + low) & 0xFFFFFFFFFFFFFFFF
    return None


def _sysent_entry(base, i):
    a = base + i * SYSENT_STRIDE
    raw_call = read_u64(a)
    if raw_call is None:
        return None
    call = _decode_sysent_ptr(raw_call)
    if call is None or call == 0:
        return None
    if not _is_ktext(call) or not _is_exec(call):
        return None
    ret_type  = read_u32(a + 16)
    narg      = read_u16(a + 20)
    arg_bytes = read_u16(a + 22)
    if ret_type is None or ret_type > 9:
        return None
    if narg is None or narg > 12:
        return None
    if arg_bytes is None or arg_bytes > 96:
        return None
    return (call, narg, ret_type, arg_bytes)


def _score_sysent(base, sample=80):
    hits = 0
    for i in range(sample):
        e = _sysent_entry(base, i)
        if e is not None:
            call, narg, rt, ab = e
            if narg > 0 or rt > 0 or ab > 0:
                hits += 2
            else:
                hits += 1
    return hits


def _find_sysent():
    for nm in ("_sysent", "sysent", "_unix_sysent", "unix_sysent"):
        a = sym_get(nm)
        if a and _score_sysent(a) > 40:
            return a, "sym:" + nm

    for a, n in funcs_named("unix_syscall"):
        f = ensure_func(a)
        if f is None:
            continue
        for _, tgt, _ in resolve_adrp_pairs(f):
            if _score_sysent(tgt) > 60:
                return tgt, n + "_adrp"

    mem = currentProgram.getMemory()
    blocks = []
    for b in mem.getBlocks():
        if not b.isInitialized():
            continue
        s = _to_u(b.getStart().getOffset())
        if not (0xFFFFFFF000000000 <= s < 0xFFFFFFF200000000):
            continue
        n = b.getName()
        if "DATA_CONST" in n:
            prio = 0
        elif n.startswith("__const"):
            prio = 1
        elif "DATA" in n:
            prio = 2
        else:
            continue
        blocks.append((prio, b))

    best    = None
    best_sc = 0
    best_src = ""
    blocks.sort(key=lambda x: x[0])
    for _, b in blocks:
        s = _to_u(b.getStart().getOffset())
        e = _to_u(b.getEnd().getOffset())
        if e - s < SYSENT_STRIDE * 200:
            continue
        a = s + ((-s) % 8)
        max_a = e - SYSENT_STRIDE * 200
        while a < max_a:
            sc = _score_sysent(a)
            if sc > best_sc:
                best_sc  = sc
                best     = a
                best_src = "scan:" + b.getName()
            a += 8

    if best is not None and best_sc > 60:
        return best, best_src
    return None, "NOT_FOUND"


def _find_mach_traps():
    for nm in ("_mach_trap_table", "mach_trap_table"):
        a = sym_get(nm)
        if a:
            return a, "sym:" + nm
    for a, n in syms_named("mach_trap"):
        if 0xFFFFFFF000000000 <= a < 0xFFFFFFF200000000:
            return a, "ghidra:" + n
    for a, n in funcs_named("mach_call_munger"):
        f = ensure_func(a)
        if f is None:
            continue
        for _, tgt, _ in resolve_adrp_pairs(f):
            if 0xFFFFFFF000000000 <= tgt < 0xFFFFFFF200000000:
                return tgt, n + "_adrp"
    return None, "NOT_FOUND"


ACCESSOR_SPECS = {
    "task_bsd_info":   ["_get_bsdtask_info", "task_bsd_info", "get_bsdtask_info"],
    "task_vm_map":     ["_task_vm_map", "task_vm_map", "get_task_map", "_get_task_map"],
    "task_itk_self":   ["_task_get_itk_self", "task_get_itk_self"],
    "task_itk_space":  ["_task_get_itk_space", "task_get_itk_space"],
    "task_thread":     ["_task_thread", "task_thread", "get_task_thread"],
    "task_proc":       ["_get_task_proc", "task_get_proc"],
    "task_t_flags":    ["_task_get_t_flags", "task_get_t_flags"],
    "proc_task":       ["_proc_task", "proc_task"],
    "proc_pid":        ["_proc_pid", "proc_pid"],
    "proc_ucred":      ["_proc_ucred", "proc_ucred"],
    "proc_ppid":       ["_proc_ppid", "proc_ppid"],
    "proc_textvp":     ["_proc_textvp", "proc_textvp"],
    "proc_fd":         ["_proc_fd", "proc_fd"],
    "proc_flag":       ["_proc_flag", "proc_flag"],
    "proc_pptr":       ["_proc_pptr", "proc_pptr"],
    "proc_pgrp":       ["_proc_pgrp", "proc_pgrp"],
    "proc_ro":         ["_proc_ro", "proc_ro"],
    "kauth_cred_uid":    ["_kauth_cred_getuid", "kauth_cred_getuid"],
    "kauth_cred_ruid":   ["_kauth_cred_getruid", "kauth_cred_getruid"],
    "kauth_cred_svuid":  ["_kauth_cred_getsvuid", "kauth_cred_getsvuid"],
    "kauth_cred_gid":    ["_kauth_cred_getgid", "kauth_cred_getgid"],
    "kauth_cred_rgid":   ["_kauth_cred_getrgid", "kauth_cred_getrgid"],
    "kauth_cred_svgid":  ["_kauth_cred_getsvgid", "kauth_cred_getsvgid"],
    "kauth_cred_label":  ["_kauth_cred_getlabel", "kauth_cred_getlabel",
                          "_kauth_cred_get_label"],
    "ipc_port_kobject":   ["_ipc_port_get_kobject", "ipc_port_get_kobject"],
    "ipc_port_receiver":  ["_ipc_port_get_receiver", "ipc_port_get_receiver"],
    "ipc_port_mscount":   ["_ipc_port_get_mscount", "ipc_port_get_mscount"],
    "ipc_space_is_table": ["_ipc_space_get_table", "ipc_space_get_table"],
    "vme_start":     ["_vm_map_entry_get_start", "vm_map_entry_get_start"],
    "vme_end":       ["_vm_map_entry_get_end", "vm_map_entry_get_end"],
    "vme_object":    ["_vm_map_entry_get_object", "vm_map_entry_get_object"],
    "vme_offset":    ["_vm_map_entry_get_offset", "vm_map_entry_get_offset"],
    "fd_ofiles":     ["_fdp_get_ofiles", "fdp_get_ofiles"],
    "fileproc_fg":   ["_fp_get_fg", "fp_get_fg"],
    "fileproc_fglob": ["_fp_get_fglob", "fp_get_fglob"],
    "vnode_data":    ["_vnode_get_data", "vnode_get_data"],
    "socket_so_proto":   ["_so_get_proto", "so_get_proto"],
    "inpcb_inp_socket":  ["_inp_get_socket", "inp_get_socket"],
    "inpcb_inp_list":    ["_inp_get_list", "inp_get_list"],
}


def _extract_field_offset(code, field_var=None):
    pats = []
    if field_var:
        pats.append(r"\*\([^)]*\*\)\s*\(\s*" + re.escape(field_var) +
                    r"\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)")
    pats.append(r"\*\([^)]*\*\)\s*\(\s*\w+\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)")
    pats.append(r"return\s+\*\([^)]*\)\s*\(\s*\w+\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)")
    pats.append(r"\(\s*\w+\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)")
    for p in pats:
        for m in re.finditer(p, code):
            off = int(m.group(1), 0)
            if 0 < off < 0x2000:
                return off
    return None


def _collect_struct_offsets():
    struct_offsets = {}
    for field, names in ACCESSOR_SPECS.items():
        for name in names:
            hits = syms_named(name)
            if not hits:
                continue
            a, n = hits[0]
            f = ensure_func(a)
            if f is None:
                continue
            code = decompile(f)
            if not code:
                continue
            off = _extract_field_offset(code)
            if off is not None:
                struct_offsets[field] = off
                break
    return struct_offsets


def _collect_syscall_offsets(sysent_entries):
    offsets = {}
    fields = [
        ("proc_p_pid",   r"p_pid",       0x68),
        ("proc_p_ppid",  r"p_ppid",      0x70),
        ("proc_p_ucred", r"p_ucred",     0x100),
        ("proc_p_fd",    r"p_fd",        0x20),
        ("task_bsd_info", r"bsd_info",   0x3a0),
    ]
    for i, h, narg, rt, ab, name in sysent_entries[:200]:
        if h is None or name.startswith("FUN_") or name == "?":
            continue
        f = ensure_func(h)
        if f is None:
            continue
        code = decompile(f)
        if not code:
            continue
        for fname, marker, guess in fields:
            if fname in offsets:
                continue
            m = re.search(r"\*\([^)]*\*\)\s*\(\s*" + marker + r"\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)", code)
            if m:
                off = int(m.group(1), 0)
                if 0 < off < 0x2000:
                    offsets[fname] = off
    return offsets


XNU_KNOWN_OFFSETS = {
    "proc_p_pid":    0x68,
    "proc_p_ppid":   0x70,
    "proc_p_ucred":  0x100,
    "task_bsd_info": 0x3A0,
    "task_vm_map":   0x28,
    "ipc_port_kobject": 0x48,
    "kauth_cred_uid":   0x18,
    "kauth_cred_gid":   0x1C,
}


def _validate_with_xnu(field, offset):
    if field in XNU_KNOWN_OFFSETS:
        known = XNU_KNOWN_OFFSETS[field]
        if offset != known:
            print("[!] {} mismatch: got 0x{:x}, xnu says 0x{:x}".format(
                field, offset, known))
            return False
    return True


def _find_ctrr_patches():
    patches = []
    anchors = {
        "ctrr_lock_boot":              ["ctrr_lock_boot", "CTRR lockdown"],
        "cpu_lock_system_registers":   ["cpu_lock_system_registers"],
        "sptm_determine_kernel_ctrr":  ["sptm_determine_kernel_ctrr",
                                        "determine_kernel_ctrr"],
    }
    for label, strs in anchors.items():
        for s in strs:
            sa = _str_addr(s)
            if sa is None:
                continue
            for xr in xrefs_to(sa):
                f = func_at(xr)
                if f is None:
                    continue
                ep = _to_u(f.getEntryPoint().getOffset())
                if _validate_addr(ep, "ktext"):
                    patches.append((label, ep))
                    break
    return patches


def _find_iokit():
    table = {
        "IOUserClient_externalMethod":      ["externalMethod"],
        "IOUserClient2022_extMethod":       ["wrong externalMethod for IOUserClient2022"],
        "IOUserClientKernelCompletion":     ["OSAction_IOUserClient_KernelCompletion"],
        "IOConnectCallMethod":              ["IOConnectCallMethod"],
        "IOServiceOpen":                    ["IOServiceOpen"],
        "AppleKeyStore":                    ["AppleKeyStore"],
        "IOSurfaceRoot":                    ["IOSurfaceRoot"],
        "I =OMobileFramebuffer":              ["IOMobileFramebuffer"],
        "AppleMobileFileIntegrity":         ["AppleMobileFileIntegrity"],
        "AppleSEPManager":                  ["AppleSEPManager"],
        "AppleAPFSContainer":               ["AppleAPFSContainer"],
        "IOHIDEventService":                ["IOHIDEventService"],
        "IOHIDSystem":                      ["IOHIDSystem"],
        "IOGraphicsAccelerator2":           ["IOGraphicsAccelerator2"],
        "IOAESAccelerator":                 ["IOAESAccelerator"],
        "AGXCommandQueue":                  ["AGXCommandQueue"],
        "AppleCLCD2":                       ["AppleCLCD2"],
        "AppleS8000AESAccelerator":         ["AppleS8000AESAccelerator"],
        "IOSurfaceMemory":                  ["IOSurfaceMemory"],
        "AppleSMC":                         ["AppleSMC"],
        "AppleEffaceableStorage":           ["AppleEffaceableStorage"],
        "AppleActuatorDevice":              ["AppleActuatorDevice"],
    }
    out = {}
    for label, needles in table.items():
        for needle in needles:
            sa = _str_addr(needle)
            if sa is None:
                continue
            for xr in xrefs_to(sa):
                f = func_at(xr)
                if f:
                    out.setdefault int(label, set()).add(
                        _to_u(f(current.getEntryPoint().getOffset()))
    return out


def main():
    print("=== kernel_rw.py ===")
    print("[*] program: " + currentProgram.getName())

    _load_symbols()
    _build_strings()

    report = []
    hdr    = []
    jout   = {}

    img_baseProgram.getImageBase().getOffset()) & 0xFFFFFFFFFFFFFFFF

    report.append("=== [1] KERNEL BASE ===")
    report.append("image_base  = " + fmt(img_base))
    report.append("unslid_base = " + fmt(KERNEL_UNSLID_BASE))
    _vks = sym_get("_vm_kernel_slide")
    report.append("_vm_kernel_slide = " + (fmt(_vks) if _vks else "runtime-only"))
    hdr.append("#define NK_KERNEL_UNSLID_BASE   " + fmt(KERNEL_UNSLID_BASE) + "ULL")
    hdr.append("#define NK_IMAGE_BASE           " + fmt(img_base) + "ULL")
    hdr.append("")
    jout["kernel_base"] = fmt(KERNEL_UNSLID_BASE)
    jout["image_base"]  = fmt(img_base)

    print("[*] sysent discovery...")
    sysent_base, sysent_src = _find_sysent()
    sysent_entries = _walk_sysent(sysent_base) if sysent_base else []
    print("[+] sysent: {} ({} entries)".format(sysent_src, len(sysent_entries)))
    report.append("")
    report.append("=== [2] SYSENT ===")
    report.append("source  = " + sysent_src)
    report.append("base    = " + (fmt(sysent_base) if sysent_base else "n/a"))
    report.append("entries = " + str(len(sysent_entries)))
    hdr.append("// SYSENT")
    if sysent_base:
        hdr.append("#define NK_SYSENT_BASE          " + fmt(sysent_base) + "ULL")
        hdr.append("#define NK_SYSENT_ENTRY_SZ      " + str(SYSENT_STRIDE))
        hdr.append("#define NK_SYSENT_COUNT         " + str(len(sysent_entries)))
        for i, h, narg, rt, ab, name in sysent_entries:
            if not h or not name or name in ("?", "NOSYS") \
               or name.startswith("FUN_") or name.startswith("s_"):
                continue
            hdr.append("#define NK_SYSENT_{:<32} {}ULL /* #{} */".format(
                norm(name).upper(), fmt(h), i))
    hdr.append("")
    jout["sysent_base"]  = fmt(sysent_base) if sysent_base else None
    jout["sysent_count"] = len(sysent_entries)
    jout["sysent"] = [{"num": i, "handler": fmt(h) if h else None,
                        "narg": narg, "ret": rt, "arg_bytes": ab, "name": name}
                       for i, h, narg, rt, ab, name in sysent_entries]

    print("[*] mach traps...")
    mt_base, mt_src = _find_mach_traps()
    report.append("")
    report.append("=== [2b] MACH TRAPS ===")
    report.append("source = " + mt_src)
    report.append("base   = " + (fmt(mt_base) if mt_base else "n/a"))
    hdr.append("// MACH TRAPS")
    if mt_base:
        hdr.append("#define NK_MACH_TRAP_TABLE       " + fmt(mt_base) + "ULL")
    hdr.append("")
    jout["mach_trap_table"] = fmt(mt_base) if mt_base else None

    print("[*] CTRR/SPTM patches...")
    ctrr_patches = _find_ctrr_patches()
    report.append("")
    report.append("=== [2c] CTRR/SPTM PATCHES ===")
    for label, ep in ctrr_patches:
        report.append("  {:<30} {}".format(label, fmt(ep)))
    hdr.append("// CTRR/SPTM PATCHES")
    for label, ep in ctrr_patches:
        hdr.append("#define NK_CTRR_{:<33} {}ULL".format(norm(label).upper(), fmt(ep)))
    hdr.append("")
    jout["ctrr_patches"] = {k: fmt(v) for k, v in ctrr_patches}

    print("[*] globals via adrp...")
    ANCHORS = {
        "kernproc":     ["p != kernproc", "soro != NULL || p ==-> kernproc"],
        "allproc":      ["allproc"],
        "initproc":     ["initproc"],
        "kernel_task":  ["kernel_task"],
        "kernel_map":   ["kernel_map"],
        "init_task":    ["init_task"],
        "task_list":    ["task_list"],
        "procs_tree":   ["procs_tree"],
        "vm_kernel_slide": ["vm_kernel_slide"],
        "pmap_kernel":  ["pmap_kernel"],
        "task_init":     ["task_init @%s:%d"],
        "proc_ro":       ["proc_task backref mismatch"],
        "task_map":      ["task->map->pmap"],
        "set_bsdtask":   ["set_bsdtask_info trying to set random bsd_info"],
        "swap_task_map": ["swap_task_map @%s:%d"],
        "zone_require":  ["zone_require failed: address not in a zone"],
        "pmap_ro":       ["pmap_ro_zone_validate_element"],
        "task_for_pid":  ["task_for_pid-allow"],
        "task_reference": ["task_reference"],
        "kauth_cred":    ["kauth_cred_getuid"],
        "kauth_cred_label": ["kauth_cred_label_update"],
        "amfi":          ["AMFI: task_for_pid() not allowed"],
        "csblob":        ["csblob_get_csblob"],
        "trust_cache":   ["AMFI: trust cache"],
        "pmap_cs":       ["pmap_cs_validate"],
        "cs_enforcement": ["cs_enforcement_disable"],
        "sandbox_root":  ["sandbox_kernel_extension"],
        "sb_evaluate":   ["sb_evaluate_internal"],
        "mac_policy":    ["mac_policy_register"],
        "kalloc_type":   ["kalloc.type.var"],
        "zone_map":      ["zone_map"],
        "zone_array":    ["zone_array"],
        "zones_built":   ["zones_built"],
        "vm_map":        ["vm_map_enter"],
        "vm_page":       ["vm_page_alloc"],
        "pv_head":       ["pv_head"],
        "ipc_space":     ["ipc_space_kernel"],
        "ipc_port":      ["ipc_port_alloc_kernel"],
        "ipc_kmsg_zone": ["ipc_kmsg_alloc"],
        "mach_port":     ["mach_port_allocate_full"],
        "vnode":         ["rootvnode"],
        "chroot":        ["chroot"],
        "fdesc":         ["fdesc_zone"],
        "proc_list":     ["proc_list_mlock"],
        "proc_find":     ["proc_find"],
        "iokit":         ["IOCreateReceivePort"],
        "driverkit":     ["DriverKit"],
        "exclave":       ["ExclaveCore"],
        "kernelkit":     ["KernelKit"],
        "swift_runtime": ["Embedded Swift"],
    }
    globals_map = {}
    for label, strs in ANCHORS.items():
        for s in strs:
            sa = _str_addr(s)
            if sa is None:
                continue
            for xr in xrefs_to(sa):
                f = func_at(xr)
                if f is None:
                    continue
                for _, tgt, kind in resolve_adrp_pairs(f):
                    if kind in ("ldr", "ldp"):
                        if _validate_addr(tgt, "any"):
                            globals_map.setdefault(tgt, set()).add(label)
    report.append("")
    report.append("=== [3] GLOBALS ===")
    for k in sorted(globals_map.keys()):
        report.append("  {}  <- {}".format(fmt(k), ",".join(sorted(globals_map[k]))))
    hdr.append("// GLOBALS")
    for k in sorted(globals_map.keys()):
        labels = "_".join(sorted(globals_map[k]))
        hdr.append("#define {:<40} {}ULL".format(
            norm("NK_G_" + labels).upper()[:40], fmt(k)))
    hdr.append("")
    jout["globals"] = {fmt(k): sorted(list(v)) for k, v in globals_map.items()}

    print("[*] struct offsets via accessors...")
    struct_offsets = _collect_struct_offsets()
    for field, off in struct_offsets.items():
        _validate_with_xnu(field, off)
    report.append("")
    report.append("=== [4] STRUCT OFFSETS ===")
    for k, v in sorted(struct_offsets.items()):
        report.append("  {:<25} 0x{:x}".format(k, v))
    hdr.append("// STRUCT OFFSETS")
    for k, v in sorted(struct_offsets.items()):
        hdr.append("#define NK_{:<30} 0x{:x}".format(norm(k).upper(), v))
    hdr.append("")
    jout["struct_offsets"] = struct_offsets

    print("[*] syscall-derived offsets fallback...")
    syscall_offsets = _collect_syscall_offsets(sysent_entries)
    merged = dict(syscall_offsets)
    merged.update(struct_offsets)
    struct_offsets = merged
    report.append("")
    report.append("=== [4b] SYSCALL-DERIVED OFFSETS ===")
    for k, v in sorted(syscall_offsets.items()):
        report.append("  {:<25} 0x{:x}".format(k, v))
    hdr.append("// SYSCALL-DERIVED OFFSETS")
    for k, v in sorted(syscall_offsets.items()):
        if k not in jout.get("struct_offsets", {}):
            hdr.append("#define NK_{:<30} 0x{:x}".format(norm(k).upper(), v))
    hdr.append("")
    jout["syscall_offsets"] = syscall_offsets
    jout["struct_offsets"]  = struct_offsets

    print("[*] kalloc/kfree...")
    kfree_ext   = sym_get("_kfree_ext")
    kalloc_ext  = sym_get("_kalloc_ext")
    kalloc_hint = sym_get("_kalloc_canblock")
    kfree_callers = set()
    if kfree_ext:
        for xr in xrefs_to(kfree_ext):
            f = func_at(xr)
            if f:
                kfree_callers.add(_to_u(f.getEntryPoint().getOffset()))
    report.append("")
    report.append("=== [5] KALLOC/KFREE ===")
    report.append("_kfree_ext      = " + (fmt(kfree_ext) if kfree_ext else "NOT_FOUND"))
    report.append("_kalloc_ext     = " + (fmt(kalloc_ext) if kalloc_ext else "NOT_FOUND"))
    report.append("_kalloc_canblock= " + (fmt(kalloc_hint) if kalloc_hint else "NOT_FOUND"))
    hdr.append("// KALLOC/KFREE")
    if kfree_ext:
        hdr.append("#define NK_KFREE_EXT            " + fmt(kfree_ext) + "ULL")
    if kalloc_ext:
        hdr.append("#define NK_KALLOC_EXT           " + fmt(kalloc_ext) + "ULL")
    if kalloc_hint:
        hdr.append("#define NK_KALLOC_CANBLOCK      " + fmt(kalloc_hint) + "ULL")
    for i, ep in enumerate(sorted(kfree_callers)[:64]):
        hdr.append("#define NK_KFREE_CALLER_{:<27} {}ULL".format(
            norm("{:04X}".format(i)), fmt(ep)))
    hdr.append("")
    jout["kfree_ext"]  = fmt(kfree_ext) if kfree_ext else None
    jout["kalloc_ext"] = fmt(kalloc_ext) if kalloc_ext else None
    jout["kalloc_canblock"] = fmt(kalloc_hint) if kalloc_hint else None

    print("[*] zones...")
    ZSTR = [
        "site.struct task", "site.struct proc", "site.struct thread",
        "site.struct ucred", "site.struct uthread",
        "site.struct ipc_port", "site.struct ipc_space", "site.struct ipc_entry",
        "site.struct ipc_kmsg", "site.struct ipc_object",
        "site.struct vm_map", "site.struct vm_map_entry", "site.struct vm_map_copy",
        "site.struct vm_object", "site.struct vm_page",
        "site.struct fileproc", "site.struct fileglob",
        "site.struct vnode", "site.struct mount",
        "site.struct necp_client_flow_registration", "site.struct necp_fd_data",
        "site.struct necp_session", "site.struct necp_session_policy",
        "site.struct necp_kernel_socket_policy", "site.struct necp_arena_info",
        "site.struct knote", "site.struct pipe",
        "site.struct posix_shm",
        "early.kalloc", "data.kalloc", "kalloc.type.var",
        "site.struct exclave_core",
        "site.struct kernelkit",
    ]
    zones = {}
    for z in ZSTR:
        sa = _str_addr(z)
        if sa is None:
            continue
        kv = [xr for xr in xrefs_to(sa)
              if 0xFFFFFFF000000000 <= xr < 0xFFFFFFF200000000]
        if kv:
            zones[z] = kv
    report.append("")
    report.append("=== [6] ZONES ===")
    for z, kv in sorted(zones.items()):
        for kva in kv:
            report.append("  {}  {}".format(fmt(kva), z))
    hdr.append("// ZONES")
    for z, kv in sorted(zones.items()):
        key = norm(z).upper()[:40]
        for i, kva in enumerate(kv):
            hdr.append("#define {:<40} {}ULL".format(
                key + ("_%d" % i if len(kv) > 1 else ""), fmt(kva)))
    hdr.append("")
    jout["zones"] = {k: [fmt(x) for x in v] for k, v in zones.items()}

    print("[*] copyin/copyout...")
    copy = {}
    for s in ("_copyin", "_copyout", "_copyinstr", "_copyoutstr",
              "_copyin_word", "_copyout_word", "_memmove_phys", "_bcopy",
              "_copyio", "_copyinmsg", "_copyoutmsg",
              "_copyin_atomic32", "_copyout_atomic32"):
        a = sym_get(s)
        if a:
            copy[s] = a
            continue
        hits = funcs_named(s.lstrip("_"))
        if hits:
            copy[s] = hits[0][0]
    for needle, key in (("ipc_object_copyin_from_kernel", "_copyin_hint"),
                        ("ipc_object_copyout_dest",        "_copyout_hint")):
        sa = _str_addr(needle)
        if sa is None:
            continue
        for xr in xrefs_to(sa):
            f = func_at(xr)
            if f:
                ep = _to_u(f.getEntryPoint().getOffset())
                if key not in copy:
                    copy[key] = ep
    report.append("")
    report.append("=== [7] COPYIN/COPYOUT ===")
    for s, a in sorted(copy.items()):
        report.append("  {:<24} {}".format(s, fmt(a)))
    hdr.append("// COPYIN/COPYOUT")
    for s, a in sorted(copy.items()):
        hdr.append("#define NK_{:<36} {}ULL".format(norm(s).upper(), fmt(a)))
    hdr.append("")
    jout["copyin_copyout"] = {k: fmt(v) for k, v in copy.items()}

    print("[*] iokit...")
    iokit = _find_iokit()
    report.append("")
    report.append("=== [8] IOKIT ===")
    for label, eps in sorted(iokit.items()):
        for ep in sorted(eps):
            report.append("  {:<30} {}".format(label, fmt(ep)))
    hdr.append("// IOKIT")
    for label, eps in sorted(iokit.items()):
        key = norm(label).upper()
        for i, ep in enumerate(sorted(eps)):
            hdr.append("#define NK_IOKIT_{:<32} {}ULL".format(
                key + ("_%d" % i if len(eps) > 1 else ""), fmt(ep)))
    hdr.append("")
    jout["iokit"] = {k: [fmt(x) for x in sorted(v)] for k, v in iokit.items()}

    print("[*] sandbox/macf...")
    SBOX = {
        "sb_evaluate":          ["sb_evaluate_internal", "sb_evaluate"],
        "sandbox_check":        ["sandbox_check"],
        "sandbox_extension":    ["sandbox_extension_consume"],
        "mac_policy_register":  ["mac_policy_register"],
        "mac_policy_unregister": ["mac_policy_unregister"],
        "mac_policy_list":      ["mac_policy_list"],
        "sandbox_label":        ["sandbox_label"],
    }
    sbox = {}
    for label, needles in SBOX.items():
        for needle in needles:
            for a, n in funcs_named(needle):
                sbox.setdefault(label, set()).add(a)
            a = sym_get("_" + needle)
            if a:
                sbox.setdefault(label, set()).add(a)
    report.append("")
    report.append("=== [9] SANDBOX / MACF ===")
    for label, eps in sorted(sbox.items()):
        for ep in sorted(eps):
            report.append("  {:<30} {}".format(label, fmt(ep)))
    hdr.append("// SANDBOX / MACF")
    for label, eps in sorted(sbox.items()):
        key = norm(label).upper()
        for i, ep in enumerate(sorted(eps)):
            hdr.append("#define NK_SBOX_{:<33} {}ULL".format(
                key + ("_%d" % i if len(eps) > 1 else ""), fmt(ep)))
    hdr.append("")
    jout["sandbox"] = {k: [fmt(x) for x in sorted(v)] for k, v in sbox.items()}

    print("[*] amfi/cs...")
    AMFI = {
        "amfi_check_dyld_policy":   ["amfi_check_dyld_policy"],
        "amfi_get_out_of_my_way":   ["amfi_get_out_of_my_way"],
        "cs_enforcement_disable":   ["cs_enforcement_disable"],
        "csblob_entitlements":      ["csblob_entitlements"],
        "cs_validate_page":         ["cs_validate_page"],
        "csblob_validate":          ["csblob_validate"],
        "pmap_cs_validate":         ["pmap_cs_validate"],
        "trust_cache_lookup":       ["trust_cache_lookup"],
        "trust_cache_add":          ["trust_cache_add"],
    }
    amfi = {}
    for label, needles in AMFI.items():
        for needle in needles:
            for a, n in funcs_named(needle):
                amfi.setdefault(label, set()).add(a)
            a = sym_get("_" + needle)
            if a:
                amfi.setdefault(label, set()).add(a)
    report.append("")
    report.append("=== [10] AMFI / CS / TRUST CACHE ===")
    for label, eps in sorted(amfi.items()):
        for ep in sorted(eps):
            report.append("  {:<30} {}".format(label, fmt(ep)))
    hdr.append("// AMFI / CS / TRUST CACHE")
    for label, eps in sorted(amfi.items()):
        key = norm(label).upper()
        for i, ep in enumerate(sorted(eps)):
            hdr.append("#define NK_AMFI_{:<33} {}ULL".format(
                key + ("_%d" % i if len(eps) > 1 else ""), fmt(ep)))
    hdr.append("")
    jout["amfi"] = {k: [fmt(x) for x in sorted(v)] for k, v in amfi.items()}

    print("[*] kauth...")
    KAUTH = {
        "kauth_cred_get":       ["kauth_cred_get"],
        "kauth_cred_unref":     ["kauth_cred_unref"],
        "kauth_cred_ref":       ["kauth_cred_ref"],
        "kauth_cred_proc_ref":  ["kauth_cred_proc_ref"],
        "kauth_authorize_action": ["kauth_authorize_action"],
        "suser":                ["suser"],
        "proc_ucred_authorize": ["proc_ucred_authorize"],
    }
    kauth = {}
    for label, needles in KAUTH.items():
        for needle in needles:
            a = sym_get("_" + needle)
            if a:
                kauth.setdefault(label, set()).add(a)
            for a, n in funcs_named(needle):
                kauth.setdefault(label, set()).add(a)
    report.append("")
    report.append("=== [11] KAUTH ===")
    for label, eps in sorted(kauth.items()):
        for ep in sorted(eps):
            report.append("  {:<30} {}".format(label, fmt(ep)))
    hdr.append("// KAUTH")
    for label, eps in sorted(kauth.items()):
        key = norm(label).upper()
        for i, ep in enumerate(sorted(eps)):
            hdr.append("#define NK_KAUTH_{:<32} {}ULL".format(
                key + ("_%d" % i if len(eps) > 1 else ""), fmt(ep)))
    hdr.append("")
    jout["kauth"] = {k: [fmt(x) for x in sorted(v)] for k, v in kauth.items()}

    print("[*] driverkit...")
    DK = {
        "IOService_driverkit":  ["IOService::start"],
        "DriverKit_root":       ["DriverKit"],
        "IOUserServer":         ["IOUserServer"],
    }
    dk = {}
    for label, needles in DK.items():
        for needle in needles:
            sa = _str_addr(needle)
            if sa is None:
                continue
            for xr in xrefs_to(sa):
                f = func_at(xr)
                if f:
                    dk.setdefault(label, set()).add(
                        _to_u(f.getEntryPoint().getOffset()))
    report.append("")
    report.append("=== [12] DRIVERKIT ===")
    for label, eps in sorted(dk.items()):
        for ep in sorted(eps):
            report.append("  {:<30} {}".format(label, fmt(ep)))
    hdr.append("// DRIVERKIT")
    for label, eps in sorted(dk.items()):
        key = norm(label).upper()
        for i, ep in enumerate(sorted(eps)):
            hdr.append("#define NK_DK_{:<34} {}ULL".format(
                key + ("_%d" % i if len(eps) > 1 else ""), fmt(ep)))
    hdr.append("")
    jout["driverkit"] = {k: [fmt(x) for x in sorted(v)] for k, v in dk.items()}

    write_lines(OUT_TXT, report)
    print("[+] wrote " + OUT_TXT)

    header = ["#ifndef NK_OFFSETS_H",
              "#define NK_OFFSETS_H",
              "",
              "// auto-generated by kernel_rw.py",
              "// program: " + currentProgram.getName(),
              ""] + hdr + ["", "#endif /* NK_OFFSETS_H */"]
    write_lines(OUT_H, header)
    print("[+] wrote " + OUT_H)

    try:
        with open(OUT_JSON, "w") as fh:
            fh.write(json.dumps(jout, indent=2, sort_keys=True))
        print("[+] wrote " + OUT_JSON)
    except Exception as e:
        print("[-] json write failed: " + str(e))

    print("")
    print("=============== SUMMARY ===============")
    print("  kernel_base      : " + fmt(KERNEL_UNSLID_BASE))
    print("  sysent_base      : " + (fmt(sysent_base) if sysent_base else "n/a"))
    print("  sysent_entries   : " + str(len(sysent_entries)))
    print("  mach_trap_table  : " + (fmt(mt_base) if mt_base else "n/a"))
    print("  ctrr_patches     : " + str(len(ctrr_patches)))
    print("  globals          : " + str(len(globals_map)))
    print("  struct_offsets   : " + str(len(struct_offsets)))
    print("  kfree callers    : " + str(len(kfree_callers)))
    print("  zones            : " + str(len(zones)))
    print("  copyin/out       : " + str(len(copy)))
    print("  iokit            : " + str(sum(len(v) for v in iokit.values())))
    print("  sandbox          : " + str(sum(len(v) for v in sbox.values())))
    print("  amfi             : " + str(sum(len(v) for v in amfi.values())))
    print("  kauth            : " + str(sum(len(v) for v in kauth.values())))
    print("  driverkit        : " + str(sum(len(v) for v in dk.values())))
    print("=======================================")
    print("[+] kernel_rw.py done")


main()
