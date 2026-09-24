# -*- coding: utf-8 -*-
# @runtime Jython

import os
import re
import json
import traceback

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

CONFIRMED = {
    "sysent_base":     "0xFFFFFFF007C192A0",
    "mach_trap_table": "0xFFFFFFF007BE8018",
    "kfree_ext":       "0xFFFFFFF00A201000",
    "kalloc_ext":      "0xFFFFFFF00A200DCC",
    "copyin":          "0xFFFFFFF00A7B9570",
    "copyout":         "0xFFFFFFF00A2C6C28",
    "proc_pid":        0x74,
    "task_thread":     0x50,
    "ctrr_lock_boot":  "0xFFFFFFF027006E62",
    "cpu_lock_sysreg": "0xFFFFFFF0270B39B4",
    "sptm_base":       "0xFFFFFFF027004000",
}

STRUCT_RANGES = {
    "proc_task":      (0x08, 0x80),
    "proc_ucred":     (0x80, 0x180),
    "proc_fd":        (0x18, 0x80),
    "proc_pptr":      (0x08, 0x80),
    "proc_pgrp":      (0x08, 0x80),
    "proc_ro":        (0x08, 0x80),
    "proc_pid":       (0x40, 0x120),
    "proc_ppid":      (0x40, 0x120),
    "proc_flag":      (0x08, 0x80),
    "proc_textvp":    (0x08, 0x100),
    "task_bsd_info":  (0x300, 0x420),
    "task_vm_map":    (0x18, 0x60),
    "task_itk_self":  (0x280, 0x3A0),
    "task_itk_space": (0x280, 0x3A0),
    "task_thread":    (0x40, 0x80),
    "task_proc":      (0x380, 0x420),
    "task_ref_count": (0x08, 0x30),
    "task_t_flags":   (0x380, 0x420),
    "ipc_port_kobject": (0x40, 0xA0),
    "ipc_port_receiver": (0x40, 0xA0),
    "ipc_port_mscount": (0x40, 0xA0),
    "ipc_port_refs":  (0x40, 0xA0),
    "ipc_space_is_table": (0x10, 0x40),
    "ipc_space_active": (0x10, 0x40),
    "ipc_entry_size": (0x08, 0x30),
    "kauth_cred_uid":  (0x10, 0x40),
    "kauth_cred_gid":  (0x10, 0x40),
    "kauth_cred_ruid": (0x10, 0x40),
    "kauth_cred_rgid": (0x10, 0x40),
    "kauth_cred_svuid": (0x10, 0x40),
    "kauth_cred_svgid": (0x10, 0x40),
    "kauth_cred_label": (0x80, 0x100),
    "vme_start":      (0x00, 0x30),
    "vme_end":        (0x00, 0x30),
    "vme_object":     (0x40, 0xA0),
    "vme_offset":     (0x40, 0xA0),
    "vm_map_header":  (0x00, 0x30),
    "vm_map_pmap":    (0x30, 0x60),
    "fd_ofiles":      (0x10, 0x80),
    "fileproc_fg":    (0x10, 0x80),
    "fileproc_fglob": (0x10, 0x80),
    "filedesc_fd_cdir": (0x40, 0xA0),
    "vnode_data":     (0x10, 0x80),
    "vnode_v_type":   (0x10, 0x40),
    "socket_so_proto": (0x10, 0x80),
    "socket_so_pcb":  (0x10, 0x80),
    "socket_so_state": (0x80, 0x100),
    "inpcb_inp_socket": (0x10, 0x80),
    "inpcb_inp_list": (0x10, 0x80),
    "inpcb_inp_ppcb": (0x10, 0x80),
    "thread_task":    (0x380, 0x420),
    "thread_uthread": (0x280, 0x3A0),
    "uthread_proc":   (0x10, 0x80),
    "mount_mnt_data": (0x10, 0x100),
}

ACCESSOR_SPECS = {
    "proc_pid":       ["_proc_pid", "proc_pid", "_proc_getpid"],
    "proc_ppid":      ["_proc_ppid", "proc_ppid"],
    "proc_task":      ["_proc_task", "proc_task", "_proc_gettask"],
    "proc_ucred":     ["_proc_ucred", "proc_ucred", "_proc_getucred"],
    "proc_fd":        ["_proc_fd", "proc_fd"],
    "proc_pptr":      ["_proc_pptr", "proc_pptr"],
    "proc_pgrp":      ["_proc_pgrp", "proc_pgrp"],
    "proc_ro":        ["_proc_ro", "proc_ro"],
    "proc_flag":      ["_proc_flag", "proc_flag"],
    "proc_textvp":    ["_proc_textvp", "proc_textvp"],
    "task_bsd_info":  ["_get_bsdtask_info", "task_bsd_info", "get_bsdtask_info", "_task_get_bsd_info"],
    "task_vm_map":    ["_task_vm_map", "task_vm_map", "get_task_map", "_get_task_map", "_task_get_map"],
    "task_itk_self":  ["_task_get_itk_self", "task_get_itk_self"],
    "task_itk_space": ["_task_get_itk_space", "task_get_itk_space"],
    "task_thread":    ["_task_thread", "task_thread", "get_task_thread"],
    "task_proc":      ["_get_task_proc", "task_get_proc"],
    "task_ref_count": ["_task_reference", "task_reference"],
    "task_t_flags":   ["_task_get_t_flags", "task_get_t_flags"],
    "ipc_port_kobject": ["_ipc_port_get_kobject", "ipc_port_get_kobject"],
    "ipc_port_receiver": ["_ipc_port_get_receiver", "ipc_port_get_receiver"],
    "ipc_port_mscount": ["_ipc_port_get_mscount", "ipc_port_get_mscount"],
    "ipc_port_refs":  ["_ipc_port_get_refs", "ipc_port_get_refs"],
    "ipc_space_is_table": ["_ipc_space_get_table", "ipc_space_get_table"],
    "ipc_space_active": ["_ipc_space_get_active", "ipc_space_get_active"],
    "kauth_cred_uid": ["_kauth_cred_getuid", "kauth_cred_getuid"],
    "kauth_cred_gid": ["_kauth_cred_getgid", "kauth_cred_getgid"],
    "kauth_cred_ruid": ["_kauth_cred_getruid", "kauth_cred_getruid"],
    "kauth_cred_rgid": ["_kauth_cred_getrgid", "kauth_cred_getrgid"],
    "kauth_cred_svuid": ["_kauth_cred_getsvuid", "kauth_cred_getsvuid"],
    "kauth_cred_svgid": ["_kauth_cred_getsvgid", "kauth_cred_getsvgid"],
    "kauth_cred_label": ["_kauth_cred_getlabel", "kauth_cred_getlabel"],
    "vme_start":      ["_vm_map_entry_get_start", "vm_map_entry_get_start"],
    "vme_end":        ["_vm_map_entry_get_end", "vm_map_entry_get_end"],
    "vme_object":     ["_vm_map_entry_get_object", "vm_map_entry_get_object"],
    "vme_offset":     ["_vm_map_entry_get_offset", "vm_map_entry_get_offset"],
    "fd_ofiles":      ["_fdp_get_ofiles", "fdp_get_ofiles"],
    "fileproc_fg":    ["_fp_get_fg", "fp_get_fg"],
    "fileproc_fglob": ["_fp_get_fglob", "fp_get_fglob"],
    "filedesc_fd_cdir": ["_fdp_get_cdir", "fdp_get_cdir"],
    "vnode_data":     ["_vnode_get_data", "vnode_get_data"],
    "vnode_v_type":   ["_vnode_get_type", "vnode_get_type"],
    "socket_so_proto": ["_so_get_proto", "so_get_proto"],
    "socket_so_pcb":  ["_so_get_pcb", "so_get_pcb"],
    "inpcb_inp_socket": ["_inp_get_socket", "inp_get_socket"],
    "inpcb_inp_list": ["_inp_get_list", "inp_get_list"],
    "inpcb_inp_ppcb": ["_inp_get_ppcb", "inp_get_ppcb"],
    "thread_task":    ["_thread_get_task", "thread_get_task"],
    "uthread_proc":   ["_uthread_get_proc", "uthread_get_proc"],
    "mount_mnt_data": ["_mount_get_data", "mount_get_data"],
}

GLOBAL_ANCHORS = {
    "kernproc":          ["p != kernproc", "so != NULL || p == kernproc"],
    "allproc":           ["allproc"],
    "initproc":          ["initproc"],
    "kernel_task":       ["kernel_task"],
    "kernel_map":        ["kernel_map"],
    "init_task":         ["init_task"],
    "task_list":         ["task_list"],
    "zone_map":          ["zone_map"],
    "zones_built":       ["zones_built"],
    "ipc_space_kernel":  ["ipc_space_kernel"],
    "ipc_space_launchd": ["ipc_space_launchd"],
    "ipc_kmsg_zone":     ["ipc_kmsg_alloc"],
    "mach_port_zone":    ["mach_port_allocate_full"],
    "vm_map_kernel":     ["vm_map_enter"],
    "vm_page_alloc":     ["vm_page_alloc"],
    "vm_object_zone":    ["vm_object_allocate"],
    "task_init":         ["task_init @%s:%d"],
    "proc_find":         ["proc_find"],
    "proc_list":         ["proc_list_mlock"],
    "pmap_kernel":       ["pmap_kernel"],
    "pmap_ro_zone":      ["pmap_ro_zone_validate_element"],
    "zone_require":      ["zone_require failed: address not in a zone"],
    "set_bsdtask":       ["set_bsdtask_info trying to set random bsd_info"],
    "swap_task_map":     ["swap_task_map @%s:%d"],
    "task_for_pid":      ["task_for_pid-allow"],
    "task_reference":    ["task_reference"],
    "kauth_cred":        ["kauth_cred_getuid"],
    "amfi":              ["AMFI: task_for_pid() not allowed"],
    "csblob":            ["csblob_get_csblob"],
    "trust_cache":       ["AMFI: trust cache"],
    "pmap_cs":           ["pmap_cs_validate"],
    "cs_enforcement":    ["cs_enforcement_disable"],
    "sandbox_root":      ["sandbox_kernel_extension"],
    "sb_evaluate":       ["sb_evaluate_internal"],
    "mac_policy":        ["mac_policy_register"],
    "kalloc_type":       ["kalloc.type.var"],
    "chroot":            ["chroot"],
    "fdesc":             ["fdesc_zone"],
    "rootvnode":         ["rootvnode"],
    "selinux":           ["selinux"],
}

KALLOC_ZONES = [
    "kalloc.type.var",
    "data.kalloc",
    "early.kalloc",
    "site.struct task",
    "site.struct proc",
    "site.struct thread",
    "site.struct uthread",
    "site.struct ucred",
    "site.struct ipc_port",
    "site.struct ipc_space",
    "site.struct ipc_entry",
    "site.struct ipc_kmsg",
    "site.struct ipc_object",
    "site.struct ipc_voucher",
    "site.struct vm_map",
    "site.struct vm_map_entry",
    "site.struct vm_map_copy",
    "site.struct vm_object",
    "site.struct vm_page",
    "site.struct fileproc",
    "site.struct fileglob",
    "site.struct filedesc",
    "site.struct vnode",
    "site.struct mount",
    "site.struct socket",
    "site.struct inpcb",
    "site.struct pipe",
    "site.struct knote",
    "site.struct posix_shm",
    "site.struct necp_client_flow_registration",
    "site.struct necp_fd_data",
    "site.struct necp_session",
    "site.struct necp_session_policy",
    "site.struct necp_kernel_socket_policy",
    "site.struct necp_arena_info",
]

PRIMITIVE_FUNCS = [
    "_copyin", "_copyout", "_copyinstr", "_copyoutstr",
    "_copyin_word", "_copyout_word", "_copyio",
    "_copyinmsg", "_copyoutmsg",
    "_copyin_atomic32", "_copyout_atomic32",
    "_memmove_phys", "_bcopy",
    "_kalloc_ext", "_kfree_ext", "_kalloc_canblock",
    "_kernel_memory_allocate", "_kmem_alloc", "_kmem_free",
    "_pmap_enter", "_pmap_remove",
    "_vm_map_enter", "_vm_map_remove",
    "_ipc_port_alloc", "_ipc_port_dealloc", "_ipc_port_copyout",
    "_ipc_space_alloc", "_ipc_space_dealloc",
    "_mach_port_allocate", "_mach_port_deallocate",
    "_task_reference", "_task_deallocate",
    "_proc_reference", "_proc_rele",
    "_thread_reference",
    "_zone_alloc", "_zone_free",
    "_page_alloc", "_page_free",
]

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
    if v is None:
        return "0x0"
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
    if a is None:
        return None
    ga = safe_addr(a)
    if ga is None:
        return None
    try:
        return int(currentProgram.getMemory().getLong(ga)) & 0xFFFFFFFFFFFFFFFF
    except Exception:
        return None

def read_u32(a):
    if a is None:
        return None
    ga = safe_addr(a)
    if ga is None:
        return None
    try:
        return int(currentProgram.getMemory().getInt(ga)) & 0xFFFFFFFF
    except Exception:
        return None

def read_u16(a):
    if a is None:
        return None
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
    if addr is not None:
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

def _is_data_ptr(p):
    if p is None or p == 0:
        return False
    ga = safe_addr(p)
    if ga is None:
        return False
    blk = currentProgram.getMemory().getBlock(ga)
    if blk is None or not blk.isInitialized():
        return False
    try:
        return not blk.isExecute()
    except Exception:
        return False

def _is_ktext(p):
    if p is None or p == 0:
        return False
    lo = p & MASK48
    return KTEXT_LO <= lo < KTEXT_HI

def _strip_pac(p):
    return 0xFFFFFFF000000000 | (p & MASK48)

def _is_exec(p):
    if p is None:
        return False
    ga = safe_addr(_strip_pac(p))
    if ga is None:
        return False
    blk = currentProgram.getMemory().getBlock(ga)
    if blk is None:
        return False
    try:
        return blk.isExecute()
    except Exception:
        v return False

def _load_symbols():

    global _sym           _cache
    if _ ifsym_cache is not None:
        return not
    _sym_cache = {}
    if not os.path.exists(SYMBOLS_JSON):
        return
    try:
        with open(SYMBOLS_JSON) as f:
            data = json.loads(f.read().strip() or "{}")
    except Exception:
        return

    def _add(name, addr):
        if not name or addr is None:
            return
        try:
            if not isinstance(name, string_types):
                name = str(name)
            name = name.strip()
            v = _parse_addr(addr)
            if v is None or v < 0xFFFF000000000000:
                return
            _sym_cache[name] = name.startswith("_"):
                _sym_cache["_" + name] = v
        except Exception:
            pass

    def _walk(node):
        try:
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
        except Exception:
            pass

    _walk(data)
    print("[+] symbols loaded: {}".format(len(_sym_cache)))

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
    try:
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
    except Exception:
        pass
    print("[+] strings indexed: {}".format(len(_string_list)))

def _str_addr(s):
    _build_strings()
    a = _string_map.get(s)
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
    seen = set()
    try:
        st = currentProgram.getSymbolTable()
        for sym in st.getAllSymbols(True):
            try:
                a):
 = _to_u(sym.getAddress().get   Offset())
                n = sym.getName()
                if if (a, n) f in seen:
                    continue
                _syms_index.append((a, n))
                seen.add(( isa, n))
            except Exception:
 None                pass
    except Exception:
        pass
    _load_symbols()
    for n, a in _sym_cache.items():
        if (a, n) in seen:
            continue
        _syms_index.append((a, n))
        seen.add((a, n))
    print("[+] symtable indexed: {}".format(len(_syms_index)))

def syms_named(pat):
    _build_symidx()
    out = []
    try:
        for a, n in _syms_index:
            if pat in n:
                out.append((a, n))
    except Exception:
        pass
    return out

def xrefs_to(addr):
    if addr is None:
        return []
    out = []
    try:
        ga = safe_addr(addr)
        if ga is None:
            return out
        rm = currentProgram.getReferenceManager()
        for r in rm.getReferencesTo(ga):
            out.append(_to_u(r.getFromAddress().getOffset()))
    except Exception:
        pass
    return out

def func_at(addr):
    if addr is None:
        return None
    try:
        ga = safe_addr(addr)
        if ga is None:
            return None
        f = getFunctionAt(ga)
        if f:
            return f
    except Exception:
        pass
    try:
        ga = safe_addr(addr)
        if ga is None:
            return None
        return getFunctionContaining(ga)
    except Exception:
        return None

def ensure_func(addr):
    f = func_at(addr)
    if f:
        return f
    if addr is None:
        return None
    try:
        ga = safe_addr(addr)
        if ga is None:
            return None
        disassemble(ga)
    except Exception:
        pass
    try:
        ga = safe_addr(addr)
        if ga is None:
            return None
        return createFunction(ga, None)
    except Exception:
        return None

def decompile(f:
        return ""
    try:
        from ghidra.app.decompiler import DecompInterface, DecompileOptions
        from ghidra.util.task import ConsoleTaskMonitor
        if _IFC[0] is None:
            ifc = DecompInterface()
            ifc.setOptions(DecompileOptions())
            ifc.openProgram(currentProgram)
            _IFC[0] = ifc
        r = _IFC[0].decompileFunction(f, 60, ConsoleTaskMonitor())
        if r.decompileCompleted():
            return r.getDecompiledFunction().getC()
    except Exception:
        pass
    return ""

def resolve_adrp_pairs(func):
    if func is None:
        return []
    out = []
    try:
        listing = currentProgram.getListing()
        body = func.getBody()
        if body is None:
            return out
        insn = listing.getInstructionAt(body.getMinAddress())
        prev = None
        while insn is not None and body.contains(insn.getAddress()):
            mn = insn.getMnemonicString().lower()
            txt = insn.toString()
            if mn == "adrp":
                try:
                    toks = txt.replace(",", " ").split()
                    page = int(toks[-1], 16) & 0xFFFFFFFFFFFFFFFF
                    prev = (toks[1], page)
                except Exception:
                    prev = None
            elif prev is not None and mn in ("add", "ldr", "ldrsw", "ldp", "ldur", "ldrh", "ldrb"):
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
                        if 0xFFFFFFF000000000 <= tgt < 0xFFFFFFF200000000:
                            out.append(tgt)
                except Exception:
                    pass
                prev = None
            else:
                if mn not in ("nop", "bti", "pacibsp", "hint"):
                    prev = None
            insn = insn.getNext()
    except Exception:
        pass
    return out

def write_lines(path, lines):
    try:
        d = os.path.dirname(path)
        if d and not os.path.isdir(d):
            os.makedirs(d)
    except Exception:
        pass
    try:
        with open(path, "w") as fh:
            for l in lines:
                fh.write(l + "\n")
    except Exception:
        pass

def norm(s):
    return re.sub(r"[^A-Za-z0-9_]", "_", s)

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
    try:
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
    except Exception:
        return None

def _score_sysent(base, sample=12):
    hits = 0
    zero_streak = 0
    for i in range(sample):
        e = _sysent_entry(base, i)
        if e is None:
            zero_streak += 1
            if zero_streak >= 3:
                return hits
            continue
        zero_streak = 0
        try:
            call, narg, rt, ab = e
            if narg > 0 or rt > 0 or ab > 0:
                hits += 2
            else:
                hits += 1
        except Exception:
            pass
    return hits

def _find_sysent():
    for nm in ("_sysent", "sysent", "_unix_sysent", "unix_sysent"):
        try:
            a = sym_get(nm)
            if a and _score_sysent(a) >= 10:
                return a, "sym:" + nm
        except Exception:
            pass
    try:
        mem = currentProgram.getMemory()
        blocks = []
        for b in mem.getBlocks():
            try:
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
            except Exception:
                pass
        blocks.sort(key=lambda x: x[0])
        for _, b in blocks:
            try:
                s = _to_u(b.getStart().getOffset())
                e = _to_u(b.getEnd().getOffset())
                scan_hi = min(e, s + 0x200000)
                if scan_hi - s < SYSENT_STRIDE * 200:
                    continue
                a = s + ((-s) % 8)
                max_a = scan_hi - SYSENT_STRIDE * 200
                best = None
                best_sc = 0
                while a < max_a:
                    sc = _score_sysent(a)
                    if sc > best_sc:
                        best_sc = sc
                        best, = a
                        if sc >= 20:
                            return a, "scan:" + b.getName()
                    a += 8
                if best is not None and best_sc >= 12:
                    return best, "scan:" + b.getName()
            except Exception:
                pass
    except Exception:
        pass
    return None, "NOT_FOUND"

def _walk_sysent(base limit=1500):
    out = []
    bad = 0
    for i in range(limit):
        e = _sysent_entry(base, i)
        if e is None:
            bad += 1
            if bad > 30:
                break
            continue
        bad = 0
        try:
            call, narg, ret_type, arg_bytes = e
            f = func_at(call)
            name = f.getName() if f else "?"
            out.append((i, call, narg, ret_type, arg_bytes, name))
        except Exception:
            pass
    return out

def _find_mach_traps():
    for nm in ("_mach_trap_table", "mach_trap_table"):
        try:
            a = sym_get(nm)
            if a:
                return a, "sym:" + nm
        except Exception:
            pass
    try:
        for a, n in syms_named("mach_trap"):
            if 0xFFFFFFF000000000 <= a < 0xFFFFFFF200000000:
                return a, "ghidra:" + n
    except Exception:
        pass
    return None, "NOT_FOUND"

def _collect_globals():
    print("[*] globals via adrp...")
    result = {}
    for label, anchors in GLOBAL_ANCHORS.items():
        for s in anchors:
            try:
                sa = _str_addr(s)
                if sa is None:
                    continue
                for xr in xrefs_to(sa):
                    f = func_at(xr)
                    if f is None:
                        continue
                    for tgt in resolve_adrp_pairs(f):
                        if _validate_addr(tgt, "any"):
                            result.setdefault(tgt, set()).add(label)
            except Exception:
                pass
    final = {}
    for addr, labels in result.items():
        for lbl in labels:
            if lbl not in final:
                final[lbl] = addr
                break
    return final

def _collect_globals_by_symbol():
    print("[*] globals via symbol...")
    result = {}
    for label in ("kernproc", "allproc", "initproc", "kernel_task",
                   "kernel_map", "zone_map", "ipc_space_kernel",
                   "ipc_space_launchd", "task_list", "pmap_kernel",
                   "proc_list", "vm_map_kernel", "rootvnode"):
        try:
            a = sym_get("_" + label)
            if a is None:
                a = sym_get(label)
            if a is not None and _validate_addr(a, "any"):
                result[label] = a
        except Exception:
            pass
    return result

def _collect_struct_offsets():
    print("[*] struct offsets via accessors...")
    out = {}
    for field, names in ACCESSOR_SPECS.items():
        for name in names:
            try:
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
                candidates = []
                for pat in [
                    r"\*\([^)]*\*\)\s*\(\s*\w+\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)",
                    r"return\s+\*\([^)]*\)\s*\(\s*\w+\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)",
                    r"\(\s*\w+\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)",
                ]:
                    for m in re.finditer(pat, code):
                        try:
                            off = int(m.group(1), 0)
                            if 0 < off < 0x2000:
                                candidates.append(off)
                        except Exception:
                            pass
                expected = STRUCT_RANGES.get(field)
                for off in candidates:
                    if expected and not (expected[0] <= off <= expected[1]):
                        continue
                    out[field] = off
                    break
                if field in out:
                    break
            except Exception:
                pass
    return out

def _collect_struct_offsets_from_globals(globals_map):
    print("[*] struct offsets via known globals...")
    out = {}

    kernproc_var = globals_map.get("kernproc")
    kernel_task_var = globals_map.get("kernel_task")
    allproc_var = globals_map.get("allproc")
    ipc_space_kernel_var = globals_map.get("ipc_space_kernel")

    first_proc = None
    if kernproc_var and _validate_addr(kernproc_var, "data"):
        v = read_u64(kernproc_var)
        if v and _is_data_ptr(v):
            first_proc = v
            print("[+] kernproc deref -> {}".format(fmt(v)))

    if first_proc is None and allproc_var and _validate_addr(allproc_var, "data"):
        v = read_u64(allproc_var)
        if v and _is_data_ptr(v):
            first_proc = v
            print("[+] allproc deref -> {}".format(fmt(v)))

    if first_proc is not None:
        for off in range(0x08, 0x80, 8):
            try:
                v = read_u64(first_proc + off)
                if v and _is_data_ptr(v):
                    pid = read_u32(v + 0x74)
                    if pid is not None and 0 < pid < 0x100000:
                        out["proc_task"] = off
                        print("[+] proc_task = 0x{:x} (pid={})".format(off, pid))
                        break
            except Exception:
                pass

    if first_proc is not None:
        for off in range(0x80, 0x180, 8):
            try:
                v = read_u64(first_proc + off)
                if v and _is_data_ptr(v):
                    uid = read_u32(v + 0x18)
                    if uid is not None and uid < 0x10000:
                        out["proc_ucred"] = off
                        print("[+] proc_ucred = 0x{:x} (uid={})".format(off, uid))
                        break
            except Exception:
                pass

    if first_proc is not None:
        for off in range(0x18, 0x80, 8):
            try:
                v = read_u64(first_proc + off)
                if v and _is_data_ptr(v):
                    first_field = read_u64(v)
                    if first_field and _is_data_ptr(first_field):
                        out["proc_fd"] = off
                        print("[+] proc_fd = 0x{:x}".format(off))
                        break
            except Exception:
                pass

    if first_proc is not None:
        for off in range(0x08, 0x100, 8):
            try:
                v = read_u64(first_proc + off)
                if v and _is_data_ptr(v):
                    first_field = read_u64(v)
                    if first_field and _is_data_ptr(first_field):
                        out.setdefault("proc_pptr", off)
                        break
            except Exception:
                pass

    kernel_task_ptr = None
    if kernel_task_var and _validate_addr(kernel_task_var, "data"):
        v = read_u64(kernel_task_var)
        if v and _is_data_ptr(v):
            kernel_task_ptr = v
            print("[+] kernel_task deref -> {}".format(fmt(v)))

    if kernel_task_ptr is not None:
        for off in range(0x300, 0x420, 8):
            try:
                v = read_u64(kernel_task_ptr + off)
                if not v or not _is_data_ptr(v):
                    continue
                pid = read_u32(v + 0x74)
                if pid is not None and 0 < pid < 0x100000:
                    out["task_bsd_info"] = off
                    print("[+] task_bsd_info = 0x{:x} (pid={})".format(off, pid))
                    break
            except Exception:
                pass

    if kernel_task_ptr is not None:
        for off in range(0x18, 0x60, 8):
            try:
                v = read_u64(kernel_task_ptr + off)
                if v and _is_data_ptr(v):
                    first_field = read_u64(v)
                    if first_field and _is_data_ptr(first_field):
                        out["task_vm_map"] = off
                        print("[+] task_vm_map = 0x{:x}".format(off))
                        break
            except Exception:
                pass

    if kernel_task_ptr is not None:
        for off in range(0x280, 0x3A0, 8):
            try:
                v = read_u64(kernel_task_ptr + off)
                if v and _is_data_ptr(v):
                    tbl = read_u64(v + 0x20)
                    if tbl and _is_data_ptr(tbl):
                        out["task_itk_space"] = off
                        print("[+] task_itk_space = 0x{:x}".format(off))
                        break
            except Exception:
                pass

    if kernel_task_ptr is not None:
        for off in range(0x380, 0x420, 8):
            try:
                v = read_u64(kernel_task_ptr + off)
                if v and _is_data_ptr(v):
                    pid = read_u32(v + 0x74)
                    if pid is not None and pid > 0:
                        out["task_proc"] = off
                        print("[+] task_proc = 0x{:x} (pid={})".format(off, pid))
                        break
            except Exception:
                pass

    if kernel_task_ptr is not None:
        for off in range(0x380, 0x420, 8):
            try:
                v = read_u64(kernel_task_ptr + off)
                if v and _is_data_ptr(v):
                    first_field = read_u64(v)
                    if first_field and _is_data_ptr(first_field):
                        out.setdefault("thread_task", off)
                        break
            except Exception:
                pass

    if ipc_space_kernel_var and _validate_addr(ipc_space_kernel_var, "data"):
        isp = read_u64(ipc_space_kernel_var)
        if isp and _is_data_ptr(isp):
            for off in range(0x10, 0x40, 8):
                try:
                    v = read_u64(isp + off)
                    if v and _is_data_ptr(v):
                        out["ipc_space_is_table"] = off
                        print("[+] ipc_space_is_table = 0x{:x}".format(off))
                        break
                except Exception:
                    pass

    return out

def _find_kalloc(kfree_ext):
    try:
        for a, n in syms_named("kalloc_ext"):
            if _validate_addr(a, "ktext"):
                return a
    except Exception:
        pass
    try:
        for a, n in syms_named("kalloc_canblock"):
            if _validate_addr(a, "ktext"):
                return a
    except Exception:
        pass
    if kfree_ext is not None:
        best = None
        best_delta = 0x10000
        try:
            for a, n in _syms_index:
                if "kalloc" not in n.lower():
                    continue
                if not _validate_addr(a, "ktext"):
                    continue
                delta = abs(a - kfree_ext)
                if delta < best_delta:
                    best_delta = delta
                    best = a
        except Exception:
            pass
        if best is not None:
            return best
    return None

def _find_kalloc_zones():
    out = {}
    for z in KALLOC_ZONES:
        try:
            sa = _str_addr(z)
            if sa is None:
                continue
            kv = [xr for xr in xrefs_to(sa)
                  if 0xFFFFFFF000000000 <= xr < 0xFFFFFFF200000000]
            if kv:
                out[z] = kv
        except Exception:
            pass
    return out

def _find_primitives():
    print("[*] primitive functions...")
    out = {}
    for name in PRIMITIVE_FUNCS:
        try:
            a = sym_get(name)
            if a is not None and _validate_addr(a, "ktext"):
                out[name] = a
        except Exception:
            pass
    return out

def main():
    print("=== kernel_rw.py ===")
    try:
        print("[*] program: " + currentProgram.getName())
    except Exception:
        pass

    report = []
    hdr    = []
    jout   = {}

    try:
        _load_symbols()
        _build_strings()
    except Exception as e:
        print("[-] init error: {}".format(e))

    try:
        img_base = int(currentProgram.getImageBase().getOffset()) & 0xFFFFFFFFFFFFFFFF
    except Exception:
        img_base = KERNEL_UNSLID_BASE

    report.append("=== [1] BASE ===")
    report.append("image_base  = " + fmt(img_base))
    report.append("unslid_base = " + fmt(KERNEL_UNSLID_BASE))
    hdr.append("#define NK_KERNEL_UNSLID_BASE   " + fmt(KERNEL_UNSLID_BASE) + "ULL")
    hdr.append("#define NK_IMAGE_BASE           " + fmt(img_base) + "ULL")
    hdr.append("")
    jout["kernel_base"] = fmt(KERNEL_UNSLID_BASE)
    jout["image_base"]  = fmt(img_base)

    print("[*] sysent discovery...")
    try:
        sysent_base, sysent_src = _find_sysent()
        sysent_entries = _walk_sysent(sysent_base) if sysent_base else []
    except Exception as e:
        print("[-] sysent error: {}".format(e))
        sysent_base, sysent_src, sysent_entries = None, "ERROR", []
    print("[+] sysent: {} ({} entries)".format(sysent_src, len(sysent_entries)))
    report.append("")
    report.append("=== [2] SYSENT ===")
    report.append("source  = " + sysent_src)
    report.append("base    = " + fmt(sysent_base))
    report.append("entries = " + str(len(sysent_entries)))
    hdr.append("// SYSENT")
    if sysent_base:
        hdr.append("#define NK_SYSENT_BASE          " + fmt(sysent_base) + "ULL")
        hdr.append("#define NK_SYSENT_ENTRY_SZ      " + str(SYSENT_STRIDE))
        hdr.append("#define NK_SYSENT_COUNT         " + str(len(sysent_entries)))
        for i, h, narg, rt, ab, name in sysent_entries:
            if not h or not name or name in ("?", "NOSYS"):
                continue
            if name.startswith("FUN_") or name.startswith("s_"):
                continue
            hdr.append("#define NK_SYSENT_{:<32} {}ULL /* #{} */".format(
                norm(name).upper(), fmt(h), i))
    hdr.append("")
    jout["sysent_base"]  = fmt(sysent_base) if sysent_base else None
    jout["sysent_count"] = len(sysent_entries)

    print("[*] mach traps...")
    try:
        mt_base, mt_src = _find_mach_traps()
    except Exception as e:
        print("[-] mach_trap error: {}".format(e))
        mt_base, mt_src = None, "ERROR"
    report.append("")
    report.append("=== [3] MACH TRAPS ===")
    report.append("source = " + mt_src)
    report.append("base   = " + fmt(mt_base))
    hdr.append("// MACH TRAPS")
    if mt_base:
        hdr.append("#define NK_MACH_TRAP_TABLE       " + fmt(mt_base) + "ULL")
    hdr.append("")
    jout["mach_trap_table"] = fmt(mt_base) if mt_base else None

    print("[*] globals...")
    globals_map = {}
    try:
        globals_map.update(_collect_globals_by_symbol())
    except Exception as e:
        print("[-] globals_sym error: {}".format(e))
    try:
        globals_map.update(_collect_globals())
    except Exception as e:
        print("[-] globals_adrp error: {}".format(e))

    report.append("")
    report.append("=== [4] GLOBALS ===")
    hdr.append("// GLOBALS")
    for k in sorted(globals_map.keys()):
        addr = globals_map[k]
        report.append("  {:<20} {}".format(k, fmt(addr)))
        hdr.append("#define NK_G_{:<30} {}ULL".format(k.upper(), fmt(addr)))
    hdr.append("")
    jout["globals"] = {k: fmt(v) for k, v in globals_map.items()}

    print("[*] struct offsets...")
    struct_offsets = {}
    try:
        struct_offsets.update(_collect_struct_offsets())
    except Exception as e:
        print("[-] struct_accessors error: {}".format(e))
    try:
        fallback = _collect_struct_offsets_from_globals(globals_map)
        for k, v in fallback.items():
            if k not in struct_offsets:
                struct_offsets[k] = v
    except Exception as e:
        print("[-] struct_globals error: {}".format(e))
        traceback.print_exc()

    report.append("")
    report.append("=== [5] STRUCT OFFSETS ===")
    hdr.append("// STRUCT OFFSETS")
    for k in sorted(struct_offsets.keys()):
        v = struct_offsets[k]
        report.append("  {:<25} 0x{:x}".format(k, v))
        hdr.append("#define NK_{:<30} 0x{:x}".format(norm(k).upper(), v))
    hdr.append("")
    jout["struct_offsets"] = struct_offsets

    print("[*] primitive functions...")
    primitives = {}
    try:
        primitives = _find_primitives()
    except Exception as e:
        print("[-] primitives error: {}".format(e))

    report.append("")
    report.append("=== [5b] PRIMITIVE FUNCTIONS ===")
    hdr.append("// PRIMITIVE FUNCTIONS")
    for name, a in sorted(primitives.items()):
        report.append("  {:<30} {}".format(name, fmt(a)))
        hdr.append("#define NK_FN_{:<30} {}ULL".format(norm(name).upper()[:30], fmt(a)))
    hdr.append("")
    jout["primitives"] = {k: fmt(v) for k, v in primitives.items()}

    print("[*] kalloc/kfree...")
    try:
        kfree_ext = sym_get("_kfree_ext")
    except Exception:
        kfree_ext = None
    try:
        kalloc_ext = _find_kalloc(kfree_ext)
    except Exception as e:
        print("[-] kalloc error: {}".format(e))
        kalloc_ext = None

    kfree_callers = set()
    if kfree_ext is not None:
        try:
            for xr in xrefs_to(kfree_ext):
                f = func_at(xr)
                if f:
                    kfree_callers.add(_to_u(f.getEntryPoint().getOffset()))
        except Exception:
            pass

    report.append("")
    report.append("=== [6] KALLOC/KFREE ===")
    report.append("_kfree_ext  = " + fmt(kfree_ext))
    report.append("_kalloc_ext = " + fmt(kalloc_ext))
    report.append("kfree_callers = " + str(len(kfree_callers)))
    hdr.append("// KALLOC/KFREE")
    if kfree_ext:
        hdr.append("#define NK_KFREE_EXT            " + fmt(kfree_ext) + "ULL")
    if kalloc_ext:
        hdr.append("#define NK_KALLOC_EXT           " + fmt(kalloc_ext) + "ULL")
    for i, ep in enumerate(sorted(kfree_callers)[:32]):
        hdr.append("#define NK_KFREE_CALLER_{:<27} {}ULL".format(
            norm("{:04X}".format(i)), fmt(ep)))
    hdr.append("")
    jout["kfree_ext"]  = fmt(kfree_ext) if kfree_ext else None
    jout["kalloc_ext"] = fmt(kalloc_ext) if kalloc_ext else None

    print("[*] kalloc zones...")
    try:
        zones = _find_kalloc_zones()
    except Exception as e:
        print("[-] zones error: {}".format(e))
        zones = {}

    report.append("")
    report.append("=== [7] KALLOC ZONES ===")
    hdr.append("// KALLOC ZONES")
    for z, kv in sorted(zones.items()):
        for kva in kv:
            report.append("  {:<45} {}".format(z, fmt(kva)))
            hdr.append("#define NK_ZONE_{:<40} {}ULL".format(
                norm(z).upper()[:40], fmt(kva)))
    hdr.append("")
    jout["zones"] = {k: [fmt(x) for x in v] for k, v in zones.items()}

    print("[*] copyin/copyout...")
    copy = {}
    for s in ("_copyin", "_copyout", "_copyinstr", "_copyoutstr",
              "_copyin_word", "_copyout_word", "_copyio",
              "_copyinmsg", "_copyoutmsg"):
        try:
            a = sym_get(s)
            if a:
                copy[s] = a
                continue
            hits = syms_named(s.lstrip("_"))
            if hits:
                copy[s] = hits[0][0]
        except Exception:
            pass

    report.append("")
    report.append("=== [8] COPYIN/COPYOUT ===")
    hdr.append("// COPYIN/COPYOUT")
    for s, a in sorted(copy.items()):
        report.append("  {:<20} {}".format(s, fmt(a)))
        hdr.append("#define NK_{:<30} {}ULL".format(norm(s).upper(), fmt(a)))
    hdr.append("")
    jout["copyin_copyout"] = {k: fmt(v) for k, v in copy.items()}

    for key, val in CONFIRMED.items():
        if key in ("proc_pid", "task_thread"):
            jout.setdefault("struct_offsets", {})
            if key not in jout["struct_offsets"]:
                jout["struct_offsets"][key] = val
        elif key in ("ctrr_lock_boot", "cpu_lock_sysreg", "sptm_base"):
            jout.setdefault("sptm", {})
            if key not in jout["sptm"]:
                jout["sptm"][key] = val
        else:
            if not jout.get(key):
                jout[key] = val

    try:
        write_lines(OUT_TXT, report)
        print("[+] wrote " + OUT_TXT)
    except Exception as e:
        print("[-] txt write error: {}".format(e))

    try:
        header = ["#ifndef NK_OFFSETS_H",
                  "#define NK_OFFSETS_H",
                  "",
                  "// auto-generated by kernel_rw.py",
                  "// program: " + currentProgram.getName(),
                  ""] + hdr + ["", "#endif /* NK_OFFSETS_H */"]
        write_lines(OUT_H, header)
        print("[+] wrote " + OUT_H)
    except Exception as e:
        print("[-] h write error: {}".format(e))

    try:
        with open(OUT_JSON, "w") as fh:
            fh.write(json.dumps(jout, indent=2, sort_keys=True))
        print("[+] wrote " + OUT_JSON)
    except Exception as e:
        print("[-] json write error: {}".format(e))

    print("")
    print("=============== SUMMARY ===============")
    print("  kernel_base      : " + fmt(KERNEL_UNSLID_BASE))
    print("  sysent_base      : " + fmt(sysent_base))
    print("  sysent_entries   : " + str(len(sysent_entries)))
    print("  mach_trap_table  : " + fmt(mt_base))
    print("  globals          : " + str(len(globals_map)))
    print("  struct_offsets   : " + str(len(struct_offsets)))
    print("  primitives       : " + str(len(primitives)))
    print("  kfree_ext        : " + fmt(kfree_ext))
    print("  kalloc_ext       : " + fmt(kalloc_ext))
    print("  kfree callers    : " + str(len(kfree_callers)))
    print("  kalloc zones     : " + str(len(zones)))
    print("  copyin/out       : " + str(len(copy)))
    print("=======================================")
    print("[+] kernel_rw.py done")

try:
    main()
except Exception as e:
    print("[-] FATAL: {}".format(e))
    traceback.print_exc()
    try:
        with open(OUT_TXT, "w") as fh:
            fh.write("FATAL: {}\n".format(e))
        with open(OUT_H, "w") as fh:
            fh.write("#error kernel_rw.py failed\n")
        with open(OUT_JSON, "w") as fh:
            fh.write("{\"error\": \"fatal\"}\n")
    except Exception:
        pass
