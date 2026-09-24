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

OUT_COMPACT = os.path.join(WORKSPACE, "offsets.h")
OUT_JSON    = os.path.join(WORKSPACE, "offsets.json")
OUT_KFD     = os.path.join(WORKSPACE, "kfd_offsets.h")
OUT_TXT     = os.path.join(WORKSPACE, "nk_kernel_rw.txt")
OUT_DISASM  = os.path.join(WORKSPACE, "disasm.txt")

KERNEL_UNSLID_BASE = 0xFFFFFFF007004000
MASK48             = 0x0000FFFFFFFFFFFF
KTEXT_LO           = 0xFFF007004000
KTEXT_HI           = 0xFFF200000000
SYSENT_STRIDE      = 24


def _write_placeholder():
    for path, content in [
        (OUT_COMPACT, "#ifndef NK_OFFSETS_H\n#define NK_OFFSETS_H\n#endif\n"),
        (OUT_JSON,    "{}\n"),
        (OUT_KFD,     "#ifndef KFD_OFFSETS_H\n#define KFD_OFFSETS_H\n#endif\n"),
        (OUT_TXT,     "=== placeholder ===\n"),
        (OUT_DISASM,  "=== no disasm ===\n"),
    ]:
        try:
            with open(path, "w") as fh:
                fh.write(content)
        except Exception:
            pass


_write_placeholder()


_sym_cache        = None
_string_map       = None
_string_list      = None
_syms_index       = None
_IFC              = [None]
_valid_addr_cache = {}
_blocks_cache     = None


CONFIRMED = {
    "sysent_base":     "0xFFFFFFF007C192A0",
    "mach_trap_table": "0xFFFFFFF007BE8018",
    "kfree_ext":       "0xFFFFFFF00A201000",
    "kalloc_ext":      "0xFFFFFFF00A200DCC",
    "copyin":          "0xFFFFFFF00A7B9570",
    "copyout":         "0xFFFFFFF00A2C6C28",
}

CONFIRMED_GLOBALS = {
    "kernproc":    "0xFFFFFFF007BBF040",
    "kernel_task": "0xFFFFFFF00700DC70",
    "zone_map":    "0xFFFFFFF00AD6A800",
    "task_list":   "0xFFFFFFF0080D93F0",
    "kernel_map":  "0xFFFFFFF007BBE228",
    "allproc":     "0xFFFFFFF007BBF048",
}

CONFIRMED_STRUCT = {
    "proc_p_pid":               0x74,
    "proc_ro_p_ucred":          0xB8,
    "thread_task_threads_next": 0x50,
}

ACCESSORS = {
    "proc_p_pid":                    ["_proc_pid", "proc_pid"],
    "proc_p_ppid":                   ["_proc_ppid", "proc_ppid"],
    "proc_p_list_le_next":           ["_proc_get_list_next", "proc_list_next"],
    "proc_p_list_le_prev":           ["_proc_get_list_prev"],
    "proc_p_proc_ro":                ["_proc_get_ro", "proc_get_ro"],
    "proc_p_fd":                     ["_proc_fd", "proc_fd"],
    "proc_p_flag":                   ["_proc_flag", "proc_flag"],
    "proc_p_textvp":                 ["_proc_textvp", "proc_textvp"],
    "proc_p_name":                   ["_proc_name", "proc_name"],
    "proc_p_task":                   ["_proc_task", "proc_task"],
    "proc_p_pgrp":                   ["_proc_pgrp", "proc_pgrp"],
    "proc_p_pptr":                   ["_proc_pptr", "proc_pptr"],
    "proc_p_sibling":                ["_proc_sibling"],
    "proc_p_children":               ["_proc_children"],
    "proc_p_stat":                   ["_proc_stat"],
    "proc_p_csflags":                ["_proc_csflags"],
    "proc_ro_pr_task":               ["_proc_ro_get_task", "proc_ro_get_task"],
    "proc_ro_p_ucred":               ["_proc_ucred", "proc_ucred"],
    "task_bsd_info":                 ["_get_bsdtask_info", "task_bsd_info"],
    "task_map":                      ["_task_vm_map", "task_vm_map", "get_task_map"],
    "task_threads_next":             ["_task_thread", "task_thread", "get_task_thread"],
    "task_itk_space":                ["_task_get_itk_space", "task_get_itk_space"],
    "task_itk_self":                 ["_task_get_itk_self", "task_get_itk_self"],
    "task_ref_count":                ["_task_reference", "task_reference"],
    "task_suspend_count":            ["_task_suspend"],
    "task_priority":                 ["_task_priority"],
    "task_task_exc_guard":           ["_task_get_exc_guard"],
    "task_t_flags":                  ["_task_get_t_flags"],
    "task_ro":                       ["_task_ro"],
    "thread_task_threads_next":      ["_thread_get_next"],
    "thread_ast":                    ["_thread_get_ast"],
    "thread_ctid":                   ["_thread_get_ctid"],
    "thread_options":                ["_thread_get_options"],
    "thread_t_tro":                  ["_thread_get_tro"],
    "thread_ro":                     ["_thread_ro"],
    "thread_ro_tro_task":            ["_thread_ro_get_task"],
    "thread_ro_tro_proc":            ["_thread_ro_get_proc"],
    "thread_machine_upcb":           ["_thread_get_upcb"],
    "thread_machine_contextdata":    ["_thread_get_contextdata"],
    "thread_machine_kstackptr":      ["_thread_get_kstackptr"],
    "thread_machine_jop_pid":        ["_thread_get_jop_pid"],
    "thread_machine_rop_pid":        ["_thread_get_rop_pid"],
    "thread_mutex_lck_mtx_data":     ["_thread_get_mutex"],
    "thread_guard_exc_info_code":    ["_thread_get_guard_exc_code"],
    "thread_mach_exc_info_exception_type": ["_thread_get_exc_type"],
    "thread_mach_exc_info_code":     ["_thread_get_mach_exc_code"],
    "thread_mach_exc_info_os_reason": ["_thread_get_mach_exc_os_reason"],
    "thread_uthread":                ["_get_uthread", "thread_uthread"],
    "uthread_uu_proc":               ["_uthread_get_proc"],
    "uthread_uu_task":               ["_uthread_get_task"],
    "uthread_uu_thread":             ["_uthread_get_thread"],
    "ucred_cr_label":                ["_kauth_cred_getlabel", "kauth_cred_getlabel"],
    "kauth_cred_uid":                ["_kauth_cred_getuid", "kauth_cred_getuid"],
    "kauth_cred_gid":                ["_kauth_cred_getgid", "kauth_cred_getgid"],
    "kauth_cred_ruid":               ["_kauth_cred_getruid"],
    "kauth_cred_rgid":               ["_kauth_cred_getrgid"],
    "kauth_cred_svuid":              ["_kauth_cred_getsvuid"],
    "kauth_cred_svgid":              ["_kauth_cred_getsvgid"],
    "label_l_perpolicy_amfi":        ["_mac_label_get_amfi"],
    "label_l_perpolicy_sandbox":     ["_mac_label_get_sandbox"],
    "ipc_space_is_table":            ["_ipc_space_get_table", "ipc_space_get_table"],
    "ipc_space_active":              ["_ipc_space_get_active"],
    "ipc_entry_ie_object":           ["_ipc_entry_get_object"],
    "ipc_port_ip_kobject":           ["_ipc_port_get_kobject", "ipc_port_get_kobject"],
    "ipc_port_ip_receiver":          ["_ipc_port_get_receiver"],
    "ipc_port_ip_mscount":           ["_ipc_port_get_mscount"],
    "ipc_port_ip_references":        ["_ipc_port_get_references"],
    "ipc_port_ip_srights":           ["_ipc_port_get_srights"],
    "ipc_port_ip_messages":          ["_ipc_port_get_messages"],
    "filedesc_fd_ofiles":            ["_fdp_get_ofiles", "fdp_get_ofiles"],
    "filedesc_fd_cdir":              ["_fdp_get_cdir", "fdp_get_cdir"],
    "fileproc_fp_glob":              ["_fp_get_fglob", "fp_get_fglob"],
    "fileproc_fp_fg":                ["_fp_get_fg", "fp_get_fg"],
    "fileglob_fg_data":              ["_fileglob_get_data"],
    "fileglob_fg_flag":              ["_fileglob_get_flag"],
    "vnode_v_iocount":               ["_vnode_get_iocount"],
    "vnode_v_writecount":            ["_vnode_get_writecount"],
    "vnode_v_flag":                  ["_vnode_get_flag"],
    "vnode_v_mount":                 ["_vnode_get_mount"],
    "vnode_v_parent":                ["_vnode_get_parent"],
    "vnode_v_data":                  ["_vnode_get_data"],
    "vnode_v_name":                  ["_vnode_get_name"],
    "vnode_v_usecount":              ["_vnode_get_usecount"],
    "vnode_v_ncchildren_tqh_first":  ["_vnode_get_ncchildren_first"],
    "vnode_v_nclinks_lh_first":      ["_vnode_get_nclinks_first"],
    "mount_mnt_flag":                ["_mount_get_flag"],
    "namecache_nc_vp":               ["_namecache_get_vp"],
    "namecache_nc_child_tqe_next":   ["_namecache_get_child_next"],
    "vm_map_hdr":                    ["_vm_map_get_header", "vm_map_get_header"],
    "vm_map_pmap":                   ["_vm_map_get_pmap"],
    "vm_map_ref_count":              ["_vm_map_get_ref_count"],
    "vm_map_header_nentries":        ["_vm_map_header_get_nentries"],
    "vm_map_header_links_next":      ["_vm_map_header_get_next"],
    "vm_map_entry_links_next":       ["_vm_map_entry_get_next"],
    "vm_map_entry_vme_object_or_delta": ["_vm_map_entry_get_object"],
    "vm_map_entry_vme_alias":        ["_vm_map_entry_get_alias"],
    "vm_object_vo_un1_vou_size":     ["_vm_object_get_size"],
    "vm_object_ref_count":           ["_vm_object_get_ref_count"],
    "vm_named_entry_backing_copy":   ["_vm_named_entry_get_backing"],
    "vm_named_entry_size":           ["_vm_named_entry_get_size"],
    "vm_page_vmp_offset":            ["_vm_page_get_offset"],
    "vm_page_vmp_object":            ["_vm_page_get_object"],
    "vm_page_vmp_next":              ["_vm_page_get_next"],
    "socket_so_usecount":            ["_so_get_usecount"],
    "socket_so_proto":               ["_so_get_proto", "so_get_proto"],
    "socket_so_background_thread":   ["_so_get_background_thread"],
    "inpcb_inp_list_le_next":        ["_inp_get_list_next"],
    "inpcb_inp_pcbinfo":             ["_inp_get_pcbinfo"],
    "inpcb_inp_socket":              ["_inp_get_socket", "inp_get_socket"],
    "inpcbinfo_ipi_zone":            ["_inpcbinfo_get_zone"],
    "inpcb_inp_depend6_inp6_icmp6filt": ["_inp_get_icmp6filt"],
    "inpcb_inp_depend6_inp6_chksum": ["_inp_get_chksum"],
    "kalloc_type_view_kt_zv_zv_name": ["_kalloc_type_view_get_name"],
    "arm_kernel_saved_state_sp":     ["_arm_kernel_saved_state_get_sp"],
    "arm_saved_state64_lr":          ["_arm_saved_state64_get_lr"],
    "arm_saved_state64_pc":          ["_arm_saved_state64_get_pc"],
    "arm_saved_state_us_ss_64":      ["_arm_saved_state_get_us_ss"],
}

GLOBAL_ANCHORS = {
    "allproc":           ["allproc"],
    "rootvnode":         ["rootvnode"],
    "proc_find":         ["proc_find"],
    "task_init":         ["task_init @%s:%d"],
    "vm_map_kernel":     ["vm_map_enter"],
    "chroot":            ["chroot"],
    "selinux":           ["selinux"],
    "kauth_cred":        ["kauth_cred_getuid"],
    "amfi":              ["AMFI: task_for_pid() not allowed"],
    "csblob":            ["csblob_get_csblob"],
    "trust_cache":       ["AMFI: trust cache"],
    "pmap_cs":           ["pmap_cs_validate"],
    "cs_enforcement":    ["cs_enforcement_disable"],
    "sb_evaluate":       ["sb_evaluate_internal"],
    "mac_policy":        ["mac_policy_register"],
    "kalloc_type":       ["kalloc.type.var"],
}

ZONE_STRINGS = [
    "kalloc.type.var", "data.kalloc", "early.kalloc",
    "site.struct task", "site.struct proc", "site.struct thread",
    "site.struct ucred", "site.struct ipc_port", "site.struct ipc_space",
    "site.struct ipc_entry", "site.struct ipc_kmsg", "site.struct ipc_object",
    "site.struct vm_map", "site.struct vm_map_entry", "site.struct vm_map_copy",
    "site.struct vm_object", "site.struct vm_page",
    "site.struct fileproc", "site.struct fileglob", "site.struct filedesc",
    "site.struct vnode", "site.struct mount", "site.struct socket",
    "site.struct inpcb", "site.struct pipe", "site.struct knote",
    "site.struct posix_shm",
    "site.struct necp_client_flow_registration", "site.struct necp_fd_data",
    "site.struct necp_session", "site.struct necp_session_policy",
    "site.struct necp_kernel_socket_policy", "site.struct necp_arena_info",
    "site.struct exclave_core", "site.struct kernelkit",
]

PRIMITIVES = [
    "_copyin", "_copyout", "_copyinstr", "_copyoutstr",
    "_kalloc_ext", "_kfree_ext", "_kalloc_canblock",
    "_kernel_memory_allocate", "_kmem_alloc", "_kmem_free",
    "_ipc_port_alloc", "_ipc_port_dealloc",
    "_ipc_space_alloc", "_ipc_space_dealloc",
    "_mach_port_allocate", "_mach_port_deallocate",
    "_task_reference", "_task_deallocate",
    "_proc_reference", "_proc_rele",
    "_zone_alloc", "_zone_free",
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
        if s.startswith(("0x", "0X")):
            return _to_u(int(s, 16))
        return _to_u(int(s, 10))
    except Exception:
        return None


def fmt(v):
    if v is None:
        return "0x0"
    if isinstance(v, string_types):
        p = _parse_addr(v)
        if p is None:
            return "0x0"
        return "0x{:016X}".format(p)
    try:
        return "0x{:016X}".format(int(v) & 0xFFFFFFFFFFFFFFFF)
    except Exception:
        return "0x0"


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


def read_u8(a):
    if a is None:
        return None
    ga = safe_addr(a)
    if ga is None:
        return None
    try:
        return int(currentProgram.getMemory().getByte(ga)) & 0xFF
    except Exception:
        return None


def _blocks():
    global _blocks_cache
    if _blocks_cache is not None:
        return _blocks_cache
    out = []
    try:
        mem = currentProgram.getMemory()
        for b in mem.getBlocks():
            try:
                if not b.isInitialized():
                    continue
                s = _to_u(b.getStart().getOffset())
                e = _to_u(b.getEnd().getOffset())
                out.append((s, e, b.getName(), b.isExecute()))
            except Exception:
                pass
    except Exception:
        pass
    _blocks_cache = out
    return out


def _in_block(addr):
    for s, e, n, x in _blocks():
        if s <= addr < e:
            return (s, e, n, x)
    return None


def _is_data_ptr(p):
    if p is None or p == 0:
        return False
    blk = _in_block(p)
    if blk is None:
        return False
    return not blk[3]


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
    blk = _in_block(_strip_pac(p))
    if blk is None:
        return False
    return blk[3]


def _validate_addr(addr, expected_type="any"):
    if addr in _valid_addr_cache:
        return _valid_addr_cache[addr]
    result = False
    if addr is not None:
        blk = _in_block(addr)
        if blk is not None:
            if expected_type == "ktext":
                result = blk[3]
            elif expected_type == "data":
                result = not blk[3]
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
            _sym_cache[name] = v
            if not name.startswith("_"):
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


def sym_get(name):
    _load_symbols()
    if name in _sym_cache:
        return _sym_cache[name]
    b = name.lstrip("_")
    if b in _sym_cache:
        return _sym_cache[b]
    if "_" + name in _sym_cache:
        return _sym_cache["_" + name]
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
                a = _to_u(sym.getAddress().getOffset())
                n = sym.getName()
                if (a, n) in seen:
                    continue
                _syms_index.append((a, n))
                seen.add((a, n))
            except Exception:
                pass
    except Exception:
        pass
    _load_symbols()
    for n, a in _sym_cache.items():
        if (a, n) in seen:
            continue
        _syms_index.append((a, n))
        seen.add((a, n))


def syms_named(pat):
    _build_symidx()
    out = []
    for a, n in _syms_index:
        if pat in n:
            out.append((a, n))
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


def decompile(f):
    if f is None:
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
        ret_type = read_u32(a + 16)
        narg     = read_u16(a + 20)
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
    streak = 0
    for i in range(sample):
        e = _sysent_entry(base, i)
        if e is None:
            streak += 1
            if streak >= 3:
                return hits
            continue
        streak = 0
        try:
            call, narg, rt, ab = e
            hits += 2 if (narg > 0 or rt > 0 or ab > 0) else 1
        except Exception:
            pass
    return hits


def _find_sysent():
    for nm in ("_sysent", "sysent", "_unix_sysent", "unix_sysent"):
        a = sym_get(nm)
        if a and _score_sysent(a) >= 10:
            return a, "sym:" + nm
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
                        best = a
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


def _find_mach_traps():
    for nm in ("_mach_trap_table", "mach_trap_table"):
        a = sym_get(nm)
        if a:
            return a, "sym:" + nm
    return None, "NOT_FOUND"


def _deref_var(var):
    if var is None:
        return None
    v = read_u64(var)
    if v is None:
        return None
    if not _is_data_ptr(v):
        return None
    return v


def _find_pid_offset(proc_ptr, candidates=(0x74, 0x68, 0x70, 0x78, 0x80, 0x84, 0x88)):
    for off in candidates:
        pid = read_u32(proc_ptr + off)
        if pid is not None and 0 < pid < 0x100000:
            return off, pid
    return None, None


def _walk_proc(proc_ptr, pid_off):
    out = {}
    if proc_ptr is None:
        return out

    if pid_off is not None:
        out["proc_p_pid"] = pid_off

    for off in range(0x08, 0x80, 8):
        v = read_u64(proc_ptr + off)
        if not _is_data_ptr(v):
            continue
        pid2 = read_u32(v + (pid_off if pid_off else 0x74))
        if pid2 is not None and 0 < pid2 < 0x100000:
            out["proc_p_list_le_next"] = off
            break

    for off in range(0x08, 0x80, 8):
        if off == out.get("proc_p_list_le_next"):
            continue
        v = read_u64(proc_ptr + off)
        if not _is_data_ptr(v):
            continue
        pid2 = read_u32(v + (pid_off if pid_off else 0x74))
        if pid2 is not None and 0 < pid2 < 0x100000:
            out["proc_p_list_le_prev"] = off
            break

    ro_off = None
    for off in range(0x08, 0x100, 8):
        v = read_u64(proc_ptr + off)
        if not _is_data_ptr(v):
            continue
        task_hint = read_u64(v + 0x18)
        if _is_data_ptr(task_hint):
            ro_off = off
            out["proc_p_proc_ro"] = off
            break

    for off in range(0x18, 0x80, 8):
        v = read_u64(proc_ptr + off)
        if not _is_data_ptr(v):
            continue
        f1 = read_u64(v)
        if _is_data_ptr(f1):
            out["proc_p_fd"] = off
            break

    for off in range(0x08, 0x100, 8):
        v = read_u64(proc_ptr + off)
        if not _is_data_ptr(v):
            continue
        vname = read_u64(v + 0xD0)
        if _is_data_ptr(vname):
            out["proc_p_textvp"] = off
            break

    if ro_off is not None:
        ro_ptr = read_u64(proc_ptr + ro_off)
        if ro_ptr is not None and _is_data_ptr(ro_ptr):
            for off in range(0x08, 0x80, 8):
                v = read_u64(ro_ptr + off)
                if not _is_data_ptr(v):
                    continue
                task_map = read_u64(v + 0x28)
                if _is_data_ptr(task_map):
                    out["proc_ro_pr_task"] = off
                    break
            for off in range(0x80, 0x180, 8):
                v = read_u64(ro_ptr + off)
                if not _is_data_ptr(v):
                    continue
                uid = read_u32(v + 0x18)
                if uid is not None and uid < 0x10000:
                    out["proc_ro_p_ucred"] = off
                    break
    return out


def _walk_task(task_ptr):
    out = {}
    if task_ptr is None:
        return out

    for off in range(0x18, 0x60, 8):
        v = read_u64(task_ptr + off)
        if not _is_data_ptr(v):
            continue
        hdr = read_u64(v + 0x08)
        if _is_data_ptr(hdr):
            out["task_map"] = off
            break

    for off in range(0x40, 0x80, 8):
        v = read_u64(task_ptr + off)
        if not _is_data_ptr(v):
            continue
        t_next = read_u64(v)
        if _is_data_ptr(t_next):
            out["task_threads_next"] = off
            break

    for off in range(0x280, 0x3A0, 8):
        v = read_u64(task_ptr + off)
        if not _is_data_ptr(v):
            continue
        tbl = read_u64(v + 0x20)
        if _is_data_ptr(tbl):
            out["task_itk_space"] = off
            out["task_itk_self"] = off
            break

    for off in range(0x300, 0x420, 8):
        v = read_u64(task_ptr + off)
        if not _is_data_ptr(v):
            continue
        pid = read_u32(v + 0x74)
        if pid is not None and 0 < pid < 0x100000:
            out["task_bsd_info"] = off
            break

    return out


def _walk_thread(task_ptr):
    out = {}
    if task_ptr is None:
        return out

    threads_off = None
    for off in range(0x40, 0x80, 8):
        v = read_u64(task_ptr + off)
        if _is_data_ptr(v):
            th = read_u64(v)
            if _is_data_ptr(th):
                threads_off = off
                break
    if threads_off is None:
        return out

    threads_head = read_u64(task_ptr + threads_off)
    if threads_head is None or not _is_data_ptr(threads_head):
        return out
    thread_ptr = read_u64(threads_head)
    if thread_ptr is None or not _is_data_ptr(thread_ptr):
        return out

    for off in range(0x40, 0x80, 8):
        v = read_u64(thread_ptr + off)
        if _is_data_ptr(v):
            nxt = read_u64(v)
            if _is_data_ptr(nxt):
                out["thread_task_threads_next"] = off
                break

    for off in range(0x300, 0x420, 8):
        v = read_u64(thread_ptr + off)
        if not _is_data_ptr(v):
            continue
        tr = read_u64(v + 0x10)
        if _is_data_ptr(tr):
            out["thread_t_tro"] = off
            tro_ptr = v
            for o2 in range(0x08, 0x80, 8):
                p = read_u64(tro_ptr + o2)
                if not _is_data_ptr(p):
                    continue
                pid2 = read_u32(p + 0x74)
                if pid2 is not None and 0 < pid2 < 0x100000:
                    out["thread_ro_tro_proc"] = o2
                    break
            for o2 in range(0x08, 0x80, 8):
                p = read_u64(tro_ptr + o2)
                if not _is_data_ptr(p):
                    continue
                m = read_u64(p + 0x28)
                if _is_data_ptr(m):
                    out["thread_ro_tro_task"] = o2
                    break
            break

    return out


def _walk_ipc(task_ptr):
    out = {}
    if task_ptr is None:
        return out

    ispace_off = None
    for off in range(0x280, 0x3A0, 8):
        v = read_u64(task_ptr + off)
        if not _is_data_ptr(v):
            continue
        tbl = read_u64(v + 0x20)
        if _is_data_ptr(tbl):
            ispace_off = off
            break
    if ispace_off is None:
        return out

    ispace = read_u64(task_ptr + ispace_off)
    if ispace is None or not _is_data_ptr(ispace):
        return out

    for off in range(0x08, 0x40, 8):
        v = read_u64(ispace + off)
        if _is_data_ptr(v):
            entry0 = read_u64(v)
            if _is_data_ptr(entry0):
                out["ipc_space_is_table"] = off
                break
    return out


def _walk_vm(task_ptr):
    out = {}
    if task_ptr is None:
        return out

    map_off = None
    for off in range(0x18, 0x60, 8):
        v = read_u64(task_ptr + off)
        if not _is_data_ptr(v):
            continue
        hdr = read_u64(v + 0x08)
        if _is_data_ptr(hdr):
            map_off = off
            break
    if map_off is None:
        return out

    vm_map = read_u64(task_ptr + map_off)
    if vm_map is None or not _is_data_ptr(vm_map):
        return out

    for off in range(0x00, 0x30, 8):
        v = read_u64(vm_map + off)
        if not _is_data_ptr(v):
            continue
        entries = read_u64(v + 0x18)
        if entries is not None and 0 < entries < 0x100000:
            out["vm_map_hdr"] = off
            out["vm_map_header_nentries"] = off
            break

    hdr_off = out.get("vm_map_hdr")
    if hdr_off is None:
        return out

    hdr = read_u64(vm_map + hdr_off)
    if hdr is None or not _is_data_ptr(hdr):
        return out

    for off in range(0x08, 0x30, 8):
        v = read_u64(hdr + off)
        if not _is_data_ptr(v):
            continue
        o = read_u64(v + 0x40)
        if _is_data_ptr(o):
            out["vm_map_entry_links_next"] = off
            first_entry = v
            for eo in range(0x30, 0x60, 8):
                e = read_u64(first_entry + eo)
                if _is_data_ptr(e):
                    out["vm_map_entry_vme_object_or_delta"] = eo
                    break
            break
    return out


def _collect_accessors():
    out = {}
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
            found = False
            for pat in [
                r"\*\([^)]*\*\)\s*\(\s*\w+\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)",
                r"return\s+\*\([^)]*\)\s*\(\s*\w+\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)",
            ]:
                for m in re.finditer(pat, code):
                    try:
                        off = int(m.group(1), 0)
                        if 0 < off < 0x2000:
                            out[field] = off
                            found = True
                            break
                    except Exception:
                        pass
                if found:
                    break
            if found:
                break
    return out


def _collect_globals():
    out = {}
    for label in ("allproc", "rootvnode", "proc_find", "task_init",
                  "vm_map_kernel", "kernel_map", "chroot", "selinux",
                  "kauth_cred", "amfi", "csblob", "trust_cache",
                  "cs_enforcement", "sb_evaluate", "mac_policy", "kalloc_type"):
        a = sym_get("_" + label) or sym_get(label)
        if a is not None and _validate_addr(a, "any"):
            out[label] = a

    for label, anchors in GLOBAL_ANCHORS.items():
        if label in out:
            continue
        for s in anchors:
            sa = _str_addr(s)
            if sa is None:
                continue
            for xr in xrefs_to(sa):
                f = func_at(xr)
                if f is None:
                    continue
                for tgt in resolve_adrp_pairs(f):
                    if _validate_addr(tgt, "any"):
                        out[label] = tgt
                        break
                if label in out:
                    break
            if label in out:
                break

    for k, v in CONFIRMED_GLOBALS.items():
        p = _parse_addr(v)
        if p is not None:
            out[k] = p
    return out


def _collect_zones():
    out = {}
    for z in ZONE_STRINGS:
        sa = _str_addr(z)
        if sa is None:
            continue
        kv = [xr for xr in xrefs_to(sa)
              if 0xFFFFFFF000000000 <= xr < 0xFFFFFFF200000000]
        if kv:
            out[z] = kv[0]
    return out


def _collect_primitives():
    out = {}
    for name in PRIMITIVES:
        a = sym_get(name)
        if a is not None and _validate_addr(a, "ktext"):
            out[name] = a
    ci = _parse_addr(CONFIRMED.get("copyin"))
    co = _parse_addr(CONFIRMED.get("copyout"))
    ke = _parse_addr(CONFIRMED.get("kalloc_ext"))
    kf = _parse_addr(CONFIRMED.get("kfree_ext"))
    if ci: out["_copyin"] = ci
    if co: out["_copyout"] = co
    if ke: out["_kalloc_ext"] = ke
    if kf: out["_kfree_ext"] = kf
    return out


def main():
    print("=== kernel_rw.py ===")

    _load_symbols()
    _build_strings()
    _build_symidx()

    sysent_base, sysent_src = _find_sysent()
    sysent_count = 0
    if sysent_base:
        for i in range(1500):
            e = _sysent_entry(sysent_base, i)
            if e is None:
                break
            sysent_count = i + 1

    mt_base, mt_src = _find_mach_traps()

    globals_map = _collect_globals()
    accessors = _collect_accessors()

    kernproc_ptr = _deref_var(globals_map.get("kernproc"))
    pid_off, _ = _find_pid_offset(kernproc_ptr) if kernproc_ptr else (None, None)
    proc_walk = _walk_proc(kernproc_ptr, pid_off)

    task_ptr = _deref_var(globals_map.get("kernel_task"))
    task_walk = _walk_task(task_ptr)
    thread_walk = _walk_thread(task_ptr)
    ipc_walk = _walk_ipc(task_ptr)
    vm_walk = _walk_vm(task_ptr)

    zones = _collect_zones()
    primitives = _collect_primitives()

    merged = {}
    for src in (CONFIRMED_STRUCT, accessors, proc_walk, task_walk,
                thread_walk, ipc_walk, vm_walk):
        for k, v in src.items():
            if isinstance(v, int):
                merged[k] = v

    compact_lines = [
        "#ifndef NK_OFFSETS_H",
        "#define NK_OFFSETS_H",
        "",
        "// base",
        "#define NK_KERNEL_BASE        " + fmt(KERNEL_UNSLID_BASE) + "ULL",
        "#define NK_SYSENT_BASE        " + fmt(sysent_base) + "ULL",
        "#define NK_SYSENT_COUNT       " + str(sysent_count),
        "#define NK_SYSENT_STRIDE      " + str(SYSENT_STRIDE),
        "#define NK_MACH_TRAP_TABLE    " + fmt(mt_base) + "ULL",
        "",
        "// globals",
    ]
    for k in sorted(globals_map.keys()):
        compact_lines.append("#define NK_G_" + k.upper() + " " + fmt(globals_map[k]) + "ULL")

    compact_lines.append("")
    compact_lines.append("// offsets")
    for k in sorted(merged.keys()):
        compact_lines.append("#define off_" + k + " 0x{:X}".format(merged[k]))

    compact_lines.append("")
    compact_lines.append("// primitives")
    for k in sorted(primitives.keys()):
        compact_lines.append("#define kfd_fn_" + k.lstrip("_") + " " + fmt(primitives[k]) + "ULL")

    compact_lines.append("")
    compact_lines.append("// zones")
    for k in sorted(zones.keys()):
        key = norm(k).upper()[:50]
        compact_lines.append("#define NK_ZONE_" + key + " " + fmt(zones[k]) + "ULL")

    compact_lines.append("")
    compact_lines.append("// sptm")
    compact_lines.append("#define NK_SPTM_CTRR_LOCK_BOOT  0xFFFFFFF027006E62ULL")
    compact_lines.append("#define NK_SPTM_CPU_LOCK_SYSREG 0xFFFFFFF0270B39B4ULL")
    compact_lines.append("#define NK_SPTM_DET_KERNEL_CTRR 0xFFFFFFF0270B2224ULL")
    compact_lines.append("")
    compact_lines.append("#endif")

    write_lines(OUT_COMPACT, compact_lines)

    kfd_lines = ["#ifndef KFD_OFFSETS_H", "#define KFD_OFFSETS_H", ""]
    for k in sorted(merged.keys()):
        kfd_lines.append("#define off_" + k + " 0x{:X}".format(merged[k]))
    kfd_lines.append("")
    for k in sorted(primitives.keys()):
        kfd_lines.append("#define kfd_fn_" + k.lstrip("_") + " " + fmt(primitives[k]) + "ULL")
    kfd_lines.append("")
    kfd_lines.append("#endif")
    write_lines(OUT_KFD, kfd_lines)

    jout = {
        "kernel_base":       fmt(KERNEL_UNSLID_BASE),
        "sysent_base":       fmt(sysent_base),
        "sysent_count":      sysent_count,
        "sysent_stride":     SYSENT_STRIDE,
        "mach_trap_table":   fmt(mt_base),
        "globals":           {k: fmt(v) for k, v in globals_map.items()},
        "offsets":           dict(merged),
        "primitives":        {k: fmt(v) for k, v in primitives.items()},
        "zones":             {k: fmt(v) for k, v in zones.items()},
    }
    try:
        with open(OUT_JSON, "w") as fh:
            fh.write(json.dumps(jout, indent=2, sort_keys=True))
    except Exception:
        pass

    report = []
    report.append("=== KERNEL ===")
    report.append("kernel_base  " + fmt(KERNEL_UNSLID_BASE))
    report.append("sysent       " + fmt(sysent_base) + " (" + str(sysent_count) + ")")
    report.append("mach_trap    " + fmt(mt_base))
    report.append("")
    report.append("globals      " + str(len(globals_map)))
    for k in sorted(globals_map.keys()):
        report.append("  " + k + "  " + fmt(globals_map[k]))
    report.append("")
    report.append("offsets      " + str(len(merged)))
    for k in sorted(merged.keys()):
        report.append("  " + k + "  0x{:X}".format(merged[k]))
    report.append("")
    report.append("primitives   " + str(len(primitives)))
    for k in sorted(primitives.keys()):
        report.append("  " + k + "  " + fmt(primitives[k]))
    report.append("")
    report.append("zones        " + str(len(zones)))
    for k in sorted(zones.keys()):
        report.append("  " + k + "  " + fmt(zones[k]))
    write_lines(OUT_TXT, report)

    print("=== SUMMARY ===")
    print("  sysent_count   " + str(sysent_count))
    print("  globals        " + str(len(globals_map)))
    print("  offsets        " + str(len(merged)))
    print("  primitives     " + str(len(primitives)))
    print("  zones          " + str(len(zones)))
    print("=== DONE ===")


try:
    main()
except Exception as e:
    print("[-] FATAL: " + str(e))
    traceback.print_exc()
    _write_placeholder()
