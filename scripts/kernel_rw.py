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

OUT_TXT     = os.path.join(WORKSPACE, "nk_kernel_rw.txt")
OUT_H       = os.path.join(WORKSPACE, "offsets.h")
OUT_JSON    = os.path.join(WORKSPACE, "offsets.json")
OUT_DISASM  = os.path.join(WORKSPACE, "disasm.txt")
OUT_KFD     = os.path.join(WORKSPACE, "kfd_offsets.h")

KERNEL_UNSLID_BASE = 0xFFFFFFF007004000
KERNEL_DATA_HI     = 0xFFFFFFF100000000
MASK48             = 0x0000FFFFFFFFFFFF
KTEXT_LO           = 0xFFF007004000
KTEXT_HI           = 0xFFF200000000
SYSENT_STRIDE      = 24


def _write_placeholder():
    for path, content in [
        (OUT_TXT,    "=== kernel_rw.py ===\n"),
        (OUT_H,      "#ifndef NK_OFFSETS_H\n#define NK_OFFSETS_H\n#endif\n"),
        (OUT_JSON,   "{}\n"),
        (OUT_DISASM, "=== no disasm ===\n"),
        (OUT_KFD,    "#ifndef KFD_OFFSETS_H\n#define KFD_OFFSETS_H\n#endif\n"),
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
    "rootvnode":   "0xFFFFFFF007CA0CF8",
}

ACCESSOR_SPECS = {
    "proc_pid":                    ["_proc_pid", "proc_pid"],
    "proc_ppid":                   ["_proc_ppid", "proc_ppid"],
    "proc_p_list_le_next":         ["_proc_get_list_next", "proc_list_next"],
    "proc_p_list_le_prev":         ["_proc_get_list_prev"],
    "proc_p_proc_ro":              ["_proc_get_ro", "proc_get_ro"],
    "proc_p_fd":                   ["_proc_fd", "proc_fd"],
    "proc_p_flag":                 ["_proc_flag", "proc_flag"],
    "proc_p_textvp":               ["_proc_textvp", "proc_textvp"],
    "proc_p_name":                 ["_proc_name", "proc_name"],
    "proc_p_task":                 ["_proc_task", "proc_task"],
    "proc_ro_pr_task":             ["_proc_ro_get_task", "proc_ro_get_task"],
    "proc_ro_p_ucred":             ["_proc_ucred", "proc_ucred"],
    "task_bsd_info":               ["_get_bsdtask_info", "task_bsd_info"],
    "task_map":                    ["_task_vm_map", "task_vm_map", "get_task_map"],
    "task_threads_next":           ["_task_thread", "task_thread", "get_task_thread"],
    "task_itk_space":              ["_task_get_itk_space", "task_get_itk_space"],
    "task_itk_self":               ["_task_get_itk_self", "task_get_itk_self"],
    "task_task_exc_guard":         ["_task_get_exc_guard"],
    "task_t_flags":                ["_task_get_t_flags"],
    "thread_task_threads_next":    ["_thread_get_next", "thread_get_next"],
    "thread_ast":                  ["_thread_get_ast"],
    "thread_ctid":                 ["_thread_get_ctid"],
    "thread_options":              ["_thread_get_options"],
    "thread_t_tro":                ["_thread_get_tro"],
    "thread_ro_tro_task":          ["_thread_ro_get_task"],
    "thread_ro_tro_proc":          ["_thread_ro_get_proc"],
    "thread_machine_upcb":         ["_thread_get_upcb"],
    "thread_machine_contextdata":  ["_thread_get_contextdata"],
    "thread_machine_kstackptr":    ["_thread_get_kstackptr"],
    "thread_machine_jop_pid":      ["_thread_get_jop_pid"],
    "thread_machine_rop_pid":      ["_thread_get_rop_pid"],
    "thread_mutex_lck_mtx_data":   ["_thread_get_mutex"],
    "thread_guard_exc_info_code":  ["_thread_get_guard_exc_code"],
    "thread_mach_exc_info_exception_type": ["_thread_get_exc_type"],
    "thread_mach_exc_info_code":   ["_thread_get_mach_exc_code"],
    "thread_mach_exc_info_os_reason": ["_thread_get_mach_exc_os_reason"],
    "ucred_cr_label":              ["_kauth_cred_getlabel", "kauth_cred_getlabel"],
    "kauth_cred_uid":              ["_kauth_cred_getuid", "kauth_cred_getuid"],
    "kauth_cred_gid":              ["_kauth_cred_getgid", "kauth_cred_getgid"],
    "kauth_cred_ruid":             ["_kauth_cred_getruid"],
    "kauth_cred_rgid":             ["_kauth_cred_getrgid"],
    "kauth_cred_svuid":            ["_kauth_cred_getsvuid"],
    "kauth_cred_svgid":            ["_kauth_cred_getsvgid"],
    "kauth_cred_label":            ["_kauth_cred_getlabel"],
    "label_l_perpolicy_amfi":      ["_mac_label_get_amfi", "mac_label_get_amfi"],
    "label_l_perpolicy_sandbox":   ["_mac_label_get_sandbox"],
    "ipc_space_is_table":          ["_ipc_space_get_table", "ipc_space_get_table"],
    "ipc_space_active":            ["_ipc_space_get_active"],
    "ipc_entry_ie_object":         ["_ipc_entry_get_object"],
    "ipc_port_ip_kobject":         ["_ipc_port_get_kobject", "ipc_port_get_kobject"],
    "ipc_port_ip_receiver":        ["_ipc_port_get_receiver"],
    "ipc_port_ip_mscount":         ["_ipc_port_get_mscount"],
    "filedesc_fd_ofiles":          ["_fdp_get_ofiles", "fdp_get_ofiles"],
    "filedesc_fd_cdir":            ["_fdp_get_cdir", "fdp_get_cdir"],
    "fileproc_fp_glob":            ["_fp_get_fglob", "fp_get_fglob"],
    "fileproc_fp_fg":              ["_fp_get_fg", "fp_get_fg"],
    "fileglob_fg_data":            ["_fileglob_get_data"],
    "fileglob_fg_flag":            ["_fileglob_get_flag"],
    "vnode_v_iocount":             ["_vnode_get_iocount"],
    "vnode_v_writecount":          ["_vnode_get_writecount"],
    "vnode_v_flag":                ["_vnode_get_flag"],
    "vnode_v_mount":               ["_vnode_get_mount"],
    "vnode_v_parent":              ["_vnode_get_parent"],
    "vnode_v_data":                ["_vnode_get_data"],
    "vnode_v_name":                ["_vnode_get_name"],
    "vnode_v_usecount":            ["_vnode_get_usecount"],
    "vnode_v_ncchildren_tqh_first": ["_vnode_get_ncchildren_first"],
    "vnode_v_nclinks_lh_first":    ["_vnode_get_nclinks_first"],
    "mount_mnt_flag":              ["_mount_get_flag"],
    "namecache_nc_vp":             ["_namecache_get_vp"],
    "namecache_nc_child_tqe_next": ["_namecache_get_child_next"],
    "vm_map_hdr":                  ["_vm_map_get_header", "vm_map_get_header"],
    "vm_map_header_nentries":      ["_vm_map_header_get_nentries"],
    "vm_map_header_links_next":    ["_vm_map_header_get_next"],
    "vm_map_entry_links_next":     ["_vm_map_entry_get_next", "vm_map_entry_get_next"],
    "vm_map_entry_vme_object_or_delta": ["_vm_map_entry_get_object"],
    "vm_map_entry_vme_alias":      ["_vm_map_entry_get_alias"],
    "vm_object_vo_un1_vou_size":   ["_vm_object_get_size"],
    "vm_object_ref_count":         ["_vm_object_get_ref_count"],
    "vm_named_entry_backing_copy": ["_vm_named_entry_get_backing"],
    "vm_named_entry_size":         ["_vm_named_entry_get_size"],
    "socket_so_usecount":          ["_so_get_usecount"],
    "socket_so_proto":             ["_so_get_proto", "so_get_proto"],
    "socket_so_background_thread": ["_so_get_background_thread"],
    "inpcb_inp_list_le_next":      ["_inp_get_list_next"],
    "inpcb_inp_pcbinfo":           ["_inp_get_pcbinfo"],
    "inpcb_inp_socket":            ["_inp_get_socket", "inp_get_socket"],
    "inpcbinfo_ipi_zone":          ["_inpcbinfo_get_zone"],
    "inpcb_inp_depend6_inp6_icmp6filt": ["_inp_get_icmp6filt"],
    "inpcb_inp_depend6_inp6_chksum":    ["_inp_get_chksum"],
    "kalloc_type_view_kt_zv_zv_name": ["_kalloc_type_view_get_name"],
    "arm_kernel_saved_state_sp":   ["_arm_kernel_saved_state_get_sp"],
    "arm_saved_state64_lr":        ["_arm_saved_state64_get_lr"],
    "arm_saved_state64_pc":        ["_arm_saved_state64_get_pc"],
    "arm_saved_state_us_ss_64":    ["_arm_saved_state_get_us_ss"],
}

GLOBAL_ANCHORS = {
    "kernproc":          ["p != kernproc", "so != NULL || p == kernproc"],
    "allproc":           ["allproc"],
    "initproc":          ["initproc"],
    "kernel_map":        ["kernel_map"],
    "init_task":         ["init_task"],
    "task_list":         ["task_list"],
    "zone_map":          ["zone_map"],
    "zones_built":       ["zones_built"],
    "ipc_space_kernel":  ["ipc_space_kernel"],
    "rootvnode":         ["rootvnode"],
    "vm_map_kernel":     ["vm_map_enter"],
    "pmap_kernel":       ["pmap_kernel"],
    "task_init":         ["task_init @%s:%d"],
    "proc_find":         ["proc_find"],
}

KALLOC_ZONES = [
    "kalloc.type.var",
    "data.kalloc",
    "early.kalloc",
    "site.struct task",
    "site.struct proc",
    "site.struct thread",
    "site.struct ucred",
    "site.struct ipc_port",
    "site.struct ipc_space",
    "site.struct ipc_entry",
    "site.struct vm_map",
    "site.struct vm_map_entry",
    "site.struct vm_object",
    "site.struct vm_page",
    "site.struct fileproc",
    "site.struct fileglob",
    "site.struct vnode",
    "site.struct mount",
    "site.struct socket",
    "site.struct inpcb",
    "site.struct pipe",
]

PRIMITIVE_FUNCS = [
    "_copyin", "_copyout", "_copyinstr", "_copyoutstr",
    "_copyio", "_copyinmsg", "_copyoutmsg",
    "_kalloc_ext", "_kfree_ext", "_kalloc_canblock",
    "_kernel_memory_allocate", "_kmem_alloc", "_kmem_free",
    "_ipc_port_alloc", "_ipc_port_dealloc",
    "_ipc_space_alloc", "_ipc_space_dealloc",
    "_mach_port_allocate", "_mach_port_deallocate",
    "_task_reference", "_task_deallocate",
    "_proc_reference", "_proc_rele",
    "_zone_alloc", "_zone_free",
    "_vm_map_enter", "_vm_map_remove",
    "_pmap_enter", "_pmap_remove",
]

DISASM_TARGETS = list(set(list(ACCESSOR_SPECS.keys()) + PRIMITIVE_FUNCS + [
    "_sysent", "unix_syscall", "_mach_trap_table", "mach_call_munger",
]))


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
        print("[-] no symbols.json")
        return
    try:
        with open(SYMBOLS_JSON) as f:
            data = json.loads(f.read().strip() or "{}")
    except Exception as e:
        print("[-] symbols parse: {}".format(e))
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
    print("[+] symtable indexed: {}".format(len(_syms_index)))


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


def disasm_func(addr, max_lines=200):
    out = []
    f = func_at(addr)
    if f is None:
        f = ensure_func(addr)
    if f is None:
        return out
    try:
        listing = currentProgram.getListing()
        body = f.getBody()
        if body is None:
            return out
        insn = listing.getInstructionAt(body.getMinAddress())
        count = 0
        while insn is not None and body.contains(insn.getAddress()) and count < max_lines:
            try:
                a = _to_u(insn.getAddress().getOffset())
                w = read_u32(a) or 0
                mnem = insn.getMnemonicString().lower()
                txt = insn.toString()
                out.append("{:016X}  {:08X}  {:<10} {}".format(a, w, mnem, txt))
            except Exception:
                pass
            insn = insn.getNext()
            count += 1
    except Exception:
        pass
    return out


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
    except Exception as e:
        print("[-] write {}: {}".format(path, e))


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


def _walk_sysent(base, limit=1500):
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


def _collect_globals_by_symbol():
    print("[*] globals via symbol...")
    out = {}
    for label in ("kernproc", "allproc", "initproc", "kernel_task",
                  "kernel_map", "zone_map", "zones_built",
                  "ipc_space_kernel", "proc_list", "rootvnode",
                  "task_list", "pmap_kernel"):
        try:
            a = sym_get("_" + label) or sym_get(label)
            if a is not None and _validate_addr(a, "any"):
                out[label] = a
        except Exception:
            pass
    return out


def _collect_globals_by_anchors():
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


def _accessor_offset(field, names):
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
            for pat in [
                r"\*\([^)]*\*\)\s*\(\s*\w+\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)",
                r"return\s+\*\([^)]*\)\s*\(\s*\w+\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)",
                r"\(\s*\w+\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)",
            ]:
                for m in re.finditer(pat, code):
                    try:
                        off = int(m.group(1), 0)
                        if 0 < off < 0x2000:
                            return off, name
                    except Exception:
                        pass
        except Exception:
            pass
    return None, None


def _deref_var(var):
    if var is None:
        return None
    v = read_u64(var)
    if v is None:
        return None
    if not _is_data_ptr(v):
        return None
    return v


def _find_pid_offset(proc_ptr, candidates=(0x68, 0x70, 0x74, 0x78, 0x80, 0x84, 0x88)):
    for off in candidates:
        pid = read_u32(proc_ptr + off)
        if pid is not None and 0 < pid < 0x100000:
            return off, pid
    return None, None


def _ptr_in_range(p, lo, hi):
    return p is not None and lo <= p < hi


def _scan_struct(ptr, name, start, end, step, validator):
    out = []
    a = start
    while a < end:
        try:
            v = read_u64(ptr + a)
            if validator(v, a):
                out.append((a, v))
        except Exception:
            pass
        a += step
    return out


def _walk_proc(kernproc_var, globals):
    print("[*] walk proc...")
    out = {}

    proc_var = globals.get("kernproc") or _parse_addr(CONFIRMED_GLOBALS.get("kernproc"))
    proc_ptr = _deref_var(proc_var)
    if proc_ptr is None:
        proc_var = globals.get("allproc") or _parse_addr(CONFIRMED_GLOBALS.get("allproc"))
        proc_ptr = _deref_var(proc_var)
    if proc_ptr is None:
        print("[-] no proc ptr")
        return out

    print("[+] proc ptr = {}".format(fmt(proc_ptr)))

    pid_off, pid_val = _find_pid_offset(proc_ptr)
    if pid_off is not None:
        out["proc_p_pid"] = pid_off
        print("[+] proc_p_pid = 0x{:x} (pid={})".format(pid_off, pid_val))

    for off in range(0x08, 0x80, 8):
        v = read_u64(proc_ptr + off)
        if not _is_data_ptr(v):
            continue
        pid2 = read_u32(v + (pid_off if pid_off else 0x74))
        if pid2 is not None and 0 < pid2 < 0x100000:
            out["proc_p_list_le_next"] = off
            print("[+] proc_p_list_le_next = 0x{:x} (next pid={})".format(off, pid2))
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
            print("[+] proc_p_list_le_prev = 0x{:x}".format(off))
            break

    for off in range(0x08, 0x100, 8):
        v = read_u64(proc_ptr + off)
        if not _is_data_ptr(v):
            continue
        task_hint = read_u64(v + 0x18)
        if _is_data_ptr(task_hint):
            out["proc_p_proc_ro"] = off
            print("[+] proc_p_proc_ro = 0x{:x}".format(off))
            break

    for off in range(0x18, 0x80, 8):
        v = read_u64(proc_ptr + off)
        if not _is_data_ptr(v):
            continue
        f1 = read_u64(v)
        if _is_data_ptr(f1):
            out["proc_p_fd"] = off
            print("[+] proc_p_fd = 0x{:x}".format(off))
            break

    for off in range(0x08, 0x80, 8):
        v = read_u64(proc_ptr + off)
        if not _is_data_ptr(v):
            continue
        t = read_u64(v + 0x1C)
        if t is not None and (t & 0xFFFF) == 0:
            out.setdefault("proc_p_flag", off)

    for off in range(0x08, 0x100, 8):
        v = read_u64(proc_ptr + off)
        if not _is_data_ptr(v):
            continue
        vname = read_u64(v + 0xD0)
        if _is_data_ptr(vname):
            out["proc_p_textvp"] = off
            print("[+] proc_p_textvp = 0x{:x}".format(off))
            break

    for off in range(0x08, 0x100, 8):
        if read_u64(proc_ptr + off) is None:
            continue
        p1 = read_u64(proc_ptr + off + 8)
        if not _is_data_ptr(p1):
            continue
        try:
            buf = read_u64(proc_ptr + off)
            if buf is None:
                continue
            if 0 < (buf & 0xFFFFFFFF) < 0x100000:
                out.setdefault("proc_p_name", off)
        except Exception:
            pass

    ro_off = out.get("proc_p_proc_ro")
    if ro_off is not None:
        ro_ptr = read_u64(proc_ptr + ro_off)
        if ro_ptr is not None and _is_data_ptr(ro_ptr):
            print("[+] proc_ro ptr = {}".format(fmt(ro_ptr)))
            for off in range(0x08, 0x80, 8):
                v = read_u64(ro_ptr + off)
                if not _is_data_ptr(v):
                    continue
                task_map = read_u64(v + 0x28)
                if _is_data_ptr(task_map):
                    out["proc_ro_pr_task"] = off
                    print("[+] proc_ro_pr_task = 0x{:x}".format(off))
                    break
            for off in range(0x80, 0x180, 8):
                v = read_u64(ro_ptr + off)
                if not _is_data_ptr(v):
                    continue
                uid = read_u32(v + 0x18)
                if uid is not None and uid < 0x10000:
                    out["proc_ro_p_ucred"] = off
                    print("[+] proc_ro_p_ucred = 0x{:x} (uid={})".format(off, uid))
                    break
            ucred_off = out.get("proc_ro_p_ucred")
            if ucred_off is not None:
                uc = read_u64(ro_ptr + ucred_off)
                if uc is not None and _is_data_ptr(uc):
                    for off in range(0x40, 0x120, 8):
                        v = read_u64(uc + off)
                        if not _is_data_ptr(v):
                            continue
                        label_sz = read_u64(v + 0x20)
                        if label_sz is not None and 0 < label_sz < 0x10000:
                            out["ucred_cr_label"] = off
                            print("[+] ucred_cr_label = 0x{:x}".format(off))
                            break
                    label_off = out.get("ucred_cr_label")
                    if label_off is not None:
                        lbl = read_u64(uc + label_off)
                        if lbl is not None and _is_data_ptr(lbl):
                            for off in range(0x40, 0x120, 8):
                                v = read_u64(lbl + off)
                                if not _is_data_ptr(v):
                                    continue
                                z1 = read_u64(v + 0x08)
                                z2 = read_u64(v + 0x10)
                                if z1 is not None and z2 is not None:
                                    out.setdefault("label_l_perpolicy_amfi", off)
                                    out.setdefault("label_l_perpolicy_sandbox", off)
                                    break

    return out


def _walk_task(globals):
    print("[*] walk task...")
    out = {}

    task_var = globals.get("kernel_task") or _parse_addr(CONFIRMED_GLOBALS.get("kernel_task"))
    task_ptr = _deref_var(task_var)
    if task_ptr is None:
        print("[-] no task ptr")
        return out, None
    print("[+] kernel_task ptr = {}".format(fmt(task_ptr)))

    for off in range(0x18, 0x60, 8):
        v = read_u64(task_ptr + off)
        if not _is_data_ptr(v):
            continue
        hdr = read_u64(v + 0x08)
        if _is_data_ptr(hdr):
            out["task_map"] = off
            print("[+] task_map = 0x{:x}".format(off))
            break

    for off in range(0x40, 0x80, 8):
        v = read_u64(task_ptr + off)
        if not _is_data_ptr(v):
            continue
        t_next = read_u64(v)
        if _is_data_ptr(t_next):
            out["task_threads_next"] = off
            print("[+] task_threads_next = 0x{:x}".format(off))
            break

    for off in range(0x280, 0x3A0, 8):
        v = read_u64(task_ptr + off)
        if not _is_data_ptr(v):
            continue
        tbl = read_u64(v + 0x20)
        if _is_data_ptr(tbl):
            out["task_itk_space"] = off
            out["task_itk_self"] = off
            print("[+] task_itk_space = 0x{:x}".format(off))
            break

    for off in range(0x300, 0x420, 8):
        v = read_u64(task_ptr + off)
        if not _is_data_ptr(v):
            continue
        pid = read_u32(v + 0x74)
        if pid is not None and 0 < pid < 0x100000:
            out["task_bsd_info"] = off
            print("[+] task_bsd_info = 0x{:x} (pid={})".format(off, pid))
            break

    for off in range(0x380, 0x420, 8):
        v = read_u32(task_ptr + off)
        if v is not None and 0 <= v < 0x10000:
            out.setdefault("task_task_exc_guard", off)
            break

    for off in range(0x100, 0x200, 8):
        v = read_u64(task_ptr + off)
        if not _is_data_ptr(v):
            continue
        th = read_u64(v)
        if _is_data_ptr(th):
            out.setdefault("task_t_flags", off)
            break

    return out, task_ptr


def _walk_thread(task_ptr):
    print("[*] walk thread...")
    out = {}
    if task_ptr is None:
        return out, None

    threads_off = None
    for off in range(0x40, 0x80, 8):
        v = read_u64(task_ptr + off)
        if _is_data_ptr(v):
            th = read_u64(v)
            if _is_data_ptr(th):
                threads_off = off
                break
    if threads_off is None:
        return out, None

    threads_head = read_u64(task_ptr + threads_off)
    if threads_head is None or not _is_data_ptr(threads_head):
        return out, None
    thread_ptr = read_u64(threads_head)
    if thread_ptr is None or not _is_data_ptr(thread_ptr):
        return out, None

    print("[+] thread ptr = {}".format(fmt(thread_ptr)))

    for off in range(0x40, 0x80, 8):
        v = read_u64(thread_ptr + off)
        if _is_data_ptr(v):
            nxt = read_u64(v)
            if _is_data_ptr(nxt):
                out["thread_task_threads_next"] = off
                print("[+] thread_task_threads_next = 0x{:x}".format(off))
                break

    for off in range(0x100, 0x400, 4):
        v = read_u32(thread_ptr + off)
        if v is not None and v < 0x1000:
            out.setdefault("thread_ast", off)
            break

    for off in range(0x280, 0x400, 8):
        v = read_u64(thread_ptr + off)
        if not _is_data_ptr(v):
            continue
        c = read_u64(v + 0x08)
        if _is_data_ptr(c):
            out.setdefault("thread_machine_contextdata", off)
            break

    for off in range(0x2A0, 0x400, 8):
        v = read_u64(thread_ptr + off)
        if not _is_data_ptr(v):
            continue
        d = read_u64(v)
        if _is_data_ptr(d):
            out.setdefault("thread_mutex_lck_mtx_data", off)
            break

    for off in range(0x300, 0x420, 8):
        v = read_u64(thread_ptr + off)
        if not _is_data_ptr(v):
            continue
        tr = read_u64(v + 0x10)
        if _is_data_ptr(tr):
            out["thread_t_tro"] = off
            print("[+] thread_t_tro = 0x{:x}".format(off))
            tro_ptr = v
            for o2 in range(0x08, 0x80, 8):
                p = read_u64(tro_ptr + o2)
                if not _is_data_ptr(p):
                    continue
                pid2 = read_u32(p + 0x74)
                if pid2 is not None and 0 < pid2 < 0x100000:
                    out["thread_ro_tro_proc"] = o2
                    print("[+] thread_ro_tro_proc = 0x{:x}".format(o2))
                    break
            for o2 in range(0x08, 0x80, 8):
                p = read_u64(tro_ptr + o2)
                if not _is_data_ptr(p):
                    continue
                m = read_u64(p + 0x28)
                if _is_data_ptr(m):
                    out["thread_ro_tro_task"] = o2
                    print("[+] thread_ro_tro_task = 0x{:x}".format(o2))
                    break
            break

    for off in range(0x350, 0x420, 8):
        v = read_u64(thread_ptr + off)
        if v is not None and 0 < (v & 0xFFFFFFFF) < 0x100000:
            out.setdefault("thread_machine_kstackptr", off)
            break

    for off in range(0x3A0, 0x420, 8):
        v = read_u64(thread_ptr + off)
        if v is not None and 0 < v < 0x100000:
            out.setdefault("thread_ctid", off)
            break

    for off in range(0x3B0, 0x420, 4):
        v = read_u32(thread_ptr + off)
        if v is not None and 0 < v < 0x10000:
            out.setdefault("thread_options", off)
            break

    for off in range(0x50, 0x120, 4):
        v = read_u32(thread_ptr + off)
        if v is not None and 0 < v < 0x10:
            out.setdefault("thread_mach_exc_info_exception_type", off)
            break

    for off in range(0x100, 0x180, 4):
        v = read_u32(thread_ptr + off)
        if v is not None and 0 <= v < 0x10000:
            out.setdefault("thread_guard_exc_info_code", off)
            break

    for off in range(0x3C0, 0x420, 8):
        v = read_u64(thread_ptr + off)
        if _is_data_ptr(v):
            r = read_u64(v + 0x08)
            if _is_data_ptr(r):
                out.setdefault("thread_mach_exc_info_os_reason", off)
                break

    return out, thread_ptr


def _walk_ipc(task_ptr):
    print("[*] walk ipc...")
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
                print("[+] ipc_space_is_table = 0x{:x}".format(off))
                break

    for off in range(0x08, 0x40, 4):
        v = read_u32(ispace + off)
        if v is not None and 0 <= v < 0x1000:
            out.setdefault("ipc_space_active", off)

    table_off = out.get("ipc_space_is_table")
    if table_off is None:
        return out

    table = read_u64(ispace + table_off)
    if table is None or not _is_data_ptr(table):
        return out

    entries = []
    for i in range(0, 4):
        e = read_u64(table + i * 0x18)
        if e is not None and (_is_data_ptr(e) or e == 0):
            entries.append(e)
    if len(entries) >= 2:
        out["sizeof_ipc_entry"] = 0x18

    for off in range(0x00, 0x20, 8):
        v = read_u64(table + off)
        if _is_data_ptr(v):
            out.setdefault("ipc_entry_ie_object", off)
            first_port = v
            for po in range(0x40, 0xA0, 8):
                r = read_u64(first_port + po)
                if _is_data_ptr(r):
                    out.setdefault("ipc_port_ip_receiver", po)
                    break
            for po in range(0x40, 0xA0, 8):
                k = read_u64(first_port + po)
                if _is_data_ptr(k):
                    out.setdefault("ipc_port_ip_kobject", po)
                    break
            break

    return out


def _walk_vm(task_ptr):
    print("[*] walk vm...")
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
            out["vm_map_header_links_next"] = off
            out["vm_map_header_nentries"] = off
            print("[+] vm_map_hdr = 0x{:x}".format(off))
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
            for eo in range(0x00, 0x30, 8):
                e = read_u64(first_entry + eo)
                if _is_data_ptr(e):
                    out.setdefault("vm_map_entry_vme_alias", eo)
                    break
            for eo in range(0x30, 0x60, 8):
                e = read_u64(first_entry + eo)
                if _is_data_ptr(e):
                    out.setdefault("vm_map_entry_vme_object_or_delta", eo)
                    vm_obj = e
                    for oo in range(0x10, 0x40, 8):
                        r = read_u32(vm_obj + oo)
                        if r is not None and 0 <= r < 0x100000:
                            out.setdefault("vm_object_ref_count", oo)
                            break
                    for oo in range(0x18, 0x40, 8):
                        s = read_u64(vm_obj + oo)
                        if s is not None and 0 < s < 0x100000000:
                            out.setdefault("vm_object_vo_un1_vou_size", oo)
                            break
                    break
            break

    return out


def _walk_vnode(proc_ptr, ro_ptr):
    print("[*] walk vnode...")
    out = {}
    vnode = None
    for src in (proc_ptr, ro_ptr):
        if src is None:
            continue
        for off in range(0x08, 0x100, 8):
            v = read_u64(src + off)
            if not _is_data_ptr(v):
                continue
            use = read_u32(v + 0xB8)
            if use is not None and 0 < use < 0x10000:
                vnode = v
                out["proc_p_textvp"] = off
                break
        if vnode is not None:
            break
    if vnode is None:
        return out

    print("[+] vnode ptr = {}".format(fmt(vnode)))

    for off in range(0x80, 0x120, 8):
        v = read_u64(vnode + off)
        if _is_data_ptr(v):
            out["vnode_v_name"] = off
            break

    for off in range(0x80, 0x120, 8):
        v = read_u64(vnode + off)
        if not _is_data_ptr(v):
            continue
        m = read_u32(v + 0x70)
        if m is not None:
            out["vnode_v_mount"] = off
            break

    for off in range(0x40, 0x80, 4):
        v = read_u8(vnode + off)
        if v is not None and 0 < v < 0x20:
            out["vnode_v_flag"] = off
            break

    for off in range(0xA0, 0xC0, 4):
        v = read_u32(vnode + off)
        if v is not None and 0 < v < 0x100000:
            out["vnode_v_usecount"] = off
            break

    for off in range(0xA0, 0xC0, 4):
        v = read_u32(vnode + off)
        if v is not None and 0 < v < 0x100000:
            out.setdefault("vnode_v_iocount", off)
            break

    for off in range(0xA0, 0xC0, 4):
        v = read_u32(vnode + off)
        if v is not None and 0 < v < 0x100000:
            out.setdefault("vnode_v_writecount", off)
            break

    for off in range(0x08, 0x40, 8):
        v = read_u64(vnode + off)
        if _is_data_ptr(v):
            out.setdefault("vnode_v_ncchildren_tqh_first", off)
            break

    for off in range(0x08, 0x40, 8):
        v = read_u64(vnode + off)
        if _is_data_ptr(v):
            out.setdefault("vnode_v_nclinks_lh_first", off)
            break

    for off in range(0x08, 0x40, 8):
        v = read_u64(vnode + off)
        if not _is_data_ptr(v):
            continue
        use = read_u32(v + 0xB8)
        if use is not None and 0 < use < 0x10000:
            out.setdefault("vnode_v_parent", off)
            break

    for off in range(0x08, 0x40, 8):
        v = read_u64(vnode + off)
        if not _is_data_ptr(v):
            continue
        use = read_u32(v + 0xB8)
        if use is not None and 0 < use < 0x10000:
            out.setdefault("vnode_v_data", off)
            break

    if "vnode_v_mount" in out:
        mnt = read_u64(vnode + out["vnode_v_mount"])
        if mnt is not None and _is_data_ptr(mnt):
            for off in range(0x40, 0xA0, 4):
                v = read_u32(mnt + off)
                if v is not None and 0 < v < 0x1000000:
                    out["mount_mnt_flag"] = off
                    break

    return out


def _walk_fd(proc_ptr):
    print("[*] walk fd...")
    out = {}
    if proc_ptr is None:
        return out

    fd_off = None
    for off in range(0x18, 0x80, 8):
        v = read_u64(proc_ptr + off)
        if not _is_data_ptr(v):
            continue
        first = read_u64(v)
        if _is_data_ptr(first):
            fd_off = off
            break
    if fd_off is None:
        return out

    fd_ptr = read_u64(proc_ptr + fd_off)
    if fd_ptr is None or not _is_data_ptr(fd_ptr):
        return out

    for off in range(0x08, 0x60, 8):
        v = read_u64(fd_ptr + off)
        if not _is_data_ptr(v):
            continue
        f1 = read_u64(v)
        if _is_data_ptr(f1):
            out["filedesc_fd_ofiles"] = off
            print("[+] filedesc_fd_ofiles = 0x{:x}".format(off))
            ofiles = v
            first_fp = read_u64(ofiles)
            if _is_data_ptr(first_fp):
                for fo in range(0x08, 0x40, 8):
                    g = read_u64(first_fp + fo)
                    if _is_data_ptr(g):
                        out.setdefault("fileproc_fp_glob", fo)
                        fg = g
                        for go in range(0x08, 0x60, 8):
                            d = read_u64(fg + go)
                            if _is_data_ptr(d):
                                out.setdefault("fileglob_fg_data", go)
                                break
                        for go in range(0x08, 0x60, 4):
                            fl = read_u32(fg + go)
                            if fl is not None and fl < 0x100000:
                                out.setdefault("fileglob_fg_flag", go)
                                break
                        break
            break

    for off in range(0x18, 0x80, 8):
        v = read_u64(fd_ptr + off)
        if not _is_data_ptr(v):
            continue
        t = read_u64(v + 0xB8)
        if t is not None and 0 < t < 0x100000:
            out.setdefault("filedesc_fd_cdir", off)
            break

    for off in range(0x08, 0x40, 8):
        v = read_u64(fd_ptr + off)
        if _is_data_ptr(v):
            out.setdefault("fileproc_fp_fg", off)
            break

    return out


def _walk_socket(task_ptr):
    print("[*] walk socket...")
    out = {}
    try:
        for s in ("com.apple.net", "com.apple.network"):
            sa = _str_addr(s)
            if sa is None:
                continue
            for xr in xrefs_to(sa):
                f = func_at(xr)
                if f is None:
                    continue
                code = decompile(f)
                if not code:
                    continue
                for m in re.finditer(r"\+\s*(0x[0-9a-fA-F]+)", code):
                    try:
                        off = int(m.group(1), 16)
                        if 0x10 < off < 0x400:
                            out.setdefault("socket_so_proto_hint", off)
                            break
                    except Exception:
                        pass
    except Exception:
        pass

    for a, n in syms_named("so_get_proto"):
        f = ensure_func(a)
        code = decompile(f)
        if not code:
            continue
        for m in re.finditer(r"return\s+\*\([^)]*\)\s*\(\s*\w+\s*\+\s*(0x[0-9a-fA-F]+)", code):
            try:
                off = int(m.group(1), 16)
                if 0 < off < 0x400:
                    out["socket_so_proto"] = off
                    break
            except Exception:
                pass
        break

    for a, n in syms_named("so_get_usecount"):
        f = ensure_func(a)
        code = decompile(f)
        if not code:
            continue
        for m in re.finditer(r"return\s+\*\([^)]*\)\s*\(\s*\w+\s*\+\s*(0x[0-9a-fA-F]+)", code):
            try:
                off = int(m.group(1), 16)
                if 0 < off < 0x400:
                    out["socket_so_usecount"] = off
                    break
            except Exception:
                pass
        break

    for a, n in syms_named("inp_get_socket"):
        f = ensure_func(a)
        code = decompile(f)
        if not code:
            continue
        for m in re.finditer(r"return\s+\*\([^)]*\)\s*\(\s*\w+\s*\+\s*(0x[0-9a-fA-F]+)", code):
            try:
                off = int(m.group(1), 16)
                if 0 < off < 0x400:
                    out["inpcb_inp_socket"] = off
                    break
            except Exception:
                pass
        break

    return out


def _find_primitive_funcs():
    print("[*] primitive funcs...")
    out = {}
    for name in PRIMITIVE_FUNCS:
        try:
            a = sym_get(name)
            if a is not None and _validate_addr(a, "ktext"):
                out[name] = a
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
                out[z] = kv[0]
        except Exception:
            pass
    return out


def _disasm_all(found_offsets, primitives):
    print("[*] disassembling...")
    lines = []
    lines.append("=== DISASM ===")
    lines.append("")

    for field, off in sorted(found_offsets.items()):
        names = ACCESSOR_SPECS.get(field, [])
        for name in names:
            hits = syms_named(name)
            if not hits:
                continue
            a, n = hits[0]
            if not _validate_addr(a, "ktext"):
                continue
            lines.append("=== {} ({}) @ {} ===".format(field, n, fmt(a)))
            lines.append("")
            for l in disasm_func(a):
                lines.append(l)
            lines.append("")
            f = func_at(a)
            code = decompile(f)
            if code:
                lines.append("--- decompiled ---")
                lines.append(code)
                lines.append("")
            break

    for name, a in sorted(primitives.items()):
        if not _validate_addr(a, "ktext"):
            continue
        lines.append("=== {} @ {} ===".format(name, fmt(a)))
        lines.append("")
        for l in disasm_func(a):
            lines.append(l)
        lines.append("")
        f = func_at(a)
        code = decompile(f)
        if code:
            lines.append("--- decompiled ---")
            lines.append(code)
            lines.append("")
        lines.append("")

    return lines


def main():
    print("=== kernel_rw.py ===")
    try:
        print("[*] program: " + currentProgram.getName())
    except Exception:
        pass

    report = []
    hdr    = []
    jout   = {}

    _load_symbols()
    _build_strings()

    try:
        img_base = int(currentProgram.getImageBase().getOffset()) & 0xFFFFFFFFFFFFFFFF
    except Exception:
        img_base = KERNEL_UNSLID_BASE

    report.append("=== BASE ===")
    report.append("image_base  = " + fmt(img_base))
    report.append("unslid_base = " + fmt(KERNEL_UNSLID_BASE))
    jout["kernel_base"] = fmt(KERNEL_UNSLID_BASE)
    jout["image_base"]  = fmt(img_base)

    print("[*] sysent...")
    sysent_base, sysent_src = _find_sysent()
    sysent_entries = _walk_sysent(sysent_base) if sysent_base else []
    report.append("")
    report.append("=== SYSENT ===")
    report.append("source  = " + sysent_src)
    report.append("base    = " + fmt(sysent_base))
    report.append("entries = " + str(len(sysent_entries)))
    jout["sysent_base"]  = fmt(sysent_base) if sysent_base else None
    jout["sysent_count"] = len(sysent_entries)

    print("[*] mach traps...")
    mt_base, mt_src = _find_mach_traps()
    report.append("")
    report.append("=== MACH TRAPS ===")
    report.append("base = " + fmt(mt_base))
    jout["mach_trap_table"] = fmt(mt_base) if mt_base else None

    print("[*] globals...")
    globals_map = {}
    try:
        globals_map.update(_collect_globals_by_symbol())
    except Exception as e:
        print("[-] globals_sym: {}".format(e))
    try:
        globals_map.update(_collect_globals_by_anchors())
    except Exception as e:
        print("[-] globals_adrp: {}".format(e))

    for k, v in CONFIRMED_GLOBALS.items():
        p = _parse_addr(v)
        if p is not None:
            globals_map.setdefault(k, p)

    report.append("")
    report.append("=== GLOBALS ===")
    for k in sorted(globals_map.keys()):
        report.append("  {:<20} {}".format(k, fmt(globals_map[k])))

    report.append("")
    report.append("=== ACCESSOR OFFSETS ===")
    accessor_result = {}
    for field, names in sorted(ACCESSOR_SPECS.items()):
        off, fname = _accessor_offset(field, names)
        if off is not None:
            accessor_result[field] = off
            report.append("  {:<40} 0x{:X}  ({})".format(field, off, fname))
    jout["accessor"] = accessor_result

    print("[*] walk proc...")
    proc_offsets = _walk_proc(globals_map.get("kernproc"), globals_map)
    print("[*] walk task...")
    task_offsets, task_ptr = _walk_task(globals_map)
    print("[*] walk thread...")
    thread_offsets, thread_ptr = _walk_thread(task_ptr)
    print("[*] walk ipc...")
    ipc_offsets = _walk_ipc(task_ptr)
    print("[*] walk vm...")
    vm_offsets = _walk_vm(task_ptr)
    print("[*] walk vnode...")
    vnode_offsets = _walk_vnode(None, None)
    print("[*] walk fd...")
    fd_offsets = _walk_fd(None)
    print("[*] walk socket...")
    sock_offsets = _walk_socket(task_ptr)

    all_offsets = {}
    for src in (accessor_result, proc_offsets, task_offsets, thread_offsets,
                ipc_offsets, vm_offsets, vnode_offsets, fd_offsets, sock_offsets):
        for k, v in src.items():
            if isinstance(v, int):
                all_offsets[k] = v

    report.append("")
    report.append("=== KFD OFFSETS ===")
    for k in sorted(all_offsets.keys()):
        report.append("  {:<45} 0x{:X}".format("off_" + k, all_offsets[k]))

    jout["offsets"] = dict(all_offsets)
    jout["globals"] = {k: fmt(v) for k, v in globals_map.items()}

    print("[*] primitives...")
    primitives = _find_primitive_funcs()
    kfree_ext = sym_get("_kfree_ext") or _parse_addr(CONFIRMED.get("kfree_ext"))
    kalloc_ext = _find_kalloc(kfree_ext) or _parse_addr(CONFIRMED.get("kalloc_ext"))
    ci = _parse_addr(CONFIRMED.get("copyin"))
    co = _parse_addr(CONFIRMED.get("copyout"))
    if ci:
        primitives["_copyin"] = ci
    if co:
        primitives["_copyout"] = co
    if kfree_ext:
        primitives["_kfree_ext"] = kfree_ext
    if kalloc_ext:
        primitives["_kalloc_ext"] = kalloc_ext

    report.append("")
    report.append("=== PRIMITIVES ===")
    for k, v in sorted(primitives.items()):
        report.append("  {:<30} {}".format(k, fmt(v)))
    jout["primitives"] = {k: fmt(v) for k, v in primitives.items()}

    print("[*] zones...")
    zones = _find_kalloc_zones()
    report.append("")
    report.append("=== ZONES ===")
    for k, v in sorted(zones.items()):
        report.append("  {:<45} {}".format(k, fmt(v)))
    jout["zones"] = {k: fmt(v) for k, v in zones.items()}

    jout["sptm"] = {
        "ctrr_lock_boot":             "0xFFFFFFF027006E62",
        "cpu_lock_system_registers":  "0xFFFFFFF0270B39B4",
        "sptm_determine_kernel_ctrr": "0xFFFFFFF0270B2224",
        "sptm_base":                  "0xFFFFFFF027004000",
    }

    jout["sysent_base"]  = fmt(sysent_base) if sysent_base else None
    jout["mach_trap_table"] = fmt(mt_base) if mt_base else None
    jout["kfree_ext"] = fmt(kfree_ext) if kfree_ext else None
    jout["kalloc_ext"] = fmt(kalloc_ext) if kalloc_ext else None
    jout["copyin"] = fmt(ci) if ci else None
    jout["copyout"] = fmt(co) if co else None
    jout["sysent_count"] = len(sysent_entries)

    try:
        write_lines(OUT_TXT, report)
        print("[+] wrote " + OUT_TXT)
    except Exception as e:
        print("[-] txt: {}".format(e))

    try:
        hdr_lines = ["#ifndef NK_OFFSETS_H", "#define NK_OFFSETS_H", ""]
        hdr_lines.append("#define NK_KERNEL_UNSLID_BASE " + fmt(KERNEL_UNSLID_BASE) + "ULL")
        hdr_lines.append("#define NK_SYSENT_BASE        " + fmt(sysent_base) + "ULL")
        hdr_lines.append("#define NK_SYSENT_COUNT       " + str(len(sysent_entries)))
        hdr_lines.append("#define NK_SYSENT_STRIDE      " + str(SYSENT_STRIDE))
        hdr_lines.append("#define NK_MACH_TRAP_TABLE    " + fmt(mt_base) + "ULL")
        hdr_lines.append("")
        for k, v in sorted(globals_map.items()):
            hdr_lines.append("#define NK_G_{:<30} {}ULL".format(k.upper(), fmt(v)))
        hdr_lines.append("")
        for k, v in sorted(all_offsets.items()):
            hdr_lines.append("#define OFF_{:<40} 0x{:X}".format(k.upper(), v))
        hdr_lines.append("")
        for k, v in sorted(primitives.items()):
            hdr_lines.append("#define NK_FN_{:<30} {}ULL".format(k.upper(), fmt(v)))
        hdr_lines.append("")
        for k, v in sorted(zones.items()):
            hdr_lines.append("#define NK_ZONE_{:<40} {}ULL".format(
                norm(k).upper()[:40], fmt(v)))
        hdr_lines.append("")
        hdr_lines.append("#endif")
        write_lines(OUT_H, hdr_lines)
        print("[+] wrote " + OUT_H)
    except Exception as e:
        print("[-] h: {}".format(e))

    try:
        kfd_lines = ["#ifndef KFD_OFFSETS_H", "#define KFD_OFFSETS_H", ""]
        for k, v in sorted(all_offsets.items()):
            kfd_lines.append("#define off_{:<45} 0x{:X}".format(k, v))
        kfd_lines.append("")
        for k, v in sorted(primitives.items()):
            kfd_lines.append("#define kfd_fn_{:<40} {}ULL".format(k.lstrip("_"), fmt(v)))
        kfd_lines.append("")
        kfd_lines.append("#endif")
        write_lines(OUT_KFD, kfd_lines)
        print("[+] wrote " + OUT_KFD)
    except Exception as e:
        print("[-] kfd: {}".format(e))

    try:
        disasm_lines = _disasm_all(all_offsets, primitives)
        write_lines(OUT_DISASM, disasm_lines)
        print("[+] wrote {} ({} lines)".format(OUT_DISASM, len(disasm_lines)))
    except Exception as e:
        print("[-] disasm: {}".format(e))

    try:
        with open(OUT_JSON, "w") as fh:
            fh.write(json.dumps(jout, indent=2, sort_keys=True))
        print("[+] wrote " + OUT_JSON)
    except Exception as e:
        print("[-] json: {}".format(e))

    print("")
    print("=== SUMMARY ===")
    print("  sysent_entries    {}".format(len(sysent_entries)))
    print("  globals           {}".format(len(globals_map)))
    print("  accessor_offsets  {}".format(len(accessor_result)))
    print("  total_offsets     {}".format(len(all_offsets)))
    print("  primitives        {}".format(len(primitives)))
    print("  zones             {}".format(len(zones)))
    print("=== DONE ===")


try:
    main()
except Exception as e:
    print("[-] FATAL: {}".format(e))
    traceback.print_exc()
    _write_placeholder()
