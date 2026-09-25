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

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
SYM = os.environ.get("SYMBOLS_JSON", os.path.join(WS, "symbols.json"))
OUT_H = os.path.join(WS, "offsets.h")
OUT_JSON = os.path.join(WS, "offsets.json")
OUT_KFD = os.path.join(WS, "kfd_offsets.h")
OUT_TXT = os.path.join(WS, "nk_kernel_rw.txt")
OUT_DIS = os.path.join(WS, "disasm.txt")

KBASE = 0xFFFFFFF007004000
MASK48 = 0x0000FFFFFFFFFFFF
KTEXT_LO = 0xFFF007004000
KTEXT_HI = 0xFFF200000000
STRIDE = 24

_sym = None
_strmap = None
_strlist = None
_symidx = None
_ifc = [None]
_okc = {}
_blocks = None

CONFIRMED = {
    "kernel_base": KBASE,
    "sysent_base": 0xFFFFFFF007C192A0,
    "mach_trap_table": 0xFFFFFFF007BE8018,
    "kfree_ext": 0xFFFFFFF00A201000,
    "kalloc_ext": 0xFFFFFFF00A200DCC,
    "copyin": 0xFFFFFFF00A7B9570,
    "copyout": 0xFFFFFFF00A2C6C28,
}
CONFIRMED_G = {
    "kernproc": 0xFFFFFFF007BBF040,
    "kernel_task": 0xFFFFFFF00700DC70,
    "zone_map": 0xFFFFFFF00AD6A800,
    "task_list": 0xFFFFFFF0080D93F0,
    "kernel_map": 0xFFFFFFF007BBE228,
    "allproc": 0xFFFFFFF007BBF048,
}
CONFIRMED_S = {
    "proc_p_pid": 0x74,
    "proc_ro_p_ucred": 0xB8,
    "thread_task_threads_next": 0x50,
}

ACCESSORS = {
    "proc_p_pid": ["_proc_pid", "proc_pid"],
    "proc_p_ppid": ["_proc_ppid", "proc_ppid"],
    "proc_p_list_le_next": ["_proc_get_list_next"],
    "proc_p_list_le_prev": ["_proc_get_list_prev"],
    "proc_p_proc_ro": ["_proc_get_ro"],
    "proc_p_fd": ["_proc_fd", "proc_fd"],
    "proc_p_flag": ["_proc_flag", "proc_flag"],
    "proc_p_textvp": ["_proc_textvp", "proc_textvp"],
    "proc_p_name": ["_proc_name", "proc_name"],
    "proc_p_task": ["_proc_task", "proc_task"],
    "proc_ro_pr_task": ["_proc_ro_get_task"],
    "proc_ro_p_ucred": ["_proc_ucred", "proc_ucred"],
    "task_bsd_info": ["_get_bsdtask_info", "task_bsd_info"],
    "task_map": ["_task_vm_map", "task_vm_map"],
    "task_threads_next": ["_task_thread", "task_thread"],
    "task_itk_space": ["_task_get_itk_space"],
    "task_itk_self": ["_task_get_itk_self"],
    "task_task_exc_guard": ["_task_get_exc_guard"],
    "task_t_flags": ["_task_get_t_flags"],
    "thread_task_threads_next": ["_thread_get_next"],
    "thread_ast": ["_thread_get_ast"],
    "thread_ctid": ["_thread_get_ctid"],
    "thread_options": ["_thread_get_options"],
    "thread_t_tro": ["_thread_get_tro"],
    "thread_ro_tro_task": ["_thread_ro_get_task"],
    "thread_ro_tro_proc": ["_thread_ro_get_proc"],
    "thread_machine_upcb": ["_thread_get_upcb"],
    "thread_machine_contextdata": ["_thread_get_contextdata"],
    "thread_machine_kstackptr": ["_thread_get_kstackptr"],
    "thread_mutex_lck_mtx_data": ["_thread_get_mutex"],
    "thread_mach_exc_info_exception_type": ["_thread_get_exc_type"],
    "thread_guard_exc_info_code": ["_thread_get_guard_exc_code"],
    "ucred_cr_label": ["_kauth_cred_getlabel", "kauth_cred_getlabel"],
    "kauth_cred_uid": ["_kauth_cred_getuid", "kauth_cred_getuid"],
    "kauth_cred_gid": ["_kauth_cred_getgid", "kauth_cred_getgid"],
    "kauth_cred_ruid": ["_kauth_cred_getruid"],
    "kauth_cred_rgid": ["_kauth_cred_getrgid"],
    "kauth_cred_svuid": ["_kauth_cred_getsvuid"],
    "kauth_cred_svgid": ["_kauth_cred_getsvgid"],
    "label_l_perpolicy_amfi": ["_mac_label_get_amfi"],
    "label_l_perpolicy_sandbox": ["_mac_label_get_sandbox"],
    "ipc_space_is_table": ["_ipc_space_get_table", "ipc_space_get_table"],
    "ipc_space_active": ["_ipc_space_get_active"],
    "ipc_entry_ie_object": ["_ipc_entry_get_object"],
    "ipc_port_ip_kobject": ["_ipc_port_get_kobject", "ipc_port_get_kobject"],
    "ipc_port_ip_receiver": ["_ipc_port_get_receiver"],
    "ipc_port_ip_mscount": ["_ipc_port_get_mscount"],
    "filedesc_fd_ofiles": ["_fdp_get_ofiles", "fdp_get_ofiles"],
    "filedesc_fd_cdir": ["_fdp_get_cdir", "fdp_get_cdir"],
    "fileproc_fp_glob": ["_fp_get_fglob", "fp_get_fglob"],
    "fileproc_fp_fg": ["_fp_get_fg", "fp_get_fg"],
    "fileglob_fg_data": ["_fileglob_get_data"],
    "fileglob_fg_flag": ["_fileglob_get_flag"],
    "vnode_v_iocount": ["_vnode_get_iocount"],
    "vnode_v_writecount": ["_vnode_get_writecount"],
    "vnode_v_flag": ["_vnode_get_flag"],
    "vnode_v_mount": ["_vnode_get_mount"],
    "vnode_v_parent": ["_vnode_get_parent"],
    "vnode_v_data": ["_vnode_get_data"],
    "vnode_v_name": ["_vnode_get_name"],
    "vnode_v_usecount": ["_vnode_get_usecount"],
    "vnode_v_ncchildren_tqh_first": ["_vnode_get_ncchildren_first"],
    "vnode_v_nclinks_lh_first": ["_vnode_get_nclinks_first"],
    "mount_mnt_flag": ["_mount_get_flag"],
    "namecache_nc_vp": ["_namecache_get_vp"],
    "namecache_nc_child_tqe_next": ["_namecache_get_child_next"],
    "vm_map_hdr": ["_vm_map_get_header"],
    "vm_map_pmap": ["_vm_map_get_pmap"],
    "vm_map_ref_count": ["_vm_map_get_ref_count"],
    "vm_map_header_nentries": ["_vm_map_header_get_nentries"],
    "vm_map_entry_links_next": ["_vm_map_entry_get_next"],
    "vm_map_entry_vme_object_or_delta": ["_vm_map_entry_get_object"],
    "vm_map_entry_vme_alias": ["_vm_map_entry_get_alias"],
    "vm_object_vo_un1_vou_size": ["_vm_object_get_size"],
    "vm_object_ref_count": ["_vm_object_get_ref_count"],
    "vm_named_entry_backing_copy": ["_vm_named_entry_get_backing"],
    "vm_named_entry_size": ["_vm_named_entry_get_size"],
    "vm_page_vmp_offset": ["_vm_page_get_offset"],
    "vm_page_vmp_object": ["_vm_page_get_object"],
    "vm_page_vmp_next": ["_vm_page_get_next"],
    "socket_so_usecount": ["_so_get_usecount"],
    "socket_so_proto": ["_so_get_proto", "so_get_proto"],
    "socket_so_background_thread": ["_so_get_background_thread"],
    "inpcb_inp_list_le_next": ["_inp_get_list_next"],
    "inpcb_inp_pcbinfo": ["_inp_get_pcbinfo"],
    "inpcb_inp_socket": ["_inp_get_socket", "inp_get_socket"],
    "inpcbinfo_ipi_zone": ["_inpcbinfo_get_zone"],
    "inpcb_inp_depend6_inp6_icmp6filt": ["_inp_get_icmp6filt"],
    "inpcb_inp_depend6_inp6_chksum": ["_inp_get_chksum"],
    "kalloc_type_view_kt_zv_zv_name": ["_kalloc_type_view_get_name"],
    "arm_kernel_saved_state_sp": ["_arm_kernel_saved_state_get_sp"],
    "arm_saved_state64_lr": ["_arm_saved_state64_get_lr"],
    "arm_saved_state64_pc": ["_arm_saved_state64_get_pc"],
    "arm_saved_state_us_ss_64": ["_arm_saved_state_get_us_ss"],
}

DISASM_TARGETS = [
    ("_copyin", 0xFFFFFFF00A7B9570),
    ("_copyout", 0xFFFFFFF00A2C6C28),
    ("_kalloc_ext", 0xFFFFFFF00A200DCC),
    ("_kfree_ext", 0xFFFFFFF00A201000),
]

MAX_DIS_LINES = 60
MAX_DIS_TOTAL = 5000


def _u(v):
    return int(v) & 0xFFFFFFFFFFFFFFFF


def _pa(v):
    if v is None:
        return None
    try:
        if isinstance(v, (int, long)):
            return _u(v)
        if not isinstance(v, string_types):
            return None
        s = v.strip()
        if not s:
            return None
        if s.startswith(("0x", "0X")):
            return _u(int(s, 16))
        return _u(int(s, 10))
    except Exception:
        return None


def fmt(v):
    if v is None:
        return "0x0"
    if isinstance(v, string_types):
        p = _pa(v)
        if p is None:
            return "0x0"
        return "0x{:016X}".format(p)
    try:
        return "0x{:016X}".format(int(v) & 0xFFFFFFFFFFFFFFFF)
    except Exception:
        return "0x0"


def tl(v):
    v = int(v) & 0xFFFFFFFFFFFFFFFF
    if v >= 0x8000000000000000:
        v -= 0x10000000000000000
    return v


def sa(a):
    try:
        return toAddr(tl(a))
    except Exception:
        return None


def r64(a):
    if a is None:
        return None
    ga = sa(a)
    if ga is None:
        return None
    try:
        return int(currentProgram.getMemory().getLong(ga)) & 0xFFFFFFFFFFFFFFFF
    except Exception:
        return None


def r32(a):
    if a is None:
        return None
    ga = sa(a)
    if ga is None:
        return None
    try:
        return int(currentProgram.getMemory().getInt(ga)) & 0xFFFFFFFF
    except Exception:
        return None


def r16(a):
    if a is None:
        return None
    ga = sa(a)
    if ga is None:
        return None
    try:
        return int(currentProgram.getMemory().getShort(ga)) & 0xFFFF
    except Exception:
        return None


def r8(a):
    if a is None:
        return None
    ga = sa(a)
    if ga is None:
        return None
    try:
        return int(currentProgram.getMemory().getByte(ga)) & 0xFF
    except Exception:
        return None


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
                s = _u(b.getStart().getOffset())
                e = _u(b.getEnd().getOffset())
                out.append((s, e, b.getName(), b.isExecute()))
            except Exception:
                pass
    except Exception:
        pass
    _blocks = out
    return out


def inblk(a):
    for s, e, n, x in blocks():
        if s <= a < e:
            return (s, e, n, x)
    return None


def is_data_ptr(p):
    if p is None or p == 0:
        return False
    b = inblk(p)
    if b is None:
        return False
    return not b[3]


def is_ktext(p):
    if p is None or p == 0:
        return False
    lo = p & MASK48
    return KTEXT_LO <= lo < KTEXT_HI


def strip_pac(p):
    return 0xFFFFFFF000000000 | (p & MASK48)


def is_exec(p):
    if p is None:
        return False
    b = inblk(strip_pac(p))
    if b is None:
        return False
    return b[3]


def va(a, t="any"):
    if a in _okc:
        return _okc[a]
    r = False
    if a is not None:
        b = inblk(a)
        if b is not None:
            if t == "ktext":
                r = b[3]
            elif t == "data":
                r = not b[3]
            else:
                r = True
    _okc[a] = r
    return r


def _load_sym():
    global _sym
    if _sym is not None:
        return
    _sym = {}
    if not os.path.exists(SYM):
        return
    try:
        with open(SYM) as f:
            data = json.loads(f.read().strip() or "{}")
    except Exception:
        return

    def _add(n, a):
        if not n or a is None:
            return
        try:
            if not isinstance(n, string_types):
                n = str(n)
            n = n.strip()
            v = _pa(a)
            if v is None or v < 0xFFFF000000000000:
                return
            _sym[n] = v
            if not n.startswith("_"):
                _sym["_" + n] = v
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
                    ka = _pa(k)
                    va = _pa(v)
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
    print("[+] symbols: {}".format(len(_sym)))


def sget(n):
    _load_sym()
    if n in _sym:
        return _sym[n]
    b = n.lstrip("_")
    if b in _sym:
        return _sym[b]
    if "_" + n in _sym:
        return _sym["_" + n]
    lo = n.lower()
    for k, v in _sym.items():
        if k.lower() == lo:
            return v
    return None


def _build_strs():
    global _strmap, _strlist
    if _strmap is not None:
        return
    _strmap = {}
    _strlist = []
    try:
        it = currentProgram.getListing().getDefinedData(True)
        while it.hasNext():
            d = it.next()
            try:
                if not d.hasStringValue():
                    continue
                v = d.getValue()
                if v is None:
                    continue
                s = str(v)
                a = _u(d.getAddress().getOffset())
                _strlist.append((a, s))
                if s not in _strmap:
                    _strmap[s] = a
            except Exception:
                pass
    except Exception:
        pass
    print("[+] strings: {}".format(len(_strlist)))


def straddr(s):
    _build_strs()
    a = _strmap.get(s)
    if a is not None:
        return a
    for a, v in _strlist:
        if s in v:
            return a
    return None


def _build_idx():
    global _symidx
    if _symidx is not None:
        return
    _symidx = []
    seen = set()
    try:
        for sym in currentProgram.getSymbolTable().getAllSymbols(True):
            try:
                a = _u(sym.getAddress().getOffset())
                n = sym.getName()
                if (a, n) in seen:
                    continue
                _symidx.append((a, n))
                seen.add((a, n))
            except Exception:
                pass
    except Exception:
        pass
    _load_sym()
    for n, a in _sym.items():
        if (a, n) in seen:
            continue
        _symidx.append((a, n))
        seen.add((a, n))
    print("[+] symidx: {}".format(len(_symidx)))


def snamed(p):
    _build_idx()
    out = []
    for a, n in _symidx:
        if p in n:
            out.append((a, n))
    return out


def xrefs(a):
    if a is None:
        return []
    out = []
    try:
        ga = sa(a)
        if ga is None:
            return out
        for r in currentProgram.getReferenceManager().getReferencesTo(ga):
            out.append(_u(r.getFromAddress().getOffset()))
    except Exception:
        pass
    return out


def fat(a):
    if a is None:
        return None
    try:
        ga = sa(a)
        if ga is None:
            return None
        f = getFunctionAt(ga)
        if f:
            return f
    except Exception:
        pass
    try:
        ga = sa(a)
        if ga is None:
            return None
        return getFunctionContaining(ga)
    except Exception:
        return None


def efunc(a):
    f = fat(a)
    if f:
        return f
    if a is None:
        return None
    try:
        ga = sa(a)
        if ga is None:
            return None
        disassemble(ga)
    except Exception:
        pass
    try:
        ga = sa(a)
        if ga is None:
            return None
        return createFunction(ga, None)
    except Exception:
        return None


def dec(f):
    if f is None:
        return ""
    try:
        from ghidra.app.decompiler import DecompInterface, DecompileOptions
        from ghidra.util.task import ConsoleTaskMonitor
        if _ifc[0] is None:
            ifc = DecompInterface()
            ifc.setOptions(DecompileOptions())
            ifc.openProgram(currentProgram)
            _ifc[0] = ifc
        r = _ifc[0].decompileFunction(f, 60, ConsoleTaskMonitor())
        if r.decompileCompleted():
            return r.getDecompiledFunction().getC()
    except Exception:
        pass
    return ""


def dis(a, maxl=MAX_DIS_LINES):
    out = []
    f = fat(a)
    if f is None:
        f = efunc(a)
    if f is None:
        return out
    try:
        listing = currentProgram.getListing()
        body = f.getBody()
        if body is None:
            return out
        insn = listing.getInstructionAt(body.getMinAddress())
        c = 0
        while insn is not None and body.contains(insn.getAddress()) and c < maxl:
            try:
                aa = _u(insn.getAddress().getOffset())
                w = r32(aa) or 0
                mn = insn.getMnemonicString().lower()
                tx = insn.toString()
                out.append("{:016X}  {:08X}  {:<10} {}".format(aa, w, mn, tx))
            except Exception:
                pass
            insn = insn.getNext()
            c += 1
    except Exception:
        pass
    return out


def adrp_pairs(f):
    if f is None:
        return []
    out = []
    try:
        listing = currentProgram.getListing()
        body = f.getBody()
        if body is None:
            return out
        insn = listing.getInstructionAt(body.getMinAddress())
        prev = None
        while insn is not None and body.contains(insn.getAddress()):
            mn = insn.getMnemonicString().lower()
            tx = insn.toString()
            if mn == "adrp":
                try:
                    toks = tx.replace(",", " ").split()
                    pg = int(toks[-1], 16) & 0xFFFFFFFFFFFFFFFF
                    prev = (toks[1], pg)
                except Exception:
                    prev = None
            elif prev is not None and mn in ("add", "ldr", "ldrsw", "ldp", "ldur", "ldrh", "ldrb"):
                try:
                    toks = tx.replace(",", " ").replace("[", " ").replace("]", " ").split()
                    imm = 0
                    for t in toks:
                        if t.startswith("#0x"):
                            imm = int(t[3:], 16)
                            break
                    br = toks[2] if len(toks) > 2 else ""
                    if br == prev[0]:
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


def wl(path, lines):
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


def nm(s):
    return re.sub(r"[^A-Za-z0-9_]", "_", s)


def _dec_sysent(raw):
    if raw is None:
        return None
    if raw >= 0xFFFF000000000000:
        return strip_pac(raw)
    lo = raw & 0xFFFFFFFF
    if lo < 0x10000000:
        return (KBASE + lo) & 0xFFFFFFFFFFFFFFFF
    return None


def _sysent_e(base, i):
    try:
        a = base + i * STRIDE
        rc = r64(a)
        if rc is None:
            return None
        call = _dec_sysent(rc)
        if call is None or call == 0:
            return None
        if not is_ktext(call) or not is_exec(call):
            return None
        rt = r32(a + 16)
        na = r16(a + 20)
        ab = r16(a + 22)
        if rt is None or rt > 9:
            return None
        if na is None or na > 12:
            return None
        if ab is None or ab > 96:
            return None
        return (call, na, rt, ab)
    except Exception:
        return None


def _score_sys(base, samp=12):
    h = 0
    z = 0
    for i in range(samp):
        e = _sysent_e(base, i)
        if e is None:
            z += 1
            if z >= 3:
                return h
            continue
        z = 0
        try:
            _, na, rt, ab = e
            h += 2 if (na > 0 or rt > 0 or ab > 0) else 1
        except Exception:
            pass
    return h


def find_sysent():
    for n in ("_sysent", "sysent", "_unix_sysent"):
        a = sget(n)
        if a and _score_sys(a) >= 10:
            return a, "sym:" + n
    try:
        bl = []
        for b in currentProgram.getMemory().getBlocks():
            try:
                if not b.isInitialized():
                    continue
                s = _u(b.getStart().getOffset())
                if not (0xFFFFFFF000000000 <= s < 0xFFFFFFF200000000):
                    continue
                n = b.getName()
                if "DATA_CONST" in n:
                    p = 0
                elif n.startswith("__const"):
                    p = 1
                elif "DATA" in n:
                    p = 2
                else:
                    continue
                bl.append((p, b))
            except Exception:
                pass
        bl.sort(key=lambda x: x[0])
        for _, b in bl:
            try:
                s = _u(b.getStart().getOffset())
                e = _u(b.getEnd().getOffset())
                hi = min(e, s + 0x200000)
                if hi - s < STRIDE * 200:
                    continue
                a = s + ((-s) % 8)
                ma = hi - STRIDE * 200
                best = None
                bs = 0
                while a < ma:
                    sc = _score_sys(a)
                    if sc > bs:
                        bs = sc
                        best = a
                        if sc >= 20:
                            return a, "scan:" + b.getName()
                    a += 8
                if best is not None and bs >= 12:
                    return best, "scan:" + b.getName()
            except Exception:
                pass
    except Exception:
        pass
    return None, "NOT_FOUND"


def find_mt():
    for n in ("_mach_trap_table", "mach_trap_table"):
        a = sget(n)
        if a:
            return a, "sym:" + n
    return None, "NOT_FOUND"


def deref_var(v):
    if v is None:
        return None
    x = r64(v)
    if x is None:
        return None
    if not is_data_ptr(x):
        return None
    return x


def find_pid_off(pp, cands=(0x74, 0x68, 0x70, 0x78, 0x80)):
    for o in cands:
        p = r32(pp + o)
        if p is not None and 0 < p < 0x100000:
            return o, p
    return None, None


def walk_proc(pp, pidoff):
    out = {}
    if pidoff is not None:
        out["proc_p_pid"] = pidoff
    for o in range(0x08, 0x80, 8):
        v = r64(pp + o)
        if not is_data_ptr(v):
            continue
        p2 = r32(v + (pidoff if pidoff else 0x74))
        if p2 is not None and 0 < p2 < 0x100000:
            out["proc_p_list_le_next"] = o
            break
    for o in range(0x08, 0x80, 8):
        if o == out.get("proc_p_list_le_next"):
            continue
        v = r64(pp + o)
        if not is_data_ptr(v):
            continue
        p2 = r32(v + (pidoff if pidoff else 0x74))
        if p2 is not None and 0 < p2 < 0x100000:
            out["proc_p_list_le_prev"] = o
            break
    for o in range(0x08, 0x100, 8):
        v = r64(pp + o)
        if not is_data_ptr(v):
            continue
        if is_data_ptr(r64(v + 0x18)):
            out["proc_p_proc_ro"] = o
            break
    for o in range(0x18, 0x80, 8):
        v = r64(pp + o)
        if not is_data_ptr(v):
            continue
        if is_data_ptr(r64(v)):
            out["proc_p_fd"] = o
            break
    return out


def walk_task(tp):
    out = {}
    if tp is None:
        return out
    for o in range(0x18, 0x60, 8):
        v = r64(tp + o)
        if not is_data_ptr(v):
            continue
        if is_data_ptr(r64(v + 0x08)):
            out["task_map"] = o
            break
    for o in range(0x40, 0x80, 8):
        v = r64(tp + o)
        if not is_data_ptr(v):
            continue
        if is_data_ptr(r64(v)):
            out["task_threads_next"] = o
            break
    for o in range(0x280, 0x3A0, 8):
        v = r64(tp + o)
        if not is_data_ptr(v):
            continue
        if is_data_ptr(r64(v + 0x20)):
            out["task_itk_space"] = o
            out["task_itk_self"] = o
            break
    for o in range(0x300, 0x420, 8):
        v = r64(tp + o)
        if not is_data_ptr(v):
            continue
        p = r32(v + 0x74)
        if p is not None and 0 < p < 0x100000:
            out["task_bsd_info"] = o
            break
    return out


def acc_search():
    out = {}
    for f, names in ACCESSORS.items():
        for n in names:
            hits = snamed(n)
            if not hits:
                continue
            a, nn = hits[0]
            fn = efunc(a)
            if fn is None:
                continue
            code = dec(fn)
            if not code:
                continue
            found = False
            for pat in [
                r"\*\([^)]*\*\)\s*\(\s*\w+\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)",
                r"return\s+\*\([^)]*\)\s*\(\s*\w+\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)",
            ]:
                for m in re.finditer(pat, code):
                    try:
                        o = int(m.group(1), 0)
                        if 0 < o < 0x2000:
                            out[f] = o
                            found = True
                            break
                    except Exception:
                        pass
                if found:
                    break
            if found:
                break
    return out


def glob_sym():
    out = {}
    for lb in ("allproc", "rootvnode", "proc_find", "task_init",
               "vm_map_kernel", "kernel_map", "chroot", "cs_enforcement",
               "kalloc_type", "mac_policy"):
        a = sget("_" + lb) or sget(lb)
        if a is not None and va(a, "any"):
            out[lb] = a
    return out


def zones():
    out = {}
    for z in ("kalloc.type.var", "data.kalloc", "early.kalloc",
              "site.struct task", "site.struct proc", "site.struct thread",
              "site.struct ucred", "site.struct ipc_port", "site.struct ipc_entry",
              "site.struct fileproc", "site.struct fileglob", "site.struct vnode",
              "site.struct mount", "site.struct socket", "site.struct inpcb",
              "site.struct pipe", "site.struct vm_page"):
        a = straddr(z)
        if a is None:
            continue
        kv = [x for x in xrefs(a) if 0xFFFFFFF000000000 <= x < 0xFFFFFFF200000000]
        if kv:
            out[z] = kv[0]
    return out


def disasm_all():
    lines = []
    lines.append("=== DISASM ===")
    lines.append("")
    total = 0
    for name, addr in DISASM_TARGETS:
        if not va(addr, "ktext"):
            continue
        lines.append("=== {} @ {} ===".format(name, fmt(addr)))
        lines.append("")
        for l in dis(addr):
            lines.append(l)
            total += 1
            if total > MAX_DIS_TOTAL:
                lines.append("=== TRUNCATED ===")
                return lines
        lines.append("")
        f = fat(addr)
        code = dec(f)
        if code:
            lines.append("--- decompile ---")
            for l in code.split("\n")[:80]:
                lines.append(l)
            lines.append("")
    return lines


def main():
    print("=== kernel_rw.py ===")
    report = []
    jout = {}

    try:
        img = int(currentProgram.getImageBase().getOffset()) & 0xFFFFFFFFFFFFFFFF
    except Exception:
        img = KBASE

    report.append("=== BASE ===")
    report.append("image_base  = " + fmt(img))
    report.append("kernel_base = " + fmt(KBASE))
    jout["kernel_base"] = fmt(KBASE)
    jout["image_base"] = fmt(img)

    print("[*] sysent...")
    sb, ss = find_sysent()
    n_sys = 0
    if sb:
        for i in range(2000):
            if _sysent_e(sb, i) is None:
                break
            n_sys = i + 1
    report.append("")
    report.append("=== SYSENT ===")
    report.append("source  = " + ss)
    report.append("base    = " + fmt(sb))
    report.append("count   = " + str(n_sys))
    jout["sysent_base"] = fmt(sb) if sb else None
    jout["sysent_count"] = n_sys
    jout["sysent_stride"] = STRIDE

    print("[*] mach_traps...")
    mt, ms = find_mt()
    report.append("")
    report.append("=== MACH TRAPS ===")
    report.append("base = " + fmt(mt))
    jout["mach_trap_table"] = fmt(mt) if mt else None

    print("[*] globals...")
    g = glob_sym()
    for k, v in CONFIRMED_G.items():
        g[k] = v
    report.append("")
    report.append("=== GLOBALS ===")
    for k in sorted(g.keys()):
        report.append("  {:<20} {}".format(k, fmt(g[k])))
    jout["globals"] = {k: fmt(v) for k, v in g.items()}

    print("[*] accessors...")
    acc = acc_search()
    report.append("")
    report.append("=== ACCESSORS ===")
    for k in sorted(acc.keys()):
        report.append("  {:<40} 0x{:X}".format(k, acc[k]))

    print("[*] walk proc...")
    kp = g.get("kernproc")
    kpp = deref_var(kp)
    pid_off = None
    pw = {}
    if kpp is not None:
        pid_off, _ = find_pid_off(kpp)
        pw = walk_proc(kpp, pid_off)
        report.append("")
        report.append("=== PROC ===")
        report.append("ptr = " + fmt(kpp))
        for k in sorted(pw.keys()):
            report.append("  {:<30} 0x{:X}".format(k, pw[k]))

    print("[*] walk task...")
    tp = deref_var(g.get("kernel_task"))
    tw = walk_task(tp)
    report.append("")
    report.append("=== TASK ===")
    report.append("ptr = " + fmt(tp))
    for k in sorted(tw.keys()):
        report.append("  {:<30} 0x{:X}".format(k, tw[k]))

    merged = {}
    for src in (CONFIRMED_S, acc, pw, tw):
        for k, v in src.items():
            if isinstance(v, int):
                merged[k] = v

    report.append("")
    report.append("=== OFFSETS ===")
    for k in sorted(merged.keys()):
        report.append("  off_{:<40} 0x{:X}".format(k, merged[k]))
    jout["offsets"] = merged

    prim = {
        "_copyin": CONFIRMED["copyin"],
        "_copyout": CONFIRMED["copyout"],
        "_kalloc_ext": CONFIRMED["kalloc_ext"],
        "_kfree_ext": CONFIRMED["kfree_ext"],
    }
    jout["primitives"] = {k: fmt(v) for k, v in prim.items()}

    zs = zones()
    report.append("")
    report.append("=== ZONES ===")
    for k in sorted(zs.keys()):
        report.append("  {:<45} {}".format(k, fmt(zs[k])))
    jout["zones"] = {k: fmt(v) for k, v in zs.items()}

    jout["sptm"] = {
        "sptm_base": "0xFFFFFFF027004000",
        "ctrr_lock_boot": "0xFFFFFFF027006E62",
        "cpu_lock_system_registers": "0xFFFFFFF0270B39B4",
        "sptm_determine_kernel_ctrr": "0xFFFFFFF0270B2224",
        "sptm_bootstrap": "0xFFFFFFF0270D21CC",
        "sptm_map": "0xFFFFFFF0270E97BC",
        "sptm_page_table": "0xFFFFFFF0270D13D4",
        "sptm_panic": "0xFFFFFFF0270BEE18",
        "sptm_region": "0xFFFFFFF0270ECEF0",
    }

    wl(OUT_TXT, report)

    hd = ["#ifndef NK_OFFSETS_H", "#define NK_OFFSETS_H", ""]
    hd.append("#define NK_KERNEL_BASE " + fmt(KBASE) + "ULL")
    hd.append("#define NK_SYSENT_BASE " + fmt(sb) + "ULL")
    hd.append("#define NK_SYSENT_COUNT " + str(n_sys))
    hd.append("#define NK_MACH_TRAP_TABLE " + fmt(mt) + "ULL")
    hd.append("")
    for k in sorted(g.keys()):
        hd.append("#define NK_G_{:<30} {}ULL".format(k.upper(), fmt(g[k])))
    hd.append("")
    for k in sorted(merged.keys()):
        hd.append("#define off_{:<40} 0x{:X}".format(k, merged[k]))
    hd.append("")
    for k in sorted(prim.keys()):
        hd.append("#define NK_FN_{:<30} {}ULL".format(k.upper(), fmt(prim[k])))
    hd.append("")
    for k in sorted(zs.keys()):
        hd.append("#define NK_ZONE_{:<40} {}ULL".format(nm(k).upper()[:40], fmt(zs[k])))
    hd.append("")
    hd.append("#endif")
    wl(OUT_H, hd)

    kd = ["#ifndef KFD_OFFSETS_H", "#define KFD_OFFSETS_H", ""]
    for k in sorted(merged.keys()):
        kd.append("#define off_{:<45} 0x{:X}".format(k, merged[k]))
    kd.append("")
    for k in sorted(prim.keys()):
        kd.append("#define kfd_fn_{:<40} {}ULL".format(k.lstrip("_"), fmt(prim[k])))
    kd.append("")
    kd.append("#endif")
    wl(OUT_KFD, kd)

    print("[*] disasm...")
    dis_lines = disasm_all()
    wl(OUT_DIS, dis_lines)

    try:
        with open(OUT_JSON, "w") as fh:
            fh.write(json.dumps(jout, indent=2, sort_keys=True))
    except Exception:
        pass

    print("")
    print("=== SUMMARY ===")
    print("  sysent_count  {}".format(n_sys))
    print("  globals       {}".format(len(g)))
    print("  accessors     {}".format(len(acc)))
    print("  offsets       {}".format(len(merged)))
    print("  zones         {}".format(len(zs)))
    print("  disasm_lines  {}".format(len(dis_lines)))
    print("=== DONE ===")


try:
    main()
except Exception as e:
    print("[-] FATAL: " + str(e))
    traceback.print_exc()