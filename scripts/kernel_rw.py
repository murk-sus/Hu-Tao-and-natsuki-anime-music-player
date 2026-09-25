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
OUT = os.path.join(WS, "result.txt")
OUT_JSON = os.path.join(WS, "offsets.json")

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
_blocks = None

CONF_G = {
    "kernproc": 0xFFFFFFF007BBF040,
    "kernel_task": 0xFFFFFFF00700DC70,
    "zone_map": 0xFFFFFFF00AD6A800,
    "task_list": 0xFFFFFFF0080D93F0,
    "kernel_map": 0xFFFFFFF007BBE228,
    "allproc": 0xFFFFFFF007BBF048,
}
CONF_S = {
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
    "thread_task_threads_next": ["_thread_get_next"],
    "thread_t_tro": ["_thread_get_tro"],
    "thread_ro_tro_task": ["_thread_ro_get_task"],
    "thread_ro_tro_proc": ["_thread_ro_get_proc"],
    "kauth_cred_uid": ["_kauth_cred_getuid", "kauth_cred_getuid"],
    "kauth_cred_gid": ["_kauth_cred_getgid", "kauth_cred_getgid"],
    "ucred_cr_label": ["_kauth_cred_getlabel", "kauth_cred_getlabel"],
    "ipc_space_is_table": ["_ipc_space_get_table"],
    "ipc_port_ip_kobject": ["_ipc_port_get_kobject"],
    "filedesc_fd_ofiles": ["_fdp_get_ofiles"],
    "fileproc_fp_glob": ["_fp_get_fglob"],
    "vnode_v_data": ["_vnode_get_data"],
    "vnode_v_mount": ["_vnode_get_mount"],
    "vnode_v_name": ["_vnode_get_name"],
    "vnode_v_usecount": ["_vnode_get_usecount"],
    "vm_map_hdr": ["_vm_map_get_header"],
    "vm_map_pmap": ["_vm_map_get_pmap"],
    "vm_map_entry_links_next": ["_vm_map_entry_get_next"],
    "vm_map_entry_vme_object_or_delta": ["_vm_map_entry_get_object"],
    "vm_object_vo_un1_vou_size": ["_vm_object_get_size"],
    "socket_so_proto": ["_so_get_proto", "so_get_proto"],
    "inpcb_inp_socket": ["_inp_get_socket"],
    "arm_saved_state64_pc": ["_arm_saved_state64_get_pc"],
    "arm_saved_state64_lr": ["_arm_saved_state64_get_lr"],
}

# Функции для дизасма. Адрес 0 = искать по символам/строкам.
DISASM = [
    ("_copyin", 0xFFFFFFF00A7B9570),
    ("_copyout", 0xFFFFFFF00A2C6C28),
    ("_kalloc_ext", 0xFFFFFFF00A200DCC),
    ("_kfree_ext", 0xFFFFFFF00A201000),
]

# NECP функции ищем по символам.
NECP_NAMES = [
    "_necp_client_copy_result",
    "necp_client_copy_result",
    "_necp_client_remove_flow",
    "necp_client_remove_flow",
    "_necp_client_add_flow",
    "necp_client_add_flow",
    "_necp_flow_alloc",
    "necp_flow_alloc",
    "_necp_client_fd_copyout",
    "necp_client_fd_copyout",
    "_necp_open",
    "necp_open",
    "_necp_action",
    "necp_action",
]

# Syscalls для NEСP, обрабатываем их через sysent.
NECP_SYSCALLS = [501, 502]

MAX_DIS = 120
MAX_TOTAL = 15000


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
    try:
        return "0x{:016X}".format(int(v) & 0xFFFFFFFFFFFFFFFF)
    except Exception:
        return "0x0"


def sa(a):
    try:
        return toAddr(int(a) & 0xFFFFFFFFFFFFFFFF)
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
                            b.getName(), b.isExecute()))
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


def is_data_ptr(p):
    if p is None or p == 0:
        return False
    b = inblk(p)
    if b is None:
        return False
    return not b[3]


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


def dis(a, maxl=MAX_DIS):
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


# ВАЖНО: правильный декодер для iOS 27 sysent
def _dec_sysent(raw):
    if raw is None or raw == 0:
        return None
    return (raw & MASK48) | 0xFFFFFFF000000000


def _sysent_e(base, i):
    try:
        a = base + i * STRIDE
        rc = r64(a)
        if rc is None:
            return None
        call = _dec_sysent(rc)
        if call is None:
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


def find_pid(pp, cands=(0x74, 0x68, 0x70, 0x78, 0x80)):
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
            for pat in [
                r"\*\([^)]*\*\)\s*\(\s*\w+\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)",
                r"return\s+\*\([^)]*\)\s*\(\s*\w+\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)",
            ]:
                done = False
                for m in re.finditer(pat, code):
                    try:
                        o = int(m.group(1), 0)
                        if 0 < o < 0x2000:
                            out[f] = o
                            done = True
                            break
                    except Exception:
                        pass
                if done:
                    break
            if f in out:
                break
    return out


def glob_sym():
    out = {}
    for lb in ("allproc", "rootvnode", "proc_find", "task_init",
               "vm_map_kernel", "kernel_map", "chroot",
               "cs_enforcement", "kalloc_type", "mac_policy"):
        a = sget("_" + lb) or sget(lb)
        if a is not None:
            blk = inblk(a)
            if blk is not None and not blk[3]:
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


def find_necp_funcs():
    out = {}
    for n in NECP_NAMES:
        a = sget(n)
        if a is not None and is_ktext(a):
            out[n] = a
    return out


def dump_dis(name, addr, lines):
    lines.append("")
    lines.append("=== {} @ {} ===".format(name, fmt(addr)))
    lines.append("")
    for l in dis(addr):
        lines.append(l)
    f = fat(addr)
    code = dec(f)
    if code:
        lines.append("--- decompile ---")
        for l in code.split("\n")[:150]:
            lines.append(l)


def main():
    print("=== kernel_rw.py ===")

    _load_sym()
    _build_strs()
    _build_idx()
    print("[+] sym: {}".format(len(_sym or {})))
    print("[+] str: {}".format(len(_strlist or [])))

    lines = []
    lines.append("=== BASE ===")
    lines.append("kernel_base = " + fmt(KBASE))

    print("[*] sysent...")
    sb, ss = find_sysent()
    n_sys = 0
    sysent_list = []
    if sb:
        for i in range(2000):
            e = _sysent_e(sb, i)
            if e is None:
                break
            n_sys = i + 1
            sysent_list.append((i, e))
    lines.append("")
    lines.append("=== SYSENT ===")
    lines.append("source = " + ss)
    lines.append("base   = " + fmt(sb))
    lines.append("count  = " + str(n_sys))
    lines.append("")
    for i, e in sysent_list[:30]:
        call, na, rt, ab = e
        f = fat(call)
        nm = f.getName() if f else "?"
        lines.append("  #{} {} narg={} ret={} name={}".format(
            i, fmt(call), na, rt, nm))

    # NECP syscalls
    if sysent_list:
        lines.append("")
        lines.append("=== NECP SYSCALLS ===")
        for idx in NECP_SYSCALLS:
            if idx < len(sysent_list):
                call, na, rt, ab = sysent_list[idx][1]
                lines.append("  syscall {} handler = {} narg={}".format(idx, fmt(call), na))
                dump_dis("syscall_{}".format(idx), call, lines)

    print("[*] mach_traps...")
    mt, ms = find_mt()
    lines.append("")
    lines.append("=== MACH TRAPS ===")
    lines.append("base = " + fmt(mt))

    print("[*] globals...")
    g = glob_sym()
    for k, v in CONF_G.items():
        g[k] = v
    lines.append("")
    lines.append("=== GLOBALS ===")
    for k in sorted(g.keys()):
        lines.append("  {:<20} {}".format(k, fmt(g[k])))

    print("[*] accessors...")
    acc = acc_search()
    lines.append("")
    lines.append("=== ACCESSORS ===")
    for k in sorted(acc.keys()):
        lines.append("  {:<40} 0x{:X}".format(k, acc[k]))

    print("[*] proc walk...")
    kp = g.get("kernproc")
    kpp = deref_var(kp)
    pid_off = None
    pw = {}
    if kpp is not None:
        pid_off, _ = find_pid(kpp)
        pw = walk_proc(kpp, pid_off)
    lines.append("")
    lines.append("=== PROC ===")
    lines.append("kernproc_var = " + fmt(kp))
    lines.append("proc_ptr     = " + fmt(kpp))
    for k in sorted(pw.keys()):
        lines.append("  {:<30} 0x{:X}".format(k, pw[k]))

    print("[*] task walk...")
    tp = deref_var(g.get("kernel_task"))
    tw = walk_task(tp)
    lines.append("")
    lines.append("=== TASK ===")
    lines.append("kernel_task_var = " + fmt(g.get("kernel_task")))
    lines.append("task_ptr        = " + fmt(tp))
    for k in sorted(tw.keys()):
        lines.append("  {:<30} 0x{:X}".format(k, tw[k]))

    # merged
    merged = {}
    for src in (CONF_S, acc, pw, tw):
        for k, v in src.items():
            if isinstance(v, int):
                merged[k] = v
    lines.append("")
    lines.append("=== OFFSETS (final) ===")
    for k in sorted(merged.keys()):
        lines.append("  off_{:<40} 0x{:X}".format(k, merged[k]))

    print("[*] zones...")
    zs = zones()
    lines.append("")
    lines.append("=== ZONES ===")
    for k in sorted(zs.keys()):
        lines.append("  {:<45} {}".format(k, fmt(zs[k])))

    print("[*] necp funcs...")
    necp = find_necp_funcs()
    lines.append("")
    lines.append("=== NECP SYMBOLS ===")
    for k in sorted(necp.keys()):
        lines.append("  {:<40} {}".format(k, fmt(necp[k])))

    print("[*] disasm hardcoded...")
    for name, addr in DISASM:
        if not is_ktext(addr):
            continue
        dump_dis(name, addr, lines)

    print("[*] disasm necp symbols...")
    for k in sorted(necp.keys()):
        dump_dis(k, necp[k], lines)

    # JSON
    jout = {
        "kernel_base": fmt(KBASE),
        "sysent_base": fmt(sb) if sb else None,
        "sysent_count": n_sys,
        "mach_trap_table": fmt(mt) if mt else None,
        "globals": {k: fmt(v) for k, v in g.items()},
        "offsets": merged,
        "accessors": acc,
        "zones": {k: fmt(v) for k, v in zs.items()},
        "necp_symbols": {k: fmt(v) for k, v in necp.items()},
    }
    try:
        with open(OUT_JSON, "w") as fh:
            fh.write(json.dumps(jout, indent=2, sort_keys=True))
    except Exception:
        pass

    # Обрезаем если разрастается
    if len(lines) > MAX_TOTAL:
        lines = lines[:MAX_TOTAL]
        lines.append("=== TRUNCATED ===")

    try:
        with open(OUT, "w") as fh:
            for l in lines:
                fh.write(l + "\n")
        print("[+] wrote " + OUT + " ({} lines)".format(len(lines)))
    except Exception as e:
        print("[-] write: " + str(e))

    print("=== SUMMARY ===")
    print("  sysent_count  {}".format(n_sys))
    print("  globals       {}".format(len(g)))
    print("  accessors     {}".format(len(acc)))
    print("  offsets       {}".format(len(merged)))
    print("  zones         {}".format(len(zs)))
    print("  necp_funcs    {}".format(len(necp)))
    print("=== DONE ===")


try:
    main()
except Exception as e:
    print("[-] FATAL: " + str(e))
    traceback.print_exc()
    try:
        with open(OUT, "w") as fh:
            fh.write("FATAL: " + str(e) + "\n")
    except Exception:
        pass