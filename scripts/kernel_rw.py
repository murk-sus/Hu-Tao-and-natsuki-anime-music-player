# -*- coding: utf-8 -*-
#
# SINGLE self-contained kernel R/W offset collector.
# No dependencies on other scripts.
#
# Outputs:
#   nk_kernel_rw.txt   - human-readable report
#   offsets.h          - #define header for exploit code
#   offsets.json       - machine-readable

import os
import re
import json

try:
    string_types = (str, unicode)
except NameError:
    string_types = (str,)

WORKSPACE    = os.environ.get("GITHUB_WORKSPACE", "/tmp")
SYMBOLS_JSON = os.environ.get("SYMBOLS_JSON",
                 os.path.join(WORKSPACE, "symbols.json"))

OUT_TXT  = os.path.join(WORKSPACE, "nk_kernel_rw.txt")
OUT_H    = os.path.join(WORKSPACE, "offsets.h")
OUT_JSON = os.path.join(WORKSPACE, "offsets.json")

KERNEL_UNSLID_BASE = 0xFFFFFFF007004000
MASK48   = 0x0000FFFFFFFFFFFF
KTEXT_LO = 0xFFF007004000
KTEXT_HI = 0xFFF200000000
STRIDE   = 16

# ============================================================ state

_sym_cache    = None
_string_map   = None
_string_list  = None
_syms_index   = None
_IFC          = [None]

# ============================================================ basic

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
        return _to_u(int(s, 16) if s.startswith(("0x","0X")) else int(s, 10))
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


def is_kva(v):
    return v is not None and 0xFFFFFFF000000000 <= v < 0xFFFFFFF200000000


# ============================================================ symbols.json

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


# ============================================================ string cache

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


def find_str_contains(sub):
    _build_strings()
    return [(a, s) for a, s in _string_list if sub in s]


def _str_addr(s):
    a = find_str_exact(s)
    if a is not None:
        return a
    for a, _ in find_str_contains(s)[:1]:
        return a
    return None


# ============================================================ symbol table cache

def _build_symidx():
    global _syms_index
    if _syms_index is not None:
        return
    _syms_index = []
    st = currentProgram.getSymbolTable()
    try:
        for sym in st.getAllSymbols(True):
            try:
                _syms_index.append((_to_u(sym.getAddress().getOffset()),
                                    sym.getName()))
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


def syms_named(pat, include_junk=False):
    _build_symidx()
    out = []
    for a, n in _syms_index:
        if not include_junk and _is_junk(n):
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


# ============================================================ func/decompile

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
    if _IFC[0] is None:
        ifc = DecompInterface()
        ifc.setOptions(DecompileOptions())
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
        elif prev is not None and mn in ("add","ldr","str","ldrb","strb",
                                          "ldrh","strh","ldrsw","ldur","stur"):
            try:
                toks = txt.replace(",", " ").replace("[", " ").replace("]", " ").split()
                imm = 0
                for t in toks:
                    if t.startswith("#0x"):
                        imm = int(t[3:], 16); break
                base_reg = toks[2] if len(toks) > 2 else ""
                if base_reg == prev[0]:
                    tgt = (prev[1] + imm) & 0xFFFFFFFFFFFFFFFF
                    if lo <= tgt < hi:
                        out.append((_to_u(insn.getAddress().getOffset()), tgt, mn))
            except Exception:
                pass
            prev = None
        else:
            if mn not in ("nop","bti","pacibsp","hint"):
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


# ============================================================ PAC helpers

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


# ============================================================ ==== MAIN ====

def main():
    print("=== kernel_rw.py ===")
    print("[*] program: " + currentProgram.getName())

    _load_symbols()
    _build_strings()

    report = []
    hdr    = []
    json_out = {}

    img_base = int(currentProgram.getImageBase().getOffset()) & 0xFFFFFFFFFFFFFFFF

    # ---------------------------------------------------- 1. BASE
    report.append("=== [1] KERNEL BASE ===")
    report.append("image_base      = " + fmt(img_base))
    report.append("unslid_base     = " + fmt(KERNEL_UNSLID_BASE))
    report.append("KASLR slide     = <runtime only>")
    _vks = sym_get("_vm_kernel_slide")
    report.append("_vm_kernel_slide= " + (fmt(_vks) if _vks else "NOT_FOUND"))

    hdr.append("// === [1] BASE ===")
    hdr.append("#define NK_KERNEL_UNSLID_BASE   " + fmt(KERNEL_UNSLID_BASE) + "ULL")
    hdr.append("#define NK_IMAGE_BASE           " + fmt(img_base) + "ULL")
    hdr.append("")

    json_out["kernel_base"] = fmt(KERNEL_UNSLID_BASE)
    json_out["image_base"]  = fmt(img_base)

    # ---------------------------------------------------- 2. SYSENT
    print("[*] sysent discovery...")

    def _entry_ok(a):
        p = read_u64(a)
        if p is None: return (False, 0, 0, 0)
        if p == 0:    return (True, 0, 0, 0)
        if not _is_ktext(p) or not _is_exec(p):
            return (False, 0, 0, 0)
        return (True, _strip_pac(p), read_u32(a+8) or 0, read_u32(a+12) or 0)

    def _looks(base, need=40):
        if base is None or not (0xFFFFFFF000000000 <= base < 0xFFFFFFF200000000):
            return False
        hits = 0
        for i in range(need):
            if _entry_ok(base + i * STRIDE)[0]:
                hits += 1
        return hits >= need - 2

    def _walk(base, limit=1200):
        out = []
        bad = 0
        for i in range(limit):
            a = base + i * STRIDE
            ok, p, ab, _ = _entry_ok(a)
            if not ok:
                bad += 1
                if bad > 30: break
                continue
            bad = 0
            if p == 0:
                out.append((i, 0, 0, "NOSYS"))
                continue
            f = func_at(p)
            out.append((i, p, ab, f.getName() if f else "?"))
        return out

    sysent_base = None
    sysent_src  = "NOT_FOUND"

    for nm in ("_sysent","sysent","_unix_sysent","unix_sysent","_unix_sysent_table"):
        a = sym_get(nm)
        if a and _looks(a, 20):
            sysent_base = a; sysent_src = "sym:" + nm; break

    if sysent_base is None:
        for a, n in syms_named("sysent"):
            if _looks(a, 20):
                sysent_base = a; sysent_src = "ghidra:" + n; break

    if sysent_base is None:
        for name in ("unix_syscall64","unix_syscall","unix_syscall_return"):
            for a, n in funcs_named(name):
                f = ensure_func(a)
                if f is None: continue
                for _, tgt, _ in resolve_adrp_pairs(f):
                    if _looks(tgt, 20):
                        sysent_base = tgt; sysent_src = n + "_adrp"; break
                if sysent_base: break
            if sysent_base: break

    if sysent_base is None:
        print("[*] scanning blocks for sysent...")
        blocks = []
        for b in currentProgram.getMemory().getBlocks():
            if not b.isInitialized(): continue
            s = _to_u(b.getStart().getOffset())
            if not (0xFFFFFFF000000000 <= s < 0xFFFFFFF200000000): continue
            n = b.getName()
            if "DATA_CONST" in n: prio = 0
            elif n.startswith("__const"): prio = 1
            elif "DATA" in n: prio = 2
            else: continue
            blocks.append((prio, b))
        blocks.sort(key=lambda x: x[0])
        for _, b in blocks:
            s = _to_u(b.getStart().getOffset())
            e = _to_u(b.getEnd().getOffset())
            print("[*]   {} {} - {}".format(b.getName(), fmt(s), fmt(e)))
            if e - s < STRIDE * 100: continue
            a = s + ((-s) % 16)
            max_a = e - STRIDE * 100
            found = None
            while a < max_a:
                if not _entry_ok(a)[0]:
                    a += 16; continue
                quick = sum(1 for k in (1,2,3) if _entry_ok(a+k*STRIDE)[0])
                if quick < 3:
                    a += 16; continue
                if _looks(a, 40):
                    found = a; break
                a += 16
            if found:
                sysent_base = found
                sysent_src  = "scan:" + b.getName()
                break

    sysent_entries = _walk(sysent_base) if sysent_base else []
    print("[+] sysent: {} ({} entries)".format(
        sysent_src, len(sysent_entries)))

    report.append("")
    report.append("=== [2] SYSENT ===")
    report.append("source  = " + sysent_src)
    report.append("base    = " + (fmt(sysent_base) if sysent_base else "n/a"))
    report.append("entries = " + str(len(sysent_entries)))
    for i, h, ab, name in sysent_entries:
        report.append("  {:>4}  {:<20}  ab={:<3}  {}".format(
            i, fmt(h) if h else "0", ab, name))

    hdr.append("// === [2] SYSENT ===")
    if sysent_base:
        hdr.append("#define NK_SYSENT_BASE          " + fmt(sysent_base) + "ULL")
        hdr.append("#define NK_SYSENT_ENTRY_SZ      16")
        hdr.append("#define NK_SYSENT_COUNT         " + str(len(sysent_entries)))
        for i, h, ab, name in sysent_entries:
            if not h or not name or name in ("?", "NOSYS") \
               or name.startswith("FUN_") or name.startswith("s_"):
                continue
            hdr.append("#define NK_SYSENT_{:<32} {}ULL /* #{} */".format(
                norm(name).upper(), fmt(h), i))
    hdr.append("")
    json_out["sysent_base"]  = fmt(sysent_base) if sysent_base else None
    json_out["sysent_count"] = len(sysent_entries)
    json_out["sysent"] = [{"num": i, "handler": fmt(h) if h else None,
                            "arg_bytes": ab, "name": name}
                           for i, h, ab, name in sysent_entries]

    # ---------------------------------------------------- 3. GLOBALS via adrp
    print("[*] globals via adrp...")
    ANCHORS = {
        "kernproc":      ["p != kernproc", "so != NULL || p == kernproc"],
        "task_init":     ["task_init @%s:%d"],
        "proc_ro":       ["proc_ro->task backref mismatch"],
        "task_map":      ["task->map->pmap"],
        "set_bsdtask":   ["set_bsdtask_info trying to set random bsd_info"],
        "swap_task_map": ["swap_task_map @%s:%d"],
        "zone_require":  ["zone_require failed: address not in a zone"],
        "pmap_ro":       ["pmap_ro_zone_validate_element"],
        "kernel_task":   ["kernel_task"],
        "task_for_pid":  ["task_for_pid-allow"],
        "kauth":         ["kauth_cred_getuid"],
        "amfi":          ["AMFI: task_for_pid() not allowed"],
    }
    globals_map = {}
    for label, strs in ANCHORS.items():
        for s in strs:
            sa = _str_addr(s)
            if sa is None: continue
            for xr in xrefs_to(sa):
                f = func_at(xr)
                if f is None: continue
                for _, tgt, kind in resolve_adrp_pairs(f):
                    if kind == "ldr":
                        globals_map.setdefault(tgt, set()).add(label)

    report.append("")
    report.append("=== [3] GLOBALS (adrp-derived) ===")
    for k in sorted(globals_map.keys()):
        report.append("  {}  <- {}".format(
            fmt(k), ",".join(sorted(globals_map[k]))))

    hdr.append("// === [3] GLOBALS ===")
    for k in sorted(globals_map.keys()):
        labels = "_".join(sorted(globals_map[k]))
        hdr.append("#define {:<40} {}ULL".format(
            norm("NK_G_"+labels).upper()[:40], fmt(k)))
    hdr.append("")
    json_out["globals"] = {fmt(k): sorted(list(v)) for k, v in globals_map.items()}

    # ---------------------------------------------------- 4. KALLOC/KFREE
    print("[*] kalloc/kfree...")
    kfree_ext = sym_get("_kfree_ext")
    kfree_callers = set()
    if kfree_ext:
        for xr in xrefs_to(kfree_ext):
            f = func_at(xr)
            if f:
                kfree_callers.add(_to_u(f.getEntryPoint().getOffset()))

    kalloc_type_sa = _str_addr("kalloc.type.var")
    kalloc_type_refs = set()
    if kalloc_type_sa:
        for xr in xrefs_to(kalloc_type_sa):
            f = func_at(xr)
            if f:
                kalloc_type_refs.add(_to_u(f.getEntryPoint().getOffset()))

    report.append("")
    report.append("=== [4] KALLOC/KFREE ===")
    report.append("_kfree_ext = " + (fmt(kfree_ext) if kfree_ext else "NOT_FOUND"))
    for ep in sorted(kfree_callers):
        report.append("  kfree caller: " + fmt(ep))
    for ep in sorted(kalloc_type_refs):
        report.append("  kalloc.type.var ref: " + fmt(ep))

    hdr.append("// === [4] KALLOC/KFREE ===")
    if kfree_ext:
        hdr.append("#define NK_KFREE_EXT            " + fmt(kfree_ext) + "ULL")
    for i, ep in enumerate(sorted(kfree_callers)):
        hdr.append("#define NK_KFREE_CALLER_{:<27} {}ULL".format(
            norm("{:04X}".format(i)), fmt(ep)))
    for i, ep in enumerate(sorted(kalloc_type_refs)):
        hdr.append("#define NK_KALLOC_TYPE_REF_{:<23} {}ULL".format(
            norm("{:04X}".format(i)), fmt(ep)))
    hdr.append("")
    json_out["kfree_ext"]     = fmt(kfree_ext) if kfree_ext else None
    json_out["kfree_callers"] = [fmt(x) for x in sorted(kfree_callers)]

    # ---------------------------------------------------- 5. ZONES
    print("[*] zones...")
    ZSTR = [
        "site.struct necp_client_flow_registration",
        "site.struct necp_fd_data",
        "site.struct necp_session",
        "site.struct necp_session_policy",
        "site.struct necp_kernel_socket_policy",
        "site.struct necp_arena_info",
        "site.struct ipc_entry",
        "site.struct ipc_kmsg",
        "site.struct task",
        "site.struct proc",
        "site.struct thread",
        "site.struct vm_map_entry",
        "site.struct vm_map_copy",
        "early.kalloc", "data.kalloc", "kalloc.type.var",
    ]
    zones = {}
    for z in ZSTR:
        sa = _str_addr(z)
        if sa is None: continue
        kv = [xr for xr in xrefs_to(sa)
              if 0xFFFFFFF000000000 <= xr < 0xFFFFFFF200000000]
        if kv:
            zones[z] = kv

    report.append("")
    report.append("=== [5] ZONES ===")
    for z, kv in sorted(zones.items()):
        for kva in kv:
            report.append("  {}  {}".format(fmt(kva), z))

    hdr.append("// === [5] ZONES ===")
    for z, kv in sorted(zones.items()):
        key = norm(z).upper()[:40]
        for i, kva in enumerate(kv):
            hdr.append("#define {:<40} {}ULL".format(
                key + ("_%d" % i if len(kv) > 1 else ""), fmt(kva)))
    hdr.append("")
    json_out["zones"] = {k: [fmt(x) for x in v] for k, v in zones.items()}

    # ---------------------------------------------------- 6. PAC GADGETS
    print("[*] PAC gadgets...")
    PAC = ("braa","brab","blraa","blrab","autia","autib",
           "pacia","pacib","paciza","pacizb","pacda","pacdb",
           "xpaci","xpacd","retaa","retab","paciasp","pacibsp",
           "autiasp","autibsp")
    pac = []
    fm = currentProgram.getFunctionManager()
    fc = 0
    for f in fm.getFunctions(True):
        fc += 1
        if fc % 2000 == 0:
            print("[*]   pac scan {} funcs, {} hits".format(fc, len(pac)))
        body = f.getBody()
        if body is None: continue
        insn = currentProgram.getListing().getInstructionAt(body.getMinAddress())
        n = 0
        while insn is not None and body.contains(insn.getAddress()) and n < 3000:
            m = insn.getMnemonicString().lower()
            if m in PAC:
                pac.append((_to_u(insn.getAddress().getOffset()),
                            f.getName(), m, insn.toString().strip()))
            insn = insn.getNext(); n += 1
        if len(pac) > 30000: break

    report.append("")
    report.append("=== [6] PAC GADGETS ({} total) ===".format(len(pac)))
    for a, fn, m, txt in pac[:800]:
        report.append("  {}  {:<8}  {}  [{}]".format(fmt(a), m, txt, fn[:30]))

    hdr.append("// === [6] PAC GADGETS (first 300) ===")
    for a, fn, m, txt in pac[:300]:
        hdr.append("#define NK_PAC_{}_{:08X}  {}ULL /* {} */".format(
            m.upper(), a & 0xFFFFFFFF, fmt(a), txt))
    hdr.append("")
    json_out["pac_gadgets"] = [{"addr": fmt(a), "mnem": m, "text": t, "fn": f}
                               for a, f, m, t in pac]

    # ---------------------------------------------------- 7. COPYIN/OUT
    print("[*] copyin/copyout...")
    COPY_SYMS = ["_copyin","_copyout","_copyinstr","_copyoutstr",
                 "_copyin_word","_copyout_word","_memmove_phys","_bcopy",
                 "_copyio","_copyinmsg","_copyoutmsg"]
    copy = {}
    for s in COPY_SYMS:
        a = sym_get(s)
        if a:
            copy[s] = a
        else:
            hits = funcs_named(s.lstrip("_"))
            if hits:
                copy[s] = hits[0][0]

    report.append("")
    report.append("=== [7] COPYIN/COPYOUT ===")
    for s, a in sorted(copy.items()):
        report.append("  {:<20} {}".format(s, fmt(a)))

    hdr.append("// === [7] COPYIN/COPYOUT ===")
    for s, a in sorted(copy.items()):
        hdr.append("#define NK_{:<36} {}ULL".format(norm(s).upper(), fmt(a)))
    hdr.append("")
    json_out["copyin_copyout"] = {k: fmt(v) for k, v in copy.items()}

    # ---------------------------------------------------- 8. IOKIT
    print("[*] iokit...")
    IOKIT = {
        "IOUserClient_externalMethod":   "externalMethod",
        "AppleKeyStore":                  "AppleKeyStore",
        "IOSurfaceRoot":                  "IOSurfaceRoot",
        "IOMobileFramebuffer":            "IOMobileFramebuffer",
        "IOConnectCallMethod":            "IOConnectCallMethod",
        "IOServiceOpen":                  "IOServiceOpen",
        "IOUserClient2022_extMethod":     "wrong externalMethod for IOUserClient2022",
        "IOUserClientKernelCompletion":   "OSAction_IOUserClient_KernelCompletion",
    }
    iokit = {}
    for label, needle in IOKIT.items():
        sa = _str_addr(needle)
        if sa is None: continue
        for xr in xrefs_to(sa):
            f = func_at(xr)
            if f:
                iokit.setdefault(label, set()).add(
                    _to_u(f.getEntryPoint().getOffset()))

    report.append("")
    report.append("=== [8] IOKIT ===")
    for label, eps in sorted(iokit.items()):
        for ep in sorted(eps):
            report.append("  {:<30} {}".format(label, fmt(ep)))

    hdr.append("// === [8] IOKIT ===")
    for label, eps in sorted(iokit.items()):
        key = norm(label).upper()
        for i, ep in enumerate(sorted(eps)):
            hdr.append("#define NK_IOKIT_{:<32} {}ULL".format(
                key + ("_%d" % i if len(eps) > 1 else ""), fmt(ep)))
    hdr.append("")
    json_out["iokit"] = {k: [fmt(x) for x in sorted(v)] for k, v in iokit.items()}

    # ---------------------------------------------------- 9. STRUCT OFFSETS
    STATIC = [
        ("PROC_TASK_OFF",       0x10),
        ("PROC_PID_OFF",        0x68),
        ("PROC_UCRED_OFF",      0xd0),
        ("PROC_TEXTVP_OFF",     0xd8),
        ("PROC_RO_OFF",         0x18),
        ("PROC_PROC_RO_OFF",    0x18),
        ("TASK_VM_MAP_OFF",     0x28),
        ("TASK_IPC_SPACE_OFF",  0xd0),
        ("TASK_BSD_INFO_OFF",   0x390),
        ("TASK_PROC_RO_OFF",    0x3b0),
        ("UCRED_UID_OFF",       0x18),
        ("UCRED_RUID_OFF",      0x1c),
        ("UCRED_SVUID_OFF",     0x20),
        ("UCRED_GID_OFF",       0x24),
        ("UCRED_RGID_OFF",      0x28),
        ("UCRED_SVGID_OFF",     0x2c),
        ("VM_MAP_PMAP_OFF",     0x48),
        ("VM_MAP_HDR_OFF",      0x00),
        ("FILEDESC_OFILES_OFF", 0x00),
        ("IPC_PORT_IP_KOBJECT", 0x68),
        ("IPC_VOUCHER_REF",     0x48),
        ("IPC_ENTRY_IE_OBJECT", 0x00),
        ("MOUNT_VNODE_DEV",     0x18),
        ("VNODE_VDATA_OFF",     0xe0),
    ]

    report.append("")
    report.append("=== [9] STRUCT FIELD OFFSETS ===")
    for n, v in STATIC:
        report.append("  {:<28} 0x{:x}".format(n, v))

    hdr.append("// === [9] STRUCT FIELD OFFSETS ===")
    for n, v in STATIC:
        hdr.append("#define {:<35} 0x{:x}".format(n, v))
    hdr.append("")
    json_out["struct_offsets"] = {n: v for n, v in STATIC}

    # ---------------------------------------------------- WRITE OUTPUTS
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
            fh.write(json.dumps(json_out, indent=2, sort_keys=True))
        print("[+] wrote " + OUT_JSON)
    except Exception as e:
        print("[-] json write failed: " + str(e))

    # ---------------------------------------------------- SUMMARY
    print("")
    print("=============== SUMMARY ===============")
    print("  kernel_base      : " + fmt(KERNEL_UNSLID_BASE))
    print("  sysent_base      : " + (fmt(sysent_base) if sysent_base else "n/a"))
    print("  sysent_entries   : " + str(len(sysent_entries)))
    print("  globals          : " + str(len(globals_map)))
    print("  kfree callers    : " + str(len(kfree_callers)))
    print("  kalloc.type refs : " + str(len(kalloc_type_refs)))
    print("  zones            : " + str(len(zones)))
    print("  PAC gadgets      : " + str(len(pac)))
    print("  copyin/out syms  : " + str(len(copy)))
    print("  iokit funcs      : " + str(sum(len(v) for v in iokit.values())))
    print("  static offsets   : " + str(len(STATIC)))
    print("=======================================")
    print("[+] kernel_rw.py done")


main()