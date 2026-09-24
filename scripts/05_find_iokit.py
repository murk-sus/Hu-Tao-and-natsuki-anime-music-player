# -*- coding: utf-8 -*-
import os

execfile(os.path.join(os.environ.get("GITHUB_WORKSPACE", "/tmp"),
                     "scripts", "00_load_symbols.py"))

WORKSPACE = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WORKSPACE, "nk_iokit.txt")

IOKIT_SYMS = [
    "IOUserClient__externalMethod",
    "IOUserClient2022__externalMethod",
    "IOConnectCallMethod",
    "is_io_connect_method",
    "IOServiceOpen",
    "IOServiceGetMatchingService",
    "IORegistryEntryGetRegistryEntryID",
    "AppleKeyStore",
    "IOSurfaceRoot",
    "IOMobileFramebuffer",
]

IOKIT_STRINGS = [
    "IOUserClient",
    "externalMethod",
    "is_io_connect_method",
    "AppleKeyStore",
    "IOSurfaceRoot",
    "IOMobileFramebuffer",
    "com.apple.driver.VideoProcessing",
    "com.apple.driver.AppleAvalancheErrorHandler",
]

VTABLE_STRINGS = [
    "AppleKeyStore", "IOSurfaceRoot", "IOMobileFramebuffer",
    "AppleAVE2", "IOAccelerator",
]

lines = []
lines.append("=== IOKIT / USERCLIENT OFFSETS ===")
lines.append("Program: " + currentProgram.getName())
lines.append("")

lines.append("--- IOKIT SYMBOLS ---")
for sym in IOKIT_SYMS:
    a = sym_get(sym)
    if a:
        lines.append("[+] {:<55} {}".format(sym, fmt(a)))
        continue
    bare = sym.split("::")[-1].lstrip("_")
    hits = syms_named(bare)
    if hits:
        for ha, hn in hits[:3]:
            lines.append("[+] {:<55} {}".format(hn, fmt(ha)))
    else:
        lines.append("[-] " + sym + " NOT_FOUND")

lines.append("")
lines.append("--- IOKIT via strings ---")
for istr in IOKIT_STRINGS:
    for saddr, sval in find_str_contains(istr)[:2]:
        xrefs = xrefs_to(saddr)
        lines.append("[+] {:<55} @ {}  xrefs={}".format(
            repr(sval[:52]), fmt(saddr), len(xrefs)))
        for xr in xrefs[:3]:
            f = func_at(xr)
            fname = f.getName() if f else "?"
            entry = 0
            if f:
                entry = int(f.getEntryPoint().getOffset()) & 0xFFFFFFFFFFFFFFFF
            lines.append("       xref @ {}  entry={}  func={}".format(
                fmt(xr), fmt(entry), fname))

lines.append("")
lines.append("--- possible vtable refs ---")
for vs in VTABLE_STRINGS:
    for saddr, sval in find_str_contains(vs)[:1]:
        for xr in xrefs_to(saddr)[:2]:
            ptr_back = read_u64(xr - 8)
            if ptr_back and is_kva(ptr_back):
                lines.append("[!] {} near {} (ptr-8={})".format(
                    vs, fmt(xr), fmt(ptr_back)))

write_lines(OUT, lines)
print("[+] 05_find_iokit.py done -> " + OUT)