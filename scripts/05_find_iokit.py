# -*- coding: utf-8 -*-
import os
import re

execfile(os.path.join(os.environ.get("GITHUB_WORKSPACE","/tmp"), "scripts", "00_load_symbols.py"))

WORKSPACE = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WORKSPACE, "nk_iokit.txt")

IOKIT_SYMS = [
    "IOUserClient::externalMethod",
    "_IOUserClient__externalMethod",
    "IOUserClient2022::externalMethod",
    "IOConnectCallMethod",
    "is_io_connect_method",
    "_is_io_connect_method",
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

lines = []
lines.append("=== IOKIT / USERCLIENT OFFSETS ===")
lines.append("Program: " + currentProgram.getName())
lines.append("")

lines.append("--- IOKIT FUNCTIONS ---")
for sym in IOKIT_SYMS:
    a = sym_get(sym)
    if a:
        lines.append("[+] {:<55} {}".format(sym, fmt(a)))
    else:
        bare = sym.split("::")[-1].lstrip("_")
        hits = syms_named(bare)
        found = False
        for ha, hn in hits[:3]:
            lines.append("[+] {:<55} {}".format(hn, fmt(ha)))
            found = True
        if not found:
            lines.append("[-] " + sym + " NOT_FOUND")

lines.append("")
lines.append("--- IOKIT via strings ---")
for istr in IOKIT_STRINGS:
    results = find_str_contains(istr)
    for saddr, sval in results[:2]:
        xrefs = xrefs_to(saddr)
        lines.append("[+] {:<55} @ {}  xrefs={}".format(
            repr(sval[:52]), fmt(saddr), len(xrefs)))
        for xr in xrefs[:3]:
            f = func_at(xr)
            fname = f.getName() if f else "?"
            entry = int(f.getEntryPoint().getOffset()) & 0xFFFFFFFFFFFFFFFF if f else 0
            lines.append("       xref @ {}  entry={}  func={}".format(
                fmt(xr), fmt(entry), fname))

lines.append("")
lines.append("--- IOKIT VTABLE SCAN ---")
VTABLE_STRINGS = ["AppleKeyStore", "IOSurfaceRoot", "IOMobileFramebuffer",
                  "AppleAVE2", "IOAccelerator"]
for vs in VTABLE_STRINGS:
    results = find_str_contains(vs)
    for saddr, sval in results[:1]:
        xrefs = xrefs_to(saddr)
        for xr in xrefs[:2]:
            ptr_back = read_u64(xr - 8)
            if ptr_back and is_kva(ptr_back):
                lines.append("[!] possible vtable ref for {} near {} (ptr-8={})".format(
                    vs, fmt(xr), fmt(ptr_back)))

write_lines(OUT, lines)
print("[+] 05_find_iokit.py done -> " + OUT)
