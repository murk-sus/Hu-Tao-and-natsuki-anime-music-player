# -*- coding: utf-8 -*-
import os
import sys

execfile(os.path.join(os.environ.get("GITHUB_WORKSPACE","/tmp"), "scripts", "00_load_symbols.py"))

WORKSPACE = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WORKSPACE, "nk_base.txt")

lines = []
lines.append("=== KERNEL BASE / SLIDE ===")
lines.append("Program: " + currentProgram.getName())

img_base = int(currentProgram.getImageBase().getOffset()) & 0xFFFFFFFFFFFFFFFF
lines.append("ImageBase (Ghidra): " + fmt(img_base))

KNOWN_UNSLID = 0xFFFFFFF007004000
slide = (img_base - KNOWN_UNSLID) & 0xFFFFFFFFFFFFFFFF
lines.append("XNU unslid base (24A437/iPhone14,5): " + fmt(KNOWN_UNSLID))
lines.append("Computed slide (if no rebase): " + fmt(slide))

sym_slide = sym_get("_vm_kernel_slide")
if sym_slide:
    lines.append("_vm_kernel_slide from symbols.json: " + fmt(sym_slide))
else:
    lines.append("_vm_kernel_slide: NOT_FOUND in symbols.json")

for pat in ("vm_kernel_slide", "_vm_kernel_slide", "gPhysBase", "_gPhysBase"):
    hits = syms_named(pat)
    for a, n in hits[:3]:
        lines.append("[+] symtable: " + n + " @ " + fmt(a))

lines.append("")
lines.append("#define NK_KERNEL_UNSLID_BASE  " + fmt(KNOWN_UNSLID))
lines.append("#define NK_IMAGE_BASE          " + fmt(img_base))

write_lines(OUT, lines)
print("[+] 01_find_base.py done -> " + OUT)
