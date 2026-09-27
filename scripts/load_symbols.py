# -*- coding: utf-8 -*-
# @runtime Jython
# load_symbols.py - apply symbols.json labels before analysis

import os
import sys
import json
import traceback

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
SYM = os.environ.get("SYMBOLS_JSON", os.path.join(WS, "symbols.json"))
OUT = os.path.join(WS, "symbols_load.log")

log_lines = []


def log(m):
    print(m)
    log_lines.append(m)


def sanitize(name):
    n = name.replace("::", "__")
    n = n.replace(" ", "_")
    n = n.replace("(", "").replace(")", "")
    n = n.replace(",", "_")
    n = n.replace("*", "")
    n = n.replace("<", "_").replace(">", "_")
    n = n.replace("-", "_")
    n = n.replace(".", "_")
    n = n.replace("[", "_").replace("]", "_")
    n = n.replace("+", "_")
    n = n.replace("=", "_")
    n = n.replace("/", "_")
    n = n.replace("&", "_")
    if not n:
        return ""
    if not (n[0].isalpha() or n[0] == "_"):
        n = "s_" + n
    if len(n) > 200:
        n = n[:200]
    return n


def parse_syms(data):
    out = []
    if isinstance(data, dict):
        for k, v in data.items():
            try:
                a = int(k)
            except Exception:
                try:
                    a = int(k, 16)
                except Exception:
                    continue
            if a < 0 or a > 0xFFFFFFFFFFFFFFFF:
                continue
            if not isinstance(v, str):
                continue
            out.append((a, v))
    elif isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            a = item.get("address")
            if a is None:
                a = item.get("addr")
            n = item.get("name")
            if n is None:
                n = item.get("symbol")
            if a is None or n is None:
                continue
            try:
                if isinstance(a, str) and a.lower().startswith("0x"):
                    ai = int(a, 16)
                elif isinstance(a, str):
                    ai = int(a)
                else:
                    ai = int(a)
            except Exception:
                continue
            out.append((ai, str(n)))
    return out


def main():
    if not os.path.isfile(SYM):
        log("[-] no symbols.json at %s" % SYM)
        return

    try:
        raw = open(SYM).read()
    except Exception as e:
        log("[-] read fail: %s" % e)
        return

    try:
        data = json.loads(raw)
    except Exception as e:
        log("[-] json parse: %s" % e)
        return

    syms = parse_syms(data)
    log("[*] parsed %d symbols" % len(syms))
    if not syms:
        log("[-] nothing to apply")
        return

    st = currentProgram.getSymbolTable()
    tx = currentProgram.startTransaction("load_symbols")
    applied = 0
    renamed = 0
    skipped = 0
    failed = 0

    try:
        for addr_int, name in syms:
            try:
                hexstr = "%X" % addr_int
                ga = currentProgram.getAddressFactory().getAddress(hexstr)
                if ga is None:
                    failed += 1
                    continue

                nm = sanitize(name)
                if not nm:
                    failed += 1
                    continue

                existing = st.getPrimarySymbol(ga)
                existing_name = ""
                if existing is not None:
                    existing_name = str(existing.getName())

                if existing_name == nm:
                    skipped += 1
                    continue

                if existing is not None:
                    try:
                        existing.setName(nm, None)
                        renamed += 1
                        continue
                    except Exception:
                        pass

                try:
                    st.createLabel(ga, nm, None)
                    applied += 1
                except Exception:
                    failed += 1
            except Exception:
                failed += 1

        currentProgram.endTransaction(tx, True)
    except Exception as e:
        currentProgram.endTransaction(tx, False)
        log("[-] fatal during apply: %s" % e)
        traceback.print_exc()

    log("[+] applied=%d renamed=%d skipped=%d failed=%d" % (applied, renamed, skipped, failed))

    # verify: check if IOUserClient is now visible
    hits = 0
    try:
        it = st.getAllSymbols(True)
        while it.hasNext():
            s = it.next()
            try:
                nm = str(s.getName())
            except Exception:
                continue
            if "IOUser" in nm or "externalMethod" in nm or "vtable" in nm:
                hits += 1
                if hits <= 20:
                    log("  found: %s @ %s" % (nm, s.getAddress()))
    except Exception as e:
        log("[-] verify iter: %s" % e)
    log("[*] IOUserClient/vtable/externalMethod matches: %d" % hits)

    try:
        fh = open(OUT, "w")
        for l in log_lines:
            fh.write(l + "\n")
        fh.close()
    except Exception:
        pass


try:
    main()
except Exception as e:
    print("FATAL %s" % e)
    traceback.print_exc()
    try:
        fh = open(OUT, "w")
        fh.write("FATAL: %s\n" % e)
        fh.write(traceback.format_exc())
        fh.close()
    except Exception:
        pass