# -*- coding: utf-8 -*-
# @runtime Jython

import os
import json
from ghidra.program.model.symbol import SourceType

SYMBOLS_JSON = os.environ.get("SYMBOLS_JSON", "")
if not SYMBOLS_JSON or not os.path.exists(SYMBOLS_JSON):
    print("[-] symbols.json not found")
else:
    try:
        with open(SYMBOLS_JSON) as f:
            data = json.loads(f.read().strip() or "{}")
    except Exception as e:
        print("[-] parse error: " + str(e))
        data = {}

    st = currentProgram.getSymbolTable()
    n = 0
    for name, addr_str in data.items():
        if not isinstance(addr_str, str):
            continue
        try:
            addr = toAddr(int(addr_str, 16))
        except Exception:
            continue
        if addr is None:
            continue
        try:
            st.createLabel(addr, name.lstrip("_"), SourceType.USER_DEFINED)
            n += 1
        except Exception:
            pass
    print("[+] symbols applied: " + str(n))
