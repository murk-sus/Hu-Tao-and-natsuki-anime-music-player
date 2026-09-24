import os
import sys

KC_PATH = os.environ.get("GHIDRA_KC_PATH")
if KC_PATH and KC_PATH not in sys.path:
    sys.path.append(KC_PATH)

try:
    from utils.iometa import ParseIOMeta
    from utils.class import kernelCache
except ImportError as e:
    print("[-] Failed to import ghidra_kernelcache: " + str(e))
    print("[-] GHIDRA_KC_PATH = " + str(KC_PATH))
    exit(1)

args = getScriptArgs()
iometa_path = args[0] if args else None

if not iometa_path or not os.path.exists(iometa_path):
    print("[-] iometa output not found: " + str(iometa_path))
    exit(1)

print("[*] Loading iometa output: " + iometa_path)
iom = ParseIOMeta(iometa_path)
Obj = iom.getObjects()
print("[*] Parsed objects: " + str(len(Obj)))

kc = kernelCache(Obj)
print("[*] Running process_all_classes()...")
kc.process_all_classes()
print("[+] ghidra_kernelcache symbolication complete")
