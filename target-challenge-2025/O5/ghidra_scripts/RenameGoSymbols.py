#@category Go
#@keybinding
#@menupath
#@toolbar

from __future__ import print_function

import json
from ghidra.app.script import GhidraScript
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.address import AddressSet


def build_name(fdesc):
    full = fdesc.get("FullName", "")
    if not full:
        return None
    name = full
    if cfg["strip_package_prefix"]:
        name = name.split(".")[-1]
    if cfg["sanitize_names"]:
        for ch in ["/", " "]:
            name = name.replace(ch, "_")
    return name

def make_body(start_addr, end_addr):
    if end_addr is None or end_addr <= start_addr:
        return None
    a0 = toAddr(start_addr + delta)
    a1 = toAddr(end_addr - 1 + delta)
    try:
        return AddressSet(a0, a1)
    except Exception:
        return None

def should_rename(func_obj):
    if cfg["rename_existing"] == "always":
        return True
    if cfg["rename_existing"] == "never":
        return False
    return func_obj.getSymbol().getSource() != SourceType.USER_DEFINED

cfg = {
    "auto_slide": True,
    "apply_body": True,
    "create_missing": True,
    "rename_existing": "if_not_user",  # "always", "if_not_user", "never"
    "strip_package_prefix": False,
    "sanitize_names": True,
    "add_plate_comment": True
}

json_file = askFile("Select symbols JSON (UserFunctions + StdFunctions)", "Open")

if not json_file:
    print("No file selected, aborting.")
    exit

try:
    with open(json_file.getAbsolutePath(), "rb") as f:
        data = json.loads(f.read())
except Exception as e:
    print("Failed to read JSON: %s" % e)
    exit

sections = ["UserFunctions", "StdFunctions"]
funcs_all = []
for sec in sections:
    arr = data.get(sec, [])
    if arr:
        funcs_all.extend([(sec, f) for f in arr])

if not funcs_all:
    print("No UserFunctions or StdFunctions found; nothing to do.")
    exit

mem = currentProgram.getMemory()
listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
image_base = currentProgram.getImageBase().getOffset()

# Auto-slide detection
delta = 0
if cfg["auto_slide"]:
    starts = [int(f.get("Start", 0)) for _, f in funcs_all if "Start" in f][:200]
    if starts:
        candidates = [0, -image_base, image_base]
        best = (0, -1)
        for d in candidates:
            score = sum(1 for s in starts if mem.contains(toAddr(s + d)))
            if score > best[1]:
                best = (d, score)
        delta = best[0]
    print("Auto-slide: image_base=0x%x, chosen delta=0x%x" % (image_base, delta))

created = renamed = resized = commented = skipped_bad_addr = conflicts = 0

tx_id = currentProgram.startTransaction("Rename Go symbols (User+Std)")
try:
    for sec, f in funcs_all:
        start = f.get("Start", None)
        end = f.get("End", None)
        if start is None:
            continue
        try:
            start = int(start)
            if end is not None:
                end = int(end)
        except Exception:
            continue

        addr = toAddr(start + delta)
        if not mem.contains(addr):
            skipped_bad_addr += 1
            continue

        name = build_name(f)
        if not name:
            continue

        func = fm.getFunctionAt(addr)
        if func is None:
            if cfg["create_missing"]:
                try:
                    func = createFunction(addr, name)
                    created += 1
                except Exception:
                    try:
                        func = fm.createFunction(name, addr, None, SourceType.ANALYSIS)
                        created += 1
                    except Exception:
                        conflicts += 1
                        continue
            else:
                continue
        else:
            if should_rename(func):
                try:
                    func.setName(name, SourceType.USER_DEFINED)
                    renamed += 1
                except Exception:
                    conflicts += 1

        if cfg["apply_body"]:
            body = make_body(start, end)
            if body is not None:
                # Check for overlaps
                overlap = False
                for other_func in fm.getFunctions(body, True):
                    if other_func != func:
                        overlap = True
                        break
                if not overlap:
                    try:
                        func.setBody(body)
                        resized += 1
                    except Exception as e:
                        print("Failed to set body for %s: %s" % (name, e))
                else:
                    print("Skipping body for %s due to overlap" % name)


        if cfg["add_plate_comment"]:
            pkg = f.get("PackageName", None)
            full = f.get("FullName", None)
            meta = ["Section: %s" % sec]
            if pkg: meta.append("Package: %s" % pkg)
            if full: meta.append("Full: %s" % full)
            try:
                setPlateComment(addr, "; ".join(meta))
                commented += 1
            except Exception:
                pass

finally:
    currentProgram.endTransaction(tx_id, True)

print("Done. Sections processed: %s" % ", ".join(sections))
print("Created: %d | Renamed: %d | Resized: %d | Commented: %d" %
                (created, renamed, resized, commented))
print("Skipped (addr not in memory): %d | Conflicts: %d" %
                (skipped_bad_addr, conflicts))

