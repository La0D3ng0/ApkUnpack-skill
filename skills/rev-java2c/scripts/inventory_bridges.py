"""Inventory JniLib.c* bridges and their integer dispatch IDs.

Requires androguard. Supply --smali-root when another DEX parser reports
fewer bridge methods than baksmali: the smali text then supplies call sites,
while the DEX method ID table supplies stable method indices.
"""

import argparse
import json
import pathlib
import re
import sys

from androguard.core.dex import DEX
from loguru import logger


logger.disable("androguard")
INVOKE = re.compile(r"Lcom/fort/andjni/JniLib;->(c\w+)\(\[Ljava/lang/Object;\)")
BOX_INT = "Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;"
CONST = re.compile(r"^(v\d+),\s*(-?(?:0x[0-9a-fA-F]+|\d+))$")
REGISTER = re.compile(r"^(v\d+),")


def dispatch_id(instructions, call_index):
    for boxed_at in range(call_index - 1, max(-1, call_index - 14), -1):
        name, output = instructions[boxed_at]
        if name != "invoke-static" or BOX_INT not in output:
            continue
        boxed_register = output.split(",", 1)[0].strip()
        for const_at in range(boxed_at - 1, max(-1, boxed_at - 12), -1):
            previous_name, previous_output = instructions[const_at]
            assigned = REGISTER.match(previous_output)
            if not assigned or assigned.group(1) != boxed_register:
                continue
            match = CONST.match(previous_output)
            if not previous_name.startswith("const") or not match:
                return None
            try:
                return int(match.group(2), 0)
            except ValueError:
                return None
    return None


def inventory(dex_path):
    dex = DEX(dex_path.read_bytes())
    rows = []
    skipped = 0
    for clazz in dex.get_classes():
        for method in clazz.get_methods():
            code = method.get_code()
            if code is None:
                if method.get_code_off():
                    skipped += 1
                continue
            instructions = [(ins.get_name(), ins.get_output())
                            for ins in code.get_bc().get_instructions()]
            for at, (name, output) in enumerate(instructions):
                if not name.startswith("invoke-"):
                    continue
                match = INVOKE.search(output)
                if not match:
                    continue
                rows.append({
                    "id": dispatch_id(instructions, at),
                    "dex": dex_path.name,
                    "class": method.get_class_name(),
                    "name": method.get_name(),
                    "prototype": method.get_descriptor().replace(" ", ""),
                    "method_idx": method.get_method_idx(),
                    "code_off": method.get_code_off(),
                    "bridge": match.group(1),
                })
    if skipped:
        print(f"WARNING: {dex_path}: parser omitted {skipped} nonzero code_off "
              "methods; disassemble with baksmali and use --smali-root",
              file=sys.stderr)
    return rows, skipped


SMALI_BRIDGE = re.compile(
    r"Lcom/fort/andjni/JniLib;->(c\w+)\(\[Ljava/lang/Object;\)")
SMALI_BOX = re.compile(
    r"invoke-static(?:/range)?\s+\{([^}]+)\},\s*"
    r"Ljava/lang/Integer;->valueOf\(I\)Ljava/lang/Integer;")
SMALI_CONST = re.compile(
    r"const(?:/[\w-]+)?\s+([vp]\d+),\s*(-?(?:0x[0-9a-fA-F]+|\d+))")
SMALI_METHOD = re.compile(r"\.method\s+.*?([^\s(]+\([^)]*\)\S+)\s*$")


def smali_dispatch_id(lines, call_index):
    """Accept only a literal boxed just before the bridge in one method."""
    for boxed_at in range(call_index - 1, -1, -1):
        boxed = SMALI_BOX.search(lines[boxed_at])
        if not boxed:
            continue
        register = boxed.group(1).split(",", 1)[0].strip()
        for at in range(boxed_at - 1, -1, -1):
            const = SMALI_CONST.search(lines[at])
            if const and const.group(1) == register:
                return int(const.group(2), 0)
            # A non-constant write to the same register makes this ambiguous.
            if re.match(r"\s*(?:move|iget|sget|aget|new-instance|array-length)\S*\s+"
                        + re.escape(register) + r"\s*[,\s]", lines[at]):
                return None
        return None
    return None


def inventory_smali(dex_path, smali_root):
    dex = DEX(dex_path.read_bytes())
    method_ids = {
        (m.get_class_name(), m.get_name(), m.get_descriptor().replace(" ", "")): index
        for index, m in enumerate(dex.get_methods())
    }
    code_offsets = {
        m.get_method_idx(): m.get_code_off()
        for clazz in dex.get_classes() for m in clazz.get_methods()
    }
    rows = []
    for source in sorted(smali_root.rglob("*.smali")):
        lines = source.read_text(encoding="utf-8").splitlines()
        clazz = next((line.split()[-1] for line in lines
                      if line.startswith(".class ")), None)
        method_line = None
        body = []
        for line in [*lines, ".end method"]:
            if line.startswith(".method "):
                method_line = line
                body = []
            elif line.startswith(".end method") and method_line:
                signature = SMALI_METHOD.search(method_line)
                if not signature or not clazz:
                    raise ValueError(f"unparsed method in {source}: {method_line}")
                name, descriptor = signature.group(1).split("(", 1)
                descriptor = "(" + descriptor
                key = clazz, name, descriptor
                for at, instruction in enumerate(body):
                    match = SMALI_BRIDGE.search(instruction)
                    if match:
                        rows.append({
                            "id": smali_dispatch_id(body, at),
                            "dex": dex_path.name,
                            "class": clazz,
                            "name": name,
                            "prototype": descriptor,
                            "method_idx": method_ids.get(key),
                            "code_off": code_offsets.get(method_ids.get(key)),
                            "bridge": match.group(1),
                            "smali": str(source.relative_to(smali_root)).replace("\\", "/"),
                        })
                method_line = None
            elif method_line:
                body.append(line)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dex", nargs="+", type=pathlib.Path)
    parser.add_argument("-o", "--output", required=True, type=pathlib.Path)
    parser.add_argument("--smali-root", type=pathlib.Path,
                        help="baksmali output for one DEX (one dex argument)")
    args = parser.parse_args()
    if args.smali_root and len(args.dex) != 1:
        parser.error("--smali-root requires exactly one DEX")
    if args.smali_root:
        rows = inventory_smali(args.dex[0], args.smali_root)
        skipped = 0
    else:
        scanned = [inventory(path) for path in args.dex]
        rows = [row for chunk, _ in scanned for row in chunk]
        skipped = sum(count for _, count in scanned)
    rows.sort(key=lambda row: (row["id"] is None, row["id"] or 0,
                               row["dex"], row["method_idx"]))
    ids = [row["id"] for row in rows if row["id"] is not None]
    summary = {
        "call_sites": len(rows),
        "resolved_ids": len(ids),
        "unique_ids": len(set(ids)),
        "min_id": min(ids, default=None),
        "max_id": max(ids, default=None),
        "duplicate_ids": len(ids) - len(set(ids)),
        "unresolved_ids": len(rows) - len(ids),
        "unresolved_method_indices": sum(row["method_idx"] is None for row in rows),
        "nonzero_code_items_not_parsed": skipped,
    }
    result = {"summary": summary, "bridges": rows}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
