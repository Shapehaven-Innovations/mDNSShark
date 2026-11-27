#!/usr/bin/env python3
# scripts/convert_ieee_oui.py
#
# Converts the IEEE Registration Authority's public MA-L assignment list
# (https://standards-oui.ieee.org/oui/oui.csv, columns: Registry,
# Assignment, Organization Name, Organization Address) into the plain
# `prefix<TAB>vendor` format OUIDataset.parse expects. Only 24-bit MA-L
# prefixes are kept; MA-M/MA-S sub-allocations are out of scope by design.
# Output is sorted by prefix so a refresh diffs cleanly. Standard library only.
#
#   curl -A "oui-table-generator/1.0" -o oui.csv https://standards-oui.ieee.org/oui/oui.csv
#   python3 scripts/convert_ieee_oui.py oui.csv mDNSShark/Resources/oui-database.txt
import csv
import re
import sys

def convert(src_path: str, dst_path: str) -> None:
    table = {}
    with open(src_path, encoding="utf-8", newline="") as src:
        rows = csv.reader(src)
        header = next(rows)
        if header[:3] != ["Registry", "Assignment", "Organization Name"]:
            sys.exit(f"unexpected header: {header!r}")
        for row in rows:
            if len(row) < 3 or row[0] != "MA-L":
                continue
            prefix = row[1].strip().lower()
            if len(prefix) != 6 or not all(c in "0123456789abcdef" for c in prefix):
                continue
            vendor = re.sub(r"\s+", " ", row[2]).strip()
            if vendor and prefix not in table:
                table[prefix] = vendor
    if len(table) < 30000:
        sys.exit(f"only {len(table)} prefixes, refusing to write")
    with open(dst_path, "w", encoding="utf-8") as dst:
        for prefix in sorted(table):
            dst.write(f"{prefix}\t{table[prefix]}\n")
    print(f"Wrote {len(table)} entries to {dst_path}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: convert_ieee_oui.py <src oui.csv> <dst oui-database.txt>")
        sys.exit(1)
    convert(sys.argv[1], sys.argv[2])
