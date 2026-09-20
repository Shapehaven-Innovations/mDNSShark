#!/usr/bin/env python3
# scripts/convert_manuf.py
#
# Converts Wireshark's `manuf` file (tab-separated: prefix, short name,
# long name; prefix may carry a `/nn` CIDR-style suffix for MA-M/MA-S
# sub-blocks) into the plain `prefix<TAB>vendor` format OUIDataset.parse
# expects. Only plain 24-bit (6 hex digit, no "/nn" suffix) MA-L prefixes
# are kept — that covers all 47 of Ubiquiti's blocks and the vast
# majority of real-world devices this app will ever see; finer-grained
# MA-M/MA-S sub-allocations are out of scope by design (see spec).
import sys

def convert(src_path: str, dst_path: str) -> None:
    seen = set()
    with open(src_path, encoding="utf-8", errors="ignore") as src, \
         open(dst_path, "w", encoding="utf-8") as dst:
        for line in src:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            prefix, vendor = parts[0].strip(), parts[-1].strip()
            if "/" in prefix:
                continue  # skip MA-M/MA-S sub-blocks
            hex_only = prefix.replace(":", "").replace("-", "").lower()
            if len(hex_only) != 6 or not all(c in "0123456789abcdef" for c in hex_only):
                continue
            if hex_only in seen:
                continue
            seen.add(hex_only)
            dst.write(f"{hex_only}\t{vendor}\n")
    print(f"Wrote {len(seen)} entries to {dst_path}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: convert_manuf.py <src manuf file> <dst oui-database.txt>")
        sys.exit(1)
    convert(sys.argv[1], sys.argv[2])
