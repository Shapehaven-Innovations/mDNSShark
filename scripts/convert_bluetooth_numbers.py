#!/usr/bin/env python3
# scripts/convert_bluetooth_numbers.py
#
# Converts Nordic Semiconductor's bluetooth-numbers-database JSON
# (v1/company_ids.json and v1/service_uuids.json, BSD-3-Clause) into the
# `key<TAB>name` text files BLECompanyTable and BLEServiceNameTable parse.
# Usage: convert_bluetooth_numbers.py company_ids.json service_uuids.json out_dir
import json
import os
import sys

def clean(name: str) -> str:
    return " ".join(name.replace("\t", " ").split())

def convert(company_json: str, service_json: str, out_dir: str) -> None:
    with open(company_json, encoding="utf-8") as f:
        companies = json.load(f)
    seen = set()
    with open(os.path.join(out_dir, "bluetooth-company-ids.txt"), "w", encoding="utf-8") as out:
        for entry in companies:
            code, name = entry.get("code"), clean(entry.get("name", ""))
            if not isinstance(code, int) or not 0 <= code <= 0xFFFF or not name or code in seen:
                continue
            seen.add(code)
            out.write(f"{code}\t{name}\n")

    with open(service_json, encoding="utf-8") as f:
        services = json.load(f)
    seen = set()
    with open(os.path.join(out_dir, "bluetooth-service-uuids.txt"), "w", encoding="utf-8") as out:
        for entry in services:
            uuid, name = entry.get("uuid", "").strip().upper(), clean(entry.get("name", ""))
            if not uuid or not name or uuid in seen:
                continue
            seen.add(uuid)
            out.write(f"{uuid}\t{name}\n")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit("usage: convert_bluetooth_numbers.py company_ids.json service_uuids.json out_dir")
    convert(sys.argv[1], sys.argv[2], sys.argv[3])
