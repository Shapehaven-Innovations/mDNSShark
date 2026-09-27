#!/usr/bin/env python3
"""Regenerate mDNSShark/Resources/cisa_kev_snapshot.json.

Fetches the live CISA KEV catalog and keeps only the entries that are both
(a) referenced by a CVE in nist_cpe_map.json's serviceTypes/manufacturers
lists, and (b) actually present in the live feed. This keeps the bundled
snapshot honest: nothing in it claims a "CISA" attribution the live catalog
doesn't back up.

Run from the repo root:
    python3 scripts/update_kev_snapshot.py

Prints to stderr any referenced CVE that is NOT in the live feed -- those
need curated (non-CISA-attributed) text added to nist_cpe_map.json's "cves"
section by hand instead.
"""
import json
import sys
import urllib.request
from datetime import date, timezone
from pathlib import Path

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REPO_ROOT = Path(__file__).resolve().parent.parent
NIST_MAP_PATH = REPO_ROOT / "mDNSShark" / "Resources" / "nist_cpe_map.json"
SNAPSHOT_PATH = REPO_ROOT / "mDNSShark" / "Resources" / "cisa_kev_snapshot.json"


def referenced_cves(nist_map: dict) -> set[str]:
    cves: set[str] = set()
    for entry in nist_map.get("serviceTypes", {}).values():
        cves.update(entry.get("cves", []))
    for entry in nist_map.get("manufacturers", {}).values():
        cves.update(entry.get("cves", []))
    return cves


def main() -> int:
    nist_map = json.loads(NIST_MAP_PATH.read_text())
    referenced = referenced_cves(nist_map)

    with urllib.request.urlopen(KEV_FEED_URL, timeout=30) as resp:
        feed = json.loads(resp.read())

    by_id = {v["cveID"]: v for v in feed["vulnerabilities"]}

    matched = [by_id[cve] for cve in sorted(referenced) if cve in by_id]
    missing = sorted(cve for cve in referenced if cve not in by_id)

    snapshot = {
        "title": "CISA KEV Snapshot - mDNSShark referenced subset",
        "catalogVersion": feed.get("catalogVersion"),
        "dateReleased": feed.get("dateReleased"),
        "snapshotDate": date.today().isoformat(),
        "vulnerabilities": [
            {
                "cveID": v["cveID"],
                "vendorProject": v["vendorProject"],
                "product": v["product"],
                "vulnerabilityName": v["vulnerabilityName"],
                "shortDescription": v["shortDescription"],
            }
            for v in matched
        ],
    }

    SNAPSHOT_PATH.write_text(json.dumps(snapshot, indent=2) + "\n")
    print(f"Wrote {len(matched)} KEV-backed entries to {SNAPSHOT_PATH}")

    if missing:
        print(
            f"\n{len(missing)} referenced CVE(s) are NOT in the live KEV feed "
            "-- these need curated (non-CISA) text in nist_cpe_map.json's "
            "\"cves\" section instead of a bundled CISA entry:",
            file=sys.stderr,
        )
        for cve in missing:
            print(f"  {cve}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
