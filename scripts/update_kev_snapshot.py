#!/usr/bin/env python3
"""Regenerate mDNSShark/Resources/cisa_kev_snapshot.json.

Fetches the live CISA KEV catalog and keeps only the entries filed under a
vendorProject one of nist_cpe_map.json's vendorAdvisories claims (via
kevVendorProjects). This keeps the bundled snapshot honest: nothing in it
claims a "CISA" attribution the live catalog doesn't back up.

Run from the repo root:
    python3 scripts/update_kev_snapshot.py
"""
import json
import urllib.request
from datetime import date, timezone
from pathlib import Path

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REPO_ROOT = Path(__file__).resolve().parent.parent
NIST_MAP_PATH = REPO_ROOT / "mDNSShark" / "Resources" / "nist_cpe_map.json"
SNAPSHOT_PATH = REPO_ROOT / "mDNSShark" / "Resources" / "cisa_kev_snapshot.json"


def allowed_vendor_projects(nist_map: dict) -> set[str]:
    projects: set[str] = set()
    for config in nist_map.get("vendorAdvisories", {}).values():
        projects.update(p.lower() for p in config.get("kevVendorProjects", []))
    return projects


def main() -> int:
    nist_map = json.loads(NIST_MAP_PATH.read_text())
    allowed_projects = allowed_vendor_projects(nist_map)

    with urllib.request.urlopen(KEV_FEED_URL, timeout=30) as resp:
        feed = json.loads(resp.read())

    matched = sorted(
        (
            v for v in feed["vulnerabilities"]
            if v.get("vendorProject", "").lower() in allowed_projects
        ),
        key=lambda v: v["cveID"],
    )

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

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
