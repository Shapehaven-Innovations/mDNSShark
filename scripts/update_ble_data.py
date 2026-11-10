#!/usr/bin/env python3
"""Regenerates the bundled Bluetooth lookup tables from their public sources. Standard library only.

Run by hand or by .github/workflows/update-ble-data.yml. The app never downloads anything: it reads the
text files this writes into Packages/DeviceFingerprint/Sources/DeviceFingerprint/Resources.

  bluetooth-company-ids.txt    company id (decimal) <TAB> name          Bluetooth SIG assigned numbers
  bluetooth-member-uuids.txt   16 bit member UUID <TAB> company         Bluetooth SIG assigned numbers
  apple-models.txt             model identifier <TAB> marketing name    AppleDB (MIT)
  apple-proximity.txt          Proximity Pairing code (hex) <TAB> name  AppleDB (MIT)
  xiaomi-products.txt          MiBeacon product id (hex) <TAB> name     Bluetooth-Devices/xiaomi-ble (Apache-2.0)
  ble-matchers.txt             label <TAB> kind <TAB> conditions        Home Assistant generated matchers (Apache-2.0)
  ble-data-SOURCE.txt          URLs, commits, dates, row counts

A file is only replaced when it passes its checks (minimum rows, known keys resolve, no shrink over 10%).
"""
import ast, collections, datetime, json, os, pathlib, re, sys, urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "Packages/DeviceFingerprint/Sources/DeviceFingerprint/Resources"
DOMAINS = pathlib.Path(__file__).resolve().parent / "ble_domain_map.tsv"
UA = {"User-Agent": "update-ble-data/1.0"}
KINDS = {"phone", "computer", "wearable", "earbuds", "audio", "tv", "tracker", "findMy", "health",
         "inputDevice", "beacon", "smartHome", "camera", "printer"}
BASE_UUID_SUFFIX = "-0000-1000-8000-00805F9B34FB"

def get(url, headers=None):
    h = dict(UA)
    if headers: h.update(headers)
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token and "api.github.com" in url: h["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=90) as r:
        return r.read().decode("utf-8")

def github_commit(repo, path):
    j = json.loads(get(f"https://api.github.com/repos/{repo}/commits?path={path}&per_page=1"))[0]
    return j["sha"], j["commit"]["committer"]["date"][:10]

def clean(s):
    return re.sub(r"\s+", " ", s.replace("\t", " ")).strip()

def write_table(name, rows, minimum, must=None, report=None):
    """rows: dict key -> value text. Replaces the file only when the checks pass."""
    path = OUT / name
    if len(rows) < minimum: sys.exit(f"{name}: only {len(rows)} rows, expected at least {minimum}")
    for k, v in (must or {}).items():
        if rows.get(k) != v: sys.exit(f"{name}: {k} is {rows.get(k)!r}, expected {v!r}")
    if path.exists():
        old = len(path.read_text(encoding="utf-8").splitlines())
        if len(rows) < old * 0.9: sys.exit(f"{name}: {len(rows)} rows vs {old} committed, refusing to shrink over 10%")
    path.write_text("".join(f"{k}\t{v}\n" for k, v in rows.items()), encoding="utf-8")
    report.append(f"{name}: {len(rows)} rows")

def yaml_pairs(text, key):
    """Pairs of (value, name) from the SIG YAML files; names may be single, double or unquoted."""
    pairs = re.findall(rf"-\s*{key}:\s*0x([0-9A-Fa-f]+)\s*\n\s*name:\s*(.+)", text)
    out = {}
    for value, name in pairs:
        name = name.strip()
        if len(name) >= 2 and name[0] == name[-1] and name[0] in "'\"": name = name[1:-1]
        out.setdefault(value.upper(), clean(name.replace("''", "'")))
    return out

def sig(report, sources):
    api = json.loads(get("https://api.bitbucket.org/2.0/repositories/bluetooth-SIG/public/commits/main?pagelen=1"))
    commit = api["values"][0]["hash"]; date = api["values"][0]["date"][:10]
    base = f"https://bitbucket.org/bluetooth-SIG/public/raw/{commit}/assigned_numbers"
    companies = yaml_pairs(get(f"{base}/company_identifiers/company_identifiers.yaml"), "value")
    write_table("bluetooth-company-ids.txt", {str(int(k, 16)): v for k, v in sorted(companies.items(), key=lambda i: int(i[0], 16))},
                3500, must={"76": "Apple, Inc.", "6": "Microsoft"}, report=report)
    members = yaml_pairs(get(f"{base}/uuids/member_uuids.yaml"), "uuid")
    write_table("bluetooth-member-uuids.txt", dict(sorted(members.items())), 600, must={"FD5A": "Samsung Electronics Co., Ltd."}, report=report)
    sources.append(f"Bluetooth SIG assigned numbers | {base} | commit {commit} {date} | company_identifiers.yaml, member_uuids.yaml | no explicit licence, public identifier-to-name pairs")

def appledb(report, sources):
    data = json.loads(get("https://api.appledb.dev/device/main.json"))
    def common(names):
        cleaned = {re.sub(r"\s*\((Left|Right|Case)\)", "", re.sub(r"\((Left|Right|Case),\s*", "(", n)).strip() for n in names}
        return sorted(cleaned, key=lambda n: (len(n), n))[0]
    by_id = collections.defaultdict(list)
    for rec in data:
        for ident in rec.get("identifier") or []: by_id[ident].append(rec["name"])
    models, proximity = {}, {}
    for ident, names in sorted(by_id.items()):
        name = clean(common(names))
        m = re.fullmatch(r"Device1,(\d+)", ident)
        if m:
            n = int(m.group(1))
            if n <= 0xFFFF: proximity[f"{(n & 0xFF) << 8 | n >> 8:04X}"] = name  # the app reads the code big endian
        else:
            models[ident] = name
    write_table("apple-models.txt", models, 600, must={"iPhone14,3": "iPhone 13 Pro Max"}, report=report)
    write_table("apple-proximity.txt", proximity, 30, must={"1420": "AirPods Pro (2nd generation)"}, report=report)
    sources.append("AppleDB | https://api.appledb.dev/device/main.json | fetched " + str(datetime.date.today()) + " | MIT, github.com/littlebyteorg/appledb")

def xiaomi(report, sources):
    path = "src/xiaomi_ble/devices.py"
    sha, date = github_commit("Bluetooth-Devices/xiaomi-ble", path)
    text = get(f"https://raw.githubusercontent.com/Bluetooth-Devices/xiaomi-ble/{sha}/{path}")
    rows = {}
    for pid, name, model in re.findall(r'0x([0-9A-Fa-f]{4}):\s*DeviceEntry\(\s*name="([^"]+)",\s*model="([^"]+)"', text):
        rows[pid.upper()] = clean(f"{name} {model}")
    write_table("xiaomi-products.txt", rows, 60, report=report)
    sources.append(f"xiaomi-ble | https://raw.githubusercontent.com/Bluetooth-Devices/xiaomi-ble/{sha}/{path} | commit {sha[:10]} {date} | Apache-2.0")

def short_uuid(u):
    u = u.upper()
    return u[4:8] if len(u) == 36 and u.startswith("0000") and u.endswith(BASE_UUID_SUFFIX) else u

def home_assistant(report, sources):
    path = "homeassistant/generated/bluetooth.py"
    sha, date = github_commit("home-assistant/core", path)
    src = get(f"https://raw.githubusercontent.com/home-assistant/core/{sha}/{path}")
    start = src.index("BLUETOOTH")
    matchers = ast.literal_eval(src[src.index("[", src.index("=", start)):src.rindex("]") + 1])
    domain_map = {}
    for line in DOMAINS.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"): continue
        domain, label, kind = line.split("\t")
        if kind != "-" and kind not in KINDS: sys.exit(f"ble_domain_map.tsv: unknown kind {kind!r} for {domain}")
        domain_map[domain] = (label, kind)
    unmapped, lines = collections.Counter(), {}
    for m in matchers:
        if "domain" not in m or ("manufacturer_id" not in m and "service_uuid" not in m and "service_data_uuid" not in m): continue
        if m["domain"] not in domain_map: unmapped[m["domain"]] += 1; continue
        label, kind = domain_map[m["domain"]]
        if kind == "-": continue
        cond = []
        if "manufacturer_id" in m: cond.append(f"mfr={m['manufacturer_id']}")
        if "manufacturer_data_start" in m: cond.append("start=" + bytes(m["manufacturer_data_start"]).hex().upper())
        if "service_uuid" in m: cond.append("svc=" + short_uuid(m["service_uuid"]))
        if "service_data_uuid" in m: cond.append("svcdata=" + short_uuid(m["service_data_uuid"]))
        lines.setdefault(" ".join(cond), set()).add((label, kind))
    # The same conditions for two different products say nothing, so drop them. Most specific conditions first.
    rows = {}
    for cond, owners in sorted(lines.items(), key=lambda i: (-len(i[0].split()), i[0])):
        if len(owners) == 1:
            label, kind = next(iter(owners))
            rows[cond] = f"{label}\t{kind}"
    # Layout is label, kind, conditions, so this file is written directly instead of through write_table.
    text = "".join(f"{v.split(chr(9))[0]}\t{v.split(chr(9))[1]}\t{k}\n" for k, v in rows.items())
    if len(rows) < 100: sys.exit(f"ble-matchers.txt: only {len(rows)} rows")
    path_out = OUT / "ble-matchers.txt"
    if path_out.exists() and len(rows) < len(path_out.read_text(encoding="utf-8").splitlines()) * 0.9:
        sys.exit("ble-matchers.txt: shrank over 10%, refusing")
    path_out.write_text(text, encoding="utf-8")
    report.append(f"ble-matchers.txt: {len(rows)} rows")
    if unmapped: report.append("UNMAPPED Home Assistant domains (add to scripts/ble_domain_map.tsv): " + ", ".join(f"{d} ({n})" for d, n in sorted(unmapped.items())))
    sources.append(f"Home Assistant | https://raw.githubusercontent.com/home-assistant/core/{sha}/{path} | commit {sha[:10]} {date} | Apache-2.0, NOTICE required")

def main():
    report, sources = [], []
    for step in (sig, appledb, xiaomi, home_assistant): step(report, sources)
    (OUT / "ble-data-SOURCE.txt").write_text(
        f"Generated by scripts/update_ble_data.py on {datetime.date.today()}\n\n" + "\n".join(sources) + "\n\n" + "\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))

if __name__ == "__main__":
    main()
