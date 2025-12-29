#!/usr/bin/env python3
from __future__ import annotations
import csv
import json
import time
import ipaddress
import requests
import re
from collections import defaultdict
from pathlib import Path
from datetime import datetime, timezone


# === CONFIGURATION ===
today = datetime.now().strftime("%Y%m%d")
timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")

INPUT_DIR = Path("./input")
API_KEY_FILE = INPUT_DIR / "api_keys" / "modat_api_key.txt"

MODAT_HOST_DIR = Path("./staging/1a_modat_host_api")
NETWORKSDB_DIR = Path("./staging/1b_networksdb_api")

OUT_DIR = Path("./staging/2_modat_service_api")
LOG_DIR = Path("./logs")

OUT_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

OUT_TXT = OUT_DIR / f"_domain_to_ip_{today}.txt"
LOG_FILE = LOG_DIR / f"modat_log_service_{timestamp}.csv"

API_URL = "https://api.magnify.modat.io/service/search/v1"

PAGE_SIZE = 100
MAX_RETRIES = 3
SLEEP_BETWEEN_IPS = 0.6
SLEEP_AFTER_BATCH = 30
BATCH_SIZE = 10


# === RESTART / CONTINUE SCAN HELPERS ===
def build_ip_file_index(out_dir: Path) -> dict[str, set[str]]:
    idx: dict[str, set[str]] = defaultdict(set)
    rx = re.compile(r"^(?:tmp_)?modat_service_(?P<safeip>.+)_(?P<date>\d{8})\.json$", re.IGNORECASE)

    if not out_dir.exists():
        return dict(idx)

    for f in out_dir.glob("*.json"):
        m = rx.match(f.name)
        if not m:
            continue
        idx[m.group("safeip")].add(m.group("date"))

    return dict(idx)

# === IPV4 extraction helpers ===
def normalize_ipv4(value) -> str | None:
    if value is None:
        return None
    s = str(value).strip().strip('"').strip("'")
    if not s:
        return None
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return None
    return str(ip) if ip.version == 4 else None


def iter_json_files(folder: Path) -> list[Path]:
    if not folder.exists():
        return []
    return sorted(p for p in folder.glob("*.json") if p.is_file())


def extract_ipv4s_from_networksdb_json(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return set()

    out: set[str] = set()

    def add_from_list(obj, key="ip"):
        if isinstance(obj, list):
            for e in obj:
                if isinstance(e, dict):
                    ip = normalize_ipv4(e.get(key))
                    if ip:
                        out.add(ip)

    add_from_list(data.get("ips"), "ip")
    add_from_list(data.get("ipv4_details"), "ip")

    if not out and isinstance(data.get("ips"), list):
        for e in data.get("ips"):
            if isinstance(e, str):
                ip = normalize_ipv4(e)
                if ip:
                    out.add(ip)
    return out


def extract_ipv4s_from_modat_host_json(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return set()

    results = data.get("results", data.get("page", []))
    if not isinstance(results, list):
        return set()

    out: set[str] = set()

    def try_add(v):
        ip = normalize_ipv4(v)
        if ip:
            out.add(ip)

    for item in results:
        if not isinstance(item, dict):
            continue

        for k in ("ip", "ip_str", "ip_address", "addr", "address"):
            if k in item:
                try_add(item.get(k))

        host = item.get("host")
        if isinstance(host, dict):
            for k in ("ip", "ip_str", "ip_address", "addr", "address"):
                if k in host:
                    try_add(host.get(k))

        interfaces = item.get("interfaces")
        if isinstance(interfaces, list):
            for iface in interfaces:
                if isinstance(iface, dict):
                    try_add(iface.get("ip"))

    return out


# === OUTPUT AND LOGGING ===
def write_txt_ips(path: Path, ips: list[str]) -> None:
    path.write_text("\n".join(ips) + ("\n" if ips else ""), encoding="utf-8")

def init_log() -> None:
    write_header = not LOG_FILE.exists() or LOG_FILE.stat().st_size == 0
    with LOG_FILE.open("a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if write_header:
            w.writerow(["ip", "status", "results", "timestamp"])

def log_row(ip: str, status: str, count: int) -> None:
    with LOG_FILE.open("a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([ip, status, count, datetime.now(timezone.utc).isoformat()])


# === Modat API helpers (service endpoint) ===
def load_api_key_or_fail() -> str:
    if not API_KEY_FILE.exists():
        raise FileNotFoundError(f"Modat API key file not found: '{API_KEY_FILE}'")
    token = API_KEY_FILE.read_text(encoding="utf-8").strip()
    if not token:
        raise RuntimeError(f"Modat API key file is empty: '{API_KEY_FILE}'")
    return token

def fetch_page(headers: dict, query: str, page: int) -> dict | None:
    payload = {"query": query, "page": page, "page_size": PAGE_SIZE}
    for attempt in range(1, MAX_RETRIES + 1):
        r = requests.post(API_URL, json=payload, headers=headers, timeout=60)
        if r.status_code == 200:
            try:
                return r.json()
            except Exception:
                return None
        if r.status_code == 429:
            wait = 3 * attempt
            print(f"[429] rate-limit → retry {attempt}/{MAX_RETRIES} in {wait}s...")
            time.sleep(wait)
            continue
        print(f"[HTTP {r.status_code}] {r.text}")
        break
    return None

def extract_results(data: dict) -> list:
    if not isinstance(data, dict):
        return []
    return data.get("page", []) or data.get("results", [])

def build_full_query_for_ip(ip: str) -> str:
    return f'ip = "{ip}"'


# === Resume support: temp file per IP ===
def safe_ip_for_filename(ip: str) -> str:
    return ip.replace(":", "-").replace("/", "_")

def temp_file_for_ip(ip: str) -> Path:
    safe_ip = safe_ip_for_filename(ip)
    return OUT_DIR / f"modat_service_{safe_ip}_{today}.json"

def load_completed_ips_from_temp() -> set[str]:
    completed = set()
    patterns = [
        f"modat_service_*_{today}.json",
        f"tmp_modat_service_*_{today}.json",  # compat met andere service-scripts
    ]
    for pat in patterns:
        for f in OUT_DIR.glob(pat):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                meta_ip = data.get("ip")
                if meta_ip:
                    completed.add(str(meta_ip).strip())
            except Exception:
                pass
    return completed

# === PARSE IP FROM FILENAME ===
def parse_ip_from_filename(filename: str) -> tuple[str | None, str | None]:
    # Matcht: modat_service_<ip>_<YYYYMMDD>.json
    if not filename.lower().startswith("modat_service_"):
        return None, None
    try:
        core = filename[len("modat_service_"):]
        ip, date = core.rsplit("_", 1)
        date = date.replace(".json", "")
        return ip.strip(), date.strip()
    except ValueError:
        return None, None


# === MAIN ===
def main() -> int:
    # 1) Combine + deduplicate all unique IPv4s from both staging folders
    modat_files = iter_json_files(MODAT_HOST_DIR)
    net_files = iter_json_files(NETWORKSDB_DIR)

    print(f"[INFO] Modat host JSON files : {len(modat_files)} ({MODAT_HOST_DIR})")
    print(f"[INFO] NetworksDB JSON files: {len(net_files)} ({NETWORKSDB_DIR})")

    modat_ips: set[str] = set()
    for p in modat_files:
        modat_ips |= extract_ipv4s_from_modat_host_json(p)

    net_ips: set[str] = set()
    for p in net_files:
        net_ips |= extract_ipv4s_from_networksdb_json(p)

    all_ips = sorted(modat_ips | net_ips, key=lambda s: ipaddress.ip_address(s))
    extra_net = sorted(net_ips - modat_ips, key=lambda s: ipaddress.ip_address(s))

    # 2) Write output txt for service scan input
    write_txt_ips(OUT_TXT, all_ips)

    # 3) “Pop up” summary + prompt to continue
    print("\n================ SUMMARY ================")
    print(f"Unique IPv4s (combined)           : {len(all_ips)}")
    print(f"Unique IPv4s from Modat host      : {len(modat_ips)}")
    print(f"Unique IPv4s from NetworksDB      : {len(net_ips)}")
    print(f"Extra IPv4s (NetworksDB vs host)  : {len(extra_net)}")
    print(f"Output list written to            : {OUT_TXT}")
    print("========================================\n")

    ans = input("Continue and rescan these IPs against Modat SERVICE API? [y/N]: ").strip().lower()
    if ans != "y":
        print("[INFO] Stopped before Modat service rescan.")
        return 0

    # 4) Start scan against Modat service API using the new txt as input
    ips_from_txt = [ln.strip() for ln in OUT_TXT.read_text(encoding="utf-8").splitlines() if ln.strip()]
    print(f"[INFO] Loaded {len(ips_from_txt)} IPv4s from '{OUT_TXT}' for service rescan.")

    token = load_api_key_or_fail()
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    init_log()

# === CONTINUE SCAN / RESCAN ===
    files = [f.name for f in OUT_DIR.glob("*.json")]

    index: dict[str, list[str]] = defaultdict(list)
    for fname in files:
        ip, date = parse_ip_from_filename(fname)
        if ip and date:
            index[ip].append(date)

    ips_today = []
    ips_old = []
    ips_no_files = []

    for ip in ips_from_txt:
        dates = index.get(ip, [])
        if not dates:
            ips_no_files.append(ip)
        elif today in dates:
            ips_today.append(ip)
        else:
            ips_old.append(ip)

    print("\n================ RESUME OVERVIEW ================")
    print(f"IPs with NO existing files                : {len(ips_no_files)}")
    print(f"IPs with files dated TODAY ({today})      : {len(ips_today)} → will be skipped")
    print(f"IPs with files dated OTHER than {today}   : {len(ips_old)}")
    print("=================================================\n")

    rescan_old = False
    if ips_old:
        rescan_old = input(
            f"{len(ips_old)} previously scanned IPs are not from today. Rescan these? [y/N]: "
        ).strip().lower() == "y"

    ips_to_scan = ips_no_files + (ips_old if rescan_old else [])

    print(f"[INFO] Final IPs to scan this run: {len(ips_to_scan)}")

    scan_count = 0

    for idx, ip in enumerate(ips_to_scan, start=1):
        if scan_count > 0 and scan_count % BATCH_SIZE == 0:
            print(f"[INFO] Batch limit reached ({BATCH_SIZE}). Sleeping {SLEEP_AFTER_BATCH}s...")
            time.sleep(SLEEP_AFTER_BATCH)

        print("\n" + "=" * 80)
        print(f"[{idx}/{len(ips_to_scan)}] Fetching services for IP: {ip}")
        query = build_full_query_for_ip(ip)
        print(query)
        print("=" * 80)

        first = fetch_page(headers, query, 1)
        if not first:
            print(f"[ERROR] No/failed response for IP {ip}")
            log_row(ip, "FAIL", 0)
            time.sleep(SLEEP_BETWEEN_IPS)
            continue

        pages = first.get("total_pages", 1)
        results = extract_results(first)
        collected = list(results)

        print(f"[INFO] IP {ip}: page 1/{pages}, {len(results)} records")

        for p in range(2, pages + 1):
            time.sleep(1.5)
            nxt = fetch_page(headers, query, p)
            if not nxt:
                print(f"[WARN] IP {ip}: stopped at page {p}")
                break
            page_results = extract_results(nxt)
            collected.extend(page_results)
            print(f"[INFO] IP {ip}: page {p}/{pages}, +{len(page_results)} records")

        # Write per-IP temp file immediately (for resume)
        tmp_path = temp_file_for_ip(ip)
        tmp_path.write_text(json.dumps({"ip": ip, "results": collected}, indent=2), encoding="utf-8")

        log_row(ip, "OK", len(collected))
        print(f"[INFO] IP {ip}: collected {len(collected)} service records → temp {tmp_path}")

        scan_count += 1
        time.sleep(SLEEP_BETWEEN_IPS)

    print("\n=== SERVICE RESCAN DONE ===")
    print(f"Temp files remain in: {OUT_DIR}")
    print(f"Log written to:      {LOG_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
