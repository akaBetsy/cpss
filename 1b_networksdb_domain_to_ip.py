from pathlib import Path
import requests, json, time, ipaddress
from datetime import datetime
from typing import Dict, List, Any

# === CONFIGURATION ===
today = datetime.now().strftime("%Y%m%d")
INPUT_DIR = Path("./input")
API_KEY_DIR = INPUT_DIR / "api_keys"
api_key_path = API_KEY_DIR / "networksdb_api_key.txt"
STAGING_DIR = Path("./staging/1b_networksdb_api")
STAGING_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR = Path("./logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)
log_file = LOG_DIR / f"networksdb_log_{today}.csv"

# === INPUT MOST RECENT .txt FROM .\input ===
def newest_txt_in_input(input_dir: Path) -> Path:
    txts = [p for p in input_dir.glob("*.txt") if p.is_file()]
    if not txts:
        raise FileNotFoundError(f"No .txt files found in '{input_dir.resolve()}'")
    return max(txts, key=lambda p: p.stat().st_mtime)

input_file = newest_txt_in_input(INPUT_DIR)
print(f"[INFO] Using newest input list: '{input_file}'")

base_output_dir = STAGING_DIR


# Load API key
with api_key_path.open("r") as f:
    api_key = f.read().strip()

headers = {"X-Api-Key": api_key}
delay_seconds = 1.5

# Load domains
with input_file.open("r", encoding="utf-8") as f:
    domains = [line.strip() for line in f if line.strip()]

# Already processed domains detection
def load_completed_safe_domains() -> set[str]:
    completed = set()
    if not STAGING_DIR.exists():
        return completed

    for f in STAGING_DIR.glob("networksdb_*_*.json"):
        stem = f.stem
        parts = stem.split("_")
        if len(parts) >= 3:
            safe_parts = parts[1:-1]
            safe = "_".join(safe_parts).lower()
            completed.add(safe)
    return completed

COMPLETED_SAFE_DOMAINS = load_completed_safe_domains()
print(f"[INFO] Found {len(COMPLETED_SAFE_DOMAINS)} already processed domains in '{STAGING_DIR}'.")


# === HELPER: NORMALIZE IP object for parity with MODAT ===
def _normalize_ip(ip_info: Dict[str, Any]) -> Dict[str, Any]:
    ip = ip_info.get("ip")
    info = ip_info.get("ip_info", {}) or {}

    out: Dict[str, Any] = {"ip": ip}

    # version
    try:
        out["version"] = ipaddress.ip_address(ip).version
    except Exception:
        out["version"] = None

    # common fields (robust to varying schemas)
    out["asn"] = info.get("asn") or info.get("asn_number")
    out["org"] = info.get("org") or info.get("organization")
    out["country"] = info.get("country")
    out["tags"] = info.get("tags")
    out["sources"] = ["networksdb:dns", "networksdb:ip-info"]

    # placeholder if reverse DNS added later
    out["rdns"] = info.get("reverse_dns") or []

    return out

# Open log file for appending
with log_file.open("a", encoding="utf-8") as log:
    if log.tell() == 0:
        log.write("domain,status,results,timestamp\n")

    for domain in domains:
        safe = domain.replace("/", "_").lower()

        if safe in COMPLETED_SAFE_DOMAINS:
            print(f"[SKIP] {domain} (safe='{safe}') already processed in '{STAGING_DIR}'.")
            log.write(f"{domain},SKIP_EXISTS,0,\"{datetime.now().isoformat()}\"\n")
            continue

        print(f"Querying: {domain}")
        domain_data: Dict[str, Any] = {"domain": domain, "timestamp": datetime.now().isoformat()}
        ipv4_results: List[Dict[str, Any]] = []
        ipv6_results: List[Dict[str, Any]] = []
        flat_ips: List[Dict[str, Any]] = []

        try:
            # /api/dns
            dns_resp = requests.get(
                "https://networksdb.io/api/dns",
                headers=headers,
                params={"domain": domain},
                timeout=30
            )
            dns_resp.raise_for_status()
            dns_data = dns_resp.json()
            if not isinstance(dns_data, dict):
                raise ValueError("DNS response is not a JSON object.")
            domain_data["dns"] = dns_data
            raw_ips = dns_data.get("results", [])
            ips = []
            for entry in raw_ips:
                if isinstance(entry, str):
                    ips.append({"ip": entry})
                elif isinstance(entry, dict) and "ip" in entry:
                    ips.append(entry)


            # /api/org-search
            org_name = domain.split(".")[0]
            org_resp = requests.post(
                "https://networksdb.io/api/org-search",
                headers=headers,
                data={"search": org_name},
                timeout=30
            )
            org_resp.raise_for_status()
            domain_data["org_search"] = org_resp.json()

            # Enrich IPs
            for ip_entry in ips:
                ip = ip_entry.get("ip")
                if not ip:
                    continue

                ip_info = {"ip": ip}

                # /api/ip-info
                ip_resp = requests.post(
                    "https://networksdb.io/api/ip-info",
                    headers=headers,
                    data={"ip": ip},
                    timeout=30
                )
                ip_resp.raise_for_status()
                ip_info["ip_info"] = ip_resp.json()

                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if ip_obj.version == 4:
                        ipv4_results.append(ip_info)
                    else:
                        ipv6_results.append(ip_info)
                except ValueError:
                    ip_info["error"] = "Invalid IP format"
                    ipv4_results.append(ip_info)
                flat_ips.append(_normalize_ip(ip_info))

                time.sleep(delay_seconds)

            domain_data["ipv4_details"] = ipv4_results
            domain_data["ipv6_details"] = ipv6_results
            domain_data["ips"] = flat_ips

            # Save JSON output
            output_file = base_output_dir / f"networksdb_{domain.replace('/', '_')}_{today}.json"
            with output_file.open("w", encoding="utf-8") as outf:
                json.dump(domain_data, outf, indent=2)

            print(f"Saved: {output_file.name}")
            log.write(f"{domain},success,{len(ips)},\"{datetime.now().isoformat()}\"\n")

        except Exception as e:
            print(f"Error for {domain}: {e}")
            log.write(f"{domain},error,0,\"{datetime.now().isoformat()}\"\n")

        time.sleep(delay_seconds)