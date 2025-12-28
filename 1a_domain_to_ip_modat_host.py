import requests
from pathlib import Path
import json, time, os, csv
from datetime import datetime, timezone

# === FOLDER STRUCTURE ===
INPUT_DIR = Path("./input")
OUTPUT_DIR = Path(r"./staging/1a_modat_host_api")
LOG_DIR = Path("./logs")

# === CONFIGURATION ===
today = datetime.now().strftime("%Y%m%d")
API_URL = "https://api.magnify.modat.io/host/search/v1"
API_KEY_FILE = Path("./input/api_keys/modat_api_key.txt")
STRICT_SUFFIX_MATCH = True
PAGE_SIZE = 100
MAX_RETRIES = 3
SLEEP_BETWEEN_COMPANIES = 3.2
SLEEP_AFTER_BATCH = 30
BATCH_SIZE = 10

# === PREPARE OUTPUT ===
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)
timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
LOG_FILE = os.path.join(LOG_DIR, f"modat_host_api_log_{timestamp}.csv")

# === LOGGING HELPERS ===
def init_log_file():
    need_header = not os.path.exists(LOG_FILE) or os.path.getsize(LOG_FILE) == 0
    with open(LOG_FILE, 'a', newline='', encoding='utf-8') as logf:
        writer = csv.writer(logf)
        if need_header:
            writer.writerow(['company', 'status', 'results', 'timestamp'])

def append_log_row(company, status, count):
    with open(LOG_FILE, 'a', newline='', encoding='utf-8') as logf:
        writer = csv.writer(logf)
        writer.writerow([company, status, count, datetime.now(timezone.utc).isoformat()])


# === INPUT MOST RECENT .txt FROM .\input ===
def newest_txt_in_input(input_dir: Path) -> Path:
    txts = [p for p in input_dir.glob("*.txt") if p.is_file()]
    if not txts:
        raise FileNotFoundError(f"No .txt files found in '{input_dir.resolve()}'")
    return max(txts, key=lambda p: p.stat().st_mtime)

COMPANY_LIST_FILE = newest_txt_in_input(INPUT_DIR)
print(f"[INFO] Using newest input list: '{COMPANY_LIST_FILE}'")


# === LOAD API KEY OPTION ===
headers = {"Accept": "application/json"}

if API_KEY_FILE.exists():
    with open(API_KEY_FILE, "r", encoding="utf-8") as f:
        api_key = f.read().strip()
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    else:
        raise RuntimeError(f"API key file is empty: '{API_KEY_FILE}'")
else:
    raise FileNotFoundError(f"API key file not found: '{API_KEY_FILE}'")

# === LOAD MOST RECENT .txt FROM .\input ===
with open(COMPANY_LIST_FILE, "r", encoding="utf-8") as f:
    companies = sorted(set([line.strip() for line in f if line.strip()]))


# === HELPER TO RESCAN FROM LAST COMPANY WHEN INTERRUPTED ===
def load_completed_safe_names() -> set[str]:
    completed = set()
    if not OUTPUT_DIR.exists():
        return completed

    for f in OUTPUT_DIR.glob("modat_host_*_*.json"):
        stem = f.stem
        parts = stem.split("_")
        if len(parts) >= 4:
            safe_name_parts = parts[2:-1]
            safe_name = "_".join(safe_name_parts).lower()
            completed.add(safe_name)
    return completed

COMPLETED_SAFE_NAMES = load_completed_safe_names()
print(f"[INFO] Found {len(COMPLETED_SAFE_NAMES)} already processed companies in '{OUTPUT_DIR}'.")


# === FUNCTION TO FETCH A PAGE WITH RETRIES ===
def fetch_page(q, page_num):
    payload = {"query": q, "page": page_num, "page_size": PAGE_SIZE}
    for attempt in range(1, MAX_RETRIES + 1):
        response = requests.post(API_URL, json=payload, headers=headers)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 429:
            wait_time = 5 * attempt
            print(f"Rate limit hit (429), retry {attempt}/{MAX_RETRIES} after {wait_time}s...")
            time.sleep(wait_time)
        else:
            print(f"HTTP {response.status_code}: {response.text}")
            break
    return None

def extract_results(response_data):
    if not isinstance(response_data, dict):
        return []
    return response_data.get("page", []) or response_data.get("results", [])


# === STRICT SUFFIX MATCH HELPERS ===
def _under(h, base):
    if not isinstance(h, str): return False
    h = h.lower().strip("."); base = base.lower().strip(".")
    return h == base or h.endswith("." + base)

def _host_from(item: dict) -> str:
    for k in ("host", "hostname", "fqdn", "domain", "name"):
        v = item.get(k)
        if isinstance(v, str) and v:
            return v
        if isinstance(v, dict):
            for kk in ("hostname", "name", "fqdn", "value"):
                vv = v.get(kk)
                if isinstance(vv, str) and vv:
                    return vv
    h = item.get("host")
    if isinstance(h, dict):
        for kk in ("hostname", "name", "fqdn", "value"):
            vv = h.get(kk)
            if isinstance(vv, str) and vv:
                return vv
    return ""

def _sans_from(item: dict) -> list[str]:
    s = item.get("san")
    if s is None:
        cert = item.get("cert")
        if isinstance(cert, dict):
            s = cert.get("san")
    if isinstance(s, str): return [s]
    if isinstance(s, list): return [x for x in s if isinstance(x, str)]
    return []


def _fqdns_from(item: dict) -> list[str]:
    f = item.get("fqdns")
    out = []
    if isinstance(f, str):
        out.append(f)
    elif isinstance(f, list):
        out.extend([x for x in f if isinstance(x, str)])

    h = item.get("host")
    if isinstance(h, dict):
        hf = h.get("fqdns")
        if isinstance(hf, str):
            out.append(hf)
        elif isinstance(hf, list):
            out.extend([x for x in hf if isinstance(x, str)])
    return out



# === MAIN LOOP ===
init_log_file()
log_entries = []
scan_count = 0

for idx, company in enumerate(companies):
    if scan_count > 0 and scan_count % BATCH_SIZE == 0:
        print(f"Batch limit reached ({BATCH_SIZE}). Sleeping {SLEEP_AFTER_BATCH} seconds...")
        time.sleep(SLEEP_AFTER_BATCH)

    company = company.strip()
    if not company:
        continue

    company_lower = company.lower()
    safe_name = company_lower.replace(" ", "_").replace("/", "_")

    if safe_name in COMPLETED_SAFE_NAMES:
        print(f"[SKIP] {company} (safe_name='{safe_name}') already processed in '{OUTPUT_DIR}'.")
        append_log_row(company, "SKIP_EXISTS", 0)
        continue

    query = f"(web.html ~ {company_lower}) OR (cert ~ {company_lower}) OR (domain ~ {company_lower})"
    print(f"\n Querying {company}...")

    response_data = fetch_page(query, 1)
    if not response_data:
        log_entries.append([company, "FAIL", 0, timestamp])
        continue

    total_pages = response_data.get("total_pages", 1)
    total_records = response_data.get("total_records", 0)
    results = extract_results(response_data)
    all_results = results.copy()

    print(f"Fetched page 1 of {total_pages}, {len(results)} results (total: {total_records})")

    for page_num in range(2, total_pages + 1):
        time.sleep(3.1)
        page_data = fetch_page(query, page_num)
        if not page_data:
            print(f"Failed to fetch page {page_num}")
            break
        results = extract_results(page_data)
        all_results.extend(results)
        print(f"Fetched page {page_num} of {total_pages}, {len(results)} results")


    # === FILTER RESULTS (strict suffix match) ===
    if STRICT_SUFFIX_MATCH:
        filtered = []
        for it in all_results:
            h = _host_from(it)
            sans = _sans_from(it)
            fqdns = _fqdns_from(it)
            if _under(h, company_lower) or any(_under(s, company_lower) for s in sans) or any(_under(f, company_lower) for f in fqdns):
                filtered.append(it)
        if len(filtered) != len(all_results):
            print(f"[FILTER] removed {len(all_results) - len(filtered)} outside *.{company_lower}")
        all_results = filtered


    # === SAVE RESULTS ===
    scan_count += 1
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    safe_name = company_lower.replace(" ", "_").replace("/", "_")
    output_file = os.path.join(OUTPUT_DIR, f"modat_host_{safe_name}_{date_str}.json")
    with open(output_file, "w", encoding="utf-8") as f_out:
        json.dump({"results": all_results}, f_out, indent=2)

    print(f"Saved {len(all_results)} results to '{output_file}'")
    append_log_row(company, "OK", len(all_results))
    time.sleep(SLEEP_BETWEEN_COMPANIES)

print(f"Logging to '{LOG_FILE}' (appended per company).")
