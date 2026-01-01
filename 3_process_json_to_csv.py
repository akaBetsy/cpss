#!/usr/bin/env python3

from __future__ import annotations

import csv
import sys
import json
import re
import hashlib
from pathlib import Path

PROGRESS_EVERY_N_FILES = 25

# ============================================================
# PATHS
# ============================================================
SERVICE_DIR = Path("./staging/2_modat_service_api")
OUTPUT_DIR = Path("./staging/3_prepare_analyses")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

OUT_CSV = OUTPUT_DIR / "modat_service_all.csv"
TMP_CSV = OUTPUT_DIR / (OUT_CSV.name + ".tmp")
MANIFEST_FILE = OUTPUT_DIR / "_manifest_modat_service.json"

DIR_1A = Path("./staging/1a_modat_host_api")
DIR_1B = Path("./staging/1b_networksdb_api")


# ============================================================
# SMALL UTILITIES
# ============================================================
DOMAIN_RE = re.compile(r"^(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.IGNORECASE)
SEP_SPLIT_RE = re.compile(r"[\s;|,]+")

def ask_yes_no(prompt: str, default_yes: bool = True) -> bool:
    ans = input(prompt).strip().lower()
    if not ans:
        return default_yes
    return ans in ("y", "yes", "j", "ja")


def clean_for_csv(value) -> str:
    """Minimal cleaning; keep semicolons intact."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)

    text = str(value)
    # Normalize whitespace, remove newlines/tabs
    text = text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ").replace("\t", " ")
    text = text.strip().strip('"').strip("'")
    return text


def dict_to_clean_string(obj) -> str:
    try:
        return clean_for_csv(json.dumps(obj, ensure_ascii=False, sort_keys=True))
    except Exception:
        return clean_for_csv(str(obj))

def normalize_fqdns(value) -> list[str]:
    def split_one(s: str) -> list[str]:
        parts = SEP_SPLIT_RE.split(s.strip())
        out = []
        for p in parts:
            t = p.strip().strip(".")
            if t:
                out.append(t)
        return out

    if value is None:
        return []

    # If list: flatten each element (and split if that element contains tabs/spaces etc.)
    if isinstance(value, list):
        out = []
        for x in value:
            if x is None:
                continue
            s = str(x).strip()
            if not s:
                continue
            out.extend(split_one(s))
        return out

    # If string: split once
    if isinstance(value, str):
        return split_one(value)

    # fallback
    s = str(value).strip().strip(".")
    return [s] if s else []



def normalize_domain_token(token: str) -> str | None:
    if not token:
        return None
    d = token.strip().lower().strip(".")
    if not d:
        return None
    if DOMAIN_RE.fullmatch(d):
        return d
    return None


def split_to_domains(value: str) -> list[str]:
    parts = SEP_SPLIT_RE.split(value.strip())
    out = []
    for p in parts:
        dom = normalize_domain_token(p)
        if dom:
            out.append(dom)
    return out


def flatten(obj, parent_key: str = "", sep: str = ".") -> dict[str, str]:
    items: dict[str, str] = {}

    if isinstance(obj, dict):
        for k, v in obj.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else str(k)

            # Skip raw certificate
            if new_key == "service.tls.raw":
                continue

            items.update(flatten(v, new_key, sep=sep))
        return items

    if isinstance(obj, list):
        # Always add count for lists (helps analysis)
        if parent_key:
            items[parent_key + "_count"] = str(len(obj))

        # List of primitives: join into one cell (use ';' to avoid '-' ambiguity)
        if all(not isinstance(x, (dict, list)) for x in obj):
            vals = [str(x) for x in obj if x is not None]
            items[parent_key] = clean_for_csv(";".join(vals))
            items[parent_key + "_count"] = str(len(vals))
            return items

        # List containing dict/list: stringify (keeps minimal complexity)
        items[parent_key] = dict_to_clean_string(obj)
        return items

    items[parent_key] = clean_for_csv(obj)
    return items


# ============================================================
# NIDV / company matching
# ============================================================
def extract_base_from_fqdn(fqdn: str) -> str:
    return (fqdn or "").strip().lower().strip(".")


def build_known_domains_index() -> set[str]:
    known: set[str] = set()

    # 1b: read domain
    if DIR_1B.exists():
        for f in DIR_1B.glob("*.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                d = data.get("domain")
                if isinstance(d, str) and d.strip():
                    for dom in split_to_domains(d):
                        known.add(dom)
            except Exception:
                pass

    # 1a: infer label from filename
    rx = re.compile(r"^modat_host_(?P<label>.+)_(?P<date>\d{8})\.json$", re.IGNORECASE)
    if DIR_1A.exists():
        for f in DIR_1A.glob("modat_host_*_*.json"):
            m = rx.match(f.name)
            if not m:
                continue
            label = m.group("label")
            if isinstance(label, str) and label.strip():
                # IMPORTANT: split label to avoid "ibm.com<TAB>maersk.com" becoming one known domain
                for dom in split_to_domains(label):
                    known.add(dom)
    return known


def match_nidv_company(fqdns: list[str], known_domains: set[str]) -> str:
    matches = set()
    for fqdn in fqdns or []:
        h = extract_base_from_fqdn(fqdn).strip(".")
        if not h:
            continue
        # Fast exact match
        if h in known_domains:
            matches.add(h)
            continue
        # Suffix match
        for dom in known_domains:
            if h.endswith("." + dom):
                matches.add(dom)
    return ";".join(sorted(matches))


# ============================================================
# MANIFEST (redo/skip)
# ============================================================
def dataset_fingerprint(service_dir: Path) -> dict:
    files = sorted(service_dir.glob("modat_service_*_*.json"))
    items = []
    for f in files:
        st = f.stat()
        items.append({"name": f.name, "size": st.st_size, "mtime": int(st.st_mtime)})

    blob = json.dumps(items, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return {"sha256": hashlib.sha256(blob).hexdigest(), "file_count": len(items), "files": items}


def load_manifest() -> dict | None:
    if not MANIFEST_FILE.exists():
        return None
    try:
        return json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))
    except Exception:
        return None


def save_manifest(m: dict) -> None:
    MANIFEST_FILE.write_text(json.dumps(m, indent=2), encoding="utf-8")


def atomic_replace(tmp_path: Path, final_path: Path) -> None:
    tmp_path.replace(final_path)

def progress_update(i: int, total: int, every: int = 25) -> None:
    if total <= 0:
        total = 1
    if not (i == 1 or i == total or (every and i % every == 0)):
        return

    pct = (i / total) * 100
    msg = f"[STATUS] Progress: {i}/{total} files ({pct:.1f}%)"

    sys.stdout.write("\r" + msg.ljust(80))
    sys.stdout.flush()


# ============================================================
# CORE PROCESSING
# ============================================================
def process_service_jsons_to_one_csv(service_dir: Path, output_csv_tmp: Path) -> bool:
    if not service_dir.exists():
        print(f"[ERROR] Directory not found: {service_dir}")
        return False

    json_files = sorted(service_dir.glob("modat_service_*_*.json"))
    if not json_files:
        print(f"[ERROR] No service JSON files found in: {service_dir}")
        return False

    known_domains = build_known_domains_index()
    print(f"[INFO] Known domain/company labels loaded: {len(known_domains)}")

    all_rows: list[dict[str, str]] = []
    all_headers: set[str] = set()

    total_files = len(json_files)

    for i, jf in enumerate(json_files, start=1):
        progress_update(i, total_files, every=PROGRESS_EVERY_N_FILES)
        try:
            data = json.loads(jf.read_text(encoding="utf-8"))
        except Exception:
            continue

        results = data.get("results", [])
        if not isinstance(results, list):
            continue

        # trace from filename: modat_service_<ip>_<YYYYMMDD>.json
        source_file = jf.name
        parts = jf.stem.split("_")
        source_ip = "_".join(parts[2:-1]) if len(parts) >= 4 else ""
        scan_date = parts[-1] if parts else ""

        for result in results:
            if not isinstance(result, dict):
                continue

            row = flatten(result)

            # Normalize fqdns for BOTH CSV output and nidv matching
            fqdns_norm = normalize_fqdns(result.get("fqdns"))

            # Overwrite flatten output to avoid TAB-separated / ambiguous formats
            row["fqdns"] = ";".join(fqdns_norm)
            row["fqdns"] = row["fqdns"].replace("\t", ";")
            row["fqdns_count"] = str(len(fqdns_norm))

            row["nidv_company"] = match_nidv_company(fqdns_norm, known_domains)
            row["nidv_hit"] = "1" if row["nidv_company"] else "0"

            row["source_file"] = source_file
            row["source_ip"] = source_ip
            row["scan_date"] = scan_date

            all_rows.append(row)
            all_headers.update(row.keys())

    sys.stdout.write("\n")
    sys.stdout.flush()

    if not all_rows:
        print("[ERROR] No rows collected; not writing CSV.")
        return False

    headers = sorted(all_headers)

    with output_csv_tmp.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=headers, quoting=csv.QUOTE_ALL, lineterminator="\n")
        w.writeheader()
        for r in all_rows:
            w.writerow({h: r.get(h, "") for h in headers})

    print(f"[INFO] Rows: {len(all_rows)}  Columns: {len(headers)}")
    return True


def main() -> int:
    new_fp = dataset_fingerprint(SERVICE_DIR)
    old_fp = load_manifest()

    unchanged = (
        OUT_CSV.exists()
        and old_fp is not None
        and old_fp.get("sha256") == new_fp.get("sha256")
    )

    if unchanged:
        do_skip = ask_yes_no(
            f"[INFO] Dataset unchanged ({new_fp['file_count']} JSON files). Skip rebuild? [Y/n]: ",
            default_yes=True,
        )
        if do_skip:
            print(f"[SKIP] Using existing CSV: {OUT_CSV}")
            return 0

    print("[RUN] Building CSV...")
    ok = process_service_jsons_to_one_csv(SERVICE_DIR, TMP_CSV)
    if not ok:
        print("[ERROR] Output was not written; not replacing existing CSV.")
        return 2

    atomic_replace(TMP_CSV, OUT_CSV)
    save_manifest(new_fp)

    print(f"[OK] Wrote: {OUT_CSV}")
    print(f"[OK] Updated manifest: {MANIFEST_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
