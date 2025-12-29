#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import requests

# ──────────────────────────────────────────────────────────────
# CONFIG (defaults)
# ──────────────────────────────────────────────────────────────
csv.field_size_limit(5000000)

DEFAULT_INPUT_CSV = Path(r".\staging\3_prepare_analyses\modat_service_all.csv")
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="

DEFAULT_USER_AGENT = "CVE-Scanner"
DEFAULT_REQUEST_DELAY_SEC = 0.75     # base throttle (tune with API key)
DEFAULT_RETRY_LIMIT = 10
DEFAULT_BACKOFF_MULTIPLIER = 1.7

# How often to checkpoint (rewrite output JSONL atomically)
CHECKPOINT_EVERY = 25

# CVE regex (robust across CSV cells / lists)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# ──────────────────────────────────────────────────────────────


@dataclass
class CvssSummary:
    v31_baseScore: Optional[float] = None
    v31_baseSeverity: Optional[str] = None
    v31_vectorString: Optional[str] = None
    v40_baseScore: Optional[float] = None
    v40_baseSeverity: Optional[str] = None
    v40_vectorString: Optional[str] = None


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_float(x: Any) -> Optional[float]:
    try:
        return float(x)
    except Exception:
        return None


def extract_unique_cves_from_csv(csv_path: Path, cve_column: str = "service.cves") -> List[str]:
    if not csv_path.exists():
        raise FileNotFoundError(f"Input CSV not found: {csv_path}")

    found: Set[str] = set()

    with csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return []

        if cve_column not in reader.fieldnames:
            raise KeyError(
                f"Column '{cve_column}' not found in CSV. Available columns: {', '.join(reader.fieldnames)}"
            )

        for row in reader:
            cell = (row.get(cve_column) or "").strip()
            if not cell:
                continue
            for m in CVE_RE.finditer(cell):
                found.add(m.group(0).upper())

    return sorted(found)


def load_existing_jsonl(jsonl_path: Path) -> Dict[str, Dict[str, Any]]:
    records: Dict[str, Dict[str, Any]] = {}
    if not jsonl_path.exists():
        return records

    with jsonl_path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                # keep going; malformed line shouldn't break the run
                continue

            # Try multiple known shapes:
            # 1) Our normalized record: {"cve_id": "..."} or {"cveId": "..."}
            cve = (obj.get("cve_id") or obj.get("cveId") or "").strip().upper()

            # 2) Raw-ish record: {"cve": {"id": "CVE-...."}}
            if not cve and isinstance(obj.get("cve"), dict):
                cve = str(obj["cve"].get("id", "")).strip().upper()

            # 3) Raw NVD API response: {"vulnerabilities":[{"cve":{"id":"CVE-...."}}]}
            if not cve and isinstance(obj.get("vulnerabilities"), list) and obj["vulnerabilities"]:
                first = obj["vulnerabilities"][0]
                if isinstance(first, dict) and isinstance(first.get("cve"), dict):
                    cve = str(first["cve"].get("id", "")).strip().upper()

            # 4) Our record with embedded NVD payload: {"nvd": {"vulnerabilities":[...]}}
            if not cve and isinstance(obj.get("nvd"), dict):
                vulns = obj["nvd"].get("vulnerabilities", [])
                if isinstance(vulns, list) and vulns:
                    first = vulns[0]
                    if isinstance(first, dict) and isinstance(first.get("cve"), dict):
                        cve = str(first["cve"].get("id", "")).strip().upper()

            if cve.startswith("CVE-"):
                records[cve] = obj
    return records


def write_jsonl_atomic(path: Path, records_by_cve: Dict[str, Dict[str, Any]]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for cve in sorted(records_by_cve.keys()):
            f.write(json.dumps(records_by_cve[cve], ensure_ascii=False) + "\n")
    tmp.replace(path)


def parse_cvss_from_nvd(nvd_json: Dict[str, Any]) -> CvssSummary:
    out = CvssSummary()

    vulns = nvd_json.get("vulnerabilities") or []
    if not vulns:
        return out

    cve = (vulns[0] or {}).get("cve", {}) or {}
    metrics = cve.get("metrics", {}) or {}

    def pick_metric(arr: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(arr, list) or not arr:
            return None
        # prefer 'Primary'
        for m in arr:
            if isinstance(m, dict) and m.get("type") == "Primary":
                return m
        # else first dict
        for m in arr:
            if isinstance(m, dict):
                return m
        return None

    v31 = pick_metric(metrics.get("cvssMetricV31"))
    if v31:
        cvss = v31.get("cvssData", {}) or {}
        out.v31_baseScore = safe_float(cvss.get("baseScore"))
        out.v31_baseSeverity = cvss.get("baseSeverity") or v31.get("baseSeverity")
        out.v31_vectorString = cvss.get("vectorString")

    v40 = pick_metric(metrics.get("cvssMetricV40"))
    if v40:
        cvss = v40.get("cvssData", {}) or {}
        out.v40_baseScore = safe_float(cvss.get("baseScore"))
        out.v40_baseSeverity = cvss.get("baseSeverity") or v40.get("baseSeverity")
        out.v40_vectorString = cvss.get("vectorString")

    return out


def fetch_nvd_cve(
    cve_id: str,
    *,
    api_key: str = "",
    user_agent: str = DEFAULT_USER_AGENT,
    request_delay_sec: float = DEFAULT_REQUEST_DELAY_SEC,
    retry_limit: int = DEFAULT_RETRY_LIMIT,
    backoff_multiplier: float = DEFAULT_BACKOFF_MULTIPLIER,
) -> Optional[Dict[str, Any]]:

    url = NVD_API_BASE + cve_id
    headers = {"User-Agent": user_agent}
    if api_key:
        headers["apiKey"] = api_key

    delay = request_delay_sec

    for attempt in range(1, retry_limit + 1):
        try:
            r = requests.get(url, headers=headers, timeout=45)
        except requests.RequestException as e:
            # transient network issue
            print(f"[NET] {cve_id}: {e} → wait {delay:.2f}s (attempt {attempt}/{retry_limit})")
            time.sleep(delay)
            delay *= backoff_multiplier
            continue

        if r.status_code == 200:
            try:
                return r.json()
            except json.JSONDecodeError:
                print(f"[JSON] {cve_id}: invalid JSON")
                return None

        if r.status_code == 429:
            print(f"[429] {cve_id}: rate limited → wait {delay:.2f}s (attempt {attempt}/{retry_limit})")
            time.sleep(delay)
            delay *= backoff_multiplier
            continue

        # Other HTTP errors: don't keep hammering
        print(f"[HTTP {r.status_code}] {cve_id}: {r.text[:200].strip()}")
        return None

    print(f"[FAIL] {cve_id}: max retries hit")
    return None


def records_to_flat_rows(records_by_cve: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []

    for cve_id in sorted(records_by_cve.keys()):
        rec = records_by_cve[cve_id]
        nvd = (rec.get("nvd") or {})
        vulns = nvd.get("vulnerabilities") or []
        cve_obj = ((vulns[0] or {}).get("cve") or {}) if vulns else {}

        published = cve_obj.get("published")
        last_modified = cve_obj.get("lastModified")

        # description (prefer EN)
        desc = None
        for d in (cve_obj.get("descriptions") or []):
            if isinstance(d, dict) and d.get("lang") == "en" and d.get("value"):
                desc = d.get("value")
                break
        if not desc:
            for d in (cve_obj.get("descriptions") or []):
                if isinstance(d, dict) and d.get("value"):
                    desc = d.get("value")
                    break

        cvss = rec.get("cvss") or {}
        rows.append({
            "cve_id": cve_id,
            "published": published,
            "lastModified": last_modified,
            "cvss_v31_baseScore": cvss.get("v31_baseScore"),
            "cvss_v31_baseSeverity": cvss.get("v31_baseSeverity"),
            "cvss_v31_vectorString": cvss.get("v31_vectorString"),
            "cvss_v40_baseScore": cvss.get("v40_baseScore"),
            "cvss_v40_baseSeverity": cvss.get("v40_baseSeverity"),
            "cvss_v40_vectorString": cvss.get("v40_vectorString"),
            "description_en": desc,
        })

    return rows


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def prompt_yes_no(question: str, default_no: bool = True) -> bool:
    """Minimal interactive prompt. In non-interactive environments, the default is applied."""
    if not sys.stdin.isatty():
        return False if default_no else True
    default = "n" if default_no else "y"
    resp = input(f"{question} [y/n] (default {default}): ").strip().lower()
    if not resp:
        return not default_no
    return resp in {"y", "yes"}


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Extract CVEs from Modat service CSV (service.cves) and fetch NVD details (JSONL + CSV)."
    )
    ap.add_argument("--input", type=str, default=str(DEFAULT_INPUT_CSV), help="Path to modat_service_all.csv")
    ap.add_argument("--delay", type=float, default=DEFAULT_REQUEST_DELAY_SEC, help="Base delay between requests.")
    ap.add_argument("--retry", type=int, default=DEFAULT_RETRY_LIMIT, help="Retry limit for 429/timeouts.")
    args = ap.parse_args()

    input_csv = Path(args.input)
    out_dir = input_csv.parent

    out_txt = out_dir / "cve_from_modat_service_api.txt"
    out_jsonl = out_dir / "cve_details_nvd_full.jsonl"
    out_csv = out_dir / "cve_details_nvd_full.csv"

    # 1) Extract CVEs from service.cves and write TXT
    cves = extract_unique_cves_from_csv(input_csv, cve_column="service.cves")
    out_txt.write_text("\n".join(cves) + ("\n" if cves else ""), encoding="utf-8")
    print(f"[OK] Extracted {len(cves)} unique CVEs from '{input_csv.name}' column 'service.cves' to {out_txt.name}")
    # print(f"[INFO] First 10 CVEs: {', '.join(cves[:10])}")

    if not cves:
        print("[INFO] No CVEs found. Exiting.")
        return

    # 2) Load existing JSONL (if any)
    existing = load_existing_jsonl(out_jsonl)
    existing_set = set(existing.keys())
    cve_set = set(cves)

    overlap = len(cve_set & existing_set)
    new_missing = sorted(cve_set - existing_set)
    extra_in_jsonl = sorted(existing_set - cve_set)

    print("\n""=== Resume / Rescan Overview ===")
    print(f"CVEs in {out_txt.name}: {len(cves)}")
    print(f"CVEs already in {out_jsonl.name}: {len(existing_set)}")
    print(f"Overlap (already covered): {overlap}")
    print(f"New CVEs (missing in JSONL): {len(new_missing)}")
    if extra_in_jsonl:
        print(f"Note: {len(extra_in_jsonl)} CVEs exist in JSONL but are not present in the current TXT list (kept unless refreshed).")

    # 3) Ask scan mode (US English as requested)
    print("Select scan mode:")
    print("  [1] Scan ONLY new CVEs (missing from JSONL)  [default]")
    print("  [2] Refresh ALL CVEs from TXT (overwrite existing records)")
    choice = input("Enter 1 or 2: ").strip()
    if choice not in {"1", "2"}:
        choice = "1"

    refresh_all = (choice == "2")
    to_fetch = cves if refresh_all else new_missing

    if not to_fetch:
        print("[INFO] Nothing to fetch (all CVEs are already present).")
        # Still (re)write CSV alongside JSONL to satisfy the requirement.
        rows = records_to_flat_rows(existing)
        write_csv(out_csv, rows)
        print(f"[OK] Wrote CSV → {out_csv.name} ({len(rows)} rows)")
        return

    api_key = input("Enter NVD API key (press Enter to continue without a key): ").strip()

    print("=== Scan Plan ===")
    print(f"Output JSONL: {out_jsonl}")
    print(f"Output CSV : {out_csv}")
    print(f"Will fetch : {len(to_fetch)} CVEs")
    print(f"Mode       : {'REFRESH ALL (overwrite)' if refresh_all else 'NEW ONLY'}")
    print(f"API key    : {'provided' if api_key else 'not provided'}")

    # 4) Fetch loop with checkpointing
    records_by_cve: Dict[str, Dict[str, Any]] = dict(existing)  # start with existing
    failed: List[str] = []

    for idx, cve in enumerate(to_fetch, start=1):
        print(f" → ({idx}/{len(to_fetch)}) querying {cve}")
        data = fetch_nvd_cve(
            cve,
            api_key=api_key,
            retry_limit=args.retry,
            request_delay_sec=args.delay,
        )

        if data is None:
            failed.append(cve)
            continue

        record = {
            "cve_id": cve,
            "fetched_at": utc_now_iso(),
            "cvss": asdict(parse_cvss_from_nvd(data)),
            "nvd": data,
        }

        # Overwrite existing record for this CVE (ensures each CVE appears once)
        records_by_cve[cve] = record

        # Checkpoint periodically so resume works after interruption
        if (idx % CHECKPOINT_EVERY) == 0:
            write_jsonl_atomic(out_jsonl, records_by_cve)
            # Always keep CSV next to JSONL (required)
            rows = records_to_flat_rows(records_by_cve)
            write_csv(out_csv, rows)
            print(f"[CHECKPOINT] Wrote {len(records_by_cve)} records → {out_jsonl.name} + {out_csv.name}")

    # Final write
    write_jsonl_atomic(out_jsonl, records_by_cve)
    rows = records_to_flat_rows(records_by_cve)
    write_csv(out_csv, rows)

    print(f"[OK] Wrote JSONL → {out_jsonl} ({len(records_by_cve)} unique CVEs)")
    print(f"[OK] Wrote CSV  → {out_csv} ({len(rows)} rows)")

    # Failures
    if failed:
        fail_path = out_dir / "cve_failed.txt"
        fail_path.write_text("\n".join(failed) + "\n", encoding="utf-8")
        print(f"[WARN] {len(failed)} CVEs failed → {fail_path}")


if __name__ == "__main__":
    main()