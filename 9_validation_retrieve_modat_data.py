#!/usr/bin/env python3
from __future__ import annotations

import json
import time
import csv
from pathlib import Path
from datetime import datetime, timezone
import requests

# =========================
# CONFIG
# =========================
COUNTRY = "NL"
TAGS = ["access management", "alarm", "building automation", "camera"]
EXCLUDE_TAG = "honeypot"

API_URL = "https://api.magnify.modat.io/service/search/v1"
API_KEY_FILE = Path("./input/api_keys/modat_api_key.txt")

PAGE_SIZE = 100
MAX_RETRIES = 3
SLEEP_BETWEEN_REQ = 1.2

OUT_DIR = Path("./staging/3_prepare_analyses")
FINAL_OUT = OUT_DIR / ".6_modat_data_validation.json"
TMP_OUT = OUT_DIR / ".6_tmp_modat_data_validation.json"
LOG_DIR = Path("./logs")

# =========================
# HELPERS
# =========================
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def load_api_key_or_fail() -> str:
    if not API_KEY_FILE.exists():
        raise FileNotFoundError(f"Modat API key file not found: '{API_KEY_FILE}'")
    token = API_KEY_FILE.read_text(encoding="utf-8").strip()
    if not token:
        raise RuntimeError(f"Modat API key file is empty: '{API_KEY_FILE}'")
    return token

def build_query() -> str:
    tag_filter = " OR ".join([f'tag="{t}"' for t in TAGS])
    return f'country="{COUNTRY}" AND ({tag_filter}) AND tag!="{EXCLUDE_TAG}"'

def extract_results(data: dict) -> list:
    if not isinstance(data, dict):
        return []
    return data.get("page", []) or data.get("results", []) or []

def post_page(headers: dict, query: str, page: int) -> dict | None:
    payload = {"query": query, "page": page, "page_size": PAGE_SIZE}
    for attempt in range(1, MAX_RETRIES + 1):
        r = requests.post(API_URL, json=payload, headers=headers, timeout=60)
        if r.status_code == 200:
            try:
                return r.json()
            except Exception:
                return None
        if r.status_code == 429:
            wait = 4 * attempt
            print(f"[429] rate-limit → retry {attempt}/{MAX_RETRIES} in {wait}s...")
            time.sleep(wait)
            continue
        print(f"[HTTP {r.status_code}] {r.text}")
        break
    return None

def ensure_dirs():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

def init_log_file(path: Path) -> None:
    need_header = (not path.exists()) or path.stat().st_size == 0
    with path.open("a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if need_header:
            w.writerow(["query", "page", "status", "results", "timestamp"])

def log_row(path: Path, query: str, page: int, status: str, count: int) -> None:
    with path.open("a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([query, page, status, count, utc_now_iso()])

def load_tmp_state() -> dict:
    if not TMP_OUT.exists():
        return {}
    try:
        return json.loads(TMP_OUT.read_text(encoding="utf-8"))
    except Exception:
        return {}

def save_tmp_state(state: dict) -> None:
    TMP_OUT.write_text(json.dumps(state, indent=2), encoding="utf-8")

def consolidate_to_final(state: dict) -> None:
    results_by_page = state.get("results_by_page", {}) or {}
    pages = sorted(
        (int(k) for k in results_by_page.keys() if str(k).isdigit()),
        key=int
    )
    combined: list = []
    for p in pages:
        combined.extend(results_by_page.get(str(p), []) or [])

    final = {
        "meta": state.get("meta", {}),
        "query": state.get("query"),
        "total_pages": state.get("total_pages"),
        "pages_done": pages,
        "results_count": len(combined),
        "results": combined,
        "exported_at": utc_now_iso(),
    }
    FINAL_OUT.write_text(json.dumps(final, indent=2), encoding="utf-8")

# =========================
# MAIN
# =========================
def main() -> int:
    ensure_dirs()

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
    log_file = LOG_DIR / f"modat_service_validation_{ts}.csv"
    init_log_file(log_file)

    token = load_api_key_or_fail()
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    query = build_query()
    state = load_tmp_state()

    # Initialize or validate tmp state
    if not state or state.get("query") != query:
        # Start fresh tmp if none exists OR query changed
        state = {
            "meta": {
                "script": "6_modat_data_validation.py",
                "api_url": API_URL,
                "page_size": PAGE_SIZE,
                "started_at": utc_now_iso(),
            },
            "query": query,
            "pages_done": [],
            "total_pages": None,
            "results_by_page": {},
        }
        save_tmp_state(state)
        print(f"[INFO] Initialized temp state: {TMP_OUT}")
    else:
        print(f"[INFO] Resuming from temp state: {TMP_OUT}")

    pages_done = set(int(p) for p in state.get("pages_done", []) if str(p).isdigit())
    total_pages = state.get("total_pages")  # may be None

    # If we don't know total_pages yet, fetch page 1 (unless already done)
    if total_pages is None and 1 not in pages_done:
        first = post_page(headers, query, 1)
        if not first:
            log_row(log_file, query, 1, "FAIL", 0)
            print("[ERROR] Failed to fetch first page; cannot determine total_pages.")
            return 1
        total_pages = int(first.get("total_pages", 1) or 1)
        results = extract_results(first)
        state["total_pages"] = total_pages
        state["results_by_page"]["1"] = results
        pages_done.add(1)
        state["pages_done"] = sorted(pages_done)
        save_tmp_state(state)
        log_row(log_file, query, 1, "OK", len(results))
        print(f"[INFO] Saved page 1/{total_pages} ({len(results)} records) to temp.")
        time.sleep(SLEEP_BETWEEN_REQ)

    # If total_pages still unknown but page 1 already done, infer from stored state (fallback)
    if total_pages is None:
        total_pages = state.get("total_pages") or 1

    # Continue remaining pages
    for page in range(1, int(total_pages) + 1):
        if page in pages_done:
            continue

        data = post_page(headers, query, page)
        if not data:
            log_row(log_file, query, page, "FAIL", 0)
            print(f"[ERROR] Failed page {page}; temp preserved for resume.")
            return 1

        # Update total_pages in case API returns it consistently
        total_pages = int(data.get("total_pages", total_pages) or total_pages)
        state["total_pages"] = total_pages

        results = extract_results(data)
        state["results_by_page"][str(page)] = results

        pages_done.add(page)
        state["pages_done"] = sorted(pages_done)
        save_tmp_state(state)

        log_row(log_file, query, page, "OK", len(results))
        print(f"[INFO] Saved page {page}/{total_pages} ({len(results)} records) to temp.")
        time.sleep(SLEEP_BETWEEN_REQ)

    # Consolidate
    consolidate_to_final(state)
    print(f"[INFO] Done. Final output: {FINAL_OUT}")
    print(f"[INFO] Temp state kept for traceability/resume: {TMP_OUT}")
    print(f"[INFO] Log: {log_file}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
