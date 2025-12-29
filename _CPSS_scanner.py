#!/usr/bin/env python3
"""
CPSS Resilience Scanner - Orchestrator (Flow Runner)

What this script does (v0):
- Welcomes user + states prerequisites (Modat + NetworksDB API keys)
- Determines input method:
  - If a file exists in input:
      - PDF  -> run 0_input_domains_from_PDF.py (expects it to write a .txt into input)
      - TXT  -> use it directly
      - Other -> try to extract domains and write a TXT to input; if not possible, ask user to choose PDF/TXT/manual
  - If no file in input or user chooses manual:
      - ask for a domain (popup) and write a TXT into input
- Runs:
  - 1a_domain_to_ip_modat_host.py
  - 1b_networksdb_domain_to_ip.py
- Summarizes and asks whether to continue with:
  - 2_modat_service_api.py.py  (if present; also accepts 2_modat_service_api.py)

Assumptions (kept minimal):
- All scripts are in the same folder as this orchestrator.
- 0_input_domains_from_PDF.py writes a .txt into input (or you can place your own .txt).
"""

from __future__ import annotations

import re
import sys
import subprocess
from pathlib import Path
from datetime import datetime

# --- Optional popups (tkinter) ---
try:
    import tkinter as tk
    from tkinter import messagebox, simpledialog
    TK_AVAILABLE = True
except Exception:
    TK_AVAILABLE = False


# ============================================================
# Paths & expected script names
# ============================================================
BASE_DIR = Path(__file__).resolve().parent

INPUT_DIR = BASE_DIR / "input"
API_KEY_DIR = INPUT_DIR / "api_keys"

STAGING_1A = BASE_DIR / "staging" / "1a_modat_host_api"
STAGING_1B = BASE_DIR / "staging" / "1b_networksdb_api"

SCRIPT_PDF = BASE_DIR / "0_input_domains_from_PDF.py"
SCRIPT_1A = BASE_DIR / "1a_domain_to_ip_modat_host.py"
SCRIPT_1B = BASE_DIR / "1b_networksdb_domain_to_ip.py"
SCRIPT_2 = BASE_DIR / "2_modat_service_api.py.py"  # as requested
SCRIPT_2_ALT = BASE_DIR / "2_modat_service_api.py"

MODAT_KEY = API_KEY_DIR / "modat_api_key.txt"
NETWORKSDB_KEY = API_KEY_DIR / "networksdb_api_key.txt"


# ============================================================
# UI helpers
# ============================================================
def _tk_root():
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    return root


def popup_info(title: str, msg: str) -> None:
    if TK_AVAILABLE:
        r = _tk_root()
        messagebox.showinfo(title, msg)
        r.destroy()
    else:
        print(f"[INFO] {title}: {msg}")


def popup_yesno(title: str, msg: str) -> bool:
    if TK_AVAILABLE:
        r = _tk_root()
        res = messagebox.askyesno(title, msg)
        r.destroy()
        return bool(res)
    else:
        ans = input(f"{title}: {msg} [y/N]: ").strip().lower()
        return ans == "y"


def popup_choice_method() -> str:
    """
    Ask user to choose among: pdf / txt / manual
    Returns one of: "pdf", "txt", "manual"
    """
    msg = (
        "Input file format could not be processed.\n\n"
        "Choose an alternative method:\n"
        "- PDF (extract domains)\n"
        "- TXT (domain list)\n"
        "- Manual (single domain)\n"
    )
    if TK_AVAILABLE:
        r = _tk_root()
        # minimal: reuse a simpledialog with constrained validation
        while True:
            v = simpledialog.askstring("Choose input method", msg + "\nType: pdf / txt / manual", parent=r)
            if v is None:
                r.destroy()
                return "manual"
            v = v.strip().lower()
            if v in ("pdf", "txt", "manual"):
                r.destroy()
                return v
    else:
        while True:
            v = input("Choose input method [pdf/txt/manual]: ").strip().lower()
            if v in ("pdf", "txt", "manual"):
                return v


def popup_ask_domain() -> str | None:
    if TK_AVAILABLE:
        r = _tk_root()
        v = simpledialog.askstring(
            "Manual domain input",
            "Enter a single domain (e.g., example.com).",
            parent=r
        )
        r.destroy()
        return v.strip() if v else None
    else:
        v = input("Enter a single domain (e.g., example.com): ").strip()
        return v or None


# ============================================================
# Domain extraction / validation
# ============================================================
DOMAIN_RE = re.compile(
    r"\b(?=.{1,253}\b)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+(?:[a-zA-Z]{2,63})\b"
)

def normalize_domain(d: str) -> str | None:
    if not d:
        return None
    d = d.strip().lower()

    # Strip common URL wrappers
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0]
    d = d.strip(" .")

    # Basic regex check
    if not DOMAIN_RE.fullmatch(d):
        return None

    # IDNA normalization (safe minimal)
    try:
        d = d.encode("idna").decode("ascii")
    except Exception:
        return None

    # Prevent obvious garbage
    if ".." in d or d.startswith("-") or d.endswith("-"):
        return None

    return d


def extract_domains_from_text(text: str) -> list[str]:
    found = set()
    for m in DOMAIN_RE.finditer(text or ""):
        nd = normalize_domain(m.group(0))
        if nd:
            found.add(nd)
    return sorted(found)


def newest_file_in_input() -> Path | None:
    if not INPUT_DIR.exists():
        return None
    files = [p for p in INPUT_DIR.iterdir() if p.is_file()]
    if not files:
        return None
    return max(files, key=lambda p: p.stat().st_mtime)


def newest_txt_in_input() -> Path | None:
    if not INPUT_DIR.exists():
        return None
    txts = [p for p in INPUT_DIR.glob("*.txt") if p.is_file()]
    if not txts:
        return None
    return max(txts, key=lambda p: p.stat().st_mtime)


def write_domains_txt(domains: list[str], out_path: Path) -> None:
    out_path.write_text("\n".join(domains) + ("\n" if domains else ""), encoding="utf-8")


# ============================================================
# Script runner
# ============================================================
def run_script(script_path: Path) -> None:
    if not script_path.exists():
        raise FileNotFoundError(f"Script not found: {script_path}")
    print(f"\n[RUN] {script_path.name}")
    # Use current interpreter to avoid environment mismatch
    subprocess.run([sys.executable, str(script_path)], cwd=str(BASE_DIR), check=True)


# ============================================================
# Flow
# ============================================================
def main() -> int:
    print("=" * 80)
    print("CPSS Resilience Scanner")
    print("=" * 80)
    print("Prerequisites:")
    print(f"- Modat.io API key      : {MODAT_KEY}")
    print(f"- NetworksDB.io API key : {NETWORKSDB_KEY}")
    print()

    INPUT_DIR.mkdir(parents=True, exist_ok=True)
    API_KEY_DIR.mkdir(parents=True, exist_ok=True)

    # Prereq check (non-invasive: inform + allow user to continue, but scripts may fail)
    missing = []
    if not MODAT_KEY.exists():
        missing.append("Modat API key (input/api_keys/modat_api_key.txt)")
    if not NETWORKSDB_KEY.exists():
        missing.append("NetworksDB API key (input/api_keys/networksdb_api_key.txt)")

    if missing:
        popup_info(
            "Missing prerequisites",
            "The following API key file(s) are missing:\n- " + "\n- ".join(missing) +
            "\n\nYou can continue, but API calls may fail."
        )
    input("\nPrerequisites check complete. Press ENTER to continue or Ctrl+C to abort...")

    # Decide input method based on file presence
    input_file = newest_file_in_input()
    if input_file:
        print(f"[INFO] Found input file: {input_file.relative_to(BASE_DIR)}")
    else:
        print("[INFO] No input file found in input")

    # If file exists, process by extension; otherwise manual
    if input_file:
        ext = input_file.suffix.lower()

        if ext == ".pdf":
            # run PDF extractor
            if not SCRIPT_PDF.exists():
                popup_info("Error", f"Missing PDF extractor script: {SCRIPT_PDF.name}")
                return 2

            run_script(SCRIPT_PDF)

            # Expect a TXT to exist afterwards
            txt = newest_txt_in_input()
            if not txt:
                popup_info(
                    "No TXT produced",
                    """PDF extraction finished, but no .txt file was found in input.\n"""
                    """Please ensure 0_input_domains_from_PDF.py writes domains to a .txt in input."""
                )
                return 2

            print(f"[INFO] Using extracted TXT: {txt.relative_to(BASE_DIR)}")

        elif ext == ".txt":
            # Use directly
            print("[INFO] TXT detected; using it as domain list.")

        else:
            # Try to read and extract domains
            try:
                raw = input_file.read_text(encoding="utf-8", errors="ignore")
                domains = extract_domains_from_text(raw)
            except Exception:
                domains = []

            if not domains:
                method = popup_choice_method()
                if method == "pdf":
                    if not SCRIPT_PDF.exists():
                        popup_info("Error", f"Missing PDF extractor script: {SCRIPT_PDF.name}")
                        return 2
                    run_script(SCRIPT_PDF)
                elif method == "txt":
                    popup_info("Action required", """Place a .txt domain list into input and re-run the orchestrator.""")
                    return 0
                else:
                    # manual
                    d = popup_ask_domain()
                    nd = normalize_domain(d or "")
                    if not nd:
                        popup_info("Invalid domain", "The provided domain is invalid. Aborting.")
                        return 2
                    out_txt = INPUT_DIR / f"manual_domains_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                    write_domains_txt([nd], out_txt)
                    print(f"[INFO] Wrote manual domain list to: {out_txt.relative_to(BASE_DIR)}")
            else:
                out_txt = INPUT_DIR / f"extracted_domains_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                write_domains_txt(domains, out_txt)
                popup_info(
                    "Domains extracted",
                    f"Extracted {len(domains)} domain(s) from {input_file.name} and wrote:\n{out_txt}"
                )
                print(f"[INFO] Using extracted TXT: {out_txt.relative_to(BASE_DIR)}")
    else:
        # manual input required
        d = popup_ask_domain()
        nd = normalize_domain(d or "")
        if not nd:
            popup_info("Invalid domain", "The provided domain is invalid. Aborting.")
            return 2
        out_txt = INPUT_DIR / f"manual_domains_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        write_domains_txt([nd], out_txt)
        print(f"[INFO] Wrote manual domain list to: {out_txt.relative_to(BASE_DIR)}")
    input("\nInput method determined. Press ENTER to continue or Ctrl+C to abort...")

    # Run 1a + 1b
    if not SCRIPT_1A.exists():
        popup_info("Error", f"Missing script: {SCRIPT_1A.name}")
        return 2
    if not SCRIPT_1B.exists():
        popup_info("Error", f"Missing script: {SCRIPT_1B.name}")
        return 2

    run_script(SCRIPT_1A)
    run_script(SCRIPT_1B)

    # Summary
    c1a = len(list(STAGING_1A.glob("*.json"))) if STAGING_1A.exists() else 0
    c1b = len(list(STAGING_1B.glob("*.json"))) if STAGING_1B.exists() else 0
    summary = (
        "Step summary:\n"
        f"- 1a Modat host outputs     : {c1a} JSON file(s) in {STAGING_1A}\n"
        f"- 1b NetworksDB outputs     : {c1b} JSON file(s) in {STAGING_1B}\n"
    )
    print("\n" + summary)
    popup_info("Step 1 complete", summary)

    # Ask to continue with service scan
    cont = popup_yesno(
        "Continue?",
        """1a and 1b finished.\n\nContinue with 2_modat_service_api.py.py (service scan)?"""
    )
    if not cont:
        print("[INFO] Flow stopped by user before Step 2.")
        return 0

    # Run 2_modat_service_api
    step2 = SCRIPT_2 if SCRIPT_2.exists() else SCRIPT_2_ALT
    if not step2.exists():
        popup_info(
            "Error",
            "Step 2 script not found.\n"
            f"Tried:\n- {SCRIPT_2.name}\n- {SCRIPT_2_ALT.name}"
        )
        return 2

    run_script(step2)

    popup_info("Done", "Step 2 finished. (More steps can be added later.)")
    print("[INFO] Flow complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
