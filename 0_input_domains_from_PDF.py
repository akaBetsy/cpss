import re
import fitz  # PyMuPDF
import requests
from pathlib import Path
from typing import List, Tuple
from datetime import date

# === Load IANA TLDs ===
tld_url = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
tld_response = requests.get(tld_url, timeout=30)
tld_response.raise_for_status()
tlds = {
    line.strip().lower()
    for line in tld_response.text.splitlines()
    if line and not line.startswith("#")
}

# === Regex Patterns ===
email_pattern = re.compile(r"\b[\w.-]+@[\w.-]+\.[a-z]{2,}\b", re.IGNORECASE)
domain_candidate_pattern = re.compile(r"\b((?:[\w-]+\.)+([a-z]{2,}))\b", re.IGNORECASE)

def clean_domain(domain_str: str) -> str:
    """Normalize a domain string (lowercase, trim punctuation, strip leading www.)."""
    cleaned = domain_str.lower().strip(".,;:")
    if cleaned.startswith("www."):
        cleaned = cleaned[4:]
    return cleaned

def verify_context(words: List[str], index: int, keyword: str, max_words: int = 10) -> bool:
    context = " ".join(words[max(0, index - max_words):index]).lower()
    return keyword.lower() in context

def page_text(page) -> str:
    """PyMuPDF page text with compatibility for different method names."""
    if hasattr(page, "get_text"):
        return page.get_text("text")
    if hasattr(page, "getText"):  # older PyMuPDF
        return page.getText("text")  # type: ignore[attr-defined]
    raise AttributeError("PyMuPDF Page has no get_text/getText method")

def extract_domains(pdf_path: str | Path) -> Tuple[List[str], List[str], List[str]]:
    found_all: List[str] = []
    found_email_verified: List[str] = []
    found_web_verified: List[str] = []

    doc = fitz.open(str(pdf_path))
    for page in doc:
        text = page_text(page).replace("-\n", "").replace("\n", " ").strip(" \t\r\n.,;:")
        words = text.split()

        for i, token in enumerate(words):
            # Email check
            if email_pattern.match(token):
                dom_part = token.split("@", 1)[1]
                dom_clean = clean_domain(dom_part)
                found_all.append(dom_clean)
                if verify_context(words, i, "e-mail"):
                    found_email_verified.append(dom_clean)

            # Domain check
            match = domain_candidate_pattern.match(token)
            if match:
                full_dom, tld = match.groups()
                if tld.lower() in tlds:
                    dom_clean = clean_domain(full_dom)
                    found_all.append(dom_clean)
                    if verify_context(words, i, "website"):
                        found_web_verified.append(dom_clean)

    return found_all, found_email_verified, found_web_verified


def main() -> None:
    # === Run: pick most recent PDF in .\input ===
    input_dir = Path("./input")
    pdf_files = list(input_dir.glob("*.pdf"))
    if not pdf_files:
        raise FileNotFoundError(f"No PDF files found in: {input_dir.resolve()}")

    pdf_file = max(pdf_files, key=lambda p: p.stat().st_mtime)
    all_found, email_verified, web_verified = extract_domains(pdf_file)

    # Combine verified lists and deduplicate
    combined_verified = sorted(set(email_verified + web_verified))

    # === Output ===
    staging_dir = Path("./input")
    staging_dir.mkdir(parents=True, exist_ok=True)

    today_str = date.today().strftime("%Y%m%d")
    out_domains_path = staging_dir / f"cpss_scan_domains_{today_str}.txt"

    with out_domains_path.open("w", encoding="utf-8") as f:
        for d in combined_verified:
            f.write(d + "\n")

    # === Print stats ===
    print(f"Verified email domains: {len(set(email_verified))}")
    print(f"Verified website domains: {len(set(web_verified))}")
    print(f"Combined unique verified domains: {len(combined_verified)}")
    print(f"Domains output written to: {out_domains_path}")


if __name__ == "__main__":
    main()
