#!/usr/bin/env python3

from __future__ import annotations

import csv
import json
from pathlib import Path

# ============================================================
# CONFIGURATION - FILL IN YOUR FILENAMES HERE
# ============================================================
INPUT_DIR = Path("./staging/4_validation")
OUTPUT_DIR = INPUT_DIR

# TODO: Fill in your JSON filenames
INPUT_FILES = [
    "6_modat_data_validation_cctv.json",  # <-- Replace with your first JSON filename
    "6_modat_data_validation_ihas_eacs.json",  # <-- Replace with your second JSON filename
]

OUTPUT_CSV = OUTPUT_DIR / "combined_output.csv"


# ============================================================
# UTILITIES
# ============================================================

def clean_for_csv(value) -> str:
    """Clean value for CSV output"""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)

    text = str(value)
    # Normalize whitespace
    text = text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ").replace("\t", " ")
    text = text.strip().strip('"').strip("'")
    return text


def dict_to_clean_string(obj) -> str:
    """Convert dict/list to JSON string for CSV"""
    try:
        return clean_for_csv(json.dumps(obj, ensure_ascii=False, sort_keys=True))
    except Exception:
        return clean_for_csv(str(obj))


def flatten(obj, parent_key: str = "", sep: str = ".") -> dict[str, str]:
    """Flatten nested JSON structure with dot notation"""
    items: dict[str, str] = {}

    if isinstance(obj, dict):
        for k, v in obj.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else str(k)

            # Skip additionalProp fields (API schema artifacts)
            if k.startswith("additionalProp"):
                continue

            # Skip raw certificate data (too large)
            if "raw" in new_key.lower() and "cert" in new_key.lower():
                continue

            items.update(flatten(v, new_key, sep=sep))
        return items

    if isinstance(obj, list):
        # Add count for lists
        if parent_key:
            items[parent_key + "_count"] = str(len(obj))

        # Empty list
        if not obj:
            items[parent_key] = ""
            items[parent_key + "_count"] = "0"
            return items

        # List of primitives: join with semicolon
        if all(not isinstance(x, (dict, list)) for x in obj):
            vals = [str(x) for x in obj if x is not None]
            items[parent_key] = clean_for_csv(";".join(vals))
            items[parent_key + "_count"] = str(len(vals))
            return items

        # List with complex objects: stringify as JSON
        items[parent_key] = dict_to_clean_string(obj)
        return items

    items[parent_key] = clean_for_csv(obj)
    return items


# ============================================================
# MODAT FORMAT SPECIFIC PROCESSING
# ============================================================

def extract_modat_record(item: dict) -> dict[str, str]:
    """
    Extract and flatten a single record from Modat format.

    Two possible structures:

    1. API format:
    {
      "ip": "x.x.x.x",
      "geo": {...},
      "asn": {...},
      "fqdns": [...],
      "tags": [...],
      "cves": [...],
      "services": [...]
    }

    2. Export format:
    {
      "ip": "x.x.x.x",
      "service": {...},  # Single service object
      "fqdns": [...],
      "asn": {...},
      "geo": {...},
      "is_anycast": false
    }
    """
    row = {}

    # IP (top level)
    row["ip"] = clean_for_csv(item.get("ip", ""))

    # Geo information
    geo = item.get("geo", {})
    if isinstance(geo, dict):
        row["geo.city_name"] = clean_for_csv(geo.get("city_name", ""))
        row["geo.country_name"] = clean_for_csv(geo.get("country_name", ""))
        row["geo.country_iso_code"] = clean_for_csv(geo.get("country_iso_code", ""))
        # Flatten any other geo fields
        for k, v in geo.items():
            if not k.startswith("additionalProp") and k not in ["city_name", "country_name", "country_iso_code"]:
                if isinstance(v, (dict, list)):
                    row[f"geo.{k}"] = dict_to_clean_string(v)
                else:
                    row[f"geo.{k}"] = clean_for_csv(v)

    # ASN information
    asn = item.get("asn", {})
    if isinstance(asn, dict):
        row["asn.number"] = clean_for_csv(asn.get("number", ""))
        row["asn.org"] = clean_for_csv(asn.get("org", ""))
        # Flatten any other asn fields
        for k, v in asn.items():
            if not k.startswith("additionalProp") and k not in ["number", "org"]:
                if isinstance(v, (dict, list)):
                    row[f"asn.{k}"] = dict_to_clean_string(v)
                else:
                    row[f"asn.{k}"] = clean_for_csv(v)

    # FQDNs (list)
    fqdns = item.get("fqdns", [])
    if isinstance(fqdns, list):
        row["fqdns"] = ";".join([str(f) for f in fqdns if f]) if fqdns else ""
        row["fqdns_count"] = str(len(fqdns))
    else:
        row["fqdns"] = clean_for_csv(fqdns)
        row["fqdns_count"] = "0"

    # Boolean fields
    row["is_anycast"] = "true" if item.get("is_anycast") else "false"

    # Tags (list) - may not be present in export format
    tags = item.get("tags", [])
    if isinstance(tags, list):
        row["tags"] = ";".join([str(t) for t in tags if t]) if tags else ""
        row["tags_count"] = str(len(tags))
    else:
        row["tags"] = clean_for_csv(tags) if tags else ""
        row["tags_count"] = "0"

    # CVEs (list) - may not be present in export format
    cves = item.get("cves", [])
    if isinstance(cves, list):
        row["cves"] = ";".join([str(c) for c in cves if c]) if cves else ""
        row["cves_count"] = str(len(cves))
    else:
        row["cves"] = clean_for_csv(cves) if cves else ""
        row["cves_count"] = "0"

    # Services handling - supports both 'service' (single) and 'services' (array)
    service_single = item.get("service")
    services_array = item.get("services")

    if service_single:
        # Export format: single 'service' object
        if isinstance(service_single, dict):
            # Flatten the service object with 'service.' prefix
            service_flat = flatten(service_single, "service")
            row.update(service_flat)

            # Extract key service fields for easy filtering
            row["service.port"] = clean_for_csv(service_single.get("port", ""))
            row["service.protocol"] = clean_for_csv(service_single.get("protocol", ""))
            row["service.transport"] = clean_for_csv(service_single.get("transport", ""))

    elif services_array:
        # API format: 'services' array
        if isinstance(services_array, list):
            row["services"] = dict_to_clean_string(services_array) if services_array else ""
            row["services_count"] = str(len(services_array))

            # Extract some key service info for easier analysis
            if services_array:
                all_ports = set()
                all_protocols = set()
                all_transports = set()

                for svc in services_array:
                    if isinstance(svc, dict):
                        if "ports" in svc and isinstance(svc["ports"], list):
                            all_ports.update([str(p) for p in svc["ports"]])
                        if "protocol" in svc:
                            all_protocols.add(str(svc["protocol"]))
                        if "transport" in svc:
                            all_transports.add(str(svc["transport"]))

                row["services.ports"] = ";".join(sorted(all_ports, key=lambda x: int(x) if x.isdigit() else 999999))
                row["services.protocols"] = ";".join(sorted(all_protocols))
                row["services.transports"] = ";".join(sorted(all_transports))

    # Flatten any other top-level fields not already handled
    handled_keys = {"ip", "geo", "asn", "fqdns", "is_anycast", "tags", "cves", "service", "services"}
    for key, value in item.items():
        if key not in handled_keys and not key.startswith("additionalProp"):
            if isinstance(value, (dict, list)):
                flattened = flatten(value, key)
                row.update(flattened)
            else:
                row[key] = clean_for_csv(value)

    return row


# ============================================================
# CORE PROCESSING
# ============================================================

def process_json_file(json_file: Path) -> list[dict[str, str]]:
    """
    Process single Modat JSON file and return list of flattened rows.

    Supports two formats:
    1. API format: {"page": [...], "page_nr": N, "total_records": N}
    2. Export format: {"results": [...], "results_count": N, "total_pages": N}
    """

    if not json_file.exists():
        print(f"[WARNING] File not found: {json_file}")
        return []

    print(f"[INFO] Processing: {json_file.name}")

    try:
        data = json.loads(json_file.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[ERROR] Failed to read {json_file.name}: {e}")
        return []

    # Detect format and get records
    records = None
    metadata = {}

    # Format 1: Export format with 'results'
    if "results" in data:
        records = data.get("results", [])
        metadata = {
            "total_pages": data.get("total_pages", "?"),
            "pages_done": len(data.get("pages_done", [])),
            "results_count": data.get("results_count", "?"),
            "exported_at": data.get("exported_at", "?")
        }
        print(f"[INFO] Format: Modat Export (results)")
        print(f"[INFO] Total pages: {metadata['total_pages']}, Pages done: {metadata['pages_done']}")
        print(f"[INFO] Results count: {metadata['results_count']}")
        print(f"[INFO] Exported at: {metadata['exported_at']}")

    # Format 2: Export format with 'results_by_page' (nested structure)
    elif "results_by_page" in data:
        results_by_page = data.get("results_by_page", {})
        if isinstance(results_by_page, dict):
            # Flatten all pages into single list
            records = []
            for page_key, page_records in results_by_page.items():
                if isinstance(page_records, list):
                    records.extend(page_records)

            metadata = {
                "total_pages": data.get("total_pages", "?"),
                "pages_done": len(data.get("pages_done", [])),
                "results_count": len(records),
            }
            print(f"[INFO] Format: Modat Export (results_by_page)")
            print(f"[INFO] Total pages: {metadata['total_pages']}, Pages done: {metadata['pages_done']}")
            print(f"[INFO] Results count: {metadata['results_count']} (flattened from {len(results_by_page)} pages)")
        else:
            print(f"[ERROR] 'results_by_page' is not a dict in {json_file.name}")
            return []

    # Format 3: API format with 'page'
    elif "page" in data:
        records = data.get("page", [])
        metadata = {
            "page_nr": data.get("page_nr", "?"),
            "total_pages": data.get("total_pages", "?"),
            "total_records": data.get("total_records", "?")
        }
        print(f"[INFO] Format: Modat API")
        print(
            f"[INFO] Page {metadata['page_nr']}/{metadata['total_pages']}, Total records: {metadata['total_records']}")

    else:
        print(f"[ERROR] Unknown format in {json_file.name}")
        print(f"[INFO] Expected 'results', 'results_by_page', or 'page' field")
        print(f"[INFO] Found keys: {list(data.keys())}")
        return []

    if not isinstance(records, list):
        print(f"[ERROR] Records field is not a list in {json_file.name}")
        return []

    print(f"[INFO] Processing {len(records)} records")

    rows = []
    source_file = json_file.name

    for idx, item in enumerate(records, start=1):
        if not isinstance(item, dict):
            continue

        # Extract and flatten the record
        row = extract_modat_record(item)

        # Add source metadata
        row["source_file"] = source_file
        row["source_format"] = "export" if "results" in data else "api"
        row["record_index"] = str(idx)

        # Add format-specific metadata
        if "results" in data:
            row["export.total_pages"] = str(metadata.get("total_pages", ""))
            row["export.results_count"] = str(metadata.get("results_count", ""))
        elif "results_by_page" in data:
            row["export.total_pages"] = str(metadata.get("total_pages", ""))
            row["export.results_count"] = str(metadata.get("results_count", ""))
        else:
            row["api.page_nr"] = str(metadata.get("page_nr", ""))

        rows.append(row)

    return rows


def process_multiple_files_to_csv(input_files: list[str], output_csv: Path) -> bool:
    """Process multiple JSON files and combine into single CSV"""

    print("=" * 70)
    print("MODAT JSON TO CSV CONVERTER")
    print("=" * 70)
    print(f"Input files: {len(input_files)}")
    for f in input_files:
        print(f"  - {f}")
    print(f"Output: {output_csv}")
    print("=" * 70)
    print()

    all_rows: list[dict[str, str]] = []
    all_headers: set[str] = set()

    # Process each file
    for filename in input_files:
        json_path = INPUT_DIR / filename
        rows = process_json_file(json_path)

        if rows:
            all_rows.extend(rows)
            # Collect all unique headers
            for row in rows:
                all_headers.update(row.keys())

        print()

    if not all_rows:
        print("[ERROR] No data collected from any file")
        return False

    # Sort headers alphabetically
    headers = sorted(all_headers)

    print(f"[INFO] Total rows collected: {len(all_rows)}")
    print(f"[INFO] Total columns: {len(headers)}")
    print(f"[INFO] Writing CSV: {output_csv}")

    # Write CSV
    try:
        with output_csv.open("w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=headers,
                quoting=csv.QUOTE_ALL,
                lineterminator="\n"
            )
            writer.writeheader()

            for row in all_rows:
                writer.writerow({h: row.get(h, "") for h in headers})

        print(f"[SUCCESS] Wrote {len(all_rows)} rows to {output_csv}")
        return True

    except Exception as e:
        print(f"[ERROR] Failed to write CSV: {e}")
        return False


# ============================================================
# MAIN
# ============================================================

def main() -> int:
    # Validate input files are specified
    if any(f in ["file1.json", "file2.json"] for f in INPUT_FILES):
        print("[ERROR] Please edit the script and fill in INPUT_FILES with your JSON filenames")
        print()
        print("Example:")
        print('  INPUT_FILES = [')
        print('      "modat_validation_20251109.json",')
        print('      "modat_validation_20251110.json",')
        print('  ]')
        return 1

    # Check input directory exists
    if not INPUT_DIR.exists():
        print(f"[ERROR] Input directory not found: {INPUT_DIR}")
        return 1

    # Process files
    success = process_multiple_files_to_csv(INPUT_FILES, OUTPUT_CSV)

    if success:
        print()
        print("=" * 70)
        print("COMPLETE")
        print("=" * 70)
        return 0
    else:
        print()
        print("=" * 70)
        print("FAILED")
        print("=" * 70)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())