#!/usr/bin/env python3

from __future__ import annotations

import csv
import json
from pathlib import Path
from datetime import datetime

# ============================================================
# CONFIGURATION - FILL IN YOUR FILENAME HERE
# ============================================================
INPUT_DIR = Path("./staging/4_validation")
OUTPUT_DIR = INPUT_DIR

# TODO: Fill in your Shodan JSON filename
INPUT_FILE = "shodan_json_file.json"  # <-- Replace with your Shodan JSON filename

OUTPUT_CSV = OUTPUT_DIR / "shodan_modat_format.csv"


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

            # Skip overly large fields
            if "html" in new_key.lower() or "data" in new_key.lower():
                if isinstance(v, str) and len(v) > 1000:
                    items[new_key] = clean_for_csv(v[:200] + "... [truncated]")
                    continue

            # Skip favicon data (too large)
            if "favicon.data" in new_key:
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
# SHODAN TO MODAT FORMAT CONVERSION
# ============================================================

def convert_shodan_to_modat_format(shodan_record: dict) -> dict[str, str]:
    """
    Convert a Shodan record to Modat-compatible format.

    Shodan structure:
    {
      "ip_str": "x.x.x.x",
      "port": 80,
      "transport": "tcp",
      "product": "...",
      "location": {...},
      "asn": "AS1234",
      "isp": "...",
      "org": "...",
      "hostnames": [...],
      "domains": [...],
      "http": {...},
      ...
    }

    Modat structure (target):
    {
      "ip": "x.x.x.x",
      "geo.city_name": "...",
      "geo.country_name": "...",
      "geo.country_iso_code": "...",
      "asn.number": 1234,
      "asn.org": "...",
      "fqdns": "...",
      "service.port": 80,
      "service.protocol": "...",
      "service.transport": "...",
      ...
    }
    """
    row = {}

    # === IP ===
    # Shodan uses 'ip_str', Modat uses 'ip'
    row["ip"] = clean_for_csv(shodan_record.get("ip_str", ""))

    # === GEO ===
    # Shodan has 'location' dict, Modat has 'geo' dict
    location = shodan_record.get("location", {})
    if isinstance(location, dict):
        row["geo.city_name"] = clean_for_csv(location.get("city", ""))
        row["geo.country_name"] = clean_for_csv(location.get("country_name", ""))
        row["geo.country_iso_code"] = clean_for_csv(location.get("country_code", ""))
        row["geo.region_code"] = clean_for_csv(location.get("region_code", ""))
        row["geo.latitude"] = clean_for_csv(location.get("latitude", ""))
        row["geo.longitude"] = clean_for_csv(location.get("longitude", ""))

    # === ASN ===
    # Shodan has 'asn' as string "AS1234", Modat has 'asn.number' as int
    asn_str = shodan_record.get("asn", "")
    if asn_str:
        # Extract number from "AS1234" format
        asn_num = asn_str.replace("AS", "").replace("as", "")
        row["asn.number"] = asn_num
    else:
        row["asn.number"] = ""

    # Shodan has separate 'org' and 'isp' fields
    row["asn.org"] = clean_for_csv(shodan_record.get("org", "") or shodan_record.get("isp", ""))
    row["asn.isp"] = clean_for_csv(shodan_record.get("isp", ""))

    # === FQDNs ===
    # Combine hostnames and domains into Modat 'fqdns' format
    hostnames = shodan_record.get("hostnames", [])
    domains = shodan_record.get("domains", [])

    all_fqdns = []
    if isinstance(hostnames, list):
        all_fqdns.extend([str(h) for h in hostnames if h])
    if isinstance(domains, list):
        all_fqdns.extend([str(d) for d in domains if d])

    # Deduplicate
    all_fqdns = list(dict.fromkeys(all_fqdns))

    row["fqdns"] = ";".join(all_fqdns)
    row["fqdns_count"] = str(len(all_fqdns))

    # Store originals too for reference
    if hostnames:
        row["shodan.hostnames"] = ";".join([str(h) for h in hostnames])
    if domains:
        row["shodan.domains"] = ";".join([str(d) for d in domains])

    # === is_anycast ===
    # Not in Shodan, default to false
    row["is_anycast"] = "false"

    # === SERVICE (single service format like Modat export) ===
    # Shodan has service info at root level
    row["service.port"] = clean_for_csv(shodan_record.get("port", ""))
    row["service.transport"] = clean_for_csv(shodan_record.get("transport", ""))
    row["service.protocol"] = clean_for_csv(shodan_record.get("product", ""))  # Shodan's 'product' ~ protocol
    row["service.product"] = clean_for_csv(shodan_record.get("product", ""))
    row["service.version"] = clean_for_csv(shodan_record.get("version", ""))
    row["service.timestamp"] = clean_for_csv(shodan_record.get("timestamp", ""))

    # === HTTP Details ===
    # Flatten HTTP object with 'service.http.' prefix (like Modat does)
    http = shodan_record.get("http", {})
    if isinstance(http, dict):
        for key, value in http.items():
            if key == "html" and isinstance(value, str) and len(value) > 500:
                # Truncate long HTML
                row[f"service.http.{key}"] = clean_for_csv(value[:200] + "... [truncated]")
            elif key == "favicon" and isinstance(value, dict):
                # Only keep favicon hash and location
                row["service.http.favicon.hash"] = clean_for_csv(value.get("hash", ""))
                row["service.http.favicon.location"] = clean_for_csv(value.get("location", ""))
            else:
                if isinstance(value, (dict, list)):
                    row[f"service.http.{key}"] = dict_to_clean_string(value)
                else:
                    row[f"service.http.{key}"] = clean_for_csv(value)

    # === Vendor-Specific Fields ===
    # Shodan often has vendor-specific fields (hikvision, etc.)
    vendor_fields = ["hikvision", "dahua", "axis", "cisco", "apache", "nginx"]
    for vendor in vendor_fields:
        if vendor in shodan_record:
            vendor_data = shodan_record[vendor]
            if isinstance(vendor_data, dict):
                for key, value in vendor_data.items():
                    if isinstance(value, (dict, list)):
                        row[f"service.{vendor}.{key}"] = dict_to_clean_string(value)
                    else:
                        row[f"service.{vendor}.{key}"] = clean_for_csv(value)

    # === Tags ===
    # Not typically in Shodan, but add empty for compatibility
    row["tags"] = ""
    row["tags_count"] = "0"

    # === CVEs ===
    # Shodan may have vulns field
    cves = []
    vulns = shodan_record.get("vulns", {})
    if isinstance(vulns, dict):
        cves = list(vulns.keys())

    row["cves"] = ";".join(cves) if cves else ""
    row["cves_count"] = str(len(cves))

    # === Additional Shodan Fields ===
    # Flatten any remaining fields with 'shodan.' prefix
    handled_keys = {
        "ip_str", "port", "transport", "product", "version", "timestamp",
        "location", "asn", "org", "isp", "hostnames", "domains", "http",
        "vulns", "ip", "data", "opts", "hash", "_shodan"
    }
    handled_keys.update(vendor_fields)

    for key, value in shodan_record.items():
        if key not in handled_keys:
            if isinstance(value, (dict, list)):
                flattened = flatten(value, f"shodan.{key}")
                row.update(flattened)
            else:
                row[f"shodan.{key}"] = clean_for_csv(value)

    return row


# ============================================================
# CORE PROCESSING
# ============================================================

def process_shodan_json_to_modat_csv(json_file: Path, output_csv: Path) -> bool:
    """Process Shodan JSON/JSONL file and output in Modat CSV format"""

    if not json_file.exists():
        print(f"[ERROR] File not found: {json_file}")
        return False

    print(f"[INFO] Reading: {json_file.name}")

    # Try to detect format: JSON or JSONL
    try:
        # First, try reading as standard JSON
        content = json_file.read_text(encoding="utf-8")
        data = json.loads(content)

        # Check if it's a dict with 'matches' (standard Shodan export)
        if isinstance(data, dict) and "matches" in data:
            matches = data.get("matches", [])
            print(f"[INFO] Format: Standard Shodan JSON")
        else:
            print(f"[ERROR] Unexpected JSON structure")
            return False

    except json.JSONDecodeError as e:
        # If standard JSON fails, try JSONL (one JSON object per line)
        print(f"[INFO] Standard JSON failed, trying JSONL format...")

        try:
            matches = []
            with open(json_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        matches.append(record)
                    except json.JSONDecodeError as line_err:
                        print(f"[WARNING] Skipped invalid JSON at line {line_num}: {line_err}")
                        continue

            print(f"[INFO] Format: JSONL (JSON Lines)")

        except Exception as jsonl_err:
            print(f"[ERROR] Failed to read as both JSON and JSONL: {jsonl_err}")
            return False

    if not isinstance(matches, list):
        print(f"[ERROR] Could not extract records")
        return False

    if len(matches) == 0:
        print(f"[ERROR] No records found")
        return False

    print(f"[INFO] Found {len(matches)} records")
    print(f"[INFO] Converting to Modat format...")

    all_rows: list[dict[str, str]] = []
    all_headers: set[str] = set()

    source_file = json_file.name

    for idx, match in enumerate(matches, start=1):
        if not isinstance(match, dict):
            continue

        # Convert Shodan record to Modat format
        row = convert_shodan_to_modat_format(match)

        # Add metadata
        row["source_file"] = source_file
        row["source_format"] = "shodan"
        row["record_index"] = str(idx)

        all_rows.append(row)
        all_headers.update(row.keys())

        if idx % 100 == 0:
            print(f"[STATUS] Processed {idx}/{len(matches)} records...", end='\r')

    print()  # New line after progress

    if not all_rows:
        print("[ERROR] No rows collected")
        return False

    # Sort headers alphabetically
    headers = sorted(all_headers)

    print(f"[INFO] Total rows: {len(all_rows)}")
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

        print(f"[SUCCESS] Wrote {len(all_rows)} rows")
        return True

    except Exception as e:
        print(f"[ERROR] Failed to write CSV: {e}")
        return False


# ============================================================
# MAIN
# ============================================================

def main() -> int:
    print("=" * 70)
    print("SHODAN TO MODAT FORMAT CONVERTER")
    print("=" * 70)
    print(f"Input:  {INPUT_FILE}")
    print(f"Output: {OUTPUT_CSV}")
    print("=" * 70)
    print()

    # Validate input file is specified
    if INPUT_FILE == "your_shodan_file.json":
        print("[ERROR] Please edit the script and fill in INPUT_FILE")
        print()
        print("Example:")
        print('  INPUT_FILE = "shodan_netherlands_cameras.json"')
        return 1

    # Check input directory exists
    if not INPUT_DIR.exists():
        print(f"[ERROR] Input directory not found: {INPUT_DIR}")
        return 1

    input_path = INPUT_DIR / INPUT_FILE

    # Process file
    success = process_shodan_json_to_modat_csv(input_path, OUTPUT_CSV)

    if success:
        print()
        print("=" * 70)
        print("COMPLETE")
        print("=" * 70)
        print()
        print("Output columns are compatible with Modat format:")
        print("  - ip, geo.*, asn.*")
        print("  - fqdns, fqdns_count")
        print("  - service.port, service.protocol, service.transport")
        print("  - service.http.* (all HTTP fields)")
        print("  - tags, cves (empty for Shodan)")
        print("  - Plus all original Shodan fields with 'shodan.' prefix")
        return 0
    else:
        print()
        print("=" * 70)
        print("FAILED")
        print("=" * 70)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())