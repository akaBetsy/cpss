#!/usr/bin/env python3
"""
Shodan JSON to Detection-Compatible CSV Converter

This converter transforms Shodan JSON exports into CSV format with column names
that match what the CPSS detection scripts expect.

Key Mappings:
- Shodan 'product' → 'service.fingerprints.service.product' (for brand detection)
- Shodan 'http.title' → 'http.html_title' (for title-based detection)
- Shodan 'http.html' → 'service.http.body' (for HTML content detection)
- Shodan 'http.server' → 'service.banner' (for server banner detection)
- Shodan 'data' → 'service.banner' (fallback banner)
- Shodan vendor fields → 'service.fingerprints.tags' (comma-separated for tag detection)
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from datetime import datetime

# ============================================================
# CONFIGURATION
# ============================================================
INPUT_DIR = Path("./staging/4_validation")
OUTPUT_DIR = INPUT_DIR

# TODO: Fill in your Shodan JSON filename
INPUT_FILE = "5_shodan_20251109.json"  # <-- Replace with your actual filename

OUTPUT_CSV = OUTPUT_DIR / "5_shodan_20251109.csv"  # Match the filename from your notebook


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


def extract_banner(shodan_record: dict) -> str:
    """
    Extract banner from Shodan record.
    Priority: http.server > data field > product
    """
    # Try HTTP server header first
    http = shodan_record.get("http", {})
    if isinstance(http, dict):
        server = http.get("server", "")
        if server:
            return clean_for_csv(server)
    
    # Try raw data field (contains full banner)
    data = shodan_record.get("data", "")
    if data and isinstance(data, str):
        # Truncate if too long
        if len(data) > 1000:
            return clean_for_csv(data[:1000] + "... [truncated]")
        return clean_for_csv(data)
    
    # Fallback to product
    product = shodan_record.get("product", "")
    if product:
        return clean_for_csv(product)
    
    return ""


def extract_tags(shodan_record: dict) -> str:
    """
    Extract tags from Shodan record for tag-based detection.
    
    Creates comma-separated tags from:
    - Vendor field names (hikvision, dahua, axis, etc.)
    - Product field (converted to tag)
    - HTTP components if present
    """
    tags = []
    
    # Add product as tag
    product = shodan_record.get("product", "")
    if product:
        # Convert "Hikvision IP Camera" to "hikvision,camera,ip"
        product_tags = product.lower().replace("-", " ").replace("/", " ").split()
        tags.extend(product_tags)
    
    # Add vendor-specific field names as tags
    vendor_fields = ["hikvision", "dahua", "axis", "cisco", "apache", "nginx", 
                     "mobotix", "bosch", "honeywell", "genetec", "paxton"]
    for vendor in vendor_fields:
        if vendor in shodan_record:
            tags.append(vendor)
    
    # Add protocol/transport info
    transport = shodan_record.get("transport", "")
    if transport:
        tags.append(transport)
    
    # Add HTTP if present
    if "http" in shodan_record:
        tags.append("http")
    
    # Remove duplicates and join
    tags = list(dict.fromkeys(tags))  # Preserve order, remove duplicates
    return ",".join(tags)


def extract_http_path(shodan_record: dict) -> str:
    """Extract HTTP path from Shodan record"""
    http = shodan_record.get("http", {})
    if isinstance(http, dict):
        location = http.get("location", "")
        if location:
            return clean_for_csv(location)
    return "/"


def extract_http_headers(shodan_record: dict) -> str:
    """
    Extract HTTP headers as string.
    Shodan doesn't store headers as separate field, so extract from 'data' field.
    """
    data = shodan_record.get("data", "")
    if not data or not isinstance(data, str):
        return ""
    
    # HTTP response starts with "HTTP/1.x" and headers end at first blank line
    if data.startswith("HTTP/"):
        header_end = data.find("\n\n")
        if header_end > 0:
            headers = data[:header_end]
            return clean_for_csv(headers)
    
    return ""


# ============================================================
# MAIN CONVERSION FUNCTION
# ============================================================

def convert_shodan_to_detection_format(shodan_record: dict) -> dict[str, str]:
    """
    Convert Shodan record to detection script format.
    
    Maps Shodan fields to the EXACT column names the detection scripts expect.
    """
    row = {}
    
    # ========================================
    # CORE IDENTIFICATION FIELDS
    # ========================================
    
    # IP address
    row["ip"] = clean_for_csv(shodan_record.get("ip_str", ""))
    
    # Port and transport
    row["service.port"] = clean_for_csv(shodan_record.get("port", ""))
    row["service.transport"] = clean_for_csv(shodan_record.get("transport", ""))
    
    # ========================================
    # CRITICAL FIELDS FOR DETECTION
    # ========================================
    
    # 1. Product field (PRIMARY for brand detection)
    # Shodan's 'product' → 'service.fingerprints.service.product'
    product = shodan_record.get("product", "")
    row["service.fingerprints.service.product"] = clean_for_csv(product)
    
    # Also store in OS product for maximum compatibility
    row["service.fingerprints.os.product"] = clean_for_csv(product)
    
    # 2. Tags (CRITICAL for tag-based detection)
    # Create comma-separated tags from vendor fields and product
    row["service.fingerprints.tags"] = extract_tags(shodan_record)
    
    # 3. Banner (for banner-based detection)
    # Priority: http.server > data > product
    row["service.banner"] = extract_banner(shodan_record)
    
    # ========================================
    # HTTP FIELDS
    # ========================================
    
    http = shodan_record.get("http", {})
    if isinstance(http, dict):
        # HTTP title - CRITICAL for title-based detection
        row["http.html_title"] = clean_for_csv(http.get("title", ""))
        
        # HTTP body (HTML content) - for content-based detection
        html = http.get("html", "")
        if html:
            # Truncate if too long
            if len(html) > 2000:
                row["service.http.body"] = clean_for_csv(html[:2000] + "... [truncated]")
            else:
                row["service.http.body"] = clean_for_csv(html)
        else:
            row["service.http.body"] = ""
        
        # HTTP path
        row["http.path"] = extract_http_path(shodan_record)
        
        # HTTP headers (extracted from data field)
        row["http.headers"] = extract_http_headers(shodan_record)
        
        # Server header (alternative banner)
        server = http.get("server", "")
        if server and not row["service.banner"]:
            row["service.banner"] = clean_for_csv(server)
    
    else:
        # No HTTP data
        row["http.html_title"] = ""
        row["service.http.body"] = ""
        row["http.path"] = ""
        row["http.headers"] = ""
    
    # ========================================
    # VENDOR-SPECIFIC FIELDS (preserve for analysis)
    # ========================================
    
    vendor_fields = ["hikvision", "dahua", "axis", "cisco", "apache", "nginx",
                     "mobotix", "bosch", "honeywell", "genetec", "paxton", "nedap"]
    
    for vendor in vendor_fields:
        if vendor in shodan_record:
            vendor_data = shodan_record[vendor]
            if isinstance(vendor_data, dict):
                for key, value in vendor_data.items():
                    if isinstance(value, (dict, list)):
                        row[f"vendor.{vendor}.{key}"] = clean_for_csv(json.dumps(value))
                    else:
                        row[f"vendor.{vendor}.{key}"] = clean_for_csv(value)
    
    # ========================================
    # CVEs (for KEV calculation)
    # ========================================
    
    vulns = shodan_record.get("vulns", {})
    if isinstance(vulns, dict) and vulns:
        cves = list(vulns.keys())
        row["service.cves"] = ";".join(cves)
        row["service.cves_count"] = str(len(cves))
    else:
        row["service.cves"] = ""
        row["service.cves_count"] = "0"
    
    # ========================================
    # METADATA (for tracking and analysis)
    # ========================================
    
    # Geolocation
    location = shodan_record.get("location", {})
    if isinstance(location, dict):
        row["geo.city_name"] = clean_for_csv(location.get("city", ""))
        row["geo.country_name"] = clean_for_csv(location.get("country_name", ""))
        row["geo.country_iso_code"] = clean_for_csv(location.get("country_code", ""))
    
    # ASN
    asn_str = shodan_record.get("asn", "")
    if asn_str:
        row["asn.number"] = asn_str.replace("AS", "").replace("as", "")
    else:
        row["asn.number"] = ""
    
    row["asn.org"] = clean_for_csv(shodan_record.get("org", "") or shodan_record.get("isp", ""))
    
    # FQDNs
    hostnames = shodan_record.get("hostnames", [])
    if isinstance(hostnames, list) and hostnames:
        row["fqdns"] = ";".join([str(h) for h in hostnames if h])
    else:
        row["fqdns"] = ""
    
    # Timestamp
    row["service.timestamp"] = clean_for_csv(shodan_record.get("timestamp", ""))
    
    return row


# ============================================================
# PROCESSING
# ============================================================

def process_shodan_json(json_file: Path, output_csv: Path) -> bool:
    """Process Shodan JSON file and convert to detection-compatible CSV"""
    
    if not json_file.exists():
        print(f"[ERROR] File not found: {json_file}")
        return False
    
    print(f"[INFO] Reading: {json_file.name}")
    
    # Try to detect format: standard JSON or JSONL
    try:
        content = json_file.read_text(encoding="utf-8")
        data = json.loads(content)
        
        if isinstance(data, dict) and "matches" in data:
            matches = data.get("matches", [])
            print(f"[INFO] Format: Standard Shodan JSON")
        elif isinstance(data, list):
            matches = data
            print(f"[INFO] Format: JSON array")
        else:
            print(f"[ERROR] Unexpected JSON structure")
            return False
    
    except json.JSONDecodeError:
        # Try JSONL format
        print(f"[INFO] Trying JSONL format...")
        matches = []
        with open(json_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    matches.append(record)
                except json.JSONDecodeError as err:
                    print(f"[WARNING] Skipped invalid JSON at line {line_num}")
                    continue
        
        print(f"[INFO] Format: JSONL")
    
    if not matches:
        print(f"[ERROR] No records found")
        return False
    
    print(f"[INFO] Found {len(matches)} records")
    print(f"[INFO] Converting to detection format...")
    
    all_rows = []
    all_headers = set()
    
    for idx, match in enumerate(matches, start=1):
        if not isinstance(match, dict):
            continue
        
        row = convert_shodan_to_detection_format(match)
        
        # Add metadata
        row["source_file"] = json_file.name
        row["record_index"] = str(idx)
        
        all_rows.append(row)
        all_headers.update(row.keys())
        
        if idx % 100 == 0:
            print(f"[STATUS] Processed {idx}/{len(matches)}...", end='\r')
    
    print()
    
    if not all_rows:
        print("[ERROR] No rows collected")
        return False
    
    # Sort headers
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
    print("SHODAN TO DETECTION FORMAT CONVERTER")
    print("=" * 70)
    print()
    print("This converter creates CSV with columns that match detection scripts:")
    print("  ✓ service.fingerprints.service.product (from Shodan 'product')")
    print("  ✓ service.fingerprints.tags (from vendor fields)")
    print("  ✓ http.html_title (from Shodan 'http.title')")
    print("  ✓ service.http.body (from Shodan 'http.html')")
    print("  ✓ service.banner (from Shodan 'http.server' or 'data')")
    print("  ✓ service.cves (from Shodan 'vulns')")
    print()
    print(f"Input:  {INPUT_FILE}")
    print(f"Output: {OUTPUT_CSV}")
    print("=" * 70)
    print()
    
    # Validate input file is specified
    if INPUT_FILE == "shodan_json_file.json":
        print("[ERROR] Please edit the script and fill in INPUT_FILE")
        print()
        print("Example:")
        print('  INPUT_FILE = "shodan_netherlands_20251109.json"')
        return 1
    
    # Check input directory exists
    if not INPUT_DIR.exists():
        print(f"[ERROR] Input directory not found: {INPUT_DIR}")
        return 1
    
    input_path = INPUT_DIR / INPUT_FILE
    
    # Process
    success = process_shodan_json(input_path, OUTPUT_CSV)
    
    if success:
        print()
        print("=" * 70)
        print("SUCCESS")
        print("=" * 70)
        print()
        print("Next steps:")
        print("  1. Run the detection notebook: 8_cpss_identification_validation_shodan_FIXED.ipynb")
        print("  2. The notebook will now find CPSS devices correctly")
        print()
        print("Key columns created:")
        print("  • service.fingerprints.service.product - Brand detection")
        print("  • service.fingerprints.tags - Tag-based detection")
        print("  • http.html_title - Title matching")
        print("  • service.http.body - HTML content analysis")
        print("  • service.banner - Banner detection")
        return 0
    else:
        print()
        print("=" * 70)
        print("FAILED")
        print("=" * 70)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
