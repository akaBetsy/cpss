#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
STRICT I&HAS DETECTION - ZERO FALSE POSITIVES VERSION
=====================================================

CHANGES FROM PREVIOUS:
1. NO generic terms (alarm, security, sensor)
2. Require brand + specific product
3. Detailed match reporting (field, pattern, value)
4. Strong exclusions

Goal: PRECISION over RECALL
"""

import re
import pandas as pd

# ========================================
# STRICT I&HAS CONFIGURATION
# ========================================

IHAS_ENHANCED_CONFIG = {

    # HTTP paths - MUST be product-specific
    'http_paths': {
        'AJAX': [
            '/ajax-security/', '/ajax/systems',
            '/ajax-alarm', '/ajaxsystems/'
        ],
        'Vanderbilt': [
            '/spc/', '/spc-connect', '/vanderbilt/spc',
            '/sipass/'
        ],
        'Honeywell': [
            '/galaxy/', '/dimension/', '/prowatch/',
            '/honeywell-security/', '/vista-'
        ],
        'Bosch': [
            '/bpa/', '/b-series/', '/solution-',
            '/bosch-security/', '/radion/'
        ],
        'Hikvision': [
            '/ax-pro/', '/ax-hub/', '/hikvision-alarm/'
        ],
        'Texecom': [
            '/premier/', '/texecom/', '/connect-'
        ],
        'Pyronix': [
            '/enforcer/', '/pyronix/', '/homecontrol/'
        ],
        'DSC': [
            '/neo/', '/powerseries/', '/pc-link/'
        ],
    },

    # Protocols - require SPECIFIC protocol evidence
    'protocols': {
        'sia-dc09': {
            'ports': [1996],
            'banner_patterns': [
                r'sia\s+dc-09', r'sia-dc09',
                r'security\s+industry\s+association',
                r'\bsia\b.*\bprotocol\b'
            ],
            'confidence': 100,
            'require_banner': True
        },
        'contact-id': {
            'ports': [1996],
            'banner_patterns': [
                r'contact\s+id', r'contact-id',
                r'ademco\s+contact',
            ],
            'confidence': 95,
            'require_banner': True
        },
    },

    # Brands - STRICT product requirements
    'brands': {
        'AJAX': {
            'brand_patterns': [r'\bajax\s+systems\b', r'\bajax-systems\b'],
            'product_patterns': [
                r'\bhub\s+(?:2|plus|2\s+plus)\b',
                r'\bajax\s+hub\b',
                r'\bajax\s+(?:security|alarm|system)\b',
                # NOT just "ajax"!
            ],
            'model_patterns': [
                r'Hub\s+(?:2|Plus)',
                r'Ajax\s+Hub',
            ],
            'cert_patterns': [r'ajax\.systems'],
            'confidence': 100,
            'require_product': True
        },

        'Vanderbilt': {
            'brand_patterns': [r'\bvanderbilt\b'],
            'product_patterns': [
                r'\bspc\b.*\b(?:4|5|6|connect)\b',
                r'\bspc\s+(?:4|5|6)',
                r'\bsipass\b',
                r'\bvanderbilt\s+spc\b',
            ],
            'model_patterns': [
                r'SPC\s+\d+',
                r'SPC\s+(?:4|5|6)',
                r'SiPass',
            ],
            'cert_patterns': [r'vanderbilt\.com'],
            'confidence': 100,
            'require_product': True
        },

        'Honeywell Security': {
            'brand_patterns': [r'\bhoneywell\b'],
            'product_patterns': [
                r'\bgalaxy\s+(?:dimension|flex|g3)\b',
                r'\bgalaxy\b.*\balarm\b',
                r'\bvista\s+\d+',
                r'\bprowatch\b',
                # Must be security product, not building automation!
            ],
            'model_patterns': [
                r'Galaxy\s+(?:Dimension|Flex|G3)',
                r'Vista\s+\d+',
            ],
            'cert_patterns': [r'honeywellsecurity\.com'],
            'confidence': 95,
            'require_product': True
        },

        'Bosch Security': {
            'brand_patterns': [r'\bbosch\b'],
            'product_patterns': [
                r'\bsolution\s+\d+',
                r'\bb-series\b',
                r'\bradion\b.*\balarm\b',
                r'\bbosch\s+(?:security|alarm|intrusion)\b',
            ],
            'model_patterns': [
                r'Solution\s+\d+',
                r'B\s+Series',
                r'Radion',
            ],
            'cert_patterns': [r'boschsecurity\.com'],
            'confidence': 95,
            'require_product': True
        },

        'Hikvision': {
            'brand_patterns': [r'\bhikvision\b'],
            'product_patterns': [
                r'\bax\s+pro\b', r'\bax-pro\b',
                r'\bax\s+hub\b',
                r'\bhikvision\s+(?:alarm|ax)\b',
                # NOT just DVR/NVR!
            ],
            'model_patterns': [
                r'AX\s+PRO',
                r'AX\s+Hub',
            ],
            'cert_patterns': [r'hikvision\.com'],
            'confidence': 90,
            'require_product': True
        },

        'Texecom': {
            'brand_patterns': [r'\btexecom\b'],
            'product_patterns': [
                r'\bpremier\s+(?:elite|48|88|168|640)\b',
                r'\bpremier\b.*\belite\b',
                r'\btexecom\s+connect\b',
            ],
            'model_patterns': [
                r'Premier\s+Elite',
                r'Premier\s+\d+',
            ],
            'cert_patterns': [r'texe\.com'],
            'confidence': 100,
            'require_product': True
        },

        'Pyronix': {
            'brand_patterns': [r'\bpyronix\b'],
            'product_patterns': [
                r'\benforcer\b',
                r'\bhomecontrol\b',
                r'\bpyronix\s+(?:enforcer|cloud)\b',
            ],
            'model_patterns': [
                r'Enforcer\s+\w+',
            ],
            'cert_patterns': [r'pyronix\.com'],
            'confidence': 100,
            'require_product': True
        },

        'DSC': {
            'brand_patterns': [r'\bdsc\b', r'\bdigital\s+security\s+controls\b'],
            'product_patterns': [
                r'\bneo\b.*\balarm\b',
                r'\bpowerseries\b',
                r'\bpc\s+link\b',
                r'\bdsc\s+(?:neo|powerseries)\b',
            ],
            'model_patterns': [
                r'PowerSeries\s+\w+',
                r'NEO\s+\w+',
            ],
            'cert_patterns': [r'dsc\.com'],
            'confidence': 95,
            'require_product': True
        },

        'Paradox': {
            'brand_patterns': [r'\bparadox\b'],
            'product_patterns': [
                r'\bevo\s+(?:hd|192)\b',  # NOT just "evo"!
                r'\bmagellan\b',
                r'\bspectra\b.*\balarm\b',
                r'\bparadox\s+(?:evo|magellan)\b',
            ],
            'model_patterns': [
                r'EVO\s+(?:HD|192)',
                r'Magellan',
                r'Spectra',
            ],
            'cert_patterns': [r'paradox\.com'],
            'confidence': 95,
            'require_product': True
        },

        'Risco': {
            'brand_patterns': [r'\brisco\b'],
            'product_patterns': [
                r'\blightsys\b',
                r'\bagility\b.*\balarm\b',
                r'\brisco\s+(?:lightsys|agility)\b',
            ],
            'model_patterns': [
                r'LightSYS',
                r'Agility',
            ],
            'cert_patterns': [r'riscogroup\.com'],
            'confidence': 100,
            'require_product': True
        },
    },

    # ENHANCED EXCLUSIONS
    'exclusions': {
        'generic_security': [
            r'\bgeneric\s+alarm\b',
            r'\btest\s+alarm\b',
            r'\balarm\s+(?:clock|bell)\b',
            r'\bfire\s+alarm\b',  # Fire safety, not intrusion
            r'\bsmoke\s+(?:alarm|detector)\b',
        ],
        'cloud_services': [
            r'\bcloudflare\b',
            r'\bamazon\s+(?:web\s+services|aws)\b',
            r'\bmicrosoft\s+azure\b',
            r'\bgoogle\s+cloud\b',
            r'\bsalesforce\b',
        ],
        'it_security': [
            r'\bids\b.*\bintrusion\s+detection\s+system\b',
            r'\bips\b.*\bintrusion\s+prevention\b',
            r'\bfirewall\b',
            r'\bsnort\b',
            r'\bsuricata\b',
            # These are IT security, not physical I&HAS
        ],
        'generic_iot': [
            r'\bsmart\s+home\b',
            r'\bhome\s+assistant\b',
            r'\biot\s+hub\b',
            r'\balexa\b',
            r'\bgoogle\s+home\b',
        ],
    },
}


# ========================================
# STRICT DETECTION WITH DETAILED REPORTING
# ========================================

def identify_ihas_enhanced(row):
    """
    STRICT I&HAS identification with detailed match reporting

    Returns match details: which field, which pattern, which value
    """

    result = {
        'is_ihas': False,
        'ihas_confidence': 0,
        'detected_brand': None,
        'detected_product': None,
        'ihas_reason': None,
        # NEW: Detailed match info
        'match_field': None,
        'match_pattern': None,
        'match_value': None,
    }

    # Extract fields safely
    def safe_str(field):
        val = row.get(field, '')
        return str(val).lower() if pd.notna(val) else ''

    fields = {
        'title': safe_str('http.html_title'),
        'banner': safe_str('service.banner'),
        'product': safe_str('service.product'),
        'http_path': safe_str('http.path'),
        'headers': safe_str('http.headers'),
        'cert_issuer': safe_str('ssl.cert.issuer'),
        'cert_subject': safe_str('ssl.cert.subject'),
        'tags': safe_str('service.fingerprints.tags'),
    }

    all_text = ' '.join(fields.values())

    # ========================================
    # STEP 1: EXCLUSIONS
    # ========================================

    for category, patterns in IHAS_ENHANCED_CONFIG['exclusions'].items():
        for pattern in patterns:
            if re.search(pattern, all_text, re.IGNORECASE):
                result['ihas_reason'] = f"EXCLUDED: {category} - {pattern}"
                return result

    # ========================================
    # STEP 2: HTTP PATH DETECTION
    # ========================================

    if fields['http_path']:
        for brand, paths in IHAS_ENHANCED_CONFIG['http_paths'].items():
            for path in paths:
                if path in fields['http_path']:
                    # Verify brand also mentioned
                    if brand.lower() in all_text:
                        result['is_ihas'] = True
                        result['ihas_confidence'] = 90
                        result['detected_brand'] = brand
                        result['ihas_reason'] = f"HTTP path: {path} + brand: {brand}"
                        result['match_field'] = 'http.path'
                        result['match_pattern'] = path
                        result['match_value'] = fields['http_path']
                        return result

    # ========================================
    # STEP 3: PROTOCOL DETECTION
    # ========================================

    port = row.get('service.port', 0)

    for proto_name, proto_config in IHAS_ENHANCED_CONFIG['protocols'].items():
        if 'ports' in proto_config and port in proto_config['ports']:
            # MUST have banner confirmation
            for pattern in proto_config['banner_patterns']:
                match = re.search(pattern, all_text, re.IGNORECASE)
                if match:
                    result['is_ihas'] = True
                    result['ihas_confidence'] = proto_config['confidence']
                    result['ihas_reason'] = f"Protocol: {proto_name} (port {port} + banner)"
                    result['match_field'] = 'service.banner + port'
                    result['match_pattern'] = pattern
                    result['match_value'] = f"Port {port}, Banner: {match.group()}"
                    return result

    # ========================================
    # STEP 4: BRAND + PRODUCT COMBINATION
    # ========================================

    for brand, brand_config in IHAS_ENHANCED_CONFIG['brands'].items():
        # Check brand
        brand_found = False
        brand_match = None
        brand_field = None

        for pattern in brand_config['brand_patterns']:
            for field_name, field_value in fields.items():
                match = re.search(pattern, field_value, re.IGNORECASE)
                if match:
                    brand_found = True
                    brand_match = match.group()
                    brand_field = field_name
                    break
            if brand_found:
                break

        if not brand_found:
            continue

        # REQUIRE product
        if brand_config.get('require_product', True):
            product_found = False
            product_match = None
            product_field = None
            product_pattern = None

            for pattern in brand_config['product_patterns']:
                for field_name, field_value in fields.items():
                    match = re.search(pattern, field_value, re.IGNORECASE)
                    if match:
                        product_found = True
                        product_match = match.group()
                        product_field = field_name
                        product_pattern = pattern
                        break
                if product_found:
                    break

            if not product_found:
                # Brand without product = NOT I&HAS
                continue

            # Success!
            result['is_ihas'] = True
            result['detected_brand'] = brand
            result['detected_product'] = product_match
            result['ihas_confidence'] = brand_config['confidence']
            result['ihas_reason'] = f"Brand: {brand_match} ({brand_field}) + Product: {product_match} ({product_field})"
            result['match_field'] = f"{brand_field} + {product_field}"
            result['match_pattern'] = product_pattern
            result['match_value'] = f"Brand: {brand_match}, Product: {product_match}"

            return result

    return result


# ========================================
# VALIDATION
# ========================================

print("Enhanced I&HAS detection loaded (STRICT VERSION)")
print("  Brands: 10")
print("  HTTP paths: 25+ (product-specific)")
print("  Protocols: 2 (with banner confirmation)")
print("")
print("  CHANGES:")
print("  - NO generic terms (alarm, security, sensor)")
print("  - Require brand + specific product")
print("  - Detailed match reporting in output")
print("  - Enhanced exclusions")
print("")
print("  Expected: Much lower count, high precision")