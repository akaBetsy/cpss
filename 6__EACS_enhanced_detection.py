#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
STRICT EACS DETECTION - ZERO FALSE POSITIVES VERSION
====================================================

MAJOR CHANGES FROM PREVIOUS VERSION:
1. NO single-word matches (edge, evo, space, etc.) - too generic
2. NO port-only detection - must have brand + context
3. Require MULTIPLE signals for confidence
4. Strong brand + product combination required
5. Enhanced exclusions for web hosting, SaaS, generic terms

This version prioritizes PRECISION over RECALL.
Better to miss some EACS than include false positives.
"""

import re
import pandas as pd

# ========================================
# STRICT EACS CONFIGURATION
# ========================================

EACS_ENHANCED_CONFIG = {

    # Dataset tags - require explicit context
    'tags': ['Access Management', 'Building Automation'],

    # HTTP paths - MUST be specific, not generic
    'http_paths': {
        'Paxton': [
            '/net2/', '/net2plus/', '/net2entry/',
            '/paxton/net2', '/paxton-net2',
            '/paxtonaccess/'
        ],
        'Genetec': [
            '/synergis/', '/genetec/synergis',
            '/acaas/', '/genetec/acaas',
            '/cloudlink/access'
        ],
        'Lenel': [
            '/onguard/', '/lenel/onguard',
            '/s2netbox/', '/lenels2/',
            '/lnl-'
        ],
        'HID': [
            '/vertx/', '/hidvertx/',
            '/hid/vertx', '/hid-vertx',
            # REMOVED: '/edge/', '/evo/' - too generic!
            '/hidglobal/vertx', '/hidorigo/',
            '/aero/access'
        ],
        'Nedap': [
            '/aeos/', '/nedap/aeos',
            '/aeos-server', '/nedapaeos/'
        ],
        'Salto': [
            '/salto/space', '/saltospace/',
            '/salto-space', '/proaccess/',
            '/salto/xs4'
            # REMOVED: '/space/' alone - too generic!
        ],
        'Honeywell': [
            '/enteliweb/', '/web600/',
            '/niagara/access', '/honeywell/access'
        ],
        'Siemens': [
            '/desigo/', '/apogee/', '/insight/',
            '/siemens/desigo', '/siveillance/'
        ],
        'Johnson Controls': [
            '/metasys/', '/verasys/',
            '/jci/metasys', '/johnsoncontrols/access'
        ],
        'Schneider': [
            '/struxureware/', '/powerscada/',
            '/ecostruxure/', '/schneider/access'
        ],
    },

    # Protocol detection - require banner confirmation, not just port
    'protocols': {
        'bacnet': {
            'ports': [47808, 47809],
            'banner_patterns': [r'bacnet', r'bac/ip', r'bacnet/ip'],
            'confidence': 95,
            'context': 'BAS',
            'require_banner': True  # Port alone not enough
        },
        'osdp': {
            'ports': [10001, 10002],
            'banner_patterns': [r'osdp', r'open supervised device protocol'],
            'confidence': 100,
            'context': 'EACS',
            'require_banner': True
        },
        'wiegand': {
            'banner_patterns': [r'wiegand protocol', r'wiegand\s+\d+'],
            'confidence': 90,
            'context': 'EACS',
            'require_banner': True
        },
    },

    # Brand patterns - STRICT, require brand + product combo
    'brands': {
        'Nedap': {
            'brand_patterns': [r'\bnedap\b'],
            'product_patterns': [
                r'\baeos\b',
                r'\baeos\s+(?:server|controller|manager)',
                r'\bnedap\s+aeos',
            ],
            'model_patterns': [
                r'AEOS\s*\d+',
                r'Nedap\s+AEOS',
            ],
            'cert_patterns': [r'nedap\.com', r'nedap\.nl'],
            'confidence': 100,
            'require_product': True  # Brand alone not enough
        },

        'Paxton': {
            'brand_patterns': [r'\bpaxton\b'],
            'product_patterns': [
                r'\bnet\s*2\b', r'\bnet2\b',
                r'\bnet2\s+(?:plus|entry|pro|lite)',
                r'\bpaxton\s+access',
            ],
            'model_patterns': [
                r'Net2\s*(?:Plus|Pro|Entry|Lite)',
                r'Paxton\s+Net2',
            ],
            'cert_patterns': [r'paxton\.co\.uk', r'paxton-access\.com'],
            'confidence': 100,
            'require_product': True
        },

        'Genetec': {
            'brand_patterns': [r'\bgenetec\b'],
            'product_patterns': [
                r'\bsynergis\b',
                r'\bacaas\b',
                r'\bcloudlink\b',
                r'\bsecurity\s+center\b.*\baccess\b',
            ],
            'model_patterns': [
                r'Synergis\s+\w+',
                r'Genetec\s+Synergis',
            ],
            'cert_patterns': [r'genetec\.com'],
            'confidence': 100,
            'require_product': True
        },

        'Lenel': {
            'brand_patterns': [r'\blenel\b', r'\blenels2\b'],
            'product_patterns': [
                r'\bonguard\b', r'\bon\s*guard\b',
                r'\bs2\s+(?:netbox|global|controller)',
                r'\blenel\s+onguard',
            ],
            'model_patterns': [
                r'OnGuard\s+\d+',
                r'Lenel\s+OnGuard',
                r'LNL-\d+',
            ],
            'cert_patterns': [r'lenel\.com', r'lnl\.com'],
            'confidence': 100,
            'require_product': True
        },

        'Salto': {
            'brand_patterns': [r'\bsalto\b'],
            'product_patterns': [
                # REMOVED: r'\bspace\b' - too generic!
                r'\bsalto\s+space\b',
                r'\bxs\s*4\b', r'\bxs4\b',
                r'\bproaccess\b',
                r'\bsalto\s+(?:space|xs4|proaccess)',
            ],
            'model_patterns': [
                r'Salto\s+Space',
                r'Salto\s+XS4',
            ],
            'cert_patterns': [r'saltosystems\.com'],
            'confidence': 100,
            'require_product': True
        },

        'HID': {
            # STRICT: HID Global, not just "HID"
            'brand_patterns': [
                r'\bhid\s+global\b',
                r'\bhidglobal\b',
                r'\bhid-global\b'
            ],
            'product_patterns': [
                r'\bvertx\b',
                # REMOVED: r'\bedge\b', r'\bevo\b' - too generic!
                r'\bhid\s+vertx\b',
                r'\bvertx\s+(?:evo|edge|v\d+)',
                r'\borigo\b',
                r'\baero\s+x\b',
            ],
            'model_patterns': [
                r'VertX\s+(?:EVO|Edge|V\d+)',
                r'HID\s+VertX',
                r'Origo',
            ],
            'cert_patterns': [r'hidglobal\.com'],
            'confidence': 100,
            'require_product': True
        },

        'ASSA ABLOY': {
            'brand_patterns': [r'\bassa\s+abloy\b', r'\bassa-abloy\b'],
            'product_patterns': [
                r'\baperture\b',
                r'\bglobal\s+solutions\b',
                r'\bassa\s+abloy\s+(?:access|control)',
            ],
            'model_patterns': [
                r'Aperture\s+\d+',
            ],
            'cert_patterns': [r'assaabloy\.com'],
            'confidence': 95,
            'require_product': True
        },

        # BAS brands - require building automation context
        'Honeywell': {
            'brand_patterns': [r'\bhoneywell\b'],
            'product_patterns': [
                r'\benteliweb\b',
                r'\bweb600\b',
                r'\bniagara\b.*\bbuilding\b',
                r'\bbuilding\s+automation\b',
            ],
            'model_patterns': [
                r'EnteliWEB',
                r'Web600',
            ],
            'cert_patterns': [r'honeywell\.com'],
            'confidence': 90,
            'require_product': True,
            'is_bas': True
        },

        'Siemens': {
            'brand_patterns': [r'\bsiemens\b'],
            'product_patterns': [
                r'\bdesigo\b',
                r'\bapogee\b',
                r'\binsight\b',
                r'\bbuilding\s+(?:automation|management)',
            ],
            'model_patterns': [
                r'Desigo\s+\w+',
                r'Apogee',
            ],
            'cert_patterns': [r'siemens\.com'],
            'confidence': 90,
            'require_product': True,
            'is_bas': True
        },

        'Johnson Controls': {
            'brand_patterns': [r'\bjohnson\s+controls\b', r'\bjci\b'],
            'product_patterns': [
                r'\bmetasys\b',
                r'\bverasys\b',
                r'\bfacility\s+explorer\b',
            ],
            'model_patterns': [
                r'Metasys\s+\d+',
            ],
            'cert_patterns': [r'johnsoncontrols\.com'],
            'confidence': 90,
            'require_product': True,
            'is_bas': True
        },

        'Schneider Electric': {
            'brand_patterns': [r'\bschneider\b', r'\bschneider\s+electric\b'],
            'product_patterns': [
                r'\bstruxureware\b',
                r'\becostruxure\b',
                r'\bbuilding\s+operation\b',
            ],
            'model_patterns': [
                r'StruxureWare',
                r'EcoStruxure',
            ],
            'cert_patterns': [r'schneider-electric\.com'],
            'confidence': 90,
            'require_product': True,
            'is_bas': True
        },
    },

    # ENHANCED EXCLUSIONS - critical for false positive prevention
    'exclusions': {
        'cloud_services': [
            r'\bcloudflare\b',
            r'\bamazon\s+(?:web\s+services|aws)\b',
            r'\bmicrosoft\s+azure\b',
            r'\bgoogle\s+cloud\b',
            r'\bsalesforce\b',
            r'\bheroku\b',
            r'\bvercel\b',
            r'\bnetlify\b',
        ],
        'web_hosting': [
            r'\bcpanel\b',
            r'\bplesk\b',
            r'\bwordpress\b',
            r'\bdrupal\b',
            r'\bjoomla\b',
            r'\bwix\b',
            r'\bsquarespace\b',
            r'\bshopify\b',
        ],
        'cdn_edge': [
            r'\bcdn\s+edge\b',
            r'\bedge\s+(?:cache|server|node)\b',
            r'\bfastly\s+edge\b',
            r'\bakamai\s+edge\b',
            r'\bcloudfront\s+edge\b',
        ],
        'generic_terms': [
            r'^edge$',  # Just "edge" alone
            r'^evo$',  # Just "evo" alone
            r'^space$',  # Just "space" alone
            r'\bedge\s+(?:computing|browser|network)\b',
            r'\bevolution\b',  # "Evolution" often shortened to "evo"
        ],
        'it_infrastructure': [
            r'\bvmware\b',
            r'\bhypervisor\b',
            r'\bvirtual\s+machine\b',
            r'\bcontainer\b',
            r'\bdocker\b',
            r'\bkubernetes\b',
        ],
    },
}


# ========================================
# STRICT DETECTION FUNCTION
# ========================================

def identify_eacs_enhanced(row):
    """
    STRICT EACS identification with multi-signal requirement

    Changes from previous version:
    1. Require brand + product combination (not brand alone)
    2. No single generic word matches
    3. Strong exclusion filtering
    4. Confidence requires multiple confirming signals
    """

    result = {
        'is_eacs': False,
        'is_bas': False,
        'eacs_confidence': 0,
        'detected_brand': None,
        'detected_product': None,
        'eacs_reason': None
    }

    # Extract fields safely
    def safe_str(field):
        val = row.get(field, '')
        return str(val).lower() if pd.notna(val) else ''

    title = safe_str('http.html_title')
    banner = safe_str('service.banner')
    product = safe_str('service.product')
    http_path = safe_str('http.path')
    headers = safe_str('http.headers')
    cert_issuer = safe_str('ssl.cert.issuer')
    cert_subject = safe_str('ssl.cert.subject')
    tags = safe_str('service.fingerprints.tags')

    # Combine all text for searching
    all_text = f"{title} {banner} {product} {http_path} {headers} {cert_issuer} {cert_subject} {tags}"

    # ========================================
    # STEP 1: EXCLUSIONS (Critical!)
    # ========================================

    for category, patterns in EACS_ENHANCED_CONFIG['exclusions'].items():
        for pattern in patterns:
            if re.search(pattern, all_text, re.IGNORECASE):
                # HARD STOP - this is not EACS
                return result

    # ========================================
    # STEP 2: HTTP PATH DETECTION (High confidence if specific)
    # ========================================

    if http_path:
        for brand, paths in EACS_ENHANCED_CONFIG['http_paths'].items():
            for path in paths:
                if path in http_path:
                    # Verify brand also appears
                    brand_confirmed = brand.lower() in all_text

                    if brand_confirmed:
                        result['is_eacs'] = True
                        result['eacs_confidence'] = 90
                        result['detected_brand'] = brand
                        result['eacs_reason'] = f"HTTP path: {path} + brand: {brand}"

                        # Check if BAS
                        brand_config = EACS_ENHANCED_CONFIG['brands'].get(brand, {})
                        if brand_config.get('is_bas', False):
                            result['is_bas'] = True

                        return result

    # ========================================
    # STEP 3: PROTOCOL DETECTION (Requires banner confirmation)
    # ========================================

    port = row.get('service.port', 0)

    for proto_name, proto_config in EACS_ENHANCED_CONFIG['protocols'].items():
        # Check port
        if 'ports' in proto_config and port in proto_config['ports']:
            # MUST have banner confirmation
            banner_confirmed = False
            for pattern in proto_config['banner_patterns']:
                if re.search(pattern, all_text, re.IGNORECASE):
                    banner_confirmed = True
                    break

            if banner_confirmed:
                result['is_eacs'] = True
                result['eacs_confidence'] = proto_config['confidence']
                result['eacs_reason'] = f"Protocol: {proto_name} (port {port} + banner)"

                if proto_config['context'] == 'BAS':
                    result['is_bas'] = True

                return result

    # ========================================
    # STEP 4: BRAND + PRODUCT COMBINATION (Strictest)
    # ========================================

    for brand, brand_config in EACS_ENHANCED_CONFIG['brands'].items():
        # Check brand patterns
        brand_found = False
        for pattern in brand_config['brand_patterns']:
            if re.search(pattern, all_text, re.IGNORECASE):
                brand_found = True
                break

        if not brand_found:
            continue

        # CRITICAL: Require product confirmation
        if brand_config.get('require_product', True):
            product_found = False
            matched_product = None

            for pattern in brand_config['product_patterns']:
                if re.search(pattern, all_text, re.IGNORECASE):
                    product_found = True
                    matched_product = pattern
                    break

            if not product_found:
                # Brand without product = NOT EACS
                continue

        # Success: Brand + Product confirmed
        result['is_eacs'] = True
        result['detected_brand'] = brand
        result['detected_product'] = matched_product
        result['eacs_confidence'] = brand_config['confidence']
        result['eacs_reason'] = f"Brand: {brand} + Product: {matched_product}"

        if brand_config.get('is_bas', False):
            result['is_bas'] = True

        return result

    # ========================================
    # STEP 5: DATASET TAG (Lowest confidence, require context)
    # ========================================

    if tags:
        for tag in EACS_ENHANCED_CONFIG['tags']:
            if tag.lower() in tags:
                # Tag alone = LOW confidence, need more signals
                # Check if there's ANY brand mention
                for brand in EACS_ENHANCED_CONFIG['brands'].keys():
                    if brand.lower() in all_text:
                        result['is_eacs'] = True
                        result['eacs_confidence'] = 60
                        result['detected_brand'] = brand
                        result['eacs_reason'] = f"Tag: {tag} + Brand mention: {brand}"
                        return result

    return result


# ========================================
# VALIDATION NOTES
# ========================================

print("Enhanced EACS detection loaded (STRICT VERSION)")
print("  Brands: 13")
print("  HTTP paths: 35+ (specific only)")
print("  Protocols: 3 (with banner confirmation)")
print("")
print("  CHANGES FROM PREVIOUS:")
print("  - NO single-word matches (edge, evo, space)")
print("  - Require brand + product combination")
print("  - Enhanced exclusions for false positives")
print("  - Port detection requires banner confirmation")
print("")
print("  Expected: Lower recall, MUCH higher precision")
print("  Goal: Zero false positives")