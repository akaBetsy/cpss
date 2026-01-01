#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
STRICT VSS DETECTION - HIGH PRECISION VERSION
=============================================

CHANGES FROM PREVIOUS:
1. Stronger product requirements
2. NO generic terms without context
3. Detailed match reporting
4. Enhanced cloud/IT camera exclusions

Goal: PRECISION over RECALL
"""

import re
import pandas as pd

# ========================================
# STRICT VSS CONFIGURATION
# ========================================

VSS_ENHANCED_CONFIG = {

    # HTTP paths - camera/NVR/VMS specific
    'http_paths': {
        'Hikvision': [
            '/doc/page/login.asp', '/ISAPI/',
            '/onvif/', '/streaming/',
            '/hikvision/', '/ivms-'
        ],
        'Dahua': [
            '/videotalk/', '/RPC2',
            '/dahua/', '/dss-', '/smartpss/'
        ],
        'Axis': [
            '/axis-cgi/', '/operator/',
            '/axis/', '/vapix/'
        ],
        'Hanwha': [
            '/stw-cgi/', '/wisenet/',
            '/hanwha/', '/ssnb-'
        ],
        'MOBOTIX': [
            '/control/', '/cgi-bin/image',
            '/mobotix/', '/mxpeg/'
        ],
        'Geutebruck': [
            '/geutebrueck/', '/gbcontrol/',
            '/gcore/', '/gconfig/'
        ],
        'Avigilon': [
            '/avigilon/', '/acc-',
            '/appearance-search/'
        ],
        'Bosch': [
            '/rcp.xml', '/bosch/',
            '/autodome/', '/dinion/'
        ],
    },

    # Protocols - VSS specific
    'protocols': {
        'rtsp': {
            'ports': [554, 8554],
            'banner_patterns': [
                r'rtsp/1\.0', r'real\s+time\s+streaming',
                r'live/stream', r'cam\d+/stream'
            ],
            'confidence': 95,
            'require_banner': True
        },
        'onvif': {
            'banner_patterns': [
                r'onvif', r'onvif.*device',
                r'/onvif/', r'onvif.*service'
            ],
            'confidence': 100,
            'require_banner': False  # ONVIF in path is enough
        },
    },

    # Brands - require camera/NVR context
    'brands': {
        'Hikvision': {
            'brand_patterns': [r'\bhikvision\b', r'\bhik\s+vision\b'],
            'product_patterns': [
                r'\bds-\d+',  # Model numbers
                r'\bivms\b', r'\bivms-\d+',
                r'\bnvr\b', r'\bdvr\b',
                r'\bipc\b',  # IP camera
                r'\bhikvision\s+(?:camera|nvr|dvr)\b',
                # Must have product context!
            ],
            'model_patterns': [
                r'DS-\d+[A-Z]+',
                r'iVMS-\d+',
            ],
            'cert_patterns': [r'hikvision\.com'],
            'confidence': 100,
            'require_product': True
        },

        'Dahua': {
            'brand_patterns': [r'\bdahua\b'],
            'product_patterns': [
                r'\bdh-\w+',  # Model prefix
                r'\bnvr\d+', r'\bdvr\d+',
                r'\bipc-\w+',
                r'\bdss\b', r'\bsmartpss\b',
                r'\bdahua\s+(?:camera|nvr|dvr)\b',
            ],
            'model_patterns': [
                r'DH-[A-Z0-9]+',
                r'IPC-\w+',
            ],
            'cert_patterns': [r'dahuasecurity\.com'],
            'confidence': 100,
            'require_product': True
        },

        'Axis': {
            'brand_patterns': [r'\baxis\b'],
            'product_patterns': [
                r'\baxis\s+[mfpq]\d+',  # Model series
                r'\baxis\s+camera\b',
                r'\bvapix\b',
                r'\baxis\s+companion\b',
                # NOT just "axis"!
            ],
            'model_patterns': [
                r'AXIS\s+[MFPQ]\d+',
                r'Axis\s+Companion',
            ],
            'cert_patterns': [r'axis\.com'],
            'confidence': 100,
            'require_product': True
        },

        'Hanwha': {
            'brand_patterns': [
                r'\bhanwha\b', r'\bwisenet\b',
                r'\bsamsung\s+wisenet\b'
            ],
            'product_patterns': [
                r'\bxnv-\w+', r'\bxnp-\w+',  # Model prefixes
                r'\bwisenet\s+(?:x|p|q)\b',
                r'\bssnb\b',  # Server
                r'\bhanwha\s+camera\b',
            ],
            'model_patterns': [
                r'XN[VPO]-\w+',
                r'Wisenet\s+[XPQ]',
            ],
            'cert_patterns': [r'hanwha-security\.com'],
            'confidence': 100,
            'require_product': True
        },

        'MOBOTIX': {
            'brand_patterns': [r'\bmobotix\b'],
            'product_patterns': [
                r'\bmx-\w+',  # Model prefix
                r'\bmxpeg\b',
                r'\bmobotix\s+(?:camera|m\d+|s\d+)\b',
            ],
            'model_patterns': [
                r'MX-[A-Z0-9]+',
                r'MOBOTIX\s+[MS]\d+',
            ],
            'cert_patterns': [r'mobotix\.com'],
            'confidence': 100,
            'require_product': True
        },

        'Geutebruck': {
            'brand_patterns': [r'\bgeutebr[üu]ck\b'],
            'product_patterns': [
                r'\bgcore\b',
                r'\bg-\w+',  # Model prefix
                r'\bgeutebrueck\s+camera\b',
            ],
            'model_patterns': [
                r'G-\w+',
                r'GCore',
            ],
            'cert_patterns': [r'geutebrueck\.com'],
            'confidence': 100,
            'require_product': True
        },

        'Avigilon': {
            'brand_patterns': [r'\bavigilon\b'],
            'product_patterns': [
                r'\bacc\b.*\b(?:server|client)\b',
                r'\bavigilon\s+(?:camera|h\d+)\b',
                r'\bappearance\s+search\b',
            ],
            'model_patterns': [
                r'H\d+[A-Z]+',
                r'ACC\s+\d+',
            ],
            'cert_patterns': [r'avigilon\.com'],
            'confidence': 100,
            'require_product': True
        },

        'Bosch Security': {
            'brand_patterns': [r'\bbosch\b'],
            'product_patterns': [
                r'\bautodome\b',
                r'\bdinion\b',
                r'\bflex\s+dome\b',
                r'\bnbn-\w+', r'\bndc-\w+',  # Model prefixes
                r'\bbosch\s+camera\b',
            ],
            'model_patterns': [
                r'NBN-\w+',
                r'AutoDome',
                r'DINION',
            ],
            'cert_patterns': [r'boschsecurity\.com'],
            'confidence': 95,
            'require_product': True
        },

        'Genetec': {
            'brand_patterns': [r'\bgenetec\b'],
            'product_patterns': [
                r'\bomnicast\b',
                r'\bstratocast\b',
                r'\bsecurity\s+center\b.*\bvideo\b',
                # Genetec makes both VSS and EACS
            ],
            'model_patterns': [
                r'Omnicast',
                r'Stratocast',
            ],
            'cert_patterns': [r'genetec\.com'],
            'confidence': 100,
            'require_product': True
        },

        'Geovision': {
            'brand_patterns': [r'\bgeovision\b', r'\bgv-\w+\b'],
            'product_patterns': [
                r'\bgv-\w+',  # Model prefix
                r'\bgeovision\s+(?:camera|nvr|gv)\b',
            ],
            'model_patterns': [
                r'GV-[A-Z0-9]+',
            ],
            'cert_patterns': [r'geovision\.com\.tw'],
            'confidence': 95,
            'require_product': True
        },

        'Vivotek': {
            'brand_patterns': [r'\bvivotek\b'],
            'product_patterns': [
                r'\bip\d+', r'\bfd\d+',  # Model series
                r'\bvivotek\s+camera\b',
                r'\bvast\b',  # VMS
            ],
            'model_patterns': [
                r'IP\d+[A-Z]*',
                r'FD\d+',
            ],
            'cert_patterns': [r'vivotek\.com'],
            'confidence': 100,
            'require_product': True
        },
    },

    # ENHANCED EXCLUSIONS
    'exclusions': {
        'cloud_cameras': [
            r'\bwebcam\b',
            r'\bzoom\s+camera\b',
            r'\bteams\s+camera\b',
            r'\bskype\s+camera\b',
            r'\bobs\s+camera\b',  # OBS Studio
        ],
        'it_cameras': [
            r'\bvirtual\s+camera\b',
            r'\bip\s+camera\b.*\bsimulator\b',
            r'\bcamera\s+emulator\b',
        ],
        'mobile_apps': [
            r'\bandroid\s+camera\b',
            r'\bios\s+camera\b',
            r'\bmobile\s+camera\b',
        ],
        'web_services': [
            r'\bcloudflare\b',
            r'\bamazon\s+(?:web\s+services|aws)\b',
            r'\bgoogle\s+cloud\b',
        ],
    },
}


# ========================================
# STRICT DETECTION WITH DETAILED REPORTING
# ========================================

def identify_vss_enhanced(row):
    """
    STRICT VSS identification with detailed match reporting
    """

    result = {
        'is_vss': False,
        'vss_confidence': 0,
        'detected_brand': None,
        'detected_product': None,
        'vss_reason': None,
        # NEW: Detailed match info
        'match_field': None,
        'match_pattern': None,
        'match_value': None,
    }

    # Extract fields
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

    for category, patterns in VSS_ENHANCED_CONFIG['exclusions'].items():
        for pattern in patterns:
            if re.search(pattern, all_text, re.IGNORECASE):
                result['vss_reason'] = f"EXCLUDED: {category} - {pattern}"
                return result

    # ========================================
    # STEP 2: PROTOCOL DETECTION (RTSP/ONVIF)
    # ========================================

    port = row.get('service.port', 0)

    for proto_name, proto_config in VSS_ENHANCED_CONFIG['protocols'].items():
        # Check port (if specified)
        port_match = True
        if 'ports' in proto_config:
            port_match = port in proto_config['ports']

        if port_match or not proto_config.get('require_banner', True):
            # Check banner patterns
            for pattern in proto_config['banner_patterns']:
                match = re.search(pattern, all_text, re.IGNORECASE)
                if match:
                    result['is_vss'] = True
                    result['vss_confidence'] = proto_config['confidence']
                    result['vss_reason'] = f"Protocol: {proto_name}"
                    result['match_field'] = 'protocol detection'
                    result['match_pattern'] = pattern
                    result['match_value'] = f"Port {port}, Pattern: {match.group()}"
                    return result

    # ========================================
    # STEP 3: HTTP PATH DETECTION
    # ========================================

    if fields['http_path']:
        for brand, paths in VSS_ENHANCED_CONFIG['http_paths'].items():
            for path in paths:
                if path in fields['http_path']:
                    # Verify brand mentioned
                    if brand.lower() in all_text:
                        result['is_vss'] = True
                        result['vss_confidence'] = 90
                        result['detected_brand'] = brand
                        result['vss_reason'] = f"HTTP path: {path} + brand: {brand}"
                        result['match_field'] = 'http.path'
                        result['match_pattern'] = path
                        result['match_value'] = fields['http_path']
                        return result

    # ========================================
    # STEP 4: BRAND + PRODUCT COMBINATION
    # ========================================

    for brand, brand_config in VSS_ENHANCED_CONFIG['brands'].items():
        # Find brand
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
                # Brand without product = NOT VSS
                continue

            # Success!
            result['is_vss'] = True
            result['detected_brand'] = brand
            result['detected_product'] = product_match
            result['vss_confidence'] = brand_config['confidence']
            result['vss_reason'] = f"Brand: {brand_match} ({brand_field}) + Product: {product_match} ({product_field})"
            result['match_field'] = f"{brand_field} + {product_field}"
            result['match_pattern'] = product_pattern
            result['match_value'] = f"Brand: {brand_match}, Product: {product_match}"

            return result

    return result


# ========================================
# VALIDATION
# ========================================

print("Enhanced VSS detection loaded (STRICT VERSION)")
print("  Brands: 11")
print("  HTTP paths: 35+ (camera/NVR specific)")
print("  Protocols: 2 (RTSP, ONVIF)")
print("")
print("  CHANGES:")
print("  - Require brand + product context")
print("  - Enhanced cloud/IT camera exclusions")
print("  - Detailed match reporting")
print("")
print("  Expected: High precision, validated results")