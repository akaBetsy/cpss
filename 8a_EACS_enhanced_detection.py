#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
COMPREHENSIVE EACS DETECTION - ALL 51 BRANDS
=============================================

Includes ALL brands from the requirement list.
Balanced approach: strict for major brands, more lenient for smaller brands.
"""

import re
import pandas as pd

# ========================================
# VENDOR DEFAULT PORT CONFIGURATION
# ========================================

VENDOR_DEFAULT_PORTS = {
    # Hikvision
    8000: {
        'brand': 'Hikvision',
        'confidence_boost': 15,
        'category': 'VSS',
        'description': 'Hikvision HTTP'
    },
    34567: {
        'brand': 'Hikvision',
        'type': 'DVR/NVR',
        'confidence_boost': 20,
        'category': 'VSS',
        'description': 'Hikvision DVR/NVR'
    },

    # Dahua
    37777: {
        'brand': 'Dahua',
        'confidence_boost': 20,
        'category': 'VSS',
        'description': 'Dahua TCP'
    },
    3800: {
        'brand': 'Dahua',
        'confidence_boost': 15,
        'category': 'VSS',
        'description': 'Dahua HTTP alternate'
    },

    # Axis
    8080: {
        'brand': 'Axis',
        'confidence_boost': 5,
        'category': 'VSS',
        'description': 'Axis HTTP (common port)'
    },

    # Genetec
    4502: {
        'brand': 'Genetec',
        'type': 'Omnicast',
        'confidence_boost': 15,
        'category': 'EACS',
        'description': 'Genetec Omnicast'
    },

    # RTSP
    554: {
        'protocol': 'RTSP',
        'confidence_boost': 10,
        'category': 'VSS',
        'description': 'RTSP standard'
    },
    8554: {
        'protocol': 'RTSP',
        'confidence_boost': 10,
        'category': 'VSS',
        'description': 'RTSP alternate'
    },
}

# ========================================
# MODERN CPSS FEATURES CONFIGURATION
# ========================================

MODERN_FEATURES_CONFIG = {
    'cloud_connectivity': {
        'patterns': [
            r'\bp2p\b', r'peer.?to.?peer',
            r'\bddns\b', r'dynamic\s+dns', r'no-ip', r'dyndns',
            r'cloud.*connect', r'cloud.*service',
            r'iot.*cloud', r'remote.*cloud'
        ],
        'confidence_boost': 5,
    },

    'mobile_access': {
        'patterns': [
            r'mobile.*app', r'mobile.*view', r'mobile.*client',
            r'remote.*app', r'remote.*view',
            r'qr.*code', r'qr.*setup', r'qr.*scan',
            r'smartphone', r'tablet.*access',
            r'android', r'ios.*app', r'iphone.*app'
        ],
        'confidence_boost': 5,
    },

    'remote_management': {
        'paths': [
            r'/api/mobile/', r'/mobile/', r'/app/',
            r'/cloud/', r'/remote/', r'/qr'
        ],
        'confidence_boost': 5,
    },
}


def detect_modern_features(row):
    """
    Detect modern CPSS features (cloud, mobile, remote)
    Returns: (detected_features: list, confidence_boost: int)
    """
    detected = []
    total_boost = 0

    # Searchable fields
    http_body = str(row.get('service.http.body', '')).lower()
    http_title = str(row.get('service.http.title', '')).lower()
    banner = str(row.get('service.banner', '')).lower()

    searchable = f"{http_body} {http_title} {banner}"

    # Check cloud connectivity
    for pattern in MODERN_FEATURES_CONFIG['cloud_connectivity']['patterns']:
        if re.search(pattern, searchable, re.IGNORECASE):
            detected.append('cloud_connectivity')
            total_boost = max(total_boost, MODERN_FEATURES_CONFIG['cloud_connectivity']['confidence_boost'])
            break

    # Check mobile access
    for pattern in MODERN_FEATURES_CONFIG['mobile_access']['patterns']:
        if re.search(pattern, searchable, re.IGNORECASE):
            detected.append('mobile_access')
            total_boost = max(total_boost, MODERN_FEATURES_CONFIG['mobile_access']['confidence_boost'])
            break

    # Check remote management paths
    for path_pattern in MODERN_FEATURES_CONFIG['remote_management']['paths']:
        if re.search(path_pattern, searchable, re.IGNORECASE):
            detected.append('remote_management')
            total_boost = max(total_boost, MODERN_FEATURES_CONFIG['remote_management']['confidence_boost'])
            break

    return detected, total_boost


# ========================================
# ENHANCED CONFIDENCE CALCULATION
# ========================================
# Enhancement: Multi-factor confidence scoring

def calculate_enhanced_confidence(row, base_confidence, brand, category, detection_methods):
    """
    Calculate confidence with multiple factors:
    - Base confidence from primary detection
    - Protocol bonuses
    - Port bonuses
    - Modern feature bonuses
    - Multiple detection method bonus

    Returns: final_confidence (0-100), bonus_details (dict)
    """
    bonuses = {}
    total_bonus = 0

    # 1. Vendor port match bonus (Q3)
    port = row.get('service.port', 0)
    if port in VENDOR_DEFAULT_PORTS:
        port_info = VENDOR_DEFAULT_PORTS[port]

        # If brand matches, apply boost
        if port_info.get('brand') == brand:
            bonus = port_info['confidence_boost']
            bonuses['vendor_port_match'] = bonus
            total_bonus += bonus
        # If protocol matches (RTSP), apply smaller boost
        elif port_info.get('protocol'):
            bonus = port_info['confidence_boost'] // 2  # Half boost for protocol-only match
            bonuses['protocol_port_match'] = bonus
            total_bonus += bonus

    # 2. Modern features bonus (Q4)
    modern_features, modern_boost = detect_modern_features(row)
    if modern_features:
        bonuses['modern_features'] = modern_boost
        total_bonus += modern_boost

    # 3. Multiple detection methods bonus
    method_count = len(detection_methods) if detection_methods else 0
    if method_count >= 3:
        bonuses['multiple_methods'] = 10
        total_bonus += 10
    elif method_count == 2:
        bonuses['multiple_methods'] = 5
        total_bonus += 5

    # Calculate final confidence (cap at 100)
    final_confidence = min(base_confidence + total_bonus, 100)

    return final_confidence, bonuses


# ========================================
# COMPREHENSIVE EACS CONFIGURATION
# ========================================

EACS_ENHANCED_CONFIG = {

    # Dataset tags
    'tags': ['Access Management', 'Building Automation', 'Access Control'],

    # HTTP paths
    'http_paths': {
        'Paxton': ['/net2/', '/net2plus/', '/paxton/'],
        'Genetec': ['/synergis/', '/acaas/', '/cloudlink/access'],
        'Lenel': ['/onguard/', '/s2netbox/', '/lenels2/', '/lnl-'],
        'HID': ['/vertx/', '/hidvertx/', '/hidorigo/', '/aero/access'],
        'Nedap': ['/aeos/', '/nedap/aeos'],
        'Salto': ['/salto/space', '/saltospace/', '/proaccess/', '/salto/xs4'],
        'Honeywell': ['/enteliweb/', '/web600/', '/niagara/access'],
        'Siemens': ['/desigo/', '/apogee/', '/insight/', '/siveillance/'],
        'Johnson Controls': ['/metasys/', '/verasys/', '/jci/'],
        'Schneider': ['/struxureware/', '/ecostruxure/'],
        'Gallagher': ['/gallagher/', '/command-centre/'],
        'Dormakaba': ['/dormakaba/', '/saflok/', '/oracode/'],
        'ASSA ABLOY': ['/assaabloy/', '/traka/'],
        'Axis': ['/axis-cgi/', '/vapix/', '/axis-access/'],
        'Software House': ['/ccure/', '/software-house/'],
        'Mercury': ['/mercury/', '/lp1501/'],
        'Bosch': ['/amc/', '/bosch-access/'],
        'Vanderbilt': ['/spc/', '/spc-connect'],
        'ZKTeco': ['/zkteco/', '/biotime/', '/zkaccess/'],
        'Suprema': ['/biostar/', '/suprema/'],
        'Allegion': ['/allegion/', '/schlage-control/'],
        'Tyco': ['/tyco/', '/c-cure/'],
        'ICT': ['/protege/', '/ict-protege/'],
        'Amag': ['/amag/', '/symmetry/'],
        'Open Path': ['/openpath/', '/alto/'],
        'Cisco': ['/cisco-acs/', '/ise/'],
        'Idemia': ['/idemia/', '/morphowave/'],
        'Thales': ['/thales/', '/gemalto/'],
        'Panasonic': ['/panasonic-access/', '/arbitrator/'],
        'TKH': ['/keyprocessor/', '/tkh-security/'],
    },

    # Protocols
    'protocols': {
        'bacnet': {
            'ports': [47808, 47809],
            'banner_patterns': [r'bacnet', r'bac/ip', r'bacnet/ip'],
            'confidence': 95,
            'context': 'BAS',
            'require_banner': True
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

    # Brands - ALL 51 BRANDS
    'brands': {
        # ========== TIER 1: MAJOR BRANDS (Strict) ==========

        'Nedap': {
            'brand_patterns': [r'\bnedap\b'],
            'product_patterns': [r'\baeos\b', r'\blumo\b', r'\banpr\b'],
            'model_patterns': [r'AEOS', r'Lumo'],
            'cert_patterns': [r'nedap\.com'],
            'confidence': 100,
            'require_product': True
        },

        'Paxton': {
            'brand_patterns': [r'\bpaxton\b'],
            'product_patterns': [r'\bnet\s*2\b', r'\bnet2\b', r'\bpaxton\s+access\b'],
            'model_patterns': [r'Net2'],
            'cert_patterns': [r'paxton\.co\.uk'],
            'confidence': 100,
            'require_product': True
        },

        'ASSA ABLOY': {
            'brand_patterns': [r'\bassa\s+abloy\b', r'\bassaabloy\b'],
            'product_patterns': [r'\btraka\b', r'\bvingcard\b', r'\babloy\b'],
            'model_patterns': [r'Traka', r'VingCard'],
            'cert_patterns': [r'assaabloy\.com'],
            'confidence': 100,
            'require_product': True
        },

        'Genetec': {
            'brand_patterns': [r'\bgenetec\b'],
            'product_patterns': [r'\bsynergis\b', r'\bacaas\b', r'\bcloudlink\b'],
            'model_patterns': [r'Synergis'],
            'cert_patterns': [r'genetec\.com'],
            'confidence': 100,
            'require_product': True,
            'is_multi_function': True  # Also does VSS
        },

        'Lenel': {
            'brand_patterns': [r'\blenel\b', r'\blenels2\b'],
            'product_patterns': [r'\bonguard\b', r'\bs2\s+netbox\b', r'\bs2\s+global\b'],
            'model_patterns': [r'OnGuard', r'LNL-'],
            'cert_patterns': [r'lenel\.com'],
            'confidence': 100,
            'require_product': True,
            'is_multi_function': True  # Also does VSS/IHAS
        },

        'Salto': {
            'brand_patterns': [r'\bsalto\b'],
            'product_patterns': [r'\bsalto\s+space\b', r'\bxs\s*4\b', r'\bproaccess\b'],
            'model_patterns': [r'Salto\s+Space', r'XS4'],
            'cert_patterns': [r'saltosystems\.com'],
            'confidence': 100,
            'require_product': True
        },

        'ZKTeco': {
            'brand_patterns': [r'\bzkteco\b', r'\bzk\s+teco\b'],
            'product_patterns': [r'\bbiotime\b', r'\bzmm220\b', r'\bzem560\b', r'\bzkaccess\b'],
            'model_patterns': [r'ZMM220', r'ZEM560', r'BioTime'],
            'cert_patterns': [r'zkteco\.com'],
            'confidence': 95,
            'require_product': True
        },

        'Allegion': {
            'brand_patterns': [r'\ballegion\b'],
            'product_patterns': [r'\bschlage\s+control\b', r'\bvon\s+duprin\b', r'\ballegion\s+access\b'],
            'model_patterns': [r'Schlage\s+Control'],
            'cert_patterns': [r'allegion\.com'],
            'confidence': 95,
            'require_product': True
        },

        'Honeywell': {
            'brand_patterns': [r'\bhoneywell\b'],
            'product_patterns': [r'\benteliweb\b', r'\bweb600\b', r'\bniagara\b', r'\bhoneywell\s+access\b'],
            'model_patterns': [r'Web600', r'EnteliWEB'],
            'cert_patterns': [r'honeywell\.com'],
            'confidence': 95,
            'require_product': True,
            'is_bas': True  # Building automation
        },

        'NEC': {
            'brand_patterns': [r'\bnec\b', r'\bnec\s+corporation\b'],
            'product_patterns': [r'\bnec\s+access\b', r'\bnec\s+control\b', r'\bneoface\b'],
            'model_patterns': [r'NeoFace'],
            'cert_patterns': [r'nec\.com'],
            'confidence': 90,
            'require_product': True
        },

        'Suprema': {
            'brand_patterns': [r'\bsuprema\b'],
            'product_patterns': [r'\bbiostar\s*2\b', r'\bbiostar\b', r'\bbioentry\b', r'\bbioliteen\b'],
            'model_patterns': [r'BioStar', r'BioEntry'],
            'cert_patterns': [r'supremainc\.com'],
            'confidence': 100,
            'require_product': True
        },

        # ========== TIER 2: ESTABLISHED BRANDS ==========

        'Abus': {
            'brand_patterns': [r'\babus\b'],
            'product_patterns': [r'\btectiq\b', r'\bwapploxx\b', r'\bcodeloxx\b', r'\babus\s+access\b'],
            'model_patterns': [r'Tectiq', r'Wapploxx', r'Codeloxx'],
            'cert_patterns': [r'abus\.com'],
            'confidence': 90,
            'require_product': True
        },

        'Alphatronics': {
            'brand_patterns': [r'\balphatronics\b'],
            'product_patterns': [r'\balphagate\b', r'\balphacrypt\b', r'\balphatronics\s+access\b'],
            'model_patterns': [r'AlphaGate'],
            'cert_patterns': [r'alphatronics\.'],
            'confidence': 85,
            'require_product': True
        },

        'Amag': {
            'brand_patterns': [r'\bamag\b'],
            'product_patterns': [r'\bsymmetry\b', r'\bamag\s+access\b'],
            'model_patterns': [r'Symmetry'],
            'cert_patterns': [r'amag\.com'],
            'confidence': 95,
            'require_product': True
        },

        'Aritech': {
            'brand_patterns': [r'\baritech\b'],
            'product_patterns': [r'\bacs\b.*\baccess\b', r'\baritech\s+access\b'],
            'model_patterns': [r'ACS'],
            'cert_patterns': [r'aritech\.'],
            'confidence': 85,
            'require_product': True
        },

        'Authasas': {
            'brand_patterns': [r'\bauthasas\b'],
            'product_patterns': [r'\bauthasas\s+access\b', r'\bauthasas\s+suite\b'],
            'model_patterns': [],
            'cert_patterns': [r'authasas\.'],
            'confidence': 85,
            'require_product': False  # Small brand, brand name itself is unique
        },

        'Axis': {
            'brand_patterns': [r'\baxis\b', r'\baxis\s+communications\b'],
            'product_patterns': [r'\baxis\s+access\b', r'\ba1001\b', r'\baxis\s+a\d+\b'],
            'model_patterns': [r'A1001', r'Axis\s+A\d+'],
            'cert_patterns': [r'axis\.com'],
            'confidence': 95,
            'require_product': True,
            'is_multi_function': True  # Also does VSS
        },

        'Axxess Identification': {
            'brand_patterns': [r'\baxxess\s+identification\b', r'\baxxess\b'],
            'product_patterns': [r'\baxxess\s+access\b', r'\baxxess\s+control\b'],
            'model_patterns': [],
            'cert_patterns': [r'axxessid\.'],
            'confidence': 85,
            'require_product': False
        },

        'Bioconnect': {
            'brand_patterns': [r'\bbioconnect\b'],
            'product_patterns': [r'\bbioconnect\s+access\b', r'\bbioconnect\s+id\b'],
            'model_patterns': [],
            'cert_patterns': [r'bioconnect\.'],
            'confidence': 85,
            'require_product': False
        },

        'Bosch': {
            'brand_patterns': [r'\bbosch\b', r'\bbosch\s+security\b'],
            'product_patterns': [r'\bamc\b', r'\baccess\s+management\b', r'\bbosch\s+access\b'],
            'model_patterns': [r'AMC'],
            'cert_patterns': [r'boschsecurity\.com'],
            'confidence': 90,
            'require_product': True,
            'is_multi_function': True  # Also does VSS/IHAS
        },

        'Broadcom': {
            'brand_patterns': [r'\bbroadcom\b', r'\bca\s+technologies\b'],
            'product_patterns': [r'\bca\s+access\b', r'\bbroadcom\s+access\b', r'\bsitemindern'],
            'model_patterns': [r'SiteMinder'],
            'cert_patterns': [r'broadcom\.com', r'ca\.com'],
            'confidence': 85,
            'require_product': True
        },

        'Cisco': {
            'brand_patterns': [r'\bcisco\b'],
            'product_patterns': [r'\bacs\b', r'\bise\b', r'\baccess\s+control\s+server\b'],
            'model_patterns': [r'Cisco\s+ACS', r'Cisco\s+ISE'],
            'cert_patterns': [r'cisco\.com'],
            'confidence': 90,
            'require_product': True
        },

        'CJIS Solutions': {
            'brand_patterns': [r'\bcjis\s+solutions\b', r'\bcjis\b'],
            'product_patterns': [r'\bcjis\s+access\b', r'\bcjis\s+compliance\b'],
            'model_patterns': [],
            'cert_patterns': [r'cjis\.'],
            'confidence': 80,
            'require_product': False
        },

        'Comelit': {
            'brand_patterns': [r'\bcomelit\b'],
            'product_patterns': [r'\bvedo\b', r'\bintercom\b', r'\bcomelit\s+access\b'],
            'model_patterns': [r'Vedo'],
            'cert_patterns': [r'comelitgroup\.com'],
            'confidence': 85,
            'require_product': True
        },

        'Dell Technologies': {
            'brand_patterns': [r'\bdell\b', r'\brsa\s+security\b'],
            'product_patterns': [r'\brsa\s+securid\b', r'\brsa\s+access\b', r'\bsecurid\b'],
            'model_patterns': [r'SecurID'],
            'cert_patterns': [r'dell\.com', r'rsa\.com'],
            'confidence': 90,
            'require_product': True
        },

        'DMP': {
            'brand_patterns': [r'\bdmp\b', r'\bdigital\s+monitoring\b'],
            'product_patterns': [r'\bxt\s+series\b', r'\bdmp\s+access\b', r'\bvirtual\s+keypad\b'],
            'model_patterns': [r'XT\s+\d+'],
            'cert_patterns': [r'dmp\.com'],
            'confidence': 85,
            'require_product': True
        },

        'Dormakaba': {
            'brand_patterns': [r'\bdormakaba\b'],
            'product_patterns': [r'\bsaflok\b', r'\boracode\b', r'\bdormakaba\s+access\b'],
            'model_patterns': [r'Saflok', r'Oracode'],
            'cert_patterns': [r'dormakaba\.com'],
            'confidence': 95,
            'require_product': True
        },

        'Fujitsu': {
            'brand_patterns': [r'\bfujitsu\b'],
            'product_patterns': [r'\bpalmsecure\b', r'\bfujitsu\s+access\b', r'\bbiometric\b'],
            'model_patterns': [r'PalmSecure'],
            'cert_patterns': [r'fujitsu\.com'],
            'confidence': 85,
            'require_product': True
        },

        'Gallagher': {
            'brand_patterns': [r'\bgallagher\b'],
            'product_patterns': [r'\bcommand\s+centre\b', r'\bgallagher\s+access\b', r'\bcommand\b'],
            'model_patterns': [r'Command\s+Centre'],
            'cert_patterns': [r'gallaghersecurity\.com'],
            'confidence': 95,
            'require_product': True
        },

        'ICT': {
            'brand_patterns': [r'\bict\b', r'\bict\s+protege\b'],
            'product_patterns': [r'\bprotege\s+wx\b', r'\bprotege\s+gx\b', r'\bprotege\b'],
            'model_patterns': [r'Protege\s+[WG]X'],
            'cert_patterns': [r'ict\.co'],
            'confidence': 90,
            'require_product': True
        },

        'Idemia': {
            'brand_patterns': [r'\bidemia\b'],
            'product_patterns': [r'\bmorphowave\b', r'\bmorphoaccess\b', r'\bidemia\s+access\b'],
            'model_patterns': [r'MorphoWave', r'MorphoAccess'],
            'cert_patterns': [r'idemia\.com'],
            'confidence': 95,
            'require_product': True
        },

        'Identiv': {
            'brand_patterns': [r'\bidentiv\b', r'\bhirsch\b'],
            'product_patterns': [r'\bhirsch\s+velocity\b', r'\bvelocity\b', r'\bidentiv\s+access\b'],
            'model_patterns': [r'Velocity'],
            'cert_patterns': [r'identiv\.com'],
            'confidence': 90,
            'require_product': True
        },

        'Johnson Controls': {
            'brand_patterns': [r'\bjohnson\s+controls\b', r'\btyco\b'],
            'product_patterns': [r'\bmetasys\b', r'\bc-cure\b', r'\bverasys\b', r'\btyco\s+access\b'],
            'model_patterns': [r'Metasys', r'C-CURE'],
            'cert_patterns': [r'johnsoncontrols\.com', r'tyco\.com'],
            'confidence': 95,
            'require_product': True,
            'is_multi_function': True,
            'is_bas': True
        },

        'Lucky Technology': {
            'brand_patterns': [r'\blucky\s+technology\b'],
            'product_patterns': [r'\biguard\b', r'\blucky\s+access\b'],
            'model_patterns': [r'iGuard'],
            'cert_patterns': [r'luckytech\.'],
            'confidence': 80,
            'require_product': True
        },

        'Lumidigm': {
            'brand_patterns': [r'\blumidigm\b'],
            'product_patterns': [r'\blumidigm\s+biometric\b', r'\bmulti-spectral\b'],
            'model_patterns': [],
            'cert_patterns': [r'lumidigm\.', r'hidglobal\.com'],
            'confidence': 85,
            'require_product': False  # Now part of HID
        },

        'Lupusec': {
            'brand_patterns': [r'\blupusec\b', r'\blupus\b'],
            'product_patterns': [r'\bxt\s+\d+\b', r'\blupusec\s+access\b'],
            'model_patterns': [r'XT\s+\d+'],
            'cert_patterns': [r'lupus-electronics\.'],
            'confidence': 85,
            'require_product': True
        },

        'Mercury': {
            'brand_patterns': [r'\bmercury\b', r'\bmercury\s+security\b'],
            'product_patterns': [r'\blp\s*\d+\b', r'\bmercury\s+panel\b', r'\bmercury\s+controller\b'],
            'model_patterns': [r'LP\d+'],
            'cert_patterns': [r'mercurysecurity\.com'],
            'confidence': 90,
            'require_product': True
        },

        'NetMotion': {
            'brand_patterns': [r'\bnetmotion\b'],
            'product_patterns': [r'\bnetmotion\s+mobility\b', r'\bnetmotion\s+wireless\b'],
            'model_patterns': [],
            'cert_patterns': [r'netmotionwireless\.com'],
            'confidence': 80,
            'require_product': False
        },

        'Open Path': {
            'brand_patterns': [r'\bopenpath\b', r'\bopen\s+path\b'],
            'product_patterns': [r'\balto\b', r'\bopenpath\s+access\b', r'\bwireless\s+access\b'],
            'model_patterns': [r'Alto'],
            'cert_patterns': [r'openpath\.com'],
            'confidence': 90,
            'require_product': True
        },

        'Panasonic': {
            'brand_patterns': [r'\bpanasonic\b'],
            'product_patterns': [r'\barbitrator\b', r'\bpanasonic\s+access\b', r'\bpanasonic\s+control\b'],
            'model_patterns': [r'Arbitrator'],
            'cert_patterns': [r'panasonic\.com'],
            'confidence': 85,
            'require_product': True,
            'is_multi_function': True
        },

        'Pistolstar': {
            'brand_patterns': [r'\bpistolstar\b'],
            'product_patterns': [r'\bpistolstar\s+access\b', r'\bpistolstar\s+id\b'],
            'model_patterns': [],
            'cert_patterns': [r'pistolstar\.'],
            'confidence': 80,
            'require_product': False
        },

        'Safran': {
            'brand_patterns': [r'\bsafran\b'],
            'product_patterns': [r'\bsafran\s+identity\b', r'\bmorpho\b', r'\bsafran\s+access\b'],
            'model_patterns': [r'Morpho'],
            'cert_patterns': [r'safran-group\.com'],
            'confidence': 85,
            'require_product': True
        },

        'Schneider Electric': {
            'brand_patterns': [r'\bschneider\b', r'\bschneider\s+electric\b'],
            'product_patterns': [r'\bstruxureware\b', r'\becostru xure\b', r'\bpowerscada\b'],
            'model_patterns': [r'StruxureWare', r'EcoStruxure'],
            'cert_patterns': [r'se\.com', r'schneider-electric\.com'],
            'confidence': 90,
            'require_product': True,
            'is_bas': True
        },

        'SecureAuth': {
            'brand_patterns': [r'\bsecureauth\b'],
            'product_patterns': [r'\bsecureauth\s+idaas\b', r'\bsecureauth\s+identity\b'],
            'model_patterns': [],
            'cert_patterns': [r'secureauth\.com'],
            'confidence': 85,
            'require_product': False
        },

        'Securenvoy': {
            'brand_patterns': [r'\bsecurenvoy\b', r'\bshearwater\b'],
            'product_patterns': [r'\bsecurenvoy\s+access\b', r'\bmfa\b'],
            'model_patterns': [],
            'cert_patterns': [r'securenvoy\.'],
            'confidence': 80,
            'require_product': False
        },

        'Siemens': {
            'brand_patterns': [r'\bsiemens\b'],
            'product_patterns': [r'\bdesigo\b', r'\bapogee\b', r'\binsight\b', r'\bsiveillance\b'],
            'model_patterns': [r'Desigo', r'Apogee'],
            'cert_patterns': [r'siemens\.com'],
            'confidence': 90,
            'require_product': True,
            'is_bas': True
        },

        'Software House': {
            'brand_patterns': [r'\bsoftware\s+house\b'],
            'product_patterns': [r'\bccure\b', r'\bc-cure\b', r'\bsoftware\s+house\s+access\b'],
            'model_patterns': [r'C-CURE'],
            'cert_patterns': [r'swhouse\.com'],
            'confidence': 95,
            'require_product': True
        },

        'Stanley': {
            'brand_patterns': [r'\bstanley\b', r'\bstanley\s+security\b'],
            'product_patterns': [r'\bstanley\s+access\b', r'\bstanley\s+control\b', r'\bpac\s+\d+\b'],
            'model_patterns': [r'PAC\s+\d+'],
            'cert_patterns': [r'stanley\.'],
            'confidence': 85,
            'require_product': True
        },

        'Thales': {
            'brand_patterns': [r'\bthales\b', r'\bgemalto\b'],
            'product_patterns': [r'\bgemalto\b', r'\bthales\s+access\b', r'\bsafeNet\b'],
            'model_patterns': [r'SafeNet', r'Gemalto'],
            'cert_patterns': [r'thalesgroup\.com', r'gemalto\.com'],
            'confidence': 90,
            'require_product': True
        },

        'TKH Security': {
            'brand_patterns': [r'\btkh\b', r'\btkh\s+security\b'],
            'product_patterns': [r'\bkeyprocessor\b', r'\btkh\s+access\b'],
            'model_patterns': [r'Keyprocessor'],
            'cert_patterns': [r'tkhsecurity\.'],
            'confidence': 85,
            'require_product': True
        },

        'Validsoft': {
            'brand_patterns': [r'\bvalidsoft\b'],
            'product_patterns': [r'\bvalidsoft\s+access\b', r'\bval\s+id\b'],
            'model_patterns': [],
            'cert_patterns': [r'validsoft\.'],
            'confidence': 80,
            'require_product': False
        },

        'Vanderbilt': {
            'brand_patterns': [r'\bvanderbilt\b'],
            'product_patterns': [r'\bspc\b', r'\bspc\s+\d+\b', r'\bsipass\b'],
            'model_patterns': [r'SPC\s+\d+', r'SiPass'],
            'cert_patterns': [r'vanderbiltindustries\.com'],
            'confidence': 95,
            'require_product': True,
            'is_multi_function': True  # Also does IHAS
        },

        'Verex': {
            'brand_patterns': [r'\bverex\b'],
            'product_patterns': [r'\bverex\s+access\b', r'\bverex\s+control\b'],
            'model_patterns': [],
            'cert_patterns': [r'verex\.'],
            'confidence': 80,
            'require_product': False
        },

        'WideBand': {
            'brand_patterns': [r'\bwideband\b'],
            'product_patterns': [r'\bwideband\s+access\b', r'\bwideband\s+mobile\b'],
            'model_patterns': [],
            'cert_patterns': [r'widebandcorp\.com'],
            'confidence': 80,
            'require_product': False
        },

        'Zenitel': {
            'brand_patterns': [r'\bzenitel\b'],
            'product_patterns': [r'\bzenitel\s+access\b', r'\bintercom\b', r'\bstentofon\b'],
            'model_patterns': [r'Stentofon'],
            'cert_patterns': [r'zenitel\.com'],
            'confidence': 85,
            'require_product': True,
            'is_multi_function': True  # Also does VSS/IHAS
        },
    },

    # Enhancement: Industrial/Building Automation Protocols
    'industrial_protocols': {
        # BACnet - Building Automation and Control networks
        'bacnet': {
            'port': 47808,
            'banner_patterns': [
                r'\bbacnet\b', r'building\s+automation',
                r'bacnet/ip', r'bac0'
            ],
            'confidence': 100,
            'subcategory': 'BAS',
            'protocol_bonus': 15,  # Strong BAS indicator
        },

        # Modbus - Industrial protocol (SCADA)
        'modbus': {
            'port': 502,
            'banner_patterns': [
                r'\bmodbus\b', r'modbus\s+tcp'
            ],
            'confidence': 95,
            'subcategory': 'BAS',
            'protocol_bonus': 12,
        },

        # OPC-UA - OPC Unified Architecture
        'opc_ua': {
            'port': 4840,
            'banner_patterns': [
                r'\bopc\b', r'opc-ua', r'opcua',
                r'opc\s+unified', r'opc\s+foundation'
            ],
            'confidence': 100,
            'subcategory': 'BAS',
            'protocol_bonus': 15,
        },

        # KNX - Building automation standard
        'knx': {
            'port': 3671,
            'banner_patterns': [
                r'\bknx\b', r'knxnet', r'knx/ip'
            ],
            'confidence': 100,
            'subcategory': 'BAS',
            'protocol_bonus': 15,
        },

        # LON - Local Operating Network
        'lon': {
            'banner_patterns': [
                r'\blon\b', r'lonworks', r'local\s+operating\s+network'
            ],
            'confidence': 95,
            'subcategory': 'BAS',
            'protocol_bonus': 12,
        },
    },

    # Enhanced exclusions
    'exclusions': {
        'web_hosting': [
            r'\bwordpress\b', r'\bjoomla\b', r'\bdrupal\b',
            r'\bcpanel\b', r'\bplesk\b', r'\bwhm\b',
        ],
        'cloud_providers': [
            r'\bcloudflare\b', r'\bamazon\s+(?:web\s+services|aws)\b',
            r'\bmicrosoft\s+azure\b', r'\bgoogle\s+cloud\b',
            r'\bsalesforce\b', r'\bheroku\b',
        ],
        'generic_terms': [
            r'\btest\s+(?:access|control)\b',
            r'\bdemo\s+(?:access|control)\b',
            r'\bgeneric\s+access\b',
        ],
    },
}

# ========================================
#  Industrial Protocol Detection Function
# ========================================

def detect_industrial_protocols(row):
    """
    Q1 Enhancement: Detect industrial/BAS protocols
    Returns: (detected_protocols: list, is_bas: bool, confidence: int, bonus: int)
    """
    detected = []
    is_bas = False
    max_confidence = 0
    total_bonus = 0

    port = row.get('service.port', 0)
    banner = str(row.get('service.banner', '')).lower()
    http_body = str(row.get('service.http.body', '')).lower()

    searchable = f"{banner} {http_body}"

    protocols = EACS_ENHANCED_CONFIG.get('industrial_protocols', {})

    for protocol_name, protocol_config in protocols.items():
        matched = False

        # Check port match
        if 'port' in protocol_config and port == protocol_config['port']:
            matched = True

        # Check banner patterns
        if 'banner_patterns' in protocol_config:
            for pattern in protocol_config['banner_patterns']:
                if re.search(pattern, searchable, re.IGNORECASE):
                    matched = True
                    break

        if matched:
            detected.append(protocol_name)
            max_confidence = max(max_confidence, protocol_config.get('confidence', 0))
            total_bonus += protocol_config.get('protocol_bonus', 0)

            # Check if BAS subcategory
            if protocol_config.get('subcategory') == 'BAS':
                is_bas = True

    return detected, is_bas, max_confidence, total_bonus


# ========================================
# DETECTION FUNCTION
# ========================================
def identify_eacs_enhanced(row):
    """
    Comprehensive EACS identification with all 51 brands
    Now accumulates ALL matching indicators for complete audit trail
    """

    result = {
        'is_eacs': False,
        'is_bas': False,
        'eacs_confidence': 0,
        'detected_brand': None,
        'detected_product': None,
        'eacs_reason': None,
        'match_field': None,
        'match_pattern': None,
        'match_value': None,
    }

    # NEW: List to accumulate all matching indicators
    reasons = []
    match_details = []

    # Extract fields safely
    def safe_str(field):
        val = row.get(field, '')
        return str(val).lower() if pd.notna(val) else ''

    fields = {
        'title': safe_str('service.http.title') or safe_str('http.html_title'),
        'body': safe_str('service.http.body'),
        'http_path': safe_str('service.http.path') or safe_str('http.path'),
        'headers': safe_str('service.http.headers') or safe_str('http.headers'),
        'banner': safe_str('service.banner'),
        'product_b': safe_str('service.fingerprints.os.product'),
        'product_a': safe_str('service.fingerprints.service.product'),
        'tags': safe_str('service.fingerprints.tags'),
        'cert_issuer': (safe_str('service.tls.issuer.common_name') or
                        safe_str('service.tls.issuer') or
                        safe_str('ssl.cert.issuer')),
        'cert_subject': (safe_str('service.tls.subject.common_name') or
                         safe_str('service.tls.subject') or
                         safe_str('ssl.cert.subject')),
    }

    # Create combined text - limit body to avoid memory issues
    body_snippet = fields['body'][:5000] if fields['body'] else ''
    all_text = ' '.join([
        fields['title'],
        fields['banner'],
        fields['product_a'],
        fields['product_b'],
        fields['http_path'],
        fields['headers'],
        body_snippet,
        fields['cert_issuer'],
        fields['cert_subject'],
        fields['tags']
    ])

    # STEP 1: EXCLUSIONS (still returns early)
    for category, patterns in EACS_ENHANCED_CONFIG['exclusions'].items():
        for pattern in patterns:
            if re.search(pattern, all_text, re.IGNORECASE):
                result['eacs_reason'] = f"EXCLUDED:{category}"
                return result

    # Track highest confidence and primary brand
    max_confidence = 0
    primary_brand = None
    primary_product = None

    # STEP 2: TAG DETECTION
    for tag in EACS_ENHANCED_CONFIG['tags']:
        if tag.lower() in fields['tags']:
            result['is_eacs'] = True
            reasons.append(f"tag:{tag}")
            max_confidence = max(max_confidence, 70)
            if 'building automation' in tag.lower():
                result['is_bas'] = True

    # STEP 3: HTTP PATH DETECTION
    for brand, paths in EACS_ENHANCED_CONFIG['http_paths'].items():
        for path in paths:
            found_in_path = fields['http_path'] and path in fields['http_path']
            found_in_body = False

            if not found_in_path and fields['body']:
                body_search = fields['body'][:10000]
                if (path in body_search or
                        f'href="{path}' in body_search or
                        f'src="{path}' in body_search):
                    found_in_body = True

            if (found_in_path or found_in_body) and brand.lower() in all_text:
                result['is_eacs'] = True
                path_confidence = 90 if found_in_path else 85
                reasons.append(f"http_path:{path}")
                reasons.append(f"brand:{brand}")
                
                if path_confidence > max_confidence:
                    max_confidence = path_confidence
                    primary_brand = brand
                    result['match_field'] = 'http_path' if found_in_path else 'body'
                    result['match_pattern'] = path

    # STEP 4: PROTOCOL DETECTION
    port = row.get('service.port', 0)
    for proto_name, proto_config in EACS_ENHANCED_CONFIG['protocols'].items():
        if 'ports' in proto_config and port in proto_config['ports']:
            for pattern in proto_config['banner_patterns']:
                match = re.search(pattern, all_text, re.IGNORECASE)
                if match:
                    result['is_eacs'] = True
                    reasons.append(f"protocol:{proto_name}")
                    reasons.append(f"port:{port}")
                    proto_confidence = proto_config['confidence']
                    
                    if proto_confidence > max_confidence:
                        max_confidence = proto_confidence
                        result['match_field'] = 'service.banner+port'
                        result['match_pattern'] = pattern
                    
                    if proto_config.get('context') == 'BAS':
                        result['is_bas'] = True

    # STEP 5: BRAND + PRODUCT DETECTION
    for brand, brand_config in EACS_ENHANCED_CONFIG['brands'].items():
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

        # Add brand to reasons
        reasons.append(f"brand:{brand}")
        
        # Check if product required
        if brand_config.get('require_product', False):
            product_found = False
            product_match = None
            product_field = None

            for pattern in brand_config['product_patterns']:
                for field_name, field_value in fields.items():
                    match = re.search(pattern, field_value, re.IGNORECASE)
                    if match:
                        product_found = True
                        product_match = match.group()
                        product_field = field_name
                        break
                if product_found:
                    break

            if product_found:
                result['is_eacs'] = True
                reasons.append(f"product:{product_match}")
                brand_confidence = brand_config['confidence']
                
                if brand_confidence > max_confidence:
                    max_confidence = brand_confidence
                    primary_brand = brand
                    primary_product = product_match
                    result['match_field'] = f"{brand_field}+{product_field}"

                if brand_config.get('is_bas', False):
                    result['is_bas'] = True
        else:
            # Brand alone is sufficient
            result['is_eacs'] = True
            brand_confidence = brand_config['confidence']
            
            if brand_confidence > max_confidence:
                max_confidence = brand_confidence
                primary_brand = brand
                result['match_field'] = brand_field

            if brand_config.get('is_bas', False):
                result['is_bas'] = True

    # ========================================
    # INDUSTRIAL/BAS PROTOCOL DETECTION
    # ========================================
    detection_methods = []
    if result['is_eacs']:
        detection_methods.append('brand_match')

    # Enhancement: Check for industrial/BAS protocols
    industrial_protocols, is_bas_device, industrial_conf, industrial_bonus = detect_industrial_protocols(row)

    if industrial_protocols:
        detection_methods.append('industrial_protocol')
        for proto in industrial_protocols:
            reasons.append(f"industrial_protocol:{proto}")
        
        max_confidence = max(max_confidence, industrial_conf)
        result['is_eacs'] = True
        result['protocols_detected'] = industrial_protocols

        # Mark as BAS if detected
        if is_bas_device:
            result['is_bas'] = True
            detection_methods.append('BAS_protocol')

    # ========================================
    # FINALIZE RESULTS
    # ========================================
    if result['is_eacs']:
        # Set primary brand and product
        result['detected_brand'] = primary_brand
        result['detected_product'] = primary_product
        
        # Enhanced confidence calculation
        final_confidence, confidence_bonuses = calculate_enhanced_confidence(
            row=row,
            base_confidence=max_confidence,
            brand=primary_brand,
            category='EACS',
            detection_methods=detection_methods
        )

        result['eacs_confidence'] = final_confidence
        result['confidence_bonuses'] = confidence_bonuses
        result['detection_methods'] = detection_methods
        
        # Combine all reasons into pipe-separated string
        # Remove duplicates while preserving order
        unique_reasons = []
        for r in reasons:
            if r not in unique_reasons:
                unique_reasons.append(r)
        
        result['eacs_reason'] = '|'.join(unique_reasons) if unique_reasons else None

    return result


print("Comprehensive EACS detection loaded")
print("")
