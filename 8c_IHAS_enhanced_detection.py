#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
COMPREHENSIVE I&HAS DETECTION - ALL 27 BRANDS
==============================================

Includes ALL brands from the requirement list.
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
# COMPREHENSIVE I&HAS CONFIGURATION
# ========================================

IHAS_ENHANCED_CONFIG = {

    'http_paths': {
        'AJAX': ['/ajax-security/', '/ajax/systems', '/ajaxsystems/'],
        'Vanderbilt': ['/spc/', '/spc-connect', '/sipass/'],
        'Honeywell': ['/galaxy/', '/dimension/', '/prowatch/', '/vista-'],
        'Bosch': ['/bpa/', '/b-series/', '/solution-', '/radion/'],
        'Hikvision': ['/ax-pro/', '/ax-hub/'],
        'Texecom': ['/premier/', '/texecom/', '/connect-'],
        'Pyronix': ['/enforcer/', '/pyronix/', '/homecontrol/'],
        'DSC': ['/neo/', '/powerseries/', '/pc-link/'],
        'Paradox': ['/evo/', '/magellan/', '/spectra/'],
        'Risco': ['/lightsys/', '/agility/'],
        'Jablotron': ['/jablotron/', '/oasis/'],
        'Satel': ['/integra/', '/versa/'],
        'Genetec': ['/synergis/', '/intrusion/'],
        'Aritech': ['/aritech/', '/advisor/'],
        'Axis': ['/axis-acc/', '/a1601/'],
        'Verisure': ['/verisure/', '/securitas/'],
        'Chubb': ['/chubb/', '/guard/'],
        'Blaupunkt': ['/blaupunkt/', '/q-series/'],
        'BTicino': ['/bticino/', '/legrand/'],
        'Abus': ['/secvest/', '/terxon/', '/secoris/'],
    },

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
                r'contact\s+id', r'contact-id', r'ademco\s+contact',
            ],
            'confidence': 95,
            'require_banner': True
        },
    },

    # IoT Protocols for modern alarm systems
    'iot_protocols': {
        # MQTT - Message Queue Telemetry Transport
        'mqtt': {
            'port': 1883,
            'banner_patterns': [
                r'\bmqtt\b', r'mosquitto', r'mqtt\s+broker',
                r'hivemq', r'emqx'
            ],
            'confidence': 85,  # Lower - also used by other IoT
            'protocol_bonus': 8,
        },

        # CoAP - Constrained Application Protocol
        'coap': {
            'port': 5683,
            'banner_patterns': [
                r'\bcoap\b', r'constrained\s+application',
                r'coap://'
            ],
            'confidence': 80,
            'protocol_bonus': 8,
        },
    },

    # Enhancement: Specific alarm protocols
    'alarm_protocols': {
        # SIA DC-09 - Security Industry Association protocol
        'sia_dc09': {
            'banner_patterns': [
                r'sia\s+dc-?09', r'sia\s+dc\s+09', r'\bdc-?09\b',
                r'sia\s+protocol', r'sia\s+level'
            ],
            'confidence': 100,
            'protocol_bonus': 15,  # Strong IHAS indicator
        },

        # Contact ID - Ademco Contact ID protocol
        'contact_id': {
            'banner_patterns': [
                r'contact\s+id', r'contactid', r'cid\s+protocol',
                r'ademco\s+contact'
            ],
            'confidence': 100,
            'protocol_bonus': 15,
        },

        # SIA IP - SIA IP Protocol
        'sia_ip': {
            'banner_patterns': [
                r'sia\s+ip', r'sia-ip', r'sia\s+encryption'
            ],
            'confidence': 100,
            'protocol_bonus': 15,
        },
    },

    'brands': {
        # ========== TIER 1: MAJOR BRANDS ==========

        'AJAX': {
            'brand_patterns': [r'\bajax\s+systems\b', r'\bajax-systems\b'],
            'product_patterns': [
                r'\bhub\s+(?:2|plus|2\s+plus)\b', r'\bajax\s+hub\b',
                r'\bajax\s+(?:security|alarm)\b'
            ],
            'model_patterns': [r'Hub\s+(?:2|Plus)', r'Ajax\s+Hub'],
            'cert_patterns': [r'ajax\.systems'],
            'confidence': 100,
            'require_product': True
        },

        'Dahua': {
            'brand_patterns': [r'\bdahua\b'],
            'product_patterns': [
                r'\balarm\b', r'\barf\w+\b', r'\bintrusion\b',
                r'\bdahua\s+(?:alarm|security)\b'
            ],
            'model_patterns': [r'ARF\w+'],
            'cert_patterns': [r'dahuasecurity\.com'],
            'confidence': 90,
            'require_product': True,
            'is_multi_function': True
        },

        'Hikvision': {
            'brand_patterns': [r'\bhikvision\b'],
            'product_patterns': [
                r'\bax\s+pro\b', r'\bax-pro\b', r'\bax\s+hub\b',
                r'\bhikvision\s+alarm\b'
            ],
            'model_patterns': [r'AX\s+PRO', r'AX\s+Hub'],
            'cert_patterns': [r'hikvision\.com'],
            'confidence': 90,
            'require_product': True,
            'is_multi_function': True
        },

        'Vanderbilt': {
            'brand_patterns': [r'\bvanderbilt\b'],
            'product_patterns': [
                r'\bspc\s*(?:4|5|6|53|43)00\b', r'\bspc\b',
                r'\bsipass\b', r'\bvanderbilt\s+spc\b'
            ],
            'model_patterns': [r'SPC\s+\d+', r'SiPass'],
            'cert_patterns': [r'vanderbiltindustries\.com'],
            'confidence': 100,
            'require_product': True,
            'is_multi_function': True
        },

        'Lenel': {
            'brand_patterns': [r'\blenel\b', r'\blenels2\b'],
            'product_patterns': [
                r'\blenel\s+(?:intrusion|alarm)\b', r'\bonguard\s+intrusion\b'
            ],
            'model_patterns': [],
            'cert_patterns': [r'lenel\.com'],
            'confidence': 85,
            'require_product': True,
            'is_multi_function': True
        },

        'Risco': {
            'brand_patterns': [r'\brisco\b'],
            'product_patterns': [
                r'\blightsys\b', r'\bagility\b', r'\brisco\s+(?:lightsys|agility)\b'
            ],
            'model_patterns': [r'LightSYS', r'Agility'],
            'cert_patterns': [r'riscogroup\.com'],
            'confidence': 100,
            'require_product': True
        },

        'Jablotron': {
            'brand_patterns': [r'\bjablotron\b'],
            'product_patterns': [
                r'\boasis\b', r'\b100\s*\+?\b', r'\bjablotron\s+(?:100|alarm)\b'
            ],
            'model_patterns': [r'Oasis', r'JA-1\d+'],
            'cert_patterns': [r'jablotron\.com'],
            'confidence': 95,
            'require_product': True
        },

        'Satel': {
            'brand_patterns': [r'\bsatel\b'],
            'product_patterns': [
                r'\bintegra\b', r'\bversa\b', r'\bsatel\s+(?:integra|versa)\b'
            ],
            'model_patterns': [r'Integra', r'Versa'],
            'cert_patterns': [r'satel\.'],
            'confidence': 95,
            'require_product': True
        },

        'Honeywell': {
            'brand_patterns': [r'\bhoneywell\b'],
            'product_patterns': [
                r'\bgalaxy\b', r'\bdimension\b', r'\bvista\b',
                r'\bprowatch\b', r'\bhoneywell\s+(?:galaxy|alarm)\b'
            ],
            'model_patterns': [r'Galaxy', r'Vista\s+\d+'],
            'cert_patterns': [r'honeywellsecurity\.com'],
            'confidence': 95,
            'require_product': True,
            'is_multi_function': True
        },

        'Bosch': {
            'brand_patterns': [r'\bbosch\b', r'\bbosch\s+security\b'],
            'product_patterns': [
                r'\bsolution\s+\d+\b', r'\bb-series\b', r'\bradion\b',
                r'\bbosch\s+(?:alarm|intrusion)\b'
            ],
            'model_patterns': [r'Solution\s+\d+', r'B\s+Series', r'Radion'],
            'cert_patterns': [r'boschsecurity\.com'],
            'confidence': 95,
            'require_product': True,
            'is_multi_function': True
        },

        'Texecom': {
            'brand_patterns': [r'\btexecom\b'],
            'product_patterns': [
                r'\bpremier\s+(?:elite|48|88|168|640)\b',
                r'\bpremier\b.*\belite\b', r'\btexecom\s+connect\b'
            ],
            'model_patterns': [r'Premier\s+Elite', r'Premier\s+\d+'],
            'cert_patterns': [r'texe\.com'],
            'confidence': 100,
            'require_product': True
        },

        'Pyronix': {
            'brand_patterns': [r'\bpyronix\b'],
            'product_patterns': [
                r'\benforcer\b', r'\bhomecontrol\b', r'\bpyronix\s+(?:enforcer|cloud)\b'
            ],
            'model_patterns': [r'Enforcer'],
            'cert_patterns': [r'pyronix\.com'],
            'confidence': 100,
            'require_product': True
        },

        'DSC': {
            'brand_patterns': [r'\bdsc\b', r'\bdigital\s+security\s+controls\b'],
            'product_patterns': [
                r'\bneo\b', r'\bpowerseries\b', r'\bpc\s+link\b',
                r'\bdsc\s+(?:neo|powerseries)\b'
            ],
            'model_patterns': [r'PowerSeries', r'NEO'],
            'cert_patterns': [r'dsc\.com'],
            'confidence': 95,
            'require_product': True
        },

        'Paradox': {
            'brand_patterns': [r'\bparadox\b'],
            'product_patterns': [
                r'\bevo\s+(?:hd|192)\b', r'\bmagellan\b',
                r'\bspectra\b', r'\bparadox\s+(?:evo|magellan)\b'
            ],
            'model_patterns': [r'EVO\s+(?:HD|192)', r'Magellan', r'Spectra'],
            'cert_patterns': [r'paradox\.com'],
            'confidence': 95,
            'require_product': True
        },

        # ========== TIER 2: ESTABLISHED BRANDS ==========

        'Abus': {
            'brand_patterns': [r'\babus\b'],
            'product_patterns': [
                r'\bsecvest\b', r'\bterxon\b', r'\bsecoris\b',
                r'\babus\s+(?:alarm|security)\b'
            ],
            'model_patterns': [r'Secvest', r'Terxon', r'Secoris'],
            'cert_patterns': [r'abus\.com'],
            'confidence': 90,
            'require_product': True,
            'is_multi_function': True
        },

        'Acre Intrusion': {
            'brand_patterns': [r'\bacre\b', r'\bacre\s+intrusion\b'],
            'product_patterns': [r'\bacre\s+(?:alarm|intrusion)\b'],
            'model_patterns': [],
            'cert_patterns': [r'acre\.'],
            'confidence': 80,
            'require_product': False
        },

        'Alphatronics': {
            'brand_patterns': [r'\balphatronics\b'],
            'product_patterns': [r'\balphatronics\s+(?:alarm|intrusion)\b'],
            'model_patterns': [],
            'cert_patterns': [r'alphatronics\.'],
            'confidence': 80,
            'require_product': False
        },

        'Aritech': {
            'brand_patterns': [r'\baritech\b'],
            'product_patterns': [
                r'\badvisor\b', r'\bcs\s+\d+\b', r'\baritech\s+alarm\b'
            ],
            'model_patterns': [r'Advisor', r'CS\s+\d+'],
            'cert_patterns': [r'aritech\.'],
            'confidence': 85,
            'require_product': True
        },

        'Axis': {
            'brand_patterns': [r'\baxis\b', r'\baxis\s+communications\b'],
            'product_patterns': [
                r'\baxis\s+acc\b', r'\ba1601\b', r'\baxis\s+alarm\b'
            ],
            'model_patterns': [r'A1601', r'Axis\s+ACC'],
            'cert_patterns': [r'axis\.com'],
            'confidence': 85,
            'require_product': True,
            'is_multi_function': True
        },

        'Blaupunkt': {
            'brand_patterns': [r'\bblaupunkt\b'],
            'product_patterns': [
                r'\bq-series\b', r'\bsa\s+\d+\b', r'\bblaupunkt\s+alarm\b'
            ],
            'model_patterns': [r'Q-Series', r'SA\s+\d+'],
            'cert_patterns': [r'blaupunkt\.'],
            'confidence': 85,
            'require_product': True
        },

        'BTicino': {
            'brand_patterns': [r'\bbticino\b', r'\blegrand\b'],
            'product_patterns': [
                r'\bbticino\s+alarm\b', r'\blegrand\s+security\b'
            ],
            'model_patterns': [],
            'cert_patterns': [r'bticino\.', r'legrand\.'],
            'confidence': 80,
            'require_product': True
        },

        'Chubb': {
            'brand_patterns': [r'\bchubb\b'],
            'product_patterns': [
                r'\bchubb\s+(?:alarm|intrusion|guard)\b'
            ],
            'model_patterns': [],
            'cert_patterns': [r'chubbfiresecurity\.com'],
            'confidence': 85,
            'require_product': True
        },

        'Genetec': {
            'brand_patterns': [r'\bgenetec\b'],
            'product_patterns': [
                r'\bsynergis\b.*\bintrusion\b', r'\bgenetec\s+intrusion\b'
            ],
            'model_patterns': [],
            'cert_patterns': [r'genetec\.com'],
            'confidence': 80,
            'require_product': True,
            'is_multi_function': True
        },

        'Integra': {
            'brand_patterns': [r'\bintegra\b'],
            'product_patterns': [r'\bintegra\s+(?:alarm|panel|128)\b'],
            'model_patterns': [r'Integra\s+\d+'],
            'cert_patterns': [],
            'confidence': 75,
            'require_product': True
        },

        'NetworkX': {
            'brand_patterns': [r'\bnetworkx\b', r'\bnetwork\s+x\b'],
            'product_patterns': [r'\bnetworkx\s+alarm\b', r'\bnetworkx\s+intrusion\b'],
            'model_patterns': [],
            'cert_patterns': [r'networkx\.'],
            'confidence': 75,
            'require_product': False
        },

        'Orisec': {
            'brand_patterns': [r'\borisec\b'],
            'product_patterns': [r'\borisec\s+(?:alarm|control)\b'],
            'model_patterns': [],
            'cert_patterns': [r'orisec\.'],
            'confidence': 75,
            'require_product': False
        },

        'Tenor': {
            'brand_patterns': [r'\btenor\b'],
            'product_patterns': [
                r'\bmultipath\s+switch\b', r'\btenor\s+(?:alarm|multipath)\b'
            ],
            'model_patterns': [],
            'cert_patterns': [r'tenor\.'],
            'confidence': 75,
            'require_product': True
        },

        'Unii': {
            'brand_patterns': [r'\bunii\b'],
            'product_patterns': [r'\bunii\s+(?:alarm|security)\b'],
            'model_patterns': [],
            'cert_patterns': [r'unii\.'],
            'confidence': 75,
            'require_product': False
        },

        'Verex': {
            'brand_patterns': [r'\bverex\b'],
            'product_patterns': [r'\bverex\s+(?:alarm|director)\b'],
            'model_patterns': [],
            'cert_patterns': [r'verex\.'],
            'confidence': 80,
            'require_product': False
        },

        'Verisure': {
            'brand_patterns': [r'\bverisure\b', r'\bsecuritas\s+direct\b'],
            'product_patterns': [
                r'\bverisure\s+alarm\b', r'\bsecuritas\s+alarm\b'
            ],
            'model_patterns': [],
            'cert_patterns': [r'verisure\.com'],
            'confidence': 90,
            'require_product': True
        },

        'Versa': {
            'brand_patterns': [r'\bversa\b'],
            'product_patterns': [r'\bversa\s+(?:alarm|panel)\b'],
            'model_patterns': [],
            'cert_patterns': [],
            'confidence': 70,
            'require_product': True
        },

        'Zenitel': {
            'brand_patterns': [r'\bzenitel\b'],
            'product_patterns': [
                r'\bzenitel\s+(?:alarm|security)\b', r'\bturbine\b'
            ],
            'model_patterns': [],
            'cert_patterns': [r'zenitel\.com'],
            'confidence': 80,
            'require_product': True,
            'is_multi_function': True
        },
    },

    'exclusions': {
        'generic_security': [
            r'\bgeneric\s+alarm\b', r'\btest\s+alarm\b',
            r'\balarm\s+clock\b', r'\bfire\s+alarm\b',
            r'\bsmoke\s+(?:alarm|detector)\b',
        ],
        'cloud_services': [
            r'\bcloudflare\b', r'\bamazon\s+aws\b',
            r'\bmicrosoft\s+azure\b', r'\bgoogle\s+cloud\b',
        ],
        'it_security': [
            r'\bids\b.*\bintrusion\s+detection\s+system\b',
            r'\bips\b.*\bintrusion\s+prevention\b',
            r'\bfirewall\b', r'\bsnort\b', r'\bsuricata\b',
        ],
    },
}


# ========================================
# PROTOCOL DETECTION FUNCTION
# ========================================
def detect_ihas_protocols_enhanced(row):
    """
    Q1/Q4 Enhancement: Detect IoT and alarm-specific protocols
    Returns: (iot_protocols: list, alarm_protocols: list, confidence: int, bonus: int)
    """
    iot_detected = []
    alarm_detected = []
    max_confidence = 0
    total_bonus = 0

    port = row.get('service.port', 0)
    banner = str(row.get('service.banner', '')).lower()
    http_body = str(row.get('service.http.body', '')).lower()
    http_title = str(row.get('service.http.title', '')).lower()

    searchable = f"{banner} {http_body} {http_title}"

    # Check IoT protocols
    iot_protocols = IHAS_ENHANCED_CONFIG.get('iot_protocols', {})
    for protocol_name, protocol_config in iot_protocols.items():
        matched = False

        if 'port' in protocol_config and port == protocol_config['port']:
            matched = True

        if 'banner_patterns' in protocol_config:
            for pattern in protocol_config['banner_patterns']:
                if re.search(pattern, searchable, re.IGNORECASE):
                    matched = True
                    break

        if matched:
            iot_detected.append(protocol_name)
            max_confidence = max(max_confidence, protocol_config.get('confidence', 0))
            total_bonus += protocol_config.get('protocol_bonus', 0)

    # Check alarm-specific protocols
    alarm_protocols = IHAS_ENHANCED_CONFIG.get('alarm_protocols', {})
    for protocol_name, protocol_config in alarm_protocols.items():
        if 'banner_patterns' in protocol_config:
            for pattern in protocol_config['banner_patterns']:
                if re.search(pattern, searchable, re.IGNORECASE):
                    alarm_detected.append(protocol_name)
                    max_confidence = max(max_confidence, protocol_config.get('confidence', 0))
                    total_bonus += protocol_config.get('protocol_bonus', 0)
                    break

    return iot_detected, alarm_detected, max_confidence, total_bonus


# ========================================
# DETECTION FUNCTION
# ========================================
def identify_ihas_enhanced(row):
    """
    Comprehensive I&HAS identification with all 27 brands
    Now accumulates ALL matching indicators for complete audit trail
    """

    result = {
        'is_ihas': False,
        'ihas_confidence': 0,
        'detected_brand': None,
        'detected_product': None,
        'ihas_reason': None,
        'match_field': None,
        'match_pattern': None,
        'match_value': None,
    }

    # NEW: List to accumulate all matching indicators
    reasons = []

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
    for category, patterns in IHAS_ENHANCED_CONFIG['exclusions'].items():
        for pattern in patterns:
            if re.search(pattern, all_text, re.IGNORECASE):
                result['ihas_reason'] = f"EXCLUDED:{category}"
                return result

    # Track highest confidence and primary brand
    max_confidence = 0
    primary_brand = None
    primary_product = None

    # STEP 2: HTTP PATH DETECTION
    if fields['http_path']:
        for brand, paths in IHAS_ENHANCED_CONFIG['http_paths'].items():
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
                    result['is_ihas'] = True
                    path_confidence = 90 if found_in_path else 85
                    reasons.append(f"http_path:{path}")
                    reasons.append(f"brand:{brand}")
                    
                    if path_confidence > max_confidence:
                        max_confidence = path_confidence
                        primary_brand = brand
                        result['match_field'] = 'http_path' if found_in_path else 'body'
                        result['match_pattern'] = path

    # STEP 3: PROTOCOL DETECTION
    port = row.get('service.port', 0)
    for proto_name, proto_config in IHAS_ENHANCED_CONFIG['protocols'].items():
        if 'ports' in proto_config and port in proto_config['ports']:
            for pattern in proto_config['banner_patterns']:
                match = re.search(pattern, all_text, re.IGNORECASE)
                if match:
                    result['is_ihas'] = True
                    reasons.append(f"protocol:{proto_name}")
                    reasons.append(f"port:{port}")
                    proto_confidence = proto_config['confidence']
                    
                    if proto_confidence > max_confidence:
                        max_confidence = proto_confidence
                        result['match_field'] = 'service.banner+port'
                        result['match_pattern'] = pattern

    # STEP 4: BRAND + PRODUCT DETECTION
    for brand, brand_config in IHAS_ENHANCED_CONFIG['brands'].items():
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
                result['is_ihas'] = True
                reasons.append(f"product:{product_match}")
                brand_confidence = brand_config['confidence']
                
                if brand_confidence > max_confidence:
                    max_confidence = brand_confidence
                    primary_brand = brand
                    primary_product = product_match
                    result['match_field'] = f"{brand_field}+{product_field}"
        else:
            result['is_ihas'] = True
            brand_confidence = brand_config['confidence']
            
            if brand_confidence > max_confidence:
                max_confidence = brand_confidence
                primary_brand = brand
                result['match_field'] = brand_field

    # ========================================
    # IoT/ALARM PROTOCOL DETECTION
    # ========================================
    detection_methods = []
    if result['is_ihas']:
        detection_methods.append('brand_match')

    # Enhancement: Check for IoT and alarm-specific protocols
    iot_proto, alarm_proto, protocol_conf, protocol_bonus = detect_ihas_protocols_enhanced(row)
    all_protocols = iot_proto + alarm_proto

    if all_protocols:
        detection_methods.append('protocol')
        for proto in all_protocols:
            reasons.append(f"ihas_protocol:{proto}")
        
        max_confidence = max(max_confidence, protocol_conf)
        result['is_ihas'] = True
        result['protocols_detected'] = all_protocols

    # ========================================
    # FINALIZE RESULTS
    # ========================================
    if result['is_ihas']:
        # Set primary brand and product
        result['detected_brand'] = primary_brand
        result['detected_product'] = primary_product
        
        # Enhanced confidence calculation
        final_confidence, confidence_bonuses = calculate_enhanced_confidence(
            row=row,
            base_confidence=max_confidence,
            brand=primary_brand,
            category='IHAS',
            detection_methods=detection_methods
        )

        result['ihas_confidence'] = final_confidence
        result['confidence_bonuses'] = confidence_bonuses
        result['detection_methods'] = detection_methods
        
        # Combine all reasons into pipe-separated string
        # Remove duplicates while preserving order
        unique_reasons = []
        for r in reasons:
            if r not in unique_reasons:
                unique_reasons.append(r)
        
        result['ihas_reason'] = '|'.join(unique_reasons) if unique_reasons else None

    return result


print("Comprehensive I&HAS detection loaded")
print("")
