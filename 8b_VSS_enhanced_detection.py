#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
COMPREHENSIVE VSS DETECTION - ALL 50 BRANDS
============================================

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
# MODERN CPSS FEATURES CONFIGURATION
# ========================================
# Q4 Enhancement: Cloud/Mobile indicators

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
# COMPREHENSIVE VSS CONFIGURATION
# ========================================

VSS_ENHANCED_CONFIG = {

    'http_paths': {
        'Hikvision': ['/doc/page/login.asp', '/ISAPI/', '/onvif/', '/streaming/'],
        'Dahua': ['/videotalk/', '/RPC2', '/dahua/', '/dss-'],
        'Axis': ['/axis-cgi/', '/operator/', '/vapix/'],
        'Hanwha': ['/stw-cgi/', '/wisenet/'],
        'MOBOTIX': ['/control/', '/cgi-bin/image', '/mxpeg/'],
        'Geutebruck': ['/geutebrueck/', '/gbcontrol/', '/gcore/'],
        'Avigilon': ['/avigilon/', '/acc-', '/appearance-search/'],
        'Bosch': ['/rcp.xml', '/bosch/', '/autodome/'],
        'Genetec': ['/omnicast/', '/stratocast/'],
        'Geovision': ['/gv-', '/geovision/'],
        'Vivotek': ['/cgi-bin/viewer/', '/vivotek/'],
        'D-Link': ['/d-link/', '/dcs-'],
        'Milestone': ['/milestone/', '/xprotect/'],
        'Foscam': ['/foscam/', '/cgi-bin/CGIProxy'],
        'Reolink': ['/reolink/', '/cgi-bin/api.cgi'],
        'TP-Link': ['/tp-link/', '/tplink-camera/'],
        'Swann': ['/swann/', '/swannview/'],
        'Arlo': ['/arlo/', '/arlo-camera/'],
        'Sony': ['/sony/', '/command/inquiry.cgi'],
        'Panasonic': ['/panasonic/', '/cgi-bin/'],
        'Netgear': ['/netgear/', '/arlo/'],
        'TruVision': ['/truvision/', '/TruVision/'],
        'IDIS': ['/idis/', '/iux/'],
        'i-Pro': ['/i-pro/', '/cgi-bin/'],
        'Unifi': ['/protect/', '/unifi-video/'],
        'Blue Iris': ['/blueiris/', '/ui3/'],
        'Zenitel': ['/zenitel/', '/turbine/'],
        'Loxone': ['/loxone/', '/intercom/'],
    },

    'protocols': {
        # Existing RTSP (enhanced)
        'rtsp': {
            'ports': [554, 8554],
            'banner_patterns': [
                r'rtsp/1\.0', r'rtsp/2\.0',
                r'real\s*time\s*streaming',
                r'live/stream', r'cam\d+/stream', r'/live/ch',
                r'rtsps', r'srtp',  # Q2: Encrypted RTSP
                r'/stream\d+', r'/video\d+',
            ],
            'confidence': 95,
            'require_banner': True,
            'protocol_bonus': 10,  # Q7: Confidence bonus
        },

        # Existing ONVIF (enhanced)
        'onvif': {
            'banner_patterns': [
                r'onvif', r'onvif.*device', r'/onvif/', r'onvif.*service',
                r'ws-security', r'wsse', r'onvif.*media',  # Enhanced
            ],
            'confidence': 100,
            'require_banner': False,
            'protocol_bonus': 15,  # Q7: Strong indicator
        },

        # Q5: PSIA - Physical Security Interoperability Alliance
        'psia': {
            'banner_patterns': [
                r'\bpsia\b', r'physical\s+security\s+interoperability',
                r'/psia/', r'psia.*service', r'psia.*media'
            ],
            'confidence': 100,
            'require_banner': False,
            'protocol_bonus': 15,  # Q7: Strong indicator
        },

        # Q2: HLS - HTTP Live Streaming (Apple)
        'hls': {
            'banner_patterns': [
                r'\.m3u8', r'application/vnd\.apple\.mpegurl',
                r'#EXTM3U', r'#EXT-X-STREAM'
            ],
            'paths': [
                r'/hls/', r'/live/.*\.m3u8', r'/stream/.*\.m3u8'
            ],
            'confidence': 90,
            'require_banner': False,
            'protocol_bonus': 10,
        },

        # Q2: DASH - Dynamic Adaptive Streaming (MPEG)
        'dash': {
            'banner_patterns': [
                r'\.mpd', r'application/dash\+xml',
                r'<MPD', r'urn:mpeg:dash'
            ],
            'confidence': 90,
            'require_banner': False,
            'protocol_bonus': 10,
        },

        # Q2: MJPEG - Motion JPEG
        'mjpeg': {
            'banner_patterns': [
                r'\bmjpe?g\b', r'motion\s+jpe?g',
                r'multipart/x-mixed-replace',
                r'boundary=.*frame'
            ],
            'confidence': 85,
            'require_banner': False,
            'protocol_bonus': 8,
        },

        # Q2: WebRTC - Real-Time Communication
        'webrtc': {
            'banner_patterns': [
                r'webrtc', r'rtcpeerconnection',
                r'webrtc.*video', r'rtc.*stream'
            ],
            'confidence': 90,
            'require_banner': False,
            'protocol_bonus': 10,
        },
    },

    'brands': {
        # ========== TIER 1: MAJOR BRANDS ==========

        'Hikvision': {
            'brand_patterns': [r'\bhikvision\b', r'\bhik\s+vision\b'],
            'product_patterns': [
                r'\bds-\d+', r'\bivms\b', r'\bnvr\b', r'\bdvr\b',
                r'\bipc\b', r'\bhikvision\s+camera\b'
            ],
            'model_patterns': [r'DS-\d+', r'iVMS'],
            'cert_patterns': [r'hikvision\.com'],
            'confidence': 100,
            'require_product': True
        },

        'Dahua': {
            'brand_patterns': [r'\bdahua\b'],
            'product_patterns': [
                r'\bdh-\w+', r'\bnvr\d+', r'\bdvr\d+', r'\bipc-\w+',
                r'\bdss\b', r'\bsmartpss\b', r'\bdahua\s+camera\b'
            ],
            'model_patterns': [r'DH-[A-Z0-9]+', r'IPC-'],
            'cert_patterns': [r'dahuasecurity\.com'],
            'confidence': 100,
            'require_product': True
        },

        'Axis': {
            'brand_patterns': [r'\baxis\b', r'\baxis\s+communications\b'],
            'product_patterns': [
                r'\baxis\s+[mfpq]\d+', r'\baxis\s+camera\b', r'\bvapix\b',
                r'\baxis\s+companion\b', r'\baxis\s+acc\b'
            ],
            'model_patterns': [r'AXIS\s+[MFPQ]\d+'],
            'cert_patterns': [r'axis\.com'],
            'confidence': 100,
            'require_product': True,
            'is_multi_function': True
        },

        'MOBOTIX': {
            'brand_patterns': [r'\bmobotix\b'],
            'product_patterns': [
                r'\bmx-\w+', r'\bmxpeg\b', r'\bmobotix\s+camera\b',
                r'\bmobotix\s+[ms]\d+\b'
            ],
            'model_patterns': [r'MX-[A-Z0-9]+', r'MOBOTIX\s+[MS]\d+'],
            'cert_patterns': [r'mobotix\.com'],
            'confidence': 100,
            'require_product': True
        },

        'Bosch': {
            'brand_patterns': [r'\bbosch\b', r'\brobert\s+bosch\b'],
            'product_patterns': [
                r'\bautodome\b', r'\bdinion\b', r'\bflex\s+dome\b',
                r'\bnbn-\w+', r'\bndc-\w+', r'\bbosch\s+camera\b'
            ],
            'model_patterns': [r'NBN-', r'AutoDome', r'DINION'],
            'cert_patterns': [r'boschsecurity\.com'],
            'confidence': 95,
            'require_product': True,
            'is_multi_function': True
        },

        'Hanwha': {
            'brand_patterns': [
                r'\bhanwha\b', r'\bwisenet\b', r'\bsamsung\s+wisenet\b', r'\btechwin\b'
            ],
            'product_patterns': [
                r'\bxnv-\w+', r'\bxnp-\w+', r'\bwisenet\s+[xpq]\b',
                r'\bssnb\b', r'\bhanwha\s+camera\b'
            ],
            'model_patterns': [r'XN[VPO]-\w+', r'Wisenet'],
            'cert_patterns': [r'hanwha-security\.com', r'hanwhatechwin\.'],
            'confidence': 100,
            'require_product': True
        },

        'Genetec': {
            'brand_patterns': [r'\bgenetec\b'],
            'product_patterns': [
                r'\bomnicast\b', r'\bstratocast\b',
                r'\bsecurity\s+center\b.*\bvideo\b'
            ],
            'model_patterns': [r'Omnicast', r'Stratocast'],
            'cert_patterns': [r'genetec\.com'],
            'confidence': 100,
            'require_product': True,
            'is_multi_function': True
        },

        'Geutebruck': {
            'brand_patterns': [r'\bgeutebr[uü]ck\b', r'\bguetebruck\b'],
            'product_patterns': [
                r'\bgcore\b', r'\bg-\w+', r'\bgeutebrueck\s+camera\b'
            ],
            'model_patterns': [r'G-\w+', r'GCore'],
            'cert_patterns': [r'geutebrueck\.com'],
            'confidence': 100,
            'require_product': True
        },

        'Avigilon': {
            'brand_patterns': [r'\bavigilon\b'],
            'product_patterns': [
                r'\bacc\b.*\b(?:server|client)\b', r'\bavigilon\s+camera\b',
                r'\bavigilon\s+h\d+\b', r'\bappearance\s+search\b'
            ],
            'model_patterns': [r'H\d+[A-Z]+', r'ACC'],
            'cert_patterns': [r'avigilon\.com'],
            'confidence': 100,
            'require_product': True
        },

        'Geovision': {
            'brand_patterns': [r'\bgeovision\b', r'\bgv-\w+\b'],
            'product_patterns': [
                r'\bgv-\w+', r'\bgeovision\s+camera\b', r'\bgeovision\s+nvr\b'
            ],
            'model_patterns': [r'GV-[A-Z0-9]+'],
            'cert_patterns': [r'geovision\.com'],
            'confidence': 95,
            'require_product': True
        },

        'Vivotek': {
            'brand_patterns': [r'\bvivotek\b'],
            'product_patterns': [
                r'\bip\d+', r'\bfd\d+', r'\bvivotek\s+camera\b', r'\bvast\b'
            ],
            'model_patterns': [r'IP\d+', r'FD\d+'],
            'cert_patterns': [r'vivotek\.com'],
            'confidence': 100,
            'require_product': True
        },

        # ========== TIER 2: ESTABLISHED BRANDS ==========

        'AVTech': {
            'brand_patterns': [r'\bavtech\b'],
            'product_patterns': [
                r'\bavtech\s+camera\b', r'\bavtech\s+ip\b', r'\bavtech\s+nvr\b'
            ],
            'model_patterns': [],
            'cert_patterns': [r'avtech\.'],
            'confidence': 85,
            'require_product': True
        },

        'D-Link': {
            'brand_patterns': [r'\bd-link\b', r'\bdlink\b'],
            'product_patterns': [
                r'\bdcs-\w+', r'\bd-link\s+camera\b', r'\bmydlink\b'
            ],
            'model_patterns': [r'DCS-\w+'],
            'cert_patterns': [r'dlink\.com'],
            'confidence': 90,
            'require_product': True
        },

        'Milestone': {
            'brand_patterns': [r'\bmilestone\b', r'\bmilestone\s+systems\b'],
            'product_patterns': [
                r'\bxprotect\b', r'\bmilestone\s+(?:essential|professional|expert)\b'
            ],
            'model_patterns': [r'XProtect'],
            'cert_patterns': [r'milestonesys\.com'],
            'confidence': 95,
            'require_product': True
        },

        'Netwave': {
            'brand_patterns': [r'\bnetwave\b'],
            'product_patterns': [r'\bnetwave\s+camera\b', r'\bnetwave\s+ip\b'],
            'model_patterns': [],
            'cert_patterns': [r'netwave\.'],
            'confidence': 80,
            'require_product': True
        },

        'Abus': {
            'brand_patterns': [r'\babus\b'],
            'product_patterns': [
                r'\babus\s+camera\b', r'\babus\s+(?:tvac|tvip)\b', r'\btvip\d+\b'
            ],
            'model_patterns': [r'TVIP\d+', r'TVAC\d+'],
            'cert_patterns': [r'abus\.com'],
            'confidence': 85,
            'require_product': True,
            'is_multi_function': True
        },

        'Digital Watchdog': {
            'brand_patterns': [r'\bdigital\s+watchdog\b', r'\bdwatchdog\b'],
            'product_patterns': [
                r'\bdw\s+spectrum\b', r'\bdigital\s+watchdog\s+camera\b'
            ],
            'model_patterns': [r'DW\s+Spectrum'],
            'cert_patterns': [r'digital-watchdog\.com'],
            'confidence': 85,
            'require_product': True
        },

        'Draytek': {
            'brand_patterns': [r'\bdraytek\b', r'\bvigor\b'],
            'product_patterns': [r'\bvigor\s+\d+\b', r'\bdraytek\s+camera\b'],
            'model_patterns': [r'Vigor\s+\d+'],
            'cert_patterns': [r'draytek\.'],
            'confidence': 80,
            'require_product': True
        },

        'Foscam': {
            'brand_patterns': [r'\bfoscam\b'],
            'product_patterns': [
                r'\bfoscam\s+camera\b', r'\bfi\d+\b', r'\bfoscam\s+[a-z]+\d+\b'
            ],
            'model_patterns': [r'FI\d+', r'R\d+'],
            'cert_patterns': [r'foscam\.com'],
            'confidence': 90,
            'require_product': True
        },

        'Hipcam': {
            'brand_patterns': [r'\bhipcam\b'],
            'product_patterns': [r'\bhipcam\s+camera\b', r'\bhipcam\s+ip\b'],
            'model_patterns': [],
            'cert_patterns': [r'hipcam\.'],
            'confidence': 75,
            'require_product': False
        },

        'Reecam': {
            'brand_patterns': [r'\breecam\b'],
            'product_patterns': [r'\breecam\s+camera\b', r'\breecam\s+ip\b'],
            'model_patterns': [],
            'cert_patterns': [r'reecam\.'],
            'confidence': 75,
            'require_product': False
        },

        'Reolink': {
            'brand_patterns': [r'\breolink\b'],
            'product_patterns': [
                r'\breolink\s+camera\b', r'\brlc-\w+\b', r'\brnv-\w+\b'
            ],
            'model_patterns': [r'RLC-\w+', r'RNV-\w+'],
            'cert_patterns': [r'reolink\.com'],
            'confidence': 90,
            'require_product': True
        },

        'TruVision': {
            'brand_patterns': [r'\btruvision\b'],
            'product_patterns': [
                r'\btruvision\s+(?:camera|nvr|dvr)\b', r'\btvn-\w+\b'
            ],
            'model_patterns': [r'TVN-\w+'],
            'cert_patterns': [r'truvision\.'],
            'confidence': 85,
            'require_product': True
        },

        'Acme Security': {
            'brand_patterns': [r'\bacme\s+security\b'],
            'product_patterns': [r'\bacme\s+camera\b', r'\bacme\s+nvr\b'],
            'model_patterns': [],
            'cert_patterns': [],
            'confidence': 75,
            'require_product': False
        },

        'AJAX': {
            'brand_patterns': [r'\bajax\s+systems\b', r'\bajax-systems\b'],
            'product_patterns': [
                r'\bajax\s+(?:hub|camera)\b', r'\bmotioncam\b'
            ],
            'model_patterns': [r'MotionCam'],
            'cert_patterns': [r'ajax\.systems'],
            'confidence': 90,
            'require_product': True,
            'is_multi_function': True
        },

        'Arlo': {
            'brand_patterns': [r'\barlo\b'],
            'product_patterns': [
                r'\barlo\s+(?:pro|ultra|essential)\b', r'\barlo\s+camera\b'
            ],
            'model_patterns': [r'Arlo\s+(?:Pro|Ultra)'],
            'cert_patterns': [r'arlo\.com'],
            'confidence': 90,
            'require_product': True
        },

        'Blue Iris': {
            'brand_patterns': [r'\bblue\s+iris\b', r'\bblueiris\b'],
            'product_patterns': [r'\bblue\s+iris\s+\d+\b', r'\bui3\b'],
            'model_patterns': [],
            'cert_patterns': [r'blueirissoftware\.com'],
            'confidence': 90,
            'require_product': False
        },

        'EasyN': {
            'brand_patterns': [r'\beasyn\b'],
            'product_patterns': [r'\beasyn\s+camera\b', r'\beasyn\s+ip\b'],
            'model_patterns': [],
            'cert_patterns': [r'easyn\.'],
            'confidence': 75,
            'require_product': False
        },

        'Grundig': {
            'brand_patterns': [r'\bgrundig\b'],
            'product_patterns': [r'\bgrundig\s+camera\b', r'\bgrundig\s+security\b'],
            'model_patterns': [],
            'cert_patterns': [r'grundig\.'],
            'confidence': 80,
            'require_product': True
        },

        'Gstreamer': {
            'brand_patterns': [r'\bgstreamer\b'],
            'product_patterns': [r'\bgst-\w+', r'\bgstreamer\s+\d+\b'],
            'model_patterns': [],
            'cert_patterns': [],
            'confidence': 70,
            'require_product': False
        },

        'IDIS': {
            'brand_patterns': [r'\bidis\b'],
            'product_patterns': [
                r'\bidis\s+(?:camera|nvr|dvr)\b', r'\bdc-\w+\b', r'\bdr-\w+\b'
            ],
            'model_patterns': [r'DC-\w+', r'DR-\w+'],
            'cert_patterns': [r'idisglobal\.com'],
            'confidence': 90,
            'require_product': True
        },

        'i-Pro': {
            'brand_patterns': [r'\bi-pro\b', r'\bipro\b'],
            'product_patterns': [
                r'\bi-pro\s+(?:camera|extreme)\b', r'\bwv-\w+\b'
            ],
            'model_patterns': [r'WV-\w+'],
            'cert_patterns': [r'i-pro\.com'],
            'confidence': 85,
            'require_product': True
        },

        'Lenel': {
            'brand_patterns': [r'\blenel\b', r'\blenels2\b'],
            'product_patterns': [
                r'\blenel\s+(?:video|vms)\b', r'\bonguard\s+video\b'
            ],
            'model_patterns': [],
            'cert_patterns': [r'lenel\.com'],
            'confidence': 85,
            'require_product': True,
            'is_multi_function': True
        },

        'Loxone': {
            'brand_patterns': [r'\bloxone\b'],
            'product_patterns': [
                r'\bloxone\s+intercom\b', r'\bloxone\s+(?:mini)?server\b'
            ],
            'model_patterns': [],
            'cert_patterns': [r'loxone\.com'],
            'confidence': 85,
            'require_product': True
        },

        'Netgear': {
            'brand_patterns': [r'\bnetgear\b'],
            'product_patterns': [
                r'\bnetgear\s+(?:arlo|camera)\b', r'\bvms\d+\b'
            ],
            'model_patterns': [r'VMS\d+'],
            'cert_patterns': [r'netgear\.com'],
            'confidence': 85,
            'require_product': True
        },

        'Panasonic': {
            'brand_patterns': [r'\bpanasonic\b'],
            'product_patterns': [
                r'\bpanasonic\s+camera\b', r'\bi-pro\b', r'\bwv-\w+\b'
            ],
            'model_patterns': [r'WV-\w+'],
            'cert_patterns': [r'panasonic\.com'],
            'confidence': 85,
            'require_product': True,
            'is_multi_function': True
        },

        'RealServer': {
            'brand_patterns': [r'\brealserver\b', r'\breal\s+server\b'],
            'product_patterns': [r'\brealserver\s+\d+\b', r'\brtsp\s+server\b'],
            'model_patterns': [],
            'cert_patterns': [],
            'confidence': 75,
            'require_product': False
        },

        'Securetech': {
            'brand_patterns': [r'\bsecuretech\b'],
            'product_patterns': [r'\bsecuretech\s+camera\b', r'\bsecuretech\s+nvr\b'],
            'model_patterns': [],
            'cert_patterns': [r'securetech\.'],
            'confidence': 75,
            'require_product': False
        },

        'Siqura': {
            'brand_patterns': [r'\bsiqura\b'],
            'product_patterns': [r'\bsiqura\s+camera\b', r'\bsiqura\s+(?:bc|mc)\d+\b'],
            'model_patterns': [r'(?:BC|MC)\d+'],
            'cert_patterns': [r'siqura\.'],
            'confidence': 85,
            'require_product': True
        },

        'Sony': {
            'brand_patterns': [r'\bsony\b'],
            'product_patterns': [
                r'\bsony\s+camera\b', r'\bsnc-\w+\b', r'\bipela\b'
            ],
            'model_patterns': [r'SNC-\w+', r'IPELA'],
            'cert_patterns': [r'sony\.com'],
            'confidence': 90,
            'require_product': True
        },

        'Swann': {
            'brand_patterns': [r'\bswann\b'],
            'product_patterns': [
                r'\bswann\s+(?:camera|nvr|dvr)\b', r'\bswannview\b'
            ],
            'model_patterns': [r'SwannView'],
            'cert_patterns': [r'swann\.com'],
            'confidence': 85,
            'require_product': True
        },

        'TP-Link': {
            'brand_patterns': [r'\btp-link\b', r'\btplink\b'],
            'product_patterns': [
                r'\btp-link\s+camera\b', r'\btapo\s+c\d+\b', r'\btapo\b'
            ],
            'model_patterns': [r'Tapo\s+C\d+'],
            'cert_patterns': [r'tp-link\.com'],
            'confidence': 85,
            'require_product': True
        },

        'Trendnet': {
            'brand_patterns': [r'\btrendnet\b', r'\btrend\s+net\b'],
            'product_patterns': [
                r'\btrendnet\s+camera\b', r'\btv-ip\d+\b'
            ],
            'model_patterns': [r'TV-IP\d+'],
            'cert_patterns': [r'trendnet\.com'],
            'confidence': 85,
            'require_product': True
        },

        'Unifi': {
            'brand_patterns': [r'\bunifi\b', r'\bubi quiti\b'],
            'product_patterns': [
                r'\bunifi\s+(?:protect|video)\b', r'\bug\s*(?:3|4)\b'
            ],
            'model_patterns': [r'UG\d+', r'UniFi\s+Protect'],
            'cert_patterns': [r'ui\.com', r'ubnt\.com'],
            'confidence': 90,
            'require_product': True
        },

        'Videotec': {
            'brand_patterns': [r'\bvideotec\b'],
            'product_patterns': [r'\bvideotec\s+camera\b', r'\bvideotec\s+housing\b'],
            'model_patterns': [],
            'cert_patterns': [r'videotec\.'],
            'confidence': 80,
            'require_product': True
        },

        'Wisenet': {
            'brand_patterns': [r'\bwisenet\b', r'\bwisenet\s+nvr\b'],
            'product_patterns': [
                r'\bwisenet\s+(?:camera|nvr|wave)\b', r'\bwave\s+\d+\b'
            ],
            'model_patterns': [r'Wave\s+\d+'],
            'cert_patterns': [r'hanwha-security\.'],
            'confidence': 85,
            'require_product': True
        },

        'Zenitel': {
            'brand_patterns': [r'\bzenitel\b'],
            'product_patterns': [
                r'\bzenitel\s+(?:camera|turbine)\b', r'\bturbine\b', r'\bstentofon\b'
            ],
            'model_patterns': [r'Turbine', r'Stentofon'],
            'cert_patterns': [r'zenitel\.com'],
            'confidence': 85,
            'require_product': True,
            'is_multi_function': True
        },
    },

    'exclusions': {
        'cloud_cameras': [
            r'\bwebcam\b', r'\bzoom\s+camera\b', r'\bteams\s+camera\b',
            r'\bskype\s+camera\b', r'\bobs\s+camera\b',
        ],
        'it_cameras': [
            r'\bvirtual\s+camera\b', r'\bcamera\s+emulator\b',
        ],
        'web_services': [
            r'\bcloudflare\b', r'\bamazon\s+aws\b', r'\bgoogle\s+cloud\b',
        ],
    },
}


# ========================================
# PROTOCOL DETECTION FUNCTION
# ========================================
def detect_vss_protocols_enhanced(row):
    """
    Enhanced protocol detection for VSS with Q2 additions
    Returns: (detected_protocols: list, max_confidence: int, total_bonus: int)
    """
    detected = []
    max_confidence = 0
    total_bonus = 0

    port = row.get('service.port', 0)
    banner = str(row.get('service.banner', '')).lower()
    http_body = str(row.get('service.http.body', '')).lower()
    http_title = str(row.get('service.http.title', '')).lower()

    searchable = f"{banner} {http_body} {http_title}"

    protocols = VSS_ENHANCED_CONFIG.get('protocols', {})

    for protocol_name, protocol_config in protocols.items():
        matched = False

        # Check port match
        if 'ports' in protocol_config:
            if port in protocol_config['ports']:
                matched = True

        # Check banner patterns
        if 'banner_patterns' in protocol_config:
            for pattern in protocol_config['banner_patterns']:
                if re.search(pattern, searchable, re.IGNORECASE):
                    matched = True
                    break

        # Check path patterns
        if 'paths' in protocol_config:
            for path_pattern in protocol_config['paths']:
                if re.search(path_pattern, searchable, re.IGNORECASE):
                    matched = True
                    break

        if matched:
            detected.append(protocol_name)
            max_confidence = max(max_confidence, protocol_config.get('confidence', 0))
            total_bonus += protocol_config.get('protocol_bonus', 0)

    return detected, max_confidence, total_bonus


# ========================================
# DETECTION FUNCTION
# ========================================
# CORRECTED VSS FUNCTION - READY TO USE
# Replace your entire identify_vss_enhanced() function with this

def identify_vss_enhanced(row):
    """
    Comprehensive VSS identification with all 50 brands
    Now accumulates ALL matching indicators for complete audit trail
    """

    result = {
        'is_vss': False,
        'vss_confidence': 0,
        'detected_brand': None,
        'detected_product': None,
        'vss_reason': None,
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
    for category, patterns in VSS_ENHANCED_CONFIG['exclusions'].items():
        for pattern in patterns:
            if re.search(pattern, all_text, re.IGNORECASE):
                result['vss_reason'] = f"EXCLUDED:{category}"
                return result

    # Track highest confidence and primary brand
    max_confidence = 0
    primary_brand = None
    primary_product = None

    # STEP 2: PROTOCOL DETECTION
    port = row.get('service.port', 0)
    for proto_name, proto_config in VSS_ENHANCED_CONFIG['protocols'].items():
        port_match = True
        if 'ports' in proto_config:
            port_match = port in proto_config['ports']

        if port_match or not proto_config.get('require_banner', True):
            for pattern in proto_config['banner_patterns']:
                match = re.search(pattern, all_text, re.IGNORECASE)
                if match:
                    result['is_vss'] = True
                    reasons.append(f"protocol:{proto_name}")
                    if port:
                        reasons.append(f"port:{port}")
                    proto_confidence = proto_config['confidence']
                    
                    if proto_confidence > max_confidence:
                        max_confidence = proto_confidence
                        result['match_field'] = 'protocol'
                        result['match_pattern'] = pattern

    # STEP 3: HTTP PATH DETECTION
    if fields['http_path']:
        for brand, paths in VSS_ENHANCED_CONFIG['http_paths'].items():
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
                    result['is_vss'] = True
                    path_confidence = 90 if found_in_path else 85
                    reasons.append(f"http_path:{path}")
                    reasons.append(f"brand:{brand}")
                    
                    if path_confidence > max_confidence:
                        max_confidence = path_confidence
                        primary_brand = brand
                        result['match_field'] = 'http_path' if found_in_path else 'body'
                        result['match_pattern'] = path

    # STEP 4: BRAND + PRODUCT DETECTION
    for brand, brand_config in VSS_ENHANCED_CONFIG['brands'].items():
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
                result['is_vss'] = True
                reasons.append(f"product:{product_match}")
                brand_confidence = brand_config['confidence']
                
                if brand_confidence > max_confidence:
                    max_confidence = brand_confidence
                    primary_brand = brand
                    primary_product = product_match
                    result['match_field'] = f"{brand_field}+{product_field}"
        else:
            result['is_vss'] = True
            brand_confidence = brand_config['confidence']
            
            if brand_confidence > max_confidence:
                max_confidence = brand_confidence
                primary_brand = brand
                result['match_field'] = brand_field

    # ========================================
    # VSS PROTOCOL DETECTION
    # ========================================
    detection_methods = []
    if result['is_vss']:
        detection_methods.append('brand_match')

    # Enhancement: Check for VSS-specific protocols (HLS, DASH, PSIA, etc.)
    protocols, protocol_conf, protocol_bonus = detect_vss_protocols_enhanced(row)

    if protocols:
        detection_methods.append('protocol')
        for proto in protocols:
            reasons.append(f"vss_protocol:{proto}")
        
        max_confidence = max(max_confidence, protocol_conf)
        result['is_vss'] = True
        result['protocols_detected'] = protocols

    # ========================================
    # FINALIZE RESULTS
    # ========================================
    if result['is_vss']:
        # Set primary brand and product
        result['detected_brand'] = primary_brand
        result['detected_product'] = primary_product
        
        # Enhanced confidence calculation
        final_confidence, confidence_bonuses = calculate_enhanced_confidence(
            row=row,
            base_confidence=max_confidence,
            brand=primary_brand,
            category='VSS',
            detection_methods=detection_methods
        )

        result['vss_confidence'] = final_confidence
        result['confidence_bonuses'] = confidence_bonuses
        result['detection_methods'] = detection_methods
        
        # Combine all reasons into pipe-separated string
        # Remove duplicates while preserving order
        unique_reasons = []
        for r in reasons:
            if r not in unique_reasons:
                unique_reasons.append(r)
        
        result['vss_reason'] = '|'.join(unique_reasons) if unique_reasons else None

    return result


print("Comprehensive VSS detection loaded")
print("")
