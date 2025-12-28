Welcome to this code library for my thesis titled: "Cyber Resilience of Physical Security"
_An Internet Exposure and Compliance Analysis of the Dutch Defense Supply Chain as part of the Master Cyber Security Engineering @ The Hague University of Applied Sciences.
_

This research aims to identify (internet) connected Physical Security systems, used by the Dutch Defense supply chain;
based on the companies related to NIDV.eu/bedrijvenlijst;
to define resilience and compliance criteria based on current legislation and best practices;
to assess the identified systems against these criteria;
to advise additional security measures for these device types;
open-source the method used, for common good.

Connected Physical Security systems in scope are:
⦁	Electronic Access Control Systems: Mechanisms like key cards, biometric scanners and PIN codes that regulate entry to facilities.
⦁	Video Surveillance Systems: CCTV cameras and monitoring setups to observe and record activities within and around premises.
⦁	Intrusion & Hold Alarm Systems (Alarm systems): Sensors and alarms that detect unauthorized access or breaches.

Workflow:
⦁	0_input_domains_from_PDF.py   Retrieve domains PDF in .\input folder and output to .\staging\cpss_scan_domains_date.txt
⦁	Scan Modat Host API for "web.html, certs, domain" based on domains (modat_domain_to_ip_apihost.py)
⦁	Scan Networksdb API for IP-addresses based on domains (networksdb_domain_to_ip.py)
⦁	Index Modat and Networksdb .JSON into Elastic (index_api_results_to_elastic.py / es_client.py)
⦁	Retrieve unique Networksdb IP's from Elastic to rescan at Modat (rescan_networksdb_ip_to_modat.py / es_client.py)
