Welcome to this code library for my thesis titled: **"Cyber Resilience of Physical Security"**
_An Internet Exposure and Compliance Analysis of the Dutch Defense Supply Chain_
as part of the Master Cyber Security Engineering @ The Hague University of Applied Sciences

This research aims to identify (internet) connected Physical Security systems, used by the Dutch Defense supply chain;
  based on the companies related to NIDV.eu/bedrijvenlijst;
  to define resilience and compliance criteria based on current legislation and best practices;
  to assess the identified systems against these criteria;
  to advise additional security measures for these device types;
  open-source the method used, for common good.

Connected Physical Security systems in scope are;
- Electronic Access Control Systems: Mechanisms like key cards, biometric scanners and PIN codes that regulate entry to facilities.
- Video Surveillance Systems: CCTV cameras and monitoring setups to observe and record activities within and around premises.
- Intrusion & Hold Alarm Systems (Alarm systems): Sensors and alarms that detect unauthorized access or breaches.

Workflow:
- _CPSS_scanner.py is the workflow orchestrator
- 0_input_domains_from_PDF.py   Retrieves domains PDF in .\input folder and output to .\input\cpss_scan_domains_date.txt
- 1a_modat_host_domain_to_ip.py Uses domains from most recent TXT from .\input to scan Modat Host API for "web.html, certs, domain" and outputs to .\staging\1a_modat_host_api\
- 1b_networksdb_domain_to_ip.py Uses domains from most recent TXT from .\input to scan NetworksDB DNS, Org-Search and IP-info and outputs to .\staging\1b_networksdb_api\
- 2_modat_service_api.py        Retrieves unique IPv4 addresses from .\staging\1a_modat_host_api\ and .\staging\1b_networksdb_api\ and outputs into .\staging\2_modat_service_api\_domain_to_ip_
  {yyyymmdd}.txt, then it asks to scan the Modat Service API on these unique IP-addresses and outputs to .\staging\2_modat_service_api
- 3_process_json_to_csv.py      Retrieves all fields, excluding raw cert, from the IP JSON files in .\staging\2_modat_service_api, matches with domain names in .\staging\1a_modat_host_api\ and .\staging\1b_networksdb_api\ and output the data into .\staging\3_prepare_analyses\modat_service_all.csv
- 4_retrieve_cve_info.py         Retrieves CVE from modat_service_all.csv and outputs to cve_from_modat_service_api.txt, then utilises this TXT to verify CVE information already present in cve_from_modat_service_api.txt and asks to scan only the diff or all CVE against the NVD CVE API   


         
