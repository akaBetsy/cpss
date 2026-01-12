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
- 4_retrieve_cve_info.py         Retrieves CVE from modat_service_all.csv and outputs to cve_from_modat_service_api.txt, then utilises this TXT to verify CVE information already present in cve_from_modat_service_api.txt and asks to scan only the diff or all CVE against the NVD CVE API   ### this script has not been used in the research, but can be used in future research ###
- 5_validation_shodan_json_to_modat_csv.py A Shodan data sample was collected via the Shodan web interface and saved as a JSON into folder .\staging\4_validation folder. This JSON file was then normalized to CSV via script 5_validation_shodan_json_to_modat_csv.py. 
- 6_validation_retrieve_modat_data.py A Modat data sample was collected with script 6_validation_retrieve_modat_data.py from the Modat Service API, output to folder .\ staging\4_validation and then normalized to CSV via script 6a_validation_json_to_csv.py.
- 7_data_collection_analysis.ipynb Analysis 1 on statistics over the modat_service_all.CSV dataset and outputs to folder .\output\1_data_statistics. The output consists of a TXT summary, details in CSV and visualisations.
- 8_cpss_identification.ipynb Analysis 2 on the modat_service_all.CSV dataset and outputs to folder .\output\2_cpss_identification. The output consists of cpss_all_services.CSV as the primary file containing the original records of identified CPSS, reason it was identified as CPSS within a CPSS category, and confidence of CPSS identification. This CSV is supported with a subset in CSV per CPSS category, a TXT summary of the analysis and visualizations saved in JPG
9_cpss_iso_analyses.ipynb on the cpss_all_services.CSV dataset and outputs to folder .\output\3_iso27002_assessment. The output consists of the primary file cpss_iso27002_assessment_complete.CSV containing full information on identified records, and a noncompliance score per resilience domain and ISO 27002 control. The noncompliance score is supported with risk indicators for likelihood and impact. This CSV is supported with a CSV per CPSS category, a TXT summary of the analysis and visualizations saved in PNG.        
