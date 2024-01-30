# IP_Reputaion_VT_CTI_ABUSEIPDB
Python script to extract IP address information from open-source platforms like VirusTotal, CTI ThreatBook and AbuseIPDB

IP Threat Analysis Tool
This tool performs threat analysis on a list of IP addresses using various APIs, including VirusTotal, AbuseIPDB, and CTI_ThreatBook. It retrieves information such as malicious count, ASN owner, country, abuse confidence score, number of reports, last updated date, and threat judgments.

Table of Contents
Prerequisites
Installation
Usage
API Keys
Input Format
Output
Dependencies
License
Prerequisites
Before using this tool, make sure you have the following prerequisites:

Python (>=3.6)
API keys for VirusTotal, AbuseIPDB, and CTI_ThreatBook
Installation
Clone the repository:

bash
Copy code
git clone https://github.com/your-username/ip-threat-analysis-tool.git
cd ip-threat-analysis-tool
Install the required Python packages:

bash
Copy code
pip install -r requirements.txt
Usage
Run the tool using the following command:

bash
Copy code
python analyze_ips.py
The tool reads IP addresses from the specified Excel file (input.xlsx by default), processes them through VirusTotal, AbuseIPDB, and CTI_ThreatBook APIs, and saves the results to an output Excel file in the "Result" folder.

API Keys
Before running the tool, replace the placeholder API keys in the script with your own keys:

vt_api_key: VirusTotal API key
CTI_api_key: CTI_ThreatBook API key
Abuse_api_key: AbuseIPDB API key
Input Format
The input file (input.xlsx by default) should be an Excel file containing a list of IP addresses in a single column, with a header row.

Output
The tool generates an output Excel file in the "Result" folder with the format output_<timestamp>.xlsx, where <timestamp> is the current date and time.

The output file includes the following columns:

IP: IP address
VT_Malicious_Count: VirusTotal malicious count
VT_ASN_Owner: VirusTotal ASN owner
VT_Country: VirusTotal country
Abuse_Confidence_Score: AbuseIPDB confidence score
Number_of_Reports: AbuseIPDB number of reports
Last_Updated: AbuseIPDB last updated date
Judgment values: CTI_ThreatBook threat judgments
Final verdict: CTI_ThreatBook final verdict
Dependencies
The tool relies on the following Python packages:

os
requests
pandas
datetime
colorama
You can install these dependencies using the provided requirements.txt file.

License
This project is licensed under the MIT License.
