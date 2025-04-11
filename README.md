# Vulnerability Scanner with CVE Integration

A Python-based vulnerability scanner that uses nmap to scan targets, checks for CVEs, generates reports, and sends alerts via Slack.

## Setup
1. Create a virtual environment: `python3 -m venv venv`
2. Activate the virtual environment: `source venv/bin/activate`
3. Install dependencies: `pip install -r requirements.txt`
4. Run `python3 cve_fetcher.py` to set up the CVE database.
5. Run `sudo python3 scanner.py` to scan and generate a report.

## Features
- Scans for open ports and vulnerabilities using nmap.
- Matches vulnerabilities against a CVE database.
- Generates an HTML report.
- Sends alerts to Slack for high-severity issues. 



