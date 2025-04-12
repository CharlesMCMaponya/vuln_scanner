# Cybersecurity Vulnerability Scanner with CVE Integration and Slack Alerts

This is a Python-based cybersecurity tool that scans for vulnerabilities, checks them against CVEs (Common Vulnerabilities and Exposures), generates an HTML report, and sends real-time alerts to Slack if issues are found.

## Technologies Used
- **Programming Language**: Python 3
- **Tools and Libraries**:
  - `nmap`: For vulnerability scanning
  - Slack API: For sending real-time alerts
  - `requests`: For fetching CVE data
- **Operating System**: Ubuntu 24.04

## Skills Demonstrated
- **Cybersecurity**: Identifying and analyzing network vulnerabilities
- **API Integration**: Working with the Slack API and CVE data APIs
- **Linux**: Developing and running the tool on Ubuntu
- **Problem-Solving**: Designing a modular and efficient vulnerability scanning solution

## Setup Instructions
1. Clone the repository:
   ```bash
   git clone https://github.com/CharlesMCMaponya/vuln_scanner.git
   cd vuln_scanner

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





