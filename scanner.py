
import nmap
import json
import sqlite3
from report_generator import generate_report
from slack_alert import send_slack_alert

def scan_target(target):
    nm = nmap.PortScanner()
    print(f"Scanning {target}...")
    nm.scan(target, arguments='-sV --script vuln')
    scan_results = []
    for host in nm.all_hosts():
        host_data = {"host": host, "ports": []}
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                port_data = nm[host][proto][port]
                service = port_data.get('name', 'unknown')
                version = port_data.get('product', '') + " " + port_data.get('version', '')
                vulnerabilities = port_data.get('script', {}).get('vuln', [])
                host_data["ports"].append({
                    "port": port,
                    "service": service,
                    "version": version,
                    "vulnerabilities": vulnerabilities
                })
        scan_results.append(host_data)
    return scan_results

def check_cve(vulnerabilities):
    conn = sqlite3.connect('data/cve.db')
    cursor = conn.cursor()
    cve_results = []
    for vuln in vulnerabilities:
        for cve in vuln.get('vulnerabilities', []):
            cursor.execute("SELECT * FROM cve WHERE cve_id=?", (cve['id'],))
            result = cursor.fetchone()
            if result:
                cve_results.append({"cve_id": result[0], "description": result[1], "severity": result[2]})
    conn.close()
    return cve_results

def save_results(results):
    with open('data/scan_results.json', 'w') as f:
        json.dump(results, f, indent=4)

if __name__ == "__main__":
    target = "127.0.0.1"  # Scanning localhost for now
    results = scan_target(target)
    save_results(results)
    cve_results = check_cve([port for host in results for port in host['ports']])
    report_path = generate_report(results, cve_results)
    print(f"Report generated at: {report_path}")
    if cve_results:
        send_slack_alert(cve_results)
