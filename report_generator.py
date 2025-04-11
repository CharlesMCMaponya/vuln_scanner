from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import os

def generate_report(scan_results, cve_results):
    report_path = "data/reports/report.html"
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, 'w') as f:
        f.write("<html><body><h1>Vulnerability Scan Report</h1>")
        f.write("<h2>Scan Results</h2>")
        for host in scan_results:
            f.write(f"<h3>Host: {host['host']}</h3>")
            for port in host['ports']:
                f.write(f"<p>Port: {port['port']} - Service: {port['service']} {port['version']}</p>")
                for vuln in port['vulnerabilities']:
                    f.write(f"<p>Vulnerability: {vuln['id']} - {vuln['output']}</p>")
        f.write("<h2>CVE Matches</h2>")
        for cve in cve_results:
            f.write(f"<p>{cve['cve_id']}: {cve['description']} (Severity: {cve['severity']})</p>")
        f.write("</body></html>")
    return report_path

