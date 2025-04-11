import sqlite3

def init_db():
    conn = sqlite3.connect('data/scan_results.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS scans
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     host TEXT, port INTEGER, service TEXT, version TEXT,
                     vulnerability TEXT, cve_id TEXT, severity TEXT)''')
    conn.commit()
    conn.close()

def save_scan_results(results, cve_results):
    conn = sqlite3.connect('data/scan_results.db')
    cursor = conn.cursor()
    for host_data in results:
        host = host_data['host']
        for port_data in host_data['ports']:
            port = port_data['port']
            service = port_data['service']
            version = port_data['version']
            for vuln in port_data['vulnerabilities']:
                cve_id = vuln['id']
                for cve in cve_results:
                    if cve['cve_id'] == cve_id:
                        cursor.execute('''INSERT INTO scans
                                        (host, port, service, version, vulnerability, cve_id, severity)
                                        VALUES (?, ?, ?, ?, ?, ?, ?)''',
                                      (host, port, service, version, vuln['output'], cve_id, cve['severity']))
    conn.commit()
    conn.close()

