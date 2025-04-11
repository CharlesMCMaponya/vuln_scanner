import sqlite3

def create_cve_database():
    conn = sqlite3.connect('data/cve.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS cve
                    (cve_id TEXT PRIMARY KEY, description TEXT, severity TEXT)''')
    # Fake CVE data for testing
    fake_cves = [
        ("CVE-2023-1234", "Fake vulnerability in test service", "HIGH"),
        ("CVE-2023-5678", "Fake issue in test software", "MEDIUM")
    ]
    cursor.executemany("INSERT OR IGNORE INTO cve VALUES (?, ?, ?)", fake_cves)
    conn.commit()
    conn.close()
    print("CVE database created/updated.")

if __name__ == "__main__":
    create_cve_database()


