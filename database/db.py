import sqlite3
import json
from datetime import datetime
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "scans.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        risk_score INTEGER,
        open_ports INTEGER,
        findings TEXT,
        compliance TEXT,
        threat_intel TEXT,
        report_file TEXT,
        pdf_file TEXT
    )''')
    conn.commit()
    conn.close()


def save_scan(target, risk_score, findings, compliance, threat_intel, report_file, pdf_file):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT INTO scans
                 (target, timestamp, risk_score, open_ports, findings, compliance, threat_intel, report_file, pdf_file)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
              (target, str(datetime.now()), risk_score, len(findings),
               json.dumps(findings), json.dumps(compliance), json.dumps(threat_intel),
               report_file, pdf_file))
    conn.commit()
    scan_id = c.lastrowid
    conn.close()
    return scan_id


def get_all_scans():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT id, target, timestamp, risk_score, open_ports FROM scans ORDER BY id DESC LIMIT 50')
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows


def get_scan(scan_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None
