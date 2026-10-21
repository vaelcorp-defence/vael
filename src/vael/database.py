import sqlite3
from pathlib import Path

DB_PATH = Path("vael.db")

def init_db():
    """Create the database and tables if they don't exist."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # Added 'poc' column for reproduction steps
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            target TEXT,
            severity TEXT,
            issue TEXT,
            url TEXT,
            evidence TEXT,
            poc TEXT,
            skill TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def save_findings(scan_id: str, target: str, findings: list):
    """Save a list of findings to the database."""
    if not findings:
        return
        
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    for f in findings:
        cursor.execute('''
            INSERT INTO findings (scan_id, target, severity, issue, url, evidence, poc, skill)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_id, 
            target, 
            f['severity'], 
            f['issue'], 
            f['target'], 
            f['evidence'], 
            f.get('poc', 'No PoC generated.'), # Fallback if a skill doesn't have one
            f['skill']
        ))
        
    conn.commit()
    conn.close()

def get_findings(status: str = None):
    """Retrieve findings from the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    if status:
        cursor.execute("SELECT target, severity, issue, url, poc, skill FROM findings WHERE severity = ?", (status,))
    else:
        cursor.execute("SELECT target, severity, issue, url, poc, skill FROM findings ORDER BY timestamp DESC")
        
    rows = cursor.fetchall()
    conn.close()
    return rows

def clear_findings():
    """Wipe the findings table."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM findings")
    conn.commit()
    conn.close()
