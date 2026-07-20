import sqlite3
from sqlite3 import Error
from contextlib import closing


DATABASE_NAME = "scanner_results.db"
def save_finding(scan_id, finding):
    pass
def save_scan(scan_id, timestamp, overall_score):
    pass

def initialize_database():
    create_scans_table_sql = """
    CREATE TABLE IF NOT EXISTS scans (
        scan_id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        overall_score REAL NOT NULL
    );
    """

    create_findings_table_sql = """
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        control_id TEXT NOT NULL,
        title TEXT NOT NULL,
        service TEXT NOT NULL,
        status TEXT NOT NULL,
        severity TEXT NOT NULL,
        category TEXT,
        control_objective TEXT,
        framework_mappings TEXT,
        evidence TEXT,
        remediation TEXT
    );
    """

    try:
        with closing(sqlite3.connect(DATABASE_NAME)) as conn:
            cursor = conn.cursor()
            cursor.execute(create_scans_table_sql)
            cursor.execute(create_findings_table_sql)
            conn.commit()
    except Error as e:
        print(f"Error occurred while initializing database: {e}")


def save_scan(scan_id, timestamp, overall_score):
    pass


def save_finding(scan_id, finding):
    pass


def save_scan_results(scan_id, timestamp, overall_score, findings):
    pass


def get_previous_scan_results():
    pass

def save_scan(scan_id, timestamp, overall_score):
    insert_scan_sql = """
    INSERT INTO scans (
        scan_id,
        timestamp,
        overall_score
    )
    VALUES (?, ?, ?);
    """

    try:
        with sqlite3.connect(DATABASE_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute(
                insert_scan_sql,
                (scan_id, timestamp, overall_score)
            )
            conn.commit()

    except Error as error:
        print(f"Error saving scan: {error}")