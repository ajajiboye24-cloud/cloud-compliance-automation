import sqlite3
from sqlite3 import Error
from contextlib import closing


DATABASE_NAME = "scanner_results.db"


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
        nist_800_53 TEXT,
        cis_aws_foundations TEXT,
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

    except Error as error:
        print(f"Error initializing database: {error}")


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


def save_finding(scan_id, finding):
    insert_finding_sql = """
    INSERT INTO findings (
        scan_id,
        control_id,
        title,
        service,
        status,
        severity,
        category,
        control_objective,
        nist_800_53,
        cis_aws_foundations,
        evidence,
        remediation
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """

    frameworks = finding.get("framework_mappings", {})

    nist_controls = ", ".join(
        frameworks.get("nist_800_53", [])
    )

    cis_controls = ", ".join(
        frameworks.get("cis_aws_foundations", [])
    )

    values = (
        scan_id,
        finding.get("control_id"),
        finding.get("title"),
        finding.get("service"),
        finding.get("status"),
        finding.get("severity"),
        finding.get("category"),
        finding.get("control_objective"),
        nist_controls,
        cis_controls,
        finding.get("evidence"),
        finding.get("remediation")
    )

    try:
        with sqlite3.connect(DATABASE_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute(insert_finding_sql, values)
            conn.commit()

    except Error as error:
        print(f"Error saving finding: {error}")


def save_scan_results(scan_id, timestamp, overall_score, findings):
    print(f"Saving scan {scan_id} with {len(findings)} findings")
    save_scan(scan_id, timestamp, overall_score)

    for finding in findings:
        save_finding(scan_id, finding)
    
    print("Database Save Completed")


def get_previous_scan_results():
    pass