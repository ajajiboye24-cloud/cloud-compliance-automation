import sqlite3

import pandas as pd
import streamlit as st


DATABASE_NAME = "scanner_results.db"


def load_scans():
    with sqlite3.connect(DATABASE_NAME) as conn:
        return pd.read_sql_query(
            """
            SELECT scan_id, timestamp, overall_score
            FROM scans
            ORDER BY timestamp DESC
            """,
            conn
        )


def load_findings(scan_id):
    with sqlite3.connect(DATABASE_NAME) as conn:
        return pd.read_sql_query(
            """
            SELECT
                control_id,
                title,
                service,
                status,
                severity,
                category,
                nist_800_53,
                cis_aws_foundations,
                evidence,
                remediation
            FROM findings
            WHERE scan_id = ?
            ORDER BY control_id
            """,
            conn,
            params=(scan_id,)
        )


def main():
    st.set_page_config(
        page_title="Cloud Compliance Dashboard",
        layout="wide"
    )

    st.title("Cloud Compliance Dashboard")
    st.caption("AWS security and compliance scan results")

    scans = load_scans()

    if scans.empty:
        st.warning("No scan results found. Run python app.py first.")
        return

    latest_scan = scans.iloc[0]
    latest_scan_id = latest_scan["scan_id"]
    findings = load_findings(latest_scan_id)

    passed = int((findings["status"] == "PASS").sum())
    failed = int((findings["status"] == "FAIL").sum())
    errors = int((findings["status"] == "ERROR").sum())

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Compliance Score",
        f"{latest_scan['overall_score']:.0f}%"
    )
    col2.metric("Passed", passed)
    col3.metric("Failed", failed)
    col4.metric("Errors", errors)

    st.subheader("Latest Scan")
    st.write(f"**Scan ID:** {latest_scan_id}")
    st.write(f"**Timestamp:** {latest_scan['timestamp']}")

    st.subheader("Control Findings")
    st.dataframe(
        findings,
        use_container_width=True,
        hide_index=True
    )

    st.subheader("Findings by Status")
    status_counts = findings["status"].value_counts()
    st.bar_chart(status_counts)

    st.subheader("Scan History")
    st.dataframe(
        scans,
        use_container_width=True,
        hide_index=True
    )


if __name__ == "__main__":
    main()