# Cloud Compliance Automation Platform
<img width="1169" height="619" alt="Screenshot 2026-07-13 at 8 37 02 AM" src="https://github.com/user-attachments/assets/1c135add-f86c-40d7-b378-1934e6331f22" />


## Overview

The **Cloud Compliance Automation Platform** is a Python application that scans AWS accounts for security misconfigurations, evaluates cloud resources against industry security standards, and generates audit-ready compliance reports.

The goal of this project is to automate cloud security assessments and demonstrate how cloud security, governance, risk, and compliance (GRC) processes can be integrated into a single platform.

---

## How It Works

1. The user runs `python app.py`.
2. The scanner connects to AWS using `boto3`.
3. Each AWS service check returns a standardized finding.
4. The compliance engine enriches the finding with NIST and CIS mappings.
5. The application prints detailed results and a compliance summary.


## Problem Statement

Cloud environments contain hundreds of security settings that organizations must continuously monitor to remain secure and compliant. Manually reviewing AWS configurations is time-consuming, error-prone, and difficult to scale.

This project solves that problem by automatically:

* Scanning AWS accounts for security misconfigurations
* Evaluating AWS resources against predefined security controls
* Mapping findings to compliance frameworks such as:

  * NIST 800-53
  * CIS AWS Foundations Benchmark
  * AWS Foundational Security Best Practices
* Generating audit-ready compliance reports
* Providing remediation recommendations for failed controls

---

## Features

## Roadmap

- [x] Build AWS scanner
- [x] Add five compliance controls
- [x] Add compliance framework mappings
- [x] Add scan summary
- [ ] Store findings in SQLite
- [ ] Build Streamlit dashboard
- [ ] Generate PDF audit reports
- [ ] Add multi-account support

## Current Controls

| Control ID | Service | Description | Severity |
|---|---|---|---|
| IAM-001 | IAM | Checks whether an IAM password policy exists | Medium |
| LOG-001 | CloudTrail | Checks whether CloudTrail is enabled | High |
| S3-001 | S3 | Checks whether S3 buckets block public access | High |
| EC2-001 | EC2 | Checks whether risky ports are open to the internet | Critical |
| IAM-002 | IAM | Checks whether IAM access keys are older than 90 days | High |




### Planned Features

* Compliance dashboard (Streamlit)
* Executive compliance reports (PDF)
* Risk scoring
* Historical scan tracking
* Security Hub integration
* AWS Config integration
* Multi-account scanning
* Docker deployment
* CI/CD with GitHub Actions

---

## Technology Stack

* Python
* AWS SDK (boto3)
* Streamlit
* SQLite
* Git
* GitHub

---

## Compliance Frameworks

This project is designed to map AWS security findings to industry-recognized frameworks, including:

* NIST 800-53
* CIS AWS Foundations Benchmark
* AWS Foundational Security Best Practices

---

## Learning Objectives

This project is intended to strengthen practical skills in:

* AWS Security
* Cloud Security
* Identity and Access Management (IAM)
* Governance, Risk, and Compliance (GRC)
* Security Automation
* Python Development
* Compliance Reporting

---

## Future Roadmap

* Expand security control library
* Add identity governance features
* Build a web dashboard
* Automate compliance reporting
* Support multiple AWS accounts
* Implement role-based access control (RBAC)
* Add audit evidence management
* Develop a REST API

---

## License

This project is for educational and portfolio purposes.
