# Cloud Compliance Automation Platform

## Overview

The **Cloud Compliance Automation Platform** is a Python application that scans AWS accounts for security misconfigurations, evaluates cloud resources against industry security standards, and generates audit-ready compliance reports.

The goal of this project is to automate cloud security assessments and demonstrate how cloud security, governance, risk, and compliance (GRC) processes can be integrated into a single platform.

---

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

### Current Features (Version 1)

* Scan AWS account configurations
* Check IAM security settings
* Check S3 security settings
* Check CloudTrail configuration
* Evaluate selected security controls
* Display Pass/Fail results
* Store scan findings

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
