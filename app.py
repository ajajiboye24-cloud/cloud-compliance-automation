from scanner.iam_checks import check_password_policy


def main():
    print("Cloud Compliance Automation Scanner")
    print("--------------------------------------")

    result = check_password_policy()

    print(f"Control ID: {result['control_id']}")
    print(f"Title: {result['title']}")
    print(f"Service: {result['service']}")
    print(f"Status: {result['status']}")
    print(f"Severity: {result['severity']}")
    print(f"Evidence: {result['evidence']}")
    print(f"Remediation: {result['remediation']}")

if __name__ == "__main__":
    main()