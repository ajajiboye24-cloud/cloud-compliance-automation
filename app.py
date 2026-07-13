from scanner.iam_checks import check_password_policy
from scanner.cloudtrail_checks import check_cloudtrail_enabled

def print_result(result):
    print("--------------------------------------")
    print(f"Control ID: {result['control_id']}")
    print(f"Title: {result['title']}")
    print(f"Service: {result['service']}")
    print(f"Status: {result['status']}")
    print(f"Severity: {result['severity']}")
    print(f"Evidence: {result['evidence']}")
    print(f"Remediation: {result['remediation']}")


def main():
    print("Cloud Compliance Automation Scanner")

    checks = [
        check_password_policy,
        check_cloudtrail_enabled
    ]

    for check in checks:
        result = check()
        print_result(result)


if __name__ == "__main__":
    main()