from scanner.iam_checks import check_password_policy
from scanner.cloudtrail_checks import check_cloudtrail_enabled
from scanner.s3_checks import check_s3_public_access_block
from scanner.ec2_checks import check_security_groups_open_to_risky_ports
from scanner.iam_checks import check_old_access_keys
from compliance.mapper import load_control_mappings, enrich_finding

def print_result(result):
    print("--------------------------------------")
    print(f"Control ID: {result['control_id']}")
    print(f"Title: {result['title']}")
    print(f"Service: {result['service']}")
    print(f"Status: {result['status']}")
    print(f"Severity: {result['severity']}")
    print(f"Category: {result['category']}")
    print(f"Control Objective: {result['control_objective']}")

    frameworks = result.get("framework_mappings", {})
    print(f"NIST 800-53: {frameworks.get('nist_800_53', [])}")
    print(f"CIS AWS Foundations: {frameworks.get('cis_aws_foundations', [])}")

    print(f"Evidence: {result['evidence']}")
    print(f"Remediation: {result['remediation']}")


def main():
    print("Cloud Compliance Automation Scanner")

    mappings = load_control_mappings()
    checks = [
        check_password_policy,
        check_cloudtrail_enabled,
        check_s3_public_access_block,
        check_security_groups_open_to_risky_ports,
        check_old_access_keys
    ]

    print(f"Total checks loaded: {len(checks)}")

    for check in checks:
        raw_result = check()
        enriched_result = enrich_finding(raw_result, mappings)
        print_result(enriched_result)

if __name__ == "__main__":
    main()