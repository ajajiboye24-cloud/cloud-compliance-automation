from scanner.iam_checks import check_password_policy, check_old_access_keys
from scanner.cloudtrail_checks import check_cloudtrail_enabled
from scanner.s3_checks import check_s3_public_access_block
from scanner.ec2_checks import check_security_groups_open_to_risky_ports

from compliance.mapper import load_control_mappings, enrich_finding
from utils.logger import setup_logger


def print_result(result):
    print("--------------------------------------")
    print(f"Control ID: {result['control_id']}")
    print(f"Title: {result['title']}")
    print(f"Service: {result['service']}")
    print(f"Status: {result['status']}")
    print(f"Severity: {result['severity']}")
    print(f"Category: {result.get('category', 'Unmapped')}")
    print(f"Control Objective: {result.get('control_objective', 'No objective mapped.')}")

    frameworks = result.get("framework_mappings", {})
    print(f"NIST 800-53: {frameworks.get('nist_800_53', [])}")
    print(f"CIS AWS Foundations: {frameworks.get('cis_aws_foundations', [])}")

    print(f"Evidence: {result['evidence']}")
    print(f"Remediation: {result['remediation']}")


def print_summary(results):
    total = len(results)
    passed = sum(1 for result in results if result["status"] == "PASS")
    failed = sum(1 for result in results if result["status"] == "FAIL")
    errors = sum(1 for result in results if result["status"] == "ERROR")

    compliance_score = round((passed / total) * 100, 2) if total > 0 else 0

    print("\n======================================")
    print("Cloud Compliance Summary")
    print("======================================")
    print(f"Total Controls: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Errors: {errors}")
    print(f"Compliance Score: {compliance_score}%")
    print("======================================")


def main():
    logger = setup_logger()
    logger.info("Starting cloud compliance scan")

    mappings = load_control_mappings()

    checks = [
        check_password_policy,
        check_cloudtrail_enabled,
        check_s3_public_access_block,
        check_security_groups_open_to_risky_ports,
        check_old_access_keys
    ]

    results = []

    for check in checks:
        logger.info(f"Running check: {check.__name__}")

        raw_result = check()
        enriched_result = enrich_finding(raw_result, mappings)

        results.append(enriched_result)
        print_result(enriched_result)

    print_summary(results)

    logger.info("Cloud compliance scan completed")


if __name__ == "__main__":
    main()