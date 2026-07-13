import boto3
from botocore.exceptions import ClientError


def check_cloudtrail_enabled():
    cloudtrail = boto3.client("cloudtrail")

    try:
        trails = cloudtrail.describe_trails()["trailList"]

        if trails:
            return {
                "control_id": "LOG-001",
                "title": "CloudTrail is enabled",
                "service": "CloudTrail",
                "status": "PASS",
                "severity": "High",
                "evidence": f"{len(trails)} CloudTrail trail(s) found.",
                "remediation": "No action required."
            }

        return {
            "control_id": "LOG-001",
            "title": "CloudTrail is enabled",
            "service": "CloudTrail",
            "status": "FAIL",
            "severity": "High",
            "evidence": "No CloudTrail trails found.",
            "remediation": "Enable CloudTrail to capture AWS account activity."
        }

    except ClientError as error:
        return {
            "control_id": "LOG-001",
            "title": "CloudTrail is enabled",
            "service": "CloudTrail",
            "status": "ERROR",
            "severity": "High",
            "evidence": str(error),
            "remediation": "Review AWS credentials and CloudTrail permissions."
        }