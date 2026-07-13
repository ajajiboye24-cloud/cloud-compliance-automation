import boto3 
from botocore.exceptions import ClientError
from datetime import datetime, timezone

def check_password_policy():
    iam = boto3.client('iam')

    try:
        iam.get_account_password_policy()

        return{
            "control_id": "IAM-001",
            "title": "IAM password policy exists",
            "service": "IAM",
            "status": "PASS",
            "severity": "Medium",
            "evidence": "IAM password policy is configured.",
            "remediation": "No action required."
        }
    
    except ClientError as error:
        if error.response['Error']['Code'] == 'NoSuchEntity':
            return{
                "control_id": "IAM-001",
                "title": "IAM password policy exists",
                "service": "IAM",
                "status": "FAIL",
                "severity": "Medium",
                "evidence": "No IAM password policy is found.",
                "remediation": "Create an IAM Account password policy."
            }
        return{
            "control_id": "IAM-001",
            "title": "IAM password policy exists",
            "service": "IAM",
            "status": "ERROR",
            "severity": "Medium",
            "evidence": str(error),
            "remediation": "Review AWS Credentials and IAM permissions."
        }
def check_old_access_keys():
    iam = boto3.client("iam")
    max_key_age_days = 90

    try:
        users = iam.list_users()["Users"]
        old_keys = []

        for user in users:
            username = user["UserName"]
            keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]

            for key in keys:
                created_date = key["CreateDate"]
                age_days = (datetime.now(timezone.utc) - created_date).days

                if age_days > max_key_age_days:
                    old_keys.append(
                        f"{username} has access key {key['AccessKeyId']} aged {age_days} days"
                    )

        if old_keys:
            return {
                "control_id": "IAM-002",
                "title": "IAM access keys should be rotated every 90 days",
                "service": "IAM",
                "status": "FAIL",
                "severity": "High",
                "evidence": "; ".join(old_keys),
                "remediation": "Rotate or delete access keys older than 90 days."
            }

        return {
            "control_id": "IAM-002",
            "title": "IAM access keys should be rotated every 90 days",
            "service": "IAM",
            "status": "PASS",
            "severity": "High",
            "evidence": "No IAM access keys older than 90 days found.",
            "remediation": "No action required."
        }

    except ClientError as error:
        return {
            "control_id": "IAM-002",
            "title": "IAM access keys should be rotated every 90 days",
            "service": "IAM",
            "status": "ERROR",
            "severity": "High",
            "evidence": str(error),
            "remediation": "Review AWS credentials and IAM permissions."
        }