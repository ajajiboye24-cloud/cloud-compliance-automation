import boto3 
from botocore.exceptions import ClientError

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