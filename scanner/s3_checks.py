import boto3
from botocore.exceptions import ClientError


def check_s3_public_access_block():
    s3 = boto3.client("s3")

    try:
        buckets = s3.list_buckets()["Buckets"]

        if not buckets:
            return {
                "control_id": "S3-001",
                "title": "S3 buckets have public access block enabled",
                "service": "S3",
                "status": "PASS",
                "severity": "High",
                "evidence": "No S3 buckets found in the account.",
                "remediation": "No action required."
            }

        failed_buckets = []

        for bucket in buckets:
            bucket_name = bucket["Name"]

            try:
                response = s3.get_public_access_block(Bucket=bucket_name)
                config = response["PublicAccessBlockConfiguration"]

                required_settings = [
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets"
                ]

                for setting in required_settings:
                    if config.get(setting) is not True:
                        failed_buckets.append(bucket_name)
                        break

            except ClientError as error:
                if error.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                    failed_buckets.append(bucket_name)
                else:
                    failed_buckets.append(bucket_name)

        if failed_buckets:
            return {
                "control_id": "S3-001",
                "title": "S3 buckets have public access block enabled",
                "service": "S3",
                "status": "FAIL",
                "severity": "High",
                "evidence": f"Buckets missing full public access block: {', '.join(failed_buckets)}",
                "remediation": "Enable all S3 Block Public Access settings for the listed buckets."
            }

        return {
            "control_id": "S3-001",
            "title": "S3 buckets have public access block enabled",
            "service": "S3",
            "status": "PASS",
            "severity": "High",
            "evidence": "All S3 buckets have full public access block enabled.",
            "remediation": "No action required."
        }

    except ClientError as error:
        return {
            "control_id": "S3-001",
            "title": "S3 buckets have public access block enabled",
            "service": "S3",
            "status": "ERROR",
            "severity": "High",
            "evidence": str(error),
            "remediation": "Review AWS credentials and S3 permissions."
        }