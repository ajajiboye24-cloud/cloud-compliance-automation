import boto3
from botocore.exceptions import ClientError


def check_security_groups_open_to_risky_ports():
    ec2 = boto3.client("ec2")

    risky_ports = {
        22: "SSH",
        3389: "RDP",
        3306: "MySQL",
        5432: "PostgreSQL"
    }

    try:
        response = ec2.describe_security_groups()
        risky_findings = []

        for group in response["SecurityGroups"]:
            group_name = group.get("GroupName")
            group_id = group.get("GroupId")

            for permission in group.get("IpPermissions", []):
                from_port = permission.get("FromPort")
                to_port = permission.get("ToPort")

                for ip_range in permission.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp")

                    if cidr == "0.0.0.0/0":
                        for port, service in risky_ports.items():
                            if from_port is not None and to_port is not None:
                                if from_port <= port <= to_port:
                                    risky_findings.append(
                                        f"{group_name} ({group_id}) allows {service} port {port} from 0.0.0.0/0"
                                    )

        if risky_findings:
            return {
                "control_id": "EC2-001",
                "title": "Security groups should not expose risky ports to the internet",
                "service": "EC2",
                "status": "FAIL",
                "severity": "Critical",
                "evidence": "; ".join(risky_findings),
                "remediation": "Restrict inbound access to risky ports using trusted IP ranges, VPNs, or private networking."
            }

        return {
            "control_id": "EC2-001",
            "title": "Security groups should not expose risky ports to the internet",
            "service": "EC2",
            "status": "PASS",
            "severity": "Critical",
            "evidence": "No security groups expose risky ports to 0.0.0.0/0.",
            "remediation": "No action required."
        }

    except ClientError as error:
        return {
            "control_id": "EC2-001",
            "title": "Security groups should not expose risky ports to the internet",
            "service": "EC2",
            "status": "ERROR",
            "severity": "Critical",
            "evidence": str(error),
            "remediation": "Review AWS credentials and EC2 permissions."
        }