
#!/usr/bin/env python3

import boto3
import argparse
import csv
import json
from tqdm import tqdm
from botocore.exceptions import ClientError, BotoCoreError

CONTROL_NAME = "ECR Repository Is Not Publicly Accessible"

# ==================================================
# AUTH
# ==================================================

def get_session(role_arn=None):
    if role_arn:
        base = boto3.Session()
        sts = base.client("sts")

        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="control-audit"
        )

        creds = assumed["Credentials"]

        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]
        )

    return boto3.Session()


def get_account_id(session):
    return session.client("sts").get_caller_identity()["Account"]


# ==================================================
# REGIONS
# ==================================================

def get_regions(session):
    ec2 = session.client("ec2", region_name="us-east-1")

    regions = ec2.describe_regions(AllRegions=True)["Regions"]

    return [
        r["RegionName"]
        for r in regions
        if r.get("OptInStatus") in ["opt-in-not-required", "opted-in"]
    ]


# ==================================================
# HELPERS
# ==================================================

def classify_error(e):
    """
    Maps a boto3/botocore exception to (status, evidence).
    One small function instead of a long if/else chain repeated
    throughout the control logic.
    """
    if isinstance(e, ClientError):
        code = e.response.get("Error", {}).get("Code", "UnknownError")

        if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
            return "SKIPPED", f"Access denied while querying ECR ({code})"

        if code in ("Throttling", "ThrottlingException"):
            return "SKIPPED", f"Throttled by AWS API ({code})"

        if code == "RepositoryNotFoundException":
            return "SKIPPED", "Repository no longer exists"

        return "SKIPPED", f"Could not evaluate resource: {code}"

    if isinstance(e, BotoCoreError):
        return "SKIPPED", f"Could not reach ECR endpoint: {e}"

    return "SKIPPED", f"Unexpected error: {e}"


def policy_allows_public_access(policy_text):
    """
    Returns True if any Allow statement grants access to a wildcard
    principal ("*" or {"AWS": "*"}), which makes the repository
    accessible to anyone regardless of AWS identity.
    """
    policy = json.loads(policy_text)
    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue

        principal = stmt.get("Principal")

        if principal == "*":
            return True

        if isinstance(principal, dict):
            aws_principal = principal.get("AWS")
            if aws_principal == "*" or (isinstance(aws_principal, list) and "*" in aws_principal):
                return True

    return False


# ==================================================
# CONTROL LOGIC
# ==================================================

def check_control(session):

    account_id = get_account_id(session)
    regions = get_regions(session)

    results = []
    total_checked = 0
    compliant = 0
    non_compliant = 0
    skipped = 0

    print(f"\nRegions to Scan: {len(regions)}\n")

    for region in tqdm(regions, desc="Scanning Regions"):

        try:
            client = session.client("ecr", region_name=region)

        except (ClientError, BotoCoreError) as e:
            status, evidence = classify_error(e)
            skipped += 1
            results.append({
                "Account": account_id,
                "Region": region,
                "ResourceId": "N/A",
                "ResourceArn": "N/A",
                "Status": status,
                "Evidence": evidence
            })
            continue

        try:
            paginator = client.get_paginator("describe_repositories")

            for page in paginator.paginate():
                for repo in page.get("repositories", []):

                    repo_name = repo.get("repositoryName", "N/A")
                    repo_arn = repo.get("repositoryArn", "N/A")

                    total_checked += 1

                    try:
                        policy_resp = client.get_repository_policy(repositoryName=repo_name)
                        is_public = policy_allows_public_access(policy_resp["policyText"])

                        if is_public:
                            status = "NON_COMPLIANT"
                            non_compliant += 1
                            evidence = "Repository policy grants access to a wildcard (*) principal"
                        else:
                            status = "COMPLIANT"
                            compliant += 1
                            evidence = "Repository policy does not grant public access"

                    except ClientError as e:
                        code = e.response.get("Error", {}).get("Code", "")

                        if code == "RepositoryPolicyNotFoundException":
                            status = "COMPLIANT"
                            compliant += 1
                            evidence = "No repository policy attached, private by default"
                        else:
                            status, evidence = classify_error(e)
                            skipped += 1

                    except BotoCoreError as e:
                        status, evidence = classify_error(e)
                        skipped += 1

                    results.append({
                        "Account": account_id,
                        "Region": region,
                        "ResourceId": repo_name,
                        "ResourceArn": repo_arn,
                        "Status": status,
                        "Evidence": evidence
                    })

        except (ClientError, BotoCoreError) as e:
            status, evidence = classify_error(e)
            skipped += 1
            results.append({
                "Account": account_id,
                "Region": region,
                "ResourceId": "N/A",
                "ResourceArn": "N/A",
                "Status": status,
                "Evidence": evidence
            })

    return results, total_checked, compliant, non_compliant, skipped, account_id


# ==================================================
# CSV
# ==================================================

def write_csv(results, account_id):
    filename = f"ecr_repositories_not_publicly_accessible_{account_id}.csv"

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["Account", "Region", "ResourceId", "ResourceArn", "Status", "Evidence"]
        )
        writer.writeheader()
        writer.writerows(results)

    return filename


# ==================================================
# MAIN
# ==================================================

def main():
    parser = argparse.ArgumentParser(
        description="Check whether ECR repositories are not publicly accessible."
    )
    parser.add_argument("-R", "--role-arn", help="IAM Role ARN to assume", default=None)
    args = parser.parse_args()

    session = get_session(args.role_arn)

    results, total_checked, compliant, non_compliant, skipped, account_id = check_control(session)

    overall = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"

    csv_file = write_csv(results, account_id)

    print("\n" + "=" * 52)
    print(f"CONTROL: {CONTROL_NAME}")
    print(f"ACCOUNT: {account_id}")
    print("=" * 52)
    print(f"Total Checked   : {total_checked}")
    print(f"Compliant       : {compliant}")
    print(f"Non-Compliant   : {non_compliant}")
    print(f"Skipped         : {skipped}")
    print(f"Overall Status  : {overall}")
    print(f"CSV Generated   : {csv_file}")
    print("=" * 52 + "\n")


if __name__ == "__main__":
    main()
