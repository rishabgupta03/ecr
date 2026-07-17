#!/usr/bin/env python3
"""
Control: ECR Repository Latest Image Has No Vulnerabilities At Or Above
Minimum Severity

FIX vs. previous version: the original script only called
describe_image_scan_findings (the BASIC scanning API). If a repository
is configured for ENHANCED scanning (Amazon Inspector), that API always
returns ScanNotFoundException regardless of whether the image was
actually scanned - because Inspector's results live in a completely
separate API. That produced misleading "Latest image has not been
scanned" SKIPPED rows even for images Inspector had already scanned.

This version calls batch_get_repository_scanning_configuration per
repository to find out which scan type is actually configured, then
branches:
  - BASIC    -> describe_image_scan_findings (unchanged from before)
  - ENHANCED -> Inspector2 list_findings, filtered to the exact image
                digest, aggregated into the same severity_counts shape
                so the existing has_findings_at_or_above() logic works
                unchanged for both paths.

Evidence now always states which scan type was used, so the CSV is
self-explanatory rather than requiring cross-referencing another script.
"""

import boto3
import argparse
import csv
from tqdm import tqdm
from botocore.exceptions import ClientError, BotoCoreError

CONTROL_NAME = "ECR Repository Latest Image Has No Vulnerabilities At Or Above Minimum Severity"

# Order matters: index position = severity rank, used to compare
# against the configured minimum severity threshold.
SEVERITY_ORDER = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

BATCH_SIZE = 100  # AWS limit for batch_get_repository_scanning_configuration

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
    """Maps a boto3/botocore exception to (status, evidence)."""
    if isinstance(e, ClientError):
        code = e.response.get("Error", {}).get("Code", "UnknownError")

        if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
            return "SKIPPED", f"Access denied while querying AWS ({code})"

        if code in ("Throttling", "ThrottlingException"):
            return "SKIPPED", f"Throttled by AWS API ({code})"

        if code == "RepositoryNotFoundException":
            return "SKIPPED", "Repository no longer exists"

        if code == "ImageNotFoundException":
            return "SKIPPED", "Latest image no longer exists"

        if code == "ScanNotFoundException":
            return "SKIPPED", "Image has not been scanned"

        return "SKIPPED", f"Could not evaluate resource: {code}"

    if isinstance(e, BotoCoreError):
        return "SKIPPED", f"Could not reach AWS endpoint: {e}"

    return "SKIPPED", f"Unexpected error: {e}"


def get_latest_image(client, repo_name):
    """
    Returns the image detail dict for the most recently pushed image
    in a repository (by imagePushedAt), or None if the repository has
    no images.
    """
    latest = None

    paginator = client.get_paginator("describe_images")
    for page in paginator.paginate(repositoryName=repo_name):
        for image in page.get("imageDetails", []):
            pushed_at = image.get("imagePushedAt")
            if pushed_at is None:
                continue
            if latest is None or pushed_at > latest.get("imagePushedAt"):
                latest = image

    return latest


def has_findings_at_or_above(severity_counts, threshold):
    threshold_rank = SEVERITY_ORDER.index(threshold)

    for severity, count in (severity_counts or {}).items():
        if severity in SEVERITY_ORDER and count > 0:
            if SEVERITY_ORDER.index(severity) >= threshold_rank:
                return True

    return False


def get_repo_scan_types(ecr_client, repo_names):
    """
    Returns {repo_name: "BASIC" | "ENHANCED"} by calling
    batch_get_repository_scanning_configuration in chunks of BATCH_SIZE.
    Repos that fail to resolve default to "BASIC" (the original, and
    still far more common, scanning type) so they still get evaluated
    via the old code path rather than silently dropped.
    """
    scan_types = {}

    for i in range(0, len(repo_names), BATCH_SIZE):
        chunk = repo_names[i:i + BATCH_SIZE]
        try:
            resp = ecr_client.batch_get_repository_scanning_configuration(
                repositoryNames=chunk
            )
            for cfg in resp.get("scanningConfigurations", []):
                scan_types[cfg["repositoryName"]] = cfg.get("scanType", "BASIC")
        except (ClientError, BotoCoreError):
            # Can't determine scan type for this chunk - fall back to
            # BASIC per repo so evaluation still proceeds normally.
            for name in chunk:
                scan_types.setdefault(name, "BASIC")

    return scan_types


def get_basic_scan_findings(ecr_client, repo_name, image_digest, severity_threshold):
    """
    Original BASIC-scanning path. Returns (status, evidence).
    """
    findings = ecr_client.describe_image_scan_findings(
        repositoryName=repo_name,
        imageId={"imageDigest": image_digest}
    )

    scan_status = findings.get("imageScanStatus", {}).get("status", "UNKNOWN")

    if scan_status != "COMPLETE":
        return "SKIPPED", f"Latest image scan status is '{scan_status}', not COMPLETE (Basic scanning)"

    severity_counts = findings.get("imageScanFindings", {}).get("findingSeverityCounts", {})

    if has_findings_at_or_above(severity_counts, severity_threshold):
        return (
            "NON_COMPLIANT",
            f"Latest image has findings at or above {severity_threshold} "
            f"(Basic scanning): {severity_counts}"
        )

    return (
        "COMPLIANT",
        f"Latest image has no findings at or above {severity_threshold} (Basic scanning)"
    )


def get_enhanced_scan_findings(inspector_client, repo_name, image_digest, severity_threshold):
    """
    ENHANCED-scanning path via Inspector2. Aggregates individual
    findings into the same severity_counts shape used by the Basic
    path so has_findings_at_or_above() works unchanged for both.
    """
    filter_criteria = {
        "resourceType": [{"comparison": "EQUALS", "value": "AWS_ECR_CONTAINER_IMAGE"}],
        "ecrImageRepositoryName": [{"comparison": "EQUALS", "value": repo_name}],
        "ecrImageHash": [{"comparison": "EQUALS", "value": image_digest}],
        "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
    }

    severity_counts = {}
    paginator = inspector_client.get_paginator("list_findings")
    for page in paginator.paginate(filterCriteria=filter_criteria):
        for finding in page.get("findings", []):
            severity = finding.get("severity", "UNKNOWN")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

    if has_findings_at_or_above(severity_counts, severity_threshold):
        return (
            "NON_COMPLIANT",
            f"Latest image has findings at or above {severity_threshold} "
            f"(Enhanced scanning / Inspector): {severity_counts}"
        )

    return (
        "COMPLIANT",
        f"Latest image has no findings at or above {severity_threshold} (Enhanced scanning / Inspector)"
    )


def evaluate_repository(ecr_client, inspector_client, repo_name, scan_type, severity_threshold):
    """
    Returns (status, evidence) for a single repository's latest image,
    routing to the correct scan-results API based on its scan_type.
    """
    latest_image = get_latest_image(ecr_client, repo_name)

    if latest_image is None:
        return "SKIPPED", "Repository has no images"

    image_digest = latest_image["imageDigest"]

    try:
        if scan_type == "ENHANCED":
            return get_enhanced_scan_findings(
                inspector_client, repo_name, image_digest, severity_threshold
            )
        return get_basic_scan_findings(
            ecr_client, repo_name, image_digest, severity_threshold
        )

    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code == "ScanNotFoundException":
            return "SKIPPED", "Latest image has not been scanned (Basic scanning)"
        if code in ("AccessDeniedException", "AccessDenied") and scan_type == "ENHANCED":
            return "SKIPPED", "Inspector2 access denied or not enabled for this account/region"
        return classify_error(e)

    except BotoCoreError as e:
        return classify_error(e)


# ==================================================
# CONTROL LOGIC
# ==================================================
def check_control(session, severity_threshold):
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
            ecr_client = session.client("ecr", region_name=region)
            inspector_client = session.client("inspector2", region_name=region)
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
            repo_paginator = ecr_client.get_paginator("describe_repositories")
            repos = []
            for page in repo_paginator.paginate():
                repos.extend(page.get("repositories", []))
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

        if not repos:
            continue

        repo_names = [r.get("repositoryName") for r in repos if r.get("repositoryName")]
        scan_types = get_repo_scan_types(ecr_client, repo_names)

        for repo in repos:
            repo_name = repo.get("repositoryName", "N/A")
            repo_arn = repo.get("repositoryArn", "N/A")
            scan_type = scan_types.get(repo_name, "BASIC")

            total_checked += 1

            try:
                status, evidence = evaluate_repository(
                    ecr_client, inspector_client, repo_name, scan_type, severity_threshold
                )
            except (ClientError, BotoCoreError) as e:
                status, evidence = classify_error(e)

            if status == "COMPLIANT":
                compliant += 1
            elif status == "NON_COMPLIANT":
                non_compliant += 1
            else:
                skipped += 1

            results.append({
                "Account": account_id,
                "Region": region,
                "ResourceId": repo_name,
                "ResourceArn": repo_arn,
                "Status": status,
                "Evidence": evidence
            })

    return results, total_checked, compliant, non_compliant, skipped, account_id


# ==================================================
# CSV
# ==================================================
def write_csv(results, account_id):
    filename = f"ecr_repositories_scan_vulnerabilities_in_latest_image_{account_id}.csv"

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
        description="Check whether each ECR repository's latest image has no vulnerabilities at or above a minimum severity."
    )
    parser.add_argument("-R", "--role-arn", help="IAM Role ARN to assume", default=None)
    parser.add_argument(
        "--severity-threshold",
        choices=SEVERITY_ORDER,
        default="CRITICAL",
        help="Minimum severity that triggers NON_COMPLIANT (default: CRITICAL)"
    )
    args = parser.parse_args()

    session = get_session(args.role_arn)

    results, total_checked, compliant, non_compliant, skipped, account_id = check_control(
        session, args.severity_threshold
    )

    overall = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"

    csv_file = write_csv(results, account_id)

    print("\n" + "=" * 52)
    print(f"CONTROL: {CONTROL_NAME}")
    print(f"ACCOUNT: {account_id}")
    print(f"SEVERITY THRESHOLD: {args.severity_threshold}")
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
