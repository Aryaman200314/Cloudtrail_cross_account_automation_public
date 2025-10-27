#!/usr/bin/env python3
"""
CloudTrail Multi-Account Automation (final version)
- Uses values from config.yaml for role_name and trail_name.
- Creates/updates cross-account trails writing to a central S3 bucket.
- No S3 prefix used.
- Skips accounts where the same trail name already exists.
"""

import argparse
import json
import sys
from typing import Dict, Any, List, Optional

import boto3
from botocore.exceptions import ClientError
import yaml


# -----------------------
# Load configuration
# -----------------------
def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r") as f:
        cfg = yaml.safe_load(f)

    required_keys = ["s3_bucket_name", "account_ids", "role_name", "trail_name"]
    for k in required_keys:
        if k not in cfg:
            raise ValueError(f"Missing required config key: '{k}'")

    cfg.setdefault("region", "us-east-1")
    cfg.setdefault("log_file_validation", True)
    cfg.setdefault("multi_region_trail", True)
    cfg.setdefault("global_service_events", True)

    # Parse account IDs
    account_ids = [a.strip() for a in cfg["account_ids"].split(",") if a.strip()]
    cfg["accounts"] = [{"account_id": a} for a in account_ids]

    return cfg


# -----------------------
# STS AssumeRole
# -----------------------
def assume_role(account_id: str, role_name: str) -> Dict[str, str]:
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    sts = boto3.client("sts")
    creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="CloudTrailSetup")["Credentials"]
    return {
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    }


# -----------------------
# S3 bucket helpers
# -----------------------
def bucket_exists(s3_client, bucket: str) -> bool:
    try:
        s3_client.head_bucket(Bucket=bucket)
        return True
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("404", "NoSuchBucket", "NotFound"):
            return False
        raise


def get_bucket_policy(s3_client, bucket: str) -> Optional[Dict[str, Any]]:
    try:
        resp = s3_client.get_bucket_policy(Bucket=bucket)
        return json.loads(resp["Policy"])
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchBucketPolicy", "NoSuchEntity"):
            return None
        raise


def put_bucket_policy(s3_client, bucket: str, policy: Dict[str, Any]) -> None:
    s3_client.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    print(f"[S3] Updated bucket policy on {bucket}")


def build_bucket_policy(bucket: str, account_ids: List[str], region: str) -> Dict[str, Any]:
    """Builds a fully valid cross-account CloudTrail bucket policy."""
    put_resources = [f"arn:aws:s3:::{bucket}/AWSLogs/{aid}/*" for aid in account_ids]
    source_arns = [f"arn:aws:cloudtrail:*:{aid}:trail/*" for aid in account_ids]

    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
                "Condition": {
                    "StringLike": {
                        "aws:SourceArn": source_arns
                    }
                }
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": put_resources,
                "Condition": {
                    "StringLike": {
                        "aws:SourceArn": source_arns,
                        "s3:x-amz-acl": "bucket-owner-full-control"
                    }
                }
            }
        ]
    }



def verify_and_update_bucket_policy(bucket_name: str, account_ids: List[str], cfg: Dict[str, Any]) -> None:
    s3 = boto3.client("s3")
    if not bucket_exists(s3, bucket_name):
        raise RuntimeError(f"S3 bucket '{bucket_name}' does not exist or is not accessible.")
    print(f"[S3] Verified bucket exists: {bucket_name}")

    existing = get_bucket_policy(s3, bucket_name)
    desired = build_bucket_policy(bucket_name, account_ids, cfg["region"])

    if existing:
        sid_to_stmt = {s.get("Sid"): s for s in existing.get("Statement", [])}
        for stmt in desired["Statement"]:
            sid_to_stmt[stmt["Sid"]] = stmt
        merged = {"Version": "2012-10-17", "Statement": list(sid_to_stmt.values())}
        put_bucket_policy(s3, bucket_name, merged)
    else:
        put_bucket_policy(s3, bucket_name, desired)


# -----------------------
# CloudTrail helpers
# -----------------------
def get_trail(ct_client, name: str) -> Optional[Dict[str, Any]]:
    try:
        return ct_client.get_trail(Name=name).get("Trail")
    except ClientError as e:
        if e.response["Error"]["Code"] in ("TrailNotFoundException", "ResourceNotFoundException"):
            return None
        raise


def create_or_update_trail(ct_client, bucket: str, trail_name: str, cfg: Dict[str, Any]) -> None:
    existing = get_trail(ct_client, trail_name)
    if existing is not None:
        print(f"[CT] Skipping account — trail '{trail_name}' already exists")
        return

    kwargs = {
        "Name": trail_name,
        "S3BucketName": bucket,
        "IncludeGlobalServiceEvents": cfg["global_service_events"],
        "IsMultiRegionTrail": cfg["multi_region_trail"],
        "EnableLogFileValidation": cfg["log_file_validation"],
    }

    print(f"[CT] Creating trail '{trail_name}' → bucket:{bucket} (no prefix)")
    ct_client.create_trail(**kwargs)

    ct_client.put_event_selectors(
        TrailName=trail_name,
        EventSelectors=[{"ReadWriteType": "All", "IncludeManagementEvents": True}],
    )

    ct_client.start_logging(Name=trail_name)
    print(f"[CT] Started logging on '{trail_name}'")


# -----------------------
# Main
# -----------------------
def main():
    parser = argparse.ArgumentParser(description="Multi-account CloudTrail setup (config-based)")
    parser.add_argument("--config", "-c", required=True, help="Path to config.yaml")
    args = parser.parse_args()

    try:
        cfg = load_config(args.config)
        role_name = cfg["role_name"]
        trail_name = cfg["trail_name"]
        bucket_name = cfg["s3_bucket_name"]

        verify_and_update_bucket_policy(bucket_name, [a["account_id"] for a in cfg["accounts"]], cfg)

        for acct in cfg["accounts"]:
            acct_id = acct["account_id"]
            print(f"\n=== Processing account {acct_id} / trail {trail_name} ===")

            creds = assume_role(acct_id, role_name)
            ct = boto3.client(
                "cloudtrail",
                region_name=cfg["region"],
                aws_access_key_id=creds["aws_access_key_id"],
                aws_secret_access_key=creds["aws_secret_access_key"],
                aws_session_token=creds["aws_session_token"],
            )

            create_or_update_trail(ct, bucket_name, trail_name, cfg)

        print("\nAll done ✅")
        print("\nProcessed accounts:")
        for acct in cfg["accounts"]:
            print(f"- {acct['account_id']} (Trail: {trail_name}, Role: {role_name})")

    except Exception as e:
        print(f"\nERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
