"""Tests for extract_resource_id with new AWS resource types.

Regression guard for issue #10 on playground-flux-prod: VPC findings showed
'unknown' as the affected resource because VpcId had no ARN-builder case.
"""
import pytest
from run import extract_resource_id


AWS_CFG = {"cloud_provider": "aws"}


class TestExtractResourceIdNewAwsResources:

    def test_vpc_builds_arn_from_vpcid(self):
        r = {"VpcId": "vpc-0abc123", "Region": "us-east-1"}
        assert extract_resource_id(r, AWS_CFG) == "arn:aws:ec2:us-east-1::vpc/vpc-0abc123"

    def test_vpc_endpoint_builds_arn(self):
        r = {"VpcEndpointId": "vpce-0deadbeef", "VpcId": "vpc-0abc", "Region": "eu-west-1"}
        assert extract_resource_id(r, AWS_CFG) == "arn:aws:ec2:eu-west-1::vpc-endpoint/vpce-0deadbeef"

    def test_ami_builds_arn(self):
        r = {"ImageId": "ami-0123", "Region": "us-west-2"}
        assert extract_resource_id(r, AWS_CFG) == "arn:aws:ec2:us-west-2::image/ami-0123"

    def test_efs_builds_arn(self):
        r = {"FileSystemId": "fs-0abc", "Region": "us-east-1"}
        assert extract_resource_id(r, AWS_CFG) == "arn:aws:elasticfilesystem:us-east-1::file-system/fs-0abc"

    def test_elasticache_builds_arn(self):
        r = {"CacheClusterId": "redis-prod-001", "Region": "us-east-1"}
        assert extract_resource_id(r, AWS_CFG) == "arn:aws:elasticache:us-east-1::cluster/redis-prod-001"

    def test_rds_snapshot_prefers_arn(self):
        r = {
            "DBSnapshotArn": "arn:aws:rds:us-east-1:123:snapshot:my-snap",
            "DBSnapshotIdentifier": "my-snap",
            "Region": "us-east-1",
        }
        assert extract_resource_id(r, AWS_CFG) == "arn:aws:rds:us-east-1:123:snapshot:my-snap"

    def test_rds_snapshot_falls_back_to_id(self):
        r = {"DBSnapshotIdentifier": "nightly-snap", "Region": "us-east-1"}
        assert extract_resource_id(r, AWS_CFG) == "arn:aws:rds:us-east-1::snapshot/nightly-snap"

    def test_iam_user_arn_wins(self):
        r = {"UserName": "alice", "Arn": "arn:aws:iam::123456789012:user/alice"}
        assert extract_resource_id(r, AWS_CFG) == "arn:aws:iam::123456789012:user/alice"

    def test_iam_user_without_arn_builds_one(self):
        r = {"UserName": "alice"}
        assert extract_resource_id(r, AWS_CFG) == "arn:aws:iam:::user/alice"

    def test_vpc_region_falls_back_to_env(self, monkeypatch):
        monkeypatch.setenv("AWS_REGION", "ap-southeast-2")
        r = {"VpcId": "vpc-xyz"}
        assert extract_resource_id(r, AWS_CFG) == "arn:aws:ec2:ap-southeast-2::vpc/vpc-xyz"
