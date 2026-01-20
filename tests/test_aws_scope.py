"""
Tests for AWS scope building and account ID retrieval.

These tests verify that:
- AWS account ID is properly retrieved via STS
- AWS scope includes account ID and region for multi-account/multi-region isolation
- S3 and other global resources get proper scope from account ID + configured region
"""
from unittest.mock import patch, MagicMock

import pytest

from run import get_aws_account_id, build_scope_from_resource_id


class TestGetAwsAccountId:
    """Tests for get_aws_account_id function"""

    @patch.dict('sys.modules', {'boto3': MagicMock()})
    def test_returns_account_id_from_sts(self):
        """Should return account ID from STS GetCallerIdentity"""
        import sys
        mock_boto3 = sys.modules['boto3']
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {
            'Account': '123456789012',
            'UserId': 'AROA...',
            'Arn': 'arn:aws:iam::123456789012:role/test-role'
        }
        mock_boto3.client.return_value = mock_sts

        result = get_aws_account_id()

        assert result == '123456789012'
        mock_boto3.client.assert_called_once_with('sts')

    @patch.dict('sys.modules', {'boto3': MagicMock()})
    def test_returns_none_when_sts_fails(self):
        """Should return None when STS call fails"""
        import sys
        mock_boto3 = sys.modules['boto3']
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.side_effect = Exception("Access denied")
        mock_boto3.client.return_value = mock_sts

        result = get_aws_account_id()

        assert result is None

    @patch.dict('sys.modules', {'boto3': MagicMock()})
    def test_returns_none_when_no_account_in_response(self):
        """Should return None when response has no Account field"""
        import sys
        mock_boto3 = sys.modules['boto3']
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {}
        mock_boto3.client.return_value = mock_sts

        result = get_aws_account_id()

        assert result is None


class TestBuildScopeFromResourceId:
    """Tests for build_scope_from_resource_id with AWS resources"""

    def test_aws_scope_includes_account_and_region_from_arn(self):
        """AWS scope should include both account and region from ARN"""
        config = {
            'cloud_provider': 'aws',
            'targets': {
                'aws': {
                    'account_id': '999999999999',  # Different from ARN
                    'regions': ['eu-west-1']  # Different from ARN
                }
            }
        }
        # EC2 ARN has both region and account
        resource_id = 'arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0'

        scope = build_scope_from_resource_id(resource_id, config)

        # Should use account and region from ARN
        assert scope == 'aws:account/123456789012/region/us-east-1'

    def test_aws_scope_uses_config_for_s3_global_resources(self):
        """S3 buckets (global) should use account from config and region from config"""
        config = {
            'cloud_provider': 'aws',
            'targets': {
                'aws': {
                    'account_id': '123456789012',
                    'regions': ['eu-west-1']
                }
            }
        }
        # S3 ARNs don't have region or account: arn:aws:s3:::bucket-name
        resource_id = 'arn:aws:s3:::my-bucket'

        scope = build_scope_from_resource_id(resource_id, config)

        assert scope == 'aws:account/123456789012/region/eu-west-1'

    def test_aws_scope_extracts_account_from_arn_region_from_config(self):
        """When ARN has account but no region, use config region"""
        config = {
            'cloud_provider': 'aws',
            'targets': {
                'aws': {
                    'account_id': '999999999999',
                    'regions': ['ap-southeast-1']
                }
            }
        }
        # IAM ARN has account but no region (global service)
        resource_id = 'arn:aws:iam::123456789012:role/my-role'

        scope = build_scope_from_resource_id(resource_id, config)

        # Account from ARN, region from config
        assert scope == 'aws:account/123456789012/region/ap-southeast-1'

    def test_aws_scope_unknown_account_when_not_available(self):
        """AWS scope should use 'unknown' when no account ID available"""
        config = {
            'cloud_provider': 'aws',
            'targets': {
                'aws': {
                    'regions': ['eu-west-1']
                    # No account_id
                }
            }
        }
        resource_id = 'arn:aws:s3:::my-bucket'

        scope = build_scope_from_resource_id(resource_id, config)

        assert scope == 'aws:account/unknown/region/eu-west-1'

    def test_azure_scope_unchanged(self):
        """Azure scope should still use subscription/resourceGroup format"""
        config = {
            'cloud_provider': 'azure',
            'targets': {
                'azure': {
                    'subscriptions': ['sub-123-456']
                }
            }
        }
        resource_id = '/subscriptions/sub-123-456/resourceGroups/my-rg/providers/Microsoft.Compute/virtualMachines/my-vm'

        scope = build_scope_from_resource_id(resource_id, config)

        assert scope == 'azure:subscription/sub-123-456/resourceGroup/my-rg'

    def test_multi_account_isolation(self):
        """Different AWS accounts should produce different scopes"""
        # Account A in eu-west-1
        config_a = {
            'cloud_provider': 'aws',
            'targets': {'aws': {'account_id': '111111111111', 'regions': ['eu-west-1']}}
        }
        # Account B in eu-west-1
        config_b = {
            'cloud_provider': 'aws',
            'targets': {'aws': {'account_id': '222222222222', 'regions': ['eu-west-1']}}
        }
        # Same bucket name (different accounts)
        resource_id = 'arn:aws:s3:::shared-bucket-name'

        scope_a = build_scope_from_resource_id(resource_id, config_a)
        scope_b = build_scope_from_resource_id(resource_id, config_b)

        assert scope_a != scope_b
        assert scope_a == 'aws:account/111111111111/region/eu-west-1'
        assert scope_b == 'aws:account/222222222222/region/eu-west-1'

    def test_multi_region_isolation(self):
        """Same account in different regions should produce different scopes"""
        # Same account, different regions
        config_us = {
            'cloud_provider': 'aws',
            'targets': {'aws': {'account_id': '123456789012', 'regions': ['us-east-1']}}
        }
        config_eu = {
            'cloud_provider': 'aws',
            'targets': {'aws': {'account_id': '123456789012', 'regions': ['eu-west-1']}}
        }
        # S3 bucket (global, so uses config region)
        resource_id = 'arn:aws:s3:::my-bucket'

        scope_us = build_scope_from_resource_id(resource_id, config_us)
        scope_eu = build_scope_from_resource_id(resource_id, config_eu)

        assert scope_us != scope_eu
        assert scope_us == 'aws:account/123456789012/region/us-east-1'
        assert scope_eu == 'aws:account/123456789012/region/eu-west-1'

    def test_regional_resources_use_arn_region(self):
        """Regional resources should use region from ARN, not config"""
        config = {
            'cloud_provider': 'aws',
            'targets': {'aws': {'account_id': '123456789012', 'regions': ['eu-west-1']}}
        }
        # EC2 instance in us-west-2 (different from config)
        resource_id = 'arn:aws:ec2:us-west-2:123456789012:instance/i-abc123'

        scope = build_scope_from_resource_id(resource_id, config)

        # Should use region from ARN, not config
        assert scope == 'aws:account/123456789012/region/us-west-2'

    def test_multi_account_multi_region_full_isolation(self):
        """Full test: different accounts deploying to multiple regions"""
        # Dev account scans eu-west-1
        config_dev_eu = {
            'cloud_provider': 'aws',
            'targets': {'aws': {'account_id': '111111111111', 'regions': ['eu-west-1']}}
        }
        # Dev account scans us-west-1
        config_dev_us = {
            'cloud_provider': 'aws',
            'targets': {'aws': {'account_id': '111111111111', 'regions': ['us-west-1']}}
        }
        # Prod account scans eu-west-1
        config_prod_eu = {
            'cloud_provider': 'aws',
            'targets': {'aws': {'account_id': '222222222222', 'regions': ['eu-west-1']}}
        }

        s3_bucket = 'arn:aws:s3:::my-bucket'

        scope_dev_eu = build_scope_from_resource_id(s3_bucket, config_dev_eu)
        scope_dev_us = build_scope_from_resource_id(s3_bucket, config_dev_us)
        scope_prod_eu = build_scope_from_resource_id(s3_bucket, config_prod_eu)

        # All three should be different
        assert len({scope_dev_eu, scope_dev_us, scope_prod_eu}) == 3
        assert scope_dev_eu == 'aws:account/111111111111/region/eu-west-1'
        assert scope_dev_us == 'aws:account/111111111111/region/us-west-1'
        assert scope_prod_eu == 'aws:account/222222222222/region/eu-west-1'
