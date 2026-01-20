"""
Tests for AWS scope building and account ID retrieval.

These tests verify that:
- AWS account ID is properly retrieved via STS
- AWS scope includes account ID for multi-account isolation
- S3 and other global resources get proper scope from account ID
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

    def test_aws_scope_uses_account_id_from_config(self):
        """AWS scope should use account ID from config for S3 buckets"""
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

        assert scope == 'aws:account/123456789012'

    def test_aws_scope_extracts_account_from_arn(self):
        """AWS scope should extract account ID from ARN when available"""
        config = {
            'cloud_provider': 'aws',
            'targets': {
                'aws': {
                    'account_id': '999999999999',  # Different from ARN
                    'regions': ['us-east-1']
                }
            }
        }
        # EC2 ARN has account ID at position 4
        resource_id = 'arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0'

        scope = build_scope_from_resource_id(resource_id, config)

        # Should use account from ARN
        assert scope == 'aws:account/123456789012'

    def test_aws_scope_falls_back_to_config_account(self):
        """AWS scope should fall back to config account ID when ARN has no account"""
        config = {
            'cloud_provider': 'aws',
            'targets': {
                'aws': {
                    'account_id': '987654321098',
                    'regions': ['eu-west-1']
                }
            }
        }
        # S3 ARN has no account
        resource_id = 'arn:aws:s3:::my-bucket'

        scope = build_scope_from_resource_id(resource_id, config)

        assert scope == 'aws:account/987654321098'

    def test_aws_scope_unknown_when_no_account_available(self):
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

        assert scope == 'aws:account/unknown'

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
        # Account A
        config_a = {
            'cloud_provider': 'aws',
            'targets': {'aws': {'account_id': '111111111111'}}
        }
        # Account B
        config_b = {
            'cloud_provider': 'aws',
            'targets': {'aws': {'account_id': '222222222222'}}
        }
        # Same bucket name (different accounts)
        resource_id = 'arn:aws:s3:::shared-bucket-name'

        scope_a = build_scope_from_resource_id(resource_id, config_a)
        scope_b = build_scope_from_resource_id(resource_id, config_b)

        assert scope_a != scope_b
        assert scope_a == 'aws:account/111111111111'
        assert scope_b == 'aws:account/222222222222'
