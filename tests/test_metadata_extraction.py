"""
Tests for metadata extraction from Cloud Custodian resources.

These tests verify that:
- Azure tags (dict format) are properly extracted
- AWS tags (list of Key/Value dicts) are properly converted to dict format
- Resource IDs are properly parsed for both Azure and AWS
"""
import pytest

from run import extract_resource_metadata


class TestExtractResourceMetadataAzure:
    """Tests for Azure resource metadata extraction"""

    def test_azure_tags_dict_format(self):
        """Azure tags in dict format should be extracted directly"""
        resource = {
            'tags': {
                'Environment': 'Production',
                'Team': 'DevOps',
                'CostCenter': '12345'
            },
            'location': 'westeurope'
        }
        resource_id = '/subscriptions/sub-123/resourceGroups/my-rg/providers/Microsoft.Storage/storageAccounts/mystorageaccount'

        metadata = extract_resource_metadata(resource, resource_id)

        assert metadata['tags'] == {
            'Environment': 'Production',
            'Team': 'DevOps',
            'CostCenter': '12345'
        }
        assert metadata['subscriptionId'] == 'sub-123'
        assert metadata['resourceGroup'] == 'my-rg'
        assert metadata['location'] == 'westeurope'

    def test_azure_empty_tags(self):
        """Azure resource with no tags should not have tags in metadata"""
        resource = {
            'tags': {},
            'location': 'eastus'
        }
        resource_id = '/subscriptions/sub-456/resourceGroups/rg-test/providers/Microsoft.Compute/virtualMachines/vm1'

        metadata = extract_resource_metadata(resource, resource_id)

        assert 'tags' not in metadata
        assert metadata['location'] == 'eastus'


class TestExtractResourceMetadataAws:
    """Tests for AWS resource metadata extraction"""

    def test_aws_tags_list_format(self):
        """AWS tags in list format should be converted to dict"""
        resource = {
            'Name': 'my-bucket',
            'Tags': [
                {'Key': 'Environment', 'Value': 'Production'},
                {'Key': 'Team', 'Value': 'Platform'},
                {'Key': 'Owner', 'Value': 'devops@example.com'}
            ]
        }
        resource_id = 'arn:aws:s3:::my-bucket'

        metadata = extract_resource_metadata(resource, resource_id)

        assert metadata['tags'] == {
            'Environment': 'Production',
            'Team': 'Platform',
            'Owner': 'devops@example.com'
        }

    def test_aws_tags_lowercase_keys(self):
        """AWS tags with lowercase key/value should also work"""
        resource = {
            'Name': 'test-bucket',
            'Tags': [
                {'key': 'env', 'value': 'dev'},
                {'key': 'app', 'value': 'myapp'}
            ]
        }
        resource_id = 'arn:aws:s3:::test-bucket'

        metadata = extract_resource_metadata(resource, resource_id)

        assert metadata['tags'] == {
            'env': 'dev',
            'app': 'myapp'
        }

    def test_aws_tags_mixed_case_keys(self):
        """AWS tags with mixed case Key/value should work"""
        resource = {
            'Name': 'mixed-bucket',
            'Tags': [
                {'Key': 'Environment', 'value': 'staging'}
            ]
        }
        resource_id = 'arn:aws:s3:::mixed-bucket'

        metadata = extract_resource_metadata(resource, resource_id)

        assert metadata['tags'] == {
            'Environment': 'staging'
        }

    def test_aws_empty_tags_list(self):
        """AWS resource with empty tags list should not have tags in metadata"""
        resource = {
            'Name': 'untagged-bucket',
            'Tags': []
        }
        resource_id = 'arn:aws:s3:::untagged-bucket'

        metadata = extract_resource_metadata(resource, resource_id)

        # Metadata may be None or dict without tags key
        assert metadata is None or 'tags' not in metadata

    def test_aws_no_tags_field(self):
        """AWS resource without Tags field should not have tags in metadata"""
        resource = {
            'Name': 'no-tags-bucket'
        }
        resource_id = 'arn:aws:s3:::no-tags-bucket'

        metadata = extract_resource_metadata(resource, resource_id)

        # Metadata may be None or dict without tags key
        assert metadata is None or 'tags' not in metadata

    def test_aws_lowercase_tags_field(self):
        """AWS resource with lowercase 'tags' field should also work"""
        resource = {
            'Name': 'lowercase-bucket',
            'tags': [
                {'Key': 'Environment', 'Value': 'test'}
            ]
        }
        resource_id = 'arn:aws:s3:::lowercase-bucket'

        metadata = extract_resource_metadata(resource, resource_id)

        assert metadata['tags'] == {
            'Environment': 'test'
        }

    def test_aws_s3_bucket_extracts_account_from_arn(self):
        """S3 bucket ARN doesn't have region/account but should handle gracefully"""
        resource = {
            'Name': 'my-bucket',
            'Tags': [
                {'Key': 'env', 'Value': 'prod'}
            ]
        }
        # S3 ARN format doesn't include region or account: arn:aws:s3:::bucket-name
        resource_id = 'arn:aws:s3:::my-bucket'

        metadata = extract_resource_metadata(resource, resource_id)

        # S3 ARN doesn't have region/account, so these shouldn't be in metadata
        assert 'region' not in metadata
        assert 'accountId' not in metadata
        assert metadata['tags'] == {'env': 'prod'}

    def test_aws_ec2_extracts_region_and_account(self):
        """EC2 ARN should extract region and account"""
        resource = {
            'InstanceId': 'i-1234567890abcdef0',
            'Tags': [
                {'Key': 'Environment', 'Value': 'development'}
            ]
        }
        resource_id = 'arn:aws:ec2:eu-west-1:123456789012:instance/i-1234567890abcdef0'

        metadata = extract_resource_metadata(resource, resource_id)

        assert metadata['region'] == 'eu-west-1'
        assert metadata['accountId'] == '123456789012'
        assert metadata['tags'] == {'Environment': 'development'}


class TestExtractResourceMetadataEdgeCases:
    """Edge case tests for metadata extraction"""

    def test_tags_with_null_values(self):
        """Tags with null values should be skipped (only non-null values extracted)"""
        resource = {
            'Name': 'test',
            'Tags': [
                {'Key': 'Environment', 'Value': 'prod'},
                {'Key': 'Owner', 'Value': None}  # Null value - will be skipped
            ]
        }
        resource_id = 'arn:aws:s3:::test'

        metadata = extract_resource_metadata(resource, resource_id)

        # Null values are skipped
        assert metadata['tags'] == {'Environment': 'prod'}

    def test_tags_with_empty_string_values(self):
        """Tags with empty string values should be included"""
        resource = {
            'Name': 'test',
            'Tags': [
                {'Key': 'Environment', 'Value': 'prod'},
                {'Key': 'Description', 'Value': ''}  # Empty string - should be included
            ]
        }
        resource_id = 'arn:aws:s3:::test'

        metadata = extract_resource_metadata(resource, resource_id)

        # Empty string is a valid value (different from None)
        assert metadata['tags'] == {'Environment': 'prod', 'Description': ''}

    def test_tags_with_missing_key(self):
        """Tags with missing Key should be skipped"""
        resource = {
            'Name': 'test',
            'Tags': [
                {'Key': 'Environment', 'Value': 'prod'},
                {'Value': 'orphan'}  # Missing Key
            ]
        }
        resource_id = 'arn:aws:s3:::test'

        metadata = extract_resource_metadata(resource, resource_id)

        # Only the valid tag should be extracted
        assert metadata['tags'] == {'Environment': 'prod'}

    def test_malformed_tag_objects_are_skipped(self):
        """Malformed tag objects should be gracefully skipped"""
        resource = {
            'Name': 'test',
            'Tags': [
                {'Key': 'Good', 'Value': 'tag'},
                "not-a-dict",  # String instead of dict
                123,  # Number instead of dict
                None  # None
            ]
        }
        resource_id = 'arn:aws:s3:::test'

        metadata = extract_resource_metadata(resource, resource_id)

        assert metadata['tags'] == {'Good': 'tag'}

    def test_invalid_resource_id_handled_gracefully(self):
        """Invalid resource IDs should not crash"""
        resource = {
            'tags': {'env': 'test'}
        }
        resource_id = 'invalid-resource-id'

        metadata = extract_resource_metadata(resource, resource_id)

        # Should still extract tags
        assert metadata['tags'] == {'env': 'test'}

    def test_iam_arn_extracts_account_no_region(self):
        """IAM ARN (global service) should extract account but no region"""
        resource = {
            'RoleName': 'my-role',
            'Tags': [
                {'Key': 'Environment', 'Value': 'production'}
            ]
        }
        # IAM ARN format: account but no region
        resource_id = 'arn:aws:iam::123456789012:role/my-role'

        metadata = extract_resource_metadata(resource, resource_id)

        assert metadata['accountId'] == '123456789012'
        assert 'region' not in metadata  # IAM is global, no region in ARN
        assert metadata['tags'] == {'Environment': 'production'}
