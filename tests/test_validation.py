"""
Tests for input validation functions in run.py

These tests verify that all user inputs are properly validated to prevent:
- Injection attacks
- SSRF vulnerabilities  
- Path traversal
- Invalid data formats
"""

import pytest
import sys
from pathlib import Path

# Add parent directory to path to import run module
sys.path.insert(0, str(Path(__file__).parent.parent))

from run import (
    validate_installation_id,
    validate_repository_token,
    validate_backend_url,
    validate_azure_subscription_id,
    validate_aws_region,
    validate_policy_name,
    sanitize_for_logging,
)


class TestValidateInstallationId:
    """Tests for GitHub installation ID validation"""
    
    def test_valid_installation_id(self):
        """Valid numeric installation IDs should pass"""
        assert validate_installation_id("12345") is True
        assert validate_installation_id("1") is True
        assert validate_installation_id("98765432109876543210") is True
    
    def test_valid_installation_id_with_whitespace(self):
        """Installation IDs with leading/trailing whitespace should pass"""
        assert validate_installation_id(" 12345 ") is True
        assert validate_installation_id("\t12345\n") is True
    
    def test_invalid_empty(self):
        """Empty or whitespace-only values should fail"""
        assert validate_installation_id("") is False
        assert validate_installation_id("   ") is False
        assert validate_installation_id(None) is False
    
    def test_invalid_non_numeric(self):
        """Non-numeric values should fail"""
        assert validate_installation_id("abc") is False
        assert validate_installation_id("123abc") is False
        assert validate_installation_id("12.34") is False
        assert validate_installation_id("-123") is False
    
    def test_injection_attempts(self):
        """Injection attempts should fail"""
        assert validate_installation_id("123; DROP TABLE users") is False
        assert validate_installation_id("123\n456") is False
        assert validate_installation_id("$(whoami)") is False


class TestValidateRepositoryToken:
    """Tests for repository token (GUID) validation"""
    
    def test_valid_guid(self):
        """Valid GUID format should pass"""
        assert validate_repository_token("12345678-1234-1234-1234-123456789012") is True
        assert validate_repository_token("abcdef01-2345-6789-abcd-ef0123456789") is True
        assert validate_repository_token("ABCDEF01-2345-6789-ABCD-EF0123456789") is True
    
    def test_valid_guid_with_whitespace(self):
        """GUIDs with whitespace should pass after trimming"""
        assert validate_repository_token(" 12345678-1234-1234-1234-123456789012 ") is True
    
    def test_invalid_empty(self):
        """Empty values should fail"""
        assert validate_repository_token("") is False
        assert validate_repository_token("   ") is False
        assert validate_repository_token(None) is False
    
    def test_invalid_format(self):
        """Invalid GUID formats should fail"""
        assert validate_repository_token("not-a-guid") is False
        assert validate_repository_token("12345678-1234-1234-1234-12345678901") is False  # too short
        assert validate_repository_token("12345678-1234-1234-1234-1234567890123") is False  # too long
        assert validate_repository_token("1234567-1234-1234-1234-123456789012") is False  # wrong segment length
        assert validate_repository_token("12345678123412341234123456789012") is False  # no dashes
    
    def test_invalid_characters(self):
        """Non-hex characters should fail"""
        assert validate_repository_token("ghijklmn-1234-1234-1234-123456789012") is False
        assert validate_repository_token("12345678-1234-1234-1234-12345678901g") is False


class TestValidateBackendUrl:
    """Tests for backend URL validation (SSRF prevention)"""
    
    def test_valid_https_url(self):
        """Valid HTTPS URLs should pass"""
        assert validate_backend_url("https://api.leftsize.com") is True
        assert validate_backend_url("https://leftsize.io/api") is True
        assert validate_backend_url("https://staging.api.leftsize.com:8443/path") is True

    def test_only_leftsize_hosts(self):
        """The repository token goes to this URL, so other hosts are rejected"""
        assert validate_backend_url("https://example.com/api") is False
        assert validate_backend_url("https://leftsize.com.evil.com/") is False
        assert validate_backend_url("https://evilleftsize.com/") is False
        assert validate_backend_url("https://user:pass@api.leftsize.com/") is False
    
    def test_invalid_http(self):
        """HTTP (non-HTTPS) URLs should fail"""
        assert validate_backend_url("http://api.leftsize.com") is False
    
    def test_invalid_empty(self):
        """Empty values should fail"""
        assert validate_backend_url("") is False
        assert validate_backend_url("   ") is False
        assert validate_backend_url(None) is False
    
    def test_ssrf_metadata_endpoints(self):
        """Cloud metadata endpoint URLs should be blocked"""
        # AWS/GCP metadata
        assert validate_backend_url("https://169.254.169.254/latest/meta-data/") is False
        assert validate_backend_url("https://metadata.google.internal/") is False
        
        # Localhost variations
        assert validate_backend_url("https://localhost/") is False
        assert validate_backend_url("https://127.0.0.1/") is False
        assert validate_backend_url("https://0.0.0.0/") is False
        
        # Case insensitive checks
        assert validate_backend_url("https://LOCALHOST/") is False
        assert validate_backend_url("https://Metadata.Google.Internal/") is False
    
    def test_ssrf_embedded_patterns(self):
        """URLs with suspicious patterns embedded should be blocked"""
        assert validate_backend_url("https://evil.com/redirect?to=169.254.169.254") is False
        assert validate_backend_url("https://evil.com/metadata/path") is False


class TestValidateAzureSubscriptionId:
    """Tests for Azure subscription ID validation"""
    
    def test_valid_subscription_id(self):
        """Valid Azure subscription GUIDs should pass"""
        assert validate_azure_subscription_id("12345678-1234-1234-1234-123456789012") is True
        assert validate_azure_subscription_id("abcdef01-2345-6789-abcd-ef0123456789") is True
    
    def test_invalid_empty(self):
        """Empty values should fail"""
        assert validate_azure_subscription_id("") is False
        assert validate_azure_subscription_id(None) is False
    
    def test_invalid_format(self):
        """Invalid formats should fail"""
        assert validate_azure_subscription_id("not-a-guid") is False
        assert validate_azure_subscription_id("/subscriptions/12345678-1234-1234-1234-123456789012") is False


class TestValidateAwsRegion:
    """Tests for AWS region validation"""
    
    def test_valid_regions(self):
        """Valid AWS region formats should pass"""
        assert validate_aws_region("us-east-1") is True
        assert validate_aws_region("us-west-2") is True
        assert validate_aws_region("eu-central-1") is True
        assert validate_aws_region("ap-southeast-1") is True
        assert validate_aws_region("sa-east-1") is True
    
    def test_valid_regions_with_whitespace(self):
        """Regions with whitespace should pass after trimming"""
        assert validate_aws_region(" us-east-1 ") is True
    
    def test_invalid_empty(self):
        """Empty values should fail"""
        assert validate_aws_region("") is False
        assert validate_aws_region("   ") is False
        assert validate_aws_region(None) is False
    
    def test_invalid_format(self):
        """Invalid region formats should fail"""
        assert validate_aws_region("useast1") is False  # no dashes
        assert validate_aws_region("US-EAST-1") is False  # uppercase not allowed
        assert validate_aws_region("us-east") is False  # missing number
        assert validate_aws_region("us-1") is False  # missing region name
        assert validate_aws_region("us-east-1a") is False  # AZ not region
    
    def test_injection_attempts(self):
        """Injection attempts should fail"""
        assert validate_aws_region("us-east-1; whoami") is False
        assert validate_aws_region("us-east-1\nus-west-2") is False


class TestValidatePolicyName:
    """Tests for policy name validation"""
    
    def test_valid_policy_names(self):
        """Valid policy names should pass"""
        assert validate_policy_name("cost-optimization") is True
        assert validate_policy_name("leftsize_idle_vm") is True
        assert validate_policy_name("Policy123") is True
        assert validate_policy_name("a") is True
    
    def test_invalid_empty(self):
        """Empty values should fail"""
        assert validate_policy_name("") is False
        assert validate_policy_name("   ") is False
        assert validate_policy_name(None) is False
    
    def test_invalid_characters(self):
        """Special characters should fail"""
        assert validate_policy_name("policy.name") is False
        assert validate_policy_name("policy/name") is False
        assert validate_policy_name("policy name") is False
        assert validate_policy_name("policy@name") is False
        assert validate_policy_name("../etc/passwd") is False
    
    def test_max_length(self):
        """Names over 100 characters should fail"""
        assert validate_policy_name("a" * 100) is True
        assert validate_policy_name("a" * 101) is False
    
    def test_path_traversal(self):
        """Path traversal attempts should fail"""
        assert validate_policy_name("..") is False
        assert validate_policy_name("../secret") is False
        assert validate_policy_name("policies/../../../etc/passwd") is False


class TestSanitizeForLogging:
    """Tests for sensitive data sanitization in logs"""
    
    def test_sanitize_sensitive_keys(self):
        """Sensitive keys should be redacted"""
        data = {
            "username": "testuser",
            "password": "secret123",
            "api_token": "abc123",
            "access_key": "AKIAIOSFODNN7EXAMPLE"
        }
        result = sanitize_for_logging(data)
        
        assert result["username"] == "testuser"  # not sensitive
        assert result["password"] == "***REDACTED***"
        assert result["api_token"] == "***REDACTED***"
        assert result["access_key"] == "***REDACTED***"
    
    def test_sanitize_nested_dict(self):
        """Nested dictionaries should be sanitized"""
        data = {
            "config": {
                "api_key": "secret",
                "endpoint": "https://api.example.com"
            }
        }
        result = sanitize_for_logging(data)
        
        assert result["config"]["api_key"] == "***REDACTED***"
        assert result["config"]["endpoint"] == "https://api.example.com"
    
    def test_sanitize_list(self):
        """Lists should be sanitized"""
        data = [
            {"token": "secret1"},
            {"token": "secret2"}
        ]
        result = sanitize_for_logging(data)
        
        assert result[0]["token"] == "***REDACTED***"
        assert result[1]["token"] == "***REDACTED***"
    
    def test_sanitize_case_insensitive(self):
        """Key matching should be case insensitive"""
        data = {
            "API_TOKEN": "secret",
            "AccessKey": "secret",
            "connectionString": "secret"
        }
        result = sanitize_for_logging(data)
        
        assert result["API_TOKEN"] == "***REDACTED***"
        assert result["AccessKey"] == "***REDACTED***"
        assert result["connectionString"] == "***REDACTED***"
    
    def test_non_dict_passthrough(self):
        """Non-dict/list values should pass through unchanged"""
        assert sanitize_for_logging("simple string") == "simple string"
        assert sanitize_for_logging(123) == 123
        assert sanitize_for_logging(None) is None
