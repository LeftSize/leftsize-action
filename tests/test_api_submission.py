"""
Tests for API submission and token handling in run.py

These tests verify:
- Token is sent via Authorization header (not in URL)
- Token is not logged
- API submission handles errors properly
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
import sys
from pathlib import Path

# Add parent directory to path to import run module
sys.path.insert(0, str(Path(__file__).parent.parent))

from run import submit_findings, group_findings, RepositoryLimitExceeded


class TestSubmitFindings:
    """Tests for the submit_findings function"""
    
    @patch('run.requests.post')
    @patch('run.logger')
    def test_token_in_authorization_header(self, mock_logger, mock_post):
        """Token should be sent via Authorization header, not in URL"""
        mock_response = Mock()
        mock_response.status_code = 202
        mock_response.json.return_value = {"message": "accepted"}
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response
        
        findings = [{
            "ruleId": "test-rule",
            "scope": "test-scope",
            "resourceId": "/test/resource",
            "metadata": {}
        }]
        
        # Config must have 'output' key wrapping the settings
        config = {
            "output": {
                "backend_url": "https://api.leftsize.com",
                "installation_id": "12345",
                "repository_token": "12345678-1234-1234-1234-123456789012"
            }
        }
        
        result = submit_findings(findings, config)
        
        # Verify the call was made
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        
        # Get URL from positional or keyword args
        url = call_args.args[0] if call_args.args else call_args.kwargs.get('url')
        
        # Verify the URL does NOT contain the token
        assert "12345678-1234-1234-1234-123456789012" not in url
        assert url == "https://api.leftsize.com/findings/12345"
        
        # Verify token is in Authorization header
        headers = call_args.kwargs.get('headers', {})
        assert "Authorization" in headers
        assert headers["Authorization"] == "Bearer 12345678-1234-1234-1234-123456789012"
        
        # Verify return value
        assert result['submitted'] is True
    
    @patch('run.requests.post')
    @patch('run.logger')
    def test_token_not_logged(self, mock_logger, mock_post):
        """Token should NOT appear in log messages"""
        mock_response = Mock()
        mock_response.status_code = 202
        mock_response.json.return_value = {"message": "accepted"}
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response
        
        token = "12345678-1234-1234-1234-123456789012"
        findings = [{
            "ruleId": "test-rule",
            "scope": "test-scope",
            "resourceId": "/test/resource",
            "metadata": {}
        }]
        
        config = {
            "output": {
                "backend_url": "https://api.leftsize.com",
                "installation_id": "12345",
                "repository_token": token
            }
        }
        
        submit_findings(findings, config)
        
        # Check all log calls don't contain the token
        for call in mock_logger.info.call_args_list:
            call_str = str(call)
            assert token not in call_str, f"Token found in log: {call_str}"
        
        for call in mock_logger.warning.call_args_list:
            call_str = str(call)
            assert token not in call_str, f"Token found in log: {call_str}"
    
    @patch('run.requests.post')
    @patch('run.logger')
    def test_skips_submission_without_backend_url(self, mock_logger, mock_post):
        """Should skip submission if backend URL is not configured"""
        findings = [{"ruleId": "test", "scope": "test", "resourceId": "/test", "metadata": {}}]
        config = {
            "output": {
                "installation_id": "12345",
                "repository_token": "12345678-1234-1234-1234-123456789012"
            }
        }
        
        result = submit_findings(findings, config)
        
        mock_post.assert_not_called()
        mock_logger.warning.assert_called()
        assert result['submitted'] is False
    
    @patch('run.requests.post')
    @patch('run.logger')
    def test_skips_submission_without_token(self, mock_logger, mock_post):
        """Should skip submission if repository token is not configured"""
        findings = [{"ruleId": "test", "scope": "test", "resourceId": "/test", "metadata": {}}]
        config = {
            "output": {
                "backend_url": "https://api.leftsize.com",
                "installation_id": "12345"
            }
        }
        
        result = submit_findings(findings, config)
        
        mock_post.assert_not_called()
        mock_logger.warning.assert_called()
        assert result['submitted'] is False
    
    @patch('run.requests.post')
    @patch('run.logger')
    def test_handles_api_error(self, mock_logger, mock_post):
        """Should log error on API failure (exception is caught internally)"""
        from requests.exceptions import HTTPError
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.raise_for_status.side_effect = HTTPError("Server error")
        mock_post.return_value = mock_response
        
        findings = [{"ruleId": "test", "scope": "test", "resourceId": "/test", "metadata": {}}]
        config = {
            "output": {
                "backend_url": "https://api.leftsize.com",
                "installation_id": "12345",
                "repository_token": "12345678-1234-1234-1234-123456789012"
            }
        }
        
        # The function re-raises the exception
        with pytest.raises(Exception):
            submit_findings(findings, config)
        
        mock_logger.error.assert_called()
    
    @patch('run.requests.post')
    @patch('run.logger')
    def test_request_timeout(self, mock_logger, mock_post):
        """Should use 30 second timeout for API requests"""
        mock_response = Mock()
        mock_response.status_code = 202
        mock_response.json.return_value = {"message": "accepted"}
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response
        
        findings = [{"ruleId": "test", "scope": "test", "resourceId": "/test", "metadata": {}}]
        config = {
            "output": {
                "backend_url": "https://api.leftsize.com",
                "installation_id": "12345",
                "repository_token": "12345678-1234-1234-1234-123456789012"
            }
        }
        
        submit_findings(findings, config)
        
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert call_args.kwargs.get('timeout') == 30
    
    @patch('run.requests.post')
    @patch('run.logger')
    def test_handles_repository_limit_exceeded(self, mock_logger, mock_post):
        """Should raise RepositoryLimitExceeded on 402 response"""
        mock_response = Mock()
        mock_response.status_code = 402
        mock_response.json.return_value = {
            "Code": "REPOSITORY_LIMIT_EXCEEDED",
            "Message": "Free tier repository limit reached",
            "Details": "Your free plan allows scanning 3 repositories",
            "Context": {
                "accountLogin": "test-org",
                "currentCount": 3,
                "limit": 3,
                "upgradeUrl": "https://github.com/marketplace/leftsize"
            }
        }
        mock_post.return_value = mock_response
        
        findings = [{"ruleId": "test", "scope": "test", "resourceId": "/test", "metadata": {}}]
        config = {
            "output": {
                "backend_url": "https://api.leftsize.com",
                "installation_id": "12345",
                "repository_token": "12345678-1234-1234-1234-123456789012"
            }
        }
        
        with pytest.raises(RepositoryLimitExceeded) as exc_info:
            submit_findings(findings, config)
        
        assert exc_info.value.current_count == 3
        assert exc_info.value.limit == 3
        assert exc_info.value.upgrade_url == "https://github.com/marketplace/leftsize"
        assert exc_info.value.account_login == "test-org"
    
    @patch('run.requests.post')
    @patch('run.logger')
    def test_returns_plan_info_from_response(self, mock_logger, mock_post):
        """Should return plan info from successful response"""
        mock_response = Mock()
        mock_response.status_code = 202
        mock_response.json.return_value = {
            "message": "accepted",
            "PlanInfo": {
                "PlanType": "Free",
                "ScannedRepositoryCount": 2,
                "RepositoryLimit": 3
            }
        }
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response
        
        findings = [{"ruleId": "test", "scope": "test", "resourceId": "/test", "metadata": {}}]
        config = {
            "output": {
                "backend_url": "https://api.leftsize.com",
                "installation_id": "12345",
                "repository_token": "12345678-1234-1234-1234-123456789012"
            }
        }
        
        result = submit_findings(findings, config)
        
        assert result['submitted'] is True
        assert result['plan_info'] is not None
        assert result['plan_info']['PlanType'] == 'Free'
        assert result['plan_info']['ScannedRepositoryCount'] == 2


class TestGroupFindings:
    """Tests for the group_findings function"""
    
    def test_groups_by_rule_and_scope(self):
        """Findings should be grouped by ruleId and scope"""
        findings = [
            {"ruleId": "rule1", "scope": "scope1", "resourceId": "/r1", "metadata": {}},
            {"ruleId": "rule1", "scope": "scope1", "resourceId": "/r2", "metadata": {}},
            {"ruleId": "rule1", "scope": "scope2", "resourceId": "/r3", "metadata": {}},
            {"ruleId": "rule2", "scope": "scope1", "resourceId": "/r4", "metadata": {}},
        ]
        
        groups = group_findings(findings)
        
        assert len(groups) == 3  # 3 unique (ruleId, scope) combinations
        
        # Find group for rule1/scope1
        rule1_scope1 = next(g for g in groups if g["policy"] == "rule1" and g["scope"] == "scope1")
        assert len(rule1_scope1["resources"]) == 2
    
    def test_uses_snake_case(self):
        """Output should use snake_case to match the Cloudflare worker schema"""
        findings = [{"ruleId": "test", "scope": "test", "resourceId": "/test", "metadata": {}}]
        
        groups = group_findings(findings)
        
        assert "policy" in groups[0]
        assert "scope" in groups[0]
        assert "resources" in groups[0]
        assert "cloud_provider" in groups[0]
    
    def test_empty_findings(self):
        """Empty findings list should return empty groups"""
        groups = group_findings([])
        assert groups == []
