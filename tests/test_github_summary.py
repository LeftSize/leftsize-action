"""
Tests for GitHub Actions summary generation in run.py

These tests verify:
- Summary correctly shows Free vs Pro tier breakdown
- Human-readable rule names are displayed
- Estimated savings are shown correctly
- Pro upsell message appears when there are Pro-only findings
"""

import pytest
import os
import tempfile
from unittest.mock import patch
import sys
from pathlib import Path

# Add parent directory to path to import run module
sys.path.insert(0, str(Path(__file__).parent.parent))

from run import print_github_summary, RepositoryLimitExceeded


class TestPrintGitHubSummary:
    """Tests for the print_github_summary function"""
    
    def test_free_tier_with_breakdown_shows_two_tables(self):
        """Free tier users should see separate tables for Free and Pro findings"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.md') as f:
            summary_file = f.name
        
        try:
            with patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': summary_file}):
                findings = [
                    {"ruleId": "leftsize-idle-vm", "scope": "sub-123", "resourceId": "/r1"},
                    {"ruleId": "leftsize-idle-vm", "scope": "sub-123", "resourceId": "/r2"},
                    {"ruleId": "leftsize-aks-overprovisioned", "scope": "sub-123", "resourceId": "/r3"},
                ]
                
                plan_info = {
                    "PlanType": "Free",
                    "ScannedRepositoryCount": 1,
                    "RepositoryLimit": 3,
                    "FindingsIncluded": 2,
                    "FindingsRequireUpgrade": 1,
                    "UpgradeUrl": "https://github.com/marketplace/leftsize",
                    "FindingsBreakdown": [
                        {
                            "RuleId": "leftsize-idle-vm",
                            "RuleName": "Idle virtual machines wasting compute costs",
                            "ResourceCount": 2,
                            "IsFreeTier": True,
                            "EstimatedSavings": 100.0,
                            "Category": "cost-optimization"
                        },
                        {
                            "RuleId": "leftsize-aks-overprovisioned",
                            "RuleName": "Overprovisioned AKS clusters",
                            "ResourceCount": 1,
                            "IsFreeTier": False,
                            "EstimatedSavings": 200.0,
                            "Category": "cost-optimization"
                        }
                    ]
                }
                
                print_github_summary(findings, submitted=True, plan_info=plan_info)
                
                with open(summary_file, 'r') as f:
                    content = f.read()
                
                # Check summary table
                assert "| Free Tier | 2 | ✅ 2 |" in content
                assert "| Pro (upgrade required) | 1 | ❌ 0 |" in content
                assert "| **Total** | **3** | **2** |" in content
                
                # Check Free tier section
                assert "Free Tier Findings (2 → Issues Created)" in content
                assert "Idle virtual machines wasting compute costs" in content
                
                # Check Pro tier section
                assert "Pro Findings (1 → Upgrade to Unlock)" in content
                assert "Overprovisioned AKS clusters" in content
                
                # Check upsell message with savings
                assert "~$200/mo in additional estimated savings" in content
                assert "Upgrade Now" in content
        finally:
            os.unlink(summary_file)
    
    def test_free_tier_all_free_rules_no_pro_section(self):
        """When all findings are free tier, no Pro section should appear"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.md') as f:
            summary_file = f.name
        
        try:
            with patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': summary_file}):
                findings = [
                    {"ruleId": "leftsize-idle-vm", "scope": "sub-123", "resourceId": "/r1"},
                ]
                
                plan_info = {
                    "PlanType": "Free",
                    "ScannedRepositoryCount": 1,
                    "RepositoryLimit": 3,
                    "FindingsIncluded": 1,
                    "FindingsRequireUpgrade": 0,
                    "FindingsBreakdown": [
                        {
                            "RuleId": "leftsize-idle-vm",
                            "RuleName": "Idle virtual machines",
                            "ResourceCount": 1,
                            "IsFreeTier": True,
                            "EstimatedSavings": 50.0,
                            "Category": "cost-optimization"
                        }
                    ]
                }
                
                print_github_summary(findings, submitted=True, plan_info=plan_info)
                
                with open(summary_file, 'r') as f:
                    content = f.read()
                
                # Check Free tier findings shown
                assert "Free Tier Findings" in content
                assert "Idle virtual machines" in content
                
                # Check Pro section NOT shown
                assert "Pro Findings" not in content
                assert "Upgrade to Unlock" not in content
        finally:
            os.unlink(summary_file)
    
    def test_pro_tier_shows_all_findings(self):
        """Pro tier users should see all findings in one table"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.md') as f:
            summary_file = f.name
        
        try:
            with patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': summary_file}):
                findings = [
                    {"ruleId": "leftsize-idle-vm", "scope": "sub-123", "resourceId": "/r1"},
                    {"ruleId": "leftsize-aks-overprovisioned", "scope": "sub-123", "resourceId": "/r2"},
                ]
                
                plan_info = {
                    "PlanType": "Pro",
                    "ScannedRepositoryCount": 5,
                    "RepositoryLimit": None,  # Unlimited
                    "FindingsIncluded": 2,
                    "FindingsRequireUpgrade": 0,
                    "FindingsBreakdown": [
                        {
                            "RuleId": "leftsize-idle-vm",
                            "RuleName": "Idle virtual machines",
                            "ResourceCount": 1,
                            "IsFreeTier": True,
                            "EstimatedSavings": 50.0,
                            "Category": "cost-optimization"
                        },
                        {
                            "RuleId": "leftsize-aks-overprovisioned",
                            "RuleName": "Overprovisioned AKS clusters",
                            "ResourceCount": 1,
                            "IsFreeTier": False,
                            "EstimatedSavings": 200.0,
                            "Category": "cost-optimization"
                        }
                    ]
                }
                
                print_github_summary(findings, submitted=True, plan_info=plan_info)
                
                with open(summary_file, 'r') as f:
                    content = f.read()
                
                # Check Pro plan indicator
                assert "Plan**: Pro" in content
                
                # Check all findings shown together
                assert "Findings by Rule" in content
                assert "Idle virtual machines" in content
                assert "Overprovisioned AKS clusters" in content
                
                # Check category column
                assert "| cost-optimization |" in content
        finally:
            os.unlink(summary_file)
    
    def test_estimated_savings_formatting(self):
        """Estimated savings should be formatted with currency symbol and thousands separator"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.md') as f:
            summary_file = f.name
        
        try:
            with patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': summary_file}):
                findings = [{"ruleId": "test", "scope": "test", "resourceId": "/r1"}]
                
                plan_info = {
                    "PlanType": "Free",
                    "ScannedRepositoryCount": 1,
                    "RepositoryLimit": 3,
                    "FindingsIncluded": 1,
                    "FindingsRequireUpgrade": 0,
                    "FindingsBreakdown": [
                        {
                            "RuleId": "test",
                            "RuleName": "Test rule",
                            "ResourceCount": 1,
                            "IsFreeTier": True,
                            "EstimatedSavings": 1500.50,
                            "Category": "cost-optimization"
                        }
                    ]
                }
                
                print_github_summary(findings, submitted=True, plan_info=plan_info)
                
                with open(summary_file, 'r') as f:
                    content = f.read()
                
                # Should show formatted savings
                assert "~$1,500/mo" in content or "~$1,501/mo" in content  # Rounding
        finally:
            os.unlink(summary_file)
    
    def test_zero_savings_shows_dash(self):
        """Zero estimated savings should show dash instead of $0"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.md') as f:
            summary_file = f.name
        
        try:
            with patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': summary_file}):
                findings = [{"ruleId": "test", "scope": "test", "resourceId": "/r1"}]
                
                plan_info = {
                    "PlanType": "Free",
                    "ScannedRepositoryCount": 1,
                    "RepositoryLimit": 3,
                    "FindingsIncluded": 1,
                    "FindingsRequireUpgrade": 0,
                    "FindingsBreakdown": [
                        {
                            "RuleId": "leftsize-missing-tags",
                            "RuleName": "Missing ownership tags",
                            "ResourceCount": 5,
                            "IsFreeTier": True,
                            "EstimatedSavings": 0,
                            "Category": "governance"
                        }
                    ]
                }
                
                print_github_summary(findings, submitted=True, plan_info=plan_info)
                
                with open(summary_file, 'r') as f:
                    content = f.read()
                
                # Should show dash for zero savings
                assert "| Missing ownership tags | 5 | - |" in content
        finally:
            os.unlink(summary_file)
    
    def test_repository_limit_exceeded_warning(self):
        """Should show warning when repository limit is exceeded"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.md') as f:
            summary_file = f.name
        
        try:
            with patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': summary_file}):
                findings = [{"ruleId": "test", "scope": "test", "resourceId": "/r1"}]
                
                limit_exceeded = RepositoryLimitExceeded(
                    "Repository limit exceeded",
                    {
                        "currentCount": 3,
                        "limit": 3,
                        "upgradeUrl": "https://github.com/marketplace/leftsize",
                        "accountLogin": "test-org"
                    }
                )
                
                print_github_summary(findings, submitted=False, limit_exceeded=limit_exceeded)
                
                with open(summary_file, 'r') as f:
                    content = f.read()
                
                # Check warning message
                assert "Free Tier Limit Reached" in content
                assert "3 repositories" in content
                assert "Upgrade to Pro" in content
        finally:
            os.unlink(summary_file)
    
    def test_fallback_when_no_breakdown(self):
        """Should show basic summary when FindingsBreakdown is not available"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.md') as f:
            summary_file = f.name
        
        try:
            with patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': summary_file}):
                findings = [
                    {"ruleId": "leftsize-idle-vm", "scope": "sub-123", "resourceId": "/r1"},
                    {"ruleId": "leftsize-idle-vm", "scope": "sub-123", "resourceId": "/r2"},
                ]
                
                # Old-style plan_info without FindingsBreakdown
                plan_info = {
                    "PlanType": "Free",
                    "ScannedRepositoryCount": 1,
                    "RepositoryLimit": 3,
                    "FindingsIncluded": 2,
                    "FindingsRequireUpgrade": 0
                    # No FindingsBreakdown
                }
                
                print_github_summary(findings, submitted=True, plan_info=plan_info)
                
                with open(summary_file, 'r') as f:
                    content = f.read()
                
                # Should fall back to basic format
                assert "Findings Detected" in content
                assert "Issues to be Created" in content
        finally:
            os.unlink(summary_file)
    
    def test_no_plan_info_shows_basic_summary(self):
        """Should show basic summary when plan_info is not provided"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.md') as f:
            summary_file = f.name
        
        try:
            with patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': summary_file}):
                findings = [
                    {"ruleId": "leftsize-idle-vm", "scope": "sub-123", "resourceId": "/r1"},
                ]
                
                print_github_summary(findings, submitted=True, plan_info=None)
                
                with open(summary_file, 'r') as f:
                    content = f.read()
                
                # Should show basic format
                assert "Findings Detected" in content
                assert "leftsize-idle-vm" in content
        finally:
            os.unlink(summary_file)
    
    def test_plan_info_footer_shows_remaining_repos(self):
        """Free tier should show remaining repository count"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.md') as f:
            summary_file = f.name
        
        try:
            with patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': summary_file}):
                findings = [{"ruleId": "test", "scope": "test", "resourceId": "/r1"}]
                
                plan_info = {
                    "PlanType": "Free",
                    "ScannedRepositoryCount": 2,
                    "RepositoryLimit": 3,
                    "FindingsIncluded": 1,
                    "FindingsRequireUpgrade": 0,
                    "FindingsBreakdown": [
                        {
                            "RuleId": "test",
                            "RuleName": "Test rule",
                            "ResourceCount": 1,
                            "IsFreeTier": True,
                            "EstimatedSavings": 0,
                            "Category": "cost"
                        }
                    ]
                }
                
                print_github_summary(findings, submitted=True, plan_info=plan_info)
                
                with open(summary_file, 'r') as f:
                    content = f.read()
                
                # Should show repo count and remaining
                assert "2/3 repositories scanned" in content
                assert "1 remaining" in content
        finally:
            os.unlink(summary_file)
