#!/usr/bin/env python3
"""
LeftSize Runner - Python entrypoint for executing Cloud Custodian policies
This enhanced version integrates with real Azure Cloud Custodian policies
"""

import sys
import json
import os
import yaml
import tempfile
import subprocess
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any
import requests
import click
import structlog

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()


def _build_custodian_env() -> dict[str, str]:
    """Build filtered subprocess environment for Cloud Custodian.
    
    Only allows cloud provider credentials and essential system env vars.
    Explicitly excludes GitHub Actions, LeftSize, and other action-specific secrets.
    """
    allow_prefixes = (
        "AZURE_", "AWS_", "GOOGLE_", "GCP_",
        "PATH", "HOME", "USER", "LANG", "LC_", "TZ",
        "PYTHONPATH",
        "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
        "http_proxy", "https_proxy", "no_proxy",
        "SSL_CERT_", "REQUESTS_CA_BUNDLE"
    )
    exclude_prefixes = ("LEFTSIZE_", "GITHUB_", "INPUT_", "RUNNER_", "ACTIONS_")
    
    filtered = {}
    for k, v in os.environ.items():
        # Skip if it matches an exclude prefix
        if any(k.startswith(p) for p in exclude_prefixes):
            continue
        # Include if it matches an allow prefix
        if any(k == p or k.startswith(p) for p in allow_prefixes):
            filtered[k] = v
    
    # Ensure critical keys exist even if not in allow_prefixes
    for key in ("PATH", "HOME", "USER"):
        if key in os.environ and key not in filtered:
            filtered[key] = os.environ[key]
    
    logger.info("Filtered subprocess environment", env_var_count=len(filtered))
    return filtered


class RepositoryLimitExceeded(Exception):
    """Raised when the free tier repository limit is exceeded"""
    def __init__(self, message: str, context: Dict[str, Any]):
        super().__init__(message)
        self.message = message
        self.context = context
        self.current_count = context.get('currentCount', 0)
        self.limit = context.get('limit', 3)
        self.upgrade_url = context.get('upgradeUrl', 'https://github.com/marketplace/leftsize')
        self.account_login = context.get('accountLogin', '')


# Input validation functions
def validate_installation_id(installation_id: str) -> bool:
    """Validate GitHub installation ID format (numeric)"""
    if not installation_id or not installation_id.strip():
        return False
    return re.match(r'^\d+$', installation_id.strip()) is not None


def validate_repository_token(token: str) -> bool:
    """Validate repository token format (GUID)"""
    if not token or not token.strip():
        return False
    # GUID format: 8-4-4-4-12 hex characters
    guid_pattern = r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    return re.match(guid_pattern, token.strip()) is not None


def validate_backend_url(url: str) -> bool:
    """Validate backend URL format"""
    if not url or not url.strip():
        return False
    # Must be HTTPS and reasonable domain
    url = url.strip()
    if not url.startswith('https://'):
        logger.warning("Backend URL must use HTTPS", url=url)
        return False
    # Check for suspicious patterns
    if any(pattern in url.lower() for pattern in ['169.254.169.254', 'metadata', 'localhost', '127.0.0.1', '0.0.0.0']):
        logger.error("Backend URL contains suspicious pattern", url=url)
        return False
    return True


def validate_azure_subscription_id(sub_id: str) -> bool:
    """Validate Azure subscription ID format (GUID)"""
    if not sub_id or not sub_id.strip():
        return False
    guid_pattern = r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    return re.match(guid_pattern, sub_id.strip()) is not None


def validate_aws_region(region: str) -> bool:
    """Validate AWS region format"""
    if not region or not region.strip():
        return False
    # AWS region pattern: us-east-1, eu-west-2, etc.
    region_pattern = r'^[a-z]{2}-[a-z]+-\d+$'
    return re.match(region_pattern, region.strip()) is not None


def get_aws_account_id() -> Optional[str]:
    """Get AWS account ID using STS GetCallerIdentity.
    
    Returns the 12-digit AWS account ID or None if unable to retrieve.
    This is used to scope findings properly in multi-account setups.
    """
    try:
        import boto3
        sts = boto3.client('sts')
        response = sts.get_caller_identity()
        account_id = response.get('Account')
        if account_id:
            logger.info("Retrieved AWS account ID", account_id=account_id)
            return account_id
        logger.warning("STS GetCallerIdentity returned no Account")
        return None
    except ImportError:
        logger.warning("boto3 not available, cannot retrieve AWS account ID")
        return None
    except Exception as e:
        logger.warning("Failed to retrieve AWS account ID", error=str(e))
        return None


def validate_policy_name(policy_name: str) -> bool:
    """Validate policy name (alphanumeric, hyphens, underscores only)"""
    if not policy_name or not policy_name.strip():
        return False
    # Only allow safe characters, max 100 chars
    if len(policy_name) > 100:
        return False
    return re.match(r'^[a-zA-Z0-9_-]+$', policy_name.strip()) is not None


def sanitize_for_logging(data: Any) -> Any:
    """Remove sensitive information from data before logging"""
    if isinstance(data, dict):
        sanitized = {}
        sensitive_keys = ['password', 'secret', 'token', 'key', 'credential', 'connectionstring', 'access_key']
        for k, v in data.items():
            if any(sensitive in k.lower() for sensitive in sensitive_keys):
                sanitized[k] = '***REDACTED***'
            elif isinstance(v, (dict, list)):
                sanitized[k] = sanitize_for_logging(v)
            else:
                sanitized[k] = v
        return sanitized
    elif isinstance(data, list):
        return [sanitize_for_logging(item) for item in data]
    else:
        return data


def github_action_main():
    """GitHub Action entry point - reads from environment variables"""
    
    # Read from GitHub Action environment variables
    verbose = os.getenv('LEFTSIZE_VERBOSE', 'false').lower() == 'true'
    backend_url = os.getenv('LEFTSIZE_BACKEND_URL', 'https://api.leftsize.com')
    installation_id = os.getenv('LEFTSIZE_INSTALLATION_ID', '')
    repository_token = os.getenv('LEFTSIZE_REPOSITORY_TOKEN', '')
    cloud_provider = os.getenv('LEFTSIZE_CLOUD_PROVIDER', 'azure')
    azure_subscription_ids = os.getenv('LEFTSIZE_AZURE_SUBSCRIPTION_IDS', '')
    aws_regions = os.getenv('LEFTSIZE_AWS_REGIONS', '')
    environment_name = os.getenv('LEFTSIZE_ENVIRONMENT_NAME', '')
    currency = os.getenv('LEFTSIZE_CURRENCY', '')
    include_policies = os.getenv('LEFTSIZE_INCLUDE_POLICIES', '')
    exclude_policies = os.getenv('LEFTSIZE_EXCLUDE_POLICIES', '')
    
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
    logger.info("LeftSize GitHub Action starting", version="1.0.0", cloud_provider=cloud_provider)
    
    # Validate required inputs
    if not validate_installation_id(installation_id):
        logger.error("Invalid installation-id format. Must be numeric.")
        set_github_output('findings-submitted', 'false')
        return 1
    
    if not validate_repository_token(repository_token):
        logger.error("Invalid repository-token format. Must be a valid GUID.")
        set_github_output('findings-submitted', 'false')
        return 1
    
    if not validate_backend_url(backend_url):
        logger.error("Invalid backend-url format. Must be HTTPS URL.")
        set_github_output('findings-submitted', 'false')
        return 1
    
    # Validate cloud provider input
    if cloud_provider not in ['azure', 'aws']:
        logger.error("Invalid cloud-provider. Must be 'azure' or 'aws'.", provider=cloud_provider)
        set_github_output('findings-submitted', 'false')
        return 1
    
    try:
        # Create minimal configuration from environment variables
        config_data = create_default_config()
        
        # Store cloud provider in config for policy filtering
        config_data['cloud_provider'] = cloud_provider
        
        # Store environment name override if provided
        if environment_name:
            config_data['environment_name'] = environment_name.strip()
            logger.info("Environment name override specified", environment=environment_name)
        
        # Override with environment variables
        if backend_url:
            config_data.setdefault('output', {})['backend_url'] = backend_url
        if installation_id:
            config_data.setdefault('output', {})['installation_id'] = installation_id
        if repository_token:
            config_data.setdefault('output', {})['repository_token'] = repository_token
        
        # Configure cloud provider targets with validation
        if cloud_provider == 'azure':
            if azure_subscription_ids:
                subs = [s.strip() for s in azure_subscription_ids.split(',') if s.strip()]
                # Validate each subscription ID
                invalid_subs = [s for s in subs if not validate_azure_subscription_id(s)]
                if invalid_subs:
                    logger.error("Invalid Azure subscription ID(s)", invalid=invalid_subs)
                    set_github_output('findings-submitted', 'false')
                    return 1
                config_data.setdefault('targets', {}).setdefault('azure', {})['subscriptions'] = subs
        elif cloud_provider == 'aws':
            if aws_regions:
                regions = [r.strip() for r in aws_regions.split(',') if r.strip()]
                # Validate each region
                invalid_regions = [r for r in regions if not validate_aws_region(r)]
                if invalid_regions:
                    logger.error("Invalid AWS region(s)", invalid=invalid_regions)
                    set_github_output('findings-submitted', 'false')
                    return 1
                config_data.setdefault('targets', {}).setdefault('aws', {})['regions'] = regions
        
        # Configure policies with validation
        if include_policies:
            categories = [c.strip() for c in include_policies.split(',') if c.strip()]
            # Validate policy category names
            invalid_cats = [c for c in categories if not validate_policy_name(c)]
            if invalid_cats:
                logger.error("Invalid policy category name(s)", invalid=invalid_cats)
                set_github_output('findings-submitted', 'false')
                return 1
            config_data.setdefault('policies', {})['include_categories'] = categories
            
        if exclude_policies:
            rules = [r.strip() for r in exclude_policies.split(',') if r.strip()]
            # Validate policy rule names
            invalid_rules = [r for r in rules if not validate_policy_name(r)]
            if invalid_rules:
                logger.error("Invalid policy rule name(s)", invalid=invalid_rules)
                set_github_output('findings-submitted', 'false')
                return 1
            config_data.setdefault('policies', {})['exclude_rules'] = rules
        
        # Policies directory (bundled in action)
        policies_dir = os.path.join(os.path.dirname(__file__), 'policies')
        
        # Validate authentication based on cloud provider
        if cloud_provider == 'azure':
            azure_config = config_data.get('targets', {}).get('azure', {})
            if not validate_azure_auth(azure_config):
                set_github_output('findings-submitted', 'false')
                logger.error("Azure authentication failed. Please configure Azure credentials.")
                return 1
            
            # Detect or use provided currency
            if currency:
                detected_currency = currency.upper()
                logger.info("Using provided currency", currency=detected_currency)
            else:
                # Try to detect from Azure subscription
                subs = azure_config.get('subscriptions', [])
                sub_id = subs[0] if subs else None
                detected_currency = detect_azure_currency(sub_id)
            config_data['currency'] = detected_currency
            
        elif cloud_provider == 'aws':
            # AWS auth validation handled by boto3/AWS CLI
            # AWS defaults to USD
            config_data['currency'] = currency.upper() if currency else 'USD'
            
            # Get AWS account ID for proper multi-account scope isolation
            aws_account_id = get_aws_account_id()
            if aws_account_id:
                config_data.setdefault('targets', {}).setdefault('aws', {})['account_id'] = aws_account_id
            else:
                logger.warning("Could not retrieve AWS account ID - multi-account scoping may not work correctly")
        
        # Execute Cloud Custodian policies
        findings = execute_custodian_policies(policies_dir, config_data)
        
        # Process findings
        if findings is None:
            set_github_output('findings-count', '0')
            set_github_output('findings-submitted', 'false')
            set_github_output('findings-json', '[]')
            logger.error("Failed to execute policies or retrieve findings.")
            return 1
        
        findings_count = len(findings)
        logger.info(f"Found {findings_count} findings")
        
        # Submit findings to backend
        submitted = False
        plan_info = None
        limit_exceeded_error = None
        
        if findings and backend_url and installation_id and repository_token:
            try:
                result = submit_findings(findings, config_data)
                submitted = result.get('submitted', False)
                plan_info = result.get('plan_info')
                if submitted:
                    logger.info("Findings submitted successfully to backend")
            except RepositoryLimitExceeded as e:
                logger.warning(f"Repository limit exceeded: {e.message}")
                limit_exceeded_error = e
                # Don't fail the workflow, but mark as not submitted
                set_github_output('findings-count', str(findings_count))
                set_github_output('findings-submitted', 'false')
                set_github_output('findings-json', json.dumps(findings, default=str))
                set_github_output('limit-exceeded', 'true')
                print_github_summary(findings, submitted=False, limit_exceeded=limit_exceeded_error)
                # Return 0 - we don't want to fail the workflow, just show the warning
                return 0
            except Exception as e:
                logger.error(f"Failed to submit findings to backend: {e}")
                set_github_output('findings-count', str(findings_count))
                set_github_output('findings-submitted', 'false')
                set_github_output('findings-json', json.dumps(findings, default=str))
                print_github_summary(findings, submitted=False)
                return 1
        
        # Set GitHub Action outputs
        set_github_output('findings-count', str(findings_count))
        set_github_output('findings-submitted', 'true' if submitted else 'false')
        set_github_output('findings-json', json.dumps(findings, default=str))
        
        # GitHub Actions summary
        print_github_summary(findings, submitted, plan_info=plan_info)
        
        logger.info("LeftSize GitHub Action completed successfully")
        return 0
        
    except Exception as e:
        set_github_output('findings-count', '0')
        set_github_output('findings-submitted', 'false')
        set_github_output('findings-json', '[]')
        logger.error("LeftSize GitHub Action failed", error=str(e), exc_info=True)
        return 1


def set_github_output(name: str, value: str):
    """Set GitHub Actions output"""
    github_output = os.getenv('GITHUB_OUTPUT')
    if github_output:
        with open(github_output, 'a') as f:
            f.write(f"{name}={value}\n")
    else:
        # Fallback for testing
        print(f"::set-output name={name}::{value}")


def print_github_summary(
    findings: List[Dict[str, Any]], 
    submitted: bool,
    plan_info: Optional[Dict[str, Any]] = None,
    limit_exceeded: Optional[RepositoryLimitExceeded] = None
):
    """Print GitHub Actions job summary
    
    Args:
        findings: List of findings from the scan
        submitted: Whether findings were submitted to backend
        plan_info: Optional plan information from the backend response
        limit_exceeded: Optional exception if repository limit was exceeded
    """
    github_step_summary = os.getenv('GITHUB_STEP_SUMMARY')
    
    # Calculate issues to be created vs findings requiring upgrade
    findings_included = len(findings)
    findings_require_upgrade = 0
    findings_breakdown = []
    
    if plan_info:
        findings_included = plan_info.get('FindingsIncluded', len(findings))
        findings_require_upgrade = plan_info.get('FindingsRequireUpgrade', 0)
        findings_breakdown = plan_info.get('FindingsBreakdown') or []
    
    summary = "# LeftSize Scan Results\n\n"
    
    # Show repository limit exceeded warning first (if applicable)
    if limit_exceeded:
        summary += f"""## ⚠️ Free Tier Limit Reached

Your free plan allows scanning **{limit_exceeded.limit} repositories**. You've already scanned {limit_exceeded.current_count} repositories.

**Findings from this scan were not submitted** because the repository limit has been exceeded.

👉 **[Upgrade to Pro]({limit_exceeded.upgrade_url})** for unlimited repository scanning.

---

"""
    
    # Show summary table for Free tier users with breakdown
    if plan_info and plan_info.get('PlanType') == 'Free' and findings_breakdown:
        # Separate free and pro findings
        free_tier_findings = [f for f in findings_breakdown if f.get('IsFreeTier', False)]
        pro_tier_findings = [f for f in findings_breakdown if not f.get('IsFreeTier', False)]
        
        free_count = sum(f.get('ResourceCount', 0) for f in free_tier_findings)
        pro_count = sum(f.get('ResourceCount', 0) for f in pro_tier_findings)
        pro_savings = sum(f.get('EstimatedSavings', 0) for f in pro_tier_findings)
        
        # Summary table
        summary += """## Summary

| Plan | Findings | Issues Created |
|------|----------|----------------|
"""
        summary += f"| Free Tier | {free_count} | ✅ {free_count} |\n"
        if pro_count > 0:
            summary += f"| Pro (upgrade required) | {pro_count} | ❌ 0 |\n"
        summary += f"| **Total** | **{free_count + pro_count}** | **{free_count}** |\n\n"
        
        # Free tier findings table
        if free_tier_findings:
            summary += f"## Free Tier Findings ({free_count} → Issues Created)\n\n"
            summary += "| Rule | Resources | Est. Savings |\n"
            summary += "|------|-----------|-------------|\n"
            for f in free_tier_findings:
                rule_name = f.get('RuleName', f.get('RuleId', 'Unknown'))
                resource_count = f.get('ResourceCount', 0)
                savings = f.get('EstimatedSavings', 0)
                savings_str = f"~${savings:,.0f}/mo" if savings > 0 else "-"
                summary += f"| {rule_name} | {resource_count} | {savings_str} |\n"
            summary += "\n"
        
        # Pro tier findings table (the upsell section)
        if pro_tier_findings:
            summary += f"## Pro Findings ({pro_count} → Upgrade to Unlock)\n\n"
            summary += "| Rule | Resources | Est. Savings |\n"
            summary += "|------|-----------|-------------|\n"
            for f in pro_tier_findings:
                rule_name = f.get('RuleName', f.get('RuleId', 'Unknown'))
                resource_count = f.get('ResourceCount', 0)
                savings = f.get('EstimatedSavings', 0)
                savings_str = f"~${savings:,.0f}/mo" if savings > 0 else "-"
                summary += f"| {rule_name} | {resource_count} | {savings_str} |\n"
            summary += "\n"
            
            # Upsell message
            upgrade_url = plan_info.get('UpgradeUrl', 'https://github.com/marketplace/leftsize')
            if pro_savings > 0:
                summary += f"> 💡 **Upgrade to Pro** to create issues for all {free_count + pro_count} findings and unlock ~${pro_savings:,.0f}/mo in additional estimated savings.\n"
            else:
                summary += f"> 💡 **Upgrade to Pro** to create issues for all {free_count + pro_count} findings.\n"
            summary += f"> 👉 [Upgrade Now]({upgrade_url})\n\n"
        
        # Plan information footer
        repo_count = plan_info.get('ScannedRepositoryCount', 0)
        repo_limit = plan_info.get('RepositoryLimit', 3)
        remaining = max(0, repo_limit - repo_count)
        summary += "---\n\n"
        summary += f"**Plan**: Free Tier ({repo_count}/{repo_limit} repositories scanned, {remaining} remaining)\n\n"
    
    # Show Pro plan summary (simpler, all findings included)
    elif plan_info and plan_info.get('PlanType') == 'Pro':
        total_findings = len(findings)
        total_savings = sum(f.get('EstimatedSavings', 0) for f in findings_breakdown) if findings_breakdown else 0
        
        summary += f"""## Summary

- **Plan**: Pro ✨
- **Findings Detected**: {total_findings}
- **Issues Created**: ✅ {total_findings}
"""
        if total_savings > 0:
            summary += f"- **Estimated Savings**: ~${total_savings:,.0f}/mo\n"
        summary += "\n"
        
        # Show findings table
        if findings_breakdown:
            summary += "## Findings by Rule\n\n"
            summary += "| Rule | Resources | Est. Savings | Category |\n"
            summary += "|------|-----------|-------------|----------|\n"
            for f in findings_breakdown:
                rule_name = f.get('RuleName', f.get('RuleId', 'Unknown'))
                resource_count = f.get('ResourceCount', 0)
                savings = f.get('EstimatedSavings', 0)
                savings_str = f"~${savings:,.0f}/mo" if savings > 0 else "-"
                category = f.get('Category', 'unknown')
                summary += f"| {rule_name} | {resource_count} | {savings_str} | {category} |\n"
            summary += "\n"
    
    # Fallback: No plan info or no breakdown - show basic summary
    else:
        summary += f"""## Summary

- **Findings Detected**: {len(findings)}
- **Issues to be Created**: {findings_included}
- **Submitted to Backend**: {'✅ Yes' if submitted else '❌ No'}

"""
        # Show basic findings by rule (fallback when no breakdown available)
        if findings:
            by_rule = {}
            for finding in findings:
                rule_id = finding.get('ruleId', 'unknown')
                if rule_id not in by_rule:
                    by_rule[rule_id] = []
                by_rule[rule_id].append(finding)
            
            summary += "## Findings by Rule\n\n"
            for rule_id, rule_findings in sorted(by_rule.items()):
                summary += f"### {rule_id}\n"
                summary += f"- Count: {len(rule_findings)}\n"
                summary += f"- Scope: {rule_findings[0].get('scope', 'N/A')}\n\n"
    
    if github_step_summary:
        with open(github_step_summary, 'a') as f:
            f.write(summary)
    else:
        print(summary)


@click.command()
@click.option('--config', '-c', default='leftsize.yml', help='Path to LeftSize configuration file')
@click.option('--policies', '-p', help='Path to Cloud Custodian policies directory')
@click.option('--policy-files', multiple=True, help='Specific policy files to run (e.g., azure-cost-optimization.yml). Can be specified multiple times.')
@click.option('--output', '-o', help='Output file for findings')
@click.option('--backend-url', help='Backend URL to submit findings')
@click.option('--installation-id', help='GitHub App installation ID')
@click.option('--repository-token', '--token', help='Repository token for backend authentication')
@click.option('--subscription-id', help='Azure subscription ID to scan')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
def main(config, policies, policy_files, output, backend_url, installation_id, repository_token, subscription_id, verbose):
    """LeftSize Runner - Execute Cloud Custodian policies for cost optimization (CLI mode)"""
    
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
    logger.info("LeftSize Runner starting", version="1.0.0")
    
    try:
        # Load configuration
        config_data = load_configuration(config)
        
        # Override config with command line arguments
        if backend_url:
            config_data.setdefault('output', {})['backend_url'] = backend_url
        if installation_id:
            config_data.setdefault('output', {})['installation_id'] = installation_id
        if repository_token:
            config_data.setdefault('output', {})['repository_token'] = repository_token
        if subscription_id:
            config_data.setdefault('targets', {}).setdefault('azure', {})['subscriptions'] = [subscription_id]
        if policy_files:
            config_data.setdefault('policies', {})['policy_files'] = list(policy_files)
            
        # Determine policies directory
        policies_dir = policies or os.path.join(os.path.dirname(__file__), 'policies')
        
        # Validate Azure authentication (pass config to get subscription ID)
        azure_config = config_data.get('targets', {}).get('azure', {})
        if not validate_azure_auth(azure_config):
            logger.error("Azure authentication failed. Please configure Azure credentials.")
            return 1
            
        # Execute Cloud Custodian policies
        findings = execute_custodian_policies(policies_dir, config_data)
        
        # Process and submit findings
        if findings is None:
            logger.error("Failed to execute policies or retrieve findings.")
            return 1
        elif findings:
            submit_findings(findings, config_data)
        else:
            logger.info("No findings generated (policies executed successfully)")
            
        logger.info("LeftSize Runner completed successfully")
        return 0
        
    except Exception as e:
        logger.error("LeftSize Runner failed", error=str(e), exc_info=True)
        return 1
    
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
    logger.info("LeftSize Runner starting", version="1.0.0")
    
    try:
        # Load configuration
        config_data = load_configuration(config)
        
        # Override config with command line arguments
        if backend_url:
            config_data.setdefault('output', {})['backend_url'] = backend_url
        if installation_id:
            config_data.setdefault('output', {})['installation_id'] = installation_id
        if repository_token:
            config_data.setdefault('output', {})['repository_token'] = repository_token
        if subscription_id:
            config_data.setdefault('targets', {}).setdefault('azure', {})['subscriptions'] = [subscription_id]
        if dry_run:
            config_data.setdefault('execution', {})['dry_run'] = True
        if policy_files:
            config_data.setdefault('policies', {})['policy_files'] = list(policy_files)
            
        # Determine policies directory
        policies_dir = policies or os.path.join(os.path.dirname(__file__), 'policies')
        
        # Validate Azure authentication (pass config to get subscription ID)
        azure_config = config_data.get('targets', {}).get('azure', {})
        if not validate_azure_auth(azure_config):
            logger.error("Azure authentication failed. Please configure Azure credentials.")
            return 1
            
        # Execute Cloud Custodian policies
        findings = execute_custodian_policies(policies_dir, config_data)
        
        # Process and submit findings
        if findings is None:
            logger.error("Failed to execute policies or retrieve findings.")
            return 1
        elif findings:
            submit_findings(findings, config_data)
        else:
            logger.info("No findings generated (policies executed successfully)")
            
        logger.info("LeftSize Runner completed successfully")
        return 0
        
    except Exception as e:
        logger.error("LeftSize Runner failed", error=str(e), exc_info=True)
        return 1


def load_configuration(config_path: str) -> Dict[str, Any]:
    """Load and validate LeftSize configuration"""
    logger.info("Loading configuration", config_path=config_path)
    
    if not os.path.exists(config_path):
        # Create a default configuration if none exists
        logger.warning("Configuration file not found, using defaults", config_path=config_path)
        return create_default_config()
    
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    # Expand environment variables
    config = expand_environment_variables(config)
    
    logger.info("Configuration loaded successfully")
    return config


def create_default_config() -> Dict[str, Any]:
    """Create a minimal default configuration for GitHub Action"""
    return {
        'version': '1.0',
        'name': 'github-action-scan',
        'targets': {},  # Will be populated from environment variables
        'auth': {
            'method': 'environment'
        },
        'policies': {},  # Will be populated from include/exclude inputs
        'output': {},   # Will be populated from environment variables
        'execution': {
            'max_workers': 4,
            'timeout_minutes': 30
        }
    }


def expand_environment_variables(config: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively expand environment variables in configuration"""
    import re
    
    def expand_value(value):
        if isinstance(value, str):
            # Replace ${VAR} and ${VAR:-default} patterns
            pattern = r'\$\{([^}]+)\}'
            
            def replace_var(match):
                var_expr = match.group(1)
                if ':-' in var_expr:
                    var_name, default = var_expr.split(':-', 1)
                    return os.getenv(var_name, default)
                else:
                    return os.getenv(var_expr, match.group(0))
            
            return re.sub(pattern, replace_var, value)
        elif isinstance(value, dict):
            return {k: expand_value(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [expand_value(item) for item in value]
        else:
            return value
    
    return expand_value(config)


def validate_azure_auth(azure_config: Dict[str, Any]) -> bool:
    """Validate that Azure authentication is properly configured"""
    logger.info("Validating Azure authentication")
    
    try:
        from azure.identity import DefaultAzureCredential
        
        # Try to create credentials - this will work with OIDC tokens set by azure/login action
        credential = DefaultAzureCredential()
        
        # If we got here, credential creation succeeded
        # Cloud Custodian will discover subscriptions automatically
        logger.info("Azure authentication validated successfully")
        return True
        
    except Exception as e:
        logger.error("Azure authentication validation failed", error=str(e))
        return False


def detect_azure_currency(subscription_id: str = None) -> str:
    """
    Detect billing currency from Azure subscription.
    Tries to get currency from the Consumption API Price Sheet.
    Falls back to USD if detection fails.
    """
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.resource import SubscriptionClient
        import requests as req
        
        credential = DefaultAzureCredential()
        
        # Get subscription ID if not provided
        if not subscription_id:
            sub_client = SubscriptionClient(credential)
            subs = list(sub_client.subscriptions.list())
            if subs:
                subscription_id = subs[0].subscription_id
            else:
                logger.warning("No Azure subscriptions found, defaulting to USD")
                return "USD"
        
        # Get access token for Azure Resource Manager
        token = credential.get_token("https://management.azure.com/.default")
        
        # Try to get currency from Consumption Price Sheet API
        # This returns prices with currency info
        url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Consumption/pricesheets/default?api-version=2023-05-01&$top=1"
        headers = {
            "Authorization": f"Bearer {token.token}",
            "Content-Type": "application/json"
        }
        
        response = req.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            # Price sheet items have 'currencyCode' field
            pricesheets = data.get('properties', {}).get('pricesheets', [])
            if pricesheets and len(pricesheets) > 0:
                currency = pricesheets[0].get('currencyCode', 'USD')
                logger.info("Detected Azure billing currency", currency=currency, subscription_id=subscription_id)
                return currency
        
        # If price sheet didn't work, try Cost Management API
        # Query for a small cost amount to get the currency
        cost_url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.CostManagement/query?api-version=2023-03-01"
        cost_body = {
            "type": "ActualCost",
            "timeframe": "MonthToDate",
            "dataset": {
                "granularity": "None",
                "aggregation": {
                    "totalCost": {"name": "Cost", "function": "Sum"}
                }
            }
        }
        
        response = req.post(cost_url, headers=headers, json=cost_body, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            # Cost response has currency in properties
            columns = data.get('properties', {}).get('columns', [])
            for col in columns:
                if col.get('name') == 'Currency':
                    rows = data.get('properties', {}).get('rows', [])
                    if rows and len(rows) > 0:
                        # Find currency column index
                        currency_idx = next((i for i, c in enumerate(columns) if c.get('name') == 'Currency'), -1)
                        if currency_idx >= 0 and len(rows[0]) > currency_idx:
                            currency = rows[0][currency_idx]
                            logger.info("Detected Azure billing currency from Cost Management", currency=currency)
                            return currency
        
        logger.warning("Could not detect Azure currency, defaulting to USD", 
                      status_code=response.status_code if 'response' in dir() else 'N/A')
        return "USD"
        
    except Exception as e:
        logger.warning("Failed to detect Azure currency, defaulting to USD", error=str(e))
        return "USD"


def execute_custodian_policies(policies_dir: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Execute Cloud Custodian policies and collect findings"""
    logger.info("Executing Cloud Custodian policies", policies_dir=policies_dir)
    
    # Get cloud provider to filter policies
    cloud_provider = config.get('cloud_provider', 'azure')
    
    # Determine which policy files to run
    policy_files = config.get('policies', {}).get('policy_files', [])
    
    if not policy_files:
        # Default: auto-discover policy files matching cloud provider
        logger.info("Auto-discovering policy files for provider", provider=cloud_provider)
        policy_files = []
        for file in Path(policies_dir).glob('*.yml'):
            # Skip example files
            if 'example' in file.name.lower():
                continue
            # Filter by cloud provider prefix
            if cloud_provider == 'azure' and file.name.startswith('aws-'):
                continue
            if cloud_provider == 'aws' and file.name.startswith('azure-'):
                continue
            policy_files.append(file.name)
        
        if not policy_files:
            logger.error("No policy files found for provider", provider=cloud_provider, policies_dir=policies_dir)
            return []
    
    logger.info("Running policy files", files=policy_files, count=len(policy_files))
    
    all_findings = []
    
    # Execute each policy file
    for policy_file in policy_files:
        policy_path = os.path.join(policies_dir, policy_file)
        
        if not os.path.exists(policy_path):
            logger.warning("Policy file not found, skipping", file=policy_file, path=policy_path)
            continue
        
        logger.info("Executing policy file", file=policy_file)
        findings = execute_single_policy_file(policy_path, config)
        
        if findings:
            logger.info("Policy file completed", file=policy_file, findings_count=len(findings))
            all_findings.extend(findings)
        else:
            logger.info("Policy file completed with no findings", file=policy_file)
    
    logger.info("All policies executed", total_findings=len(all_findings))
    return all_findings


def execute_single_policy_file(policies_file: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Execute a single Cloud Custodian policy file"""
    findings = []
    
    # Create temporary directory for Custodian output
    with tempfile.TemporaryDirectory() as temp_dir:
        output_dir = os.path.join(temp_dir, 'custodian-output')
        os.makedirs(output_dir, exist_ok=True)
        
        # Build Custodian command - use the custodian from the same Python environment
        custodian_bin = os.path.join(os.path.dirname(sys.executable), 'custodian')
        if not os.path.isfile(custodian_bin):
            custodian_bin = 'custodian'  # Fall back to PATH
        cmd = [
            custodian_bin, 'run',
            '--output-dir', output_dir,
            '--cache-period', '0',  # Disable caching for fresh results
            policies_file
        ]
        
        # Add dry-run flag if configured
        if config.get('execution', {}).get('dry_run', True):
            cmd.append('--dry-run')
            logger.info("Running in dry-run mode")
        
        # Note: Cloud Custodian doesn't support --var for Azure provider
        # Subscription is configured via environment variables
        
        logger.info("Executing custodian command", cmd=" ".join(cmd))
        
        try:
            # Execute Cloud Custodian
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=config.get('execution', {}).get('timeout_minutes', 30) * 60,
                env=_build_custodian_env()
            )
            
            if result.returncode != 0:
                logger.error("Custodian execution failed", returncode=result.returncode)
                # Only log stdout/stderr when LEFTSIZE_DEBUG is enabled
                if os.environ.get("LEFTSIZE_DEBUG", "").lower() in ("1", "true", "yes"):
                    logger.debug("Custodian stdout", stdout=result.stdout)
                    logger.debug("Custodian stderr", stderr=result.stderr)
                return []
            
            logger.info("Custodian execution completed")
            # Only log stdout when LEFTSIZE_DEBUG is enabled
            if os.environ.get("LEFTSIZE_DEBUG", "").lower() in ("1", "true", "yes"):
                logger.debug("Custodian output", stdout=result.stdout)
            
            # Parse Custodian output
            findings = parse_custodian_output(output_dir, config)
            
        except subprocess.TimeoutExpired:
            logger.error("Custodian execution timed out")
            return []
        except Exception as e:
            logger.error("Custodian execution error", error=str(e))
            return []
    
    logger.info("Policy execution completed", findings_count=len(findings))
    return findings


def build_scope_from_resource_id(resource_id: str, config: Dict[str, Any]) -> str:
    """Build LeftSize scope from resource ID - handles Azure and AWS formats.
    
    For AWS: Uses account ID + region for proper isolation in multi-account and multi-region setups.
    For Azure: Uses subscription ID and resource group.
    """
    cloud_provider = config.get('cloud_provider', 'azure')
    
    # Helper to get AWS account ID from config (set during initialization via STS)
    def get_aws_account_id_from_config() -> Optional[str]:
        return config.get('targets', {}).get('aws', {}).get('account_id')
    
    # Helper to get AWS region from config or environment
    def get_aws_region_from_config() -> str:
        regions = config.get('targets', {}).get('aws', {}).get('regions', [])
        if regions:
            return regions[0]
        return os.getenv('AWS_REGION', 'us-east-1')
    
    try:
        if cloud_provider == 'aws':
            # AWS ARN format: arn:aws:service:region:account:resource
            # Extract both account and region from ARN when available
            account_id = None
            region = None
            
            if resource_id.startswith('arn:aws:'):
                parts = resource_id.split(':')
                # parts[3] is region, parts[4] is account ID
                if len(parts) >= 5:
                    if parts[3]:  # Region (empty for global services like S3)
                        region = parts[3]
                    if parts[4]:  # Account ID
                        account_id = parts[4]
            
            # Fall back to config values if not in ARN
            if not account_id:
                account_id = get_aws_account_id_from_config()
            if not region:
                region = get_aws_region_from_config()
            
            # Use account + region scope for proper multi-account AND multi-region isolation
            account_id = account_id or 'unknown'
            return f"aws:account/{account_id}/region/{region}"
        
        # Azure resource ID: /subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{type}/{name}
        parts = resource_id.split('/')
        if len(parts) >= 5 and parts[1] == 'subscriptions':
            subscription_id = parts[2]
            resource_group = parts[4] if len(parts) >= 5 else 'unknown'
            return f"azure:subscription/{subscription_id}/resourceGroup/{resource_group}"
        else:
            # Fallback scope - ensure we never return None
            subscription_id = get_subscription_id(config) or 'unknown'
            return f"azure:subscription/{subscription_id}"
    except Exception:
        # Final fallback - ensure we never return None
        if cloud_provider == 'aws':
            account_id = get_aws_account_id_from_config() or 'unknown'
            region = get_aws_region_from_config()
            return f"aws:account/{account_id}/region/{region}"
        subscription_id = get_subscription_id(config) or 'unknown'
        return f"azure:subscription/{subscription_id}"


def get_subscription_id(config: Dict[str, Any]) -> str:
    """Get Azure subscription ID from config or environment - never returns None"""
    subscriptions = config.get('targets', {}).get('azure', {}).get('subscriptions', [])
    if subscriptions and subscriptions[0]:
        return subscriptions[0]
    
    env_subscription = os.getenv('AZURE_SUBSCRIPTION_ID')
    if env_subscription:
        return env_subscription
    
    # Return a safe default instead of None
    return 'unknown'


def parse_custodian_output(output_dir: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Parse Cloud Custodian output and convert to LeftSize findings"""
    logger.info("Parsing Custodian output", output_dir=output_dir)
    
    findings = []
    
    # Iterate through policy output directories
    for policy_dir in Path(output_dir).iterdir():
        if not policy_dir.is_dir():
            continue
            
        policy_name = policy_dir.name
        resources_file = policy_dir / 'resources.json'
        
        if not resources_file.exists():
            logger.debug("No resources.json found for policy", policy=policy_name)
            continue
            
        try:
            with open(resources_file) as f:
                resources = json.load(f)
            
            if not resources:
                logger.debug("No resources found for policy", policy=policy_name)
                continue
                
            logger.info("Found resources for policy", policy=policy_name, count=len(resources))
            
            # Convert Custodian resources to LeftSize findings
            for resource in resources:
                finding = convert_resource_to_finding(policy_name, resource, config)
                if finding:
                    findings.append(finding)
                    
        except Exception as e:
            logger.error("Error parsing resources for policy", 
                        policy=policy_name, error=str(e))
            continue
    
    return findings


def extract_resource_id(resource: Dict[str, Any], config: Dict[str, Any]) -> str:
    """Extract resource ID from Cloud Custodian resource - handles Azure and AWS formats"""
    
    cloud_provider = config.get('cloud_provider', 'azure')
    
    # Azure resources have 'id' field
    if resource.get('id'):
        return resource['id']
    
    # AWS resources use different ID fields depending on resource type
    if cloud_provider == 'aws':
        # S3 buckets use 'Name'
        if resource.get('Name'):
            bucket_name = resource['Name']
            # Construct ARN-style ID for S3 buckets
            return f"arn:aws:s3:::{bucket_name}"
        
        # EC2 instances use 'InstanceId'
        if resource.get('InstanceId'):
            instance_id = resource['InstanceId']
            region = resource.get('Region', os.getenv('AWS_REGION', 'us-east-1'))
            # Note: Account ID not available, using placeholder
            return f"arn:aws:ec2:{region}::instance/{instance_id}"
        
        # EBS volumes use 'VolumeId'
        if resource.get('VolumeId'):
            volume_id = resource['VolumeId']
            region = resource.get('Region', os.getenv('AWS_REGION', 'us-east-1'))
            return f"arn:aws:ec2:{region}::volume/{volume_id}"
        
        # EBS snapshots use 'SnapshotId'
        if resource.get('SnapshotId'):
            snapshot_id = resource['SnapshotId']
            region = resource.get('Region', os.getenv('AWS_REGION', 'us-east-1'))
            return f"arn:aws:ec2:{region}::snapshot/{snapshot_id}"

        # VPCs use 'VpcId'
        if resource.get('VpcId') and not resource.get('VpcEndpointId'):
            vpc_id = resource['VpcId']
            region = resource.get('Region', os.getenv('AWS_REGION', 'us-east-1'))
            return f"arn:aws:ec2:{region}::vpc/{vpc_id}"

        # VPC Endpoints use 'VpcEndpointId'
        if resource.get('VpcEndpointId'):
            endpoint_id = resource['VpcEndpointId']
            region = resource.get('Region', os.getenv('AWS_REGION', 'us-east-1'))
            return f"arn:aws:ec2:{region}::vpc-endpoint/{endpoint_id}"

        # AMIs use 'ImageId'
        if resource.get('ImageId'):
            image_id = resource['ImageId']
            region = resource.get('Region', os.getenv('AWS_REGION', 'us-east-1'))
            return f"arn:aws:ec2:{region}::image/{image_id}"

        # EFS filesystems
        if resource.get('FileSystemId'):
            fs_id = resource['FileSystemId']
            region = resource.get('Region', os.getenv('AWS_REGION', 'us-east-1'))
            return f"arn:aws:elasticfilesystem:{region}::file-system/{fs_id}"

        # ElastiCache cache clusters
        if resource.get('CacheClusterId'):
            cache_id = resource['CacheClusterId']
            region = resource.get('Region', os.getenv('AWS_REGION', 'us-east-1'))
            return f"arn:aws:elasticache:{region}::cluster/{cache_id}"

        # RDS snapshots
        if resource.get('DBSnapshotArn'):
            return resource['DBSnapshotArn']
        if resource.get('DBSnapshotIdentifier'):
            snap_id = resource['DBSnapshotIdentifier']
            region = resource.get('Region', os.getenv('AWS_REGION', 'us-east-1'))
            return f"arn:aws:rds:{region}::snapshot/{snap_id}"

        # EKS clusters (c7n returns 'name' + 'arn')
        if resource.get('arn') and 'eks' in str(resource.get('arn', '')):
            return resource['arn']

        # IAM users expose 'UserName' and 'Arn' (fallback Arn handles it, but ensure UserName path works)
        if resource.get('UserName') and not resource.get('Arn'):
            user_name = resource['UserName']
            return f"arn:aws:iam:::user/{user_name}"
        
        # RDS instances use 'DBInstanceIdentifier'
        if resource.get('DBInstanceIdentifier'):
            db_id = resource['DBInstanceIdentifier']
            region = resource.get('Region', os.getenv('AWS_REGION', 'us-east-1'))
            return f"arn:aws:rds:{region}::db/{db_id}"
        
        # Lambda functions use 'FunctionName' or 'FunctionArn'
        if resource.get('FunctionArn'):
            return resource['FunctionArn']
        if resource.get('FunctionName'):
            func_name = resource['FunctionName']
            region = resource.get('Region', os.getenv('AWS_REGION', 'us-east-1'))
            return f"arn:aws:lambda:{region}::function/{func_name}"
        
        # NAT Gateways use 'NatGatewayId'
        if resource.get('NatGatewayId'):
            nat_id = resource['NatGatewayId']
            region = resource.get('Region', os.getenv('AWS_REGION', 'us-east-1'))
            return f"arn:aws:ec2:{region}::natgateway/{nat_id}"
        
        # Generic fallback for AWS - try common ARN/ID patterns across many c7n
        # resource types before giving up. Ordered from most-specific to least.
        # Values are checked for non-empty, so missing keys naturally skip.
        arn_like_fields = [
            # Fully-qualified ARNs (all casings c7n uses across resources)
            'Arn', 'ARN', 'arn',
            'LoadBalancerArn',         # app-elb, elbv2
            'AutoScalingGroupARN',     # asg
            'TableArn',                # dynamodb
            'CertificateArn',          # acm-certificate
            'serviceArn',              # ecs-service
            'repositoryArn',           # ecr
            'DBSnapshotArn',           # rds-snapshot (also handled earlier)
            'ResourceARN', 'ResourceArn',
            'ResourceId',
        ]
        for id_field in arn_like_fields:
            val = resource.get(id_field)
            if val:
                return val

        # Resources without ARNs in their payload — build one from identifier + region
        region = resource.get('Region', os.getenv('AWS_REGION', 'us-east-1'))
        if resource.get('AutoScalingGroupName'):
            return f"arn:aws:autoscaling:{region}::autoScalingGroup/{resource['AutoScalingGroupName']}"
        if resource.get('LoadBalancerName'):  # classic ELB
            return f"arn:aws:elasticloadbalancing:{region}::loadbalancer/{resource['LoadBalancerName']}"
        if resource.get('AllocationId'):  # EIP
            return f"arn:aws:ec2:{region}::elastic-ip/{resource['AllocationId']}"
        if resource.get('GroupId'):  # security group
            return f"arn:aws:ec2:{region}::security-group/{resource['GroupId']}"
        if resource.get('DomainName'):  # elasticsearch / opensearch
            return f"arn:aws:es:{region}::domain/{resource['DomainName']}"
        if resource.get('TableName'):  # dynamodb without TableArn
            return f"arn:aws:dynamodb:{region}::table/{resource['TableName']}"
        if resource.get('logGroupName'):  # cloudwatch logs
            return f"arn:aws:logs:{region}::log-group/{resource['logGroupName']}"
        if resource.get('repositoryName'):  # ecr
            return f"arn:aws:ecr:{region}::repository/{resource['repositoryName']}"
    
    # Final fallback - generate a unique ID from available data
    resource_name = resource.get('name', '') or resource.get('Name', '') or 'unknown'
    resource_type = resource.get('type', '') or resource.get('c7n:resource-type', '') or 'resource'
    return f"{cloud_provider}:{resource_type}/{resource_name}"


def convert_resource_to_finding(policy_name: str, resource: Dict[str, Any], config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Convert a Cloud Custodian resource to a LeftSize finding"""
    
    try:
        # Use policy name directly as rule ID (already has leftsize- prefix)
        rule_id = policy_name
        
        # Extract resource ID and basic info - handle both Azure and AWS formats
        # Azure uses 'id', AWS uses various fields depending on resource type
        resource_id = extract_resource_id(resource, config)
        resource_name = resource.get('name', '') or resource.get('Name', '')
        # For AWS resources that have tag-based names (e.g. VPCs, subnets),
        # try extracting Name from the tag list so UI/search shows friendly names.
        if not resource_name:
            aws_tags = resource.get('Tags')
            if isinstance(aws_tags, list):
                for tag in aws_tags:
                    if isinstance(tag, dict) and tag.get('Key') == 'Name' and tag.get('Value'):
                        resource_name = tag['Value']
                        break
        # Fall back to the AWS resource identifier fields when no tag Name present
        if not resource_name:
            resource_name = (
                resource.get('VpcId')
                or resource.get('VpcEndpointId')
                or resource.get('ImageId')
                or resource.get('FileSystemId')
                or resource.get('CacheClusterId')
                or resource.get('DBSnapshotIdentifier')
                or resource.get('DBInstanceIdentifier')
                or resource.get('UserName')
                or resource.get('InstanceId')
                or resource.get('VolumeId')
                or resource.get('SnapshotId')
                or resource.get('LoadBalancerName')
                or resource.get('AutoScalingGroupName')
                or resource.get('DomainName')
                or resource.get('TableName')
                or resource.get('logGroupName')
                or resource.get('repositoryName')
                or resource.get('AllocationId')
                or resource.get('GroupId')
                or resource.get('NatGatewayId')
                or ''
            )
        resource_type = resource.get('type', '') or resource.get('c7n:resource-type', '')
        
        # Build scope from resource ID
        scope = build_scope_from_resource_id(resource_id, config)
        
        # Extract metadata from resource - only include what Cloud Custodian provides
        metadata = extract_resource_metadata(resource, resource_id)
        
        # Add environment override if specified in config
        # This allows users to manually specify environment when auto-detection doesn't work
        environment_override = config.get('environment_name')
        if environment_override:
            if metadata is None:
                metadata = {}
            metadata['environmentOverride'] = environment_override
        
        finding = {
            'ruleId': rule_id,
            'resourceId': resource_id,
            'resourceName': resource_name,
            'resourceType': resource_type,
            'scope': scope,
            'discoveredAt': datetime.now(timezone.utc).isoformat(),
            'metadata': metadata  # Include extracted metadata
        }
        
        return finding
        
    except Exception as e:
        logger.error("Error converting resource to finding", 
                    policy=policy_name, 
                    resource_id=resource.get('id', 'unknown'),
                    error=str(e))
        return None


def extract_resource_metadata(resource: Dict[str, Any], resource_id: str) -> Dict[str, Any]:
    """Extract relevant metadata from Cloud Custodian resource"""
    metadata = {}
    
    try:
        # Parse resource ID to extract components
        # Azure format: /subscriptions/{sub}/resourceGroups/{rg}/...
        # AWS format: arn:aws:service:region:account:resource
        parts = resource_id.split('/')
        if len(parts) >= 5 and parts[1] == 'subscriptions':
            # Azure resource ID
            metadata['subscriptionId'] = parts[2]
            if len(parts) >= 5:
                metadata['resourceGroup'] = parts[4]
            if len(parts) >= 9:
                metadata['resourceName'] = parts[8]
        elif resource_id.startswith('arn:aws:'):
            # AWS ARN - extract account and region
            arn_parts = resource_id.split(':')
            if len(arn_parts) >= 5:
                if arn_parts[3]:  # region (empty for global services)
                    metadata['region'] = arn_parts[3]
                if arn_parts[4]:  # account ID
                    metadata['accountId'] = arn_parts[4]
        
        # Extract location (Azure)
        location = resource.get('location')
        if location:
            metadata['location'] = location
        
        # Extract tags - handle both Azure (dict) and AWS (list) formats
        # Azure: {"Environment": "Production", "Team": "DevOps"}
        # AWS: [{"Key": "Environment", "Value": "Production"}, {"Key": "Team", "Value": "DevOps"}]
        tags = resource.get('tags') or resource.get('Tags')
        if tags:
            if isinstance(tags, dict):
                # Azure format - already a dict
                metadata['tags'] = tags
            elif isinstance(tags, list):
                # AWS format - convert list of Key/Value dicts to simple dict
                tags_dict = {}
                for tag in tags:
                    if isinstance(tag, dict):
                        key = tag.get('Key') if tag.get('Key') is not None else tag.get('key')
                        # Handle value carefully - empty string '' is valid, None is not
                        value = tag.get('Value') if 'Value' in tag else tag.get('value')
                        if key and value is not None:
                            tags_dict[key] = value
                if tags_dict:
                    metadata['tags'] = tags_dict
        
        # Extract resource-specific properties
        properties = resource.get('properties', {})
        sku = resource.get('sku', {})
        
        # VM-specific
        if 'virtualMachines' in resource_id:
            hw_profile = properties.get('hardwareProfile', {})
            if 'vmSize' in hw_profile:
                metadata['vmSize'] = hw_profile['vmSize']
        
        # Disk-specific
        if 'disks' in resource_id:
            if 'diskSizeGB' in properties:
                metadata['diskSizeGB'] = properties['diskSizeGB']
            if 'tier' in sku:
                metadata['skuTier'] = sku['tier']
            if 'name' in sku:
                metadata['skuName'] = sku['name']
        
        # App Service Plan-specific
        if 'serverfarms' in resource_id:
            if 'tier' in sku:
                metadata['tier'] = sku['tier']
            if 'size' in sku:
                metadata['size'] = sku['size']
            if 'name' in sku:
                metadata['skuName'] = sku['name']
            if 'capacity' in sku:
                metadata['capacity'] = sku['capacity']
        
        # Storage Account-specific
        if 'storageAccounts' in resource_id:
            if 'tier' in sku:
                metadata['skuTier'] = sku['tier']
            if 'name' in sku:
                metadata['skuName'] = sku['name']
            if 'accessTier' in properties:
                metadata['accessTier'] = properties['accessTier']
            if 'allowBlobPublicAccess' in properties:
                metadata['allowBlobPublicAccess'] = properties['allowBlobPublicAccess']
        
        # Public IP-specific
        if 'publicIPAddresses' in resource_id:
            if 'name' in sku:
                metadata['skuName'] = sku['name']
            if 'tier' in sku:
                metadata['skuTier'] = sku['tier']
            ip_config = properties.get('ipConfiguration', {})
            if ip_config:
                metadata['associated'] = True
            else:
                metadata['associated'] = False
        
    except Exception as e:
        logger.warning("Failed to extract metadata from resource", 
                      resource_id=resource_id, error=str(e))
    
    return metadata if metadata else None



def submit_findings(findings: List[Dict[str, Any]], config: Dict[str, Any]) -> Dict[str, Any]:
    """Submit findings to LeftSize backend
    
    Returns:
        Dict with submission result info including plan details if available
        
    Raises:
        RepositoryLimitExceeded: If the free tier repository limit is exceeded
    """
    
    output_config = config.get('output', {})
    backend_url = output_config.get('backend_url')
    installation_id = output_config.get('installation_id')
    # Support both 'token' (from config file) and 'repository_token' (from command line)
    repository_token = output_config.get('repository_token') or output_config.get('token')
    
    result = {'submitted': False, 'plan_info': None}
    
    # Save local output if configured
    if output_config.get('local_output', {}).get('enabled', False):
        save_local_output(findings, output_config)
    
    if not backend_url or not installation_id:
        logger.warning("Backend URL or installation ID not configured, skipping submission")
        return result
    
    if not repository_token:
        logger.warning("Repository token not configured, skipping submission")
        return result
    
    try:
        # Get currency from config
        currency = config.get('currency', 'USD')
        
        # Group findings by rule and scope (as expected by backend)
        finding_groups = group_findings(findings, currency)
        
        # Submit to backend - token passed via Authorization header (not in URL for security)
        url = f"{backend_url}/findings/{installation_id}"
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'LeftSize-Runner/1.0',
            'Authorization': f'Bearer {repository_token}'
        }
        
        # Log URL without sensitive token
        logger.info("Submitting findings to backend", 
                   url=url, 
                   finding_groups=len(finding_groups),
                   total_findings=len(findings),
                   currency=currency)
        
        payload = {"FindingGroups": finding_groups, "Currency": currency}
        response = requests.post(url, json=payload, headers=headers, timeout=30)
        
        # Handle 402 Payment Required (repository limit exceeded)
        if response.status_code == 402:
            try:
                error_data = response.json()
                error_code = error_data.get('Code', '')
                if error_code == 'REPOSITORY_LIMIT_EXCEEDED':
                    context = error_data.get('Context', {})
                    raise RepositoryLimitExceeded(
                        error_data.get('Message', 'Repository limit exceeded'),
                        context
                    )
            except (ValueError, KeyError):
                pass
            # If we can't parse the error, raise generic
            response.raise_for_status()
        
        response.raise_for_status()
        
        response_data = response.json()
        logger.info("Findings submitted successfully", response_status=response.status_code)
        # Only log response data when LEFTSIZE_DEBUG is enabled
        if os.environ.get("LEFTSIZE_DEBUG", "").lower() in ("1", "true", "yes"):
            logger.debug("Backend response", response_data=response_data)
        
        result['submitted'] = True
        # Extract plan info from response if available
        if 'PlanInfo' in response_data:
            result['plan_info'] = response_data['PlanInfo']
        
        return result
        
    except RepositoryLimitExceeded:
        raise  # Re-raise to allow caller to handle specifically
    except Exception as e:
        logger.error("Failed to submit findings to backend", error=str(e))
        raise  # Re-raise to allow caller to handle


def group_findings(findings: List[Dict[str, Any]], currency: str = 'USD') -> List[Dict[str, Any]]:
    """Group findings by rule ID and scope for backend submission"""
    
    groups = {}
    
    for finding in findings:
        rule_id = finding['ruleId']
        scope = finding['scope']
        key = (rule_id, scope)
        
        if key not in groups:
            # Determine cloud_provider from scope string
            cloud_provider = 'azure' if scope.startswith('azure:') else 'aws'
            groups[key] = {
                'policy': rule_id,
                'scope': scope,
                'cloud_provider': cloud_provider,
                'resources': []
            }
        
        resource = {
            'resource_id': finding['resourceId'],
            'policy': rule_id,
            'metadata': finding.get('metadata') or {},
            'estimated_savings': finding.get('estimatedSavings', 0),
            'currency': currency,
        }
        
        groups[key]['resources'].append(resource)
    
    return list(groups.values())


def determine_severity(rule_id: str, metadata: Dict[str, Any]) -> str:
    """Determine severity based on rule ID patterns and metadata"""
    
    # Check if severity is in metadata (from resource tags)
    if metadata:
        if 'leftsize-severity' in metadata:
            return metadata['leftsize-severity'].lower()
        # Check tags dict if present
        tags = metadata.get('tags', {})
        if isinstance(tags, dict) and 'leftsize-severity' in tags:
            return tags['leftsize-severity'].lower()
    
    rule_lower = rule_id.lower()
    
    # Critical: Security issues with direct data breach risk
    if any(kw in rule_lower for kw in ['anonymous', 'public-access', 'unencrypted', 'no-encryption']):
        return 'critical'
    
    # High: Security misconfigurations, missing critical tags
    if any(kw in rule_lower for kw in ['security', 'exposed', 'open-', 'unrestricted']):
        return 'high'
    
    # Medium: Governance issues, missing tags, cost optimization
    if any(kw in rule_lower for kw in ['missing-', 'untagged', 'idle', 'unused', 'governance']):
        return 'medium'
    
    # Low: Minor issues, recommendations
    if any(kw in rule_lower for kw in ['recommend', 'suggest', 'consider']):
        return 'low'
    
    # Default to medium for cost optimization findings
    return 'medium'


def save_local_output(findings: List[Dict[str, Any]], output_config: Dict[str, Any]) -> None:
    """Save findings to local file for debugging"""
    
    local_config = output_config.get('local_output', {})
    output_format = local_config.get('format', 'json')
    output_file = local_config.get('file', 'leftsize-findings.json')
    
    try:
        with open(output_file, 'w') as f:
            if output_format == 'yaml':
                yaml.dump(findings, f, default_flow_style=False)
            else:
                json.dump(findings, f, indent=2, default=str)
                
        logger.info("Local output saved", file=output_file, format=output_format)
        
    except Exception as e:
        logger.error("Failed to save local output", error=str(e))


if __name__ == "__main__":
    # Check if running in GitHub Actions
    if os.getenv('GITHUB_ACTIONS') == 'true':
        # Check mode
        mode = os.getenv('LEFTSIZE_MODE', 'scan').lower()
        if mode == 'stats':
            # Import and run stats mode
            from stats import stats_main
            sys.exit(stats_main())
        else:
            # Default: scan mode
            sys.exit(github_action_main())
    else:
        sys.exit(main())