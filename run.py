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
import time
import uuid
from urllib.parse import urlsplit
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
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


def configure_logging(verbose: bool) -> None:
    """INFO for everything; with verbose or LEFTSIZE_DEBUG, DEBUG for LeftSize's own
    loggers only (LEFTSIZE_DEBUG also turns on Custodian's output and the API response).
    Library loggers (botocore, urllib3, azure) stay quiet: their debug output includes
    request headers and signing details."""
    logging.basicConfig(level=logging.INFO)
    level = logging.DEBUG if verbose or _debug_enabled() else logging.INFO
    for name in (__name__, 'run', 'stats', '__main__'):
        logging.getLogger(name).setLevel(level)
    for name in ('botocore', 'boto3', 'urllib3', 'azure', 'c7n', 'c7n_azure'):
        logging.getLogger(name).setLevel(logging.WARNING)


def record_problem(config: Dict[str, Any], message: str) -> None:
    """Note something that made the scan incomplete, for the job summary and the
    failed-policies output. Problems never stop the scan by themselves."""
    problems = config.setdefault('scan_problems', [])
    if message not in problems:
        problems.append(message)


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
        self.upgrade_url = context.get('upgradeUrl', 'https://leftsize.com/#pricing')
        self.account_login = context.get('accountLogin', '')
        self.plan = context.get('plan', 'Free')


class SubmissionRateLimited(Exception):
    """Raised when the backend's daily submission limit is reached (HTTP 429)."""


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


# The repository token is sent to the backend, so only LeftSize hosts are accepted
BACKEND_DOMAINS = ('leftsize.com', 'leftsize.io')


def validate_backend_url(url: str) -> bool:
    """An https URL on a LeftSize domain (api.leftsize.com by default)."""
    if not url or not url.strip():
        return False
    url = url.strip()
    if not url.lower().startswith('https://'):
        logger.warning("Backend URL must use HTTPS", url=url)
        return False
    try:
        parts = urlsplit(url)
        host = (parts.hostname or '').lower()
        _ = parts.port  # raises ValueError on a malformed port
    except ValueError:
        return False
    if parts.username or parts.password:
        return False
    if not any(host == d or host.endswith('.' + d) for d in BACKEND_DOMAINS):
        logger.error("Backend URL must be a LeftSize host", host=host)
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
    # 'all' scans every region enabled for the account
    if region.strip() == 'all':
        return True
    # AWS region pattern: us-east-1, eu-west-2, us-gov-west-1, etc.
    region_pattern = r'^[a-z]{2}(-gov|-iso[a-z]?)?-[a-z]+-\d+$'
    return re.match(region_pattern, region.strip()) is not None


def get_aws_account_name(session: Any = None) -> Optional[str]:
    """The AWS account name (account:GetAccountInformation for the caller's own account,
    read-only and part of ReadOnlyAccess), e.g. "flux-acc". In AWS Organizations this is
    the name shown for the member account; it often names the environment."""
    try:
        if session is None:
            import boto3
            session = boto3.session.Session()
        name = session.client('account').get_account_information().get('AccountName')
        logger.info("AWS account name", name=name)
        return name
    except Exception as e:
        logger.warning("Could not read the AWS account name; environment from tags and names only", error=str(e))
        return None


def get_aws_account_alias(session: Any = None) -> Optional[str]:
    """The AWS account alias (iam:ListAccountAliases, read-only), e.g. "shop-acc".
    Used as an environment signal when accounts represent environments."""
    try:
        if session is None:
            import boto3
            session = boto3.session.Session()
        aliases = session.client('iam').list_account_aliases().get('AccountAliases') or []
        alias = aliases[0] if aliases else None
        logger.info("AWS account alias", alias=alias)
        return alias
    except Exception as e:
        logger.warning("Could not read the AWS account alias; environment from tags and names only", error=str(e))
        return None


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
    
    configure_logging(verbose)
    
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
    
    mode = os.getenv('LEFTSIZE_MODE', 'scan').strip().lower() or 'scan'
    if mode != 'scan':
        logger.error("Invalid mode. Must be 'scan' or 'stats'.", mode=mode)
        set_github_output('findings-submitted', 'false')
        return 1
    
    # Validate cloud provider input
    cloud_provider = cloud_provider.strip().lower()
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
            unknown_cats = [c for c in categories if normalize_policy_category(c) is None]
            if unknown_cats:
                logger.error("Unknown policy category. Use: cost-optimization, deprecation, governance, security",
                             invalid=unknown_cats)
                set_github_output('findings-submitted', 'false')
                return 1
            config_data.setdefault('policies', {})['include_categories'] = [
                normalize_policy_category(c) for c in categories]
            
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
                # sts:GetCallerIdentity needs no permission, so this means no usable credentials
                set_github_output('findings-submitted', 'false')
                logger.error("AWS authentication failed: sts:GetCallerIdentity did not return an account. "
                             "Configure AWS credentials (for example aws-actions/configure-aws-credentials) "
                             "before this step.")
                return 1
            aws_account_name = get_aws_account_name()
            if aws_account_name:
                config_data.setdefault('targets', {}).setdefault('aws', {})['account_name'] = aws_account_name
            aws_account_alias = get_aws_account_alias()
            if aws_account_alias:
                config_data.setdefault('targets', {}).setdefault('aws', {})['account_alias'] = aws_account_alias
        
        # Execute Cloud Custodian policies
        findings = execute_custodian_policies(policies_dir, config_data)
        problems = config_data.get('scan_problems', [])
        
        if findings is None:
            set_scan_outputs([], submitted=False, problems=problems)
            print_github_summary([], submitted=False, problems=problems, scan_failed=True)
            logger.error("No policies could run, so this scan has no results. Check the cloud "
                         "credentials and the errors above.")
            return 1
        
        findings_count = len(findings)
        logger.info(f"Found {findings_count} findings")
        
        # Submit findings to backend
        submitted = False
        plan_info = None
        
        if findings and backend_url and installation_id and repository_token:
            try:
                result = submit_findings(findings, config_data)
                submitted = result.get('submitted', False)
                plan_info = result.get('plan_info')
                if submitted:
                    logger.info("Findings submitted successfully to backend")
            except RepositoryLimitExceeded as e:
                # Don't fail the workflow: the summary explains the plan limit
                logger.warning(f"Repository limit exceeded: {e.message}")
                set_scan_outputs(findings, submitted=False, problems=problems, limit_exceeded=True)
                print_github_summary(findings, submitted=False, limit_exceeded=e, problems=problems)
                return 0
            except SubmissionRateLimited as e:
                # Daily submission limit: the next scheduled scan submits again
                logger.warning(f"Findings not submitted: {e}")
                set_scan_outputs(findings, submitted=False, problems=problems)
                print_github_summary(findings, submitted=False, problems=problems, rate_limited=e)
                return 0
            except Exception as e:
                logger.error(f"Failed to submit findings to backend: {e}")
                set_scan_outputs(findings, submitted=False, problems=problems)
                print_github_summary(findings, submitted=False, problems=problems)
                return 1
        
        set_scan_outputs(findings, submitted=submitted, problems=problems)
        print_github_summary(findings, submitted, plan_info=plan_info, problems=problems)
        
        if problems:
            logger.warning("Scan completed with problems; some results may be missing", problems=problems)
        logger.info("LeftSize GitHub Action completed successfully")
        return 0
        
    except Exception as e:
        set_scan_outputs([], submitted=False, problems=[])
        logger.error("LeftSize GitHub Action failed", error=str(e), exc_info=True)
        return 1


# GitHub limits a step's outputs to 1 MB in total; larger findings go to a file only
FINDINGS_JSON_OUTPUT_LIMIT = 512 * 1024


def set_scan_outputs(
    findings: List[Dict[str, Any]],
    submitted: bool,
    problems: List[str],
    limit_exceeded: bool = False,
) -> None:
    """Set the action outputs. findings-file always holds every finding; findings-json
    holds them too unless that would exceed GitHub's output size limit."""
    findings_json = json.dumps(findings, default=str)
    findings_file = ''
    runner_temp = os.getenv('RUNNER_TEMP')
    if runner_temp and os.path.isdir(runner_temp):
        findings_file = os.path.join(runner_temp, 'leftsize-findings.json')
        with open(findings_file, 'w') as f:
            f.write(findings_json)
    if len(findings_json) > FINDINGS_JSON_OUTPUT_LIMIT:
        logger.warning("findings-json output is too large for GitHub; use findings-file instead",
                       size=len(findings_json))
        findings_json = '[]'
    set_github_output('findings-count', str(len(findings)))
    set_github_output('findings-submitted', 'true' if submitted else 'false')
    set_github_output('findings-json', findings_json)
    set_github_output('findings-file', findings_file)
    set_github_output('failed-policies', json.dumps(problems))
    set_github_output('limit-exceeded', 'true' if limit_exceeded else 'false')


def set_github_output(name: str, value: str):
    """Set GitHub Actions output"""
    github_output = os.getenv('GITHUB_OUTPUT')
    if github_output:
        with open(github_output, 'a') as f:
            f.write(f"{name}={value}\n")
    else:
        # Fallback for testing
        print(f"::set-output name={name}::{value}")


def _md_cell(value: Any) -> str:
    """Text from the backend as one markdown table cell: no pipes, line breaks or links."""
    text = re.sub(r'[\r\n|]+', ' ', str(value))
    return text.replace('[', '(').replace(']', ')').strip()


def _safe_link(url: Any, fallback: str = 'https://leftsize.com/#pricing') -> str:
    """Only https links to a LeftSize domain end up in the summary."""
    text = str(url or '')
    try:
        host = (urlsplit(text).hostname or '').lower()
    except ValueError:
        return fallback
    if text.lower().startswith('https://') and not re.search(r'[\s()<>]', text) and any(
            host == d or host.endswith('.' + d) for d in BACKEND_DOMAINS):
        return text
    return fallback


def print_github_summary(
    findings: List[Dict[str, Any]], 
    submitted: bool,
    plan_info: Optional[Dict[str, Any]] = None,
    limit_exceeded: Optional[RepositoryLimitExceeded] = None,
    problems: Optional[List[str]] = None,
    scan_failed: bool = False,
    rate_limited: Optional[Exception] = None,
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
    
    if scan_failed:
        summary += ("## ❌ Scan failed\n\nNo policies could run, so there are no results. This is "
                    "usually expired or missing cloud credentials; the log of this step shows the error.\n\n")
    if rate_limited:
        summary += (f"## ⚠️ Findings not submitted\n\n{_md_cell(rate_limited)} The next scheduled scan "
                    "submits again.\n\n---\n\n")
    if problems:
        summary += "## ⚠️ Incomplete scan\n\nSome checks didn't run, so findings may be missing:\n\n"
        summary += "".join(f"- {_md_cell(p)}\n" for p in problems[:50])
        if len(problems) > 50:
            summary += f"- … and {len(problems) - 50} more\n"
        summary += "\nMissing read permissions are the usual cause.\n\n---\n\n"
    
    # Show repository limit exceeded warning first (if applicable)
    if limit_exceeded:
        summary += f"""## ⚠️ Repository Limit Reached

Your {_md_cell(limit_exceeded.plan)} plan allows scanning **{limit_exceeded.limit} repositories**. You've already scanned {limit_exceeded.current_count} repositories.

**Findings from this scan were not submitted** because the repository limit has been exceeded.

👉 **[See plans]({_safe_link(limit_exceeded.upgrade_url)})** to scan more repositories.

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
            summary += f"| Team (upgrade required) | {pro_count} | ❌ 0 |\n"
        summary += f"| **Total** | **{free_count + pro_count}** | **{free_count}** |\n\n"
        
        # Free tier findings table
        if free_tier_findings:
            summary += f"## Free Tier Findings ({free_count} → Issues Created)\n\n"
            summary += "| Rule | Resources | Est. Savings |\n"
            summary += "|------|-----------|-------------|\n"
            for f in free_tier_findings:
                rule_name = _md_cell(f.get('RuleName', f.get('RuleId', 'Unknown')))
                resource_count = f.get('ResourceCount', 0)
                savings = f.get('EstimatedSavings', 0)
                savings_str = f"~${savings:,.0f}/mo" if savings > 0 else "-"
                summary += f"| {rule_name} | {resource_count} | {savings_str} |\n"
            summary += "\n"
        
        # Pro tier findings table (the upsell section)
        if pro_tier_findings:
            summary += f"## Team Findings ({pro_count} → Upgrade to Unlock)\n\n"
            summary += "| Rule | Resources | Est. Savings |\n"
            summary += "|------|-----------|-------------|\n"
            for f in pro_tier_findings:
                rule_name = _md_cell(f.get('RuleName', f.get('RuleId', 'Unknown')))
                resource_count = f.get('ResourceCount', 0)
                savings = f.get('EstimatedSavings', 0)
                savings_str = f"~${savings:,.0f}/mo" if savings > 0 else "-"
                summary += f"| {rule_name} | {resource_count} | {savings_str} |\n"
            summary += "\n"
            
            # Upsell message
            upgrade_url = _safe_link(plan_info.get('UpgradeUrl'))
            if pro_savings > 0:
                summary += f"> 💡 **Upgrade to Team** to create issues for all {free_count + pro_count} findings and unlock ~${pro_savings:,.0f}/mo in additional estimated savings.\n"
            else:
                summary += f"> 💡 **Upgrade to Team** to create issues for all {free_count + pro_count} findings.\n"
            summary += f"> 👉 [Upgrade Now]({upgrade_url})\n\n"
        
        # Plan information footer
        repo_count = plan_info.get('ScannedRepositoryCount', 0)
        repo_limit = plan_info.get('RepositoryLimit', 3)
        remaining = max(0, repo_limit - repo_count)
        summary += "---\n\n"
        summary += f"**Plan**: Free Tier ({repo_count}/{repo_limit} repositories scanned, {remaining} remaining)\n\n"
    
    # Paid plans (Team, Business, legacy Pro): all findings included
    elif plan_info and plan_info.get('PlanType') in ('Team', 'Business', 'Pro'):
        plan_name = _md_cell(plan_info.get('PlanType'))
        total_findings = len(findings)
        total_savings = sum(f.get('EstimatedSavings', 0) for f in findings_breakdown) if findings_breakdown else 0
        
        summary += f"""## Summary

- **Plan**: {plan_name} ✨
- **Findings Detected**: {total_findings}
- **Issues Created**: ✅ {total_findings}
"""
        if total_savings > 0:
            summary += f"- **Estimated Savings**: ~${total_savings:,.0f}/mo\n"
        summary += "\n"
        
        # Show findings table
        if findings_breakdown:
            # The backend may not send a category; only show the column when it does
            with_category = any(f.get('Category') for f in findings_breakdown)
            summary += "## Findings by Rule\n\n"
            summary += "| Rule | Resources | Est. Savings |" + (" Category |" if with_category else "") + "\n"
            summary += "|------|-----------|-------------|" + ("----------|" if with_category else "") + "\n"
            for f in findings_breakdown:
                rule_name = _md_cell(f.get('RuleName', f.get('RuleId', 'Unknown')))
                resource_count = f.get('ResourceCount', 0)
                savings = f.get('EstimatedSavings', 0)
                savings_str = f"~${savings:,.0f}/mo" if savings > 0 else "-"
                category = f" {_md_cell(f.get('Category') or '-')} |" if with_category else ""
                summary += f"| {rule_name} | {resource_count} | {savings_str} |{category}\n"
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
    
    configure_logging(verbose)
    
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
        
        credential = DefaultAzureCredential()
        # Creating the credential succeeds even without a login, so ask for a token. A
        # failure is only a warning: Custodian authenticates on its own, and when it can't,
        # no policy file runs and the scan fails anyway.
        try:
            credential.get_token("https://management.azure.com/.default")
            logger.info("Azure authentication validated successfully")
        except Exception as e:
            logger.warning("Azure token request failed; the scan fails if Custodian can't log in either",
                           error=str(e))
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
        
        # Without azure-subscription-ids: the subscription being scanned (Custodian's
        # session: the azure/login subscription), not the first one the login can see
        if not subscription_id:
            try:
                from c7n_azure.session import Session
                subscription_id = Session().get_subscription_id()
            except Exception as e:
                logger.debug("Could not read the scanned subscription", error=str(e))
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


POLICY_CATEGORIES = ('cost-optimization', 'deprecation', 'governance', 'security')
POLICY_CATEGORY_ALIASES = {
    'cost': 'cost-optimization',
    'aks-optimization': 'cost-optimization',
    'deprecations': 'deprecation',
}


def normalize_policy_category(category: str) -> Optional[str]:
    """Map an include-policies value to a policy metadata category (None if unknown)."""
    value = category.strip().lower()
    value = POLICY_CATEGORY_ALIASES.get(value, value)
    return value if value in POLICY_CATEGORIES else None


def filter_policy_file(policy_path: str, config: Dict[str, Any], work_dir: str) -> Optional[str]:
    """Apply include-policies / exclude-policies to one policy file.

    Returns the path to run: the original file when no filter applies, a
    filtered copy in work_dir, or None when no policy of the file is left.
    """
    filters = config.get('policies', {})
    include = set(filters.get('include_categories') or [])
    exclude = {r if r.startswith('leftsize-') else f'leftsize-{r}' for r in filters.get('exclude_rules') or []}
    if not include and not exclude:
        return policy_path

    with open(policy_path) as f:
        data = yaml.safe_load(f) or {}
    policies = data.get('policies') or []
    kept = [
        p for p in policies
        if (not include or (p.get('metadata') or {}).get('category') in include)
        and p.get('name') not in exclude
    ]
    if not kept:
        return None
    if len(kept) == len(policies):
        return policy_path
    filtered_path = os.path.join(work_dir, os.path.basename(policy_path))
    with open(filtered_path, 'w') as f:
        yaml.safe_dump({**data, 'policies': kept}, f, sort_keys=False)
    logger.info("Filtered policy file", file=os.path.basename(policy_path), kept=len(kept), total=len(policies))
    return filtered_path


def strip_policy_actions(policy_path: str, work_dir: str) -> str:
    """A copy of the policy file without `actions:` blocks, so no policy can change a
    resource even if --dry-run were ever dropped. Returns the original path when no
    policy has actions."""
    with open(policy_path) as f:
        data = yaml.safe_load(f) or {}
    policies = data.get('policies') or []
    if not any('actions' in p for p in policies):
        return policy_path
    stripped = [{k: v for k, v in p.items() if k != 'actions'} for p in policies]
    safe_dir = os.path.join(work_dir, 'read-only')
    os.makedirs(safe_dir, exist_ok=True)
    safe_path = os.path.join(safe_dir, os.path.basename(policy_path))
    with open(safe_path, 'w') as f:
        yaml.safe_dump({**data, 'policies': stripped}, f, sort_keys=False)
    return safe_path


def execute_custodian_policies(policies_dir: str, config: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """Execute Cloud Custodian policies and collect findings.

    Returns None when no policy file could run at all (credentials, timeouts, a broken
    install), so the scan fails instead of reporting "no findings". Files that fail
    while others succeed are recorded as scan problems."""
    global LOOKUP_RESOURCE_GROUP_TAGS
    logger.info("Executing Cloud Custodian policies", policies_dir=policies_dir)
    # Real scan: environment classification may read Azure resource group tags
    LOOKUP_RESOURCE_GROUP_TAGS = True
    
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
            return None
    
    logger.info("Running policy files", files=policy_files, count=len(policy_files))
    
    all_findings = []
    ran = 0
    failed_files = []
    
    # Execute each policy file (filtered copies of include/exclude-policies go to filter_dir).
    # One Custodian cache for the whole scan: policies of the same resource type reuse the
    # resource list instead of listing it again. The cache is new for every scan.
    with tempfile.TemporaryDirectory() as filter_dir:
        config['_custodian_cache'] = os.path.join(filter_dir, 'custodian.cache')
        for policy_file in policy_files:
            policy_path = os.path.join(policies_dir, policy_file)
            
            if not os.path.exists(policy_path):
                logger.warning("Policy file not found, skipping", file=policy_file, path=policy_path)
                continue
            
            run_path = filter_policy_file(policy_path, config, filter_dir)
            if run_path is None:
                logger.info("All policies of file filtered out, skipping", file=policy_file)
                continue
            
            logger.info("Executing policy file", file=policy_file)
            findings = execute_single_policy_file(strip_policy_actions(run_path, filter_dir), config)
            
            if findings is None:
                failed_files.append(policy_file)
                record_problem(config, f"{policy_file}: did not run (see the log above)")
                continue
            ran += 1
            if findings:
                logger.info("Policy file completed", file=policy_file, findings_count=len(findings))
                all_findings.extend(findings)
            else:
                logger.info("Policy file completed with no findings", file=policy_file)
    
        config.pop('_custodian_cache', None)
    
    if failed_files and ran == 0:
        logger.error("No policy file could run", failed_files=failed_files)
        return None
    logger.info("All policies executed", total_findings=len(all_findings), failed_files=failed_files)
    return all_findings


def custodian_region_args(config: Dict[str, Any]) -> List[str]:
    """--region flags for the configured AWS regions (none for Azure or when unset)."""
    if config.get('cloud_provider') != 'aws':
        return []
    regions = config.get('targets', {}).get('aws', {}).get('regions', [])
    args: List[str] = []
    for region in regions:
        args.extend(['--region', region])
    return args


def _debug_enabled() -> bool:
    return os.environ.get("LEFTSIZE_DEBUG", "").lower() in ("1", "true", "yes")


def execute_single_policy_file(policies_file: str, config: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """Execute a single Cloud Custodian policy file. Returns None when the file couldn't
    run (non-zero exit other than 2, timeout, Custodian missing)."""
    findings = []
    
    # Create temporary directory for Custodian output
    with tempfile.TemporaryDirectory() as temp_dir:
        output_dir = os.path.join(temp_dir, 'custodian-output')
        os.makedirs(output_dir, exist_ok=True)
        
        # Build Custodian command - use the custodian from the same Python environment
        custodian_bin = os.path.join(os.path.dirname(sys.executable), 'custodian')
        if not os.path.isfile(custodian_bin):
            custodian_bin = 'custodian'  # Fall back to PATH
        cache_file = config.get('_custodian_cache')
        cache_args = ['--cache', cache_file, '--cache-period', '60'] if cache_file else ['--cache-period', '0']
        cmd = [
            custodian_bin, 'run',
            '--output-dir', output_dir,
            *cache_args,
            policies_file
        ]
        
        # AWS: scan the configured regions; without any, Custodian uses the
        # runner's default region (the region of the aws-actions login step)
        cmd.extend(custodian_region_args(config))
        
        # Always dry-run: LeftSize only reads, so policy actions (such as tags) never run
        cmd.append('--dry-run')
        
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
            
            # Exit code 2 means some policies in the file raised (throttling, access
            # denied, retired service endpoint) while the rest ran and wrote their
            # resources.json. Keep those results instead of dropping the whole file.
            if result.returncode == 2:
                failed = sorted(set(re.findall(r'^\s*-\s*(leftsize-[\w-]+)', result.stderr or '', re.M)))
                logger.warning("Some policies failed; keeping results of the others",
                               failed_policies=failed or 'see custodian log')
                for name in failed:
                    record_problem(config, f"{name}: failed (often a missing read permission or throttling)")
                if not failed:
                    record_problem(config, f"{os.path.basename(policies_file)}: some policies failed (set LEFTSIZE_DEBUG for details)")
            elif result.returncode != 0:
                logger.error("Custodian execution failed", returncode=result.returncode,
                             error=_last_error_line(result.stderr))
                if _debug_enabled():
                    logger.debug("Custodian stdout", stdout=result.stdout)
                    logger.debug("Custodian stderr", stderr=result.stderr)
                return None
            else:
                logger.info("Custodian execution completed")
            # Only log Custodian's output when LEFTSIZE_DEBUG is enabled. Its log (per-policy
            # counts, "unable to invoke method" access warnings) goes to stderr.
            if _debug_enabled():
                logger.debug("Custodian output", stdout=result.stdout)
                logger.debug("Custodian stderr", stderr=result.stderr)
            
            # Parse Custodian output
            findings = parse_custodian_output(output_dir, config)
            
        except subprocess.TimeoutExpired:
            logger.error("Custodian execution timed out", file=os.path.basename(policies_file))
            return None
        except Exception as e:
            logger.error("Custodian execution error", error=str(e))
            return None
    
    logger.info("Policy execution completed", findings_count=len(findings))
    return findings


def _last_error_line(stderr: Optional[str]) -> str:
    """The last non-empty line of Custodian's stderr (usually the exception), cut short."""
    lines = [line.strip() for line in (stderr or '').splitlines() if line.strip()]
    return lines[-1][:300] if lines else ''


def default_aws_region(config: Dict[str, Any]) -> str:
    """Region to attribute an AWS resource to when the resource itself doesn't say.

    While parsing one region's output of a multi-region run this is that region;
    otherwise the first configured region, else the runner's AWS_REGION.
    """
    scan_region = config.get('_scan_region')
    if scan_region:
        return scan_region
    regions = config.get('targets', {}).get('aws', {}).get('regions', [])
    if regions and regions[0] != 'all':
        return regions[0]
    return os.getenv('AWS_REGION', 'us-east-1')


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
        return default_aws_region(config)
    
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
            # Azure IDs are case-insensitive and the same resource group is reported as
            # e.g. "ALL-RG" by VMs and "all-rg" by other resources; lowercase the scope
            # so one resource group always maps to one finding group / issue.
            subscription_id = parts[2].lower()
            resource_group = (parts[4] if len(parts) >= 5 else 'unknown').lower()
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


VALID_SEVERITIES = ('critical', 'high', 'medium', 'low')


def read_policy_info(policy_dir: Path) -> Dict[str, Optional[str]]:
    """Read severity and resource type from the policy definition Custodian saved next to resources.json."""
    info: Dict[str, Optional[str]] = {'severity': None, 'resource_type': None}
    metadata_file = policy_dir / 'metadata.json'
    if not metadata_file.exists():
        return info
    try:
        with open(metadata_file) as f:
            policy = json.load(f).get('policy') or {}
        severity = str((policy.get('metadata') or {}).get('severity', '')).lower()
        info['severity'] = severity if severity in VALID_SEVERITIES else None
        resource_type = policy.get('resource')
        if isinstance(resource_type, str):
            # Custodian accepts both "azure.vm" and bare AWS names like "ec2"
            info['resource_type'] = resource_type if '.' in resource_type else f'aws.{resource_type}'
    except (OSError, ValueError, AttributeError) as e:
        logger.debug("Could not read policy metadata", policy_dir=str(policy_dir), error=str(e))
    return info


def _policy_output_dirs(output_dir: Path, config: Dict[str, Any]):
    """Yield (policy_dir, config) for every policy output directory.

    Custodian writes <output>/<policy>/ for a single region and
    <output>/<region>/<policy>/ when it runs several regions; for the latter the
    config is copied with the region set, so resources get the right region.
    """
    for child in sorted(output_dir.iterdir()):
        if not child.is_dir():
            continue
        if (child / 'resources.json').exists() or (child / 'metadata.json').exists():
            yield child, config
            continue
        region_config = dict(config)
        region_config['_scan_region'] = child.name
        for policy_dir in sorted(child.iterdir()):
            if policy_dir.is_dir():
                yield policy_dir, region_config


def resource_display_name(resource: Dict[str, Any]) -> str:
    """Friendly name: Azure `name`, the AWS Name tag, or the AWS identifier field."""
    name = resource.get('name', '') or resource.get('Name', '')
    # For AWS resources that have tag-based names (e.g. VPCs, subnets),
    # try extracting Name from the tag list so UI/search shows friendly names.
    if not name:
        aws_tags = resource.get('Tags')
        if isinstance(aws_tags, list):
            for tag in aws_tags:
                if isinstance(tag, dict) and tag.get('Key') == 'Name' and tag.get('Value'):
                    name = tag['Value']
                    break
    # Fall back to the AWS resource identifier fields when no tag Name present
    if not name:
        name = (
            resource.get('VpcId')
            or resource.get('VpcEndpointId')
            or resource.get('ImageId')
            or resource.get('FileSystemId')
            or resource.get('CacheClusterId')
            or resource.get('DBSnapshotIdentifier')
            or resource.get('DBInstanceIdentifier')
            or resource.get('DBClusterIdentifier')
            or resource.get('FunctionName')
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
    return name


# ---------------------------------------------------------------------------
# Environment classification (production vs non-production)
#
# Signals, strongest first: the environment-name input, resource tags, Azure
# resource group tags, the resource name, the resource group name, and a
# single-letter resource group suffix (-P/-A/-T/-D). Names are split into words
# and only whole words count ("latest" is not "test"). Any production signal
# wins; a resource is only non-production with positive evidence, so rules that
# suggest shutting things down never reach a resource that might be production.
# ---------------------------------------------------------------------------

ENVIRONMENTS = ('production', 'acceptance', 'staging', 'test', 'development', 'sandbox', 'non-production')
ENVIRONMENT_WORDS: Dict[str, str] = {
    **dict.fromkeys(['prod', 'prd', 'production', 'live'], 'production'),
    **dict.fromkeys(['acc', 'acpt', 'acceptance', 'acceptatie', 'uat', 'preprod', 'preproduction'], 'acceptance'),
    **dict.fromkeys(['stg', 'stage', 'staging'], 'staging'),
    **dict.fromkeys(['test', 'tst', 'testing', 'qa'], 'test'),
    **dict.fromkeys(['dev', 'develop', 'development', 'ontwikkeling'], 'development'),
    **dict.fromkeys(['sandbox', 'sbx'], 'sandbox'),
    **dict.fromkeys(['nonprod', 'nonproduction'], 'non-production'),
}
# Last word of a resource group name (Freelance-NG-A); S and O are ambiguous and skipped.
# Trailing filler words are looked past: Freelance-NG-P-backup is still -P.
ENVIRONMENT_SUFFIXES = {'p': 'production', 'a': 'acceptance', 't': 'test', 'd': 'development'}
ENVIRONMENT_SUFFIX_FILLER = {'rg', 'backup', 'backups', 'bkp'}
ENVIRONMENT_TAG_KEYS = {'environment', 'env', 'stage', 'environmentname', 'environment-name', 'environment_name'}
NON_PRODUCTION = set(ENVIRONMENTS) - {'production'}


def _environment_words(text: str) -> List[str]:
    """Lower-case words of a name, split on - _ . / space; trailing digits dropped
    (prod01 -> prod); "pre prod" and "non prod" joined so they don't read as prod.
    Hex words with digits are dropped: GUID parts such as "acc2" or "dea1" aren't words."""
    words = [re.sub(r'\d+$', '', w) for w in re.split(r'[-_./\s]+', (text or '').lower())
             if w and not (re.fullmatch(r'[0-9a-f]+', w) and re.search(r'\d', w))]
    joined: List[str] = []
    for w in words:
        if joined and joined[-1] in ('pre', 'non') and w in ('prod', 'production'):
            joined[-1] += w
        else:
            joined.append(w)
    return [w for w in joined if w]


def environment_from_text(text: str) -> Optional[str]:
    found = [ENVIRONMENT_WORDS[w] for w in _environment_words(text) if w in ENVIRONMENT_WORDS]
    if not found:
        return None
    return 'production' if 'production' in found else found[0]


def _tag_dict(resource: Dict[str, Any]) -> Dict[str, str]:
    tags = resource.get('tags')
    if isinstance(tags, dict):
        return {str(k): str(v) for k, v in tags.items() if v is not None}
    for key in ('Tags', 'TagList'):
        if isinstance(resource.get(key), list):
            return {t['Key']: str(t.get('Value', '')) for t in resource[key] if isinstance(t, dict) and 'Key' in t}
    return {}


def _environment_from_tags(tags: Dict[str, str]) -> Optional[Tuple[str, str]]:
    for key, value in tags.items():
        if key.lower() in ENVIRONMENT_TAG_KEYS:
            env = environment_from_text(value)
            if env:
                return env, f'{key}={value}'
    return None


def _azure_id_parts(resource_id: str) -> Tuple[Optional[str], Optional[str]]:
    """(subscription id, resource group name) from an Azure resource ID."""
    m = re.match(r'^/subscriptions/([^/]+)(?:/resourceGroups/([^/]+))?', resource_id or '', re.IGNORECASE)
    return (m.group(1).lower(), m.group(2)) if m else (None, None)


# Resource group tags per subscription, from one Resource Graph query (None when it failed).
# Only looked up during a real scan (see execute_custodian_policies), never in unit tests.
_RESOURCE_GROUP_TAGS: Dict[str, Optional[Dict[str, Dict[str, str]]]] = {}
LOOKUP_RESOURCE_GROUP_TAGS = False


def _azure_resource_group_tags(subscription_id: str, client: Any = None) -> Optional[Dict[str, Dict[str, str]]]:
    """{lower-case resource group name: tags} for a subscription; None when the query failed."""
    try:
        from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions
        if client is None:
            client = _resource_graph_client(subscription_id)
        query = ("resourcecontainers | where type =~ 'microsoft.resources/subscriptions/resourcegroups'"
                 " | where isnotempty(tags) | project name = tolower(name), tags")
        groups: Dict[str, Dict[str, str]] = {}
        skip_token = None
        while True:
            response = client.resources(QueryRequest(
                subscriptions=[subscription_id], query=query,
                options=QueryRequestOptions(skip_token=skip_token, result_format='objectArray')))
            for row in response.data or []:
                if row.get('name') and isinstance(row.get('tags'), dict):
                    groups[row['name']] = {str(k): str(v) for k, v in row['tags'].items() if v is not None}
            skip_token = response.skip_token
            if not skip_token:
                logger.info("Resource group tags read", subscription=subscription_id, tagged_groups=len(groups))
                return groups
    except Exception as e:
        logger.warning("Resource group tag lookup failed; environment from names only", subscription=subscription_id, error=str(e))
        return None


_SUBSCRIPTIONS: Dict[str, Optional[Dict[str, Any]]] = {}


def _azure_subscription_info(subscription_id: str, client: Any = None) -> Optional[Dict[str, Any]]:
    """{'name': display name, 'tags': {...}} of a subscription; None when the query failed."""
    try:
        from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions
        if client is None:
            client = _resource_graph_client(subscription_id)
        query = "resourcecontainers | where type =~ 'microsoft.resources/subscriptions' | project name, tags"
        rows = client.resources(QueryRequest(subscriptions=[subscription_id], query=query,
                                             options=QueryRequestOptions(result_format='objectArray'))).data or []
        row = rows[0] if rows else {}
        info = {'name': row.get('name') or '', 'tags': {str(k): str(v) for k, v in (row.get('tags') or {}).items() if v is not None}}
        logger.info("Azure subscription read", subscription=subscription_id, name=info['name'])
        return info
    except Exception as e:
        logger.warning("Subscription lookup failed; environment from tags and names only", subscription=subscription_id, error=str(e))
        return None


def _subscription_info(subscription_id: Optional[str]) -> Dict[str, Any]:
    if not LOOKUP_RESOURCE_GROUP_TAGS or not subscription_id:
        return {}
    if subscription_id not in _SUBSCRIPTIONS:
        _SUBSCRIPTIONS[subscription_id] = _azure_subscription_info(subscription_id)
    return _SUBSCRIPTIONS[subscription_id] or {}


def _resource_group_tags(subscription_id: Optional[str], resource_group: Optional[str]) -> Dict[str, str]:
    if not LOOKUP_RESOURCE_GROUP_TAGS or not subscription_id or not resource_group:
        return {}
    if subscription_id not in _RESOURCE_GROUP_TAGS:
        _RESOURCE_GROUP_TAGS[subscription_id] = _azure_resource_group_tags(subscription_id)
    return (_RESOURCE_GROUP_TAGS[subscription_id] or {}).get(resource_group.lower(), {})


def parse_environment_override(value: Optional[str]) -> Tuple[Optional[str], List[Tuple[str, str]]]:
    """environment-name input: a bare value for the whole scan ("Acceptance"), or
    name=environment pairs separated by commas or new lines (Shop-NG-A=acceptance,
    *-prod-*=production), matched against resource group and resource names (wildcards allowed).
    Only recognised environments count: onboarding workflows pass matrix labels such as
    MAIN, which must not switch off detection. Returns normalized environments."""
    if not value or not value.strip():
        return None, []
    if '=' not in value:
        return environment_from_text(value), []
    pairs = []
    for part in re.split(r'[,\n]+', value):
        if '=' in part:
            pattern, env = part.split('=', 1)
            normalized = environment_from_text(env)
            if pattern.strip() and normalized:
                pairs.append((pattern.strip().lower(), normalized))
    return None, pairs


def classify_environment(resource: Dict[str, Any], config: Dict[str, Any]) -> Tuple[str, str]:
    """(environment, how it was decided). Environment is one of ENVIRONMENTS or 'unknown'."""
    import fnmatch
    resource_id = resource.get('id') or ''
    subscription_id, resource_group = _azure_id_parts(resource_id)
    name = resource_display_name(resource)
    tags = _tag_dict(resource)
    # AKS node resource groups (MC_...) and their resources point at the cluster's own group
    parent_group = tags.get('aks-managed-cluster-rg')
    cluster_name = tags.get('aks-managed-cluster-name')

    whole_scan, pairs = parse_environment_override(config.get('environment_name'))
    for pattern, env in pairs:
        for candidate in (resource_group, parent_group, name):
            if candidate and fnmatch.fnmatchcase(candidate.lower(), pattern):
                return env, f'environment-name input ({pattern}={env})'
    if whole_scan:
        return whole_scan, f"environment-name input ({config.get('environment_name', '').strip()})"

    signals: List[Tuple[str, str]] = []
    found = _environment_from_tags(tags)
    if found:
        signals.append((found[0], f'tag {found[1]} on the resource'))
    for group in (resource_group, parent_group):
        found = _environment_from_tags(_resource_group_tags(subscription_id, group))
        if found:
            signals.append((found[0], f'tag {found[1]} on resource group {group}'))
    # Names of parent resources in the ID (the server of a database, the plan of a web app slot)
    provider_path = re.split(r'/providers/', resource_id, flags=re.IGNORECASE)
    parent_names = provider_path[-1].split('/')[2:-1:2] if len(provider_path) > 1 else []
    parents = [('parent resource name', p) for p in parent_names]
    for label, text in (('resource name', name), *parents, ('cluster name', cluster_name),
                        ('resource group name', parent_group), ('resource group name', resource_group)):
        env = environment_from_text(text) if text else None
        if env:
            signals.append((env, f'{label} {text}'))
    for group in (parent_group, resource_group):
        words = _environment_words(group or '')
        while len(words) > 2 and words[-1] in ENVIRONMENT_SUFFIX_FILLER:
            words.pop()
        if len(words) > 1 and words[-1] in ENVIRONMENT_SUFFIXES:
            signals.append((ENVIRONMENT_SUFFIXES[words[-1]], f'resource group name {group} (suffix -{words[-1].upper()})'))

    # Weakest: the account or subscription, for setups with one per environment (shop-acc)
    subscription = _subscription_info(subscription_id)
    if subscription_id and LOOKUP_RESOURCE_GROUP_TAGS and (
            _SUBSCRIPTIONS.get(subscription_id, {}) is None or _RESOURCE_GROUP_TAGS.get(subscription_id, {}) is None):
        record_problem(config, f"subscription {subscription_id}: resource group or subscription tags couldn't be "
                               "read; environments come from names only")
    found = _environment_from_tags(subscription.get('tags') or {})
    if found:
        signals.append((found[0], f"tag {found[1]} on subscription {subscription.get('name') or subscription_id}"))
    env = environment_from_text(subscription.get('name') or '')
    if env:
        signals.append((env, f"subscription name {subscription['name']}"))
    aws_target = config.get('targets', {}).get('aws', {})
    for label, text in (('AWS account name', aws_target.get('account_name')),
                        ('AWS account alias', aws_target.get('account_alias'))):
        env = environment_from_text(text) if text else None
        if env:
            signals.append((env, f'{label} {text}'))

    for env, source in signals:
        if env == 'production':
            return env, source
    return signals[0] if signals else ('unknown', 'no environment tag or recognisable name')


def is_non_production(resource: Dict[str, Any], config: Dict[str, Any]) -> bool:
    return classify_environment(resource, config)[0] in NON_PRODUCTION


def _non_production_only(resources: List[Dict[str, Any]], config: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [r for r in resources if is_non_production(r, config)]


def _eks_cluster_has_compute(cluster: Dict[str, Any], session: Any = None) -> Optional[bool]:
    """True when an EKS cluster has managed node groups, Fargate profiles or running EC2
    instances tagged for it (self-managed nodes, Karpenter); None when the check failed.
    Read-only calls only."""
    name = cluster.get('name')
    arn = cluster.get('arn') or ''
    parts = arn.split(':')
    if not name or len(parts) < 4 or not parts[3]:
        return None
    region = parts[3]
    try:
        if session is None:
            import boto3
            session = boto3.session.Session()
        eks = session.client('eks', region_name=region)
        if eks.list_nodegroups(clusterName=name, maxResults=1).get('nodegroups'):
            return True
        if eks.list_fargate_profiles(clusterName=name, maxResults=1).get('fargateProfileNames'):
            return True
        ec2 = session.client('ec2', region_name=region)
        state = {'Name': 'instance-state-name', 'Values': ['pending', 'running']}
        for tag_filter in ({'Name': 'tag-key', 'Values': [f'kubernetes.io/cluster/{name}']},
                           {'Name': 'tag:eks:eks-cluster-name', 'Values': [name]}):
            reservations = ec2.describe_instances(Filters=[tag_filter, state], MaxResults=5).get('Reservations')
            if any(res.get('Instances') for res in reservations or []):
                return True
        return False
    except Exception as e:
        logger.warning("EKS compute check failed; cluster not reported", cluster=name, error=str(e))
        return None


def _eks_without_compute(resources: List[Dict[str, Any]], config: Dict[str, Any]) -> List[Dict[str, Any]]:
    kept = []
    for cluster in resources:
        has_compute = _eks_cluster_has_compute(cluster)
        if has_compute is None:
            record_problem(config, f"leftsize-inactive-eks-cluster: node check failed for cluster {cluster.get('name')}; not reported")
        elif not has_compute:
            kept.append(cluster)
    return kept


def _resource_graph_client(subscription_id: str) -> Any:
    """Resource Graph client with the same authentication Custodian uses for the scan
    (c7n_azure Session: environment credentials, OIDC or the az CLI login)."""
    from c7n_azure.session import Session
    return Session(subscription_id=subscription_id).client('azure.mgmt.resourcegraph.ResourceGraphClient')


# Enabled VM auto-shutdown schedules (Microsoft.DevTestLab/schedules, named shutdown-computevm-<vm>)
SHUTDOWN_SCHEDULES_QUERY = (
    "resources"
    " | where type =~ 'microsoft.devtestlab/schedules'"
    " | where properties.status =~ 'Enabled' and properties.taskType =~ 'ComputeVmShutdownTask'"
    " | project vm = tolower(tostring(properties.targetResourceId))"
)


def _azure_shutdown_schedule_targets(subscription_id: str, client: Any = None) -> Optional[set]:
    """Lower-cased IDs of the VMs in a subscription that have an enabled auto-shutdown
    schedule (one read-only Resource Graph query); None when the query failed."""
    try:
        from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions
        if client is None:
            client = _resource_graph_client(subscription_id)
        targets: set = set()
        skip_token = None
        while True:
            response = client.resources(QueryRequest(
                subscriptions=[subscription_id], query=SHUTDOWN_SCHEDULES_QUERY,
                options=QueryRequestOptions(skip_token=skip_token, result_format='objectArray')))
            targets.update(row['vm'] for row in response.data or [] if row.get('vm'))
            skip_token = response.skip_token
            if not skip_token:
                logger.info("Auto-shutdown schedules found", subscription=subscription_id, vms=len(targets))
                return targets
    except Exception as e:
        logger.warning("Auto-shutdown schedule lookup failed; VMs not reported", subscription=subscription_id, error=str(e))
        return None


def _vms_without_shutdown_schedule(resources: List[Dict[str, Any]], config: Dict[str, Any]) -> List[Dict[str, Any]]:
    targets_by_subscription: Dict[str, Optional[set]] = {}
    kept = []
    for vm in resources:
        vm_id = (vm.get('id') or '').lower()
        parts = vm_id.split('/')
        if len(parts) < 3 or parts[1] != 'subscriptions':
            continue
        subscription_id = parts[2]
        if subscription_id not in targets_by_subscription:
            targets_by_subscription[subscription_id] = _azure_shutdown_schedule_targets(subscription_id)
        targets = targets_by_subscription[subscription_id]
        if targets is None:
            record_problem(config, f"leftsize-vm-scheduled-shutdown-missing: auto-shutdown schedules of subscription "
                                   f"{subscription_id} couldn't be read; VMs not reported")
        elif vm_id not in targets:
            kept.append(vm)
    return kept


# S3 Block Public Access: the account-level setting applies to every bucket on top of
# the bucket's own setting. Custodian's check-public-block only reads the bucket level
# (and treats a missing or unreadable setting as "all off"), so it flags every bucket
# of an account that blocks public access at account level.
S3_PUBLIC_BLOCK_KEYS = ('BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets')
_S3_ACCOUNT_PUBLIC_BLOCK: Dict[str, Optional[Dict[str, bool]]] = {}


def _s3_account_public_block(account_id: str, session: Any = None) -> Optional[Dict[str, bool]]:
    """The account-level Block Public Access settings (all False when none is set);
    None when they couldn't be read. One read-only s3control call per account."""
    try:
        if session is None:
            import boto3
            session = boto3.session.Session()
        client = session.client('s3control', region_name=session.region_name or 'us-east-1')
        try:
            config = client.get_public_access_block(AccountId=account_id)['PublicAccessBlockConfiguration']
        except Exception as e:
            code = getattr(e, 'response', {}).get('Error', {}).get('Code')
            if code != 'NoSuchPublicAccessBlockConfiguration':
                raise
            config = {}
        settings = {key: bool(config.get(key)) for key in S3_PUBLIC_BLOCK_KEYS}
        logger.info("S3 account-level Block Public Access read", account=account_id, **settings)
        return settings
    except Exception as e:
        logger.warning("S3 account-level Block Public Access lookup failed; using bucket settings only",
                       account=account_id, error=str(e))
        return None


def _s3_public_block_gaps(resources: List[Dict[str, Any]], config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Buckets where neither the bucket nor the account turns on all four Block Public
    Access settings. Buckets whose own setting couldn't be read are skipped, and no bucket
    is reported when the account-level setting couldn't be read. The settings
    that are off on both levels are stored as c7n:PublicAccessBlockOff for the issue."""
    account_id = config.get('targets', {}).get('aws', {}).get('account_id')
    account = None
    if account_id:
        if account_id not in _S3_ACCOUNT_PUBLIC_BLOCK:
            _S3_ACCOUNT_PUBLIC_BLOCK[account_id] = _s3_account_public_block(account_id)
        account = _S3_ACCOUNT_PUBLIC_BLOCK[account_id]
    if account is None:
        # Without the account-level setting every bucket would look open: report none
        if resources:
            record_problem(config, "leftsize-public-s3-access: the account-level Block Public Access setting "
                                   "couldn't be read (s3:GetAccountPublicAccessBlock); buckets not reported")
        return []
    kept = []
    for bucket in resources:
        if 'GetPublicAccessBlock' in (bucket.get('c7n:DeniedMethods') or []):
            continue
        own = bucket.get('c7n:PublicAccessBlock') or {}
        off = [key for key in S3_PUBLIC_BLOCK_KEYS if not own.get(key) and not account.get(key)]
        if off:
            bucket['c7n:PublicAccessBlockOff'] = off
            kept.append(bucket)
    return kept


# Checks Custodian filters can't express, applied to a policy's matches after the run
POLICY_POST_FILTERS = {
    'leftsize-inactive-eks-cluster': _eks_without_compute,
    'leftsize-public-s3-access': _s3_public_block_gaps,
    # Non-production rules: environment from tags and names (classify_environment)
    'leftsize-ec2-scheduled-shutdown-missing': _non_production_only,
    'leftsize-rds-multiaz-nonprod': _non_production_only,
    'leftsize-aks-dev-clusters-always-running': _non_production_only,
    'leftsize-sql-business-critical-nonprod': _non_production_only,
    # Non-production first: it needs no API calls and leaves fewer VMs for the schedule lookup
    'leftsize-vm-scheduled-shutdown-missing':
        lambda resources, config: _vms_without_shutdown_schedule(_non_production_only(resources, config), config),
}


def parse_custodian_output(output_dir: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Parse Cloud Custodian output and convert to LeftSize findings"""
    logger.info("Parsing Custodian output", output_dir=output_dir)
    
    findings = []
    
    # A run over several regions nests output per region: <output>/<region>/<policy>/
    for policy_dir, policy_config in _policy_output_dirs(Path(output_dir), config):
        policy_name = policy_dir.name
        resources_file = policy_dir / 'resources.json'
        
        if not resources_file.exists():
            logger.debug("No resources.json found for policy", policy=policy_name)
            continue
            
        try:
            with open(resources_file) as f:
                resources = json.load(f)
            
            post_filter = POLICY_POST_FILTERS.get(policy_name)
            if post_filter and resources:
                resources = post_filter(resources, policy_config)

            if not resources:
                logger.debug("No resources found for policy", policy=policy_name)
                continue
                
            logger.info("Found resources for policy", policy=policy_name, count=len(resources))

            policy_info = read_policy_info(policy_dir)

            # Convert Custodian resources to LeftSize findings
            for resource in resources:
                finding = convert_resource_to_finding(policy_name, resource, policy_config,
                                                      policy_info['resource_type'])
                if finding:
                    if policy_info['severity']:
                        finding['metadata'] = finding.get('metadata') or {}
                        finding['metadata'].setdefault('severity', policy_info['severity'])
                    findings.append(finding)
                    
        except Exception as e:
            logger.error("Error parsing resources for policy", 
                        policy=policy_name, error=str(e))
            continue
    
    return findings


# Identifiers of resources that carry a 'VpcId' but aren't VPCs
NON_VPC_ID_KEYS = (
    'DBSnapshotArn', 'DBSnapshotIdentifier', 'DBClusterSnapshotArn', 'DBClusterSnapshotIdentifier',
    'SubnetId', 'NetworkInterfaceId', 'ClusterIdentifier', 'Arn', 'ARN', 'arn',
)


def extract_resource_id(resource: Dict[str, Any], config: Dict[str, Any]) -> str:
    """Extract resource ID from Cloud Custodian resource - handles Azure and AWS formats"""
    
    cloud_provider = config.get('cloud_provider', 'azure')
    
    # Azure resources have 'id' field
    if resource.get('id'):
        return resource['id']
    
    # AWS resources use different ID fields depending on resource type
    if cloud_provider == 'aws':
        # S3 buckets use 'Name' (ListBuckets only returns Name + CreationDate, no ARN).
        # Other resource types also have a 'Name', so require the S3 shape.
        if (resource.get('Name') and 'CreationDate' in resource
                and not any(resource.get(k) for k in ('Arn', 'ARN', 'arn'))):
            bucket_name = resource['Name']
            # Construct ARN-style ID for S3 buckets
            return f"arn:aws:s3:::{bucket_name}"
        
        # EC2 instances use 'InstanceId'
        if resource.get('InstanceId'):
            instance_id = resource['InstanceId']
            region = resource.get('Region', default_aws_region(config))
            # Note: Account ID not available, using placeholder
            return f"arn:aws:ec2:{region}::instance/{instance_id}"
        
        # EBS snapshots carry the source 'VolumeId' too, so handle them first
        if resource.get('SnapshotId') and 'Progress' in resource:
            snapshot_id = resource['SnapshotId']
            region = resource.get('Region', default_aws_region(config))
            return f"arn:aws:ec2:{region}::snapshot/{snapshot_id}"

        # EBS volumes use 'VolumeId'
        if resource.get('VolumeId'):
            volume_id = resource['VolumeId']
            region = resource.get('Region', default_aws_region(config))
            return f"arn:aws:ec2:{region}::volume/{volume_id}"
        
        # EBS snapshots use 'SnapshotId'
        if resource.get('SnapshotId'):
            snapshot_id = resource['SnapshotId']
            region = resource.get('Region', default_aws_region(config))
            return f"arn:aws:ec2:{region}::snapshot/{snapshot_id}"

        # Load balancers, NAT gateways and security groups also carry a 'VpcId',
        # so handle them before the VPC branch
        if resource.get('LoadBalancerArn'):
            return resource['LoadBalancerArn']
        if resource.get('NatGatewayId'):
            region = resource.get('Region', default_aws_region(config))
            return f"arn:aws:ec2:{region}::natgateway/{resource['NatGatewayId']}"
        if resource.get('GroupId') and 'IpPermissions' in resource:
            region = resource.get('Region', default_aws_region(config))
            return f"arn:aws:ec2:{region}::security-group/{resource['GroupId']}"

        # VPCs use 'VpcId'. Many other resources (RDS snapshots, subnets, ENIs) carry a
        # 'VpcId' too, so only a resource that looks like a VPC counts as one.
        if (resource.get('VpcId') and not resource.get('VpcEndpointId')
                and ('DhcpOptionsId' in resource or 'IsDefault' in resource
                     or not any(resource.get(k) for k in NON_VPC_ID_KEYS))):
            vpc_id = resource['VpcId']
            region = resource.get('Region', default_aws_region(config))
            return f"arn:aws:ec2:{region}::vpc/{vpc_id}"

        # VPC Endpoints use 'VpcEndpointId'
        if resource.get('VpcEndpointId'):
            endpoint_id = resource['VpcEndpointId']
            region = resource.get('Region', default_aws_region(config))
            return f"arn:aws:ec2:{region}::vpc-endpoint/{endpoint_id}"

        # AMIs use 'ImageId'
        if resource.get('ImageId'):
            image_id = resource['ImageId']
            region = resource.get('Region', default_aws_region(config))
            return f"arn:aws:ec2:{region}::image/{image_id}"

        # EFS filesystems
        if resource.get('FileSystemId'):
            fs_id = resource['FileSystemId']
            region = resource.get('Region', default_aws_region(config))
            return f"arn:aws:elasticfilesystem:{region}::file-system/{fs_id}"

        # ElastiCache cache clusters
        if resource.get('CacheClusterId'):
            cache_id = resource['CacheClusterId']
            region = resource.get('Region', default_aws_region(config))
            return f"arn:aws:elasticache:{region}::cluster/{cache_id}"

        # RDS snapshots
        if resource.get('DBSnapshotArn'):
            return resource['DBSnapshotArn']
        if resource.get('DBSnapshotIdentifier'):
            snap_id = resource['DBSnapshotIdentifier']
            region = resource.get('Region', default_aws_region(config))
            return f"arn:aws:rds:{region}::snapshot/{snap_id}"

        # EKS clusters (c7n returns 'name' + 'arn')
        if resource.get('arn') and 'eks' in str(resource.get('arn', '')):
            return resource['arn']

        # WorkSpaces carry a 'UserName' too, so handle them before the IAM user branch
        if resource.get('WorkspaceId'):
            region = resource.get('Region', default_aws_region(config))
            return f"arn:aws:workspaces:{region}::workspace/{resource['WorkspaceId']}"

        # IAM users expose 'UserName' and 'Arn' (fallback Arn handles it, but ensure UserName path works)
        if resource.get('UserName') and not resource.get('Arn'):
            user_name = resource['UserName']
            return f"arn:aws:iam:::user/{user_name}"
        
        # RDS instances use 'DBInstanceIdentifier'
        if resource.get('DBInstanceIdentifier'):
            db_id = resource['DBInstanceIdentifier']
            region = resource.get('Region', default_aws_region(config))
            return f"arn:aws:rds:{region}::db/{db_id}"
        
        # Lambda functions use 'FunctionName' or 'FunctionArn'
        if resource.get('FunctionArn'):
            return resource['FunctionArn']
        if resource.get('FunctionName'):
            func_name = resource['FunctionName']
            region = resource.get('Region', default_aws_region(config))
            return f"arn:aws:lambda:{region}::function/{func_name}"
        
        # NAT Gateways use 'NatGatewayId'
        if resource.get('NatGatewayId'):
            nat_id = resource['NatGatewayId']
            region = resource.get('Region', default_aws_region(config))
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
            'DBClusterArn',            # rds-cluster
            'ClusterArn',              # kafka, emr
            'ReplicationInstanceArn',  # dms-instance
            'ReadinessCheckArn',       # readiness-check
            'DirectoryArn',            # cloud-directory
            'nodegroupArn',            # eks-nodegroup
            'computeEnvironmentArn',   # batch-compute
            'EnvironmentArn',          # elasticbeanstalk-environment
            'ResourceId',
        ]
        for id_field in arn_like_fields:
            val = resource.get(id_field)
            if val:
                return val

        # Resources without ARNs in their payload — build one from identifier + region
        region = resource.get('Region', default_aws_region(config))
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
        if resource.get('Name') and isinstance(resource.get('Command'), dict):  # glue job
            return f"arn:aws:glue:{region}::job/{resource['Name']}"
        if resource.get('Id') and resource.get('Edition'):  # kendra index
            return f"arn:aws:kendra:{region}::index/{resource['Id']}"
        if resource.get('DirectoryId'):  # directory service
            return f"arn:aws:ds:{region}::directory/{resource['DirectoryId']}"
    
    # Final fallback - generate a unique ID from available data
    resource_name = resource.get('name', '') or resource.get('Name', '') or 'unknown'
    resource_type = resource.get('type', '') or resource.get('c7n:resource-type', '') or 'resource'
    return f"{cloud_provider}:{resource_type}/{resource_name}"


def convert_resource_to_finding(policy_name: str, resource: Dict[str, Any], config: Dict[str, Any],
                                policy_resource_type: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Convert a Cloud Custodian resource to a LeftSize finding"""
    
    try:
        # Use policy name directly as rule ID (already has leftsize- prefix)
        rule_id = policy_name
        
        # Extract resource ID and basic info - handle both Azure and AWS formats
        # Azure uses 'id', AWS uses various fields depending on resource type
        resource_id = extract_resource_id(resource, config)
        resource_name = resource_display_name(resource)
        resource_type = resource.get('type', '') or resource.get('c7n:resource-type', '')
        
        # Build scope from resource ID
        scope = build_scope_from_resource_id(resource_id, config)
        
        # Extract metadata from resource - only include what Cloud Custodian provides
        metadata = extract_resource_metadata(resource, resource_id, policy_resource_type)
        
        # Environment (production, acceptance, ...) and how it was decided, for issue titles and lists
        environment, environment_source = classify_environment(resource, config)
        metadata = metadata or {}
        metadata['environment'] = environment
        metadata['environmentSource'] = environment_source
        
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


# Resource fields exposed to issue templates as {{Metadata.<key>}}, per Cloud
# Custodian resource type. Each key maps to dotted paths into the raw resource;
# the first path that resolves wins. A `[]` segment collects values from a list
# and joins them as "a, b, c". Keys set by the resource-specific extraction in
# extract_resource_metadata are never overwritten.
RESOURCE_FIELD_PATHS: Dict[str, Dict[str, List[str]]] = {
    # --- AWS ---
    'aws.rds': {'engine': ['Engine'], 'engineVersion': ['EngineVersion'],
                'instanceClass': ['DBInstanceClass'], 'dbClusterIdentifier': ['DBClusterIdentifier'],
                'storageSize': ['AllocatedStorage'], 'storageType': ['StorageType'], 'iops': ['Iops'],
                'provisionedIops': ['Iops'], 'backupRetentionPeriod': ['BackupRetentionPeriod'],
                'databaseName': ['DBName'], 'availabilityZone': ['AvailabilityZone'],
                'multiAZ': ['MultiAZ'], 'licenseModel': ['LicenseModel']},
    'aws.rds-snapshot': {'engine': ['Engine'], 'engineVersion': ['EngineVersion'],
                         'storageSize': ['AllocatedStorage'], 'instanceId': ['DBInstanceIdentifier']},
    'aws.ebs': {'volumeId': ['VolumeId'], 'volumeType': ['VolumeType'], 'volumeSize': ['Size'],
                'iops': ['Iops'], 'provisionedIops': ['Iops'], 'availabilityZone': ['AvailabilityZone'],
                'instanceId': ['Attachments[].InstanceId'], 'deviceName': ['Attachments[].Device']},
    'aws.ebs-snapshot': {'volumeId': ['VolumeId'], 'volumeSize': ['VolumeSize']},
    'aws.network-addr': {'ipAddress': ['PublicIp'], 'instanceId': ['InstanceId']},
    'aws.dynamodb-table': {'billingMode': ['BillingModeSummary.BillingMode']},
    'aws.vpc-endpoint': {'vpcEndpointType': ['VpcEndpointType'], 'serviceName': ['ServiceName']},
    'aws.cache-cluster': {'engine': ['Engine'], 'engineVersion': ['EngineVersion'],
                          'cacheNodeType': ['CacheNodeType'], 'nodeType': ['CacheNodeType'],
                          'cacheClusterId': ['CacheClusterId'],
                          'replicationGroupId': ['ReplicationGroupId']},
    'aws.elasticsearch': {'engineVersion': ['ElasticsearchVersion'],
                          'instanceType': ['ElasticsearchClusterConfig.InstanceType'],
                          'instanceCount': ['ElasticsearchClusterConfig.InstanceCount'],
                          'domainName': ['DomainName']},
    'aws.eks': {'kubernetesVersion': ['version'], 'supportType': ['upgradePolicy.supportType']},
    'aws.eks-nodegroup': {'kubernetesVersion': ['version'], 'nodegroupName': ['nodegroupName'],
                          'clusterName': ['clusterName'], 'amiType': ['amiType'],
                          'releaseVersion': ['releaseVersion']},
    'aws.lambda': {'runtime': ['Runtime'], 'functionName': ['FunctionName'], 'memory': ['MemorySize']},
    'aws.batch-compute': {'imageType': ['computeResources.ec2Configuration[].imageType'],
                          'allocationStrategy': ['computeResources.allocationStrategy'],
                          'orchestrationType': ['containerOrchestrationType']},
    'aws.ec2': {'imageId': ['ImageId'], 'instanceType': ['InstanceType'], 'instanceId': ['InstanceId'],
                'platform': ['PlatformDetails'],
                'availabilityZone': ['Placement.AvailabilityZone'], 'vpcId': ['VpcId'],
                'ipAddress': ['PublicIpAddress']},
    'aws.ami': {'imageName': ['Name'], 'creationDate': ['CreationDate'],
                'snapshotIds': ['BlockDeviceMappings[].Ebs.SnapshotId'],
                'volumeSizesGb': ['BlockDeviceMappings[].Ebs.VolumeSize']},
    'aws.elasticbeanstalk-environment': {'applicationName': ['ApplicationName'],
                                         'solutionStackName': ['SolutionStackName']},
    'aws.workspaces': {'userName': ['UserName'],
                       'operatingSystem': ['WorkspaceProperties.OperatingSystemName'],
                       'protocol': ['WorkspaceProperties.Protocols[]'], 'bundleId': ['BundleId'],
                       'directoryId': ['DirectoryId']},
    'aws.glue-job': {'glueVersion': ['GlueVersion'], 'jobCommand': ['Command.Name'],
                     'pythonVersion': ['Command.PythonVersion']},
    'aws.emr': {'releaseLabel': ['ReleaseLabel'], 'runningAmiVersion': ['RunningAmiVersion'],
                'clusterName': ['Name']},
    'aws.kafka': {'clusterName': ['ClusterName'],
                  'kafkaVersion': ['Provisioned.CurrentBrokerSoftwareInfo.KafkaVersion']},
    'aws.dms-instance': {'engineVersion': ['EngineVersion'], 'instanceClass': ['ReplicationInstanceClass'],
                         'replicationInstanceIdentifier': ['ReplicationInstanceIdentifier']},
    'aws.airflow': {'airflowVersion': ['AirflowVersion'], 'environmentClass': ['EnvironmentClass']},
    'aws.cloud-directory': {'directoryName': ['Name']},
    'aws.directory': {'directoryName': ['Name'], 'directorySize': ['Size']},
    'aws.kendra': {'indexName': ['Name'], 'edition': ['Edition']},
    'aws.cloudsearch': {'searchInstanceType': ['SearchInstanceType']},
    'aws.readiness-check': {'resourceSet': ['ResourceSet']},
    # --- Azure ---
    'azure.storage': {'kind': ['kind']},
    'azure.disk': {'osType': ['properties.osType']},
    'azure.vm': {'osDiskName': ['properties.storageProfile.osDisk.name'],
                 'osDiskId': ['properties.storageProfile.osDisk.managedDisk.id'],
                 'osDiskSize': ['properties.storageProfile.osDisk.diskSizeGB'],
                 'osDiskSku': ['properties.storageProfile.osDisk.managedDisk.storageAccountType'],
                 'osType': ['properties.storageProfile.osDisk.osType']},
    'azure.sql-database': {'databaseName': ['name'], 'currentSku': ['sku.name'], 'skuName': ['sku.name'],
                           'skuTier': ['sku.tier'], 'capacity': ['sku.capacity']},
    'azure.sqlserver': {'serverName': ['name']},
    'azure.keyvault': {'vaultName': ['name']},
    'azure.snapshot': {'diskSizeGB': ['properties.diskSizeGB'], 'timeCreated': ['properties.timeCreated'],
                       'skuName': ['sku.name'], 'incremental': ['properties.incremental']},
    'azure.vmss': {'vmSize': ['sku.name'], 'capacity': ['sku.capacity'],
                   'orchestrationMode': ['properties.orchestrationMode'],
                   'upgradePolicyMode': ['properties.upgradePolicy.mode']},
    'aws.asg': {'minSize': ['MinSize'], 'maxSize': ['MaxSize'], 'desiredCapacity': ['DesiredCapacity']},
    'azure.aks': {'kubernetesVersion': ['properties.kubernetesVersion'],
                  'networkPolicy': ['properties.networkProfile.networkPolicy'],
                  'identityType': ['identity.type']},
    'azure.webapp': {'runtime': ['c7n:configuration.linuxFxVersion']},
    'azure.cognitiveservice': {'kind': ['kind'], 'skuName': ['sku.name']},
    'azure.spring-service-instance': {'skuName': ['sku.name'], 'skuTier': ['sku.tier']},
    'azure.appserviceplan': {'numberOfSites': ['properties.numberOfSites'], 'kind': ['kind']},
    'azure.publicip': {'ipAddress': ['properties.ipAddress'], 'skuName': ['sku.name'],
                       'publicIpAllocationMethod': ['properties.publicIPAllocationMethod'],
                       'ipVersion': ['properties.publicIPAddressVersion'],
                       'ipConfigurationId': ['properties.ipConfiguration.id']},
    'azure.application-gateway': {
        'skuName': ['properties.sku.name'], 'operationalState': ['properties.operationalState'],
        'wafMode': ['properties.webApplicationFirewallConfiguration.firewallMode'],
        'wafRuleSetType': ['properties.webApplicationFirewallConfiguration.ruleSetType'],
        'wafRuleSetVersion': ['properties.webApplicationFirewallConfiguration.ruleSetVersion'],
        'firewallPolicyId': ['properties.firewallPolicy.id']},
    'azure.front-door': {'enabledState': ['properties.enabledState'],
                         'frontendHostNames': ['properties.frontendEndpoints[].properties.hostName'],
                         'resourceState': ['properties.resourceState']},
    'azure.cdnprofile': {'skuName': ['sku.name'], 'resourceState': ['properties.resourceState']},
    'azure.networksecuritygroup': {'flowLogIds': ['properties.flowLogs[].id']},
    'azure.postgresql-flexibleserver': {
        'skuName': ['sku.name'], 'skuTier': ['sku.tier'], 'engineVersion': ['properties.version'],
        'state': ['properties.state'], 'replicationRole': ['properties.replicationRole'],
        'highAvailabilityMode': ['properties.highAvailability.mode']},
    'azure.mysql-flexibleserver': {
        'skuName': ['sku.name'], 'skuTier': ['sku.tier'], 'engineVersion': ['properties.version'],
        'state': ['properties.state'], 'replicationRole': ['properties.replicationRole'],
        'highAvailabilityMode': ['properties.highAvailability.mode']},
    'azure.mariadb-server': {'skuName': ['sku.name'], 'engineVersion': ['properties.version']},
    'azure.loadbalancer': {'skuName': ['sku.name']},
    'azure.redis': {'skuName': ['properties.sku.name'], 'skuCapacity': ['properties.sku.capacity'],
                    'skuFamily': ['properties.sku.family'], 'redisVersion': ['properties.redisVersion']},
    'azure.armresource': {'skuName': ['sku.name'], 'skuCapacity': ['sku.capacity']},
    'azure.bastion-host': {'skuName': ['sku.name'], 'scaleUnits': ['properties.scaleUnits']},
    'azure.hdinsight': {'clusterVersion': ['properties.clusterVersion'],
                        'clusterState': ['properties.clusterState'],
                        'clusterKind': ['properties.clusterDefinition.kind']},
}


def _aks_node_pools(resource: Dict[str, Any]) -> Optional[List[str]]:
    """One line per AKS node pool, e.g. 'pool1: Linux/Ubuntu, k8s 1.31.9, image AKSUbuntu-2204...'."""
    pools = (resource.get('properties') or {}).get('agentPoolProfiles') or []
    lines = [
        f"{p.get('name') or '-'}: {p.get('osType') or '-'}/{p.get('osSKU') or '-'}, "
        f"k8s {p.get('orchestratorVersion') or '-'}, image {p.get('nodeImageVersion') or '-'}"
        for p in pools if isinstance(p, dict)
    ]
    return lines or None


def _aks_pool_sizes(resource: Dict[str, Any]) -> Optional[str]:
    """Node pools as "vmSize:count:os" separated by commas, e.g. "Standard_B2ms:3:Linux,Standard_D4s_v5:2:Windows".
    Used for savings estimates; None when a pool has no size or count."""
    pools = [p for p in (resource.get('properties') or {}).get('agentPoolProfiles') or [] if isinstance(p, dict)]
    if not pools or any(not p.get('vmSize') or not isinstance(p.get('count'), int) for p in pools):
        return None
    return ','.join(f"{p['vmSize']}:{p['count']}:{p.get('osType') or 'Linux'}" for p in pools)


def _aks_node_count(resource: Dict[str, Any]) -> Optional[int]:
    pools = (resource.get('properties') or {}).get('agentPoolProfiles') or []
    counts = [p.get('count') for p in pools if isinstance(p, dict) and isinstance(p.get('count'), int)]
    return sum(counts) if counts else None


def _aks_vm_sizes(resource: Dict[str, Any]) -> Optional[str]:
    pools = (resource.get('properties') or {}).get('agentPoolProfiles') or []
    sizes = sorted({p.get('vmSize') for p in pools if isinstance(p, dict) and p.get('vmSize')})
    return ', '.join(sizes) or None


# Azure VM sizes with an announced retirement, in the same groups and with the same
# patterns as the leftsize-vm-*-retirement* policies (azure-deprecations.yml).
# (label, regex, retirement date)
VM_SIZE_RETIREMENTS = [
    ('M192i_v2', re.compile(r'^Standard_M192i(d)?(m)?s_v2$', re.I), '2027-03-31'),
    ('NP/HC/HBv2', re.compile(r'^Standard_(NP\d+s|HC44(-\d+)?rs|HB120(-\d+)?rs_v2)$', re.I), '2027-05-31'),
    ('D/Ds/Dv2/Dsv2/Ls', re.compile(r'^Standard_(DS?\d+(-\d+)?|DS?\d+(-\d+)?_v2(_Promo)?|L\d+s)$', re.I), '2028-05-01'),
    ('Av2/Amv2/Bv1/F/Fs/Fsv2/G/Gs/Lsv2',
     re.compile(r'^Standard_(A\d+m?_v2|B\d+(ls|s|ms)|F\d+s?|F\d+s_v2|GS?\d+(-\d+)?|L\d+s_v2)$', re.I), '2028-11-15'),
    ('Dv3/Dsv3/Ev3/Esv3', re.compile(r'^Standard_(D\d+s?_v3|E\d+(-\d+)?i?s?_v3)$', re.I), '2029-11-15'),
]


def vm_size_retirement(vm_size: Optional[str]) -> Optional[tuple]:
    """Return (series label, retirement date) when the VM size is scheduled for retirement."""
    for label, pattern, date in VM_SIZE_RETIREMENTS:
        if vm_size and pattern.match(vm_size):
            return label, date
    return None


def _aks_retiring_pools(resource: Dict[str, Any]) -> Optional[List[str]]:
    lines = []
    for p in (resource.get('properties') or {}).get('agentPoolProfiles') or []:
        if not isinstance(p, dict):
            continue
        retirement = vm_size_retirement(p.get('vmSize'))
        if retirement:
            lines.append(f"{p.get('name') or '-'}: {p.get('vmSize')} × {p.get('count', '?')} nodes "
                         f"({p.get('mode') or '-'}) — {retirement[0]} retires {retirement[1]}")
    return lines or None


def _aks_retirement_date(resource: Dict[str, Any]) -> Optional[str]:
    dates = [r[1] for p in (resource.get('properties') or {}).get('agentPoolProfiles') or []
             if isinstance(p, dict) and (r := vm_size_retirement(p.get('vmSize')))]
    return min(dates) if dates else None


def _vmss_retiring_series(resource: Dict[str, Any]) -> Optional[str]:
    r = vm_size_retirement((resource.get('sku') or {}).get('name'))
    return r[0] if r else None


def _vmss_retirement_date(resource: Dict[str, Any]) -> Optional[str]:
    r = vm_size_retirement((resource.get('sku') or {}).get('name'))
    return r[1] if r else None


def _lb_backend_pool_count(resource: Dict[str, Any]) -> int:
    return len((resource.get('properties') or {}).get('backendAddressPools') or [])


def _lb_public_ip_count(resource: Dict[str, Any]) -> int:
    frontends = (resource.get('properties') or {}).get('frontendIPConfigurations') or []
    return sum(1 for f in frontends
               if isinstance(f, dict) and ((f.get('properties') or {}).get('publicIPAddress')))


def _asg_instance_types(resource: Dict[str, Any]) -> Optional[str]:
    types = sorted({i.get('InstanceType') for i in resource.get('Instances') or []
                    if isinstance(i, dict) and i.get('InstanceType')})
    return ', '.join(types) or None


def _avg_cpu_percent(resource: Dict[str, Any]) -> Optional[float]:
    """Average CPUUtilization over the datapoints a `metrics` filter fetched (c7n.metrics annotation)."""
    for key, datapoints in (resource.get('c7n.metrics') or {}).items():
        if '.CPUUtilization.Average.' in key and datapoints:
            values = [d['Average'] for d in datapoints if isinstance(d, dict) and 'Average' in d]
            if values:
                return round(sum(values) / len(values), 1)
    return None


def _azure_metric_average(resource: Dict[str, Any], metric: str) -> Optional[float]:
    """Average of the values an Azure `metric` filter fetched (c7n:metrics annotation, keyed by "<metric>, ...")."""
    for key, entry in (resource.get('c7n:metrics') or {}).items():
        if key.split(',')[0] == metric and isinstance(entry, dict):
            values = [v for v in entry.get('measurement') or [] if isinstance(v, (int, float))]
            if values:
                return round(sum(values) / len(values), 1)
    return None


def _aks_avg_node_cpu(resource: Dict[str, Any]) -> Optional[float]:
    return _azure_metric_average(resource, 'node_cpu_usage_percentage')


def _aks_avg_node_memory(resource: Dict[str, Any]) -> Optional[float]:
    return _azure_metric_average(resource, 'node_memory_working_set_percentage')


def _s3_bucket_region(resource: Dict[str, Any]) -> Optional[str]:
    """S3 ARNs carry no region; use the bucket location Custodian adds (same mapping as c7n's get_region)."""
    location = resource.get('Location')
    if not isinstance(location, dict):
        return None
    constraint = location.get('LocationConstraint')
    return {None: 'us-east-1', '': 'us-east-1', 'EU': 'eu-west-1'}.get(constraint, constraint)


# Fields that need more than a path lookup (counts, lists, derived values).
RESOURCE_FIELD_BUILDERS: Dict[str, Dict[str, Any]] = {
    'azure.aks': {'nodePools': _aks_node_pools, 'nodeCount': _aks_node_count, 'vmSizes': _aks_vm_sizes,
                  'retiringNodePools': _aks_retiring_pools, 'retirementDate': _aks_retirement_date,
                  'avgNodeCpuPercent': _aks_avg_node_cpu, 'avgNodeMemoryPercent': _aks_avg_node_memory,
                  'nodePoolSizes': _aks_pool_sizes},
    'azure.vmss': {'retiringSeries': _vmss_retiring_series, 'retirementDate': _vmss_retirement_date},
    'azure.loadbalancer': {'backendPoolCount': _lb_backend_pool_count, 'publicIpCount': _lb_public_ip_count},
    'aws.asg': {'instanceTypes': _asg_instance_types},
    'aws.ec2': {'avgCpuPercent': _avg_cpu_percent},
    'aws.rds': {'avgCpuPercent': _avg_cpu_percent},
    'aws.s3': {'region': _s3_bucket_region,
               'publicAccessBlockOff': lambda r: ', '.join(r.get('c7n:PublicAccessBlockOff') or []) or None},
}


def _resolve_field_path(resource: Any, path: str) -> Any:
    """Resolve a dotted path (with optional `[]` list segments) in a resource dict."""
    current: List[Any] = [resource]
    for segment in path.split('.'):
        collect = segment.endswith('[]')
        key = segment[:-2] if collect else segment
        next_values: List[Any] = []
        for value in current:
            if not isinstance(value, dict) or value.get(key) is None:
                continue
            item = value[key]
            if collect and isinstance(item, list):
                next_values.extend(i for i in item if i is not None)
            else:
                next_values.append(item)
        current = next_values
        if not current:
            return None
    scalars = [v for v in current if isinstance(v, (str, int, float, bool))]
    if not scalars:
        return None
    if '[]' in path:
        return ', '.join(str(v) for v in scalars)
    return scalars[0]


def extract_resource_fields(resource: Dict[str, Any], resource_type: Optional[str]) -> Dict[str, Any]:
    """Extract the template fields declared for this resource type."""
    fields: Dict[str, Any] = {}
    for key, paths in RESOURCE_FIELD_PATHS.get(resource_type or '', {}).items():
        for path in paths:
            value = _resolve_field_path(resource, path)
            if value is not None and value != '':
                fields[key] = value
                break
    for key, builder in RESOURCE_FIELD_BUILDERS.get(resource_type or '', {}).items():
        value = builder(resource)
        if value is not None and value != '' and value != []:
            fields[key] = value
    return fields


def extract_resource_metadata(resource: Dict[str, Any], resource_id: str,
                              resource_type: Optional[str] = None) -> Dict[str, Any]:
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
        
        # Tag names only: tag values can hold anything (connection strings, e-mail
        # addresses) and the backend doesn't need them. Environment detection reads the
        # values locally, before this metadata is built.
        # Azure: {"Environment": "Production"}; AWS: [{"Key": "Environment", "Value": "Production"}]
        tags = resource.get('tags') or resource.get('Tags')
        tag_keys = set()
        if isinstance(tags, dict):
            tag_keys = {str(k) for k in tags}
        elif isinstance(tags, list):
            for tag in tags:
                if isinstance(tag, dict):
                    key = tag.get('Key') if tag.get('Key') is not None else tag.get('key')
                    value = tag.get('Value') if 'Value' in tag else tag.get('value')
                    if key and value is not None:
                        tag_keys.add(str(key))
        if tag_keys:
            metadata['tagKeys'] = sorted(tag_keys)
        
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

        # Generic template fields (engine versions, runtimes, OS SKUs, ...)
        for key, value in extract_resource_fields(resource, resource_type).items():
            metadata.setdefault(key, value)
        
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
        
        # One ScanId for all attempts: a retried scan overwrites the same stored payload
        payload = {"FindingGroups": finding_groups, "Currency": currency, "ScanId": str(uuid.uuid4())}
        response = post_with_retry(url, payload, headers)
        
        if response.status_code == 429:
            try:
                message = response.json().get('message') or ''
            except ValueError:
                message = ''
            raise SubmissionRateLimited(message or 'Daily submission limit reached. Retry after UTC midnight.')
        
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
        
        try:
            response_data = response.json()
        except ValueError:
            response_data = {}
        if not isinstance(response_data, dict):
            response_data = {}
        logger.info("Findings submitted successfully", response_status=response.status_code)
        # Only log response data when LEFTSIZE_DEBUG is enabled
        if os.environ.get("LEFTSIZE_DEBUG", "").lower() in ("1", "true", "yes"):
            logger.debug("Backend response", response_data=response_data)
        
        result['submitted'] = True
        # Extract plan info from response if available
        if 'PlanInfo' in response_data:
            result['plan_info'] = response_data['PlanInfo']
        
        return result
        
    except (RepositoryLimitExceeded, SubmissionRateLimited):
        raise  # Re-raise to allow caller to handle specifically
    except Exception as e:
        logger.error("Failed to submit findings to backend", error=str(e))
        raise  # Re-raise to allow caller to handle


SUBMIT_ATTEMPTS = 3
SUBMIT_TIMEOUT_SECONDS = 60


def post_with_retry(url: str, payload: Dict[str, Any], headers: Dict[str, str],
                    attempts: int = SUBMIT_ATTEMPTS, backoff_seconds: float = 5) -> requests.Response:
    """POST, retrying connection errors, timeouts and 5xx responses. 4xx responses are
    returned at once: they won't change on a retry, and every attempt counts toward the
    daily submission limit."""
    for attempt in range(1, attempts + 1):
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=SUBMIT_TIMEOUT_SECONDS)
        except (requests.ConnectionError, requests.Timeout) as e:
            if attempt == attempts:
                raise
            logger.warning("Submitting findings failed; retrying", attempt=attempt, error=str(e))
        else:
            if response.status_code < 500 or attempt == attempts:
                return response
            logger.warning("Backend error; retrying", attempt=attempt, status=response.status_code)
        time.sleep(backoff_seconds * attempt)
    raise RuntimeError("unreachable")


def group_findings(findings: List[Dict[str, Any]], currency: str = 'USD') -> List[Dict[str, Any]]:
    """Group findings by rule ID and scope for backend submission. A resource is listed
    once per group: Custodian lists global resources such as S3 buckets again in every
    region of a multi-region scan, and those findings share one scope."""
    
    groups = {}
    seen = set()
    
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
        
        if (key, finding['resourceId']) in seen:
            continue
        seen.add((key, finding['resourceId']))
        
        resource = {
            'resource_id': finding['resourceId'],
            'policy': rule_id,
            'metadata': finding.get('metadata') or {},
            'estimated_savings': finding.get('estimatedSavings', 0),
            'currency': currency,
        }
        
        groups[key]['resources'].append(resource)
    
    return list(groups.values())


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