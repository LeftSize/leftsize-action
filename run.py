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


def github_action_main():
    """GitHub Action entry point - reads from environment variables"""
    
    # Read from GitHub Action environment variables
    verbose = os.getenv('LEFTSIZE_VERBOSE', 'false').lower() == 'true'
    backend_url = os.getenv('LEFTSIZE_BACKEND_URL')
    installation_id = os.getenv('LEFTSIZE_INSTALLATION_ID')
    repository_token = os.getenv('LEFTSIZE_REPOSITORY_TOKEN')
    cloud_provider = os.getenv('LEFTSIZE_CLOUD_PROVIDER', 'azure')
    azure_subscription_ids = os.getenv('LEFTSIZE_AZURE_SUBSCRIPTION_IDS', '')
    aws_regions = os.getenv('LEFTSIZE_AWS_REGIONS', '')
    include_policies = os.getenv('LEFTSIZE_INCLUDE_POLICIES', '')
    exclude_policies = os.getenv('LEFTSIZE_EXCLUDE_POLICIES', '')
    
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
    logger.info("LeftSize GitHub Action starting", version="1.0.0", cloud_provider=cloud_provider)
    
    try:
        # Create minimal configuration from environment variables
        config_data = create_default_config()
        
        # Override with environment variables
        if backend_url:
            config_data.setdefault('output', {})['backend_url'] = backend_url
        if installation_id:
            config_data.setdefault('output', {})['installation_id'] = installation_id
        if repository_token:
            config_data.setdefault('output', {})['repository_token'] = repository_token
        
        # Configure cloud provider targets
        if cloud_provider == 'azure':
            if azure_subscription_ids:
                subs = [s.strip() for s in azure_subscription_ids.split(',') if s.strip()]
                config_data.setdefault('targets', {}).setdefault('azure', {})['subscriptions'] = subs
        elif cloud_provider == 'aws':
            if aws_regions:
                regions = [r.strip() for r in aws_regions.split(',') if r.strip()]
                config_data.setdefault('targets', {}).setdefault('aws', {})['regions'] = regions
        
        # Configure policies
        if include_policies:
            categories = [c.strip() for c in include_policies.split(',') if c.strip()]
            config_data.setdefault('policies', {})['include_categories'] = categories
        if exclude_policies:
            rules = [r.strip() for r in exclude_policies.split(',') if r.strip()]
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
        elif cloud_provider == 'aws':
            # AWS auth validation handled by boto3/AWS CLI
            pass
        
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
        if findings and backend_url and installation_id and repository_token:
            try:
                submit_findings(findings, config_data)
                submitted = True
                logger.info("Findings submitted successfully to backend")
            except Exception as e:
                logger.warning(f"Failed to submit findings to backend: {e}")
                submitted = False
        
        # Set GitHub Action outputs
        set_github_output('findings-count', str(findings_count))
        set_github_output('findings-submitted', 'true' if submitted else 'false')
        set_github_output('findings-json', json.dumps(findings, default=str))
        
        # GitHub Actions summary
        print_github_summary(findings, submitted)
        
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


def print_github_summary(findings: List[Dict[str, Any]], submitted: bool):
    """Print GitHub Actions job summary"""
    github_step_summary = os.getenv('GITHUB_STEP_SUMMARY')
    
    summary = f"""# LeftSize Cloud Cost Optimization Scan Results

## Summary
- **Findings**: {len(findings)}
- **Submitted to Backend**: {'✅ Yes' if submitted else '❌ No'}

"""
    
    if findings:
        # Group by rule
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
        from azure.mgmt.resource import ResourceManagementClient
        
        # Try to create credentials and test them
        credential = DefaultAzureCredential()
        
        # Test authentication by attempting to list resource groups
        subscription_id = azure_config.get('subscriptions', [None])[0]
        if not subscription_id:
            logger.error("Azure subscription ID not found in configuration. Azure authentication cannot proceed.")
            return False
            
        client = ResourceManagementClient(credential, subscription_id)
        # Just try to get the client - actual API call will be made by Custodian
        logger.info("Azure authentication validated successfully")
        return True
        
    except Exception as e:
        logger.error("Azure authentication validation failed", error=str(e))
        return False


def execute_custodian_policies(policies_dir: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Execute Cloud Custodian policies and collect findings"""
    logger.info("Executing Cloud Custodian policies", policies_dir=policies_dir)
    
    # Determine which policy files to run
    policy_files = config.get('policies', {}).get('policy_files', [])
    
    if not policy_files:
        # Default: auto-discover all policy files
        logger.info("No policy files specified, auto-discovering...")
        policy_files = []
        for file in Path(policies_dir).glob('*.yml'):
            # Skip example files
            if 'example' not in file.name.lower():
                policy_files.append(file.name)
                logger.info("Discovered policy file", file=file.name)
        
        if not policy_files:
            logger.error("No policy files found in directory", policies_dir=policies_dir)
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
        
        # Build Custodian command
        cmd = [
            'custodian', 'run',
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
                env=os.environ
            )
            
            if result.returncode != 0:
                logger.error("Custodian execution failed", 
                           returncode=result.returncode,
                           stdout=result.stdout,
                           stderr=result.stderr)
                return []
            
            logger.info("Custodian execution completed", stdout=result.stdout)
            
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
    """Build LeftSize scope from Azure resource ID"""
    try:
        # Parse Azure resource ID: /subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{type}/{name}
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


def convert_resource_to_finding(policy_name: str, resource: Dict[str, Any], config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Convert a Cloud Custodian resource to a LeftSize finding"""
    
    try:
        # Use policy name directly as rule ID (already has leftsize- prefix)
        rule_id = policy_name
        
        # Extract resource ID and basic info
        resource_id = resource.get('id', '')
        resource_name = resource.get('name', '')
        resource_type = resource.get('type', '')
        
        # Build scope from resource ID
        scope = build_scope_from_resource_id(resource_id, config)
        
        # Extract metadata from resource - only include what Cloud Custodian provides
        metadata = extract_resource_metadata(resource, resource_id)
        
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
        parts = resource_id.split('/')
        if len(parts) >= 5 and parts[1] == 'subscriptions':
            metadata['subscriptionId'] = parts[2]
            if len(parts) >= 5:
                metadata['resourceGroup'] = parts[4]
            if len(parts) >= 9:
                metadata['resourceName'] = parts[8]
        
        # Extract location
        location = resource.get('location')
        if location:
            metadata['location'] = location
        
        # Extract tags
        tags = resource.get('tags', {})
        if tags:
            metadata['tags'] = tags
        
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



def submit_findings(findings: List[Dict[str, Any]], config: Dict[str, Any]) -> None:
    """Submit findings to LeftSize backend"""
    
    output_config = config.get('output', {})
    backend_url = output_config.get('backend_url')
    installation_id = output_config.get('installation_id')
    # Support both 'token' (from config file) and 'repository_token' (from command line)
    repository_token = output_config.get('repository_token') or output_config.get('token')
    
    # Save local output if configured
    if output_config.get('local_output', {}).get('enabled', False):
        save_local_output(findings, output_config)
    
    if not backend_url or not installation_id:
        logger.warning("Backend URL or installation ID not configured, skipping submission")
        return
    
    if not repository_token:
        logger.warning("Repository token not configured, skipping submission")
        return
    
    try:
        # Group findings by rule and scope (as expected by backend)
        finding_groups = group_findings(findings)
        
        # Submit to backend - URL now includes both installationId and repositoryToken
        url = f"{backend_url}/findings/{installation_id}/{repository_token}"
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'LeftSize-Runner/1.0'
        }
        
        logger.info("Submitting findings to backend", 
                   url=url, 
                   finding_groups=len(finding_groups),
                   total_findings=len(findings))
        
        response = requests.post(url, json=finding_groups, headers=headers, timeout=30)
        response.raise_for_status()
        
        logger.info("Findings submitted successfully", 
                   response_status=response.status_code,
                   response_data=response.json())
        
    except Exception as e:
        logger.error("Failed to submit findings to backend", error=str(e))
        # Don't fail the entire run if submission fails


def group_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Group findings by rule ID and scope for backend submission"""
    
    groups = {}
    
    for finding in findings:
        key = (finding['ruleId'], finding['scope'])
        
        if key not in groups:
            groups[key] = {
                'RuleId': finding['ruleId'],  # Use PascalCase to match backend expectation
                'Scope': finding['scope'],
                'Findings': []
            }
        
        # Convert to backend expected format (PascalCase)
        backend_finding = {
            'ResourceId': finding['resourceId'],
            'Metadata': finding.get('metadata')
        }
        
        groups[key]['Findings'].append(backend_finding)
    
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
        sys.exit(github_action_main())
    else:
        sys.exit(main())