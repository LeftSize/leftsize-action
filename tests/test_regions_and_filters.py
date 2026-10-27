"""
Tests for AWS region selection, multi-region Custodian output and the
include-policies / exclude-policies filters.
"""

import json
import os
import sys
from pathlib import Path

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from run import (  # noqa: E402
    custodian_region_args,
    filter_policy_file,
    normalize_policy_category,
    parse_custodian_output,
    validate_aws_region,
)

POLICIES_DIR = Path(__file__).parent.parent / 'policies'


def aws_config(regions=None):
    config = {'cloud_provider': 'aws', 'targets': {'aws': {'account_id': '123456789012'}}}
    if regions is not None:
        config['targets']['aws']['regions'] = regions
    return config


def write_policy_output(policy_dir: Path, resources):
    policy_dir.mkdir(parents=True)
    (policy_dir / 'resources.json').write_text(json.dumps(resources))


class TestRegionArgs:
    def test_one_flag_per_configured_region(self):
        assert custodian_region_args(aws_config(['us-east-1', 'eu-west-1'])) == [
            '--region', 'us-east-1', '--region', 'eu-west-1']

    def test_no_flags_without_regions(self):
        assert custodian_region_args(aws_config()) == []

    def test_no_flags_for_azure(self):
        assert custodian_region_args({'cloud_provider': 'azure', 'targets': {'aws': {'regions': ['us-east-1']}}}) == []

    def test_all_and_govcloud_are_valid_regions(self):
        assert validate_aws_region('all')
        assert validate_aws_region('us-gov-west-1')
        assert not validate_aws_region('us-east-1; rm -rf /')


class TestMultiRegionOutput:
    def test_single_region_layout(self, tmp_path):
        write_policy_output(tmp_path / 'leftsize-unused-elastic-ip',
                            [{'AllocationId': 'eipalloc-1', 'PublicIp': '1.2.3.4'}])
        findings = parse_custodian_output(str(tmp_path), aws_config(['eu-west-1']))
        assert len(findings) == 1
        assert findings[0]['scope'] == 'aws:account/123456789012/region/eu-west-1'

    def test_nested_region_layout_keeps_each_region(self, tmp_path):
        write_policy_output(tmp_path / 'us-east-1' / 'leftsize-unused-elastic-ip',
                            [{'AllocationId': 'eipalloc-1', 'PublicIp': '1.2.3.4'}])
        write_policy_output(tmp_path / 'eu-west-1' / 'leftsize-unused-elastic-ip',
                            [{'AllocationId': 'eipalloc-2', 'PublicIp': '5.6.7.8'}])
        findings = parse_custodian_output(str(tmp_path), aws_config(['us-east-1', 'eu-west-1']))
        scopes = sorted(f['scope'] for f in findings)
        assert scopes == ['aws:account/123456789012/region/eu-west-1',
                          'aws:account/123456789012/region/us-east-1']
        assert all(f['ruleId'] == 'leftsize-unused-elastic-ip' for f in findings)


class TestPolicyFilters:
    def test_category_aliases(self):
        assert normalize_policy_category('cost') == 'cost-optimization'
        assert normalize_policy_category('Deprecations') == 'deprecation'
        assert normalize_policy_category('security') == 'security'
        assert normalize_policy_category('bogus') is None

    def test_no_filters_runs_the_original_file(self, tmp_path):
        path = str(POLICIES_DIR / 'aws-governance.yml')
        assert filter_policy_file(path, {}, str(tmp_path)) == path

    def test_include_category_drops_files_without_matches(self, tmp_path):
        config = {'policies': {'include_categories': ['security']}}
        assert filter_policy_file(str(POLICIES_DIR / 'aws-cost-optimization.yml'), config, str(tmp_path)) is None
        assert filter_policy_file(str(POLICIES_DIR / 'aws-security.yml'), config,
                                  str(tmp_path)) == str(POLICIES_DIR / 'aws-security.yml')

    def test_include_category_keeps_only_matching_policies(self, tmp_path):
        # azure-governance.yml mixes governance and security policies
        config = {'policies': {'include_categories': ['security']}}
        out = filter_policy_file(str(POLICIES_DIR / 'azure-governance.yml'), config, str(tmp_path))
        kept = yaml.safe_load(open(out))['policies']
        assert kept and all(p['metadata']['category'] == 'security' for p in kept)

    def test_exclude_rule_with_or_without_prefix(self, tmp_path):
        source = yaml.safe_load(open(POLICIES_DIR / 'aws-security.yml'))['policies']
        first, second = source[0]['name'], source[1]['name']
        config = {'policies': {'exclude_rules': [first, second.removeprefix('leftsize-')]}}
        out = filter_policy_file(str(POLICIES_DIR / 'aws-security.yml'), config, str(tmp_path))
        names = [p['name'] for p in yaml.safe_load(open(out))['policies']]
        assert first not in names and second not in names
        assert len(names) == len(source) - 2
