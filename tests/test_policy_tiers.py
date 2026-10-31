"""
Plan model: cost optimization rules (incl. AKS optimization) are Free, all other
categories are Pro. Every policy declares its tier in metadata so the action
policies, the worker's issue templates and the website agree.
"""

from pathlib import Path

import pytest
import yaml

POLICIES_DIR = Path(__file__).parent.parent / 'policies'
FREE_FILES = {'aws-cost-optimization.yml', 'azure-cost-optimization.yml', 'azure-aks-optimization.yml',
              'cloudflare-cost-optimization.yml'}


def _policies() -> list:
    found = []
    for path in sorted(POLICIES_DIR.glob('*.yml')):
        expected = 'free' if path.name in FREE_FILES else 'pro'
        for policy in (yaml.safe_load(path.read_text()) or {}).get('policies', []):
            found.append(pytest.param(policy, expected, id=policy['name']))
    return found


@pytest.mark.parametrize('policy,expected', _policies())
def test_policy_tier_matches_category(policy: dict, expected: str) -> None:
    assert (policy.get('metadata') or {}).get('tier') == expected


CATEGORY_BY_FILE_SUFFIX = {
    'cost-optimization': 'cost-optimization',
    'aks-optimization': 'cost-optimization',
    'deprecations': 'deprecation',
    'governance': 'governance',
    'security': 'security',
}


def _policies_with_category() -> list:
    found = []
    for path in sorted(POLICIES_DIR.glob('*.yml')):
        suffix = path.stem.split('-', 1)[1]
        for policy in (yaml.safe_load(path.read_text()) or {}).get('policies', []):
            found.append(pytest.param(policy, CATEGORY_BY_FILE_SUFFIX[suffix], id=policy['name']))
    return found


@pytest.mark.parametrize('policy,expected', _policies_with_category())
def test_policy_category_matches_file(policy: dict, expected: str) -> None:
    # include-policies filters on metadata.category; the website groups by file
    assert (policy.get('metadata') or {}).get('category') == expected
