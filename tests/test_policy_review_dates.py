"""
Deprecation rules describe dates that pass: a retirement that is "upcoming" today is
past next quarter, and a rule may become useless once the service is gone. Every
deprecation rule carries metadata.review_by (YYYY-MM-DD); a daily check in the
LeftSize backend repo opens an issue when that date has passed. The date is the next
change the rule describes, but at most six months out, so dates that providers move
get re-checked. review_note is an optional hint on what to change.
"""

import datetime
from pathlib import Path

import pytest
import yaml

POLICIES_DIR = Path(__file__).parent.parent / 'policies'


def _policies() -> list:
    found = []
    for path in sorted(POLICIES_DIR.glob('*.yml')):
        for policy in (yaml.safe_load(path.read_text()) or {}).get('policies', []):
            found.append(pytest.param(policy, id=policy['name']))
    return found


@pytest.mark.parametrize('policy', _policies())
def test_review_by_is_a_date(policy: dict) -> None:
    metadata = policy.get('metadata') or {}
    if metadata.get('category') == 'deprecation':
        assert 'review_by' in metadata, 'deprecation rules need metadata.review_by'
    if 'review_by' in metadata:
        value = metadata['review_by']
        assert isinstance(value, str), "quote review_by ('YYYY-MM-DD') so YAML keeps it a string"
        # fromisoformat also takes 20261101 and 2026-W44-7; only YYYY-MM-DD is allowed
        assert datetime.date.fromisoformat(value).isoformat() == value, 'use YYYY-MM-DD'
    if 'review_note' in metadata:
        assert 'review_by' in metadata and isinstance(metadata['review_note'], str)
