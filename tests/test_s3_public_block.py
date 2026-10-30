"""
leftsize-public-s3-access: Custodian's check-public-block reads only the bucket-level
Block Public Access setting; run.py combines it with the account-level setting
(one s3control call per account, fake session here).
"""

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import run  # noqa: E402

ALL_ON = {k: True for k in run.S3_PUBLIC_BLOCK_KEYS}
ALL_OFF = {k: False for k in run.S3_PUBLIC_BLOCK_KEYS}
CONFIG = {'cloud_provider': 'aws', 'targets': {'aws': {'account_id': '111122223333'}}}


class ClientError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {'Error': {'Code': code}}


class FakeS3Control:
    def __init__(self, config: Optional[Dict[str, bool]], error: Optional[str], calls: List[str]) -> None:
        self.config, self.error, self.calls = config, error, calls

    def get_public_access_block(self, AccountId: str) -> Dict[str, Any]:
        self.calls.append(AccountId)
        if self.error:
            raise ClientError(self.error)
        return {'PublicAccessBlockConfiguration': self.config}


class FakeSession:
    region_name = 'eu-west-1'

    def __init__(self, config: Optional[Dict[str, bool]] = None, error: Optional[str] = None) -> None:
        self.calls: List[str] = []
        self._client = FakeS3Control(config, error, self.calls)

    def client(self, service: str, region_name: str) -> FakeS3Control:
        assert service == 's3control'
        return self._client


@pytest.mark.parametrize('label,session,expected', [
    ('account block fully on', FakeSession(ALL_ON), ALL_ON),
    ('no account-level setting', FakeSession(error='NoSuchPublicAccessBlockConfiguration'), ALL_OFF),
    ('access denied', FakeSession(error='AccessDenied'), None),
], ids=lambda x: x if isinstance(x, str) else '')
def test_account_lookup(label: str, session: FakeSession, expected: Optional[Dict[str, bool]]) -> None:
    assert run._s3_account_public_block('111122223333', session=session) == expected
    assert session.calls == ['111122223333']


def bucket(name: str, own: Optional[Dict[str, bool]] = None, denied: bool = False) -> Dict[str, Any]:
    b: Dict[str, Any] = {'Name': name, 'c7n:PublicAccessBlock': own if own is not None else dict(ALL_OFF)}
    if denied:
        b['c7n:DeniedMethods'] = ['GetPublicAccessBlock']
    return b


@pytest.fixture
def account(monkeypatch: pytest.MonkeyPatch):
    def set_account(settings: Optional[Dict[str, bool]]) -> List[str]:
        calls: List[str] = []
        monkeypatch.setattr(run, '_S3_ACCOUNT_PUBLIC_BLOCK', {})

        def lookup(account_id: str, session: Any = None) -> Optional[Dict[str, bool]]:
            calls.append(account_id)
            return settings
        monkeypatch.setattr(run, '_s3_account_public_block', lookup)
        return calls
    return set_account


def names(buckets: List[Dict[str, Any]]) -> List[str]:
    return [b['Name'] for b in buckets]


def test_account_block_on_clears_every_bucket(account) -> None:
    calls = account(ALL_ON)
    kept = run.POLICY_POST_FILTERS['leftsize-public-s3-access']([bucket('a'), bucket('b')], CONFIG)
    assert kept == []
    assert calls == ['111122223333']  # one lookup per account, not per bucket


def test_no_account_block_keeps_buckets_with_gaps(account) -> None:
    account(ALL_OFF)
    kept = run._s3_public_block_gaps([bucket('open'), bucket('closed', ALL_ON)], CONFIG)
    assert names(kept) == ['open']
    assert kept[0]['c7n:PublicAccessBlockOff'] == list(run.S3_PUBLIC_BLOCK_KEYS)


def test_settings_combine_per_key(account) -> None:
    account(dict(ALL_OFF, BlockPublicAcls=True, IgnorePublicAcls=True))
    own = dict(ALL_OFF, BlockPublicPolicy=True)
    kept = run._s3_public_block_gaps([bucket('mixed', own)], CONFIG)
    assert kept[0]['c7n:PublicAccessBlockOff'] == ['RestrictPublicBuckets']


def test_unreadable_bucket_setting_is_skipped(account) -> None:
    account(ALL_OFF)
    assert run._s3_public_block_gaps([bucket('denied', denied=True)], CONFIG) == []


def test_account_lookup_failure_reports_no_bucket(account) -> None:
    # Without the account-level setting every bucket would look open
    account(None)
    config = dict(CONFIG)
    assert run._s3_public_block_gaps([bucket('open'), bucket('closed', ALL_ON)], config) == []
    assert any('leftsize-public-s3-access' in p for p in config['scan_problems'])


def test_off_settings_reach_the_finding(account) -> None:
    account(dict(ALL_ON, RestrictPublicBuckets=False))
    kept = run._s3_public_block_gaps([bucket('b1')], CONFIG)
    fields = run.extract_resource_fields(kept[0], 'aws.s3')
    assert fields['publicAccessBlockOff'] == 'RestrictPublicBuckets'
