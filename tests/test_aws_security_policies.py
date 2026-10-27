"""
Runs the AWS S3 public-access policy through Cloud Custodian's real filter chain,
with the S3 GetPublicAccessBlock call stubbed.
"""

from pathlib import Path
from typing import Any, Dict, Optional

import pytest
import yaml
from botocore.exceptions import ClientError

from c7n.config import Config
from c7n.policy import Policy
from c7n.resources import load_resources

load_resources(('aws.s3',))
import c7n.resources.s3 as s3  # noqa: E402

POLICY_FILE = Path(__file__).parent.parent / 'policies' / 'aws-security.yml'
DOCS = {p['name']: p for p in yaml.safe_load(POLICY_FILE.read_text())['policies']}
ALL_ON = {'BlockPublicAcls': True, 'IgnorePublicAcls': True, 'BlockPublicPolicy': True, 'RestrictPublicBuckets': True}


class FakeS3:
    def __init__(self, config: Optional[Dict[str, bool]]) -> None:
        self.config = config

    def get_public_access_block(self, Bucket: str) -> Dict[str, Any]:
        if self.config is None:
            raise ClientError({'Error': {'Code': 'NoSuchPublicAccessBlockConfiguration', 'Message': ''}}, 'GetPublicAccessBlock')
        return {'PublicAccessBlockConfiguration': self.config}


def matches(config: Optional[Dict[str, bool]], monkeypatch: pytest.MonkeyPatch) -> bool:
    monkeypatch.setattr(s3, 'local_session', lambda factory: None)
    monkeypatch.setattr(s3, 'bucket_client', lambda session, bucket: FakeS3(config))
    manager = Policy(DOCS['leftsize-public-s3-access'], Config.empty(region='eu-west-1')).resource_manager
    # A bucket as c7n's augment step returns it: no PublicAccessBlockConfiguration or Encryption keys
    bucket = {'Name': 'b1', 'Location': {'LocationConstraint': 'eu-west-1'}, 'Tags': []}
    return bool(manager.filter_resources([bucket]))


@pytest.mark.parametrize('config, expected', [
    (ALL_ON, False),
    (None, True),
    (dict(ALL_ON, BlockPublicPolicy=False), True),
    (dict(ALL_ON, IgnorePublicAcls=False), True),
])
def test_public_s3_access(config: Optional[Dict[str, bool]], expected: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    assert matches(config, monkeypatch) is expected


def test_removed_rules_stay_removed() -> None:
    assert 'leftsize-unencrypted-s3-buckets' not in DOCS
