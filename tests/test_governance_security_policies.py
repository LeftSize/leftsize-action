"""
Runs the governance policies (AWS + Azure) and the AWS security policies through
Cloud Custodian's real filter chain. Only the cloud API calls are stubbed:
the IAM credential report, flow logs and snapshot attributes come from test data.
"""

import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest
import yaml

from c7n.config import Config
from c7n.policy import Policy
from c7n.resources import load_resources

load_resources(('aws.*', 'azure.*'))
import c7n.resources.ebs as ebs  # noqa: E402
import c7n.resources.rds as rds  # noqa: E402
from c7n.resources.iam import CredentialReport  # noqa: E402
from c7n.resources.vpc import FlowLog  # noqa: E402
from c7n_azure.utils import serialize  # noqa: E402
from azure.keyvault.certificates._generated import models as kv_models  # noqa: E402
from azure.keyvault.certificates._models import CertificateProperties  # noqa: E402

POLICIES = Path(__file__).parent.parent / 'policies'


def load(name: str) -> Dict[str, Dict[str, Any]]:
    return {p['name']: p for p in yaml.safe_load((POLICIES / name).read_text())['policies']}


AWS_GOV = load('aws-governance.yml')
AZ_GOV = load('azure-governance.yml')
AWS_SEC = load('aws-security.yml')

NOW = datetime.datetime.now(datetime.timezone.utc)


def days_ago(n: int) -> str:
    return (NOW - datetime.timedelta(days=n)).isoformat()


def days_ahead(n: int) -> str:
    return (NOW + datetime.timedelta(days=n)).isoformat()


def run(doc: Dict[str, Any], resource: Dict[str, Any], region: str = 'us-east-1') -> bool:
    manager = Policy(doc, Config.empty(region=region, account_id='111111111111')).resource_manager
    manager.get_client = lambda *a, **k: None
    for f in manager.filters:
        f.manager.get_client = lambda *a, **k: None
    return bool(manager.filter_resources([resource]))


# ---------------------------------------------------------------------------
# Ownership tags
# ---------------------------------------------------------------------------

AWS_TAG_RULES = {
    'leftsize-missing-ownership-tags': {'InstanceId': 'i-1'},
    'leftsize-missing-ownership-tags-rds': {'DBInstanceIdentifier': 'db1'},
    'leftsize-missing-ownership-tags-s3': {'Name': 'bucket1'},
    'leftsize-missing-ownership-tags-ebs': {'VolumeId': 'vol-1'},
    'leftsize-missing-ownership-tags-elb': {'LoadBalancerName': 'lb1'},
}
TAG_CASES: List[Tuple[str, Dict[str, str], bool]] = [
    ('no tags', {}, True),
    ('other tags only', {'Team': 'x'}, True),
    ('owner set', {'owner': 'team-a'}, False),
    ('Owner set', {'Owner': 'team-a'}, False),
    ('owner empty', {'owner': ''}, True),
    ('owner empty but Owner set', {'owner': '', 'Owner': 'team-a'}, False),
]


@pytest.mark.parametrize('rule', sorted(AWS_TAG_RULES))
@pytest.mark.parametrize('label,tags,expected', TAG_CASES, ids=[c[0] for c in TAG_CASES])
def test_aws_ownership_tags(rule: str, label: str, tags: Dict[str, str], expected: bool) -> None:
    resource = dict(AWS_TAG_RULES[rule], Tags=[{'Key': k, 'Value': v} for k, v in tags.items()])
    assert run(AWS_GOV[rule], resource) is expected


AZ_TAG_RULES = [n for n in AZ_GOV if n.startswith('leftsize-missing-ownership-tags')]


def test_all_azure_tag_rules_covered() -> None:
    assert len(AZ_TAG_RULES) == 6


@pytest.mark.parametrize('rule', sorted(AZ_TAG_RULES))
@pytest.mark.parametrize('label,tags,expected', TAG_CASES + [('tags key missing', None, True)],
                         ids=[c[0] for c in TAG_CASES] + ['tags key missing'])
def test_azure_ownership_tags(rule: str, label: str, tags: Optional[Dict[str, str]], expected: bool) -> None:
    resource: Dict[str, Any] = {'id': '/subscriptions/s/resourceGroups/rg/providers/X/y/r1', 'name': 'r1', 'properties': {}}
    if tags is not None:
        resource['tags'] = tags
    assert run(AZ_GOV[rule], resource, region='westeurope') is expected


# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('status,not_after,expected', [
    ('ISSUED', days_ahead(10), True),
    ('ISSUED', days_ahead(60), False),
    ('EXPIRED', days_ago(5), False),
    ('PENDING_VALIDATION', days_ahead(10), False),
])
def test_acm_certificate_expiring(status: str, not_after: str, expected: bool) -> None:
    cert = {'CertificateArn': 'arn:aws:acm:us-east-1:1:certificate/u', 'Status': status,
            'NotAfter': datetime.datetime.fromisoformat(not_after)}
    assert run(AWS_GOV['leftsize-acm-certificate-expiring'], cert) is expected


def keyvault_cert(enabled: bool, expires_in_days: Optional[int]) -> Dict[str, Any]:
    """A certificate exactly as c7n-azure serializes it from the pinned SDK."""
    raw: Dict[str, Any] = {'enabled': enabled}
    if expires_in_days is not None:
        raw['exp'] = int((NOW + datetime.timedelta(days=expires_in_days)).timestamp())
    item = kv_models.CertificateItem({'id': 'https://v.vault.azure.net/certificates/c1', 'attributes': raw})
    return serialize(CertificateProperties._from_certificate_item(item))


def test_keyvault_cert_shape() -> None:
    # Guards the filter keys: an SDK upgrade that changes this shape must fail here.
    cert = keyvault_cert(True, 10)
    assert set(cert['attributes']) == {'data'}
    assert cert['attributes']['data']['enabled'] is True
    assert isinstance(cert['attributes']['data']['exp'], int)


@pytest.mark.parametrize('enabled,days,expected', [
    (True, 10, True),
    (True, -3, True),   # already expired, still enabled
    (True, 60, False),
    (False, 10, False),
    (True, None, False),  # no expiry date
])
def test_keyvault_cert_expiring(enabled: bool, days: Optional[int], expected: bool) -> None:
    assert run(AZ_GOV['leftsize-keyvault-cert-expiring'], keyvault_cert(enabled, days), region='westeurope') is expected


# ---------------------------------------------------------------------------
# IAM (credential report)
# ---------------------------------------------------------------------------

HEADER = ('user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,'
          'password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,'
          'access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,'
          'access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,'
          'access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,'
          'cert_1_last_rotated,cert_2_active,cert_2_last_rotated')

Key = Tuple[str, str, str]  # (active, last_rotated, last_used_date)
NO_KEY: Key = ('false', 'N/A', 'N/A')


def report_row(created: int = 400, password: str = 'false', pw_used: str = 'N/A', mfa: str = 'false',
               k1: Key = NO_KEY, k2: Key = NO_KEY) -> str:
    def key(k: Key) -> str:
        active, rotated, used = k
        return f'{active},{rotated},{used},N/A,N/A'
    return (f'u1,arn:aws:iam::111111111111:user/u1,{days_ago(created)},{password},{pw_used},N/A,N/A,{mfa},'
            f'{key(k1)},{key(k2)},false,N/A,false,N/A')


def run_iam(rule: str, row: str, monkeypatch: pytest.MonkeyPatch) -> bool:
    monkeypatch.setattr(CredentialReport, 'fetch_credential_report', lambda self: f'{HEADER}\n{row}\n')
    user = {'UserName': 'u1', 'Arn': 'arn:aws:iam::111111111111:user/u1', 'UserId': 'AID1'}
    return run(AWS_SEC[rule], user)


def label_ids(x: Any) -> str:
    """Use the case label as test id; hide the CSV row and the expected flag."""
    return x if isinstance(x, str) and not x.startswith('u1,') else ''


def k(active: bool, rotated_days: int, used_days: Optional[int]) -> Key:
    return ('true' if active else 'false', days_ago(rotated_days), days_ago(used_days) if used_days is not None else 'N/A')


@pytest.mark.parametrize('label,row,expected', [
    ('active key used 100 days ago', report_row(k1=k(True, 400, 100)), True),
    ('active key used 10 days ago', report_row(k1=k(True, 400, 10)), False),
    ('active key never used, created 200 days ago', report_row(k1=k(True, 200, None)), True),
    ('active key never used, created 10 days ago', report_row(k1=k(True, 10, None)), False),
    ('inactive key unused 300 days', report_row(k1=k(False, 400, 300)), False),
    ('recent active key + old inactive key', report_row(k1=k(True, 50, 1), k2=k(False, 400, 300)), False),
    ('recent active key + old active key', report_row(k1=k(True, 50, 1), k2=k(True, 400, 300)), True),
    ('no keys', report_row(), False),
], ids=label_ids)
def test_iam_unused_access_key(label: str, row: str, expected: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    assert run_iam('leftsize-iam-unused-access-key', row, monkeypatch) is expected


@pytest.mark.parametrize('label,row,expected', [
    ('console user without MFA', report_row(password='true', pw_used=days_ago(1)), True),
    ('console user with MFA', report_row(password='true', pw_used=days_ago(1), mfa='true'), False),
    ('key-only user without MFA', report_row(k1=k(True, 10, 1)), False),
], ids=label_ids)
def test_iam_user_without_mfa(label: str, row: str, expected: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    assert run_iam('leftsize-iam-user-without-mfa', row, monkeypatch) is expected


@pytest.mark.parametrize('label,row,expected', [
    ('password used 100 days ago, no keys', report_row(password='true', pw_used=days_ago(100)), True),
    ('password never used, no keys', report_row(password='true', pw_used='no_information'), True),
    ('no credentials at all', report_row(), True),
    ('key used 120 days ago', report_row(k1=k(True, 400, 120)), True),
    ('password old but key used yesterday', report_row(password='true', pw_used=days_ago(100), k1=k(True, 400, 1)), False),
    ('password used yesterday', report_row(password='true', pw_used=days_ago(1)), False),
    ('key used 10 days ago', report_row(k1=k(True, 400, 10)), False),
    ('user created 10 days ago, never used', report_row(created=10, k1=k(True, 10, None)), False),
], ids=label_ids)
def test_iam_unused_user(label: str, row: str, expected: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    assert run_iam('leftsize-iam-unused-user', row, monkeypatch) is expected


# ---------------------------------------------------------------------------
# VPC flow logs
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('label,logs,expected', [
    ('no flow logs', [], True),
    ('active VPC flow log', [{'ResourceId': 'vpc-1', 'FlowLogStatus': 'ACTIVE'}], False),
    ('flow log on another VPC', [{'ResourceId': 'vpc-2', 'FlowLogStatus': 'ACTIVE'}], True),
    ('only subnet flow log', [{'ResourceId': 'subnet-1', 'FlowLogStatus': 'ACTIVE'}], True),
])
def test_vpc_flow_logs_disabled(label: str, logs: List[Dict[str, str]], expected: bool,
                                monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(FlowLog, 'resources', lambda self, *a, **kw: logs)
    assert run(AWS_SEC['leftsize-vpc-flow-logs-disabled'], {'VpcId': 'vpc-1'}) is expected


# ---------------------------------------------------------------------------
# Plain value filters
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('rule,resource,expected', [
    ('leftsize-rds-publicly-accessible', {'DBInstanceIdentifier': 'd', 'PubliclyAccessible': True, 'DBInstanceStatus': 'available'}, True),
    ('leftsize-rds-publicly-accessible', {'DBInstanceIdentifier': 'd', 'PubliclyAccessible': False, 'DBInstanceStatus': 'available'}, False),
    ('leftsize-rds-publicly-accessible', {'DBInstanceIdentifier': 'd', 'PubliclyAccessible': True, 'DBInstanceStatus': 'stopped'}, False),
    ('leftsize-ami-public', {'ImageId': 'ami-1', 'Public': True}, True),
    ('leftsize-ami-public', {'ImageId': 'ami-1', 'Public': False}, False),
    # c7n's S3 augment: {} when logging is off, LoggingEnabled body when on, key missing on AccessDenied
    ('leftsize-s3-bucket-logging-disabled', {'Name': 'b', 'Logging': {}}, True),
    ('leftsize-s3-bucket-logging-disabled', {'Name': 'b', 'Logging': {'TargetBucket': 'logs', 'TargetPrefix': 'b/'}}, False),
    ('leftsize-s3-bucket-logging-disabled', {'Name': 'b', 'c7n:DeniedMethods': ['get_bucket_logging']}, False),
])
def test_aws_value_rules(rule: str, resource: Dict[str, Any], expected: bool) -> None:
    assert run(AWS_SEC[rule], resource) is expected


# ---------------------------------------------------------------------------
# Public snapshots (attribute calls stubbed)
# ---------------------------------------------------------------------------

class FakeClient:
    def __init__(self, perms: List[Dict[str, str]], restore: List[str]) -> None:
        self.perms = perms
        self.restore = restore

    def describe_snapshot_attribute(self, **kw: Any) -> Dict[str, Any]:
        return {'CreateVolumePermissions': self.perms}

    def describe_db_snapshot_attributes(self, **kw: Any) -> Dict[str, Any]:
        return {'DBSnapshotAttributesResult': {'DBSnapshotAttributes': [
            {'AttributeName': 'restore', 'AttributeValues': self.restore}]}}


class FakeSession:
    def __init__(self, client: FakeClient) -> None:
        self._client = client

    def client(self, *a: Any, **kw: Any) -> FakeClient:
        return self._client


@pytest.mark.parametrize('perms,expected', [
    ([{'Group': 'all'}], True),
    ([{'UserId': '222222222222'}], False),
    ([], False),
])
def test_ebs_snapshot_public(perms: List[Dict[str, str]], expected: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ebs, 'local_session', lambda factory: FakeSession(FakeClient(perms, [])))
    assert run(AWS_SEC['leftsize-ebs-snapshot-public'], {'SnapshotId': 'snap-1'}) is expected


@pytest.mark.parametrize('restore,expected', [
    (['all'], True),
    (['222222222222'], False),
    ([], False),
])
def test_rds_snapshot_public(restore: List[str], expected: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rds, 'local_session', lambda factory: FakeSession(FakeClient([], restore)))
    snap = {'DBSnapshotIdentifier': 's1', 'DBSnapshotArn': 'arn:aws:rds:us-east-1:111111111111:snapshot:s1'}
    assert run(AWS_SEC['leftsize-rds-snapshot-public'], snap) is expected
