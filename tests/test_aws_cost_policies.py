"""
Runs the AWS cost-optimization policies through Cloud Custodian's real filter
chain, with only the AWS API calls (CloudWatch, related-resource lookups) stubbed.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

import pytest
import yaml

from c7n.config import Config
from c7n.manager import resources as registry
from c7n.policy import Policy
from c7n.resources import load_resources

load_resources(('aws.*',))
import c7n.filters.metrics as metrics  # noqa: E402
import c7n.resources.rds as rds  # noqa: E402
import c7n.resources.vpc as vpc  # noqa: E402

POLICY_FILE = Path(__file__).parent.parent / 'policies' / 'aws-cost-optimization.yml'
DOCS = {p['name']: p for p in yaml.safe_load(POLICY_FILE.read_text())['policies']}
NOW = datetime.now(timezone.utc)


def ago(days: int) -> datetime:
    return NOW - timedelta(days=days)


def run(policy: str, resource: Dict[str, Any]) -> bool:
    manager = Policy(DOCS[policy], Config.empty(region='eu-west-1', account_id='123456789012')).resource_manager
    return bool(manager.filter_resources([resource]))


class FakeCloudWatch:
    """Records GetMetricStatistics calls and answers from a {metric name: value} map."""

    def __init__(self, values: Dict[str, Optional[float]]) -> None:
        self.values = values
        self.calls: List[Dict[str, Any]] = []

    def get_metric_statistics(self, **params: Any) -> Dict[str, Any]:
        self.calls.append(params)
        value = self.values.get(params['MetricName'])
        if value is None:
            return {'Datapoints': []}
        return {'Datapoints': [{params['Statistics'][0]: value, 'Timestamp': NOW}]}


class FakeSession:
    def __init__(self, cw: FakeCloudWatch) -> None:
        self.cw = cw

    def client(self, name: str) -> FakeCloudWatch:
        assert name == 'cloudwatch'
        return self.cw


@pytest.fixture
def cloudwatch(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeCloudWatch]:
    cw = FakeCloudWatch({})
    monkeypatch.setattr(metrics, 'local_session', lambda factory: FakeSession(cw))
    yield cw


def iter_filters(filters: List[Any]) -> Iterator[Dict[str, Any]]:
    for f in filters:
        if not isinstance(f, dict):
            continue
        for key in ('and', 'or', 'not'):
            if key in f:
                yield from iter_filters(f[key])
        yield f


METRIC_POLICIES = [name for name, doc in DOCS.items()
                   if any(f.get('type') == 'metrics' for f in iter_filters(doc.get('filters', [])))]


@pytest.mark.parametrize('policy', METRIC_POLICIES)
def test_metric_dimensions_are_not_duplicated(policy: str) -> None:
    """c7n adds the resource's own dimension and sends `dimensions:` values literally,
    so repeating the default dimension sends a bogus second value."""
    doc = DOCS[policy]
    model = registry.get(doc['resource'].split('.', 1)[1]).resource_type
    for f in iter_filters(doc['filters']):
        if f.get('type') == 'metrics':
            assert getattr(model, 'dimension', None) not in f.get('dimensions', {}), policy


EC2_BASE = {
    'InstanceId': 'i-0abc', 'InstanceType': 'm5.large', 'State': {'Name': 'running'},
    'LaunchTime': ago(60), 'BlockDeviceMappings': [], 'Tags': [],
}


def test_inactive_ec2_queries_the_real_instance(cloudwatch: FakeCloudWatch) -> None:
    cloudwatch.values.update({'CPUUtilization': 1.0, 'NetworkOut': 1000.0})
    assert run('leftsize-inactive-ec2-instance', dict(EC2_BASE))
    for call in cloudwatch.calls:
        assert call['Dimensions'] == [{'Name': 'InstanceId', 'Value': 'i-0abc'}]


@pytest.mark.parametrize('cpu, expected', [(5.0, False), (20.0, True), (50.0, False)])
def test_underutilized_ec2(cpu: float, expected: bool, cloudwatch: FakeCloudWatch) -> None:
    cloudwatch.values['CPUUtilization'] = cpu
    assert run('leftsize-underutilized-ec2-instance', dict(EC2_BASE)) is expected


@pytest.mark.parametrize('invocations, expected', [(None, True), (0.0, True), (3.0, False)])
def test_unused_lambda(invocations: Optional[float], expected: bool, cloudwatch: FakeCloudWatch) -> None:
    cloudwatch.values['Invocations'] = invocations
    fn = {'FunctionName': 'fn', 'LastModified': (NOW - timedelta(days=90)).strftime('%Y-%m-%dT%H:%M:%S.000+0000')}
    assert run('leftsize-unused-lambda-function', fn) is expected
    assert cloudwatch.calls[0]['Dimensions'] == [{'Name': 'FunctionName', 'Value': 'fn'}]


@pytest.mark.parametrize('arch, runtime, expected', [
    (['x86_64'], 'python3.12', True),
    (None, 'python3.12', True),
    (['arm64'], 'python3.12', False),
    (['x86_64'], 'provided.al2023', False),
])
def test_lambda_x86(arch: Optional[List[str]], runtime: str, expected: bool, cloudwatch: FakeCloudWatch) -> None:
    cloudwatch.values['Invocations'] = 50.0
    fn: Dict[str, Any] = {'FunctionName': 'fn', 'Runtime': runtime}
    if arch:
        fn['Architectures'] = arch
    assert run('leftsize-lambda-x86-architecture', fn) is expected


@pytest.mark.parametrize('connections, expected', [(None, True), (5.0, True), (6.0, True), (12.0, False)])
def test_idle_elasticache(connections: Optional[float], expected: bool, cloudwatch: FakeCloudWatch) -> None:
    cloudwatch.values['CurrConnections'] = connections
    cluster = {'CacheClusterId': 'redis-001', 'CacheClusterCreateTime': ago(60), 'CacheClusterStatus': 'available'}
    assert run('leftsize-idle-elasticache-cluster', cluster) is expected
    assert cloudwatch.calls[0]['Dimensions'] == [
        {'Name': 'CacheClusterId', 'Value': 'redis-001'}, {'Name': 'CacheNodeId', 'Value': '0001'}]


@pytest.mark.parametrize('lb_type, requests, expected', [
    ('application', None, True),
    ('application', 3.0, True),
    ('application', 500.0, False),
    ('network', None, False),
])
def test_unused_alb(lb_type: str, requests: Optional[float], expected: bool, cloudwatch: FakeCloudWatch) -> None:
    cloudwatch.values['RequestCount'] = requests
    lb = {'Type': lb_type, 'CreatedTime': ago(30), 'LoadBalancerName': 'web',
          'LoadBalancerArn': 'arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/web/50dc6c495c0c9188'}
    assert run('leftsize-unused-alb', lb) is expected


@pytest.mark.parametrize('bytes_out, expected', [(None, True), (0.0, True), (1024.0, False)])
def test_inactive_nat_gateway(bytes_out: Optional[float], expected: bool, cloudwatch: FakeCloudWatch) -> None:
    cloudwatch.values['BytesOutToDestination'] = bytes_out
    nat = {'NatGatewayId': 'nat-0abc', 'State': 'available', 'CreateTime': ago(30)}
    assert run('leftsize-inactive-nat-gateway', nat) is expected
    assert cloudwatch.calls[0]['Dimensions'] == [{'Name': 'NatGatewayId', 'Value': 'nat-0abc'}]


SERVICE_BASE = {'serviceArn': 'arn:aws:ecs:eu-west-1:123456789012:service/c1/api', 'serviceName': 'api', 'desiredCount': 2, 'createdAt': ago(30), 'Tags': []}


@pytest.mark.parametrize('extra, expected', [
    ({'launchType': 'FARGATE'}, True),
    ({'launchType': 'EC2'}, False),
    ({'capacityProviderStrategy': [{'capacityProvider': 'FARGATE', 'weight': 1}]}, True),
    ({'capacityProviderStrategy': [{'capacityProvider': 'FARGATE', 'weight': 1},
                                   {'capacityProvider': 'FARGATE_SPOT', 'weight': 3}]}, False),
    ({'launchType': 'FARGATE', 'Tags': [{'Key': 'Environment', 'Value': 'Production'}]}, False),
    ({'launchType': 'FARGATE', 'Tags': [{'Key': 'Environment', 'Value': 'dev'}]}, True),
    ({'launchType': 'FARGATE', 'desiredCount': 1}, False),
    # describe_services never returns a PascalCase LaunchType
    ({'LaunchType': 'FARGATE'}, False),
])
def test_fargate_spot_eligible(extra: Dict[str, Any], expected: bool) -> None:
    assert run('leftsize-fargate-spot-eligible', dict(SERVICE_BASE, **extra)) is expected


def bucket(lifecycle: Optional[List[Dict[str, Any]]], versioning: Optional[str] = None) -> Dict[str, Any]:
    b: Dict[str, Any] = {'Name': 'b1', 'CreationDate': ago(100), 'Tags': [],
                         'Lifecycle': {'Rules': lifecycle} if lifecycle is not None else None,
                         'Versioning': {'Status': versioning} if versioning else {}}
    return b


ABORT = {'ID': 'abort', 'Status': 'Enabled', 'Filter': {}, 'AbortIncompleteMultipartUpload': {'DaysAfterInitiation': 7}}
EXPIRE = {'ID': 'exp', 'Status': 'Enabled', 'Filter': {}, 'Expiration': {'Days': 365}}
NONCURRENT = {'ID': 'nc', 'Status': 'Enabled', 'Filter': {}, 'NoncurrentVersionExpiration': {'NoncurrentDays': 30}}


@pytest.mark.parametrize('rules, expected', [
    (None, True),
    ([EXPIRE], True),
    ([EXPIRE, ABORT], False),
    ([dict(ABORT, Status='Disabled')], True),
])
def test_s3_incomplete_multipart_uploads(rules: Optional[List[Dict[str, Any]]], expected: bool) -> None:
    assert run('leftsize-s3-incomplete-multipart-uploads', bucket(rules)) is expected


@pytest.mark.parametrize('rules, versioning, expected', [
    (None, 'Enabled', True),
    ([EXPIRE], 'Enabled', True),
    ([EXPIRE, NONCURRENT], 'Enabled', False),
    (None, 'Suspended', False),
    (None, None, False),
])
def test_s3_non_current_versions(rules: Optional[List[Dict[str, Any]]], versioning: Optional[str],
                                 expected: bool) -> None:
    assert run('leftsize-s3-non-current-versions', bucket(rules, versioning)) is expected


@pytest.mark.parametrize('rules, expected', [
    (None, True),
    ([dict(EXPIRE, Status='Disabled')], True),
    ([EXPIRE], False),
])
def test_s3_missing_lifecycle_policy(rules: Optional[List[Dict[str, Any]]], expected: bool) -> None:
    assert run('leftsize-s3-missing-lifecycle-policy', bucket(rules)) is expected


RDS_BASE = {'DBInstanceIdentifier': 'db1', 'Engine': 'postgres', 'DBInstanceStatus': 'available',
            'MultiAZ': True, 'BackupRetentionPeriod': 30, 'Tags': []}


@pytest.mark.parametrize('extra, expected', [
    ({'DBInstanceIdentifier': 'orders-dev-db'}, True),
    ({'DBInstanceIdentifier': 'dev-orders'}, True),
    ({'DBInstanceIdentifier': 'orders-prod'}, False),
    ({'Tags': [{'Key': 'Environment', 'Value': 'Staging'}]}, True),
    ({'Engine': 'docdb', 'DBInstanceIdentifier': 'orders-dev-db'}, False),
    ({'MultiAZ': False, 'DBInstanceIdentifier': 'orders-dev-db'}, False),
])
def test_rds_multiaz_nonprod(extra: Dict[str, Any], expected: bool) -> None:
    assert run('leftsize-rds-multiaz-nonprod', dict(RDS_BASE, **extra)) is expected


@pytest.mark.parametrize('extra, expected', [
    ({'DBInstanceIdentifier': 'orders-qa'}, True),
    ({'DBInstanceIdentifier': 'orders-qa', 'BackupRetentionPeriod': 7}, False),
])
def test_rds_excessive_backup_retention(extra: Dict[str, Any], expected: bool) -> None:
    assert run('leftsize-rds-excessive-backup-retention', dict(RDS_BASE, **extra)) is expected


@pytest.mark.parametrize('tag_value, expected', [('Dev', True), ('staging', True), ('prod', False)])
def test_scheduled_shutdown_env_tag_case(tag_value: str, expected: bool) -> None:
    instance = dict(EC2_BASE, Tags=[{'Key': 'Environment', 'Value': tag_value}])
    assert run('leftsize-ec2-scheduled-shutdown-missing', instance) is expected


@pytest.mark.parametrize('instance_exists, expected', [(False, True), (True, False)])
def test_orphaned_rds_snapshots(instance_exists: bool, expected: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    live = [dict(RDS_BASE, DBInstanceIdentifier='db1')] if instance_exists else []
    monkeypatch.setattr(rds.RDS, 'get_resources', lambda self, ids, *a, **k: [r for r in live if r['DBInstanceIdentifier'] in ids])
    monkeypatch.setattr(rds.RDS, 'resources', lambda self, *a, **k: live)
    snap = {'DBSnapshotIdentifier': 'snap1', 'DBInstanceIdentifier': 'db1', 'SnapshotType': 'manual',
            'Status': 'available', 'SnapshotCreateTime': ago(60), 'TagList': []}
    assert run('leftsize-orphaned-rds-snapshots', snap) is expected


@pytest.mark.parametrize('nat_state, endpoint_service, expected', [
    ('available', None, True),
    ('available', 'com.amazonaws.eu-west-1.s3', False),
    ('available', 'com.amazonaws.eu-west-1.dynamodb', True),
    (None, None, False),
    ('deleted', None, False),
])
def test_missing_vpc_endpoint_s3(nat_state: Optional[str], endpoint_service: Optional[str], expected: bool,
                                 monkeypatch: pytest.MonkeyPatch) -> None:
    nats = [{'NatGatewayId': 'nat-1', 'VpcId': 'vpc-1', 'State': nat_state}] if nat_state else []
    endpoints = [{'VpcEndpointId': 'vpce-1', 'VpcId': 'vpc-1', 'ServiceName': endpoint_service,
                  'VpcEndpointType': 'Gateway'}] if endpoint_service else []
    monkeypatch.setattr(vpc.NATGateway, 'resources', lambda self, *a, **k: nats)
    monkeypatch.setattr(vpc.NATGateway, 'get_resources', lambda self, ids, *a, **k: [n for n in nats if n['NatGatewayId'] in ids])
    monkeypatch.setattr(vpc.VpcEndpoint, 'resources', lambda self, *a, **k: endpoints)
    v = {'VpcId': 'vpc-1', 'State': 'available', 'IsDefault': False, 'Tags': []}
    assert run('leftsize-missing-vpc-endpoint-s3', v) is expected


@pytest.mark.parametrize('extra, expected', [
    ({'LastAccessedDate': ago(120)}, True),
    ({'LastAccessedDate': ago(10)}, False),
    ({}, True),
    ({'CreatedDate': ago(30)}, False),
])
def test_secrets_manager_unused(extra: Dict[str, Any], expected: bool) -> None:
    secret = dict({'Name': 's1', 'ARN': 'arn:aws:secretsmanager:eu-west-1:123456789012:secret:s1', 'CreatedDate': ago(400)}, **extra)
    assert run('leftsize-secrets-manager-unused', secret) is expected


@pytest.mark.parametrize('flags, expected', [([True, True], False), ([True, False], True)])
def test_ebs_delete_on_termination_disabled(flags: List[bool], expected: bool) -> None:
    instance = dict(EC2_BASE, BlockDeviceMappings=[
        {'DeviceName': f'/dev/sd{c}', 'Ebs': {'VolumeId': f'vol-{c}', 'DeleteOnTermination': f, 'AttachTime': ago(60)}}
        for c, f in zip('ab', flags)])
    assert run('leftsize-ebs-delete-on-termination-disabled', instance) is expected
