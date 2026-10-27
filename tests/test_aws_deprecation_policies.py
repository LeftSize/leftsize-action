"""
Runs the AWS deprecation policies through Cloud Custodian's real filter chain, using
resource dicts shaped like c7n's describe/augment output. No AWS calls are made: the
only filter that needs one (the EC2 `image` filter) has its AMI lookup stubbed.
"""

from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

from c7n.config import Config
from c7n.policy import Policy
from c7n.resources import load_resources

load_resources(('aws.*',))
from c7n.resources.ec2 import InstanceImageBase  # noqa: E402

POLICY_FILE = Path(__file__).parent.parent / 'policies' / 'aws-deprecations.yml'
DOCS = {p['name']: p for p in yaml.safe_load(POLICY_FILE.read_text())['policies']}


def matches(rule: str, resource: Dict[str, Any]) -> bool:
    manager = Policy(DOCS[rule], Config.empty(region='eu-west-1')).resource_manager
    return bool(manager.filter_resources([resource]))


def test_rule_count() -> None:
    assert len(DOCS) == 32


# --- Lambda -------------------------------------------------------------------

@pytest.mark.parametrize('runtime, expected', [
    ('python3.10', True),
    ('nodejs20.x', True),
    ('provided.al2', True),
    ('java8', True),
    ('python3.12', False),
    ('java17.al2023', False),
    ('java8.al2', False),       # not yet inside the 6-month window
    ('provided.al2023', False),
])
def test_lambda_runtime(runtime: str, expected: bool) -> None:
    assert matches('leftsize-lambda-deprecated-runtime', {'FunctionName': 'f', 'Runtime': runtime}) is expected


def test_lambda_container_image_not_matched() -> None:
    assert matches('leftsize-lambda-deprecated-runtime', {'FunctionName': 'f', 'PackageType': 'Image'}) is False


# --- EKS ----------------------------------------------------------------------

@pytest.mark.parametrize('version, expected', [
    ('1.9', True),     # numeric compare, not string compare
    ('1.30', True),
    ('1.31', True),
    ('1.34', True),
    ('1.35', False),
    ('1.37', False),
])
def test_eks_version(version: str, expected: bool) -> None:
    assert matches('leftsize-eks-outdated-version', {'name': 'c', 'status': 'ACTIVE', 'version': version}) is expected


def test_eks_deleting_skipped() -> None:
    assert matches('leftsize-eks-outdated-version', {'name': 'c', 'status': 'DELETING', 'version': '1.31'}) is False


@pytest.mark.parametrize('ami_type, expected', [
    ('AL2_x86_64', True),
    ('AL2_ARM_64', True),
    ('AL2023_x86_64_STANDARD', False),
    ('BOTTLEROCKET_x86_64', False),
    ('CUSTOM', False),
])
def test_eks_nodegroup_al2(ami_type: str, expected: bool) -> None:
    ng = {'nodegroupName': 'ng', 'status': 'ACTIVE', 'amiType': ami_type}
    assert matches('leftsize-eks-nodegroup-al2-ami', ng) is expected


# --- AWS Batch ----------------------------------------------------------------

def batch_env(ec2_config: Any = None, ce_type: str = 'EC2') -> Dict[str, Any]:
    compute: Dict[str, Any] = {'type': ce_type}
    if ec2_config is not None:
        compute['ec2Configuration'] = ec2_config
    return {'computeEnvironmentName': 'ce', 'type': 'MANAGED', 'computeResources': compute}


@pytest.mark.parametrize('env, expected', [
    (batch_env([{'imageType': 'ECS_AL2'}]), True),
    (batch_env([{'imageType': 'ECS_AL2023'}, {'imageType': 'ECS_AL2_NVIDIA'}]), True),
    (batch_env([{'imageType': 'ECS_AL2023'}]), False),
    (batch_env(None), False),                                   # ec2Configuration never set
    (batch_env([{'imageType': 'ECS_AL2'}], ce_type='FARGATE'), False),
])
def test_batch_al2(env: Dict[str, Any], expected: bool) -> None:
    assert matches('leftsize-batch-compute-al2-ami', env) is expected


# --- EC2 Amazon Linux 2 (image filter, AMI lookup stubbed) ---------------------

@pytest.mark.parametrize('ami_name, expected', [
    ('amzn2-ami-kernel-5.10-hvm-2.0.20240620.0-x86_64-gp2', True),
    ('amzn2-ami-ecs-hvm-2.0.20240610-x86_64-ebs', True),
    ('al2023-ami-2023.5.20240624.0-kernel-6.1-x86_64', False),
    ('amazon-eks-node-1.29-v20240624', False),
    (None, False),   # AMI not found (deregistered / private)
])
def test_ec2_al2(ami_name: Any, expected: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    image = {'ImageId': 'ami-1', 'Name': ami_name} if ami_name else None

    def fake_prefetch(self: Any, instances: List[Dict[str, Any]]) -> None:
        self.image_map = {'ami-1': image} if image else {}

    monkeypatch.setattr(InstanceImageBase, 'prefetch_instance_images', fake_prefetch)
    instance = {'InstanceId': 'i-1', 'ImageId': 'ami-1', 'State': {'Name': 'running'}}
    assert matches('leftsize-ec2-amazon-linux-2-eol', instance) is expected


# --- Elastic Beanstalk ----------------------------------------------------------

@pytest.mark.parametrize('stack, expected', [
    ('64bit Amazon Linux 2 v5.9.4 running Node.js 18', True),
    ('64bit Amazon Linux 2018.03 v2.11.6 running Java 8', True),
    ('64bit Amazon Linux 2023 v6.2.0 running Node.js 20', True),
    ('64bit Amazon Linux 2023 v4.1.0 running Python 3.9', True),
    ('64bit Amazon Linux 2023 v6.6.0 running Node.js 22', False),
    ('64bit Amazon Linux 2023 v4.3.0 running Python 3.12', False),
])
def test_eb_linux(stack: str, expected: bool) -> None:
    env = {'EnvironmentName': 'e', 'Status': 'Ready', 'SolutionStackName': stack}
    assert matches('leftsize-elasticbeanstalk-retired-linux-platform', env) is expected


@pytest.mark.parametrize('stack, expected', [
    ('64bit Windows Server 2016 v2.23.6 running IIS 10.0', True),
    ('64bit Windows Server Core 2016 v2.23.6 running IIS 10.0', True),
    ('64bit Windows Server 2019 v2.23.6 running IIS 10.0', False),
])
def test_eb_windows_2016(stack: str, expected: bool) -> None:
    env = {'EnvironmentName': 'e', 'Status': 'Ready', 'SolutionStackName': stack}
    assert matches('leftsize-elasticbeanstalk-windows-2016-platform', env) is expected


# --- WorkSpaces -----------------------------------------------------------------

@pytest.mark.parametrize('protocols, expected', [
    (['PCOIP'], True),
    (['WSP'], False),
    (['PCOIP', 'WSP'], True),
])
def test_workspaces_pcoip(protocols: List[str], expected: bool) -> None:
    ws = {'WorkspaceId': 'ws-1', 'State': 'AVAILABLE', 'WorkspaceProperties': {'Protocols': protocols}}
    assert matches('leftsize-workspaces-pcoip-end-of-support', ws) is expected


# --- Glue -------------------------------------------------------------------------

@pytest.mark.parametrize('job, expected', [
    ({'Command': {'Name': 'glueetl'}}, True),                       # no GlueVersion => 0.9
    ({'Command': {'Name': 'glueetl'}, 'GlueVersion': '2.0'}, True),
    ({'Command': {'Name': 'gluestreaming'}, 'GlueVersion': '1.0'}, True),
    ({'Command': {'Name': 'glueetl'}, 'GlueVersion': '3.0'}, False),
    ({'Command': {'Name': 'glueetl'}, 'GlueVersion': '5.0'}, False),
    ({'Command': {'Name': 'pythonshell', 'PythonVersion': '3'}}, True),
    ({'Command': {'Name': 'pythonshell', 'PythonVersion': '2'}}, True),
    ({'Command': {'Name': 'pythonshell', 'PythonVersion': '3.9'}}, False),
    ({'Command': {'Name': 'glueray'}}, False),
])
def test_glue_job(job: Dict[str, Any], expected: bool) -> None:
    assert matches('leftsize-glue-job-eol-version', dict(job, Name='j')) is expected


# --- EMR ----------------------------------------------------------------------------

@pytest.mark.parametrize('cluster, eos_2026, eos_2027', [
    ({'ReleaseLabel': 'emr-5.35.0'}, True, False),
    ({'ReleaseLabel': 'emr-5.36.2'}, False, True),
    ({'ReleaseLabel': 'emr-6.5.0'}, True, False),
    ({'ReleaseLabel': 'emr-6.15.0'}, False, True),
    ({'ReleaseLabel': 'emr-6.6.0'}, False, True),
    ({'ReleaseLabel': 'emr-4.9.6'}, True, False),
    ({'ReleaseLabel': 'emr-7.1.0'}, False, False),
    ({'RunningAmiVersion': '3.11.0'}, True, False),   # 2.x/3.x: AMI version, no release label
])
def test_emr(cluster: Dict[str, Any], eos_2026: bool, eos_2027: bool) -> None:
    c = dict(cluster, Id='j-1', Name='c')
    assert matches('leftsize-emr-release-end-of-support', c) is eos_2026
    assert matches('leftsize-emr-release-support-ending-2027', c) is eos_2027


# --- MSK ---------------------------------------------------------------------------

def msk(version: str) -> Dict[str, Any]:
    return {'ClusterName': 'k', 'State': 'ACTIVE',
            'Provisioned': {'CurrentBrokerSoftwareInfo': {'KafkaVersion': version}}}


@pytest.mark.parametrize('version, expected', [
    ('2.8.2.tiered', True),
    ('3.5.1', True),
    ('3.7.x', True),
    ('3.7.x.kraft', True),
    ('3.8.x', False),
    ('3.9.x', False),
    ('4.0.x.kraft', False),
])
def test_msk(version: str, expected: bool) -> None:
    assert matches('leftsize-msk-kafka-version-end-of-support', msk(version)) is expected


def test_msk_serverless_skipped() -> None:
    serverless = {'ClusterName': 'k', 'State': 'ACTIVE', 'ClusterType': 'SERVERLESS', 'Serverless': {}}
    assert matches('leftsize-msk-kafka-version-end-of-support', serverless) is False


# --- DMS ---------------------------------------------------------------------------

@pytest.mark.parametrize('version, expected', [
    ('3.4.7', True),
    ('3.5.3', True),
    ('3.5.4', True),
    ('3.6.0', True),
    ('3.6.1', False),
    ('3.5.10', False),
])
def test_dms(version: str, expected: bool) -> None:
    ri = {'ReplicationInstanceIdentifier': 'r', 'EngineVersion': version, 'ReplicationInstanceStatus': 'available'}
    assert matches('leftsize-dms-replication-engine-eol', ri) is expected


# --- RDS family ---------------------------------------------------------------------

def rds(engine: str, version: str, **extra: Any) -> Dict[str, Any]:
    return dict({'DBInstanceIdentifier': 'db', 'DBInstanceStatus': 'available',
                 'Engine': engine, 'EngineVersion': version}, **extra)


@pytest.mark.parametrize('db, expected', [
    (rds('mysql', '5.7.44'), True),
    (rds('mysql', '8.0.40'), True),
    (rds('mysql', '8.4.3'), False),
    (rds('postgres', '12.22'), True),
    (rds('postgres', '13.20'), True),
    (rds('postgres', '14.15'), False),
    (rds('aurora-mysql', '5.7.mysql_aurora.2.11.2'), True),
    (rds('aurora-mysql', '8.0.mysql_aurora.3.08.0'), False),
    (rds('aurora-postgresql', '13.18'), True),
    (rds('mysql', '5.7.44', EngineLifecycleSupport='open-source-rds-extended-support'), True),
    (rds('mysql', '5.7.44', EngineLifecycleSupport='open-source-rds-extended-support-disabled'), False),
    (rds('postgres', '12.22', DBInstanceStatus='deleting'), False),
])
def test_rds_outdated(db: Dict[str, Any], expected: bool) -> None:
    assert matches('leftsize-rds-outdated-version', db) is expected


@pytest.mark.parametrize('rule, db, expected', [
    ('leftsize-rds-postgres11-end-of-extended-support', rds('postgres', '11.22'), True),
    ('leftsize-rds-postgres11-end-of-extended-support', rds('postgres', '12.22'), False),
    ('leftsize-rds-postgres14-end-of-standard-support', rds('aurora-postgresql', '14.15'), True),
    ('leftsize-rds-mariadb-end-of-support', rds('mariadb', '10.6.20'), True),
    ('leftsize-rds-mariadb-end-of-support', rds('mariadb', '10.11.10'), False),
    ('leftsize-rds-sqlserver-2016-end-of-support', rds('sqlserver-se', '13.00.6455.2.v1'), True),
    ('leftsize-rds-sqlserver-2016-end-of-support', rds('sqlserver-se', '15.00.4415.2.v1'), False),
    ('leftsize-rds-custom-oracle-end-of-support', rds('custom-oracle-ee', '19.c.ee.002'), True),
    ('leftsize-rds-custom-oracle-end-of-support', rds('oracle-ee', '19.0.0.0.ru-2024-10.rur-2024-10.r1'), False),
    ('leftsize-docdb-36-extended-support', rds('docdb', '3.6.0'), True),
    ('leftsize-docdb-36-extended-support', rds('docdb', '5.0.0'), False),
    ('leftsize-neptune-engine-end-of-life', rds('neptune', '1.2.1.2'), True),
    ('leftsize-neptune-engine-end-of-life', rds('neptune', '1.4.6.1'), True),
    ('leftsize-neptune-engine-end-of-life', rds('neptune', '1.4.6.2'), False),
    ('leftsize-neptune-engine-end-of-life', rds('neptune', '1.4.7.0'), False),
])
def test_rds_family(rule: str, db: Dict[str, Any], expected: bool) -> None:
    assert matches(rule, db) is expected


# --- ElastiCache / OpenSearch --------------------------------------------------------

@pytest.mark.parametrize('engine, version, eol, v6', [
    ('redis', '5.0.6', True, False),
    ('redis', '4.0.10', True, False),
    ('redis', '6.2.6', False, True),
    ('redis', '7.1.0', False, False),
    ('valkey', '7.2.6', False, False),
    ('memcached', '1.6.22', False, False),
])
def test_elasticache(engine: str, version: str, eol: bool, v6: bool) -> None:
    cc = {'CacheClusterId': 'c', 'CacheClusterStatus': 'available', 'Engine': engine, 'EngineVersion': version}
    assert matches('leftsize-elasticache-eol-redis', cc) is eol
    assert matches('leftsize-elasticache-redis6-end-of-standard-support', cc) is v6


@pytest.mark.parametrize('version, expected', [
    ('5.6', True),
    ('6.7', True),
    ('6.8', False),
    ('7.8', True),
    ('7.10', False),
    ('OpenSearch_1.2', True),
    ('OpenSearch_1.3', False),
    ('OpenSearch_2.9', True),
    ('OpenSearch_2.11', False),
    ('OpenSearch_3.1', False),
])
def test_opensearch(version: str, expected: bool) -> None:
    domain = {'DomainName': 'd', 'Deleted': False, 'ElasticsearchVersion': version}
    assert matches('leftsize-opensearch-outdated-version', domain) is expected


# --- MWAA / maintenance-mode services ---------------------------------------------------

@pytest.mark.parametrize('version, expected', [
    ('2.6.3', True),
    ('1.10.12', True),
    ('2.10.3', False),
    ('3.0.6', False),
])
def test_mwaa(version: str, expected: bool) -> None:
    env = {'Name': 'a', 'AirflowVersion': version, 'Status': 'AVAILABLE'}
    assert matches('leftsize-mwaa-airflow-version-end-of-support', env) is expected


@pytest.mark.parametrize('rule, resource, expected', [
    ('leftsize-simple-ad-maintenance', {'DirectoryId': 'd-1', 'Type': 'SimpleAD', 'Stage': 'Active'}, True),
    ('leftsize-simple-ad-maintenance', {'DirectoryId': 'd-1', 'Type': 'MicrosoftAD', 'Stage': 'Active'}, False),
    ('leftsize-cloudsearch-maintenance', {'DomainName': 'd', 'Deleted': False}, True),
    ('leftsize-cloudsearch-maintenance', {'DomainName': 'd', 'Deleted': True}, False),
    ('leftsize-kendra-maintenance', {'Id': 'i', 'Name': 'n', 'Status': 'ACTIVE'}, True),
    ('leftsize-cloud-directory-end-of-support', {'DirectoryArn': 'arn', 'Name': 'n', 'State': 'ENABLED'}, True),
    ('leftsize-arc-readiness-check-maintenance', {'ReadinessCheckName': 'rc', 'ResourceSet': 'rs'}, True),
    ('leftsize-pinpoint-deprecated', {'Id': 'abc', 'Name': 'app'}, True),
    ('leftsize-timestream-deprecated', {'DatabaseName': 'db', 'Arn': 'arn'}, True),
])
def test_service_level_rules(rule: str, resource: Dict[str, Any], expected: bool) -> None:
    assert matches(rule, resource) is expected
