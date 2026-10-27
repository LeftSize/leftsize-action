"""
leftsize-inactive-eks-cluster: the Custodian filters (status, age, Auto Mode) run
through the real filter chain; the compute check that DescribeCluster can't express
(run.py _eks_cluster_has_compute) runs against a fake boto3 session.
"""

import datetime
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
import yaml

from c7n.config import Config
from c7n.policy import Policy
from c7n.resources import load_resources

sys.path.insert(0, str(Path(__file__).parent.parent))
import run  # noqa: E402

load_resources(('aws.eks',))

DOC = next(p for p in yaml.safe_load((Path(__file__).parent.parent / 'policies' / 'aws-cost-optimization.yml').read_text())['policies']
           if p['name'] == 'leftsize-inactive-eks-cluster')
NOW = datetime.datetime.now(datetime.timezone.utc)
ARN = 'arn:aws:eks:eu-west-1:123456789012:cluster/demo'


def cluster(age_days: int = 30, status: str = 'ACTIVE', **extra: Any) -> Dict[str, Any]:
    return dict({'name': 'demo', 'arn': ARN, 'status': status,
                 'createdAt': (NOW - datetime.timedelta(days=age_days)).isoformat()}, **extra)


@pytest.mark.parametrize('label,resource,expected', [
    ('active, 30 days old', cluster(), True),
    ('Auto Mode disabled', cluster(computeConfig={'enabled': False}), True),
    ('created 2 days ago', cluster(age_days=2), False),
    ('Auto Mode', cluster(computeConfig={'enabled': True, 'nodePools': ['general-purpose']}), False),
    ('creating', cluster(status='CREATING'), False),
], ids=lambda x: x if isinstance(x, str) else '')
def test_policy_filters(label: str, resource: Dict[str, Any], expected: bool) -> None:
    manager = Policy(DOC, Config.empty(region='eu-west-1', account_id='123456789012')).resource_manager
    assert bool(manager.filter_resources([resource])) is expected


class FakeClient:
    def __init__(self, nodegroups: List[str], fargate: List[str], tagged: Dict[str, int],
                 fail: bool, calls: List[Any]) -> None:
        self.nodegroups, self.fargate, self.tagged, self.fail, self.calls = nodegroups, fargate, tagged, fail, calls

    def list_nodegroups(self, **kw: Any) -> Dict[str, Any]:
        self.calls.append(('list_nodegroups', kw))
        if self.fail:
            raise RuntimeError('AccessDenied')
        return {'nodegroups': self.nodegroups}

    def list_fargate_profiles(self, **kw: Any) -> Dict[str, Any]:
        self.calls.append(('list_fargate_profiles', kw))
        return {'fargateProfileNames': self.fargate}

    def describe_instances(self, Filters: List[Dict[str, Any]], **kw: Any) -> Dict[str, Any]:
        self.calls.append(('describe_instances', Filters))
        key = Filters[0]['Name']
        count = self.tagged.get(key, 0)
        return {'Reservations': [{'Instances': [{'InstanceId': f'i-{n}'} for n in range(count)]}] if count else []}


class FakeSession:
    def __init__(self, nodegroups: Optional[List[str]] = None, fargate: Optional[List[str]] = None,
                 tagged: Optional[Dict[str, int]] = None, fail: bool = False) -> None:
        self.calls: List[Any] = []
        self.regions: List[str] = []
        self._client = FakeClient(nodegroups or [], fargate or [], tagged or {}, fail, self.calls)

    def client(self, service: str, region_name: str) -> FakeClient:
        self.regions.append(region_name)
        return self._client


@pytest.mark.parametrize('label,session,expected', [
    ('nothing at all', FakeSession(), False),
    ('managed node group', FakeSession(nodegroups=['ng-1']), True),
    ('Fargate profile', FakeSession(fargate=['fp-default']), True),
    ('self-managed / Karpenter node (kubernetes.io/cluster tag)', FakeSession(tagged={'tag-key': 1}), True),
    ('Karpenter node (eks:eks-cluster-name tag)', FakeSession(tagged={'tag:eks:eks-cluster-name': 2}), True),
    ('API call denied', FakeSession(fail=True), None),
], ids=lambda x: x if isinstance(x, str) else '')
def test_has_compute(label: str, session: FakeSession, expected: Optional[bool]) -> None:
    assert run._eks_cluster_has_compute(cluster(), session=session) is expected
    assert set(session.regions) <= {'eu-west-1'}


def test_ec2_lookup_uses_cluster_tags_and_live_states() -> None:
    session = FakeSession()
    run._eks_cluster_has_compute(cluster(), session=session)
    filters = [c[1] for c in session.calls if c[0] == 'describe_instances']
    assert {'Name': 'tag-key', 'Values': ['kubernetes.io/cluster/demo']} in filters[0]
    assert {'Name': 'tag:eks:eks-cluster-name', 'Values': ['demo']} in filters[1]
    assert all({'Name': 'instance-state-name', 'Values': ['pending', 'running']} in f for f in filters)


def test_cluster_without_arn_is_not_reported() -> None:
    assert run._eks_cluster_has_compute({'name': 'demo'}, session=FakeSession()) is None


def test_post_filter_keeps_only_clusters_without_compute(monkeypatch: pytest.MonkeyPatch) -> None:
    answers = {'a': False, 'b': True, 'c': None}
    monkeypatch.setattr(run, '_eks_cluster_has_compute', lambda c, session=None: answers[c['name']])
    kept = run.POLICY_POST_FILTERS['leftsize-inactive-eks-cluster']([{'name': n} for n in 'abc'])
    assert [c['name'] for c in kept] == ['a']


def test_parse_output_applies_post_filter(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import json
    policy_dir = tmp_path / 'leftsize-inactive-eks-cluster'
    policy_dir.mkdir()
    (policy_dir / 'resources.json').write_text(json.dumps([cluster(), dict(cluster(), name='busy', arn=ARN + '2')]))
    (policy_dir / 'metadata.json').write_text(json.dumps({'policy': {'resource': 'aws.eks', 'metadata': {}}}))
    monkeypatch.setattr(run, '_eks_cluster_has_compute', lambda c, session=None: c['name'] == 'busy')
    findings = run.parse_custodian_output(str(tmp_path), {'cloud_provider': 'aws', 'aws': {'region': 'eu-west-1'}})
    assert len(findings) == 1
    assert findings[0]['resourceId'].endswith('cluster/demo')
