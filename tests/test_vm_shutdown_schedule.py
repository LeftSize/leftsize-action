"""
leftsize-vm-scheduled-shutdown-missing: Custodian finds running non-prod VMs; run.py
then drops VMs with an enabled auto-shutdown schedule, found with one Resource Graph
query per subscription (fake client here).
"""

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import run  # noqa: E402


def vm_id(name: str, sub: str = 'sub-1', rg: str = 'RG-Dev') -> str:
    return f'/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{name}'


class FakeGraph:
    """Answers QueryRequests from a list of pages of rows; records each request."""

    def __init__(self, pages: List[List[Dict[str, str]]], fail: bool = False) -> None:
        self.pages, self.fail, self.requests = pages, fail, []

    def resources(self, request: Any) -> Any:
        self.requests.append(request)
        if self.fail:
            raise RuntimeError('AuthorizationFailed')
        index = int(request.options.skip_token or 0)
        more = index + 1 < len(self.pages)
        return SimpleNamespace(data=self.pages[index], skip_token=str(index + 1) if more else None)


def test_query_selects_enabled_vm_shutdown_schedules() -> None:
    graph = FakeGraph([[{'vm': vm_id('a').lower()}]])
    assert run._azure_shutdown_schedule_targets('sub-1', client=graph) == {vm_id('a').lower()}
    request = graph.requests[0]
    assert request.subscriptions == ['sub-1']
    assert "microsoft.devtestlab/schedules" in request.query
    assert "properties.status =~ 'Enabled'" in request.query
    assert "properties.taskType =~ 'ComputeVmShutdownTask'" in request.query
    assert request.options.result_format == 'objectArray'


def test_query_follows_skip_token() -> None:
    graph = FakeGraph([[{'vm': 'x'}], [{'vm': 'y'}], [{'vm': 'z'}]])
    assert run._azure_shutdown_schedule_targets('sub-1', client=graph) == {'x', 'y', 'z'}
    assert len(graph.requests) == 3


def test_query_failure_returns_none() -> None:
    assert run._azure_shutdown_schedule_targets('sub-1', client=FakeGraph([], fail=True)) is None


def lookup(answers: Dict[str, Optional[set]], calls: List[str]):
    def fake(subscription_id: str, client: Any = None) -> Optional[set]:
        calls.append(subscription_id)
        return answers[subscription_id]
    return fake


@pytest.mark.parametrize('label,targets,expected', [
    ('no schedules in the subscription', set(), ['dev-1', 'dev-2']),
    ('dev-1 has a schedule (ID casing differs)', {vm_id('dev-1').lower()}, ['dev-2']),
    ('both have schedules', {vm_id('dev-1').lower(), vm_id('dev-2').lower()}, []),
    ('lookup failed: report nothing', None, []),
], ids=lambda x: x if isinstance(x, str) else '')
def test_post_filter(label: str, targets: Optional[set], expected: List[str], monkeypatch: pytest.MonkeyPatch) -> None:
    calls: List[str] = []
    monkeypatch.setattr(run, '_azure_shutdown_schedule_targets', lookup({'sub-1': targets}, calls))
    vms = [{'id': vm_id('dev-1'), 'name': 'dev-1'}, {'id': vm_id('dev-2'), 'name': 'dev-2'}]
    kept = run.POLICY_POST_FILTERS['leftsize-vm-scheduled-shutdown-missing'](vms)
    assert [v['name'] for v in kept] == expected
    assert calls == ['sub-1']  # one query per subscription, not per VM


def test_post_filter_queries_each_subscription_once(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: List[str] = []
    monkeypatch.setattr(run, '_azure_shutdown_schedule_targets',
                        lookup({'sub-1': set(), 'sub-2': {vm_id('b', 'sub-2').lower()}}, calls))
    vms = [{'id': vm_id('a', 'sub-1')}, {'id': vm_id('b', 'sub-2')}, {'id': vm_id('c', 'sub-1')}]
    kept = run._vms_without_shutdown_schedule(vms)
    assert [v['id'] for v in kept] == [vm_id('a', 'sub-1'), vm_id('c', 'sub-1')]
    assert sorted(calls) == ['sub-1', 'sub-2']


def test_parse_output_applies_post_filter(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy_dir = tmp_path / 'leftsize-vm-scheduled-shutdown-missing'
    policy_dir.mkdir()
    vms = [{'id': vm_id('dev-1'), 'name': 'dev-1', 'location': 'westeurope', 'resourceGroup': 'RG-Dev'},
           {'id': vm_id('dev-2'), 'name': 'dev-2', 'location': 'westeurope', 'resourceGroup': 'RG-Dev'}]
    (policy_dir / 'resources.json').write_text(json.dumps(vms))
    (policy_dir / 'metadata.json').write_text(json.dumps({'policy': {'resource': 'azure.vm', 'metadata': {}}}))
    monkeypatch.setattr(run, '_azure_shutdown_schedule_targets', lambda s, client=None: {vm_id('dev-1').lower()})
    findings = run.parse_custodian_output(str(tmp_path), {'cloud_provider': 'azure'})
    assert [f['resourceId'] for f in findings] == [vm_id('dev-2')]
