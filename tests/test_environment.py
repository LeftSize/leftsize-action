"""
Environment classification (run.py classify_environment): production vs non-production
from tags, resource group tags and names. The name patterns mirror a real Azure
subscription with several environments in one subscription (names changed).
"""

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import run  # noqa: E402

SUB = '00000000-0000-0000-0000-000000000001'


def az(rg: str, name: str, kind: str = 'Microsoft.Compute/virtualMachines', **tags: str) -> Dict[str, Any]:
    return {'id': f'/subscriptions/{SUB}/resourceGroups/{rg}/providers/{kind}/{name}', 'name': name, 'tags': tags or {}}


def aws(name: Optional[str] = None, **tags: str) -> Dict[str, Any]:
    tag_list = [{'Key': k, 'Value': v} for k, v in tags.items()]
    if name:
        tag_list.append({'Key': 'Name', 'Value': name})
    return {'InstanceId': 'i-0abc', 'Tags': tag_list}


@pytest.mark.parametrize('label,resource,expected', [
    # One subscription, environments in resource group suffixes and resource names
    ('acceptance VM by name', az('Shop-NG-A', 'shoppf-acc-ssh-vm'), 'acceptance'),
    ('production VM by name', az('Shop-NG-P', 'shoppf-prod-ssh-vm'), 'production'),
    ('acceptance group suffix only', az('Shop-NG-A', 'vnet-core'), 'acceptance'),
    ('production group suffix only', az('Shop-NG-P', 'vnet-core'), 'production'),
    ('shared group (-S) is not an environment', az('Shop-NG-S', 'shopregistry'), 'unknown'),
    ('backup group inherits its suffix', az('Shop-NG-A-backup', 'snapshot-1', 'Microsoft.Compute/snapshots'), 'acceptance'),
    ('GUID parts are not words (acc2)', az('Shop-NG-P-backup', 'snapshot-4df108e9-813e-47fb-acc2-57fe8ea9abda',
                                           'Microsoft.Compute/snapshots'), 'production'),
    ('GUID name in an unrecognised group', az('backups', 'snapshot-4df108e9-813e-47fb-acc2-57fe8ea9abda'), 'unknown'),
    ('AKS node resource group', az('MC_Shop-NG-A_shoppf-acc_westeurope', 'aks-nodepool1-vmss',
                                   'Microsoft.Compute/virtualMachineScaleSets'), 'acceptance'),
    ('AKS node group via aks-managed tags', az('MC_x_y_westeurope', 'aks-pool-vmss', 'Microsoft.Compute/virtualMachineScaleSets',
                                               **{'aks-managed-cluster-rg': 'Shop-NG-P', 'aks-managed-cluster-name': 'shoppf'}), 'production'),
    # Child resources: the parent's name counts (SQL database on an acceptance server)
    ('database on an acc server', {'id': f'/subscriptions/{SUB}/resourceGroups/Shop-NG-S/providers/Microsoft.Sql/servers/shop-acc-sql/databases/orders',
                                   'name': 'orders'}, 'acceptance'),
    ('database on a prod server', {'id': f'/subscriptions/{SUB}/resourceGroups/Shop-NG-S/providers/Microsoft.Sql/servers/shop-prod-sql/databases/orders-test',
                                   'name': 'orders-test'}, 'production'),
    # AKS pool names (np1) are not "non-production"
    ('AKS node pool np1', az('MC_x_y_westeurope', 'aks-np1-12345678-vmss', 'Microsoft.Compute/virtualMachineScaleSets'), 'unknown'),
    # Tags
    ('Environment tag', az('rg', 'vm1', Environment='Development'), 'development'),
    ('env tag, other casing', az('rg', 'vm1', ENV='uat'), 'acceptance'),
    ('Stage tag', az('rg', 'vm1', Stage='stg'), 'staging'),
    ('production tag beats a dev name', az('rg-dev', 'dev-vm', Environment='prod'), 'production'),
    ('production name beats a test tag', az('rg', 'shop-prod-vm', Environment='test'), 'production'),
    ('unrecognised tag value', az('rg', 'vm1', Environment='blue'), 'unknown'),
    # Whole words only
    ('"latest" is not test', az('rg', 'latest-build-vm'), 'unknown'),
    ('"devices" is not dev', az('rg', 'devices-api'), 'unknown'),
    ('"product" is not prod', az('rg', 'product-catalog'), 'unknown'),
    ('pre-prod is acceptance, not production', az('rg', 'shop-pre-prod-db'), 'acceptance'),
    ('non-prod', az('rg', 'shop-non-prod'), 'non-production'),
    ('trailing digits', az('rg', 'web-uat-02'), 'acceptance'),
    ('Dutch OTAP word', az('rg-ontwikkeling', 'vm1'), 'development'),
    # AWS
    ('AWS Environment tag', aws(Environment='staging'), 'staging'),
    ('AWS Name tag', aws('orders-dev-worker'), 'development'),
    ('AWS untagged', aws(), 'unknown'),
], ids=lambda x: x if isinstance(x, str) else '')
def test_classify(label: str, resource: Dict[str, Any], expected: str) -> None:
    assert run.classify_environment(resource, {})[0] == expected


def test_source_explains_the_decision() -> None:
    assert run.classify_environment(az('Shop-NG-A', 'vnet-core'), {})[1] == 'resource group name Shop-NG-A (suffix -A)'
    assert run.classify_environment(az('rg', 'vm1', Environment='Development'), {})[1] == 'tag Environment=Development on the resource'


@pytest.mark.parametrize('override,resource,expected', [
    ('Production', az('Shop-NG-A', 'shoppf-acc-vm'), 'production'),
    ('DEV', az('rg', 'vm1'), 'development'),
    ('Shop-NG-A=acceptance, Shop-NG-P=production', az('Shop-NG-A', 'vm1'), 'acceptance'),
    ('Shop-NG-A=acceptance, Shop-NG-P=production', az('shop-ng-p', 'vm1'), 'production'),
    ('*-dev-*=development', az('rg', 'shop-dev-vm1'), 'development'),
    # Onboarding workflows pass matrix labels: unrecognised ones don't switch off detection
    ('MAIN', az('Shop-NG-A', 'vm1'), 'acceptance'),
    ('MAIN', az('Shop-NG-P', 'vm1'), 'production'),
    ('Shop-NG-A=blue', az('Shop-NG-A', 'vm1'), 'acceptance'),
    # No mapping matches: detection as usual
    ('Shop-NG-A=acceptance', az('Shop-NG-S', 'registry'), 'unknown'),
])
def test_environment_name_input(override: str, resource: Dict[str, Any], expected: str) -> None:
    assert run.classify_environment(resource, {'environment_name': override})[0] == expected


class FakeGraph:
    def __init__(self, rows: List[Dict[str, Any]]) -> None:
        self.rows = rows

    def resources(self, request: Any) -> Any:
        return SimpleNamespace(data=self.rows, skip_token=None)


def test_resource_group_tags(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [{'name': 'platform-core', 'tags': {'Environment': 'Test'}}, {'name': 'billing', 'tags': {'env': 'prod'}}]
    assert run._azure_resource_group_tags(SUB, client=FakeGraph(rows)) == {
        'platform-core': {'Environment': 'Test'}, 'billing': {'env': 'prod'}}

    monkeypatch.setattr(run, 'LOOKUP_RESOURCE_GROUP_TAGS', True)
    monkeypatch.setattr(run, '_RESOURCE_GROUP_TAGS', {SUB.lower(): {'platform-core': {'Environment': 'Test'}}})
    env, source = run.classify_environment(az('Platform-Core', 'vm1'), {})
    assert (env, source) == ('test', 'tag Environment=Test on resource group Platform-Core')


def test_resource_group_tags_not_looked_up_outside_a_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: Any, **k: Any) -> None:
        raise AssertionError('no Azure calls in unit tests')
    monkeypatch.setattr(run, '_azure_resource_group_tags', boom)
    assert run.classify_environment(az('rg', 'vm1'), {})[0] == 'unknown'


def test_findings_carry_environment() -> None:
    finding = run.convert_resource_to_finding('leftsize-idle-vm', az('Shop-NG-A', 'shoppf-acc-vm'), {'cloud_provider': 'azure'}, 'azure.vm')
    assert finding['metadata']['environment'] == 'acceptance'
    assert finding['metadata']['environmentSource'] == 'resource name shoppf-acc-vm'
    assert 'environmentOverride' not in finding['metadata']


def test_non_production_post_filter_never_keeps_production() -> None:
    resources = [az('Shop-NG-A', 'a'), az('Shop-NG-P', 'p'), az('Shop-NG-S', 's'), az('rg', 'x', env='dev')]
    kept = run.POLICY_POST_FILTERS['leftsize-aks-dev-clusters-always-running'](resources, {})
    assert [r['name'] for r in kept] == ['a', 'x']


def test_lookups_use_custodians_azure_session(monkeypatch: pytest.MonkeyPatch) -> None:
    import c7n_azure.session as session

    created: List[Any] = []

    class FakeSession:
        def __init__(self, subscription_id: Optional[str] = None, **kwargs: Any) -> None:
            created.append(subscription_id)

        def client(self, name: str) -> Any:
            assert name == 'azure.mgmt.resourcegraph.ResourceGraphClient'
            return FakeGraph([])

    monkeypatch.setattr(session, 'Session', FakeSession)
    assert run._azure_resource_group_tags(SUB) == {}
    assert run._azure_shutdown_schedule_targets(SUB) == set()
    assert created == [SUB, SUB]


ALIAS = lambda alias: {'targets': {'aws': {'account_alias': alias}}}  # noqa: E731


@pytest.mark.parametrize('label,resource,config,expected', [
    ('unnamed Lambda in the acc account', {'FunctionName': 'bag-search-api-jwt-authorizer'}, ALIAS('flux-acc'), 'acceptance'),
    ('EBS volume with only an ID', {'VolumeId': 'vol-0a396600e68e5c416'}, ALIAS('flux-model-dev'), 'development'),
    ('prod account', {'FunctionName': 'authorizer'}, ALIAS('flux-prod'), 'production'),
    ('resource name beats the account for non-prod', aws('orders-test-worker'), ALIAS('flux-acc'), 'test'),
    ('production name in a dev account stays production', aws('orders-prod-worker'), ALIAS('flux-dev'), 'production'),
    ('production account beats a dev name', aws('orders-dev-worker'), ALIAS('flux-prod'), 'production'),
    ('alias without an environment', {'FunctionName': 'authorizer'}, ALIAS('flux-main'), 'unknown'),
], ids=lambda x: x if isinstance(x, str) else '')
def test_aws_account_alias(label: str, resource: Dict[str, Any], config: Dict[str, Any], expected: str) -> None:
    assert run.classify_environment(resource, config)[0] == expected


def test_account_alias_source() -> None:
    assert run.classify_environment({'FunctionName': 'authorizer'}, ALIAS('flux-acc')) == ('acceptance', 'AWS account alias flux-acc')


class FakeIAM:
    def __init__(self, aliases: List[str], fail: bool = False) -> None:
        self.aliases, self.fail = aliases, fail

    def list_account_aliases(self) -> Dict[str, Any]:
        if self.fail:
            raise RuntimeError('AccessDenied')
        return {'AccountAliases': self.aliases}


@pytest.mark.parametrize('aliases,fail,expected', [(['flux-acc'], False, 'flux-acc'), ([], False, None), (['x'], True, None)])
def test_get_aws_account_alias(aliases: List[str], fail: bool, expected: Optional[str]) -> None:
    session = SimpleNamespace(client=lambda service: FakeIAM(aliases, fail))
    assert run.get_aws_account_alias(session) == expected


def test_azure_subscription_name_and_tags(monkeypatch: pytest.MonkeyPatch) -> None:
    info = run._azure_subscription_info(SUB, client=FakeGraph([{'name': 'shop-acc', 'tags': {'costcenter': '42'}}]))
    assert info == {'name': 'shop-acc', 'tags': {'costcenter': '42'}}

    monkeypatch.setattr(run, 'LOOKUP_RESOURCE_GROUP_TAGS', True)
    monkeypatch.setattr(run, '_RESOURCE_GROUP_TAGS', {SUB.lower(): {}})
    monkeypatch.setattr(run, '_SUBSCRIPTIONS', {SUB.lower(): info})
    assert run.classify_environment(az('platform', 'vm1'), {}) == ('acceptance', 'subscription name shop-acc')
    # A resource's own name still wins for non-prod, and production always wins
    assert run.classify_environment(az('platform', 'vm1-test'), {})[0] == 'test'
    monkeypatch.setattr(run, '_SUBSCRIPTIONS', {SUB.lower(): {'name': 'Shop', 'tags': {'Environment': 'Production'}}})
    assert run.classify_environment(az('platform', 'vm1-test'), {}) == ('production', 'tag Environment=Production on subscription Shop')
