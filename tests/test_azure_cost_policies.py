"""
Runs the Azure cost and AKS policies through Cloud Custodian's real filter chain.
Only the Azure API calls are stubbed: metric values come from the test
resource's `_metrics` (the real `no_data_action` handling is kept), and the VM
instance view is pre-filled as `instanceView`, which the instance-view filter
then uses instead of calling the API.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest
import yaml

from c7n.config import Config
from c7n.policy import Policy
from c7n.resources import load_resources

load_resources(('azure.*',))
from c7n_azure.filters import MetricFilter  # noqa: E402

POLICIES_DIR = Path(__file__).parent.parent / 'policies'
DOCS: Dict[str, Dict[str, Any]] = {}
for _file in ('azure-cost-optimization.yml', 'azure-aks-optimization.yml'):
    DOCS.update({p['name']: p for p in yaml.safe_load((POLICIES_DIR / _file).read_text())['policies']})


@pytest.fixture(autouse=True)
def fake_metrics(monkeypatch: pytest.MonkeyPatch) -> None:
    def get_metric_data(self: MetricFilter, resource: Dict[str, Any]) -> Optional[List[Optional[float]]]:
        # Mirrors MetricFilter.get_metric_data after the API call
        m = resource.get('_metrics', {}).get(self.metric)
        if self.no_data_action == 'to_zero':
            m = [0] if m is None else [0 if v is None else v for v in m]
        return m

    def process(self: MetricFilter, resources: List[Dict[str, Any]], event: Any = None) -> List[Dict[str, Any]]:
        return [r for r in resources if self.passes_op_filter(r)]

    monkeypatch.setattr(MetricFilter, 'get_metric_data', get_metric_data)
    monkeypatch.setattr(MetricFilter, 'process', process)


def matches(name: str, resource: Dict[str, Any]) -> bool:
    manager = Policy(DOCS[name], Config.empty(region='westeurope')).resource_manager
    manager.get_client = lambda *a, **k: None
    base = {'id': '/subscriptions/s/resourceGroups/rg/providers/X/y/r1', 'name': 'r1',
            'resourceGroup': 'rg', 'location': 'westeurope'}
    return bool(manager.filter_resources([dict(base, **resource)]))


def ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def view(power: str, provisioned_days_ago: int = 60) -> Dict[str, Any]:
    return {'statuses': [{'code': 'ProvisioningState/succeeded', 'time': ago(provisioned_days_ago)},
                         {'code': f'PowerState/{power}'}]}


def vm(size: str = 'Standard_D4s_v5', os: str = 'Linux', power: str = 'running', **extra: Any) -> Dict[str, Any]:
    props = {'hardwareProfile': {'vmSize': size}, 'storageProfile': {'osDisk': {'osType': os}}}
    props.update(extra.pop('props', {}))
    return dict({'properties': props, 'instanceView': view(power)}, **extra)


def asp(tier: str, sites: int, name: str = 'P1v3', **extra: Any) -> Dict[str, Any]:
    return dict({'sku': {'tier': tier, 'name': name}, 'properties': {'numberOfSites': sites}}, **extra)


def pip(**props: Any) -> Dict[str, Any]:
    return {'properties': dict({'publicIPAllocationMethod': 'Static'}, **props)}


def lb(*pools: Dict[str, Any], **tags: str) -> Dict[str, Any]:
    return {'properties': {'backendAddressPools': [{'properties': p} for p in pools]}, 'tags': tags}


def appgw(*pools: Dict[str, Any], state: str = 'Running') -> Dict[str, Any]:
    return {'properties': {'provisioningState': 'Succeeded', 'operationalState': state,
                           'backendAddressPools': [{'properties': p} for p in pools]}}


def disk(state: str, created_days: int = 60, size: int = 256, **props: Any) -> Dict[str, Any]:
    return {'sku': {'name': 'Premium_LRS'},
            'properties': dict({'diskState': state, 'timeCreated': ago(created_days), 'diskSizeGB': size}, **props)}


def sqldb(tier: str, sku: str, **props: Any) -> Dict[str, Any]:
    return {'sku': {'tier': tier, 'name': sku},
            'properties': dict({'status': 'Online', 'creationDate': ago(60)}, **props)}


def aks(*pools: Dict[str, Any], power: str = 'Running', **tags: str) -> Dict[str, Any]:
    return {'properties': {'powerState': {'code': power}, 'agentPoolProfiles': list(pools)}, 'tags': tags}


IDLE_CPU = {'Percentage CPU': [1.0, 2.0, 1.5]}
NAT = {'id': '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/natGateways/n'}

CASES: Dict[str, List[Tuple[str, Dict[str, Any], bool]]] = {
 'leftsize-idle-vm': [
   ('running, CPU 1-2%', vm(_metrics=IDLE_CPU), True),
   ('running, CPU 40%', vm(_metrics={'Percentage CPU': [40.0]}), False),
   ('deallocated, CPU 0%', vm(power='deallocated', _metrics=IDLE_CPU), False),
   ('no metric data', vm(), False),
 ],
 'leftsize-idle-app-service-plan-no-apps': [
   ('empty Premium v3 plan', asp('PremiumV3', 0), True),
   ('plan with apps', asp('PremiumV3', 2), False),
   ('empty Free plan', asp('Free', 0, 'F1'), False),
   ('empty Consumption plan', asp('Dynamic', 0, 'Y1'), False),
   ('empty Flex Consumption plan', asp('FlexConsumption', 0, 'FC1'), False),
 ],
 'leftsize-idle-app-service-plan': [
   ('low CPU and memory', asp('Standard', 1, 'S1', _metrics={'CpuPercentage': [3.0], 'MemoryPercentage': [20.0]}), True),
   ('busy CPU', asp('Standard', 1, 'S1', _metrics={'CpuPercentage': [60.0], 'MemoryPercentage': [20.0]}), False),
   ('empty plan (other rule)', asp('Standard', 0, 'S1', _metrics={'CpuPercentage': [0.0], 'MemoryPercentage': [0.0]}), False),
 ],
 'leftsize-outdated-app-service-plan': [
   ('S1 with apps', asp('Standard', 2, 'S1'), True),
   ('B2 with apps', asp('Basic', 1, 'B2'), True),
   ('F1 with apps', asp('Free', 1, 'F1'), False),
   ('P1v3 with apps', asp('PremiumV3', 1, 'P1v3'), False),
   ('S1 without apps', asp('Standard', 0, 'S1'), False),
 ],
 'leftsize-unattached-disk': [
   ('data disk unattached 30 days', disk('Unattached', 30), True),
   ('created 2 days ago', disk('Unattached', 2), False),
   ('OS disk', disk('Unattached', 30, osType='Linux'), False),
   ('attached', disk('Attached', 30), False),
 ],
 'leftsize-unused-public-ip': [
   ('static, no association', pip(), True),
   ('attached to a NIC', pip(ipConfiguration={'id': 'x'}), False),
   ('used by a NAT gateway', pip(natGateway=NAT), False),
   ('linked to a cross-region LB IP', pip(linkedPublicIPAddress={'id': 'x'}), False),
   ('dynamic, no association', pip(publicIPAllocationMethod='Dynamic'), False),
 ],
 'leftsize-inactive-azure-load-balancer': [
   ('no pools', lb(), True),
   ('one empty pool', lb({}), True),
   ('NIC-based member', lb({'backendIPConfigurations': [{'id': 'x'}]}), False),
   ('IP-based member', lb({'loadBalancerBackendAddresses': [{'name': 'a'}]}), False),
   ('empty but tagged Production', lb({}, Environment='Production'), False),
 ],
 'leftsize-hybrid-benefit-missing': [
   ('Windows, no license type', vm(os='Windows'), True),
   ('Windows, licenseType None', vm(os='Windows', props={'licenseType': 'None'}), True),
   ('Windows_Server', vm(os='Windows', props={'licenseType': 'Windows_Server'}), False),
   ('Linux', vm(os='Linux'), False),
   ('Windows, deallocated', vm(os='Windows', power='deallocated'), False),
 ],
 'leftsize-vm-scheduled-shutdown-missing': [
   ('running, Environment=Dev', vm(tags={'Environment': 'Dev'}), True),
   ('running, Env=staging', vm(tags={'Env': 'staging'}), True),
   ('running, environment=production', vm(tags={'environment': 'production'}), False),
   ('deallocated dev VM', vm(power='deallocated', tags={'env': 'dev'}), False),
   ('no tags', vm(), False),
 ],
 'leftsize-orphaned-snapshots': [
   ('45 days old', {'properties': {'timeCreated': ago(45)}}, True),
   ('10 days old', {'properties': {'timeCreated': ago(10)}}, False),
   # Tags seen on AKS CSI driver snapshots in a real subscription
   ('45 days old, made by the AKS CSI driver', {'properties': {'timeCreated': ago(45)},
                                                 'tags': {'k8s-azure-created-by': 'kubernetes-azure-dd',
                                                          'source_volume_id': '/subscriptions/s/x/disks/pvc-1'}}, False),
   ('45 days old, other tags', {'properties': {'timeCreated': ago(45)}, 'tags': {'owner': 'team-a'}}, True),
 ],
 'leftsize-storage-suboptimal-tier': [
   ('Hot GPv2, 5 transactions', {'kind': 'StorageV2', 'properties': {'accessTier': 'Hot', 'creationTime': ago(200)},
                                 '_metrics': {'Transactions': [1.0, 4.0]}}, True),
   ('Hot GPv2, busy', {'kind': 'StorageV2', 'properties': {'accessTier': 'Hot', 'creationTime': ago(200)},
                       '_metrics': {'Transactions': [5000.0]}}, False),
   ('Cool GPv2, idle', {'kind': 'StorageV2', 'properties': {'accessTier': 'Cool', 'creationTime': ago(200)},
                        '_metrics': {'Transactions': [0.0]}}, False),
   ('Hot GPv2, 30 days old', {'kind': 'StorageV2', 'properties': {'accessTier': 'Hot', 'creationTime': ago(30)},
                              '_metrics': {'Transactions': [0.0]}}, False),
 ],
 'leftsize-vm-arm-architecture': [
   ('Linux D4s_v5', vm('Standard_D4s_v5'), True),
   ('Linux E8as_v4', vm('Standard_E8as_v4'), True),
   ('Linux D2_v3', vm('Standard_D2_v3'), True),
   ('Arm D4ps_v5', vm('Standard_D4ps_v5'), False),
   ('Arm E8pds_v5', vm('Standard_E8pds_v5'), False),
   ('Windows D4s_v5', vm('Standard_D4s_v5', os='Windows'), False),
   ('B2s', vm('Standard_B2s'), False),
   ('deallocated D4s_v5', vm('Standard_D4s_v5', power='deallocated'), False),
 ],
 'leftsize-sql-business-critical-nonprod': [
   ('BC tagged Environment=Test', dict(sqldb('BusinessCritical', 'BC_Gen5_4'), tags={'Environment': 'Test'}), True),
   ('BC tagged env=prod', dict(sqldb('BusinessCritical', 'BC_Gen5_4'), tags={'env': 'prod'}), False),
   ('GP tagged dev', dict(sqldb('GeneralPurpose', 'GP_Gen5_4'), tags={'env': 'dev'}), False),
 ],
 'leftsize-stopped-vm-storage-costs': [
   ('deallocated 60 days', vm(power='deallocated'), True),
   ('deallocated 3 days', dict(vm(), instanceView=view('deallocated', 3)), False),
   ('running', vm(), False),
 ],
 # ARM sku for DTU databases: tier + capacity (DTUs); name is 'S3' or 'Standard' (Databases - Get docs)
 'leftsize-sql-database-dtu-model': [
   ('Standard S3 (100 DTU)', {'sku': {'name': 'S3', 'tier': 'Standard', 'capacity': 100}, 'properties': {}}, True),
   ('Standard S6, name "Standard"', {'sku': {'name': 'Standard', 'tier': 'Standard', 'capacity': 400}, 'properties': {}}, True),
   ('Premium P1', {'sku': {'name': 'P1', 'tier': 'Premium', 'capacity': 125}, 'properties': {}}, True),
   ('Standard S2 (50 DTU)', {'sku': {'name': 'S2', 'tier': 'Standard', 'capacity': 50}, 'properties': {}}, False),
   ('Standard S0', {'sku': {'name': 'S0', 'tier': 'Standard', 'capacity': 10}, 'properties': {}}, False),
   ('Basic', {'sku': {'name': 'Basic', 'tier': 'Basic', 'capacity': 5}, 'properties': {}}, False),
   ('vCore General Purpose', {'sku': {'name': 'GP_Gen5', 'tier': 'GeneralPurpose', 'capacity': 2}, 'properties': {}}, False),
   ('Premium in an elastic pool', {'sku': {'name': 'ElasticPool', 'tier': 'Premium', 'capacity': 0},
                                   'properties': {'elasticPoolId': '/x/elasticPools/p'}}, False),
   ('master', {'name': 'master', 'sku': {'name': 'System', 'tier': 'Standard', 'capacity': 200}, 'properties': {}}, False),
 ],
 'leftsize-overprovisioned-aks-nodes': [
   ('CPU 8%, memory 25%', dict(aks({'name': 'np1'}), _metrics={'node_cpu_usage_percentage': [8.0, 9.0],
                                                             'node_memory_working_set_percentage': [25.0, 30.0]}), True),
   ('CPU 8%, memory 70%', dict(aks({'name': 'np1'}), _metrics={'node_cpu_usage_percentage': [8.0],
                                                             'node_memory_working_set_percentage': [70.0]}), False),
   ('CPU 45%, memory 25%', dict(aks({'name': 'np1'}), _metrics={'node_cpu_usage_percentage': [45.0],
                                                              'node_memory_working_set_percentage': [25.0]}), False),
   ('no metric data', aks({'name': 'np1'}), False),
   ('stopped cluster', dict(aks({'name': 'np1'}, power='Stopped'), _metrics={'node_cpu_usage_percentage': [1.0],
                                                                           'node_memory_working_set_percentage': [5.0]}), False),
 ],
 'leftsize-sql-elastic-pool-empty': [
   ('pool, no data points', {'type': 'Microsoft.Sql/servers/elasticPools'}, True),
   ('pool, 0 bytes allocated', {'type': 'Microsoft.Sql/servers/elasticPools', '_metrics': {'allocated_data_storage': [0, None]}}, True),
   ('pool with databases', {'type': 'Microsoft.Sql/servers/elasticPools', '_metrics': {'allocated_data_storage': [0, 5.0e9]}}, False),
   ('not a pool', {'type': 'Microsoft.Sql/servers/databases'}, False),
 ],
 'leftsize-sql-hybrid-benefit-missing': [
   ('GP provisioned, LicenseIncluded', sqldb('GeneralPurpose', 'GP_Gen5_4', licenseType='LicenseIncluded'), True),
   ('BC provisioned, no licenseType', sqldb('BusinessCritical', 'BC_Gen5_4'), True),
   ('GP with BasePrice', sqldb('GeneralPurpose', 'GP_Gen5_4', licenseType='BasePrice'), False),
   ('GP serverless', sqldb('GeneralPurpose', 'GP_S_Gen5_2', licenseType='LicenseIncluded'), False),
   ('Hyperscale', sqldb('Hyperscale', 'HS_Gen5_4', licenseType='LicenseIncluded'), False),
   ('GP in an elastic pool', sqldb('GeneralPurpose', 'ElasticPool', elasticPoolId='/x/elasticPools/p'), False),
   ('DTU Standard', sqldb('Standard', 'S2'), False),
 ],
 'leftsize-acr-no-lifecycle-policy': [
   ('Premium, retention disabled', {'sku': {'tier': 'Premium'}, 'properties': {'policies': {'retentionPolicy': {'status': 'disabled', 'days': 7}}}}, True),
   ('Premium, no policies returned', {'sku': {'tier': 'Premium'}, 'properties': {}}, True),
   ('Premium, retention enabled', {'sku': {'tier': 'Premium'}, 'properties': {'policies': {'retentionPolicy': {'status': 'enabled', 'days': 7}}}}, False),
   ('Standard (retention not available)', {'sku': {'tier': 'Standard'}, 'properties': {'policies': {'retentionPolicy': {'status': 'disabled'}}}}, False),
 ],
 'leftsize-app-gateway-idle': [
   ('one empty pool', appgw({'backendAddresses': []}), True),
   ('two empty pools', appgw({'backendAddresses': []}, {}), True),
   ('pool with an FQDN target', appgw({'backendAddresses': [{'fqdn': 'app.example.com'}]}), False),
   ('pool with a NIC target', appgw({'backendIPConfigurations': [{'id': 'x'}]}), False),
   ('empty pool but gateway stopped', appgw({'backendAddresses': []}, state='Stopped'), False),
 ],
 'leftsize-redis-cache-underutilized': [
   ('memory 5%', {'properties': {'provisioningState': 'Succeeded'}, '_metrics': {'usedmemorypercentage': [5.0]}}, True),
   ('memory 70%', {'properties': {'provisioningState': 'Succeeded'}, '_metrics': {'usedmemorypercentage': [70.0]}}, False),
 ],
 'leftsize-disk-attached-to-deallocated-vm': [
   ('Reserved, deallocated 30 days ago', disk('Reserved', LastOwnershipUpdateTime=ago(30)), True),
   ('Reserved, no ownership time, old disk', disk('Reserved', 90), True),
   ('Reserved, deallocated last night', disk('Reserved', LastOwnershipUpdateTime=ago(0)), False),
   ('Attached to a running VM', disk('Attached', LastOwnershipUpdateTime=ago(30)), False),
   ('Unattached', disk('Unattached', LastOwnershipUpdateTime=ago(30)), False),
 ],
 'leftsize-azure-sql-overprovisioned': [
   ('DTU S3 at 5%', dict(sqldb('Standard', 'S3'), _metrics={'dtu_consumption_percent': [5.0]}), True),
   ('DTU S3 at 70%', dict(sqldb('Standard', 'S3'), _metrics={'dtu_consumption_percent': [70.0]}), False),
   ('vCore DB (no DTU metric)', sqldb('GeneralPurpose', 'GP_Gen5_4'), False),
   ('pooled DB', dict(sqldb('Standard', 'ElasticPool', elasticPoolId='/x/p'), _metrics={'dtu_consumption_percent': [1.0]}), False),
   ('master', dict(sqldb('Standard', 'S0'), name='master', _metrics={'dtu_consumption_percent': [1.0]}), False),
 ],
 'leftsize-cosmos-overprovisioned-throughput': [
   ('provisioned, 10%', {'properties': {'provisioningState': 'Succeeded', 'capabilities': []}, '_metrics': {'NormalizedRUConsumption': [10.0]}}, True),
   ('provisioned, 80%', {'properties': {'provisioningState': 'Succeeded'}, '_metrics': {'NormalizedRUConsumption': [80.0]}}, False),
   ('serverless', {'properties': {'provisioningState': 'Succeeded', 'capabilities': [{'name': 'EnableServerless'}]},
                   '_metrics': {'NormalizedRUConsumption': [1.0]}}, False),
 ],
 'leftsize-vm-regional-price-increase-2027': [
   ('D4s_v5 in westeurope', vm('Standard_D4s_v5'), True),
   ('D4as_v7 (AMD v7) in northeurope', dict(vm('Standard_D4as_v7'), location='northeurope'), True),
   ('D4s_v7 (Intel v7, excluded)', vm('Standard_D4s_v7'), False),
   ('DS2_v2 (excluded)', vm('Standard_DS2_v2'), False),
   ('D4s_v5 in eastus', dict(vm('Standard_D4s_v5'), location='eastus'), False),
   ('D4s_v5 deallocated', vm('Standard_D4s_v5', power='deallocated'), False),
 ],
 'leftsize-storage-regional-price-increase-2027': [
   ('StorageV2 in francecentral', {'kind': 'StorageV2', 'location': 'francecentral'}, True),
   ('GPv1 in westeurope', {'kind': 'Storage'}, False),
   ('StorageV2 in eastus', {'kind': 'StorageV2', 'location': 'eastus'}, False),
 ],
 'leftsize-bastion-idle': [
   ('Standard, no sessions (no data)', {'sku': {'name': 'Standard'}, 'properties': {'provisioningState': 'Succeeded'}}, True),
   ('Basic, sessions', {'sku': {'name': 'Basic'}, 'properties': {'provisioningState': 'Succeeded'}, '_metrics': {'sessions': [0, 3.0]}}, False),
   ('Developer (free)', {'sku': {'name': 'Developer'}, 'properties': {'provisioningState': 'Succeeded'}}, False),
 ],
 'leftsize-storage-sftp-enabled': [
   ('SFTP on', {'properties': {'isSftpEnabled': True}}, True),
   ('SFTP off', {'properties': {'isSftpEnabled': False}}, False),
   ('not returned', {'properties': {}}, False),
 ],
 'leftsize-aks-cluster-autoscaler-disabled': [
   ('one pool, 3 nodes, no autoscaler', aks({'count': 3, 'enableAutoScaling': False}), True),
   ('two pools 2+2 nodes, flag unset', aks({'count': 2}, {'count': 2}), True),
   ('autoscaler on every pool', aks({'count': 3, 'enableAutoScaling': True}), False),
   ('autoscaler on one of two pools', aks({'count': 3, 'enableAutoScaling': True}, {'count': 3}), False),
   ('2 nodes total', aks({'count': 2, 'enableAutoScaling': False}), False),
   ('stopped cluster', aks({'count': 5}, power='Stopped'), False),
 ],
 'leftsize-aks-using-expensive-vm-sizes': [
   ('D8s_v3 pool', aks({'vmSize': 'Standard_D8s_v3'}), True),
   ('second pool on E16s_v3', aks({'vmSize': 'Standard_D4s_v5'}, {'vmSize': 'Standard_E16s_v3'}), True),
   ('D4s_v5 only', aks({'vmSize': 'Standard_D4s_v5'}), False),
 ],
 'leftsize-aks-dev-clusters-always-running': [
   ('running, Environment=Dev', aks({'count': 1}, Environment='Dev'), True),
   ('running, prod', aks({'count': 1}, env='prod'), False),
   ('stopped dev', aks({'count': 1}, power='Stopped', env='dev'), False),
 ],
}


@pytest.mark.parametrize(
    'name,label,resource,expected',
    [(name, label, res, want) for name, cs in CASES.items() for label, res, want in cs],
    ids=[f'{name.replace("leftsize-", "")}: {label}' for name, cs in CASES.items() for label, _, _ in cs],
)
def test_azure_cost_policy(name: str, label: str, resource: Dict[str, Any], expected: bool) -> None:
    assert matches(name, resource) is expected
