"""
Runs the Azure deprecation policies through Cloud Custodian's real filter chain.

Only the Azure API calls are stubbed:
- `instance-view` (VM power state): a fake compute client returns the
  instance view for the VM, as `virtual_machines.get(..., expand='instanceview')`.
- `configuration` (web app site config): a fake web client returns the
  site config, as `web_apps.get_configuration(...)`.
Resource dicts use the shape c7n produces (SDK model `serialize(True)`).
"""

from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

import pytest
import yaml

from c7n.config import Config
from c7n.policy import Policy
from c7n.resources import load_resources

load_resources(('azure.*',))

POLICY_FILE = Path(__file__).parent.parent / 'policies' / 'azure-deprecations.yml'
DOCS = {p['name']: p for p in yaml.safe_load(POLICY_FILE.read_text())['policies']}


class _Serializable:
    def __init__(self, data: Dict[str, Any]) -> None:
        self._data = data

    def serialize(self, keep_readonly: bool = False) -> Dict[str, Any]:
        return self._data


class FakeClient:
    """Answers the per-resource calls made by instance-view and configuration filters."""

    def __init__(self, resource: Dict[str, Any]) -> None:
        self.calls: List[str] = []
        power: Optional[str] = resource.get('_power')
        site_config: Dict[str, Any] = resource.get('_site_config', {})
        statuses = [{'code': 'ProvisioningState/succeeded'}]
        if power:
            statuses.append({'code': f'PowerState/{power}'})

        def vm_get(rg: str, name: str, expand: Optional[str] = None) -> Any:
            assert expand == 'instanceview'
            self.calls.append('instance-view')
            return SimpleNamespace(instance_view=_Serializable({'statuses': statuses}))

        def get_configuration(rg: str, name: str) -> Any:
            self.calls.append('configuration')
            return _Serializable({'properties': site_config})

        self.virtual_machines = SimpleNamespace(get=vm_get)
        self.web_apps = SimpleNamespace(get_configuration=get_configuration)


def matches(name: str, resource: Dict[str, Any]) -> bool:
    manager = Policy(DOCS[name], Config.empty(region='westeurope')).resource_manager
    full = dict(resource)
    full.setdefault('id', '/subscriptions/s/resourceGroups/rg/providers/X/y/r1')
    full.setdefault('name', 'r1')
    full.setdefault('resourceGroup', 'rg')
    client = FakeClient(full)
    manager.get_client = lambda *a, **k: client
    for f in manager.filters:
        f.manager.get_client = lambda *a, **k: client
    return bool(manager.filter_resources([full]))


# ---------- builders ----------

def vm(size: str, power: Optional[str] = 'running', **props: Any) -> Dict[str, Any]:
    properties: Dict[str, Any] = {'hardwareProfile': {'vmSize': size},
                                  'storageProfile': {'osDisk': {'managedDisk': {'id': 'd'}}, 'dataDisks': []}}
    properties.update(props)
    return {'type': 'Microsoft.Compute/virtualMachines', 'properties': properties, '_power': power}


def vmss(size: str, name: str = 'web-vmss', tags: Any = None) -> Dict[str, Any]:
    r: Dict[str, Any] = {'name': name, 'sku': {'name': size, 'tier': 'Standard', 'capacity': 2},
                         'properties': {'provisioningState': 'Succeeded'}}
    if tags is not None:
        r['tags'] = tags
    return r


def aks(version: str = '1.35.1', state: str = 'Succeeded', **pool: Any) -> Dict[str, Any]:
    p = {'name': 'nodepool1', 'vmSize': 'Standard_D4s_v5', 'orchestratorVersion': version,
         'nodeImageVersion': 'AKSUbuntu-2404gen2containerd-202610.01.0', 'osType': 'Linux', 'osSKU': 'Ubuntu'}
    p.update(pool)
    return {'properties': {'provisioningState': state, 'kubernetesVersion': version,
                           'agentPoolProfiles': [p],
                           'networkProfile': {'networkPlugin': 'azure'}, 'addonProfiles': {}}}


def funcapp(fx: str, kind: str = 'functionapp,linux') -> Dict[str, Any]:
    return {'kind': kind, 'properties': {}, '_site_config': {'linuxFxVersion': fx}}


CASES: Dict[str, List[Tuple[str, Dict[str, Any], bool]]] = {
 'leftsize-nvv4-series-retirement': [
   ('NVv4 running', vm('Standard_NV8as_v4'), True),
   ('NVv3 deallocated (flagged on purpose)', vm('Standard_NV12s_v3', power='deallocated'), True),
   ('lower-case size from API', vm('standard_nv32ahs_v4'), True),
   ('NVadsA10_v5 replacement', vm('Standard_NV36ads_A10_v5'), False),
   ('NVv2-style size not in list', vm('Standard_NV6'), False),
 ],
 'leftsize-functions-linux-consumption-retirement': [
   ('Linux Y1 plan with kind linux', {'kind': 'functionapp,linux', 'sku': {'name': 'Y1'}, 'properties': {'reserved': True, 'numberOfSites': 2}}, True),
   ('Y1 plan, no kind, reserved true (Bicep sample)', {'kind': '', 'sku': {'name': 'Y1'}, 'properties': {'reserved': True, 'numberOfSites': 1}}, True),
   ('Windows Y1 plan', {'kind': 'functionapp', 'sku': {'name': 'Y1'}, 'properties': {'reserved': False, 'numberOfSites': 1}}, False),
   ('empty Linux Y1 plan', {'kind': 'functionapp,linux', 'sku': {'name': 'Y1'}, 'properties': {'reserved': True, 'numberOfSites': 0}}, False),
   ('Flex Consumption FC1', {'kind': 'functionapp,linux', 'sku': {'name': 'FC1'}, 'properties': {'reserved': True, 'numberOfSites': 1}}, False),
 ],
 'leftsize-aks-outdated-version': [
   ('control plane 1.34.2', aks('1.34.2'), True),
   ('control plane 1.29', aks('1.29'), True),
   ('control plane 1.35, node pool lagging on 1.33.1', aks('1.35.1', orchestratorVersion='1.33.1'), True),
   ('everything on 1.35', aks('1.35.0'), False),
   ('1.36 is not matched by the 1.3x prefix', aks('1.36.0'), False),
   ('cluster being deleted', aks('1.30.0', state='Deleting'), False),
 ],
 'leftsize-appgateway-v1-deprecated': [
   ('Standard_Medium', {'properties': {'sku': {'name': 'Standard_Medium', 'tier': 'Standard'}}}, True),
   ('WAF_Large', {'properties': {'sku': {'name': 'WAF_Large', 'tier': 'WAF'}}}, True),
   ('Standard_v2', {'properties': {'sku': {'name': 'Standard_v2', 'tier': 'Standard_v2'}}}, False),
 ],
 'leftsize-hdd-os-disk-retirement': [
   ('Standard HDD OS disk', {'sku': {'name': 'Standard_LRS'}, 'properties': {'osType': 'Linux'}}, True),
   ('Standard HDD data disk (no osType)', {'sku': {'name': 'Standard_LRS'}, 'properties': {}}, False),
   ('Standard SSD OS disk', {'sku': {'name': 'StandardSSD_LRS'}, 'properties': {'osType': 'Windows'}}, False),
 ],
 'leftsize-mariadb-deprecated': [
   ('any MariaDB server', {'properties': {'version': '10.3'}}, True),
 ],
 'leftsize-basic-loadbalancer-deprecated': [
   ('Basic LB', {'sku': {'name': 'Basic'}}, True),
   ('Standard LB', {'sku': {'name': 'Standard'}}, False),
 ],
 'leftsize-unmanaged-disks-retirement': [
   ('unmanaged OS disk', vm('Standard_D2s_v5', storageProfile={'osDisk': {'vhd': {'uri': 'https://sa.blob.core.windows.net/vhds/os.vhd'}}, 'dataDisks': []}), True),
   ('managed OS disk, one unmanaged data disk',
    vm('Standard_D2s_v5', storageProfile={'osDisk': {'managedDisk': {'id': 'd'}},
                                         'dataDisks': [{'lun': 0, 'managedDisk': {'id': 'x'}}, {'lun': 1, 'vhd': {'uri': 'https://sa/vhds/d.vhd'}}]}), True),
   ('managed OS and data disks', vm('Standard_D2s_v5', storageProfile={'osDisk': {'managedDisk': {'id': 'd'}}, 'dataDisks': [{'lun': 0, 'managedDisk': {'id': 'x'}}]}), False),
   ('managed OS disk, dataDisks key absent', vm('Standard_D2s_v5', storageProfile={'osDisk': {'managedDisk': {'id': 'd'}}}), False),
 ],
 'leftsize-storage-legacy-account-retirement': [
   ('GPv1 Standard_LRS', {'kind': 'Storage', 'sku': {'name': 'Standard_LRS'}, 'resourceGroup': 'app-rg'}, True),
   ('legacy BlobStorage Standard_RAGRS', {'kind': 'BlobStorage', 'sku': {'name': 'Standard_RAGRS'}, 'resourceGroup': 'app-rg'}, True),
   ('GPv2', {'kind': 'StorageV2', 'sku': {'name': 'Standard_LRS'}, 'resourceGroup': 'app-rg'}, False),
   ('Premium GPv1 (outside Microsoft inventory query)', {'kind': 'Storage', 'sku': {'name': 'Premium_LRS'}, 'resourceGroup': 'app-rg'}, False),
   ('Databricks DBFS account', {'kind': 'Storage', 'sku': {'name': 'Standard_GRS'}, 'resourceGroup': 'databricks-rg-ws-abc123'}, False),
 ],
 'leftsize-vm-m192i-v2-retirement': [
   ('M192is_v2 running', vm('Standard_M192is_v2'), True),
   ('M192idms_v2 stopped (allocated)', vm('Standard_M192idms_v2', power='stopped'), True),
   ('M192is_v2 deallocated', vm('Standard_M192is_v2', power='deallocated'), False),
   ('M192ms_v2 (not isolated)', vm('Standard_M192ms_v2'), False),
 ],
 'leftsize-vm-hpc-fpga-retirement-2027': [
   ('NP10s', vm('Standard_NP10s'), True),
   ('HC44-16rs', vm('Standard_HC44-16rs'), True),
   ('HB120-32rs_v2', vm('Standard_HB120-32rs_v2'), True),
   ('HB120rs_v3', vm('Standard_HB120rs_v3'), False),
   ('HB120rs_v2 deallocated', vm('Standard_HB120rs_v2', power='deallocated'), False),
 ],
 'leftsize-vm-series-retirement-2028-05': [
   ('D2 (v1)', vm('Standard_D2'), True),
   ('DS12-1_v2', vm('Standard_DS12-1_v2'), True),
   ('D2_v2_Promo', vm('Standard_D2_v2_Promo'), True),
   ('DS2_v2 starting', vm('Standard_DS2_v2', power='starting'), True),
   ('L8s (v1)', vm('Standard_L8s'), True),
   ('D2s_v3 (other group)', vm('Standard_D2s_v3'), False),
   ('L8s_v2 (other group)', vm('Standard_L8s_v2'), False),
   ('L8s_v3', vm('Standard_L8s_v3'), False),
   ('D2ds_v5', vm('Standard_D2ds_v5'), False),
   ('DS2_v2 deallocated', vm('Standard_DS2_v2', power='deallocated'), False),
 ],
 'leftsize-vm-series-retirement-2028-11': [
   ('A2_v2', vm('Standard_A2_v2'), True),
   ('A4m_v2', vm('Standard_A4m_v2'), True),
   ('B1ls', vm('Standard_B1ls'), True),
   ('B2ms', vm('Standard_B2ms'), True),
   ('F4s', vm('Standard_F4s'), True),
   ('F8s_v2', vm('Standard_F8s_v2'), True),
   ('GS4-8', vm('Standard_GS4-8'), True),
   ('L16s_v2', vm('Standard_L16s_v2'), True),
   ('B2s_v2 (Bsv2, not retiring)', vm('Standard_B2s_v2'), False),
   ('B2ts_v2', vm('Standard_B2ts_v2'), False),
   ('F4s_v6', vm('Standard_F4s_v6'), False),
   ('A2 (classic Basic A, not in this group)', vm('Standard_A2'), False),
   ('L8s_v3', vm('Standard_L8s_v3'), False),
 ],
 'leftsize-vm-v3-series-retirement-2029': [
   ('D4s_v3', vm('Standard_D4s_v3'), True),
   ('D2_v3', vm('Standard_D2_v3'), True),
   ('E64is_v3', vm('Standard_E64is_v3'), True),
   ('E16-4s_v3', vm('Standard_E16-4s_v3'), True),
   ('E4_v3 deallocated', vm('Standard_E4_v3', power='deallocated'), False),
   ('E4s_v4', vm('Standard_E4s_v4'), False),
   ('D4as_v4', vm('Standard_D4as_v4'), False),
   ('D2_v2 (other group)', vm('Standard_D2_v2'), False),
 ],
 'leftsize-aks-azure-linux-2-node-pools': [
   ('AzureLinux V2 image', aks(nodeImageVersion='AKSAzureLinux-V2gen2-202512.06.0', osSKU='AzureLinux'), True),
   ('CBL-Mariner V2 image', aks(nodeImageVersion='AKSCBLMariner-V2gen2-202405.03.0', osSKU='CBLMariner'), True),
   ('Azure Linux 3 image', aks(nodeImageVersion='AKSAzureLinux-V3gen2-202610.01.0', osSKU='AzureLinux'), False),
   ('Ubuntu image', aks(), False),
 ],
 'leftsize-aks-ubuntu-2004-node-pools': [
   ('Ubuntu 20.04 CVM image', aks(nodeImageVersion='AKSUbuntu-2004cvmcontainerd-202510.01.0'), True),
   ('Ubuntu 20.04 FIPS image', aks(nodeImageVersion='AKSUbuntu-2004fipscontainerd-202510.01.0'), True),
   ('Ubuntu 22.04 image', aks(nodeImageVersion='AKSUbuntu-2204gen2containerd-202610.01.0'), False),
 ],
 'leftsize-aks-ubuntu-2204-node-pools': [
   ('Ubuntu 22.04 image', aks(nodeImageVersion='AKSUbuntu-2204gen2containerd-202610.01.0'), True),
   ('osSKU pinned to Ubuntu2204', aks(nodeImageVersion='', osSKU='Ubuntu2204'), True),
   ('Ubuntu 24.04 image', aks(), False),
   ('Windows pool', aks(nodeImageVersion='AKSWindows-2022-containerd-20348.4000.251010', osType='Windows', osSKU='Windows2022'), False),
 ],
 'leftsize-aks-windows-unsupported-node-pools': [
   ('Windows Server 2019 image', aks(nodeImageVersion='AKSWindows-2019-containerd-17763.6414.241010', osType='Windows'), True),
   ('Annual Channel 23H2 image', aks(nodeImageVersion='AKSWindows-23H2-gen2-25398.1189.241015', osType='Windows'), True),
   ('osSKU Windows2019 only', aks(nodeImageVersion='', osType='Windows', osSKU='Windows2019'), True),
   ('Windows Server 2022 image', aks(nodeImageVersion='AKSWindows-2022-containerd-20348.4000.251010', osType='Windows', osSKU='Windows2022'), False),
 ],
 'leftsize-aks-kubenet-retirement': [
   ('kubenet', {'properties': {'provisioningState': 'Succeeded', 'networkProfile': {'networkPlugin': 'kubenet'}}}, True),
   ('Azure CNI', {'properties': {'provisioningState': 'Succeeded', 'networkProfile': {'networkPlugin': 'azure'}}}, False),
 ],
 'leftsize-aks-open-service-mesh-retirement': [
   ('OSM enabled', {'properties': {'provisioningState': 'Succeeded', 'addonProfiles': {'openServiceMesh': {'enabled': True, 'config': {}}}}}, True),
   ('OSM disabled', {'properties': {'provisioningState': 'Succeeded', 'addonProfiles': {'openServiceMesh': {'enabled': False}}}}, False),
   ('no add-ons', {'properties': {'provisioningState': 'Succeeded', 'addonProfiles': {}}}, False),
 ],
 'leftsize-functions-dotnet-inprocess-end-of-support': [
   ('in-process DOTNET|8.0', funcapp('DOTNET|8.0'), True),
   ('isolated DOTNET-ISOLATED|8.0', funcapp('DOTNET-ISOLATED|8.0'), False),
   ('Logic App Standard', funcapp('DOTNET|8.0', kind='functionapp,workflowapp,linux'), False),
   ('web app (not a function app)', funcapp('DOTNET|8.0', kind='app,linux'), False),
 ],
 'leftsize-functions-linux-language-end-of-support': [
   ('Python 3.10', funcapp('Python|3.10'), True),
   ('Python 3.9 with image version', funcapp('Python|3.9|2.0'), True),
   ('Node 20', funcapp('Node|20'), True),
   ('PowerShell 7.4', funcapp('PowerShell|7.4'), True),
   ('DOTNET-ISOLATED|9.0', funcapp('DOTNET-ISOLATED|9.0'), True),
   ('Python 3.11', funcapp('Python|3.11'), False),
   ('Python 3.11 with image version', funcapp('Python|3.11|2.0'), False),
   ('Node 22', funcapp('Node|22'), False),
   ('DOTNET-ISOLATED|10.0', funcapp('DOTNET-ISOLATED|10.0'), False),
   ('Java 17', funcapp('Java|17'), False),
   ('Flex Consumption (empty linuxFxVersion)', funcapp(''), False),
 ],
 'leftsize-ai-services-retired': [
   ('LUIS', {'kind': 'LUIS', 'sku': {'name': 'S0'}}, True),
   ('LUIS.Authoring', {'kind': 'LUIS.Authoring', 'sku': {'name': 'F0'}}, True),
   ('QnAMaker', {'kind': 'QnAMaker', 'sku': {'name': 'S0'}}, True),
   ('TextAnalytics (Language)', {'kind': 'TextAnalytics', 'sku': {'name': 'S'}}, False),
 ],
 'leftsize-content-moderator-retirement': [
   ('ContentModerator', {'kind': 'ContentModerator', 'sku': {'name': 'S0'}}, True),
   ('ContentSafety', {'kind': 'ContentSafety', 'sku': {'name': 'S0'}}, False),
 ],
 'leftsize-spring-apps-retirement': [
   ('any Spring Apps instance', {'sku': {'name': 'S0', 'tier': 'Standard'}}, True),
 ],
 'leftsize-cloud-services-extended-support-retirement': [
   ('Microsoft.Compute/cloudServices', {'type': 'Microsoft.Compute/cloudServices'}, True),
   ('other ARM resource', {'type': 'Microsoft.Compute/virtualMachines'}, False),
 ],
 'leftsize-basic-public-ip-retired': [
   ('Basic public IP', {'sku': {'name': 'Basic', 'tier': 'Regional'}}, True),
   ('Standard public IP', {'sku': {'name': 'Standard', 'tier': 'Regional'}}, False),
 ],
 'leftsize-appgateway-waf-config-retirement': [
   ('WAF_v2 with legacy config', {'properties': {'sku': {'name': 'WAF_v2', 'tier': 'WAF_v2'},
                                                'webApplicationFirewallConfiguration': {'enabled': True, 'firewallMode': 'Prevention'}}}, True),
   ('WAF_v2 with WAF policy only', {'properties': {'sku': {'name': 'WAF_v2', 'tier': 'WAF_v2'}, 'firewallPolicy': {'id': 'p'}}}, False),
   ('Standard_v2', {'properties': {'sku': {'name': 'Standard_v2', 'tier': 'Standard_v2'}}}, False),
 ],
 'leftsize-front-door-classic-retirement': [
   ('any classic Front Door', {'properties': {'enabledState': 'Enabled'}}, True),
 ],
 'leftsize-cdn-classic-retirement': [
   ('Standard_Microsoft', {'sku': {'name': 'Standard_Microsoft'}}, True),
   ('Front Door Standard profile', {'sku': {'name': 'Standard_AzureFrontDoor'}}, False),
 ],
 'leftsize-nsg-flow-logs-retirement': [
   ('NSG with flow log', {'properties': {'flowLogs': [{'id': '/subscriptions/s/.../flowLogs/fl1'}]}}, True),
   ('NSG with empty flowLogs list', {'properties': {'flowLogs': []}}, False),
   ('NSG without flowLogs key', {'properties': {}}, False),
 ],
 'leftsize-postgresql-flexible-extended-support': [
   ('PostgreSQL 11', {'properties': {'version': '11'}}, True),
   ('PostgreSQL 14', {'properties': {'version': '14'}}, True),
   ('PostgreSQL 15', {'properties': {'version': '15'}}, False),
   ('PostgreSQL 16', {'properties': {'version': '16'}}, False),
 ],
 'leftsize-mysql-flexible-extended-support': [
   ('MySQL 5.7', {'properties': {'version': '5.7'}}, True),
   ('MySQL 8.0.21', {'properties': {'version': '8.0.21'}}, True),
   ('MySQL 8.4', {'properties': {'version': '8.4'}}, False),
 ],
 'leftsize-redis-enterprise-retirement': [
   ('Enterprise_E10', {'type': 'Microsoft.Cache/redisEnterprise', 'sku': {'name': 'Enterprise_E10', 'capacity': 2}}, True),
   ('EnterpriseFlash_F300', {'type': 'Microsoft.Cache/redisEnterprise', 'sku': {'name': 'EnterpriseFlash_F300', 'capacity': 3}}, True),
   ('Azure Managed Redis Balanced_B5', {'type': 'Microsoft.Cache/redisEnterprise', 'sku': {'name': 'Balanced_B5'}}, False),
   ('redisEnterprise database child type', {'type': 'Microsoft.Cache/redisEnterprise/databases', 'sku': {'name': 'Enterprise_E10'}}, False),
 ],
 'leftsize-redis-cache-retirement': [
   ('any Azure Cache for Redis', {'properties': {'sku': {'name': 'Standard', 'family': 'C', 'capacity': 1}}}, True),
 ],
 'leftsize-hdinsight-retired-version': [
   ('HDInsight 4.0', {'properties': {'clusterVersion': '4.0.3000.1'}}, True),
   ('HDInsight 5.0', {'properties': {'clusterVersion': '5.0.3000.0'}}, True),
   ('HDInsight 5.1', {'properties': {'clusterVersion': '5.1.3000.0'}}, False),
 ],
 'leftsize-vmss-retiring-size': [
   ('DS2_v2 scale set', vmss('Standard_DS2_v2'), True),
   ('D4s_v3 scale set with unrelated tags', vmss('Standard_D4s_v3', tags={'env': 'prod'}), True),
   ('B2ms scale set, empty tags', vmss('Standard_B2ms', tags={}), True),
   ('M192is_v2 scale set', vmss('Standard_M192is_v2'), True),
   ('HB120rs_v2 scale set', vmss('Standard_HB120rs_v2'), True),
   ('current size D4s_v5', vmss('Standard_D4s_v5'), False),
   ('AKS scale set by aks-managed tag', vmss('Standard_DS2_v2', name='custom', tags={'aks-managed-poolName': 'np1'}), False),
   ('AKS scale set by name pattern', vmss('Standard_DS2_v2', name='aks-nodepool1-12345678-vmss'), False),
 ],
 'leftsize-aks-node-pool-retiring-size': [
   ('default DS2_v2 pool', aks(vmSize='Standard_DS2_v2'), True),
   ('D4s_v3 pool', aks(vmSize='Standard_D4s_v3'), True),
   ('B2s pool', aks(vmSize='Standard_B2s'), True),
   ('D4s_v5 pool', aks(), False),
 ],
}


def _params() -> List[Any]:
    return [pytest.param(name, label, res, exp, id=f'{name}: {label}')
            for name, cases in CASES.items() for label, res, exp in cases]


@pytest.mark.parametrize('name,label,resource,expected', _params())
def test_azure_deprecation_policy(name: str, label: str, resource: Dict[str, Any], expected: bool) -> None:
    assert matches(name, resource) is expected


def test_every_rule_has_cases() -> None:
    assert set(CASES) == set(DOCS)


def test_vmss_tags_null() -> None:
    """Scale sets without any tags come back with tags=None from the SDK."""
    r = vmss('Standard_DS2_v2')
    r['tags'] = None
    assert matches('leftsize-vmss-retiring-size', r) is True


def test_instance_view_only_called_for_size_matches() -> None:
    """instance-view runs after the size filter: non-matching VMs cost no extra API call."""
    manager = Policy(DOCS['leftsize-vm-series-retirement-2028-05'], Config.empty(region='westeurope')).resource_manager
    resources = []
    for i, size in enumerate(['Standard_D4s_v5', 'Standard_DS2_v2']):
        r = dict(vm(size), id=f'/subscriptions/s/resourceGroups/rg/providers/X/y/vm{i}', name=f'vm{i}', resourceGroup='rg')
        resources.append(r)
    calls: List[str] = []

    def get_client(*a: Any, **k: Any) -> Any:
        c = FakeClient({'_power': 'running'})
        c.calls = calls
        return c

    for f in manager.filters:
        f.manager.get_client = get_client
    manager.get_client = get_client
    assert [r['name'] for r in manager.filter_resources(resources)] == ['vm1']
    assert calls == ['instance-view']
