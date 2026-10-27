"""
Runs the Azure security policies through Cloud Custodian's real filter chain.
Only the Azure API calls are stubbed: SQL firewall rules come from the test
resource, and web app configuration is pre-filled as `c7n:configuration`.
"""

from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest
import yaml
from netaddr import IPRange, IPSet

from c7n.config import Config
from c7n.policy import Policy
from c7n.resources import load_resources

load_resources(('azure.*',))
from c7n_azure.resources.sqlserver import SqlServerFirewallRulesFilter  # noqa: E402

POLICY_FILE = Path(__file__).parent.parent / 'policies' / 'azure-security.yml'
DOCS = {p['name']: p for p in yaml.safe_load(POLICY_FILE.read_text())['policies']}


@pytest.fixture(autouse=True)
def fake_firewall_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    def query_rules(self: Any, resource: Dict[str, Any]) -> IPSet:
        rules = IPSet()
        for start, end in resource.get('_rules', []):
            rules.add(IPRange(start, end))
        return rules

    monkeypatch.setattr(SqlServerFirewallRulesFilter, '_query_rules', query_rules)


def matches(name: str, resource: Dict[str, Any]) -> bool:
    manager = Policy(DOCS[name], Config.empty(region='westeurope')).resource_manager
    manager.get_client = lambda *a, **k: None
    for f in manager.filters:
        f.manager.get_client = lambda *a, **k: None
    full = dict(resource, id='/subscriptions/s/resourceGroups/rg/providers/X/y/r1', name='r1', resourceGroup='rg')
    return bool(manager.filter_resources([full]))


def nsg(*rules: Tuple[int, str, str, str]) -> Dict[str, Any]:
    """Build an NSG from (priority, access, source, port) inbound TCP rules."""
    return {'properties': {'securityRules': [
        {'name': f'r{prio}', 'properties': {'priority': prio, 'direction': 'Inbound', 'access': access, 'protocol': 'Tcp',
                                           'sourceAddressPrefix': source, 'sourceAddressPrefixes': [], 'sourcePortRange': '*',
                                           'destinationAddressPrefix': '*', 'destinationAddressPrefixes': [], 'destinationPortRange': port, 'destinationPortRanges': []}}
        for prio, access, source, port in rules]}}


CASES: Dict[str, List[Tuple[str, Dict[str, Any], bool]]] = {
 'leftsize-open-network-ports': [
   ('SSH from any source', nsg((100, 'Allow', '*', '22')), True),
   ('RDP from Internet tag', nsg((100, 'Allow', 'Internet', '3389')), True),
   ('all ports from 0.0.0.0/0', nsg((100, 'Allow', '0.0.0.0/0', '*')), True),
   ('port range covering PostgreSQL', nsg((100, 'Allow', '*', '5000-6000')), True),
   ('SSH from office range only', nsg((100, 'Allow', '203.0.113.0/24', '22')), False),
   ('HTTPS from anywhere', nsg((100, 'Allow', '*', '443')), False),
   ('SSH allowed but denied by an earlier rule', nsg((100, 'Deny', '*', '22'), (200, 'Allow', '*', '22')), False),
   ('no custom rules', {'properties': {'securityRules': []}}, False),
 ],
 'leftsize-sql-server-open-to-internet': [
   ('rule 0.0.0.0-255.255.255.255, public access on', {'properties': {'publicNetworkAccess': 'Enabled'}, '_rules': [('0.0.0.0', '255.255.255.255')]}, True),
   ('same rule, publicNetworkAccess not set', {'properties': {}, '_rules': [('0.0.0.0', '255.255.255.255')]}, True),
   ('two halves covering everything', {'properties': {'publicNetworkAccess': 'Enabled'}, '_rules': [('0.0.0.0', '127.255.255.255'), ('128.0.0.0', '255.255.255.255')]}, True),
   ('only "Allow Azure services" 0.0.0.0', {'properties': {'publicNetworkAccess': 'Enabled'}, '_rules': [('0.0.0.0', '0.0.0.0')]}, False),
   ('office range only', {'properties': {'publicNetworkAccess': 'Enabled'}, '_rules': [('203.0.113.0', '203.0.113.255')]}, False),
   ('open rule but public access Disabled', {'properties': {'publicNetworkAccess': 'Disabled'}, '_rules': [('0.0.0.0', '255.255.255.255')]}, False),
 ],
 'leftsize-storage-shared-key-access-enabled': [
   ('allowSharedKeyAccess true', {'properties': {'allowSharedKeyAccess': True}}, True),
   ('allowSharedKeyAccess not set (default allows)', {'properties': {}}, True),
   ('allowSharedKeyAccess false', {'properties': {'allowSharedKeyAccess': False}}, False),
 ],
 'leftsize-keyvault-purge-protection-disabled': [
   ('purge protection not set', {'properties': {'enableSoftDelete': True}}, True),
   ('purge protection false', {'properties': {'enablePurgeProtection': False}}, True),
   ('purge protection true', {'properties': {'enablePurgeProtection': True}}, False),
 ],
 'leftsize-webapp-https-only-disabled': [
   ('httpsOnly false', {'properties': {'httpsOnly': False}}, True),
   ('httpsOnly not set', {'properties': {}}, True),
   ('httpsOnly true', {'properties': {'httpsOnly': True}}, False),
 ],
 'leftsize-webapp-outdated-tls': [
   ('minTlsVersion 1.0', {'properties': {}, 'c7n:configuration': {'minTlsVersion': '1.0'}}, True),
   ('minTlsVersion 1.1', {'properties': {}, 'c7n:configuration': {'minTlsVersion': '1.1'}}, True),
   ('minTlsVersion 1.2', {'properties': {}, 'c7n:configuration': {'minTlsVersion': '1.2'}}, False),
   ('minTlsVersion 1.3', {'properties': {}, 'c7n:configuration': {'minTlsVersion': '1.3'}}, False),
 ],
 'leftsize-anonymous-blob-access': [
   ('allowBlobPublicAccess true', {'properties': {'allowBlobPublicAccess': True}}, True),
   ('allowBlobPublicAccess not set (older accounts allow it)', {'properties': {}}, True),
   ('allowBlobPublicAccess false', {'properties': {'allowBlobPublicAccess': False}}, False),
 ],
 'leftsize-storage-http-allowed': [
   ('HTTPS only off', {'properties': {'supportsHttpsTrafficOnly': False}}, True),
   ('HTTPS only on', {'properties': {'supportsHttpsTrafficOnly': True}}, False),
 ],
 'leftsize-storage-outdated-tls': [
   ('TLS1_0', {'properties': {'minimumTlsVersion': 'TLS1_0'}}, True),
   ('TLS1_1', {'properties': {'minimumTlsVersion': 'TLS1_1'}}, True),
   ('TLS1_2', {'properties': {'minimumTlsVersion': 'TLS1_2'}}, False),
 ],
 'leftsize-storage-public-network-access': [
   ('Enabled + default Allow', {'properties': {'publicNetworkAccess': 'Enabled', 'networkAcls': {'defaultAction': 'Allow'}}}, True),
   ('not set + default Allow', {'properties': {'networkAcls': {'defaultAction': 'Allow'}}}, True),
   ('Enabled + default Deny', {'properties': {'publicNetworkAccess': 'Enabled', 'networkAcls': {'defaultAction': 'Deny'}}}, False),
   ('Disabled', {'properties': {'publicNetworkAccess': 'Disabled', 'networkAcls': {'defaultAction': 'Allow'}}}, False),
   ('SecuredByPerimeter', {'properties': {'publicNetworkAccess': 'SecuredByPerimeter', 'networkAcls': {'defaultAction': 'Allow'}}}, False),
 ],
 'leftsize-unencrypted-disks': [
   ('attached, platform key', {'properties': {'diskState': 'Attached', 'encryption': {'type': 'EncryptionAtRestWithPlatformKey'}}}, True),
   ('attached, customer key', {'properties': {'diskState': 'Attached', 'encryption': {'type': 'EncryptionAtRestWithCustomerKey'}}}, False),
   ('attached, platform and customer keys', {'properties': {'diskState': 'Attached', 'encryption': {'type': 'EncryptionAtRestWithPlatformAndCustomerKeys'}}}, False),
   ('unattached, platform key', {'properties': {'diskState': 'Unattached', 'encryption': {'type': 'EncryptionAtRestWithPlatformKey'}}}, False),
 ],
 'leftsize-defender-for-cloud-disabled': [
   ('Free tier', {'properties': {'pricingTier': 'Free'}}, True),
   ('Standard tier', {'properties': {'pricingTier': 'Standard'}}, False),
 ],
 'leftsize-sql-auditing-disabled': [
   ('auditing Disabled', {'properties': {'c7n:auditing-settings': {'state': 'Disabled'}}}, True),
   ('auditing Enabled', {'properties': {'c7n:auditing-settings': {'state': 'Enabled'}}}, False),
 ],
 'leftsize-aks-local-accounts-enabled': [
   ('disableLocalAccounts false', {'properties': {'disableLocalAccounts': False}}, True),
   ('disableLocalAccounts not set', {'properties': {}}, True),
   ('disableLocalAccounts true', {'properties': {'disableLocalAccounts': True}}, False),
 ],
}


@pytest.mark.parametrize(
    'name,label,resource,expected',
    [(name, label, res, want) for name, cs in CASES.items() for label, res, want in cs],
    ids=[f'{name.replace("leftsize-", "")}: {label}' for name, cs in CASES.items() for label, _, _ in cs],
)
def test_azure_security_policy(name: str, label: str, resource: Dict[str, Any], expected: bool) -> None:
    assert matches(name, resource) is expected
