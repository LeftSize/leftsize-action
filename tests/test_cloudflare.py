"""
Cloudflare provider (c7n_cloudflare) and its LeftSize rules.

The policies run through Cloud Custodian's real policy and filter chain; only the
HTTP layer is replaced by FakeHttp, which answers Cloudflare API paths with canned
`result` payloads in the API's envelope ({"success": true, "result": ...}).
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
import yaml

import c7n_cloudflare  # noqa: F401  registers the provider
from c7n.config import Config
from c7n.policy import Policy
from c7n.resources import load_resources
from c7n.utils import reset_session_cache
from c7n_cloudflare import client as cf_client

import run

load_resources(('cloudflare.*',))

POLICIES_DIR = Path(__file__).parent.parent / 'policies'
DOCS = {
    p['name']: p
    for f in POLICIES_DIR.glob('cloudflare-*.yml')
    for p in yaml.safe_load(f.read_text())['policies']
}
ACCOUNT = '0123456789abcdef0123456789abcdef'


class FakeResponse:
    def __init__(self, status: int, body: Dict[str, Any], headers: Optional[Dict[str, str]] = None) -> None:
        self.status_code = status
        self._body = body
        self.headers = headers or {}

    def json(self) -> Dict[str, Any]:
        return self._body


class FakeHttp:
    """requests.Session stand-in: routes[path] is a result, a FakeResponse, or a list of them (per call)."""

    def __init__(self, routes: Dict[str, Any]) -> None:
        self.routes = routes
        self.headers: Dict[str, str] = {}
        self.calls: List[tuple] = []

    def get(self, url: str, params: Optional[Dict[str, Any]] = None, timeout: int = 0) -> FakeResponse:
        path = url[len(cf_client.API_BASE):]
        self.calls.append((path, dict(params or {})))
        if path not in self.routes:
            return FakeResponse(404, {'success': False, 'errors': [{'code': 7003, 'message': f'no route {path}'}]})
        answer = self.routes[path]
        if isinstance(answer, list) and answer and isinstance(answer[0], FakeResponse):
            answer = answer.pop(0) if len(answer) > 1 else answer[0]
        if isinstance(answer, FakeResponse):
            return answer
        if callable(answer):
            answer = answer(params or {})
        if isinstance(answer, dict) and 'result_info' in answer:
            return FakeResponse(200, {'success': True, **answer})
        return FakeResponse(200, {'success': True, 'result': answer})


def zone(name: str, plan: str = 'free', status: str = 'active', paused: bool = False,
         account: str = ACCOUNT, price: float = 0) -> Dict[str, Any]:
    return {
        'id': f'id-{name}', 'name': name, 'status': status, 'paused': paused,
        'account': {'id': account, 'name': 'Example account'},
        'plan': {'id': plan, 'name': f'{plan.title()} Website', 'legacy_id': plan, 'price': price,
                 'currency': 'USD', 'frequency': 'monthly' if price else ''},
        'name_servers': ['ada.ns.cloudflare.com', 'bob.ns.cloudflare.com'],
        'activated_on': '2025-01-01T00:00:00Z', 'created_on': '2024-12-01T00:00:00Z', 'type': 'full',
    }


@pytest.fixture
def cloudflare(monkeypatch: pytest.MonkeyPatch):
    """Install a FakeHttp for the given routes; returns the fake."""
    monkeypatch.setenv('CLOUDFLARE_API_TOKEN', 'test-token')
    monkeypatch.delenv('CLOUDFLARE_ACCOUNT_IDS', raising=False)
    monkeypatch.setattr(cf_client.time, 'sleep', lambda s: None)

    def install(routes: Dict[str, Any]) -> FakeHttp:
        reset_session_cache()  # c7n keeps sessions per process; each test needs its own fake
        fake = FakeHttp(routes)
        monkeypatch.setattr(cf_client.requests, 'Session', lambda: fake)
        return fake
    return install


def run_policy(name: str, output_dir: Optional[str] = None) -> List[Dict[str, Any]]:
    options = Config.empty(output_dir=output_dir or '', cache='', dryrun=True)
    policy = Policy(DOCS[name], options)
    if output_dir:
        return policy()
    return policy.resource_manager.resources()


# ---------- the three rules ----------

def test_paid_zone_not_serving(cloudflare) -> None:
    cloudflare({'/zones': [
        zone('pending-pro.com', plan='pro', status='pending', price=25),
        zone('paused-biz.com', plan='business', paused=True, price=250),
        zone('moved-ent.com', plan='enterprise', status='moved'),
        zone('active-pro.com', plan='pro', price=25),
        zone('pending-free.com', status='pending'),
        {**zone('no-plan.com', status='pending'), 'plan': {}},
    ]})
    names = sorted(z['name'] for z in run_policy('leftsize-cloudflare-paid-zone-not-serving'))
    assert names == ['moved-ent.com', 'paused-biz.com', 'pending-pro.com']


def test_ssl_unencrypted_origin(cloudflare) -> None:
    fake = cloudflare({
        '/zones': [zone('flex.com'), zone('off.com'), zone('strict.com'), zone('full.com'),
                   zone('pending.com', status='pending'), zone('paused.com', paused=True)],
        '/zones/id-flex.com/settings/ssl': {'id': 'ssl', 'value': 'flexible'},
        '/zones/id-off.com/settings/ssl': {'id': 'ssl', 'value': 'off'},
        '/zones/id-strict.com/settings/ssl': {'id': 'ssl', 'value': 'strict'},
        '/zones/id-full.com/settings/ssl': {'id': 'ssl', 'value': 'full'},
    })
    found = run_policy('leftsize-cloudflare-zone-ssl-unencrypted-origin')
    assert sorted(z['name'] for z in found) == ['flex.com', 'off.com']
    assert {z['name']: z['c7n:zone-settings']['ssl'] for z in found} == {'flex.com': 'flexible', 'off.com': 'off'}
    # Pending and paused zones are filtered out before any settings call
    assert not any('pending.com' in p or 'paused.com' in p for p, _ in fake.calls)


def test_page_rules_deprecated(cloudflare) -> None:
    rules = [
        {'id': 'r1', 'status': 'active',
         'targets': [{'target': 'url', 'constraint': {'operator': 'matches', 'value': 'example.com/old/*'}}],
         'actions': [{'id': 'forwarding_url', 'value': {'url': 'https://example.com/new/$1', 'status_code': 301}}]},
        {'id': 'r2', 'status': 'disabled',
         'targets': [{'target': 'url', 'constraint': {'operator': 'matches', 'value': 'example.com/api/*'}}],
         'actions': [{'id': 'disable_performance'}, {'id': 'cache_level', 'value': 'bypass'}]},
    ]
    cloudflare({
        '/zones': [zone('example.com'), zone('clean.com'), zone('pending.com', status='pending')],
        '/zones/id-example.com/pagerules': rules,
        '/zones/id-clean.com/pagerules': [],
    })
    found = run_policy('leftsize-cloudflare-page-rules-deprecated')
    assert [z['name'] for z in found] == ['example.com']
    assert found[0]['c7n:page-rules'] == {
        'count': 2, 'active': 1,
        'settings': ['cache_level', 'disable_performance', 'forwarding_url'],
        'unmigrated': ['disable_performance'],
        'urls': ['example.com/old/*', 'example.com/api/*'],
    }


# ---------- client ----------

def test_pagination_and_account_filter(cloudflare, monkeypatch: pytest.MonkeyPatch) -> None:
    other = 'f' * 32

    def zones(params: Dict[str, Any]) -> Dict[str, Any]:
        page = params['page']
        account = params.get('account.id')
        items = [zone(f'{account[:4]}-{page}.com', plan='pro', status='pending', account=account)]
        return {'result': items, 'result_info': {'page': page, 'total_pages': 2}}
    monkeypatch.setenv('CLOUDFLARE_ACCOUNT_IDS', f'{ACCOUNT},{other}')
    fake = cloudflare({'/zones': zones})
    names = sorted(z['name'] for z in run_policy('leftsize-cloudflare-paid-zone-not-serving'))
    assert names == ['0123-1.com', '0123-2.com', 'ffff-1.com', 'ffff-2.com']
    assert [(p['account.id'], p['page']) for _, p in fake.calls] == [(ACCOUNT, 1), (ACCOUNT, 2), (other, 1), (other, 2)]


def test_retries_rate_limit_then_succeeds(cloudflare) -> None:
    cloudflare({'/zones': [FakeResponse(429, {'success': False}, {'Retry-After': '1'}),
                           FakeResponse(200, {'success': True, 'result': [zone('a.com')]})]})
    assert [z['name'] for z in cf_client.Session().paginate('/zones')] == ['a.com']


def test_permission_error_names_the_problem(cloudflare) -> None:
    cloudflare({'/zones': [zone('a.com')],
                '/zones/id-a.com/pagerules': FakeResponse(
                    403, {'success': False, 'errors': [{'code': 10000, 'message': 'Authentication error'}]})})
    with pytest.raises(cf_client.CloudflareError, match='403.*missing a read permission'):
        run_policy('leftsize-cloudflare-page-rules-deprecated')


def test_session_requires_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv('CLOUDFLARE_API_TOKEN', raising=False)
    with pytest.raises(ValueError, match='CLOUDFLARE_API_TOKEN'):
        cf_client.Session()


# ---------- action integration (run.py) ----------

def test_findings_from_custodian_output(cloudflare, tmp_path: Path) -> None:
    """Custodian output -> LeftSize findings and the submitted finding groups."""
    cloudflare({'/zones': [zone('pending-pro.com', plan='pro', status='pending', price=25)]})
    run_policy('leftsize-cloudflare-paid-zone-not-serving', output_dir=str(tmp_path))
    config = {'cloud_provider': 'cloudflare'}
    findings = run.parse_custodian_output(str(tmp_path), config)
    assert len(findings) == 1
    f = findings[0]
    assert f['resourceId'] == f'cloudflare:account/{ACCOUNT}/zone/pending-pro.com'
    assert f['scope'] == f'cloudflare:account/{ACCOUNT}'
    assert f['resourceName'] == 'pending-pro.com'
    assert f['resourceType'] == 'cloudflare.zone'
    m = f['metadata']
    assert (m['zoneName'], m['status'], m['planName'], m['planPrice'], m['severity']) == \
        ('pending-pro.com', 'pending', 'Pro Website', 25, 'medium')
    assert m['nameServers'] == 'ada.ns.cloudflare.com, bob.ns.cloudflare.com'
    groups = run.group_findings(findings)
    assert [(g['policy'], g['scope'], g['cloud_provider']) for g in groups] == [
        ('leftsize-cloudflare-paid-zone-not-serving', f'cloudflare:account/{ACCOUNT}', 'cloudflare')]
    json.dumps(groups)  # submittable


def test_page_rule_metadata_for_templates() -> None:
    resource = {**zone('example.com'), 'c7n:page-rules': {
        'count': 3, 'active': 2, 'settings': ['cache_level', 'waf'], 'unmigrated': ['waf'], 'urls': ['a/*']}}
    m = run.extract_resource_metadata(resource, 'cloudflare:account/x/zone/example.com', 'cloudflare.zone')
    assert (m['pageRuleCount'], m['pageRulesActive'], m['pageRuleSettings'], m['pageRulesUnmigrated']) == \
        (3, 2, 'cache_level, waf', 'waf')


def test_policy_discovery_is_per_provider() -> None:
    """Each provider runs only its own files: AWS and Azure scans must not pick up cloudflare-*.yml."""
    seen: Dict[str, List[str]] = {}
    original = run.filter_policy_file
    for provider in run.CLOUD_PROVIDERS:
        files: List[str] = []
        run.filter_policy_file = lambda path, config, work, files=files: files.append(Path(path).name)  # type: ignore
        try:
            run.execute_custodian_policies(str(POLICIES_DIR), {'cloud_provider': provider})
        finally:
            run.filter_policy_file = original
        seen[provider] = files
    assert seen['cloudflare'] and all(f.startswith('cloudflare-') for f in seen['cloudflare'])
    assert seen['aws'] and all(f.startswith('aws-') for f in seen['aws'])
    assert seen['azure'] and all(f.startswith('azure-') for f in seen['azure'])


def test_custodian_command_and_env(monkeypatch: pytest.MonkeyPatch) -> None:
    cmd = run.custodian_command({'cloud_provider': 'cloudflare'})
    assert cmd[-1].endswith('leftsize_custodian.py')
    assert run.custodian_command({'cloud_provider': 'aws'})[0].endswith('custodian')
    monkeypatch.setenv('CLOUDFLARE_API_TOKEN', 'secret')
    monkeypatch.setenv('LEFTSIZE_CLOUDFLARE_API_TOKEN', 'secret')
    env = run._build_custodian_env()
    assert env.get('CLOUDFLARE_API_TOKEN') == 'secret'
    assert 'LEFTSIZE_CLOUDFLARE_API_TOKEN' not in env


def test_account_id_validation() -> None:
    assert run.validate_cloudflare_account_id(ACCOUNT)
    assert not run.validate_cloudflare_account_id('not-an-account')
    assert not run.validate_cloudflare_account_id(ACCOUNT.upper())
