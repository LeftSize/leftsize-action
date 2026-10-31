"""
Cloudflare provider (c7n_cloudflare) and its LeftSize rules.

The policies run through Cloud Custodian's real policy and filter chain; only the
HTTP layer is replaced by FakeHttp, which answers Cloudflare API paths with canned
`result` payloads in the API's envelope ({"success": true, "result": ...}).
"""

import json
from datetime import datetime, timezone
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

    def post(self, url: str, json: Optional[Dict[str, Any]] = None, timeout: int = 0) -> FakeResponse:
        path = url[len(cf_client.API_BASE):]
        self.calls.append((path, dict((json or {}).get('variables') or {})))
        answer = self.routes.get(path)
        if callable(answer):
            answer = answer((json or {}).get('variables') or {})
        return FakeResponse(200, {'data': answer, 'errors': None})

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


# ---------- more zone rules ----------

def zone_settings(name: str, **settings: Any) -> Dict[str, Any]:
    return {f'/zones/id-{name}/settings/{k}': {'id': k, 'value': v} for k, v in settings.items()}


HSTS_ON = {'strict_transport_security': {'enabled': True, 'max_age': 15552000}}
HSTS_OFF = {'strict_transport_security': {'enabled': False, 'max_age': 0}}


def test_ssl_full_not_strict(cloudflare) -> None:
    cloudflare({'/zones': [zone('full.com'), zone('strict.com')],
                **zone_settings('full.com', ssl='full'), **zone_settings('strict.com', ssl='strict')})
    assert [z['name'] for z in run_policy('leftsize-cloudflare-zone-ssl-full-not-strict')] == ['full.com']


def test_weak_tls_settings(cloudflare) -> None:
    good = dict(min_tls_version='1.2', always_use_https='on', security_header=HSTS_ON)
    cloudflare({
        '/zones': [zone('old-tls.com'), zone('http.com'), zone('no-hsts.com'), zone('good.com')],
        **zone_settings('old-tls.com', **{**good, 'min_tls_version': '1.0'}),
        **zone_settings('http.com', **{**good, 'always_use_https': 'off'}),
        **zone_settings('no-hsts.com', **{**good, 'security_header': HSTS_OFF}),
        **zone_settings('good.com', **good),
    })
    found = run_policy('leftsize-cloudflare-zone-weak-tls-settings')
    assert sorted(z['name'] for z in found) == ['http.com', 'no-hsts.com', 'old-tls.com']


def test_dnssec_disabled(cloudflare) -> None:
    cloudflare({
        '/zones': [zone('off.com'), zone('on.com'), zone('stuck.com'), zone('new.com'),
                   {**zone('partial.com'), 'type': 'partial'}],
        '/zones/id-off.com/dnssec': {'status': 'disabled'},
        '/zones/id-on.com/dnssec': {'status': 'active'},
        '/zones/id-stuck.com/dnssec': {'status': 'pending', 'modified_on': '2026-01-01T00:00:00+00:00'},
        '/zones/id-new.com/dnssec': {'status': 'pending', 'modified_on': datetime.now(timezone.utc).isoformat()},
    })
    assert sorted(z['name'] for z in run_policy('leftsize-cloudflare-zone-dnssec-disabled')) == ['off.com', 'stuck.com']


def test_legacy_zone_features(cloudflare, tmp_path: Path) -> None:
    minify_off = {'css': 'off', 'html': 'off', 'js': 'off'}
    cloudflare({'/zones': [zone('minify.com'), zone('clean.com')],
                **zone_settings('minify.com', minify={**minify_off, 'css': 'on', 'js': 'on'}),
                **zone_settings('clean.com', minify=minify_off)})
    run_policy('leftsize-cloudflare-zone-legacy-features', output_dir=str(tmp_path))
    findings = run.parse_custodian_output(str(tmp_path), {'cloud_provider': 'cloudflare'})
    assert [(f['resourceName'], f['metadata']['minifyOn']) for f in findings] == [('minify.com', 'css, js')]


# ---------- Workers ----------

def worker_routes(scripts: Dict[str, Dict[str, Any]], requests: Dict[str, int],
                  listing: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
    listing = listing or {}
    routes: Dict[str, Any] = {
        '/zones': [zone('a.com')],
        '/accounts': [],
        f'/accounts/{ACCOUNT}/workers/scripts': [
            {'id': n, 'modified_on': '2026-10-01T00:00:00Z', **listing.get(n, {})} for n in scripts],
        f'/accounts/{ACCOUNT}/workers/domains': [],
        '/graphql': lambda v: {'viewer': {'accounts': [{'workersInvocationsAdaptive': [
            {'sum': {'requests': n}, 'dimensions': {'scriptName': s}} for s, n in requests.items()]}]}},
    }
    for name, settings in scripts.items():
        routes[f'/accounts/{ACCOUNT}/workers/scripts/{name}/settings'] = settings
        routes[f'/accounts/{ACCOUNT}/workers/scripts/{name}/schedules'] = {'schedules': []}
    return routes


def test_worker_full_log_sampling(cloudflare) -> None:
    fake = cloudflare(worker_routes({
        'busy-full': {'observability': {'enabled': True}},
        'busy-sampled': {'observability': {'enabled': True, 'head_sampling_rate': 0.05}},
        'busy-logs-off': {'observability': {'enabled': False}},
        'quiet-full': {'observability': {'enabled': True, 'logs': {'enabled': True, 'head_sampling_rate': 1}}},
    }, {'busy-full': 12_000_000, 'busy-sampled': 50_000_000, 'busy-logs-off': 50_000_000, 'quiet-full': 1_000}))
    found = run_policy('leftsize-cloudflare-worker-full-log-sampling')
    assert [w['id'] for w in found] == ['busy-full']
    assert found[0]['leftsize']['requests'] == 12_000_000
    # Accounts come from the zones when /accounts lists nothing; one GraphQL query per account
    graphql = [v for p, v in fake.calls if p == '/graphql']
    assert len(graphql) == 1 and graphql[0]['accountTag'] == ACCOUNT


def test_worker_plaintext_secrets_never_stores_values(cloudflare, tmp_path: Path) -> None:
    cloudflare(worker_routes({
        'leaky': {'bindings': [{'name': 'STRIPE_SECRET_KEY', 'type': 'plain_text', 'text': 'sk_live_supersecret'},
                               {'name': 'API_TOKEN', 'type': 'secret_text'},
                               {'name': 'PUBLIC_URL', 'type': 'plain_text', 'text': 'https://x'}]},
        'clean': {'bindings': [{'name': 'DB_PASSWORD', 'type': 'secret_text'}]},
    }, {}))
    run_policy('leftsize-cloudflare-worker-plaintext-secrets', output_dir=str(tmp_path))
    raw = '\n'.join(p.read_text() for p in tmp_path.rglob('*.json'))
    assert 'sk_live_supersecret' not in raw
    findings = run.parse_custodian_output(str(tmp_path), {'cloud_provider': 'cloudflare'})
    assert [(f['resourceId'], f['resourceName'], f['metadata']['plaintextSecretNames']) for f in findings] == [
        (f'cloudflare:account/{ACCOUNT}/worker/leaky', 'leaky', 'STRIPE_SECRET_KEY')]


# ---------- API tokens ----------

def token(tid: str, issued_days: int, used_days: Optional[int], status: str = 'active', **extra: Any) -> Dict[str, Any]:
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    t = {'id': tid, 'name': f'token {tid}', 'status': status,
         'issued_on': (now - timedelta(days=issued_days)).isoformat(), 'policies': []}
    if used_days is not None:
        t['last_used_on'] = (now - timedelta(days=used_days)).isoformat()
    t.update(extra)
    return t


def test_api_token_unused(cloudflare) -> None:
    cloudflare({'/zones': [zone('a.com')], '/accounts': [], f'/accounts/{ACCOUNT}/tokens': [
        token('stale', 400, 120), token('never-used-old', 200, None), token('never-used-new', 10, None),
        token('recent', 400, 3), token('disabled-stale', 400, 200, status='disabled'),
    ]})
    found = run_policy('leftsize-cloudflare-api-token-unused')
    assert sorted(t['id'] for t in found) == ['never-used-old', 'stale']


def test_api_token_unrestricted(cloudflare, tmp_path: Path) -> None:
    write = [{'effect': 'allow', 'permission_groups': [{'id': 'g1', 'name': 'DNS Write'}, {'id': 'g2', 'name': 'Zone Read'}],
              'resources': {}}]
    read = [{'effect': 'allow', 'permission_groups': [{'id': 'g2', 'name': 'Zone Read'}], 'resources': {}}]
    cloudflare({'/zones': [zone('a.com')], '/accounts': [], f'/accounts/{ACCOUNT}/tokens': [
        token('wide-open', 30, 1, policies=write),
        token('expires', 30, 1, policies=write, expires_on='2027-01-01T00:00:00Z'),
        token('ip-locked', 30, 1, policies=write, condition={'request_ip': {'in': ['192.0.2.0/24']}}),
        token('read-only', 30, 1, policies=read),
    ]})
    run_policy('leftsize-cloudflare-api-token-unrestricted', output_dir=str(tmp_path))
    findings = run.parse_custodian_output(str(tmp_path), {'cloud_provider': 'cloudflare'})
    assert [(f['resourceId'], f['resourceName'], f['metadata']['writePermissions']) for f in findings] == [
        (f'cloudflare:account/{ACCOUNT}/api-token/wide-open', 'token wide-open', 'DNS Write')]


# ---------- R2 ----------

def r2_routes(buckets: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    routes: Dict[str, Any] = {
        '/zones': [zone('a.com')], '/accounts': [],
        f'/accounts/{ACCOUNT}/r2/buckets': {'result': {'buckets': [
            {'name': n, 'creation_date': '2025-01-01T00:00:00Z', 'location': 'WEUR', 'storage_class': 'Standard'}
            for n in buckets]}, 'result_info': {'cursor': ''}},
    }
    for name, parts in buckets.items():
        for path, value in parts.items():
            routes[f'/accounts/{ACCOUNT}/r2/buckets/{name}/{path}'] = value
    return routes


def test_r2_public_dev_url(cloudflare) -> None:
    cloudflare(r2_routes({
        'public': {'domains/managed': {'bucketId': 'b1', 'domain': 'pub-abc.r2.dev', 'enabled': True}},
        'private': {'domains/managed': {'bucketId': 'b2', 'domain': 'pub-def.r2.dev', 'enabled': False}},
    }))
    assert [b['name'] for b in run_policy('leftsize-cloudflare-r2-public-dev-url')] == ['public']


def test_r2_cors_any_origin(cloudflare) -> None:
    cloudflare(r2_routes({
        'any': {'cors': {'rules': [{'allowed': {'origins': ['*'], 'methods': ['GET']}}]}},
        'mine': {'cors': {'rules': [{'allowed': {'origins': ['https://example.com'], 'methods': ['GET']}}]}},
        'none': {'cors': FakeResponse(404, {'success': False, 'errors': [{'code': 10059, 'message': 'no cors'}]})},
    }))
    assert [b['name'] for b in run_policy('leftsize-cloudflare-r2-cors-any-origin')] == ['any']


def test_r2_no_multipart_abort(cloudflare) -> None:
    abort = {'abortMultipartUploadsTransition': {'condition': {'maxAge': 604800, 'type': 'Age'}}}
    cloudflare(r2_routes({
        'default-rule': {'lifecycle': {'rules': [{'id': 'd', 'enabled': True, 'conditions': {'prefix': ''}, **abort}]}},
        'no-rules': {'lifecycle': {'rules': []}},
        'prefix-only': {'lifecycle': {'rules': [{'id': 'p', 'enabled': True, 'conditions': {'prefix': 'tmp/'}, **abort}]}},
        'disabled': {'lifecycle': {'rules': [{'id': 'x', 'enabled': False, 'conditions': {}, **abort}]}},
    }))
    found = run_policy('leftsize-cloudflare-r2-no-multipart-abort')
    assert sorted(b['name'] for b in found) == ['disabled', 'no-rules', 'prefix-only']
    assert all(b['leftsize']['multipartAbortDays'] is None for b in found)


# ---------- account, certificates, Worker hygiene ----------

def test_account_2fa(cloudflare, tmp_path: Path) -> None:
    member = lambda email, tfa, status='accepted': {'id': email, 'status': status,  # noqa: E731
                                                    'user': {'email': email, 'two_factor_authentication_enabled': tfa}}
    other = 'f' * 32
    cloudflare({
        '/zones': [zone('a.com'), zone('b.com', account=other)], '/accounts': [],
        f'/accounts/{ACCOUNT}': {'id': ACCOUNT, 'name': 'Main', 'settings': {'enforce_twofactor': False}},
        f'/accounts/{ACCOUNT}/members': [member('a@example.com', True)],
        f'/accounts/{other}': {'id': other, 'name': 'Other', 'settings': {'enforce_twofactor': True}},
        f'/accounts/{other}/members': [member('b@example.com', True), member('c@example.com', False),
                                       member('pending@example.com', False, status='pending')],
    })
    run_policy('leftsize-cloudflare-account-2fa-not-enforced', output_dir=str(tmp_path))
    findings = run.parse_custodian_output(str(tmp_path), {'cloud_provider': 'cloudflare'})
    got = {f['resourceId']: (f['metadata']['enforceTwoFactor'], f['metadata']['membersWithout2faCount']) for f in findings}
    assert got == {f'cloudflare:account/{ACCOUNT}/account/{ACCOUNT}': (False, 0),
                   f'cloudflare:account/{other}/account/{other}': (True, 1)}
    raw = '\n'.join(p.read_text() for p in tmp_path.rglob('*.json'))
    assert 'c@example.com' not in raw  # member emails are never kept


def test_certificate_expiring(cloudflare, tmp_path: Path) -> None:
    from datetime import timedelta
    soon = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
    later = (datetime.now(timezone.utc) + timedelta(days=200)).isoformat()
    cloudflare({
        '/zones': [zone('a.com', plan='business'), zone('free.com')],
        '/zones/id-free.com/custom_certificates': FakeResponse(403, {'success': False, 'errors': [{'code': 9109}]}),
        '/certificates': lambda p: [{'id': 'oca-soon', 'hostnames': ['a.com', '*.a.com'], 'expires_on': soon,
                                     'certificate': '-----BEGIN CERTIFICATE-----secret-pem'},
                                    {'id': 'oca-later', 'hostnames': ['a.com'], 'expires_on': later}]
        if p.get('zone_id') == 'id-a.com' else [],
        '/zones/id-a.com/custom_certificates': [{'id': 'custom-soon', 'hosts': ['shop.a.com'], 'expires_on': soon,
                                                'issuer': 'DigiCert', 'status': 'active'}],
    })
    run_policy('leftsize-cloudflare-certificate-expiring', output_dir=str(tmp_path))
    assert 'BEGIN CERTIFICATE' not in '\n'.join(p.read_text() for p in tmp_path.rglob('*.json'))
    findings = run.parse_custodian_output(str(tmp_path), {'cloud_provider': 'cloudflare'})
    got = sorted((f['resourceId'].rsplit('/', 1)[1], f['metadata']['certificateKind'], f['metadata']['hostnames'])
                 for f in findings)
    assert got == [('custom-soon', 'custom', 'shop.a.com'), ('oca-soon', 'origin-ca', 'a.com, *.a.com')]


def test_worker_unused(cloudflare) -> None:
    cloudflare(worker_routes(
        {'idle': {}, 'busy': {}, 'assets-only': {}, 'new': {}},
        {'busy': 500},
        {'assets-only': {'has_assets': True}, 'new': {'modified_on': datetime.now(timezone.utc).isoformat()}},
    ))
    assert [w['id'] for w in run_policy('leftsize-cloudflare-worker-unused')] == ['idle']


def test_worker_outdated_compatibility_date(cloudflare) -> None:
    cloudflare(worker_routes({'old': {'compatibility_date': '2024-01-01'},
                              'recent': {'compatibility_date': datetime.now(timezone.utc).date().isoformat()}}, {}))
    assert [w['id'] for w in run_policy('leftsize-cloudflare-worker-outdated-compatibility-date')] == ['old']


# ---------- Registrar, Zero Trust, tunnels, load balancing ----------

def ago(days: int) -> str:
    from datetime import timedelta
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def base_routes(**extra: Any) -> Dict[str, Any]:
    return {'/zones': [zone('a.com')], '/accounts': [], **extra}


def test_domains(cloudflare) -> None:
    domains = [
        {'domain_name': 'expiring.com', 'status': 'active', 'auto_renew': False, 'locked': True, 'expires_at': ago(-10)},
        {'domain_name': 'renews.com', 'status': 'active', 'auto_renew': True, 'locked': True, 'expires_at': ago(-10)},
        {'domain_name': 'later.com', 'status': 'active', 'auto_renew': False, 'locked': True, 'expires_at': ago(-200)},
        {'domain_name': 'gone.com', 'status': 'redemption_period', 'auto_renew': False, 'locked': True, 'expires_at': ago(5)},
        {'domain_name': 'unlocked.com', 'status': 'active', 'auto_renew': True, 'locked': False, 'expires_at': ago(-300)},
    ]
    fake = cloudflare(base_routes(**{f'/accounts/{ACCOUNT}/registrar/registrations':
                                     {'result': domains, 'result_info': {'cursor': ''}}}))
    assert sorted(d['domain_name'] for d in run_policy('leftsize-cloudflare-domain-expiring')) == ['expiring.com', 'gone.com']
    assert [d['domain_name'] for d in run_policy('leftsize-cloudflare-domain-transfer-unlocked')] == ['unlocked.com']
    assert all(p['per_page'] == 50 for path, p in fake.calls if path.endswith('/registrations'))


def test_zero_trust_inactive_seat(cloudflare, tmp_path: Path) -> None:
    users = [
        {'id': 'u1', 'email': 'stale@example.com', 'access_seat': True, 'gateway_seat': False,
         'last_successful_login': ago(90), 'created_at': ago(400)},
        {'id': 'u2', 'email': 'active@example.com', 'access_seat': True, 'gateway_seat': True,
         'last_successful_login': ago(2), 'created_at': ago(400)},
        {'id': 'u3', 'email': 'never@example.com', 'access_seat': False, 'gateway_seat': True, 'created_at': ago(100)},
        {'id': 'u4', 'email': 'removed@example.com', 'access_seat': False, 'gateway_seat': False,
         'last_successful_login': ago(300), 'created_at': ago(400)},
    ]
    cloudflare(base_routes(**{f'/accounts/{ACCOUNT}/access/users': users,
                              f'/accounts/{ACCOUNT}/access/organizations': {'user_seat_expiration_inactive_time': None}}))
    run_policy('leftsize-cloudflare-zero-trust-inactive-seat', output_dir=str(tmp_path))
    findings = run.parse_custodian_output(str(tmp_path), {'cloud_provider': 'cloudflare'})
    assert sorted((f['resourceId'].rsplit('/', 1)[1], f['metadata']['email']) for f in findings) == [
        ('u1', 'stale@example.com'), ('u3', 'never@example.com')]


def test_access_app_allows_everyone(cloudflare) -> None:
    def app(aid: str, *policies: Dict[str, Any]) -> Dict[str, Any]:
        return {'id': aid, 'name': aid, 'domain': f'{aid}.a.com', 'type': 'self_hosted', 'policies': list(policies)}
    everyone = {'name': 'all', 'decision': 'allow', 'include': [{'everyone': {}}], 'require': [], 'exclude': []}
    cloudflare(base_routes(**{f'/accounts/{ACCOUNT}/access/apps': [
        app('open', everyone),
        app('required', {**everyone, 'require': [{'email_domain': {'domain': 'a.com'}}]}),
        app('bypass', {**everyone, 'decision': 'bypass'}),
        app('emails', {'name': 'team', 'decision': 'allow', 'include': [{'email_domain': {'domain': 'a.com'}}]}),
    ]}))
    found = run_policy('leftsize-cloudflare-access-app-allows-everyone')
    assert [(a['id'], a['leftsize']['everyonePolicies']) for a in found] == [('open', ['all'])]


def test_access_service_token_unused(cloudflare) -> None:
    cloudflare(base_routes(**{f'/accounts/{ACCOUNT}/access/service_tokens': [
        {'id': 's1', 'name': 'old', 'last_seen_at': ago(120), 'created_at': ago(400)},
        {'id': 's2', 'name': 'used', 'last_seen_at': ago(1), 'created_at': ago(400)},
        {'id': 's3', 'name': 'never-old', 'created_at': ago(200)},
        {'id': 's4', 'name': 'never-new', 'created_at': ago(5)},
        {'id': 's5', 'name': 'disabled-old', 'enabled': False, 'last_seen_at': ago(300), 'created_at': ago(400)},
    ]}))
    assert sorted(t['name'] for t in run_policy('leftsize-cloudflare-access-service-token-unused')) == ['never-old', 'old']


def test_tunnel_inactive_and_pagination(cloudflare) -> None:
    tunnels = [{'id': f't{i}', 'name': f'filler-{i}', 'status': 'healthy', 'created_at': ago(400)} for i in range(50)]
    tunnels += [{'id': 'down-old', 'name': 'down-old', 'status': 'down', 'conns_inactive_at': ago(60), 'created_at': ago(400)},
                {'id': 'down-new', 'name': 'down-new', 'status': 'down', 'conns_inactive_at': ago(3), 'created_at': ago(400)},
                {'id': 'never', 'name': 'never', 'status': 'inactive', 'created_at': ago(45)}]

    def pages(params: Dict[str, Any]) -> Dict[str, Any]:
        start = (params['page'] - 1) * params['per_page']
        assert params['is_deleted'] == 'false'
        # Like the tunnels API: no total_pages in result_info
        return {'result': tunnels[start:start + params['per_page']],
                'result_info': {'page': params['page'], 'per_page': params['per_page']}}
    cloudflare(base_routes(**{f'/accounts/{ACCOUNT}/cfd_tunnel': pages}))
    assert sorted(t['id'] for t in run_policy('leftsize-cloudflare-tunnel-inactive')) == ['down-old', 'never']


def test_lb_pool_unused(cloudflare) -> None:
    pools_path = f'/accounts/{ACCOUNT}/load_balancers/pools'
    lb = {'reference_type': 'referrer', 'resource_type': 'load_balancer', 'resource_name': 'www.a.com', 'resource_id': 'lb1'}
    monitor = {'reference_type': 'referral', 'resource_type': 'monitor', 'resource_name': 'health', 'resource_id': 'm1'}
    cloudflare({
        '/zones': [zone('a.com')], '/accounts': [],
        pools_path: [{'id': 'p-used', 'name': 'used', 'origins': [{'address': '192.0.2.1'}]},
                     {'id': 'p-orphan', 'name': 'orphan', 'origins': [{'address': '192.0.2.9'}, {'address': '192.0.2.10'}]}],
        f'{pools_path}/p-used/references': [lb, monitor],
        f'{pools_path}/p-orphan/references': [monitor],
    })
    found = run_policy('leftsize-cloudflare-lb-pool-unused')
    assert [(p['name'], p['leftsize']['originCount'], p['leftsize']['referrers']) for p in found] == [('orphan', 2, [])]


def test_paginate_stops_when_endpoint_ignores_paging(cloudflare) -> None:
    items = [{'id': f'g{i}'} for i in range(80)]
    fake = cloudflare({'/things': {'result': items, 'result_info': {'count': 80}}})
    assert len(list(cf_client.Session().paginate('/things'))) == 80
    assert len([c for c in fake.calls if c[0] == '/things']) == 2


# ---------- review fixes ----------

def test_retry_after_http_date_and_network_errors(cloudflare, monkeypatch: pytest.MonkeyPatch) -> None:
    import requests as rq
    calls = {'n': 0}
    ok = FakeResponse(200, {'success': True, 'result': [zone('a.com')]})

    class Flaky(FakeHttp):
        def get(self, url, params=None, timeout=0):  # type: ignore[override]
            calls['n'] += 1
            if calls['n'] == 1:
                raise rq.ConnectionError('reset')
            if calls['n'] == 2:
                return FakeResponse(429, {'success': False}, {'Retry-After': 'Wed, 21 Oct 2015 07:28:00 GMT'})
            return ok
    reset_session_cache()
    monkeypatch.setattr(cf_client.requests, 'Session', lambda: Flaky({}))
    assert [z['name'] for z in cf_client.Session().paginate('/zones')] == ['a.com']
    assert calls['n'] == 3


def test_one_account_failing_doesnt_hide_others(cloudflare, monkeypatch: pytest.MonkeyPatch, caplog) -> None:
    other = 'f' * 32
    monkeypatch.setenv('CLOUDFLARE_ACCOUNT_IDS', f'{ACCOUNT},{other}')
    cloudflare({
        '/zones': [zone('a.com')],
        f'/accounts/{ACCOUNT}/access/service_tokens': FakeResponse(403, {'success': False, 'errors': [{'code': 10000}]}),
        f'/accounts/{other}/access/service_tokens': [{'id': 's1', 'name': 'old', 'last_seen_at': ago(200), 'created_at': ago(400)}],
    })
    with caplog.at_level('WARNING', logger='custodian.cloudflare'):
        found = run_policy('leftsize-cloudflare-access-service-token-unused')
    assert [t['name'] for t in found] == ['old']
    assert any('Skipped access-service-token of account' in r.message for r in caplog.records)


def test_zone_settings_fetched_once_per_run(cloudflare) -> None:
    fake = cloudflare({'/zones': [zone('a.com')], **zone_settings('a.com', ssl='flexible')})
    run_policy('leftsize-cloudflare-zone-ssl-unencrypted-origin')
    run_policy('leftsize-cloudflare-zone-ssl-full-not-strict')
    assert len([c for c in fake.calls if c[0].endswith('/settings/ssl')]) == 1


def test_withdrawn_setting_counts_as_off(cloudflare) -> None:
    cloudflare({'/zones': [zone('a.com')]})  # /settings/minify -> 404
    assert run_policy('leftsize-cloudflare-zone-legacy-features') == []


def test_names_are_sanitized_for_issues() -> None:
    resource = {'id': 'abc', 'name': 'deploy [click](https://evil)\n`rm -rf` <img src=x>', 'status': 'active',
                'account': {'id': ACCOUNT}, 'c7n:cloudflare-id': f'account/{ACCOUNT}/api-token/abc',
                'leftsize': {'writePermissions': ['DNS Write']}}
    f = run.convert_resource_to_finding('leftsize-cloudflare-api-token-unrestricted', resource,
                                        {'cloud_provider': 'cloudflare'}, 'cloudflare.api-token')
    assert f['metadata']['tokenName'] == 'deploy click(https://evil) rm -rf img src=x'
    assert '\n' not in f['resourceName'] and '[' not in f['resourceName']


def test_cloudflare_env_allow_list_is_narrow(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('CLOUDFLARE_API_TOKEN', 't')
    monkeypatch.setenv('CLOUDFLARE_API_KEY', 'global-key')
    env = run._build_custodian_env()
    assert 'CLOUDFLARE_API_TOKEN' in env and 'CLOUDFLARE_API_KEY' not in env


def test_auth_accepts_token_without_zones(cloudflare) -> None:
    cloudflare({'/zones': FakeResponse(403, {'success': False, 'errors': [{'code': 9109}]}),
                '/user/tokens/verify': {'id': 't', 'status': 'active'}})
    assert run.validate_cloudflare_auth({}) is True
    cloudflare({'/zones': FakeResponse(403, {'success': False, 'errors': [{'code': 9109}]})})
    assert run.validate_cloudflare_auth({}) is False


# ---------- Copilot review fixes ----------

FORBIDDEN = FakeResponse(403, {'success': False, 'errors': [{'code': 9109, 'message': 'Unauthorized'}]})


def test_zones_of_one_account_failing_keeps_the_others(cloudflare, monkeypatch: pytest.MonkeyPatch) -> None:
    other = 'f' * 32
    monkeypatch.setenv('CLOUDFLARE_ACCOUNT_IDS', f'{ACCOUNT},{other}')

    class PerAccount(FakeHttp):
        def get(self, url, params=None, timeout=0):  # type: ignore[override]
            if url.endswith('/zones') and (params or {}).get('account.id') == other:
                return FORBIDDEN
            return super().get(url, params, timeout)
    reset_session_cache()
    monkeypatch.setattr(cf_client.requests, 'Session', lambda: PerAccount({'/zones': [zone('a.com')]}))
    assert [z['name'] for z in cf_client.Session().zones()] == ['a.com']


def test_accounts_fall_back_to_zones_when_listing_is_forbidden(cloudflare) -> None:
    cloudflare({'/zones': [zone('a.com')], '/accounts': FORBIDDEN})
    assert cf_client.Session().accounts() == [ACCOUNT]


def test_paginate_detects_repeat_after_caller_annotates(cloudflare) -> None:
    items = [{'id': f'g{i}'} for i in range(80)]
    fake = cloudflare({'/things': lambda p: {'result': [dict(i) for i in items], 'result_info': {'count': 80}}})
    listed = []
    for item in cf_client.Session().paginate('/things'):
        item['leftsize'] = {}  # managers annotate what they get
        listed.append(item)
    assert len(listed) == 80
    assert len([c for c in fake.calls if c[0] == '/things']) == 2


def test_account_2fa_skips_a_forbidden_account(cloudflare, monkeypatch: pytest.MonkeyPatch) -> None:
    other = 'f' * 32
    monkeypatch.setenv('CLOUDFLARE_ACCOUNT_IDS', f'{ACCOUNT},{other}')
    cloudflare({
        '/zones': [zone('a.com')],
        f'/accounts/{ACCOUNT}': FORBIDDEN,
        f'/accounts/{other}': {'id': other, 'name': 'Other', 'settings': {'enforce_twofactor': False}},
        f'/accounts/{other}/members': [],
    })
    assert [a['id'] for a in run_policy('leftsize-cloudflare-account-2fa-not-enforced')] == [other]


def test_empty_workers_list_is_a_note_not_a_problem(cloudflare, caplog) -> None:
    cloudflare(worker_routes({}, {}))
    with caplog.at_level('INFO', logger='custodian.cloudflare'):
        assert run_policy('leftsize-cloudflare-worker-unused') == []
    notes = [r for r in caplog.records if 'No Workers listed' in r.message]
    assert notes and all(r.levelname == 'INFO' for r in notes)


def test_worker_analytics_failure_skips_only_that_account(cloudflare, monkeypatch: pytest.MonkeyPatch) -> None:
    other = 'f' * 32
    monkeypatch.setenv('CLOUDFLARE_ACCOUNT_IDS', f'{ACCOUNT},{other}')
    routes = worker_routes({'idle': {}}, {})
    routes[f'/accounts/{other}/workers/scripts'] = [{'id': 'idle2', 'modified_on': '2026-01-01T00:00:00Z'}]
    routes[f'/accounts/{other}/workers/domains'] = []
    routes[f'/accounts/{other}/workers/scripts/idle2/settings'] = {}
    routes[f'/accounts/{other}/workers/scripts/idle2/schedules'] = {'schedules': []}
    fake = cloudflare(routes)

    def post(url, json=None, timeout=0):
        if (json or {}).get('variables', {}).get('accountTag') == other:
            return FakeResponse(200, {'data': None, 'errors': [{'message': 'not authorized'}]})
        return FakeHttp.post(fake, url, json, timeout)
    fake.post = post  # type: ignore[method-assign]
    found = run_policy('leftsize-cloudflare-worker-unused')
    assert [w['id'] for w in found] == ['idle']


def test_cloudflare_env_allow_list_matches_exact_names(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('CLOUDFLARE_API_TOKEN', 't')
    monkeypatch.setenv('CLOUDFLARE_API_TOKEN_PRODUCTION', 'other')
    monkeypatch.setenv('CLOUDFLARE_ACCOUNT_IDS_OLD', 'x')
    env = run._build_custodian_env()
    assert 'CLOUDFLARE_API_TOKEN' in env
    assert 'CLOUDFLARE_API_TOKEN_PRODUCTION' not in env and 'CLOUDFLARE_ACCOUNT_IDS_OLD' not in env


def test_registrar_finding_has_domain_name() -> None:
    resource = {'domain_name': 'example.com', 'account': {'id': ACCOUNT}, 'locked': False,
                'c7n:cloudflare-id': f'account/{ACCOUNT}/domain/example.com'}
    f = run.convert_resource_to_finding('leftsize-cloudflare-domain-transfer-unlocked', resource,
                                        {'cloud_provider': 'cloudflare'}, 'cloudflare.domain')
    assert f['resourceName'] == 'example.com'


def test_environment_source_is_sanitized() -> None:
    resource = {'id': 'abc', 'name': 'prod [click](https://example.com)', 'status': 'active',
                'account': {'id': ACCOUNT}, 'c7n:cloudflare-id': f'account/{ACCOUNT}/api-token/abc',
                'leftsize': {}}
    f = run.convert_resource_to_finding('leftsize-cloudflare-api-token-unrestricted', resource,
                                        {'cloud_provider': 'cloudflare'}, 'cloudflare.api-token')
    assert all('[' not in v for v in f['metadata'].values() if isinstance(v, str))
