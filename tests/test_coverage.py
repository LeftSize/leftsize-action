"""
Scan coverage: which rules ran where, sent with the findings so LeftSize can tell
"no longer found" from "not looked at".
"""

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import run  # noqa: E402
import leftsize_custodian  # noqa: E402

AWS_CONFIG = {
    'cloud_provider': 'aws',
    'targets': {'aws': {'account_id': '123456789012', 'regions': ['eu-west-1']}},
}
AZURE_CONFIG = {
    'cloud_provider': 'azure',
    'targets': {'azure': {'subscriptions': ['ABCDEF00-0000-0000-0000-000000000000']}},
}


def policy_output(root: Path, name: str, resources=None, examined=None, region: str = '') -> None:
    """A policy's Custodian output dir: resources.json when it ran to the end, and the
    wrapper's leftsize-examined.json."""
    d = root / region / name if region else root / name
    d.mkdir(parents=True)
    (d / 'metadata.json').write_text('{}')
    if resources is not None:
        (d / 'resources.json').write_text(json.dumps(resources))
    if examined is not None:
        (d / 'leftsize-examined.json').write_text(json.dumps({'examined': examined}))


class TestRecordCoverage:

    def test_lists_policies_that_ran_with_their_scope_and_examined_count(self, tmp_path):
        policy_output(tmp_path, 'leftsize-unattached-ebs-volume', resources=[{'VolumeId': 'vol-1'}], examined=12)
        policy_output(tmp_path, 'leftsize-unused-elastic-ip', resources=[], examined=3)
        config = dict(AWS_CONFIG)
        run.record_coverage(str(tmp_path), config, failed=set(), degraded=False)
        assert config['scan_coverage'] == [
            {'Policy': 'leftsize-unattached-ebs-volume', 'Scope': 'aws:account/123456789012/region/eu-west-1', 'Examined': 12},
            {'Policy': 'leftsize-unused-elastic-ip', 'Scope': 'aws:account/123456789012/region/eu-west-1', 'Examined': 3},
        ]

    def test_leaves_out_policies_that_failed_or_did_not_finish(self, tmp_path):
        policy_output(tmp_path, 'leftsize-ok', resources=[], examined=1)
        policy_output(tmp_path, 'leftsize-raised', resources=None)  # exception: no resources.json
        policy_output(tmp_path, 'leftsize-named-in-stderr', resources=[], examined=5)
        config = dict(AWS_CONFIG)
        run.record_coverage(str(tmp_path), config, failed={'leftsize-named-in-stderr'}, degraded=False)
        assert [c['Policy'] for c in config['scan_coverage']] == ['leftsize-ok']

    def test_one_entry_per_region_of_a_multi_region_run(self, tmp_path):
        policy_output(tmp_path, 'leftsize-idle-nat-gateway', resources=[], examined=2, region='eu-west-1')
        policy_output(tmp_path, 'leftsize-idle-nat-gateway', resources=[], examined=0, region='us-east-1')
        config = dict(AWS_CONFIG)
        run.record_coverage(str(tmp_path), config, failed=set(), degraded=False)
        assert [(c['Scope'], c['Examined']) for c in config['scan_coverage']] == [
            ('aws:account/123456789012/region/eu-west-1', 2),
            ('aws:account/123456789012/region/us-east-1', 0),
        ]

    def test_azure_covers_the_subscription_lowercased(self, tmp_path):
        policy_output(tmp_path, 'leftsize-unattached-disk', resources=[], examined=7)
        config = dict(AZURE_CONFIG)
        run.record_coverage(str(tmp_path), config, failed=set(), degraded=False)
        assert config['scan_coverage'][0]['Scope'] == 'azure:subscription/abcdef00-0000-0000-0000-000000000000'

    def test_examined_is_null_without_the_wrappers_count(self, tmp_path):
        policy_output(tmp_path, 'leftsize-unattached-disk', resources=[])
        config = dict(AZURE_CONFIG)
        run.record_coverage(str(tmp_path), config, failed=set(), degraded=False)
        assert config['scan_coverage'][0]['Examined'] is None

    def test_marks_a_run_with_access_warnings_as_degraded(self, tmp_path):
        policy_output(tmp_path, 'leftsize-unencrypted-ebs', resources=[], examined=4)
        config = dict(AWS_CONFIG)
        run.record_coverage(str(tmp_path), config, failed=set(), degraded=True)
        assert config['scan_coverage'][0]['Degraded'] is True

    def test_no_coverage_for_cloudflare_or_an_unknown_account(self, tmp_path):
        policy_output(tmp_path, 'leftsize-cloudflare-zone-dnssec-disabled', resources=[], examined=3)
        cloudflare = {'cloud_provider': 'cloudflare'}
        run.record_coverage(str(tmp_path), cloudflare, failed=set(), degraded=False)
        no_account = {'cloud_provider': 'aws', 'targets': {'aws': {}}}
        run.record_coverage(str(tmp_path), no_account, failed=set(), degraded=False)
        assert cloudflare['scan_coverage'] == [] and no_account['scan_coverage'] == []

    @pytest.mark.parametrize('stderr,degraded', [
        ("custodian.resources.s3:WARNING Bucket:x unable to invoke method:GetBucketEncryption error:AccessDenied", True),
        ("An error occurred (UnauthorizedOperation) when calling the DescribeVolumes operation", True),
        ("(AuthorizationFailed) The client does not have authorization", True),
        ("custodian.policy:INFO policy:leftsize-x resource:ebs region:eu-west-1 count:0 time:0.10", False),
    ])
    def test_degraded_pattern(self, stderr, degraded):
        assert bool(run.DEGRADED_SCAN_PATTERN.search(stderr)) is degraded


class TestExaminedCount:

    def _manager(self, written):
        manager = SimpleNamespace(filters=[], log=Mock())
        output = SimpleNamespace(write_file=lambda name, data: written.append((name, json.loads(data))))
        manager.ctx = SimpleNamespace(policy=SimpleNamespace(resource_manager=manager), output=output,
                                      tracer=SimpleNamespace(subsegment=None))
        return manager

    def test_records_the_policys_own_unfiltered_count_once(self, monkeypatch):
        written = []
        manager = self._manager(written)
        monkeypatch.setattr(leftsize_custodian, '_filter_resources', lambda self, resources, event=None: resources[:1])
        assert leftsize_custodian._record_examined(manager, [{}, {}, {}]) == [{}]
        leftsize_custodian._record_examined(manager, [{}])
        assert written == [('leftsize-examined.json', {'examined': 3})]

    def test_ignores_managers_of_related_resources(self, monkeypatch):
        written = []
        policy_manager = self._manager(written)
        related = SimpleNamespace(ctx=policy_manager.ctx)
        monkeypatch.setattr(leftsize_custodian, '_filter_resources', lambda self, resources, event=None: resources)
        leftsize_custodian._record_examined(related, [{}, {}])
        assert written == []

    def test_is_installed_on_every_resource_manager(self):
        from c7n.manager import ResourceManager
        assert ResourceManager.filter_resources is leftsize_custodian._record_examined


class TestPayload:

    @patch('run.requests.post')
    def test_sends_scan_start_and_coverage(self, mock_post):
        mock_post.return_value = Mock(status_code=202, json=Mock(return_value={}))
        coverage = [{'Policy': 'leftsize-unattached-disk', 'Scope': 'azure:subscription/abc', 'Examined': 2}]
        config = {
            'output': {'backend_url': 'https://api.leftsize.com', 'installation_id': '1',
                       'repository_token': '12345678-1234-1234-1234-123456789012'},
            'scan_started_at': 1_900_000_000,
            'scan_coverage': coverage,
        }
        assert run.submit_findings([], config)['submitted'] is True
        payload = mock_post.call_args.kwargs['json']
        assert payload['FindingGroups'] == []
        assert payload['ScanStartedAt'] == 1_900_000_000
        assert payload['Coverage'] == coverage
