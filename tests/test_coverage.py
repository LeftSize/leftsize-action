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


def policy_output(root: Path, name: str, resources=None, examined=None, region: str = '', subscription=None,
                  aws=('123456789012', None)) -> None:
    """A policy's Custodian output dir: resources.json when it ran to the end, and the
    wrapper's leftsize-examined.json."""
    d = root / region / name if region else root / name
    d.mkdir(parents=True)
    (d / 'metadata.json').write_text('{}')
    if resources is not None:
        (d / 'resources.json').write_text(json.dumps(resources))
    if examined is not None or subscription is not None:
        info = {'examined': examined}
        if subscription:
            info['subscription'] = subscription
        elif aws:
            info['account'], info['region'] = aws[0], aws[1] or region or 'eu-west-1'
        (d / 'leftsize-examined.json').write_text(json.dumps(info))


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

    def test_azure_covers_the_subscription_custodian_used_lowercased(self, tmp_path):
        # Configured A first, but Custodian's session used B (AZURE_SUBSCRIPTION_ID)
        policy_output(tmp_path, 'leftsize-unattached-disk', resources=[], examined=7,
                      subscription='BBBBBBBB-0000-0000-0000-000000000000')
        config = dict(AZURE_CONFIG)
        run.record_coverage(str(tmp_path), config, failed=set(), degraded=False)
        assert config['scan_coverage'][0]['Scope'] == 'azure:subscription/bbbbbbbb-0000-0000-0000-000000000000'

    def test_no_azure_coverage_without_the_subscription_custodian_used(self, tmp_path):
        policy_output(tmp_path, 'leftsize-unattached-disk', resources=[], examined=7)
        config = dict(AZURE_CONFIG)
        run.record_coverage(str(tmp_path), config, failed=set(), degraded=False)
        assert config['scan_coverage'] == []

    def test_no_coverage_without_the_wrappers_record(self, tmp_path):
        policy_output(tmp_path, 'leftsize-unattached-ebs-volume', resources=[])
        config = dict(AWS_CONFIG)
        run.record_coverage(str(tmp_path), config, failed=set(), degraded=False)
        assert config['scan_coverage'] == []

    def test_marks_a_policy_whose_resources_had_denied_reads_as_degraded(self, tmp_path):
        policy_output(tmp_path, 'leftsize-unencrypted-s3', resources=[], examined=4)
        info_file = tmp_path / 'leftsize-unencrypted-s3' / 'leftsize-examined.json'
        info_file.write_text(json.dumps({**json.loads(info_file.read_text()), 'denied': 1}))
        config = dict(AWS_CONFIG)
        run.record_coverage(str(tmp_path), config, failed=set(), degraded=False)
        assert config['scan_coverage'][0]['Degraded'] is True

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
        ("2026-11-13 21:49:35,1: custodian.resources.s3:WARNING Bucket:x unable to invoke method:GetBucketPolicy error:Throttling", True),
        ("2026-11-13 21:49:35,1: custodian.azure.query:WARNING Child enumeration failed for vault-1. (TooManyRequests)", True),
        ("2026-11-13 21:49:35,1: custodian.leftsize.azure:WARNING Could not list the API keys of ai-1 (HTTP 500): Internal error", True),
        ("2026-11-13 21:49:35,1: custodian.cloudflare:WARNING account 123 skipped", True),
        # A policy that raised: excluded from coverage, doesn't degrade the others
        ("2026-11-13 21:49:35,1: custodian.commands:ERROR Error while executing policy leftsize-cloudsearch-maintenance, continuing\n"
         "botocore.exceptions.ClientError: An error occurred (AccessDeniedException) when calling the ListDomainNames operation", False),
        ("2026-11-13 21:49:35,1: custodian.policy:INFO policy:leftsize-x resource:ebs region:eu-west-1 count:0 time:0.10", False),
        ("2026-11-13 21:49:35,1: custodian.cloudflare:INFO 0 zones: the token may lack Zone Read", False),
    ])
    def test_degraded_warning(self, stderr, degraded):
        assert run.degraded_warning(stderr) is degraded


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
        assert leftsize_custodian._record_examined(manager, [{}, {'c7n:DeniedMethods': ['GetBucketEncryption']}, {}]) == [{}]
        leftsize_custodian._record_examined(manager, [{}])
        assert written == [('leftsize-examined.json', {'examined': 3, 'denied': 1})]

    def test_counts_denied_reads_that_filters_add(self, monkeypatch):
        written = []
        manager = self._manager(written)

        def check_public_block(self, resources, event=None):
            resources[0]['c7n:DeniedMethods'] = ['GetPublicAccessBlock']
            return []
        monkeypatch.setattr(leftsize_custodian, '_filter_resources', check_public_block)
        leftsize_custodian._record_examined(manager, [{}, {}])
        assert written == [('leftsize-examined.json', {'examined': 2, 'denied': 1})]

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


class TestScannedWhere:

    def test_records_the_subscription_of_an_azure_managers_session(self, monkeypatch):
        import c7n.utils
        AzureManager = type('AzureManager', (), {'__module__': 'c7n_azure.resources.disk'})
        manager = AzureManager()
        manager.session_factory = object()
        monkeypatch.setattr(c7n.utils, 'local_session',
                            lambda factory: SimpleNamespace(get_subscription_id=lambda: 'sub-b'))
        assert leftsize_custodian._scanned_where(manager) == {'subscription': 'sub-b'}

    def test_nothing_for_other_providers_or_when_the_lookup_fails(self, monkeypatch):
        import c7n.utils
        assert leftsize_custodian._scanned_where(SimpleNamespace()) == {}
        AzureManager = type('AzureManager', (), {'__module__': 'c7n_azure.resources.disk'})
        manager = AzureManager()
        manager.session_factory = object()

        def boom(factory):
            raise RuntimeError('no credentials')
        monkeypatch.setattr(c7n.utils, 'local_session', boom)
        assert leftsize_custodian._scanned_where(manager) == {}


class TestAwsScope:

    def test_uses_the_region_custodian_ran_in_not_the_assumed_default(self, tmp_path):
        # No aws-regions input: LeftSize assumes eu-west-1, boto's default was us-west-2
        policy_output(tmp_path, 'leftsize-unattached-ebs-volume', resources=[], examined=3, aws=('123456789012', 'us-west-2'))
        config = dict(AWS_CONFIG)
        run.record_coverage(str(tmp_path), config, failed=set(), degraded=False)
        assert config['scan_coverage'][0]['Scope'] == 'aws:account/123456789012/region/us-west-2'

    def test_no_coverage_when_the_account_differs_or_is_unknown(self, tmp_path):
        policy_output(tmp_path, 'leftsize-a', resources=[], examined=3, aws=('999999999999', 'eu-west-1'))
        policy_output(tmp_path, 'leftsize-b', resources=[], examined=3, aws=None)
        config = dict(AWS_CONFIG)
        run.record_coverage(str(tmp_path), config, failed=set(), degraded=False)
        assert config['scan_coverage'] == []

    def test_wrapper_records_an_aws_managers_account_and_region(self):
        AwsManager = type('AwsManager', (), {'__module__': 'c7n.resources.ebs'})
        manager = AwsManager()
        manager.config = SimpleNamespace(region='us-west-2', account_id='123456789012')
        assert leftsize_custodian._scanned_where(manager) == {'region': 'us-west-2', 'account': '123456789012'}
        manager.config = SimpleNamespace(region='', account_id='123456789012')
        assert leftsize_custodian._scanned_where(manager) == {}


class TestAutoCloseInput:

    @pytest.mark.parametrize('value,expected', [(None, None), ('true', None), ('false', False), (' FALSE ', False)])
    @patch('run.requests.post')
    def test_sends_auto_close_false_only_when_turned_off(self, mock_post, monkeypatch, value, expected):
        if value is None:
            monkeypatch.delenv('LEFTSIZE_AUTO_CLOSE', raising=False)
        else:
            monkeypatch.setenv('LEFTSIZE_AUTO_CLOSE', value)
        mock_post.return_value = Mock(status_code=202, json=Mock(return_value={}))
        config = {'output': {'backend_url': 'https://api.leftsize.com', 'installation_id': '1',
                             'repository_token': '12345678-1234-1234-1234-123456789012'}}
        run.submit_findings([], config)
        assert mock_post.call_args.kwargs['json'].get('AutoClose') is expected
