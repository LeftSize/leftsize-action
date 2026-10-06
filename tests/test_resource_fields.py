"""Tests for per-resource-type template fields, policy severity and partial custodian failures."""
import json
import subprocess
from unittest import mock

import run
from run import extract_resource_fields, extract_resource_metadata, read_policy_info


class TestExtractResourceFields:

    def test_aws_rds_fields(self):
        r = {"Engine": "mysql", "EngineVersion": "8.0.35", "DBInstanceClass": "db.r6g.large"}
        assert extract_resource_fields(r, "aws.rds") == {
            "engine": "mysql", "engineVersion": "8.0.35", "instanceClass": "db.r6g.large"}

    def test_nested_and_list_paths(self):
        r = {"WorkspaceProperties": {"OperatingSystemName": "WINDOWS_SERVER_2019", "Protocols": ["PCOIP", "WSP"]}}
        fields = extract_resource_fields(r, "aws.workspaces")
        assert fields["operatingSystem"] == "WINDOWS_SERVER_2019"
        assert fields["protocol"] == "PCOIP, WSP"

    def test_fields_are_scoped_to_resource_type(self):
        # 'Name' maps to clusterName for EMR only, not for every resource with a Name
        assert extract_resource_fields({"Name": "x"}, "aws.emr") == {"clusterName": "x"}
        assert extract_resource_fields({"Name": "x"}, "aws.s3") == {}
        assert extract_resource_fields({"Name": "x"}, None) == {}

    def test_aks_node_pools_are_a_list_of_strings(self):
        r = {"properties": {"kubernetesVersion": "1.31.9", "agentPoolProfiles": [
            {"name": "sys", "osType": "Linux", "osSKU": "AzureLinux", "orchestratorVersion": "1.31.9",
             "nodeImageVersion": "AKSAzureLinux-V2gen2-202512.06.0"},
            {"name": "win", "osType": "Windows"},
        ]}}
        fields = extract_resource_fields(r, "azure.aks")
        assert fields["kubernetesVersion"] == "1.31.9"
        assert fields["nodePools"] == [
            "sys: Linux/AzureLinux, k8s 1.31.9, image AKSAzureLinux-V2gen2-202512.06.0",
            "win: Windows/-, k8s -, image -",
        ]

    def test_webapp_runtime_from_configuration_annotation(self):
        r = {"c7n:configuration": {"linuxFxVersion": "DOTNET|8.0"}}
        assert extract_resource_fields(r, "azure.webapp") == {"runtime": "DOTNET|8.0"}

    def test_metadata_includes_fields_without_overwriting_builtin_keys(self):
        rid = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct"
        r = {"kind": "Storage", "sku": {"name": "Standard_LRS"}, "location": "westeurope", "properties": {}}
        md = extract_resource_metadata(r, rid, "azure.storage")
        assert md["kind"] == "Storage"
        assert md["skuName"] == "Standard_LRS"


class TestReadPolicyInfo:

    def _write(self, tmp_path, policy):
        (tmp_path / "metadata.json").write_text(json.dumps({"policy": policy}))
        return tmp_path

    def test_reads_severity_and_resource_type(self, tmp_path):
        d = self._write(tmp_path, {"name": "p", "resource": "azure.vm", "metadata": {"severity": "High"}})
        assert read_policy_info(d) == {"severity": "high", "resource_type": "azure.vm"}

    def test_bare_aws_resource_names_get_prefix(self, tmp_path):
        d = self._write(tmp_path, {"name": "p", "resource": "ec2"})
        assert read_policy_info(d) == {"severity": None, "resource_type": "aws.ec2"}

    def test_invalid_severity_is_ignored(self, tmp_path):
        d = self._write(tmp_path, {"name": "p", "resource": "aws.rds", "metadata": {"severity": "urgent"}})
        assert read_policy_info(d)["severity"] is None

    def test_missing_metadata_file(self, tmp_path):
        assert read_policy_info(tmp_path) == {"severity": None, "resource_type": None}


class TestPartialCustodianFailure:

    def _run(self, tmp_path, returncode):
        policy_file = tmp_path / "p.yml"
        policy_file.write_text("policies: []\n")
        completed = subprocess.CompletedProcess([], returncode, stdout="", stderr=" - leftsize-broken\n")
        with mock.patch.object(run.subprocess, "run", return_value=completed), \
             mock.patch.object(run, "parse_custodian_output", return_value=[{"ruleId": "leftsize-ok"}]) as parse:
            findings = run.execute_single_policy_file(str(policy_file), {"cloud_provider": "azure"})
        return findings, parse

    def test_exit_code_2_keeps_results_of_other_policies(self, tmp_path):
        findings, parse = self._run(tmp_path, 2)
        assert parse.called
        assert findings == [{"ruleId": "leftsize-ok"}]

    def test_fatal_exit_code_returns_nothing(self, tmp_path):
        findings, parse = self._run(tmp_path, 1)
        assert not parse.called
        assert findings == []
