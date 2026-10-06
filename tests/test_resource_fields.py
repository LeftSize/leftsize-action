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


class TestDerivedFields:

    def test_aks_counts_sizes_and_retiring_pools(self):
        r = {"properties": {"agentPoolProfiles": [
            {"name": "sys", "vmSize": "Standard_DS2_v2", "count": 3, "mode": "System"},
            {"name": "work", "vmSize": "Standard_D4s_v5", "count": 2, "mode": "User"},
            {"name": "old", "vmSize": "Standard_D8s_v3", "count": 1, "mode": "User"},
        ]}}
        f = extract_resource_fields(r, "azure.aks")
        assert f["nodeCount"] == 6
        assert f["vmSizes"] == "Standard_D4s_v5, Standard_D8s_v3, Standard_DS2_v2"
        assert f["retiringNodePools"] == [
            "sys: Standard_DS2_v2 × 3 nodes (System) — D/Ds/Dv2/Dsv2/Ls retires 2028-05-01",
            "old: Standard_D8s_v3 × 1 nodes (User) — Dv3/Dsv3/Ev3/Esv3 retires 2029-11-15",
        ]
        assert f["retirementDate"] == "2028-05-01"

    def test_aks_without_retiring_pools(self):
        r = {"properties": {"agentPoolProfiles": [{"name": "a", "vmSize": "Standard_D4s_v5", "count": 2}]}}
        f = extract_resource_fields(r, "azure.aks")
        assert "retiringNodePools" not in f and "retirementDate" not in f

    def test_vmss_retirement(self):
        r = {"sku": {"name": "Standard_F4s_v2", "capacity": 4},
             "properties": {"orchestrationMode": "Uniform", "upgradePolicy": {"mode": "Manual"}}}
        assert extract_resource_fields(r, "azure.vmss") == {
            "vmSize": "Standard_F4s_v2", "capacity": 4, "orchestrationMode": "Uniform",
            "upgradePolicyMode": "Manual", "retiringSeries": "Av2/Amv2/Bv1/F/Fs/Fsv2/G/Gs/Lsv2",
            "retirementDate": "2028-11-15"}

    def test_load_balancer_counts_keep_zero(self):
        r = {"properties": {"backendAddressPools": [], "frontendIPConfigurations": [
            {"properties": {"publicIPAddress": {"id": "pip"}}}, {"properties": {"privateIPAddress": "10.0.0.4"}}]}}
        assert extract_resource_fields(r, "azure.loadbalancer") == {"backendPoolCount": 0, "publicIpCount": 1}

    def test_asg_fields(self):
        r = {"MinSize": 3, "MaxSize": 10, "DesiredCapacity": 4,
             "Instances": [{"InstanceType": "m5.large"}, {"InstanceType": "m5.xlarge"}]}
        assert extract_resource_fields(r, "aws.asg") == {
            "minSize": 3, "maxSize": 10, "desiredCapacity": 4,
            "instanceTypes": "m5.large, m5.xlarge"}

    def test_average_cpu_from_metrics_annotation(self):
        r = {"c7n.metrics": {"AWS/EC2.CPUUtilization.Average.14": [{"Average": 20.0}, {"Average": 30.0}]}}
        assert extract_resource_fields(r, "aws.ec2") == {"avgCpuPercent": 25.0}
        assert extract_resource_fields({}, "aws.ec2") == {}

    def test_vm_size_retirement_matches_policy_groups(self):
        assert run.vm_size_retirement("Standard_M192ims_v2") == ("M192i_v2", "2027-03-31")
        assert run.vm_size_retirement("Standard_HB120-96rs_v2") == ("NP/HC/HBv2", "2027-05-31")
        assert run.vm_size_retirement("Standard_DS11-1_v2") == ("D/Ds/Dv2/Dsv2/Ls", "2028-05-01")
        assert run.vm_size_retirement("Standard_B2ms") == ("Av2/Amv2/Bv1/F/Fs/Fsv2/G/Gs/Lsv2", "2028-11-15")
        assert run.vm_size_retirement("Standard_E4-2s_v3") == ("Dv3/Dsv3/Ev3/Esv3", "2029-11-15")
        for current in ("Standard_D4s_v5", "Standard_B2s_v2", "Standard_D4s_v7", None):
            assert run.vm_size_retirement(current) is None


def test_vm_retirement_table_matches_policies():
    """VM_SIZE_RETIREMENTS must classify sizes exactly like the leftsize-vm-*-retirement* policies."""
    import re
    from pathlib import Path
    import yaml
    policies = {p["name"]: p for p in yaml.safe_load(
        (Path(run.__file__).parent / "policies" / "azure-deprecations.yml").read_text())["policies"]}
    by_label = {label: pattern for label, pattern, _ in run.VM_SIZE_RETIREMENTS}
    pairs = {
        "leftsize-vm-hpc-fpga-retirement-2027": "NP/HC/HBv2",
        "leftsize-vm-series-retirement-2028-05": "D/Ds/Dv2/Dsv2/Ls",
        "leftsize-vm-series-retirement-2028-11": "Av2/Amv2/Bv1/F/Fs/Fsv2/G/Gs/Lsv2",
        "leftsize-vm-v3-series-retirement-2029": "Dv3/Dsv3/Ev3/Esv3",
    }
    for name, label in pairs.items():
        size_filter = next(f for f in policies[name]["filters"]
                           if isinstance(f, dict) and f.get("key") == "properties.hardwareProfile.vmSize")
        assert by_label[label].pattern.replace("\\\\", "\\") == size_filter["value"], name
    m192 = next(f for f in policies["leftsize-vm-m192i-v2-retirement"]["filters"]
                if isinstance(f, dict) and f.get("key") == "properties.hardwareProfile.vmSize")["value"]
    assert all(by_label["M192i_v2"].match(size) for size in m192)
    assert not by_label["M192i_v2"].match("standard_m192is_v3")
