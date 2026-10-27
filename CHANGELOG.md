# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- With `LEFTSIZE_DEBUG`, Custodian's own log (per-policy counts, access-denied warnings) is now shown for policy files that succeed too, not only for failed ones.

## [1.0.24] - 2026-10-27

### Fixed
- `public-s3-access` flagged every bucket in accounts that block public access at account level. Cloud Custodian's check only reads the bucket-level setting; the account-level Block Public Access setting is now read too (one read-only `s3:GetAccountPublicAccessBlock` call per account, covered by ReadOnlyAccess) and a setting counts as on when either level turns it on. Buckets whose own setting can't be read are skipped. Issues list the settings that are off on both levels.

## [1.0.23] - 2026-10-27

### Added
- Environment detection per resource: environment tags on the resource or its Azure resource group, then words in the resource, parent resource (such as a database's server) or resource group name (`prod`, `acc`, `uat`, `test`, `dev`, `staging`, …), then a one-letter resource group suffix (`-P`, `-A`, `-T`, `-D`). Any production signal wins; resources without clear non-production evidence count as unknown. Every finding carries `environment` and `environmentSource`, and issues show them.
- `environment-name` accepts `name=environment` pairs for subscriptions with several environments. Values that are not an environment (such as the onboarding matrix label `MAIN`) are ignored instead of overriding detection.
- Azure resource group tags are read with one Resource Graph query per subscription, using the same Azure sign-in as the scan (Reader is enough).

### Changed
- The non-production rules (`vm-scheduled-shutdown-missing`, `aks-dev-clusters-always-running`, `sql-business-critical-nonprod`, `ec2-scheduled-shutdown-missing`, `rds-multiaz-nonprod`) use this detection instead of tags only. `rds-multiaz-nonprod` no longer matches name fragments such as `devices` or `latest`.

## [1.0.22] - 2026-10-27

### Removed
- `orphaned-kubernetes-resources`, `multi-az-nonprod-ec2` and `s3-intelligent-tiering-missing`: they matched every AKS cluster, every non-prod EC2 instance and nearly every S3 bucket.

### Changed
- `inactive-eks-cluster` now only reports clusters with no managed node groups, no Fargate profiles and no running EC2 nodes tagged for the cluster (read-only `eks:ListNodegroups`, `eks:ListFargateProfiles`, `ec2:DescribeInstances`). Clusters younger than 7 days and EKS Auto Mode clusters are skipped.
- `overprovisioned-aks-nodes` now uses the AKS node CPU and memory platform metrics (7-day average under 20% CPU and 40% memory).
- `sql-database-dtu-model` is now a cost rule (Free) for Standard S3+ and Premium databases only.
- `standard-lrs-attached-disk` is now a governance rule (reliability, not a saving).
- `s3-bucket-logging-disabled` skips log destination buckets and has severity low.
- `orphaned-snapshots` skips snapshots made by the AKS disk CSI driver (Kubernetes VolumeSnapshots, e.g. Velero backups).
- `unencrypted-disks` (customer-managed key check): accurate description, severity low; all managed disks are encrypted at rest.
- `vm-scheduled-shutdown-missing` now skips VMs with an enabled auto-shutdown schedule (one read-only Resource Graph query per subscription, covered by Reader). If the query fails, no VM is reported.

## [1.0.3] - 2026-04-16

### Security
- Removed Cloud Custodian stdout/stderr from default logs; gate verbose output behind `LEFTSIZE_DEBUG`.
- Removed backend response body from default logs.
- Narrowed subprocess environment passed to Custodian to an allow-list (no GitHub/LeftSize secrets propagated).

### Docs
- README examples now show a minimum `permissions:` block.

## [1.0.0] - 2025-10-29

### Added
- Initial release of LeftSize GitHub Action
- Support for Azure cloud provider
- Support for AWS cloud provider
- OIDC authentication for both Azure and AWS
- Include/exclude policy filtering
- Multi-subscription/multi-region scanning
- Custom policy support
- GitHub Actions outputs (findings-count, findings-submitted, findings-json)
- Comprehensive README with setup guides
- Safe, read-only scanning (100% non-destructive)

### Policies Included
#### Azure
- azure-cost-optimization.yml (idle VMs, unattached disks, unused IPs, App Service Plans, Load Balancers)
- azure-governance.yml (security groups, tagging, encryption)
- azure-deprecations.yml (deprecated services)
- azure-aks-optimization.yml (AKS cost optimization)

#### AWS
- aws-cost-optimization.yml (idle instances, unattached volumes, unused IPs, snapshots)
- aws-governance.yml (security groups, tagging, encryption)

[1.0.0]: https://github.com/leftsize/leftsize-action/releases/tag/v1.0.0
