# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.30] - 2026-10-31

### Fixed
- `LEFTSIZE_DEBUG` on its own now shows Custodian's output and the API response, as documented. Before, it also needed `verbose: true`.
- Resources that carry a `VpcId` but aren't VPCs, such as RDS snapshots, are no longer reported under their VPC's ID. Two orphaned RDS snapshots in one VPC showed up as one resource with the VPC's ARN.
- A resource is listed once per issue group. Custodian lists S3 buckets again in every region of a multi-region scan, and those findings share one scope.
- Azure currency detection uses the subscription being scanned (Custodian's session, the `azure/login` subscription) when `azure-subscription-ids` isn't set, instead of the first subscription the login can see.

### Changed
- Lambda runtime rule: `python3.10` is deprecated as of 2026-10-31; `nodejs22.x` (deprecated 2027-04-30) is now flagged.
- Amazon Pinpoint and AKS Azure Linux 2.0 rule descriptions describe their October 2026 dates in the past tense.

## [1.0.29] - 2026-10-31

### Changed
- **A scan that can't run now fails the step** instead of finishing green with 0 findings. Before, missing or expired credentials, a policy file that timed out or a broken install each looked like a clean account. Now the step exits 1 when no policy file could run; AWS credentials are checked with `sts:GetCallerIdentity` (a failure is fatal; it was a warning); for Azure a token is requested up front and a failure is logged as a warning (creating the credential alone always succeeded). Scans that were silently broken will turn red, which is the point.
- Checks that fail while the rest of the scan runs (missing read permissions, throttling, a lookup that failed) are listed in the job summary under **Incomplete scan** and in the new `failed-policies` output, instead of only in the log.
- `leftsize-public-s3-access` reports no bucket when the account-level Block Public Access setting can't be read, instead of flagging every bucket without its own block.
- Only the **names** of resource tags are sent (`tagKeys`), not their values: tag values can hold connection strings or e-mail addresses, and LeftSize doesn't use them. Environment detection still reads tag values, on the runner.
- Policy files of one scan share a Custodian resource cache (new per scan, 60 minutes): policies for the same resource type no longer list and augment it again (S3 was listed 7 times, RDS 18). Scans of large accounts make far fewer API calls.
- The policies' `actions:` blocks are removed before Custodian runs, on top of `--dry-run`, so no code path can change a resource.
- `verbose: true` turns on debug logging for LeftSize only; botocore, urllib3 and Azure SDK logs stay at warning level (their debug output includes request signing details).
- `backend-url` must be an https URL on a LeftSize domain (`leftsize.com`, `leftsize.io`), in scan and stats mode: the repository token is sent to it.

### Fixed
- Submitting findings retries network errors, timeouts and server errors (3 attempts, one `ScanId` for all of them) and waits up to 60 seconds per attempt. Client errors aren't retried. The daily submission limit (HTTP 429) is reported in the summary and keeps the step green, like the repository limit.
- `findings-json` is an empty array when it would exceed 512 KB (GitHub's output limit is 1 MB); the new `findings-file` output always has every finding. `limit-exceeded` is now a declared output.
- `cloud-provider` accepts any case (`AWS`), and an unknown `mode` is an error instead of running a scan.
- Text from the API in the job summary (rule names, links) is escaped; links only point to LeftSize domains.

### Security
- Third-party actions are pinned by commit SHA (`actions/setup-python`, `actions/cache`, and the image workflow's actions). `azure-identity` and `azure-mgmt-resource` are pinned to the versions c7n-azure pins; pytest is no longer installed on customer runners (`requirements-dev.txt`).
- Docker image (not used by the action itself): base image pinned by digest, unused Azure CLI (`curl | bash`) and AWS CLI downloads removed, `stats.py` included so stats mode works in the image.

## [1.0.28] - 2026-10-29

### Added
- Fields the LeftSize worker needs for savings estimates from list prices: EC2 platform, RDS Multi-AZ and license model, Azure VM OS type, public IP SKU, App Service Plan kind, snapshot SKU and type (incremental or full), and AKS node pools (`vmSize:count:os`).

## [1.0.27] - 2026-10-28

### Added
- The AWS account name (`account:GetAccountInformation` for the scanned account, read-only and part of ReadOnlyAccess) is used as an environment signal next to the account alias. In AWS Organizations this is the member account's name, such as `shop-acc`; most accounts have no alias.

## [1.0.26] - 2026-10-28

### Added
- Environment detection also uses the account a resource lives in, for setups with one account per environment: the AWS account alias (one read-only `iam:ListAccountAliases` call per scan) and the Azure subscription name and tags (one Resource Graph query per subscription). It is the weakest signal: tags and names of the resource itself come first, and any production signal still wins.

## [1.0.25] - 2026-10-27

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
