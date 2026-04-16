# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
