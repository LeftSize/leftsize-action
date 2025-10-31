# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Security Features

### Input Validation
- All user inputs are validated with strict patterns
- Installation IDs must be numeric
- Repository tokens must be valid GUIDs
- Backend URLs must use HTTPS
- Azure subscription IDs validated as GUIDs
- AWS regions validated against proper format
- Policy names restricted to alphanumeric characters

### Secure Defaults
- Default backend URL: `https://api.leftsize.io`
- HTTPS-only communication
- SSRF protection (blocks metadata services, localhost, private IPs)
- Maximum input length limits

### Dependency Security
- All Python dependencies pinned to exact versions
- Regular security updates via Dependabot (when available)
- No arbitrary package installation

### Data Protection
- Sensitive data sanitized from logs
- Resource details not logged in normal operation
- Only counts and summaries logged

### Safe Operations
- 100% read-only Cloud Custodian policies
- No destructive operations (delete, stop, terminate)
- Only tagging and marking operations

## Reporting a Vulnerability

If you discover a security vulnerability, please email: **security@leftsize.io**

**Please do NOT** create a public GitHub issue for security vulnerabilities.

### What to include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Time:
- Initial response: Within 48 hours
- Status update: Within 1 week
- Fix timeline: Depends on severity (Critical: days, High: weeks, Medium: months)

## Security Best Practices for Users

### Repository Configuration
1. **Use private repositories** when possible
2. **Limit workflow permissions** to minimum required
3. **Use OIDC** for cloud authentication (no long-lived secrets)
4. **Rotate repository tokens** regularly
5. **Review workflow runs** periodically

### Secrets Management
```yaml
# ✅ Good - Secrets in GitHub Secrets
secrets:
  LEFTSIZE_INSTALLATION_ID: ${{ secrets.LEFTSIZE_INSTALLATION_ID }}
  LEFTSIZE_REPOSITORY_TOKEN: ${{ secrets.LEFTSIZE_REPOSITORY_TOKEN }}

# ❌ Bad - Hardcoded secrets
installation-id: "12345"
repository-token: "abc-123-def"
```

### OIDC Setup (Recommended)
```yaml
permissions:
  id-token: write  # Required for OIDC
  contents: read

jobs:
  leftsize-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: azure/login@v1
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
```

### Cloud Permissions
- **Azure**: Reader + Monitoring Reader (minimum)
- **AWS**: ReadOnlyAccess policy (minimum)
- Create separate service principals per environment
- Follow principle of least privilege

## Known Limitations

### Platform Support
- Linux runners only (`ubuntu-latest`, `ubuntu-20.04`, `ubuntu-22.04`)
- Not compatible with Windows or macOS runners (Docker limitation)

### Data Exposure
- `findings-json` output contains resource metadata
- Visible in GitHub Actions logs
- Use private repositories for sensitive infrastructure

### Backend URL
- Users can specify custom backend URLs (their choice)
- Action validates HTTPS and blocks obvious SSRF attempts
- Users responsible for ensuring destination is trusted

## Security Audit History

- **2025-10-31**: Initial security review completed
- **2025-10-31**: Input validation and dependency pinning implemented

## Security Contacts

- **Security Issues**: security@leftsize.io
- **General Support**: support@leftsize.io
- **Documentation**: https://docs.leftsize.io

## Acknowledgments

We appreciate the security research community and welcome responsible disclosure of vulnerabilities.
