# LeftSize: Dependabot for cloud waste

LeftSize scans your AWS and Azure accounts with read-only access and opens **GitHub issues** for idle and orphaned resources, upcoming service retirements, and security and governance gaps. Each issue lists the affected resources, the estimated impact and the fix, so the team that owns the resources can act on it like any other issue.

This repository is the open-source (MIT) GitHub Action that runs the scan. It uses [Cloud Custodian](https://github.com/cloud-custodian/cloud-custodian) under the hood and runs on **your** GitHub Actions runner: cloud credentials never leave it.

- **Website:** [leftsize.com](https://leftsize.com)
- **Rule catalog:** [leftsize.com/rules](https://leftsize.com/rules/): every check, what it detects and how to fix it
- **Install:** [LeftSize GitHub App](https://github.com/apps/leftsize)
- **Compare:** [vs Azure Advisor, AWS Trusted Advisor, Infracost and Cloud Custodian](https://leftsize.com/compare/)

## What you get

A scheduled scan turns each finding group into an issue that is updated on every run. For example:

> **[COST] 3 idle VMs (≈ $350.40/mo)**
>
> We've identified **3** VMs with minimal activity (≤5% CPU over 7+ days), wasting **≈$350.40/month**.
>
> **Affected resources**
> - **`vm-build-agent-02`** in **rg-dev** (≈ $140.16/mo)
> - **`vm-test-runner`** in **rg-dev** (≈ $140.16/mo)
> - **`vm-demo-old`** in **rg-dev** (≈ $70.08/mo)
>
> **Quick fix:** `az vm deallocate --name "vm-build-agent-02" --resource-group "rg-dev"` …
>
> Comment `@leftsize explain`, `@leftsize howto`, `@leftsize script azure-cli`, `@leftsize impact`, `@leftsize alternatives`, `@leftsize snooze 14d` or `@leftsize ignore reason="..."` on the issue.

## Plans

| | Free | Team | Business |
|---|---|---|---|
| Repositories | 3 | 10 | Unlimited |
| Cost optimization rules (AWS + Azure) | ✅ All | ✅ All | ✅ All |
| Deprecation & retirement alerts | – | ✅ | ✅ |
| Security & governance rules | – | ✅ | ✅ |
| Support | Docs | Email | Priority email |
| Price per GitHub organization | $0 | $79/month or $790/year | $249/month or $2,490/year |

Early-access prices; see [leftsize.com/#pricing](https://leftsize.com/#pricing). To get a paid plan, contact [hi@leftsize.com](mailto:hi@leftsize.com).

## Features

- 🔍 **Read-only** - Scans with Reader / ReadOnlyAccess; never changes your infrastructure
- ☁️ **AWS and Azure** - One workflow for both clouds
- 🐙 **GitHub issues** - Findings land in the repository of the team that owns the resources
- 🔐 **OIDC** - Keyless sign-in from your runner; no cloud secrets stored by LeftSize
- 📅 **Retirements** - Retiring VM sizes, end-of-support runtimes and engines, with dates
- 🎯 **Customizable** - Include or exclude policy categories

## Quick Start

### Prerequisites

1. Install the [LeftSize GitHub App](https://github.com/apps/leftsize)
2. Complete onboarding to get your `installation-id` and `repository-token`
3. Configure cloud provider authentication (Azure or AWS)

### Basic Usage (Azure)

```yaml
name: LeftSize Cost Optimization Scan

on:
  schedule:
    - cron: '0 0 * * *'  # Daily at midnight
  workflow_dispatch:      # Manual trigger

permissions:
  id-token: write        # Required for OIDC
  contents: read

jobs:
  leftsize-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Azure Login (OIDC)
        uses: azure/login@v1
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
      
      - name: Run LeftSize Scan
        uses: leftsize/leftsize-action@v1
        with:
          installation-id: ${{ secrets.LEFTSIZE_INSTALLATION_ID }}
          repository-token: ${{ secrets.LEFTSIZE_REPOSITORY_TOKEN }}
```

### AWS Usage

```yaml
permissions:
  id-token: write        # Required for OIDC
  contents: read

jobs:
  leftsize-scan:
    runs-on: ubuntu-latest
    steps:
      - name: AWS Login (OIDC)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: us-east-1
      
      - name: Run LeftSize Scan
        uses: leftsize/leftsize-action@v1
        with:
          installation-id: ${{ secrets.LEFTSIZE_INSTALLATION_ID }}
          repository-token: ${{ secrets.LEFTSIZE_REPOSITORY_TOKEN }}
          cloud-provider: aws
```

## Configuration

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `installation-id` | ✅ Yes | - | GitHub App installation ID from LeftSize onboarding |
| `repository-token` | ✅ Yes | - | Secure repository token from LeftSize onboarding |
| `backend-url` | No | `https://api.leftsize.com` | LeftSize backend API URL |
| `cloud-provider` | No | `azure` | Cloud provider: `azure` or `aws` |
| `azure-subscription-ids` | No | Login subscription | Subscription ID used for scoping and currency detection. The scan covers the subscription selected by `azure/login`; scan more subscriptions with a matrix (one job per subscription). |
| `aws-regions` | No | Login region | Comma-separated AWS regions to scan, or `all` for every enabled region |
| `include-policies` | No | All | Rule categories: `cost-optimization`, `deprecation`, `governance`, `security` |
| `exclude-policies` | No | None | Rule names to skip (comma-separated, with or without the `leftsize-` prefix) |
| `environment-name` | No | Detected per resource | Environment of the scanned resources: one value for the whole scan (`Production`), or `name=environment` pairs for a subscription with several environments (`Freelance-NG-A=acceptance, Freelance-NG-P=production`). Values that aren't an environment (such as a matrix label `MAIN`) are ignored. See [Production vs non-production](#production-vs-non-production). |
| `verbose` | No | `false` | Enable verbose logging |

### Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total number of findings detected |
| `findings-submitted` | Whether findings were successfully submitted (`true`/`false`) |
| `findings-json` | JSON string of all findings for custom processing |

### Production vs non-production

Some rules only apply to non-production resources, such as shutting down dev VMs at night or dropping Multi-AZ on test databases. LeftSize decides the environment per resource, using the first of these signals that applies:

1. The `environment-name` input, if it names an environment (`PROD`, `DEV`, `acceptance`, …)
2. An `Environment`, `Env` or `Stage` tag on the resource, then on its Azure resource group
3. Words in the resource name or resource group name: `prod`, `prd`, `live` → production; `acc`, `uat`, `preprod` → acceptance; `stg`, `staging`; `test`, `tst`, `qa`; `dev`; `sandbox`; `nonprod`
4. A one-letter last word in the resource group name: `-P`, `-A`, `-T`, `-D` (for example `Shop-NG-A`)

Any production signal wins, and a resource without positive non-production evidence is never treated as non-production. Each issue shows the environment and what it was based on.

## Advanced Examples

### Multi-Subscription Azure Scan

Each job scans the subscription it logs in to, so use a matrix with one entry per subscription:

```yaml
permissions:
  id-token: write        # Required for OIDC
  contents: read

jobs:
  leftsize-scan:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        environment: [PROD, DEV]
    steps:
      - uses: azure/login@v2
        with:
          client-id: ${{ secrets[format('AZURE_CLIENT_ID_{0}', matrix.environment)] }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets[format('AZURE_SUBSCRIPTION_ID_{0}', matrix.environment)] }}
      - uses: leftsize/leftsize-action@v1
        with:
          installation-id: ${{ secrets.LEFTSIZE_INSTALLATION_ID }}
          repository-token: ${{ secrets.LEFTSIZE_REPOSITORY_TOKEN }}
          environment-name: ${{ matrix.environment }}
```

### AWS Multi-Region Scan

```yaml
permissions:
  id-token: write        # Required for OIDC
  contents: read

jobs:
  leftsize-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: leftsize/leftsize-action@v1
        with:
          installation-id: ${{ secrets.LEFTSIZE_INSTALLATION_ID }}
          repository-token: ${{ secrets.LEFTSIZE_REPOSITORY_TOKEN }}
          cloud-provider: aws
          aws-regions: "us-east-1,eu-west-1,ap-southeast-1"
```

### Filter Policies

```yaml
permissions:
  id-token: write        # Required for OIDC
  contents: read

jobs:
  leftsize-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: leftsize/leftsize-action@v1
        with:
          installation-id: ${{ secrets.LEFTSIZE_INSTALLATION_ID }}
          repository-token: ${{ secrets.LEFTSIZE_REPOSITORY_TOKEN }}
          include-policies: cost-optimization,governance  # Only cost and governance rules
          exclude-policies: leftsize-idle-vm              # Skip a specific rule
```

### Custom Processing of Findings

```yaml
permissions:
  id-token: write        # Required for OIDC
  contents: read

jobs:
  leftsize-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Run LeftSize Scan
        id: leftsize
        uses: leftsize/leftsize-action@v1
        with:
          installation-id: ${{ secrets.LEFTSIZE_INSTALLATION_ID }}
          repository-token: ${{ secrets.LEFTSIZE_REPOSITORY_TOKEN }}

      - name: Process Findings
        run: |
          echo "Found ${{ steps.leftsize.outputs.findings-count }} findings"
          echo "Submitted: ${{ steps.leftsize.outputs.findings-submitted }}"
          
          # Custom processing
          echo '${{ steps.leftsize.outputs.findings-json }}' | jq '.[] | select(.severity == "high")'
```

## Azure Setup (OIDC)

### 1. Create Azure AD App Registration

```bash
# Create app
az ad app create --display-name "LeftSize-GitHub-Action"

# Get app ID
APP_ID=$(az ad app list --display-name "LeftSize-GitHub-Action" --query "[0].appId" -o tsv)

# Create service principal
az ad sp create --id $APP_ID

# Get object ID
OBJECT_ID=$(az ad sp list --display-name "LeftSize-GitHub-Action" --query "[0].id" -o tsv)
```

### 2. Configure Federated Credentials

```bash
# Create credential configuration
cat > credential.json << EOF
{
  "name": "github-actions",
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:YOUR-ORG/YOUR-REPO:ref:refs/heads/main",
  "audiences": ["api://AzureADTokenExchange"]
}
EOF

# Add federated credential
az ad app federated-credential create --id $APP_ID --parameters credential.json
```

### 3. Assign Permissions

```bash
# Assign Reader role (minimum required)
az role assignment create \
  --assignee $OBJECT_ID \
  --role "Reader" \
  --scope /subscriptions/YOUR-SUBSCRIPTION-ID

# Assign Monitoring Reader (for metrics)
az role assignment create \
  --assignee $OBJECT_ID \
  --role "Monitoring Reader" \
  --scope /subscriptions/YOUR-SUBSCRIPTION-ID
```

### 4. Add Secrets to GitHub

Add these secrets to your repository:
- `AZURE_CLIENT_ID`: App ID from step 1
- `AZURE_TENANT_ID`: Your Azure AD tenant ID
- `AZURE_SUBSCRIPTION_ID`: Your subscription ID
- `LEFTSIZE_INSTALLATION_ID`: From LeftSize onboarding
- `LEFTSIZE_REPOSITORY_TOKEN`: From LeftSize onboarding

## AWS Setup (OIDC)

### 1. Create IAM OIDC Provider

```bash
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1
```

### 2. Create IAM Role

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::ACCOUNT-ID:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:YOUR-ORG/YOUR-REPO:ref:refs/heads/main"
        }
      }
    }
  ]
}
```

### 3. Attach Read-Only Policies

```bash
aws iam attach-role-policy \
  --role-name LeftSize-GitHub-Action \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

### 4. Add Secrets to GitHub

- `AWS_ROLE_ARN`: ARN of the role created above
- `LEFTSIZE_INSTALLATION_ID`: From LeftSize onboarding
- `LEFTSIZE_REPOSITORY_TOKEN`: From LeftSize onboarding

## Policies Included

The action ships the curated LeftSize policies in [`policies/`](policies/): cost optimization, deprecations and retirements, security and governance for AWS and Azure. The [rule catalog](https://leftsize.com/rules/) documents every rule: what it checks, why it matters and how to fix it.

## Runner Requirements

⚠️ **Important**: This action requires a Linux runner (`ubuntu-latest`, `ubuntu-20.04`, or `ubuntu-22.04`). It does not work on Windows or macOS runners due to Docker-based action limitations.

```yaml
jobs:
  leftsize-scan:
    runs-on: ubuntu-latest  # Required
```

## Runner minutes

LeftSize runs on **your** GitHub Actions runners, not our infrastructure:
- **Free tier**: 2000 minutes/month (GitHub Free)
- **Typical scan**: 3-5 minutes
- **Result**: ~400 scans/month on free tier

For larger organizations, use [self-hosted runners](https://docs.github.com/en/actions/hosting-your-own-runners) for unlimited usage.

## Security

- ✅ **No Cloud Credentials Stored** - Uses OIDC (keyless authentication)
- ✅ **Read-Only Operations** - All policies are 100% safe, no destructive actions
- ✅ **Multi-Tenant Secure** - Repository tokens prevent cross-tenant attacks
- ✅ **Minimal Permissions** - Only requires Reader and Monitoring Reader roles

## Troubleshooting

### Authentication Failed

**Azure**:
```bash
# Test authentication locally
az login
az account show

# Verify service principal
az ad sp show --id $AZURE_CLIENT_ID
```

**AWS**:
```bash
# Test authentication locally
aws sts get-caller-identity

# Verify role trust policy
aws iam get-role --role-name LeftSize-GitHub-Action
```

### No Findings

This is normal! It means your infrastructure is well-optimized. The action will still submit a report with zero findings.

### Findings Not Submitted

Check:
1. `LEFTSIZE_INSTALLATION_ID` is correct
2. `LEFTSIZE_REPOSITORY_TOKEN` matches your repository
3. Backend URL is reachable (`https://api.leftsize.com`)

Findings are saved as artifacts even if submission fails.

## Support

- 📚 [Documentation](https://support.leftsize.com)
- 💬 [GitHub Discussions](https://github.com/leftsize/leftsize-action/discussions)
- 🐛 [Report Issues](https://github.com/leftsize/leftsize-action/issues)
- 📧 Email: support@leftsize.com

## License

MIT License - See [LICENSE](LICENSE) file for details.

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

Made with ❤️ by the LeftSize team
