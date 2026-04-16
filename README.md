# LeftSize GitHub Action

Scan your AWS and Azure infrastructure for cost optimization opportunities using Cloud Custodian. Run scans directly in GitHub Actions - no infrastructure required from your side.

## Features

- 🔍 **Safe Scanning** - 100% read-only operations, no changes to your infrastructure
- ☁️ **Multi-Cloud** - Supports Azure and AWS
- 🚀 **Zero Config** - Works out-of-the-box with sensible defaults
- 🔐 **Secure** - Uses OIDC for authentication, no secrets storage needed
- 📊 **Actionable** - Findings submitted to LeftSize dashboard for tracking
- 🎯 **Customizable** - Filter policies, add custom rules

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
| `azure-subscription-ids` | No | All accessible | Comma-separated Azure subscription IDs to scan |
| `aws-regions` | No | All accessible | Comma-separated AWS regions to scan |
| `include-policies` | No | All | Policy categories: `cost-optimization`, `governance`, `security` |
| `exclude-policies` | No | None | Specific policy names to skip (comma-separated) |
| `verbose` | No | `false` | Enable verbose logging |

### Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total number of findings detected |
| `findings-submitted` | Whether findings were successfully submitted (`true`/`false`) |
| `findings-json` | JSON string of all findings for custom processing |

## Advanced Examples

### Multi-Subscription Azure Scan

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
          azure-subscription-ids: "sub-id-1,sub-id-2,sub-id-3"
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
          include-policies: cost-optimization,governance  # Only cost and governance policies
          exclude-policies: leftsize-idle-vm              # Skip specific rule
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

The action includes curated Cloud Custodian policies:

### Cost Optimization (Azure)
- `leftsize-idle-vm` - Idle virtual machines
- `leftsize-unattached-disk` - Unattached managed disks
- `leftsize-unused-public-ip` - Unused public IP addresses
- `leftsize-idle-app-service-plan` - Underutilized App Service Plans
- `leftsize-idle-app-service-plan-no-apps` - Empty App Service Plans
- `leftsize-inactive-azure-load-balancer` - Inactive load balancers

### Cost Optimization (AWS)
- `leftsize-idle-ecs-instances` - Idle ECS container instances
- `leftsize-unattached-ebs-volumes` - Unattached EBS volumes
- `leftsize-unused-elastic-ips` - Unused Elastic IPs
- `leftsize-old-snapshots` - Old EBS snapshots
- And more...

### Governance
- Security group rules
- Unencrypted resources
- Missing tags
- And more...

## Runner Requirements

⚠️ **Important**: This action requires a Linux runner (`ubuntu-latest`, `ubuntu-20.04`, or `ubuntu-22.04`). It does not work on Windows or macOS runners due to Docker-based action limitations.

```yaml
jobs:
  leftsize-scan:
    runs-on: ubuntu-latest  # Required
```

## Pricing

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

- 📚 [Documentation](https://docs.leftsize.io)
- 💬 [GitHub Discussions](https://github.com/leftsize/leftsize-action/discussions)
- 🐛 [Report Issues](https://github.com/leftsize/leftsize-action/issues)
- 📧 Email: support@leftsize.io

## License

MIT License - See [LICENSE](LICENSE) file for details.

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

Made with ❤️ by the LeftSize team
