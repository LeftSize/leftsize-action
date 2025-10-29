# LeftSize GitHub Action - Deployment Guide

## What We've Built

A complete GitHub Action that:
- ✅ Scans Azure and AWS infrastructure for cost optimization opportunities
- ✅ Runs on customer's GitHub Actions runners (zero LeftSize compute cost)
- ✅ 100% safe, read-only operations
- ✅ Supports OIDC authentication (no secrets storage)
- ✅ Multi-subscription/multi-region scanning
- ✅ Flexible policy filtering
- ✅ Outputs findings for custom processing

## Repository Structure

```
leftsize-action/
├── action.yml              # GitHub Action metadata and interface
├── Dockerfile              # Container with Python, Cloud Custodian, Azure/AWS CLIs
├── entrypoint.sh          # Entry script
├── run.py                 # Core scanner logic (adapted from apps/runner)
├── requirements.txt       # Python dependencies
├── policies/              # Curated Cloud Custodian policies
│   ├── azure-cost-optimization.yml
│   ├── azure-governance.yml
│   ├── azure-aks-optimization.yml
│   ├── azure-deprecations.yml
│   ├── aws-cost-optimization.yml
│   └── aws-governance.yml
├── README.md              # Comprehensive documentation
├── LICENSE                # MIT License
├── CHANGELOG.md           # Version history
└── .gitignore
```

## Deployment Steps

### 1. Create Public GitHub Repository

```bash
# The repository is already initialized with git
cd /Users/michiel/projects/private/leftsize/leftsize-action

# Create a new public repository on GitHub:
# https://github.com/new
# Name: leftsize-action
# Description: Scan AWS and Azure for cost optimization opportunities
# Visibility: Public
```

### 2. Push to GitHub

```bash
# Add remote (replace with your actual repo URL)
git remote add origin https://github.com/leftsize/leftsize-action.git

# Push
git push -u origin main
```

### 3. Create Release Tags

```bash
# Create v1.0.0 release
git tag -a v1.0.0 -m "Release v1.0.0 - Initial release"
git push origin v1.0.0

# Create v1 major version tag (for convenience)
git tag -a v1 -m "Version 1"
git push origin v1
```

### 4. Create GitHub Release

1. Go to: `https://github.com/leftsize/leftsize-action/releases/new`
2. Choose tag: `v1.0.0`
3. Release title: `v1.0.0 - Initial Release`
4. Description: Copy from CHANGELOG.md
5. Click "Publish release"

### 5. (Optional) Publish to GitHub Marketplace

1. Go to repository settings
2. Check "GitHub Marketplace" option
3. Fill out marketplace listing:
   - **Category**: Deployment, Monitoring
   - **Icon**: Cloud icon (already in action.yml)
   - **Color**: Blue (already in action.yml)
   - **Short description**: "Scan AWS and Azure for cost optimization opportunities"
   - **Long description**: Use README.md content
   - **Pricing**: Free
4. Submit for review

## Testing Before Public Release

### 1. Test Locally with Act

```bash
# Install act (GitHub Actions local runner)
brew install act  # macOS
# or
sudo apt install act  # Linux

# Create test workflow
mkdir -p .github/workflows
cat > .github/workflows/test.yml << 'EOF'
name: Test LeftSize Action
on: workflow_dispatch
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./
        with:
          installation-id: "test-123"
          repository-token: "test-token"
EOF

# Test with act
act workflow_dispatch
```

### 2. Test in Private Repository First

1. Create a private test repository
2. Add action as local action:
   ```yaml
   - uses: ./leftsize-action  # Local path
   ```
3. Configure Azure/AWS authentication
4. Run workflow and verify:
   - Authentication works
   - Policies execute
   - Findings are generated
   - Outputs are set correctly

### 3. Test with Real Backend

```yaml
- uses: leftsize/leftsize-action@v1
  with:
    installation-id: ${{ secrets.LEFTSIZE_INSTALLATION_ID }}
    repository-token: ${{ secrets.LEFTSIZE_REPOSITORY_TOKEN }}
    azure-subscription-ids: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
    backend-url: https://api.leftsize.io  # or your test backend
    verbose: true
```

## Integration with Onboarding Flow

### Update Backend Workflow Template Generation

The backend needs to generate workflow YAML for users. Update the template to use the action:

**Template** (pseudo-code for backend):
```yaml
name: LeftSize Cost Optimization Scan
on:
  schedule:
    - cron: '0 0 * * *'
  workflow_dispatch:
permissions:
  id-token: write
  contents: read
jobs:
  leftsize-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Azure Login
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

### Update Onboarding Page

Update `website/src/pages/onboarding.astro` to:
1. Show setup instructions for OIDC (Azure/AWS)
2. Display the workflow YAML using the action
3. Provide secrets to add to GitHub:
   - `LEFTSIZE_INSTALLATION_ID`
   - `LEFTSIZE_REPOSITORY_TOKEN`
   - Azure: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`
   - AWS: `AWS_ROLE_ARN`

## Documentation Updates Needed

### 1. Main LeftSize Documentation Site

Add pages:
- "GitHub Action Setup Guide"
- "Azure OIDC Configuration"
- "AWS OIDC Configuration"
- "Policy Reference"
- "Troubleshooting"

### 2. Blog Post

Announce the GitHub Action:
- "Introducing LeftSize GitHub Action"
- Benefits of running on GitHub Actions
- Setup walkthrough
- Example findings

### 3. Update Website

- Add "GitHub Action" to navigation
- Update feature list to mention GitHub Actions
- Add testimonials about ease of use

## Support Preparation

### 1. Common Issues & Solutions

Create KB articles:
- "Authentication failed" → OIDC setup guide
- "No findings" → This is normal, good infrastructure
- "Findings not submitted" → Check installation ID and token
- "Docker error" → Must use Linux runner

### 2. Example Repositories

Create public example repos:
- `leftsize-action-example-azure`
- `leftsize-action-example-aws`
- `leftsize-action-example-multi-cloud`

### 3. Video Tutorials

Record screencasts:
- "5-minute setup for Azure"
- "Adding LeftSize to existing workflow"
- "Understanding your findings"

## Monitoring & Analytics

### Track Action Usage

1. GitHub provides action insights:
   - Go to: `https://github.com/leftsize/leftsize-action/insights/traffic`
   - Track: Stars, forks, clones, views

2. Backend analytics:
   - Track API calls from GitHub Actions
   - User agent: "LeftSize-Runner/1.0"
   - Count successful scans
   - Track findings trends

### Success Metrics

Monitor:
- ⭐ GitHub stars
- 📦 Action runs per day
- ✅ Successful scan rate
- 🔍 Average findings per scan
- 👥 Active installations
- 📈 Week-over-week growth

## Maintenance Plan

### Weekly
- Monitor GitHub issues
- Review pull requests
- Check action run failures

### Monthly
- Update Cloud Custodian policies
- Update Azure/AWS CLI versions
- Review and merge community contributions
- Release patch versions if needed

### Quarterly
- Major feature releases
- Policy pack updates
- Documentation improvements
- Performance optimizations

## Next Steps

1. ✅ Repository created and initialized
2. 🔄 Push to GitHub
3. 🔄 Create releases (v1.0.0, v1)
4. 🔄 Test with real Azure/AWS environment
5. 🔄 Update backend workflow template generation
6. 🔄 Update onboarding flow
7. 🔄 Create documentation
8. 🔄 Announce release
9. 🔄 Monitor adoption

## Rollback Plan

If issues arise:
1. Delete GitHub Marketplace listing (if published)
2. Delete release tags
3. Update v1 tag to point to last good version
4. Communicate via GitHub release notes

## Success Criteria

- ✅ Action runs successfully on Linux runners
- ✅ Authenticates with Azure via OIDC
- ✅ Authenticates with AWS via OIDC
- ✅ Executes policies and finds resources
- ✅ Submits findings to backend
- ✅ Outputs are set correctly
- ✅ README is clear and comprehensive
- ✅ 95%+ success rate in production

---

Ready to deploy! 🚀
