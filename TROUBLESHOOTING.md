# GitHub Findings Manager - Troubleshooting Guide

## Empty Spreadsheet Issues

If your generated Excel spreadsheet is empty, follow this step-by-step debugging guide:

### Step 1: Enable Debug Mode

Run with detailed debugging to see what's happening:

```bash
./github-findings-manager --org YOUR_ORG --debug
```

### Step 2: Check Repository Processing

Look for these key log messages:

```
INFO[...] Repositories found: X
INFO[...] Total findings: 0
DEBUG[...] Repository Details:
- repo-name: env=, pod=, code_scan=false, secrets=false, dependabot=false
```

If `env=` and `pod=` are empty, your repositories don't have custom properties configured.

### Step 3: Configure GitHub Custom Properties

The tool relies on GitHub's custom properties feature to assign repositories to environments and pods.

#### 3.1 Create Custom Properties in Your Organization

1. Go to your GitHub organization settings
2. Navigate to **Repository** → **Custom properties**
3. Create these properties:

**Environment Property:**
- Name: `environment` or `EnvironmentType`
- Type: Single select
- Values: `Production`, `Staging`, `Development`

**Pod Property:**
- Name: `pod` or `team`
- Type: Single select
- Values: `platform`, `security`, `frontend`, `backend`, `api`, etc.

#### 3.2 Assign Properties to Repositories

1. In the custom properties page, click **Set values**
2. Select repositories and click **Edit properties**
3. Assign appropriate values to each repository

### Step 4: Verify Token Permissions

Your `GITHUB_TOKEN` needs these permissions:

```
Required Scopes:
- repo (full repository access)
- read:org (organization metadata)
- repo:security_events (security findings)
```

For custom properties access:
- Organization admin permissions OR
- Fine-grained token with "Custom properties" repository permissions (read)

### Step 5: Check Security Features

Repositories must have security features enabled:

- **Code Scanning**: GitHub Advanced Security with CodeQL
- **Secret Scanning**: Available for public repos, requires GitHub Advanced Security for private repos
- **Dependabot**: Dependency alerts and security updates

Enable these in repository **Settings** → **Security & analysis**.

### Step 6: Use Manual Repository Assignments

If custom properties aren't available, use the manual assignment file:

1. Create `repo-assignments.json`:

```json
{
  "comment": "Manual repository assignments",
  "repositories": {
    "your-repo-name": {
      "environment_type": "Production",
      "pod": "backend"
    },
    "another-repo": {
      "environment_type": "Development",
      "pod": "frontend"
    }
  }
}
```

2. Run the tool (it will automatically load this file):

```bash
./github-findings-manager --org YOUR_ORG --debug
```

### Step 7: Test with Specific Repositories

Test with repositories you know have findings:

```bash
./github-findings-manager --org YOUR_ORG --repos "specific-repo-with-findings" --debug
```

### Step 8: Bypass Environment Filtering

Test without environment filtering to see all repositories:

```bash
./github-findings-manager --org YOUR_ORG --env-type "" --debug
```

## Common Error Messages

### "Custom properties not accessible"

```
DEBUG[...] Custom properties not accessible for repo-name (status: 403)
```

**Solution:** 
- Ensure your token has organization admin permissions, OR
- Use manual repository assignments with `repo-assignments.json`

### "No repositories match filter criteria"

```
WARN[...] No repositories match filter criteria. Consider:
- Using --env-type '' to include all repositories
- Checking if custom properties are set on repositories  
- Using --repos to specify repositories directly
```

**Solution:**
- Check your `--env-type` filter (default is "Production")
- Ensure repositories have the correct custom property values
- Use `--env-type ""` to include all repositories

### "No findings collected"

```
WARN[...] No findings collected. This could be due to:
1. No repositories match the environment filter
2. Repositories don't have security features enabled
3. GitHub token lacks required permissions
4. Organization doesn't have security features configured
```

**Solution:**
1. Verify custom properties are set correctly
2. Enable security features in repository settings
3. Check token permissions include `repo:security_events`
4. Verify GitHub Advanced Security is available for your organization

## API Rate Limiting

If you see rate limiting messages:

```
INFO[...] Rate limit reached, waiting 60s before retry
```

This is normal behavior. The tool automatically handles rate limiting with exponential backoff.

## Custom Properties API Details

The tool uses GitHub's REST API endpoint:
```
GET /repos/{owner}/{repo}/properties/values
```

Supported property names (case-insensitive):
- Environment: `environment`, `EnvironmentType`, `environment_type`, `environmentType`
- Pod/Team: `pod`, `Pod`, `POD`, `team`

Values are automatically converted to strings and assigned to repositories.

## Getting Help

If you're still experiencing issues:

1. Run with `--debug` and check the detailed logs
2. Verify your GitHub organization has the necessary features enabled
3. Test with a single repository that you know has security findings
4. Check the GitHub organization audit log for API access attempts

For additional support, include the debug output (without sensitive information) when reporting issues. 