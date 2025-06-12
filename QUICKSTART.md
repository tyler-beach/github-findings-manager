# Quick Start Guide

Get up and running with GitHub Findings Manager in 5 minutes.

## Prerequisites

1. **Go 1.21+** installed on your system
2. **GitHub Personal Access Token** with required permissions:
   - `repo` (for private repositories)
   - `security_events` (for security findings)
   - `read:org` (for organization access)

## Installation

### Option 1: Build from Source (Recommended)
```bash
# Clone and build
git clone <repository-url>
cd github-findings-manager
go mod download
go build -o github-findings-manager

# Make executable
chmod +x github-findings-manager
```

### Option 2: Using Make
```bash
make build
```

### Option 3: Docker
```bash
docker pull ghcr.io/your-org/github-findings-manager:latest
```

## Quick Setup

### 1. Set Environment Variables
```bash
export GITHUB_TOKEN="ghp_your_token_here"
export GITHUB_FINDINGS_ORG="your-organization"
```

### 2. First Run
```bash
# Basic scan
./github-findings-manager --org your-organization

# With custom environment type
./github-findings-manager --org your-organization --env-type "Staging"

# Verbose output
./github-findings-manager --org your-organization --verbose
```

### 3. Using Configuration File
```bash
# Copy example configuration
cp example-config.yaml ~/.github-findings-manager.yaml

# Edit your settings
vi ~/.github-findings-manager.yaml

# Run with config
./github-findings-manager --config ~/.github-findings-manager.yaml
```

## Docker Usage

### Quick Run
```bash
docker run --rm -it \
  -e GITHUB_TOKEN="$GITHUB_TOKEN" \
  -v $(pwd)/reports:/app/output \
  ghcr.io/your-org/github-findings-manager:latest \
  --org your-organization --output /app/output/report.xlsx
```

### With Configuration File
```bash
docker run --rm -it \
  -e GITHUB_TOKEN="$GITHUB_TOKEN" \
  -v $(pwd)/config.yaml:/app/config.yaml \
  -v $(pwd)/reports:/app/output \
  ghcr.io/your-org/github-findings-manager:latest \
  --config /app/config.yaml --org your-organization
```

## Common Use Cases

### 1. Weekly Security Report
```bash
./github-findings-manager \
  --org mycompany \
  --env-type "Production" \
  --output "weekly-security-$(date +%Y-%m-%d).xlsx" \
  --verbose
```

### 2. CI/CD Integration
```bash
# Generate CSV for automated processing
./github-findings-manager \
  --org mycompany \
  --output findings.xlsx

# CSV will be automatically created as findings.csv
```

### 3. Multi-Environment Scan
```bash
# Production
./github-findings-manager --org mycompany --env-type "Production" --output prod-findings.xlsx

# Staging  
./github-findings-manager --org mycompany --env-type "Staging" --output staging-findings.xlsx

# Development
./github-findings-manager --org mycompany --env-type "Development" --output dev-findings.xlsx
```

### 4. Performance Optimization for Large Orgs
```bash
export GITHUB_FINDINGS_MAX_WORKERS=20
export GITHUB_FINDINGS_CACHE_DURATION=48h

./github-findings-manager \
  --org large-organization \
  --verbose
```

## Output Files

After running, you'll get:
- `findings-report.xlsx` - Comprehensive Excel dashboard
- `findings-report.csv` - CSV export for CI/CD
- `findings.db` - Local SQLite database cache

## Troubleshooting

### 1. Authentication Issues
```bash
# Test your token
curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user

# Check organization access
curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/orgs/your-org/repos
```

### 2. Rate Limiting
```bash
# Check current limits
curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/rate_limit

# Reduce worker count
export GITHUB_FINDINGS_MAX_WORKERS=5
```

### 3. Memory Issues
```bash
# Build with optimizations
go build -ldflags="-s -w" -o github-findings-manager

# Reduce cache size
export GITHUB_FINDINGS_CACHE_DURATION=6h
```

### 4. Custom Properties Not Found
If your organization doesn't use custom properties, the tool will still work but will show "Unknown" for Pod and EnvironmentType. To fix this:

1. Set up GitHub custom properties in your organization
2. Add `EnvironmentType` and `Pod` properties to repositories
3. Re-run the scan

## Next Steps

1. **Review the Excel Report**: Open the generated Excel file and explore the different sheets
2. **Customize Configuration**: Edit `example-config.yaml` for your specific needs
3. **Set Up Automation**: Use the CI/CD examples in README.md
4. **Monitor Performance**: Use `--verbose` flag to monitor API usage and performance

## Getting Help

- **Documentation**: See README.md for comprehensive documentation
- **Issues**: Report bugs and feature requests on GitHub
- **Configuration**: Use `example-config.yaml` as a reference for all options

## Performance Tips

1. **Enable Caching**: Always keep cache enabled for better performance
2. **Optimize Workers**: Start with 10 workers, adjust based on rate limits
3. **Use Delta Updates**: For regular scans, use `--since` flag for incremental updates
4. **Monitor Rate Limits**: Use `--verbose` to track API usage

## Security Best Practices

1. **Token Security**: Never commit tokens to version control
2. **Minimal Permissions**: Use tokens with only required scopes
3. **Regular Rotation**: Rotate GitHub tokens regularly
4. **Secure Storage**: Use environment variables or secure vaults for tokens

---

🎉 **You're Ready!** Your first security findings report should be generated and ready for analysis. 