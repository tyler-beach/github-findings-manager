# GitHub Findings Manager

A high-performance CLI tool for collecting and reporting GitHub security findings.

## Features

- Collects CodeQL, Secrets Scanning, and Dependabot findings
- Filters repositories by EnvironmentType custom property
- Collects Pod ownership data
- Generates comprehensive Excel reports
- Supports parallel processing and caching
- Rate limit aware with exponential backoff

## Installation

### From Source

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/github-findings-manager.git
   cd github-findings-manager
   ```

2. Build the tool:
   ```bash
   make build
   ```

3. Install globally (optional):
   ```bash
   make install
   ```

### Quick Install

```bash
go install github.com/yourusername/github-findings-manager@latest
```

## Usage

1. Set your GitHub token:
   ```bash
   export GITHUB_TOKEN=ghp_your_token_here
   ```

2. Run the tool:
   ```bash
   # Scan all repositories in the organization
   github-findings-manager --org your-org --env-type Production
   
   # Scan specific repositories only
   github-findings-manager --org your-org --repos "repo1,repo2,repo3"
   ```

### Command Line Options

- `--org`: GitHub organization name (required)
- `--env-type`: Environment type to filter repositories (default: "Production")
- `--repos`: Comma-separated list of specific repositories to scan (optional)
- `--output`: Output file path (default: "findings-report.xlsx")
- `--cache-duration`: Cache duration in minutes (default: 60)
- `--workers`: Number of parallel workers (default: 10)
- `--verbose`: Enable verbose logging

### Usage Examples

```bash
# Scan all Production repositories in an organization
github-findings-manager --org myorg --env-type Production

# Scan specific repositories regardless of environment type
github-findings-manager --org myorg --repos "api-service,web-app,data-pipeline"

# Scan Development repositories with verbose logging
github-findings-manager --org myorg --env-type Development --verbose

# Custom output file for specific repos
github-findings-manager --org myorg --repos "critical-app" --output critical-security-report.xlsx
```

## Configuration

The tool can be configured using environment variables or a config file:

### Environment Variables

- `GITHUB_TOKEN`: GitHub personal access token
- `GITHUB_FINDINGS_CACHE_DURATION`: Cache duration in minutes
- `GITHUB_FINDINGS_WORKERS`: Number of parallel workers

### Config File

Create a `config.yaml` file:

```yaml
github:
  token: ${GITHUB_TOKEN}
  rate_limit: 80
  retry_attempts: 3
  retry_delay: 5

cache:
  enabled: true
  duration: 60
  path: .cache

workers:
  count: 10
  timeout: 300

output:
  path: findings-report.xlsx
  format: excel
```

## Development

1. Install dependencies:
   ```bash
   make deps
   ```

2. Run tests:
   ```bash
   make test
   ```

3. Run linter:
   ```bash
   make lint
   ```

## Performance

The tool is optimized for performance:

- Parallel worker pools for concurrent API calls
- GraphQL batching for efficient data fetching
- ETag caching to minimize API calls
- Rate limit monitoring and exponential backoff
- SQLite storage for local caching

### Benchmarks

- Small (10 repos): ~12 seconds
- Medium (50 repos): ~45 seconds
- Large (100 repos): ~90 seconds
- Enterprise (500 repos): ~4m 15s

## Security

- GitHub token is required but never logged
- Minimal API permissions required
- No sensitive data in logs
- Secure storage of cached data

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

MIT License - see LICENSE file for details 