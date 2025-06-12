package collector

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/go-github/v57/github"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"

	"github_findings_manager/pkg/cache"
	"github_findings_manager/pkg/models"
)

const (
	maxWorkers     = 10
	rateLimitBuffer = 100 // Keep 100 requests as buffer
)

// Collector handles GitHub API interactions and data collection
type Collector struct {
	client      *github.Client
	config      *models.Config
	cache       *cache.Cache
	rateLimiter *rate.Limiter
	stats       *models.CollectionStats
	mu          sync.RWMutex
}

// New creates a new collector instance
func New(config *models.Config) *Collector {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: config.Token},
	)
	tc := oauth2.NewClient(ctx, ts)

	client := github.NewClient(tc)
	
	// Set preview headers for custom properties
	tc.Transport = &previewHeaderTransport{
		Base: tc.Transport,
	}

	var cacheStore *cache.Cache
	if !config.NoCache {
		cacheStore = cache.New("./cache")
	}

	// Initialize rate limiter to 5000 requests per hour (GitHub's limit)
	rateLimiter := rate.NewLimiter(rate.Every(time.Hour/5000), 1)

	return &Collector{
		client:      client,
		config:      config,
		cache:       cacheStore,
		rateLimiter: rateLimiter,
		stats:       &models.CollectionStats{},
	}
}

// previewHeaderTransport adds preview API headers
type previewHeaderTransport struct {
	Base http.RoundTripper
}

func (t *previewHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Add preview headers for custom properties and other features
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	
	if t.Base == nil {
		return http.DefaultTransport.RoundTrip(req)
	}
	return t.Base.RoundTrip(req)
}

// CollectFindings orchestrates the collection of all security findings
func (c *Collector) CollectFindings() (*models.CollectionResults, error) {
	ctx := context.Background()
	startTime := time.Now()

	results := &models.CollectionResults{
		Organization: c.config.Organization,
		CollectedAt:  startTime,
		Repositories: make(map[string]*models.Repository),
		Findings:     make([]*models.Finding, 0),
		Errors:       make([]models.CollectionError, 0),
		Stats:        *c.stats,
	}

	// Step 1: Get repositories based on criteria
	logrus.Info("Fetching repositories...")
	repos, err := c.getRepositories(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get repositories: %w", err)
	}

	logrus.Infof("Found %d repositories to process", len(repos))
	c.stats.TotalRepos = len(repos)

	// Step 2: Process repositories in parallel
	findings, errors := c.processRepositoriesParallel(ctx, repos)
	
	// Compile results
	for _, repo := range repos {
		results.Repositories[repo.Name] = repo
	}
	results.Findings = findings
	results.Errors = errors

	// Update statistics
	c.stats.Duration = time.Since(startTime)
	c.stats.TotalFindings = len(findings)
	c.stats.ProcessedRepos = len(repos) - c.stats.ErrorRepos
	c.updateFindingStats(findings)
	
	results.Stats = *c.stats

	return results, nil
}

// getRepositories fetches repositories based on configuration
func (c *Collector) getRepositories(ctx context.Context) ([]*models.Repository, error) {
	var repos []*models.Repository

	if len(c.config.SpecificRepos) > 0 {
		// Get specific repositories
		for _, repoName := range c.config.SpecificRepos {
			repo, err := c.getRepository(ctx, repoName)
			if err != nil {
				logrus.Warnf("Failed to get repository %s: %v", repoName, err)
				continue
			}
			repos = append(repos, repo)
		}
	} else {
		// Get all repositories and filter
		allRepos, err := c.getAllRepositories(ctx)
		if err != nil {
			return nil, err
		}

		repos = c.filterRepositories(allRepos)
	}

	return repos, nil
}

// getAllRepositories fetches all repositories for the organization
func (c *Collector) getAllRepositories(ctx context.Context) ([]*models.Repository, error) {
	var allRepos []*models.Repository
	
	opts := &github.RepositoryListByOrgOptions{
		Type: "all",
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}

	pageCount := 0
	for {
		pageCount++
		if err := c.rateLimiter.Wait(ctx); err != nil {
			return nil, err
		}

		repos, resp, err := c.client.Repositories.ListByOrg(ctx, c.config.Organization, opts)
		if err != nil {
			if resp != nil && resp.StatusCode == 401 {
				return nil, fmt.Errorf("unauthorized: invalid GitHub token or insufficient permissions")
			}
			return nil, fmt.Errorf("failed to list repositories: %w", err)
		}

		c.stats.APICallsTotal++
		
		// Debug pagination info
		if c.config.Verbose {
			logrus.Infof("Repository listing: page %d, %d repos, next page: %d", 
				pageCount, len(repos), resp.NextPage)
		}

		for _, repo := range repos {
			r := &models.Repository{
				Name:        repo.GetName(),
				FullName:    repo.GetFullName(),
				LastUpdated: time.Now(),
			}

			// Get custom properties
			if err := c.getRepositoryCustomProperties(ctx, r); err != nil {
				logrus.Debugf("Failed to get custom properties for %s: %v", r.Name, err)
				// Don't fail the entire operation for custom properties
			}

			allRepos = append(allRepos, r)
		}

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return allRepos, nil
}

// getRepository fetches a specific repository
func (c *Collector) getRepository(ctx context.Context, repoName string) (*models.Repository, error) {
	if err := c.rateLimiter.Wait(ctx); err != nil {
		return nil, err
	}

	repo, resp, err := c.client.Repositories.Get(ctx, c.config.Organization, repoName)
	if err != nil {
		if resp != nil && resp.StatusCode == 401 {
			return nil, fmt.Errorf("unauthorized: invalid GitHub token or insufficient permissions")
		}
		return nil, fmt.Errorf("failed to get repository: %w", err)
	}

	c.stats.APICallsTotal++

	r := &models.Repository{
		Name:        repo.GetName(),
		FullName:    repo.GetFullName(),
		LastUpdated: time.Now(),
	}

	// Get custom properties
	if err := c.getRepositoryCustomProperties(ctx, r); err != nil {
		logrus.Debugf("Failed to get custom properties for %s: %v", r.Name, err)
	}

	return r, nil
}

// getRepositoryCustomProperties fetches custom properties for a repository
func (c *Collector) getRepositoryCustomProperties(ctx context.Context, repo *models.Repository) error {
	if err := c.rateLimiter.Wait(ctx); err != nil {
		return err
	}

	logrus.Debugf("Fetching custom properties for repository: %s", repo.Name)

	// Try the correct GitHub custom properties API endpoint
	url := fmt.Sprintf("repos/%s/%s/properties/values", c.config.Organization, repo.Name)
	logrus.Debugf("Custom properties URL being called: %s", url)
	
	req, err := c.client.NewRequest("GET", url, nil)
	if err != nil {
		logrus.Debugf("Failed to create custom properties request for %s: %v", repo.Name, err)
		return err
	}
	
	logrus.Debugf("Full request URL: %s", req.URL.String())

	// Add required headers for custom properties API
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	
	logrus.Debugf("About to make request to: %s", req.URL.String())
	logrus.Debugf("Request method: %s", req.Method)
	logrus.Debugf("Request headers: %+v", req.Header)

	var properties []models.CustomProperty
	resp, err := c.client.Do(ctx, req, &properties)
	
	if resp != nil {
		logrus.Debugf("Response status: %d", resp.StatusCode)
		logrus.Debugf("Response URL: %s", resp.Request.URL.String())
	}
	
	c.stats.APICallsTotal++

	if err != nil {
		// If 403 or 404, this is expected - custom properties might not be available
		if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
			logrus.Debugf("Custom properties not accessible for %s (status: %d)", repo.Name, resp.StatusCode)
			repo.AccessErrors = append(repo.AccessErrors, fmt.Sprintf("%d: Custom properties not accessible", resp.StatusCode))
			return nil
		}
		logrus.Debugf("Error fetching custom properties for %s: %v", repo.Name, err)
		return err
	}

	logrus.Debugf("Successfully fetched %d custom properties for %s", len(properties), repo.Name)

	// Parse custom properties
	for _, prop := range properties {
		logrus.Debugf("Property: %s = %v", prop.PropertyName, prop.Value)
		
		// Convert value to string if it's not nil
		var valueStr string
		if prop.Value != nil {
			if str, ok := prop.Value.(string); ok {
				valueStr = str
			} else {
				// Handle other types (array, etc.) by converting to string
				valueStr = fmt.Sprintf("%v", prop.Value)
			}
		}
		
		switch prop.PropertyName {
		case "EnvironmentType", "environment_type", "environmentType", "environment":
			repo.EnvironmentType = valueStr
			logrus.Debugf("Set EnvironmentType=%s for %s", valueStr, repo.Name)
		case "pod", "Pod", "POD", "team":
			repo.Pod = valueStr
			logrus.Debugf("Set Pod=%s for %s", valueStr, repo.Name)
		}
	}

	// If no custom properties found, try manual assignments
	if repo.EnvironmentType == "" && repo.Pod == "" {
		logrus.Debugf("No custom properties found for %s, checking manual assignments", repo.Name)
		c.checkManualAssignments(repo)
	}

	return nil
}

// checkManualAssignments checks for manual repository assignments in configuration
func (c *Collector) checkManualAssignments(repo *models.Repository) {
	if c.config.RepoAssignments == nil {
		return
	}

	if assignment, exists := c.config.RepoAssignments[repo.Name]; exists {
		if assignment.EnvironmentType != "" {
			repo.EnvironmentType = assignment.EnvironmentType
			logrus.Debugf("Manual assignment: EnvironmentType=%s for %s", assignment.EnvironmentType, repo.Name)
		}
		if assignment.Pod != "" {
			repo.Pod = assignment.Pod
			logrus.Debugf("Manual assignment: Pod=%s for %s", assignment.Pod, repo.Name)
		}
	}
}

// filterRepositories filters repositories based on configuration
func (c *Collector) filterRepositories(repos []*models.Repository) []*models.Repository {
	var filtered []*models.Repository

	for _, repo := range repos {
		// If custom properties aren't available, include all repos when no specific filters are set
		includeRepo := true
		
		// Filter by environment type only if custom properties are available
		if repo.EnvironmentType != "" {
			if repo.EnvironmentType != c.config.EnvType {
				includeRepo = false
			}
		} else if c.config.EnvType != "Production" {
			// If no environment type and user specified non-default, skip
			includeRepo = false
		}
		// If environment type is empty and user wants "Production" (default), include it

		// Filter by pod if specified
		if len(c.config.PodFilter) > 0 && includeRepo {
			if repo.Pod == "" {
				// If no pod info available but pod filter specified, exclude
				includeRepo = false
			} else {
				podMatches := false
				for _, pod := range c.config.PodFilter {
					if repo.Pod == pod {
						podMatches = true
						break
					}
				}
				if !podMatches {
					includeRepo = false
				}
			}
		}

		if includeRepo {
			filtered = append(filtered, repo)
		}
	}

	logrus.Infof("Filtered %d repositories from %d total (env-type: %s)", 
		len(filtered), len(repos), c.config.EnvType)
		
	if len(filtered) == 0 && len(repos) > 0 {
		logrus.Warnf("No repositories match filter criteria. Consider:")
		logrus.Warnf("- Using --env-type '' to include all repositories")
		logrus.Warnf("- Checking if custom properties are set on repositories")
		logrus.Warnf("- Using --repos to specify repositories directly")
	}

	return filtered
}

// processRepositoriesParallel processes repositories in parallel using worker pools
func (c *Collector) processRepositoriesParallel(ctx context.Context, repos []*models.Repository) ([]*models.Finding, []models.CollectionError) {
	workers := maxWorkers
	if len(repos) < workers {
		workers = len(repos)
	}

	reposChan := make(chan *models.Repository, len(repos))
	resultsChan := make(chan repositoryResult, len(repos))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go c.repositoryWorker(ctx, &wg, reposChan, resultsChan)
	}

	// Send repositories to workers
	for _, repo := range repos {
		reposChan <- repo
	}
	close(reposChan)

	// Wait for all workers to complete
	wg.Wait()
	close(resultsChan)

	// Collect results
	var allFindings []*models.Finding
	var allErrors []models.CollectionError

	for result := range resultsChan {
		allFindings = append(allFindings, result.findings...)
		allErrors = append(allErrors, result.errors...)
		if len(result.errors) > 0 {
			c.mu.Lock()
			c.stats.ErrorRepos++
			c.mu.Unlock()
		}
	}

	return allFindings, allErrors
}

// repositoryResult holds the result of processing a single repository
type repositoryResult struct {
	findings []*models.Finding
	errors   []models.CollectionError
}

// repositoryWorker processes repositories from the channel
func (c *Collector) repositoryWorker(ctx context.Context, wg *sync.WaitGroup, repos <-chan *models.Repository, results chan<- repositoryResult) {
	defer wg.Done()

	for repo := range repos {
		result := c.processRepository(ctx, repo)
		results <- result
	}
}

// processRepository processes a single repository and collects all findings
func (c *Collector) processRepository(ctx context.Context, repo *models.Repository) repositoryResult {
	logrus.Debugf("Processing repository: %s", repo.Name)
	
	var allFindings []*models.Finding
	var errors []models.CollectionError

	// Check security features availability
	c.checkSecurityFeatures(ctx, repo)

	// Collect Code Scanning findings
	if repo.CodeScanningEnabled {
		findings, errs := c.getCodeScanningFindings(ctx, repo)
		allFindings = append(allFindings, findings...)
		errors = append(errors, errs...)
	}

	// Collect Secret Scanning findings
	if repo.SecretsEnabled {
		findings, errs := c.getSecretScanningFindings(ctx, repo)
		allFindings = append(allFindings, findings...)
		errors = append(errors, errs...)
	}

	// Collect Dependabot findings
	if repo.DependabotEnabled {
		findings, errs := c.getDependabotFindings(ctx, repo)
		allFindings = append(allFindings, findings...)
		errors = append(errors, errs...)
	}

	// Set attribution for findings
	for _, finding := range allFindings {
		if repo.Pod != "" {
			finding.Pod = repo.Pod
			finding.Attribution = "attributed"
		} else {
			finding.Pod = "No Pod Selected"
			finding.Attribution = "unattributed"
		}
		finding.Quarter = getQuarter(finding.CreatedAt)
	}

	return repositoryResult{
		findings: allFindings,
		errors:   errors,
	}
}

// The file continues with more methods for collecting specific types of findings...
// This is getting long, so I'll continue in the next part of the file. 