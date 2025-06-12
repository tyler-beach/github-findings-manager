package github

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github-findings-manager/internal/config"
	"github-findings-manager/internal/models"
	"github-findings-manager/internal/storage"
)

// Collector orchestrates the collection of findings from GitHub
type Collector struct {
	client  *Client
	storage *storage.SQLiteStorage
	config  *config.Config
	logger  *logrus.Logger
}

// NewCollector creates a new collector instance
func NewCollector(client *Client, storage *storage.SQLiteStorage, config *config.Config) *Collector {
	client.SetStorage(storage)
	client.SetConfig(config)
	
	return &Collector{
		client:  client,
		storage: storage,
		config:  config,
		logger:  logrus.New(),
	}
}

// CollectFindings orchestrates the collection of all findings
func (c *Collector) CollectFindings(ctx context.Context) ([]*models.Finding, error) {
	start := time.Now()

	var filteredRepos []*models.Repository
	var err error

	// Check if specific repositories are requested
	if c.config.Repositories != "" {
		// Step 1: Get specific repositories
		c.logger.Info("Fetching specific repositories...")
		filteredRepos, err = c.getSpecificRepositories(ctx, c.config.Repositories)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch specific repositories: %w", err)
		}
	} else {
		// Step 1: Fetch all repositories
		c.logger.Info("Fetching all repositories...")
		repos, err := c.client.GetRepositories(ctx, c.config.Organization)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch repositories: %w", err)
		}

		// Step 2: Filter repositories by environment type
		filteredRepos = c.filterRepositories(repos)
		c.logger.WithFields(logrus.Fields{
			"total":    len(repos),
			"filtered": len(filteredRepos),
			"env_type": c.config.EnvType,
		}).Info("Filtered repositories by environment type")
	}

	// Step 3: Save repositories to storage
	if err := c.saveRepositories(filteredRepos); err != nil {
		c.logger.WithError(err).Warn("Failed to save repositories to storage")
	}

	// Step 4: Collect findings in parallel
	c.logger.WithField("repositories", len(filteredRepos)).Info("Starting parallel findings collection")
	findings, err := c.collectFindingsParallel(ctx, filteredRepos)
	if err != nil {
		return nil, fmt.Errorf("failed to collect findings: %w", err)
	}

	// Step 5: Save findings to storage
	if err := c.saveFindings(findings); err != nil {
		c.logger.WithError(err).Warn("Failed to save findings to storage")
	}

	duration := time.Since(start)
	c.logger.WithFields(logrus.Fields{
		"findings":     len(findings),
		"repositories": len(filteredRepos),
		"duration":     duration,
	}).Info("Collection completed")

	return findings, nil
}

// getSpecificRepositories fetches specific repositories by name
func (c *Collector) getSpecificRepositories(ctx context.Context, repoList string) ([]*models.Repository, error) {
	// Parse comma-separated repository names
	repoNames := strings.Split(repoList, ",")
	var repos []*models.Repository
	
	for _, repoName := range repoNames {
		repoName = strings.TrimSpace(repoName)
		if repoName == "" {
			continue
		}
		
		c.logger.WithField("repo", repoName).Debug("Fetching specific repository")
		
		// Get repository details from GitHub
		ghRepo, _, err := c.client.client.Repositories.Get(ctx, c.config.Organization, repoName)
		if err != nil {
			c.logger.WithFields(logrus.Fields{
				"repo":  repoName,
				"error": err.Error(),
			}).Error("Failed to fetch repository")
			continue // Skip this repo but continue with others
		}
		
		// Convert to our repository model
		repo := &models.Repository{
			ID:              ghRepo.GetID(),
			Name:            ghRepo.GetName(),
			FullName:        ghRepo.GetFullName(),
			Owner:           ghRepo.GetOwner().GetLogin(),
			URL:             ghRepo.GetHTMLURL(),
			IsPrivate:       ghRepo.GetPrivate(),
			DefaultBranch:   ghRepo.GetDefaultBranch(),
			CreatedAt:       ghRepo.GetCreatedAt().Time,
			UpdatedAt:       ghRepo.GetUpdatedAt().Time,
			CustomProperties: make(map[string]string),
		}
		
		// Fetch custom properties for this repo
		if err := c.client.fetchCustomProperties(ctx, repo); err != nil {
			c.logger.WithError(err).WithField("repo", repo.FullName).Warn("Failed to fetch custom properties")
		}
		
		repos = append(repos, repo)
	}
	
	c.logger.WithFields(logrus.Fields{
		"requested": len(repoNames),
		"found":     len(repos),
	}).Info("Fetched specific repositories")
	
	return repos, nil
}

// filterRepositories filters repositories by environment type
func (c *Collector) filterRepositories(repos []*models.Repository) []*models.Repository {
	var filtered []*models.Repository
	
	for _, repo := range repos {
		if repo.EnvironmentType == c.config.EnvType {
			filtered = append(filtered, repo)
		}
	}
	
	return filtered
}

// saveRepositories saves repositories to storage
func (c *Collector) saveRepositories(repos []*models.Repository) error {
	for _, repo := range repos {
		if err := c.storage.SaveRepository(repo); err != nil {
			c.logger.WithError(err).WithField("repo", repo.FullName).Error("Failed to save repository")
		}
	}
	return nil
}

// saveFindings saves findings to storage
func (c *Collector) saveFindings(findings []*models.Finding) error {
	for _, finding := range findings {
		if err := c.storage.SaveFinding(finding); err != nil {
			c.logger.WithError(err).WithField("finding", finding.ID).Error("Failed to save finding")
		}
	}
	return nil
}

// collectFindingsParallel collects findings using parallel worker pools
func (c *Collector) collectFindingsParallel(ctx context.Context, repos []*models.Repository) ([]*models.Finding, error) {
	// Create worker pool
	workerCount := c.config.GetWorkerPoolSize()
	jobs := make(chan *models.Repository, len(repos))
	results := make(chan []*models.Finding, len(repos))
	errors := make(chan error, len(repos))
	
	var wg sync.WaitGroup

	// Start workers
	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go c.worker(ctx, w, jobs, results, errors, &wg)
	}

	// Send jobs
	go func() {
		defer close(jobs)
		for _, repo := range repos {
			select {
			case jobs <- repo:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for workers to complete
	go func() {
		wg.Wait()
		close(results)
		close(errors)
	}()

	// Collect results
	var allFindings []*models.Finding
	var collectionErrors []error
	
	for i := 0; i < len(repos); i++ {
		select {
		case findings := <-results:
			if findings != nil {
				allFindings = append(allFindings, findings...)
			}
		case err := <-errors:
			if err != nil {
				collectionErrors = append(collectionErrors, err)
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Log collection errors but don't fail the entire operation
	for _, err := range collectionErrors {
		c.logger.WithError(err).Error("Repository collection error")
	}

	return allFindings, nil
}

// worker processes repositories and collects findings
func (c *Collector) worker(ctx context.Context, id int, jobs <-chan *models.Repository, results chan<- []*models.Finding, errors chan<- error, wg *sync.WaitGroup) {
	defer wg.Done()

	c.logger.WithField("worker", id).Debug("Worker started")

	for repo := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
			findings, err := c.collectRepositoryFindings(ctx, repo)
			if err != nil {
				c.logger.WithFields(logrus.Fields{
					"worker": id,
					"repo":   repo.FullName,
					"error":  err.Error(),
				}).Error("Failed to collect repository findings")
				errors <- err
				results <- nil
			} else {
				c.logger.WithFields(logrus.Fields{
					"worker":   id,
					"repo":     repo.FullName,
					"findings": len(findings),
				}).Debug("Collected repository findings")
				results <- findings
				errors <- nil
			}
		}
	}

	c.logger.WithField("worker", id).Debug("Worker completed")
}

// collectRepositoryFindings collects all types of findings for a single repository
func (c *Collector) collectRepositoryFindings(ctx context.Context, repo *models.Repository) ([]*models.Finding, error) {
	var allFindings []*models.Finding
	
	owner := repo.Owner
	repoName := repo.Name

	// Collect different types of findings in parallel
	var wg sync.WaitGroup
	var mu sync.Mutex
	
	findingTypes := []struct {
		name string
		fn   func(context.Context, string, string) ([]*models.Finding, error)
	}{
		{"code_scanning", c.client.GetCodeScanningAlerts},
		{"secret_scanning", c.client.GetSecretScanningAlerts},
		{"dependabot", c.client.GetDependabotAlerts},
	}

	for _, ft := range findingTypes {
		wg.Add(1)
		go func(findingType string, fetchFn func(context.Context, string, string) ([]*models.Finding, error)) {
			defer wg.Done()
			
			findings, err := fetchFn(ctx, owner, repoName)
			if err != nil {
				c.logger.WithFields(logrus.Fields{
					"repo": repo.FullName,
					"type": findingType,
					"error": err.Error(),
				}).Error("Failed to fetch findings")
				return
			}

			// Associate findings with repository and add to collection
			mu.Lock()
			for _, finding := range findings {
				finding.Repository = repo
				finding.RepoID = repo.ID
				allFindings = append(allFindings, finding)
			}
			mu.Unlock()

			c.logger.WithFields(logrus.Fields{
				"repo":     repo.FullName,
				"type":     findingType,
				"findings": len(findings),
			}).Debug("Collected findings")
		}(ft.name, ft.fn)
	}

	wg.Wait()
	return allFindings, nil
}

// GetCollectionStats returns statistics about the collection process
func (c *Collector) GetCollectionStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Get rate limit information
	if rateLimits, _, err := c.client.GetRateLimit(ctx); err == nil {
		stats["rate_limits"] = map[string]interface{}{
			"core": map[string]interface{}{
				"limit":     rateLimits.Core.Limit,
				"remaining": rateLimits.Core.Remaining,
				"reset":     rateLimits.Core.Reset.Time,
			},
			"search": map[string]interface{}{
				"limit":     rateLimits.Search.Limit,
				"remaining": rateLimits.Search.Remaining,
				"reset":     rateLimits.Search.Reset.Time,
			},
		}
	}

	// Get storage statistics
	if dbStats, err := c.storage.GetStats(); err == nil {
		stats["storage"] = dbStats
	}

	// Get configuration
	stats["config"] = map[string]interface{}{
		"organization":  c.config.Organization,
		"env_type":      c.config.EnvType,
		"max_workers":   c.config.MaxWorkers,
		"cache_enabled": c.config.CacheEnabled,
	}

	return stats, nil
}

// DeltaUpdate performs incremental updates for repositories that have changed
func (c *Collector) DeltaUpdate(ctx context.Context, since time.Time) ([]*models.Finding, error) {
	c.logger.WithField("since", since).Info("Starting delta update")

	// Get repositories from storage
	repos, err := c.storage.GetRepositories(c.config.EnvType)
	if err != nil {
		return nil, fmt.Errorf("failed to get repositories from storage: %w", err)
	}

	// Filter repositories that might have new findings
	var reposToUpdate []*models.Repository
	for _, repo := range repos {
		if repo.UpdatedAt.After(since) {
			reposToUpdate = append(reposToUpdate, repo)
		}
	}

	c.logger.WithFields(logrus.Fields{
		"total_repos":   len(repos),
		"repos_to_update": len(reposToUpdate),
	}).Info("Filtered repositories for delta update")

	if len(reposToUpdate) == 0 {
		return []*models.Finding{}, nil
	}

	// Collect findings for updated repositories
	return c.collectFindingsParallel(ctx, reposToUpdate)
}

// CleanupCache removes expired cache entries
func (c *Collector) CleanupCache() error {
	return c.storage.CleanupExpiredCache()
} 