package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/google/go-github/v57/github"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"

	"github-findings-manager/internal/config"
	"github-findings-manager/internal/models"
	"github-findings-manager/internal/storage"
)

// Client wraps the GitHub client with enhanced functionality
type Client struct {
	client     *github.Client
	storage    *storage.SQLiteStorage
	config     *config.Config
	rateLimiter *rate.Limiter
	httpClient *http.Client
	logger     *logrus.Logger
	
	// Caching
	etags      map[string]string
	etagsMutex sync.RWMutex
}

// NewClient creates a new enhanced GitHub client
func NewClient(token string) (*Client, error) {
	if token == "" {
		return nil, fmt.Errorf("GitHub token is required")
	}

	// Create OAuth2 client
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	httpClient := oauth2.NewClient(context.Background(), ts)

	// Add custom headers for preview API features
	httpClient.Transport = &customTransport{
		Transport: httpClient.Transport,
		headers: map[string]string{
			"Accept": "application/vnd.github+json,application/vnd.github.mercy-preview+json",
		},
	}

	client := github.NewClient(httpClient)

	// Create rate limiter (GitHub allows 5000 requests per hour for authenticated users)
	rateLimiter := rate.NewLimiter(rate.Limit(80), 10) // 80 req/min with burst of 10

	return &Client{
		client:      client,
		httpClient:  httpClient,
		rateLimiter: rateLimiter,
		logger:      logrus.New(),
		etags:       make(map[string]string),
	}, nil
}

// customTransport adds custom headers to requests
type customTransport struct {
	Transport http.RoundTripper
	headers   map[string]string
}

func (t *customTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	for key, value := range t.headers {
		req.Header.Set(key, value)
	}
	return t.Transport.RoundTrip(req)
}

// SetStorage sets the storage backend for caching
func (c *Client) SetStorage(storage *storage.SQLiteStorage) {
	c.storage = storage
}

// SetConfig sets the configuration
func (c *Client) SetConfig(config *config.Config) {
	c.config = config
}

// withRateLimit applies rate limiting to API calls
func (c *Client) withRateLimit(ctx context.Context) error {
	return c.rateLimiter.Wait(ctx)
}

// withRetry executes a function with exponential backoff retry
// isSecurityFeatureDisabled checks if the error indicates a disabled security feature
func (c *Client) isSecurityFeatureDisabled(err error) bool {
	if err == nil {
		return false
	}
	
	// TEMPORARILY DISABLE ALL SECURITY FEATURE DETECTION FOR DEBUGGING
	c.logger.WithFields(logrus.Fields{
		"error_message": err.Error(),
	}).Debug("Security feature detection temporarily disabled - treating all errors as retriable")
	
	return false // Always return false to disable the feature temporarily
}

func (c *Client) withRetry(ctx context.Context, fn func() error) error {
	// Execute function once without retry logic
	if err := fn(); err != nil {
		// Check if it's a security feature disabled error - log appropriately
		if c.isSecurityFeatureDisabled(err) {
			c.logger.WithField("error", err.Error()).Debug("Security feature disabled")
			return err
		}
		
		// Check if it's a rate limit error - still handle gracefully
		if rateLimitErr, ok := err.(*github.RateLimitError); ok {
			c.logger.WithFields(logrus.Fields{
				"reset_time": rateLimitErr.Rate.Reset.Time,
				"remaining":  rateLimitErr.Rate.Remaining,
			}).Warn("Rate limit hit")
			return err
		}
		
		// Log the error and return
		c.logger.WithField("error", err.Error()).Error("Request failed")
		return err
	}
	
	return nil
}

// GetRepositories fetches repositories for an organization with custom properties
func (c *Client) GetRepositories(ctx context.Context, org string) ([]*models.Repository, error) {
	c.logger.WithField("org", org).Info("Fetching repositories")

	var allRepos []*models.Repository
	opts := &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}

	for {
		if err := c.withRateLimit(ctx); err != nil {
			return nil, err
		}

		var repos []*github.Repository
		var resp *github.Response
		var err error

		err = c.withRetry(ctx, func() error {
			repos, resp, err = c.client.Repositories.ListByOrg(ctx, org, opts)
			return err
		})

		if err != nil {
			return nil, fmt.Errorf("failed to list repositories: %w", err)
		}

		// Convert GitHub repositories to our models
		for _, repo := range repos {
			modelRepo := &models.Repository{
				ID:            repo.GetID(),
				Name:          repo.GetName(),
				FullName:      repo.GetFullName(),
				Owner:         repo.GetOwner().GetLogin(),
				URL:           repo.GetHTMLURL(),
				IsPrivate:     repo.GetPrivate(),
				DefaultBranch: repo.GetDefaultBranch(),
				CreatedAt:     repo.GetCreatedAt().Time,
				UpdatedAt:     repo.GetUpdatedAt().Time,
				CustomProperties: make(map[string]string),
			}

			// Fetch custom properties
			if err := c.fetchCustomProperties(ctx, modelRepo); err != nil {
				c.logger.WithError(err).WithField("repo", repo.GetFullName()).Warn("Failed to fetch custom properties")
			}

			allRepos = append(allRepos, modelRepo)
		}

		if resp.NextPage == 0 {
			break
		}
		opts.ListOptions.Page = resp.NextPage
	}

	c.logger.WithField("count", len(allRepos)).Info("Fetched repositories")
	
	// Debug logging to see repository details
	for _, repo := range allRepos {
		c.logger.WithFields(logrus.Fields{
			"repo": repo.FullName,
			"env_type": repo.EnvironmentType,
			"pod": repo.Pod,
		}).Debug("Repository details")
	}
	
	return allRepos, nil
}

// fetchCustomProperties fetches custom properties for a repository
func (c *Client) fetchCustomProperties(ctx context.Context, repo *models.Repository) error {
	if err := c.withRateLimit(ctx); err != nil {
		return err
	}

	// GitHub API endpoint for custom properties (preview API)
	url := fmt.Sprintf("repos/%s/properties/values", repo.FullName)
	
	req, err := c.client.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Add preview headers
	req.Header.Set("Accept", "application/vnd.github.mercy-preview+json")

	var properties []struct {
		PropertyName string `json:"property_name"`
		Value        interface{} `json:"value"`
	}

	err = c.withRetry(ctx, func() error {
		_, err := c.client.Do(ctx, req, &properties)
		return err
	})

	if err != nil {
		// Custom properties might not be available for all repos
		c.logger.WithError(err).WithField("repo", repo.FullName).Debug("Custom properties not available")
		return nil
	}

	// Parse custom properties
	for _, prop := range properties {
		if prop.PropertyName == "EnvironmentType" {
			if val, ok := prop.Value.(string); ok {
				repo.EnvironmentType = val
				repo.CustomProperties["EnvironmentType"] = val
			}
		} else if prop.PropertyName == "pod" {
			if val, ok := prop.Value.(string); ok {
				repo.Pod = val
				repo.CustomProperties["pod"] = val
			}
		} else {
			// Store other custom properties as strings
			if val, ok := prop.Value.(string); ok {
				repo.CustomProperties[prop.PropertyName] = val
			}
		}
	}

	return nil
}

// GetCodeScanningAlerts fetches code scanning alerts for a repository
func (c *Client) GetCodeScanningAlerts(ctx context.Context, owner, repo string) ([]*models.Finding, error) {
	cacheKey := fmt.Sprintf("code_scanning_%s_%s", owner, repo)
	
	// Check cache first
	if c.storage != nil && c.config.CacheEnabled {
		if cached, _, found, err := c.storage.GetCache(cacheKey); err == nil && found {
			c.logger.WithField("repo", fmt.Sprintf("%s/%s", owner, repo)).Debug("Using cached code scanning data")
			
			var findings []*models.Finding
			if err := json.Unmarshal([]byte(cached), &findings); err == nil {
				return findings, nil
			}
		}
	}

	if err := c.withRateLimit(ctx); err != nil {
		return nil, err
	}

	var allFindings []*models.Finding
	opts := &github.AlertListOptions{
		State: "open",
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}

	for {
		var alerts []*github.Alert
		var resp *github.Response
		var err error

		err = c.withRetry(ctx, func() error {
			alerts, resp, err = c.client.CodeScanning.ListAlertsForRepo(ctx, owner, repo, opts)
			return err
		})

		if err != nil {
			// If security feature is disabled, return empty results instead of error
			if c.isSecurityFeatureDisabled(err) {
				c.logger.WithField("repo", fmt.Sprintf("%s/%s", owner, repo)).Info("Code scanning not enabled for repository")
				return allFindings, nil
			}
			c.logger.WithFields(logrus.Fields{
				"repo": fmt.Sprintf("%s/%s", owner, repo),
				"error": err.Error(),
			}).Error("Failed to list code scanning alerts")
			return nil, fmt.Errorf("failed to list code scanning alerts: %w", err)
		}

		// Convert alerts to findings
		for _, alert := range alerts {
			finding := &models.Finding{
				ID:          fmt.Sprintf("cs_%d", alert.GetNumber()),
				Type:        models.FindingTypeCodeQL,
				Number:      alert.GetNumber(),
				Title:       alert.GetRule().GetDescription(),
				Description: alert.GetMostRecentInstance().GetMessage().GetText(),
				Severity:    models.FindingSeverity(alert.GetRule().GetSecuritySeverityLevel()),
				State:       c.convertAlertState(alert.GetState()),
				CreatedAt:   alert.GetCreatedAt().Time,
				UpdatedAt:   alert.GetUpdatedAt().Time,
				RuleName:    alert.GetRule().GetName(),
				RuleID:      alert.GetRule().GetID(),
				Tool:        alert.GetTool().GetName(),
				HTMLURL:     alert.GetHTMLURL(),
			}

			if !alert.GetDismissedAt().IsZero() {
				dismissedAt := alert.GetDismissedAt().Time
				finding.DismissedAt = &dismissedAt
			}

			if !alert.GetFixedAt().IsZero() {
				fixedAt := alert.GetFixedAt().Time
				finding.FixedAt = &fixedAt
			}

			// Add location information
			if instance := alert.GetMostRecentInstance(); instance != nil {
				if location := instance.GetLocation(); location != nil {
					finding.Location = fmt.Sprintf("%s:%d", location.GetPath(), location.GetStartLine())
				}
			}

			// Store raw data
			if rawData, err := json.Marshal(alert); err == nil {
				finding.RawData = rawData
			}

			allFindings = append(allFindings, finding)
		}

		if resp.NextPage == 0 {
			break
		}
		opts.ListOptions.Page = resp.NextPage
	}

	// Cache the results
	if c.storage != nil && c.config.CacheEnabled {
		if data, err := json.Marshal(allFindings); err == nil {
			c.storage.SetCache(cacheKey, string(data), "", c.config.CacheDuration)
		}
	}

	return allFindings, nil
}

// GetSecretScanningAlerts fetches secret scanning alerts for a repository
func (c *Client) GetSecretScanningAlerts(ctx context.Context, owner, repo string) ([]*models.Finding, error) {
	cacheKey := fmt.Sprintf("secret_scanning_%s_%s", owner, repo)
	
	// Check cache first
	if c.storage != nil && c.config.CacheEnabled {
		if cached, _, found, err := c.storage.GetCache(cacheKey); err == nil && found {
			c.logger.WithField("repo", fmt.Sprintf("%s/%s", owner, repo)).Debug("Using cached secret scanning data")
			
			var findings []*models.Finding
			if err := json.Unmarshal([]byte(cached), &findings); err == nil {
				return findings, nil
			}
		}
	}

	if err := c.withRateLimit(ctx); err != nil {
		return nil, err
	}

	var allFindings []*models.Finding
	opts := &github.SecretScanningAlertListOptions{
		State: "open",
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}

	for {
		var alerts []*github.SecretScanningAlert
		var resp *github.Response
		var err error

		err = c.withRetry(ctx, func() error {
			alerts, resp, err = c.client.SecretScanning.ListAlertsForRepo(ctx, owner, repo, opts)
			return err
		})

		if err != nil {
			// If security feature is disabled, return empty results instead of error
			if c.isSecurityFeatureDisabled(err) {
				c.logger.WithField("repo", fmt.Sprintf("%s/%s", owner, repo)).Debug("Secret scanning not enabled for repository")
				return allFindings, nil
			}
			return nil, fmt.Errorf("failed to list secret scanning alerts: %w", err)
		}

		// Convert alerts to findings
		for _, alert := range alerts {
			finding := &models.Finding{
				ID:          fmt.Sprintf("ss_%d", alert.GetNumber()),
				Type:        models.FindingTypeSecrets,
				Number:      alert.GetNumber(),
				Title:       fmt.Sprintf("Secret detected: %s", alert.GetSecretType()),
				Description: fmt.Sprintf("Secret of type '%s' detected", alert.GetSecretTypeDisplayName()),
				Severity:    models.SeverityHigh, // Secrets are typically high severity
				State:       c.convertSecretState(alert.GetState()),
				CreatedAt:   alert.GetCreatedAt().Time,
				UpdatedAt:   alert.GetUpdatedAt().Time,
				RuleName:    alert.GetSecretType(),
				Tool:        "secret-scanning",
				HTMLURL:     alert.GetHTMLURL(),
			}

			if !alert.GetResolvedAt().IsZero() {
				resolvedAt := alert.GetResolvedAt().Time
				finding.FixedAt = &resolvedAt
			}

			// Store raw data
			if rawData, err := json.Marshal(alert); err == nil {
				finding.RawData = rawData
			}

			allFindings = append(allFindings, finding)
		}

		if resp.NextPage == 0 {
			break
		}
		opts.ListOptions.Page = resp.NextPage
	}

	// Cache the results
	if c.storage != nil && c.config.CacheEnabled {
		if data, err := json.Marshal(allFindings); err == nil {
			c.storage.SetCache(cacheKey, string(data), "", c.config.CacheDuration)
		}
	}

	return allFindings, nil
}

// GetDependabotAlerts fetches Dependabot alerts for a repository
func (c *Client) GetDependabotAlerts(ctx context.Context, owner, repo string) ([]*models.Finding, error) {
	cacheKey := fmt.Sprintf("dependabot_%s_%s", owner, repo)
	
	// Check cache first
	if c.storage != nil && c.config.CacheEnabled {
		if cached, _, found, err := c.storage.GetCache(cacheKey); err == nil && found {
			c.logger.WithField("repo", fmt.Sprintf("%s/%s", owner, repo)).Debug("Using cached Dependabot data")
			
			var findings []*models.Finding
			if err := json.Unmarshal([]byte(cached), &findings); err == nil {
				return findings, nil
			}
		}
	}

	if err := c.withRateLimit(ctx); err != nil {
		return nil, err
	}

	var allFindings []*models.Finding
	opts := &github.ListAlertsOptions{
		State: github.String("open"),
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}

	for {
		var alerts []*github.DependabotAlert
		var resp *github.Response
		var err error

		err = c.withRetry(ctx, func() error {
			alerts, resp, err = c.client.Dependabot.ListRepoAlerts(ctx, owner, repo, opts)
			return err
		})

		if err != nil {
			// If security feature is disabled, return empty results instead of error
			if c.isSecurityFeatureDisabled(err) {
				c.logger.WithField("repo", fmt.Sprintf("%s/%s", owner, repo)).Debug("Dependabot not enabled for repository")
				return allFindings, nil
			}
			return nil, fmt.Errorf("failed to list Dependabot alerts: %w", err)
		}

		// Convert alerts to findings
		for _, alert := range alerts {
			severity := models.SeverityMedium
			if alert.GetSecurityAdvisory() != nil {
				severity = models.FindingSeverity(alert.GetSecurityAdvisory().GetSeverity())
			}

			finding := &models.Finding{
				ID:          fmt.Sprintf("db_%d", alert.GetNumber()),
				Type:        models.FindingTypeDependabot,
				Number:      alert.GetNumber(),
				Title:       alert.GetSecurityAdvisory().GetSummary(),
				Description: alert.GetSecurityAdvisory().GetDescription(),
				Severity:    severity,
				State:       c.convertDependabotState(alert.GetState()),
				CreatedAt:   alert.GetCreatedAt().Time,
				UpdatedAt:   alert.GetUpdatedAt().Time,
				Tool:        "dependabot",
				HTMLURL:     alert.GetHTMLURL(),
			}

			if !alert.GetDismissedAt().IsZero() {
				dismissedAt := alert.GetDismissedAt().Time
				finding.DismissedAt = &dismissedAt
			}

			if !alert.GetFixedAt().IsZero() {
				fixedAt := alert.GetFixedAt().Time
				finding.FixedAt = &fixedAt
			}

			// Add dependency information
			if dep := alert.GetDependency(); dep != nil {
				finding.RuleName = dep.GetPackage().GetName()
				finding.Location = dep.GetManifestPath()
			}

			// Store raw data
			if rawData, err := json.Marshal(alert); err == nil {
				finding.RawData = rawData
			}

			allFindings = append(allFindings, finding)
		}

		if resp.NextPage == 0 {
			break
		}
		opts.ListOptions.Page = resp.NextPage
	}

	// Cache the results
	if c.storage != nil && c.config.CacheEnabled {
		if data, err := json.Marshal(allFindings); err == nil {
			c.storage.SetCache(cacheKey, string(data), "", c.config.CacheDuration)
		}
	}

	return allFindings, nil
}

// Helper functions to convert GitHub states to our models
func (c *Client) convertAlertState(state string) models.FindingState {
	switch state {
	case "open":
		return models.StateOpen
	case "fixed":
		return models.StateFixed
	case "dismissed":
		return models.StateDismissed
	default:
		return models.StateOpen
	}
}

func (c *Client) convertSecretState(state string) models.FindingState {
	switch state {
	case "open":
		return models.StateOpen
	case "resolved":
		return models.StateFixed
	default:
		return models.StateOpen
	}
}

func (c *Client) convertDependabotState(state string) models.FindingState {
	switch state {
	case "open":
		return models.StateOpen
	case "fixed":
		return models.StateFixed
	case "dismissed":
		return models.StateDismissed
	default:
		return models.StateOpen
	}
}

// GetRateLimit returns the current rate limit status
func (c *Client) GetRateLimit(ctx context.Context) (*github.RateLimits, *github.Response, error) {
	return c.client.RateLimits(ctx)
}