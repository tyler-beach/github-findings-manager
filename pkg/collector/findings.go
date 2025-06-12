package collector

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/go-github/v57/github"

	"github_findings_manager/pkg/cache"
	"github_findings_manager/pkg/models"
)

// checkSecurityFeatures checks what security features are enabled for a repository
func (c *Collector) checkSecurityFeatures(ctx context.Context, repo *models.Repository) {
	// Optimize by checking features in parallel if eager loading is enabled
	if c.config.UseEagerLoading {
		var wg sync.WaitGroup
		wg.Add(3) // Three features to check
		
		// Check features in parallel to speed up processing
		go func() {
			defer wg.Done()
			repo.CodeScanningEnabled = c.isCodeScanningEnabled(ctx, repo.Name)
		}()
		
		go func() {
			defer wg.Done()
			repo.SecretsEnabled = c.isSecretScanningEnabled(ctx, repo.Name)
		}()
		
		go func() {
			defer wg.Done()
			repo.DependabotEnabled = c.isDependabotEnabled(ctx, repo.Name)
		}()
		
		wg.Wait()
		
	} else {
		// Sequential checks (original behavior)
		repo.CodeScanningEnabled = c.isCodeScanningEnabled(ctx, repo.Name)
		repo.SecretsEnabled = c.isSecretScanningEnabled(ctx, repo.Name)
		repo.DependabotEnabled = c.isDependabotEnabled(ctx, repo.Name)
	}
}

// isCodeScanningEnabled checks if code scanning is enabled for a repository
func (c *Collector) isCodeScanningEnabled(ctx context.Context, repoName string) bool {
	// Try to get from cache first
	if c.cache != nil {
		cacheKey := cache.GenerateKey("code_scanning_enabled", c.config.Organization, repoName)
		if entry, hit := c.cache.Get(cacheKey); hit {
			c.mu.Lock()
			c.stats.CacheHits++
			c.mu.Unlock()
			enabled := len(entry.Data) > 0 && entry.Data[0] == 1
			return enabled
		}
	}

	if err := c.rateLimiter.Wait(ctx); err != nil {
		return false
	}

	_, resp, err := c.client.CodeScanning.ListAlertsForRepo(ctx, c.config.Organization, repoName, 
		&github.AlertListOptions{State: "open", ListOptions: github.ListOptions{PerPage: 1}})
	
	c.stats.APICallsTotal++
	
	// If we get a 404, code scanning is not enabled
	// If we get 200, it's enabled
	enabled := err == nil || (resp != nil && resp.StatusCode != 404)
	
	// Cache the result for future queries
	if c.cache != nil {
		var data []byte
		if enabled {
			data = []byte{1} // true
		} else {
			data = []byte{0} // false
		}
		etag := ""
		if resp != nil {
			etag = resp.Header.Get("ETag")
		}
		c.cache.Set(cache.GenerateKey("code_scanning_enabled", c.config.Organization, repoName), 
		            etag, data, defaultTTL)
	}
	
	return enabled
}

// isSecretScanningEnabled checks if secret scanning is enabled for a repository
func (c *Collector) isSecretScanningEnabled(ctx context.Context, repoName string) bool {
	if err := c.rateLimiter.Wait(ctx); err != nil {
		return false
	}

	_, resp, err := c.client.SecretScanning.ListAlertsForRepo(ctx, c.config.Organization, repoName,
		&github.SecretScanningAlertListOptions{State: "open", ListOptions: github.ListOptions{PerPage: 1}})
	
	c.stats.APICallsTotal++
	
	return err == nil || (resp != nil && resp.StatusCode != 404)
}

// isDependabotEnabled checks if Dependabot is enabled for a repository
func (c *Collector) isDependabotEnabled(ctx context.Context, repoName string) bool {
	if err := c.rateLimiter.Wait(ctx); err != nil {
		return false
	}

	_, resp, err := c.client.Dependabot.ListRepoAlerts(ctx, c.config.Organization, repoName,
		&github.ListAlertsOptions{State: github.String("open"), ListOptions: github.ListOptions{PerPage: 1}})
	
	c.stats.APICallsTotal++
	
	return err == nil || (resp != nil && resp.StatusCode != 404)
}

// getCodeScanningFindings fetches code scanning findings for a repository
func (c *Collector) getCodeScanningFindings(ctx context.Context, repo *models.Repository) ([]*models.Finding, []models.CollectionError) {
	var findings []*models.Finding
	var errors []models.CollectionError

	// Configure state filter based on configuration
	state := "open"
	if c.config.IncludeClosedFindings {
		state = "all" // GitHub API supports "all", "open", "closed"
	}

	opts := &github.AlertListOptions{
		State: state,
		ListOptions: github.ListOptions{PerPage: 100},
	}

	pageCount := 0
	for {
		pageCount++
		if err := c.rateLimiter.Wait(ctx); err != nil {
			errors = append(errors, models.CollectionError{
				Repository: repo.Name,
				Type:       "code_scanning",
				Message:    fmt.Sprintf("Rate limiter error: %v", err),
				Timestamp:  time.Now(),
			})
			break
		}

		alerts, resp, err := c.client.CodeScanning.ListAlertsForRepo(ctx, c.config.Organization, repo.Name, opts)
		if err != nil {
			statusCode := 0
			if resp != nil {
				statusCode = resp.StatusCode
			}

			errors = append(errors, models.CollectionError{
				Repository: repo.Name,
				Type:       "code_scanning",
				Message:    fmt.Sprintf("Failed to fetch code scanning alerts: %v", err),
				StatusCode: statusCode,
				Timestamp:  time.Now(),
			})

			// Don't retry for 401/403 errors
			if statusCode == 401 || statusCode == 403 {
				break
			}
		}

		c.stats.APICallsTotal++

		for _, alert := range alerts {
			finding := &models.Finding{
				ID:          int(alert.GetNumber()),
				Repository:  repo.Name,
				Type:        "code_scanning",
				Severity:    alert.GetRule().GetSeverity(),
				State:       alert.GetState(),
				CreatedAt:   alert.GetCreatedAt().Time,
				UpdatedAt:   alert.GetUpdatedAt().Time,
				Title:       alert.GetRule().GetDescription(),
				Description: alert.GetRule().GetFullDescription(),
				URL:         alert.GetHTMLURL(),
				RuleID:      alert.GetRule().GetID(),
			}
			findings = append(findings, finding)
		}

		// Debug pagination info
		if c.config.Verbose {
			fmt.Printf("Code scanning %s: page %d, %d alerts, next page: %d\n", 
				repo.Name, pageCount, len(alerts), resp.NextPage)
		}

		if resp.NextPage == 0 {
			break
		}
		opts.ListOptions.Page = resp.NextPage
	}

	c.mu.Lock()
	c.stats.CodeScanningFindings += len(findings)
	c.mu.Unlock()

	return findings, errors
}

// getSecretScanningFindings fetches secret scanning findings for a repository
func (c *Collector) getSecretScanningFindings(ctx context.Context, repo *models.Repository) ([]*models.Finding, []models.CollectionError) {
	var findings []*models.Finding
	var errors []models.CollectionError

	// Configure state filter based on configuration
	state := "open"
	if c.config.IncludeClosedFindings {
		state = "all" // GitHub API supports "all", "open", "resolved"
	}

	opts := &github.SecretScanningAlertListOptions{
		State: state,
		ListOptions: github.ListOptions{PerPage: 100},
	}

	pageCount := 0
	for {
		pageCount++
		if err := c.rateLimiter.Wait(ctx); err != nil {
			errors = append(errors, models.CollectionError{
				Repository: repo.Name,
				Type:       "secrets",
				Message:    fmt.Sprintf("Rate limiter error: %v", err),
				Timestamp:  time.Now(),
			})
			break
		}

		alerts, resp, err := c.client.SecretScanning.ListAlertsForRepo(ctx, c.config.Organization, repo.Name, opts)
		if err != nil {
			statusCode := 0
			if resp != nil {
				statusCode = resp.StatusCode
			}

			errors = append(errors, models.CollectionError{
				Repository: repo.Name,
				Type:       "secrets",
				Message:    fmt.Sprintf("Failed to fetch secret scanning alerts: %v", err),
				StatusCode: statusCode,
				Timestamp:  time.Now(),
			})

			if statusCode == 401 || statusCode == 403 {
				break
			}
		}

		c.stats.APICallsTotal++

		for _, alert := range alerts {
			finding := &models.Finding{
				ID:         int(alert.GetNumber()),
				Repository: repo.Name,
				Type:       "secrets",
				Severity:   "high", // Secrets are typically high severity
				State:      alert.GetState(),
				CreatedAt:  alert.GetCreatedAt().Time,
				UpdatedAt:  alert.GetUpdatedAt().Time,
				Title:      fmt.Sprintf("Secret detected: %s", alert.GetSecretType()),
				URL:        alert.GetHTMLURL(),
				SecretType: alert.GetSecretType(),
			}
			findings = append(findings, finding)
		}

		// Debug pagination info
		if c.config.Verbose {
			fmt.Printf("Secret scanning %s: page %d, %d alerts, next page: %d\n", 
				repo.Name, pageCount, len(alerts), resp.NextPage)
		}

		if resp.NextPage == 0 {
			break
		}
		opts.ListOptions.Page = resp.NextPage
	}

	c.mu.Lock()
	c.stats.SecretsFindings += len(findings)
	c.mu.Unlock()

	return findings, errors
}

// getDependabotFindings fetches Dependabot findings for a repository
func (c *Collector) getDependabotFindings(ctx context.Context, repo *models.Repository) ([]*models.Finding, []models.CollectionError) {
	var findings []*models.Finding
	var errors []models.CollectionError

	// Configure state filter based on configuration
	var stateFilter *string
	if c.config.IncludeClosedFindings {
		stateFilter = nil // No state filter = all states
	} else {
		stateFilter = github.String("open")
	}

	opts := &github.ListAlertsOptions{
		State: stateFilter,
		ListOptions: github.ListOptions{PerPage: 100},
	}

	pageCount := 0
	for {
		pageCount++
		if err := c.rateLimiter.Wait(ctx); err != nil {
			errors = append(errors, models.CollectionError{
				Repository: repo.Name,
				Type:       "dependabot",
				Message:    fmt.Sprintf("Rate limiter error: %v", err),
				Timestamp:  time.Now(),
			})
			break
		}

		alerts, resp, err := c.client.Dependabot.ListRepoAlerts(ctx, c.config.Organization, repo.Name, opts)
		if err != nil {
			statusCode := 0
			if resp != nil {
				statusCode = resp.StatusCode
			}

			errors = append(errors, models.CollectionError{
				Repository: repo.Name,
				Type:       "dependabot",
				Message:    fmt.Sprintf("Failed to fetch Dependabot alerts: %v", err),
				StatusCode: statusCode,
				Timestamp:  time.Now(),
			})

			if statusCode == 401 || statusCode == 403 {
				break
			}
		}

		c.stats.APICallsTotal++

		for _, alert := range alerts {
			var packageName, versionRange string
			if alert.Dependency != nil {
				packageName = alert.Dependency.GetPackage().GetName()
			}
			if alert.SecurityVulnerability != nil {
				versionRange = alert.SecurityVulnerability.GetVulnerableVersionRange()
			}

			finding := &models.Finding{
				ID:                     int(alert.GetNumber()),
				Repository:             repo.Name,
				Type:                   "dependabot",
				Severity:               alert.GetSecurityVulnerability().GetSeverity(),
				State:                  alert.GetState(),
				CreatedAt:              alert.GetCreatedAt().Time,
				UpdatedAt:              alert.GetUpdatedAt().Time,
				Title:                  alert.GetSecurityAdvisory().GetSummary(),
				Description:            alert.GetSecurityAdvisory().GetDescription(),
				URL:                    alert.GetHTMLURL(),
				PackageName:            packageName,
				VulnerableVersionRange: versionRange,
			}
			findings = append(findings, finding)
		}

		// Debug pagination info
		if c.config.Verbose {
			fmt.Printf("Dependabot %s: page %d, %d alerts, next page: %d\n", 
				repo.Name, pageCount, len(alerts), resp.NextPage)
		}

		if resp.NextPage == 0 {
			break
		}
		opts.ListOptions.Page = resp.NextPage
	}

	c.mu.Lock()
	c.stats.DependabotFindings += len(findings)
	c.mu.Unlock()

	return findings, errors
}

// updateFindingStats updates statistics based on collected findings
func (c *Collector) updateFindingStats(findings []*models.Finding) {
	for _, finding := range findings {
		if finding.Attribution == "attributed" {
			c.stats.AttributedFindings++
		} else {
			c.stats.UnattributedFindings++
		}
	}
}

// getQuarter converts a time to quarter string (e.g., "2024-Q1")
func getQuarter(t time.Time) string {
	year := t.Year()
	month := t.Month()
	
	var quarter int
	switch {
	case month >= 1 && month <= 3:
		quarter = 1
	case month >= 4 && month <= 6:
		quarter = 2
	case month >= 7 && month <= 9:
		quarter = 3
	case month >= 10 && month <= 12:
		quarter = 4
	}
	
	return fmt.Sprintf("%d-Q%d", year, quarter)
} 