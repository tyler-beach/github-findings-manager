package models

import (
	"fmt"
	"time"
)

// Config holds the application configuration
type Config struct {
	Organization  string
	EnvType       string
	SpecificRepos []string
	PodFilter     []string
	OutputDir     string
	Token         string
	Verbose       bool
	CSVOutput     bool
	NoCache       bool
	IncludeClosedFindings bool // Whether to include closed/resolved findings
	// Manual repository assignments when custom properties aren't available
	RepoAssignments map[string]RepoAssignment
}

// RepoAssignment holds manual repository assignments
type RepoAssignment struct {
	EnvironmentType string `json:"environment_type"`
	Pod             string `json:"pod"`
}

// Repository represents a GitHub repository with its properties
type Repository struct {
	Name                string    `json:"name"`
	FullName            string    `json:"full_name"`
	Pod                 string    `json:"pod"`
	EnvironmentType     string    `json:"environment_type"`
	CodeScanningEnabled bool      `json:"code_scanning_enabled"`
	SecretsEnabled      bool      `json:"secrets_enabled"`
	DependabotEnabled   bool      `json:"dependabot_enabled"`
	LastUpdated         time.Time `json:"last_updated"`
	AccessErrors        []string  `json:"access_errors,omitempty"`
}

// Finding represents a security finding
type Finding struct {
	ID             int       `json:"id"`
	Repository     string    `json:"repository"`
	Type           string    `json:"type"` // "code_scanning", "secrets", "dependabot"
	Severity       string    `json:"severity"`
	State          string    `json:"state"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Title          string    `json:"title"`
	Description    string    `json:"description"`
	Pod            string    `json:"pod"`
	Attribution    string    `json:"attribution"` // "attributed" or "unattributed"
	Quarter        string    `json:"quarter"`
	URL            string    `json:"url"`
	RuleID         string    `json:"rule_id,omitempty"`
	SecretType     string    `json:"secret_type,omitempty"`
	PackageName    string    `json:"package_name,omitempty"`
	VulnerableVersionRange string `json:"vulnerable_version_range,omitempty"`
}

// CollectionResults holds all collected data
type CollectionResults struct {
	Organization  string                 `json:"organization"`
	CollectedAt   time.Time             `json:"collected_at"`
	Repositories  map[string]*Repository `json:"repositories"`
	Findings      []*Finding            `json:"findings"`
	Errors        []CollectionError     `json:"errors"`
	Stats         CollectionStats       `json:"stats"`
}

// CollectionError represents an error during collection
type CollectionError struct {
	Repository string    `json:"repository"`
	Type       string    `json:"type"`
	Message    string    `json:"message"`
	StatusCode int       `json:"status_code"`
	Timestamp  time.Time `json:"timestamp"`
}

// CollectionStats holds statistics about the collection
type CollectionStats struct {
	TotalRepos           int           `json:"total_repos"`
	ProcessedRepos       int           `json:"processed_repos"`
	SkippedRepos         int           `json:"skipped_repos"`
	ErrorRepos           int           `json:"error_repos"`
	TotalFindings        int           `json:"total_findings"`
	CodeScanningFindings int           `json:"code_scanning_findings"`
	SecretsFindings      int           `json:"secrets_findings"`
	DependabotFindings   int           `json:"dependabot_findings"`
	AttributedFindings   int           `json:"attributed_findings"`
	UnattributedFindings int           `json:"unattributed_findings"`
	APICallsTotal        int           `json:"api_calls_total"`
	CacheHits            int           `json:"cache_hits"`
	Duration             time.Duration `json:"duration"`
}

// GetTotalFindings returns the total number of findings
func (cr *CollectionResults) GetTotalFindings() int {
	return len(cr.Findings)
}

// GetAttributedFindings returns findings that are attributed to a pod
func (cr *CollectionResults) GetAttributedFindings() []*Finding {
	var attributed []*Finding
	for _, finding := range cr.Findings {
		if finding.Pod != "" && finding.Pod != "unattributed" {
			attributed = append(attributed, finding)
		}
	}
	return attributed
}

// GetUnattributedFindings returns findings that are not attributed to any pod
func (cr *CollectionResults) GetUnattributedFindings() []*Finding {
	var unattributed []*Finding
	for _, finding := range cr.Findings {
		if finding.Pod == "" || finding.Pod == "unattributed" {
			unattributed = append(unattributed, finding)
		}
	}
	return unattributed
}

// GetFindingsByType returns findings grouped by type
func (cr *CollectionResults) GetFindingsByType() map[string][]*Finding {
	byType := make(map[string][]*Finding)
	for _, finding := range cr.Findings {
		byType[finding.Type] = append(byType[finding.Type], finding)
	}
	return byType
}

// GetFindingsByQuarter returns findings grouped by quarter
func (cr *CollectionResults) GetFindingsByQuarter() map[string][]*Finding {
	byQuarter := make(map[string][]*Finding)
	for _, finding := range cr.Findings {
		if finding.Quarter == "" {
			finding.Quarter = getQuarter(finding.CreatedAt)
		}
		byQuarter[finding.Quarter] = append(byQuarter[finding.Quarter], finding)
	}
	return byQuarter
}

// GetFindingsByPod returns findings grouped by pod
func (cr *CollectionResults) GetFindingsByPod() map[string][]*Finding {
	byPod := make(map[string][]*Finding)
	for _, finding := range cr.Findings {
		pod := finding.Pod
		if pod == "" {
			pod = "unattributed"
		}
		byPod[pod] = append(byPod[pod], finding)
	}
	return byPod
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

// CustomProperty represents a GitHub repository custom property
type CustomProperty struct {
	PropertyName string      `json:"property_name"`
	Value        interface{} `json:"value"` // Can be string, array, null, etc.
}

// RateLimitInfo holds rate limit information
type RateLimitInfo struct {
	Limit     int       `json:"limit"`
	Remaining int       `json:"remaining"`
	ResetTime time.Time `json:"reset_time"`
} 