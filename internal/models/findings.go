package models

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// FindingType represents the type of security finding
type FindingType string

const (
	FindingTypeCodeQL     FindingType = "code_scanning"
	FindingTypeSecrets    FindingType = "secrets"
	FindingTypeDependabot FindingType = "dependabot"
)

// FindingSeverity represents the severity level of a finding
type FindingSeverity string

const (
	SeverityCritical FindingSeverity = "critical"
	SeverityHigh     FindingSeverity = "high"
	SeverityMedium   FindingSeverity = "medium"
	SeverityLow      FindingSeverity = "low"
	SeverityInfo     FindingSeverity = "info"
	SeverityNote     FindingSeverity = "note"
)

// FindingState represents the current state of a finding
type FindingState string

const (
	StateOpen     FindingState = "open"
	StateFixed    FindingState = "fixed"
	StateDismissed FindingState = "dismissed"
)

// Repository represents a GitHub repository with custom properties
type Repository struct {
	ID              int64             `json:"id" db:"id"`
	Name            string            `json:"name" db:"name"`
	FullName        string            `json:"full_name" db:"full_name"`
	Owner           string            `json:"owner" db:"owner"`
	URL             string            `json:"url" db:"url"`
	IsPrivate       bool              `json:"is_private" db:"is_private"`
	DefaultBranch   string            `json:"default_branch" db:"default_branch"`
	CustomProperties map[string]string `json:"custom_properties" db:"custom_properties"`
	Pod             string            `json:"pod" db:"pod"`
	EnvironmentType string            `json:"environment_type" db:"environment_type"`
	CreatedAt       time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at" db:"updated_at"`
}

// Finding represents a security finding from GitHub
type Finding struct {
	ID          string          `json:"id" db:"id"`
	Type        FindingType     `json:"type" db:"type"`
	Repository  *Repository     `json:"repository" db:"-"`
	RepoID      int64           `json:"repo_id" db:"repo_id"`
	Number      int             `json:"number" db:"number"`
	Title       string          `json:"title" db:"title"`
	Description string          `json:"description" db:"description"`
	Severity    FindingSeverity `json:"severity" db:"severity"`
	State       FindingState    `json:"state" db:"state"`
	CreatedAt   time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at" db:"updated_at"`
	FixedAt     *time.Time      `json:"fixed_at,omitempty" db:"fixed_at"`
	DismissedAt *time.Time      `json:"dismissed_at,omitempty" db:"dismissed_at"`
	
	// Finding-specific fields
	RuleName    string `json:"rule_name,omitempty" db:"rule_name"`
	RuleID      string `json:"rule_id,omitempty" db:"rule_id"`
	Tool        string `json:"tool,omitempty" db:"tool"`
	Location    string `json:"location,omitempty" db:"location"`
	
	// Metadata
	HTMLURL    string            `json:"html_url" db:"html_url"`
	RawData    json.RawMessage   `json:"raw_data,omitempty" db:"raw_data"`
	Metadata   map[string]string `json:"metadata,omitempty" db:"metadata"`
}

// FindingsSummary represents aggregated findings data
type FindingsSummary struct {
	TotalFindings    int                           `json:"total_findings"`
	ByType           map[FindingType]int           `json:"by_type"`
	BySeverity       map[FindingSeverity]int       `json:"by_severity"`
	ByState          map[FindingState]int          `json:"by_state"`
	ByOwnership      map[string]int                `json:"by_ownership"`
	ByQuarter        map[string]int                `json:"by_quarter"`
	Repositories     map[string]*RepositorySummary `json:"repositories"`
	GeneratedAt      time.Time                     `json:"generated_at"`
}

// RepositorySummary represents summary data for a repository
type RepositorySummary struct {
	Repository   *Repository                 `json:"repository"`
	FindingCount int                         `json:"finding_count"`
	BySeverity   map[FindingSeverity]int     `json:"by_severity"`
	ByType       map[FindingType]int         `json:"by_type"`
	ByState      map[FindingState]int        `json:"by_state"`
}

// GetQuarter returns the quarter string for a given time
func (f *Finding) GetQuarter() string {
	month := f.CreatedAt.Month()
	year := f.CreatedAt.Year()
	
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

// GetOwnership returns the ownership status based on Pod property
func (f *Finding) GetOwnership() string {
	if f.Repository == nil {
		return "Unknown"
	}
	
	pod := f.Repository.Pod
	// A repository is considered "Unowned" if:
	// 1. Pod is empty/not set
	// 2. Pod is explicitly set to "No Pod Selected"
	// 3. Pod is set to other unassigned values like "unknown" or "unassigned"
	if pod == "" || 
		strings.EqualFold(pod, "No Pod Selected") ||
		strings.ToLower(pod) == "unknown" || 
		strings.ToLower(pod) == "unassigned" {
		return "Unowned"
	}
	
	return "Owned"
}

// GetAgeInDays returns the age of the finding in days
func (f *Finding) GetAgeInDays() int {
	return int(time.Since(f.CreatedAt).Hours() / 24)
}

// IsOpen returns true if the finding is in an open state
func (f *Finding) IsOpen() bool {
	return f.State == StateOpen
}

// IsCritical returns true if the finding is critical or high severity
func (f *Finding) IsCritical() bool {
	return f.Severity == SeverityCritical || f.Severity == SeverityHigh
}

// QuarterlyFindings represents findings grouped by quarter
type QuarterlyFindings struct {
	Quarter  string     `json:"quarter"`
	Findings []*Finding `json:"findings"`
	Summary  struct {
		Total      int                     `json:"total"`
		BySeverity map[FindingSeverity]int `json:"by_severity"`
		ByType     map[FindingType]int     `json:"by_type"`
		ByState    map[FindingState]int    `json:"by_state"`
	} `json:"summary"`
}

// GroupFindingsByQuarter groups findings by quarter
func GroupFindingsByQuarter(findings []*Finding) map[string]*QuarterlyFindings {
	quarters := make(map[string]*QuarterlyFindings)
	
	for _, finding := range findings {
		quarter := finding.GetQuarter()
		
		if quarters[quarter] == nil {
			quarters[quarter] = &QuarterlyFindings{
				Quarter:  quarter,
				Findings: []*Finding{},
				Summary: struct {
					Total      int                     `json:"total"`
					BySeverity map[FindingSeverity]int `json:"by_severity"`
					ByType     map[FindingType]int     `json:"by_type"`
					ByState    map[FindingState]int    `json:"by_state"`
				}{
					BySeverity: make(map[FindingSeverity]int),
					ByType:     make(map[FindingType]int),
					ByState:    make(map[FindingState]int),
				},
			}
		}
		
		q := quarters[quarter]
		q.Findings = append(q.Findings, finding)
		q.Summary.Total++
		q.Summary.BySeverity[finding.Severity]++
		q.Summary.ByType[finding.Type]++
		q.Summary.ByState[finding.State]++
	}
	
	return quarters
}

// SummarizeFindings creates a summary of all findings
func SummarizeFindings(findings []*Finding) *FindingsSummary {
	summary := &FindingsSummary{
		TotalFindings: len(findings),
		ByType:        make(map[FindingType]int),
		BySeverity:    make(map[FindingSeverity]int),
		ByState:       make(map[FindingState]int),
		ByOwnership:   make(map[string]int),
		ByQuarter:     make(map[string]int),
		Repositories:  make(map[string]*RepositorySummary),
		GeneratedAt:   time.Now(),
	}
	
	for _, finding := range findings {
		// Aggregate by type, severity, state
		summary.ByType[finding.Type]++
		summary.BySeverity[finding.Severity]++
		summary.ByState[finding.State]++
		
		// Aggregate by ownership
		ownership := finding.GetOwnership()
		summary.ByOwnership[ownership]++
		
		// Aggregate by quarter
		quarter := finding.GetQuarter()
		summary.ByQuarter[quarter]++
		
		// Aggregate by repository
		if finding.Repository != nil {
			repoKey := finding.Repository.FullName
			if summary.Repositories[repoKey] == nil {
				summary.Repositories[repoKey] = &RepositorySummary{
					Repository:   finding.Repository,
					FindingCount: 0,
					BySeverity:   make(map[FindingSeverity]int),
					ByType:       make(map[FindingType]int),
					ByState:      make(map[FindingState]int),
				}
			}
			
			repoSummary := summary.Repositories[repoKey]
			repoSummary.FindingCount++
			repoSummary.BySeverity[finding.Severity]++
			repoSummary.ByType[finding.Type]++
			repoSummary.ByState[finding.State]++
		}
	}
	
	return summary
} 