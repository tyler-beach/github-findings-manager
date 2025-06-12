package reports

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github_findings_manager/pkg/models"
)

// Reporter handles report generation
type Reporter struct {
	config *models.Config
}

// New creates a new reporter instance
func New(config *models.Config) *Reporter {
	return &Reporter{
		config: config,
	}
}

// GenerateCSVReport generates CSV output for CI/CD compatibility
func (r *Reporter) GenerateCSVReport(results *models.CollectionResults) error {
	filename := fmt.Sprintf("github_findings_%s_%s.csv", 
		results.Organization, 
		results.CollectedAt.Format("2006-01-02_15-04-05"))
	filepath := filepath.Join(r.config.OutputDir, filename)

	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write headers
	headers := []string{
		"Repository", "FindingType", "Severity", "State", "Title", 
		"CreatedDate", "UpdatedDate", "Pod", "Attribution", "Quarter", 
		"URL", "RuleID", "SecretType", "PackageName", "VulnerableVersionRange",
	}
	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("failed to write CSV headers: %w", err)
	}

	// Write findings data
	for _, finding := range results.Findings {
		record := []string{
			finding.Repository,
			finding.Type,
			finding.Severity,
			finding.State,
			finding.Title,
			finding.CreatedAt.Format("2006-01-02"),
			finding.UpdatedAt.Format("2006-01-02"),
			finding.Pod,
			finding.Attribution,
			finding.Quarter,
			finding.URL,
			finding.RuleID,
			finding.SecretType,
			finding.PackageName,
			finding.VulnerableVersionRange,
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("failed to write CSV record: %w", err)
		}
	}

	logrus.Infof("CSV report saved to: %s", filepath)
	return nil
}

// GenerateMarkdownReport creates a comprehensive Markdown summary
func (r *Reporter) GenerateMarkdownReport(results *models.CollectionResults) error {
	filename := fmt.Sprintf("github_findings_summary_%s_%s.md", 
		results.Organization, 
		results.CollectedAt.Format("2006-01-02_15-04-05"))
	filepath := filepath.Join(r.config.OutputDir, filename)

	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create Markdown file: %w", err)
	}
	defer file.Close()

	content := r.generateMarkdownContent(results)
	if _, err := file.WriteString(content); err != nil {
		return fmt.Errorf("failed to write Markdown content: %w", err)
	}

	logrus.Infof("Markdown report saved to: %s", filepath)
	return nil
}

// generateMarkdownContent creates the Markdown report content
func (r *Reporter) generateMarkdownContent(results *models.CollectionResults) string {
	var sb strings.Builder

	// Title and metadata
	sb.WriteString(fmt.Sprintf("# GitHub Security Findings Report\n\n"))
	sb.WriteString(fmt.Sprintf("**Organization:** %s\n", results.Organization))
	sb.WriteString(fmt.Sprintf("**Generated:** %s\n", results.CollectedAt.Format("January 2, 2006 at 3:04 PM")))
	sb.WriteString(fmt.Sprintf("**Duration:** %s\n\n", results.Stats.Duration.String()))

	// Executive Summary
	sb.WriteString("## Executive Summary\n\n")
	sb.WriteString(fmt.Sprintf("This report provides a comprehensive analysis of security findings across %d repositories in the %s organization.\n\n", 
		len(results.Repositories), results.Organization))

	// Key Metrics
	sb.WriteString("### Key Metrics\n\n")
	sb.WriteString("| Metric | Count |\n")
	sb.WriteString("|--------|-------|\n")
	sb.WriteString(fmt.Sprintf("| **Total Findings** | %d |\n", len(results.Findings)))
	sb.WriteString(fmt.Sprintf("| **Repositories Analyzed** | %d |\n", len(results.Repositories)))
	sb.WriteString(fmt.Sprintf("| **Code Scanning Findings** | %d |\n", results.Stats.CodeScanningFindings))
	sb.WriteString(fmt.Sprintf("| **Secret Scanning Findings** | %d |\n", results.Stats.SecretsFindings))
	sb.WriteString(fmt.Sprintf("| **Dependabot Findings** | %d |\n", results.Stats.DependabotFindings))
	sb.WriteString(fmt.Sprintf("| **Attributed Findings** | %d |\n", results.Stats.AttributedFindings))
	sb.WriteString(fmt.Sprintf("| **Unattributed Findings** | %d |\n", results.Stats.UnattributedFindings))
	sb.WriteString("\n")

	// Attribution Analysis
	sb.WriteString("## Attribution Analysis\n\n")
	attributionRate := float64(results.Stats.AttributedFindings) / float64(len(results.Findings)) * 100
	sb.WriteString(fmt.Sprintf("**Attribution Rate:** %.1f%% of findings are attributed to specific pods.\n\n", attributionRate))

	// Findings by Pod
	findingsByPod := results.GetFindingsByPod()
	if len(findingsByPod) > 1 { // More than just "unattributed"
		sb.WriteString("### Findings by Pod\n\n")
		sb.WriteString("| Pod | Findings Count | Percentage |\n")
		sb.WriteString("|-----|----------------|------------|\n")
		
		for pod, findings := range findingsByPod {
			percentage := float64(len(findings)) / float64(len(results.Findings)) * 100
			sb.WriteString(fmt.Sprintf("| %s | %d | %.1f%% |\n", pod, len(findings), percentage))
		}
		sb.WriteString("\n")
	}

	// Findings Over Time
	sb.WriteString("## Findings Over Time\n\n")
	findingsByQuarter := results.GetFindingsByQuarter()
	if len(findingsByQuarter) > 0 {
		sb.WriteString("### Quarterly Breakdown\n\n")
		sb.WriteString("| Quarter | Total | Attributed | Unattributed |\n")
		sb.WriteString("|---------|-------|------------|-------------|\n")
		
		// Sort quarters for consistent output
		quarters := make([]string, 0, len(findingsByQuarter))
		for quarter := range findingsByQuarter {
			quarters = append(quarters, quarter)
		}
		
		for _, quarter := range quarters {
			findings := findingsByQuarter[quarter]
			attributed := 0
			unattributed := 0
			
			for _, finding := range findings {
				if finding.Attribution == "attributed" {
					attributed++
				} else {
					unattributed++
				}
			}
			
			sb.WriteString(fmt.Sprintf("| %s | %d | %d | %d |\n", quarter, len(findings), attributed, unattributed))
		}
		sb.WriteString("\n")
	}

	// Findings by Type
	sb.WriteString("## Findings by Type\n\n")
	findingsByType := results.GetFindingsByType()
	sb.WriteString("| Finding Type | Count | Percentage |\n")
	sb.WriteString("|--------------|-------|------------|\n")
	
	for findingType, findings := range findingsByType {
		percentage := float64(len(findings)) / float64(len(results.Findings)) * 100
		sb.WriteString(fmt.Sprintf("| %s | %d | %.1f%% |\n", 
			strings.Title(strings.ReplaceAll(findingType, "_", " ")), 
			len(findings), 
			percentage))
	}
	sb.WriteString("\n")

	// Repository Coverage
	sb.WriteString("## Repository Coverage\n\n")
	codeScanningRepos := 0
	secretScanningRepos := 0
	dependabotRepos := 0
	
	for _, repo := range results.Repositories {
		if repo.CodeScanningEnabled {
			codeScanningRepos++
		}
		if repo.SecretsEnabled {
			secretScanningRepos++
		}
		if repo.DependabotEnabled {
			dependabotRepos++
		}
	}
	
	sb.WriteString("| Security Feature | Enabled Repositories | Coverage |\n")
	sb.WriteString("|------------------|---------------------|----------|\n")
	sb.WriteString(fmt.Sprintf("| Code Scanning | %d | %.1f%% |\n", 
		codeScanningRepos, 
		float64(codeScanningRepos)/float64(len(results.Repositories))*100))
	sb.WriteString(fmt.Sprintf("| Secret Scanning | %d | %.1f%% |\n", 
		secretScanningRepos, 
		float64(secretScanningRepos)/float64(len(results.Repositories))*100))
	sb.WriteString(fmt.Sprintf("| Dependabot | %d | %.1f%% |\n", 
		dependabotRepos, 
		float64(dependabotRepos)/float64(len(results.Repositories))*100))
	sb.WriteString("\n")

	// Error Summary
	if len(results.Errors) > 0 {
		sb.WriteString("## Errors and Access Issues\n\n")
		sb.WriteString(fmt.Sprintf("**Total Errors:** %d\n\n", len(results.Errors)))
		
		errorsByType := make(map[string]int)
		errorsByStatus := make(map[int]int)
		
		for _, err := range results.Errors {
			errorsByType[err.Type]++
			if err.StatusCode > 0 {
				errorsByStatus[err.StatusCode]++
			}
		}
		
		if len(errorsByType) > 0 {
			sb.WriteString("### Errors by Type\n\n")
			sb.WriteString("| Error Type | Count |\n")
			sb.WriteString("|------------|-------|\n")
			for errorType, count := range errorsByType {
				sb.WriteString(fmt.Sprintf("| %s | %d |\n", errorType, count))
			}
			sb.WriteString("\n")
		}
		
		if len(errorsByStatus) > 0 {
			sb.WriteString("### Errors by Status Code\n\n")
			sb.WriteString("| Status Code | Count | Description |\n")
			sb.WriteString("|-------------|-------|-------------|\n")
			for statusCode, count := range errorsByStatus {
				description := getStatusCodeDescription(statusCode)
				sb.WriteString(fmt.Sprintf("| %d | %d | %s |\n", statusCode, count, description))
			}
			sb.WriteString("\n")
		}
	}

	// Recommendations
	sb.WriteString("## Recommendations\n\n")
	sb.WriteString("Based on the analysis of security findings, consider the following actions:\n\n")
	
	if results.Stats.UnattributedFindings > 0 {
		sb.WriteString(fmt.Sprintf("1. **Improve Attribution:** %d findings (%.1f%%) are unattributed. Review pod assignments for repositories.\n", 
			results.Stats.UnattributedFindings, 
			float64(results.Stats.UnattributedFindings)/float64(len(results.Findings))*100))
	}
	
	if codeScanningRepos < len(results.Repositories) {
		sb.WriteString(fmt.Sprintf("2. **Enable Code Scanning:** %d repositories don't have code scanning enabled.\n", 
			len(results.Repositories)-codeScanningRepos))
	}
	
	if secretScanningRepos < len(results.Repositories) {
		sb.WriteString(fmt.Sprintf("3. **Enable Secret Scanning:** %d repositories don't have secret scanning enabled.\n", 
			len(results.Repositories)-secretScanningRepos))
	}
	
	if dependabotRepos < len(results.Repositories) {
		sb.WriteString(fmt.Sprintf("4. **Enable Dependabot:** %d repositories don't have Dependabot enabled.\n", 
			len(results.Repositories)-dependabotRepos))
	}
	
	sb.WriteString("\n")

	// Technical Details
	sb.WriteString("## Technical Details\n\n")
	sb.WriteString(fmt.Sprintf("- **Collection Method:** GitHub REST API v4\n"))
	sb.WriteString(fmt.Sprintf("- **API Calls Made:** %d\n", results.Stats.APICallsTotal))
	sb.WriteString(fmt.Sprintf("- **Cache Hits:** %d\n", results.Stats.CacheHits))
	sb.WriteString(fmt.Sprintf("- **Processing Time:** %s\n", results.Stats.Duration.String()))
	sb.WriteString(fmt.Sprintf("- **Environment Filter:** %s\n", r.config.EnvType))
	
	if len(r.config.PodFilter) > 0 {
		sb.WriteString(fmt.Sprintf("- **Pod Filter:** %s\n", strings.Join(r.config.PodFilter, ", ")))
	}
	
	if len(r.config.SpecificRepos) > 0 {
		sb.WriteString(fmt.Sprintf("- **Specific Repositories:** %s\n", strings.Join(r.config.SpecificRepos, ", ")))
	}

	sb.WriteString("\n---\n")
	sb.WriteString(fmt.Sprintf("*Report generated by GitHub Findings Manager v1.0.0 on %s*\n", 
		time.Now().Format("January 2, 2006 at 3:04 PM")))

	return sb.String()
}

// getStatusCodeDescription returns a human-readable description for HTTP status codes
func getStatusCodeDescription(statusCode int) string {
	switch statusCode {
	case 401:
		return "Unauthorized - Invalid token or insufficient permissions"
	case 403:
		return "Forbidden - Access denied to resource"
	case 404:
		return "Not Found - Resource does not exist"
	case 422:
		return "Unprocessable Entity - Invalid request parameters"
	case 429:
		return "Too Many Requests - Rate limit exceeded"
	case 500:
		return "Internal Server Error - GitHub API error"
	default:
		return "Unknown error"
	}
} 