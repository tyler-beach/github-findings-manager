package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github_findings_manager/pkg/collector"
	"github_findings_manager/pkg/models"
	"github_findings_manager/pkg/reports"
)

var version = "1.0.0"

func main() {
	app := &cli.App{
		Name:    "github-findings-manager",
		Usage:   "High-performance CLI tool to fetch and report on GitHub security findings",
		Version: version,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "org",
				Usage:    "GitHub organization name (required)",
				Required: true,
			},
			&cli.StringFlag{
				Name:  "env-type",
				Usage: "Environment type to filter repositories (use empty string '' for all repos)",
				Value: "Production",
			},
			&cli.StringFlag{
				Name:  "repos",
				Usage: "Comma-separated list of specific repositories to analyze",
			},
			&cli.StringFlag{
				Name:  "pod",
				Usage: "Comma-separated list of pods to filter repositories",
			},
			&cli.StringFlag{
				Name:  "output",
				Usage: "Output directory for reports",
				Value: "./reports",
			},
			&cli.BoolFlag{
				Name:  "verbose",
				Usage: "Enable verbose logging",
			},
			&cli.BoolFlag{
				Name:  "csv",
				Usage: "Generate CSV fallback output",
			},
			&cli.BoolFlag{
				Name:  "no-cache",
				Usage: "Disable caching",
			},
			&cli.BoolFlag{
				Name:  "include-closed",
				Usage: "Include closed/resolved findings in addition to open ones",
			},
			&cli.BoolFlag{
				Name:  "dry-run",
				Usage: "Show what would be processed without making API calls",
			},
			&cli.BoolFlag{
				Name:  "debug",
				Usage: "Enable debug logging with detailed API information",
			},
			&cli.StringFlag{
				Name:  "assignments-file",
				Usage: "JSON file with manual repository assignments (pod/environment)",
				Value: "repo-assignments.json",
			},
		},
		Action: run,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func run(c *cli.Context) error {
	// Configure logging
	if c.Bool("debug") {
		logrus.SetLevel(logrus.DebugLevel)
	} else if c.Bool("verbose") {
		logrus.SetLevel(logrus.InfoLevel)
	} else {
		logrus.SetLevel(logrus.WarnLevel)
	}

	// Validate GitHub token
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return fmt.Errorf("GITHUB_TOKEN environment variable is required")
	}

	// Parse input parameters
	config := &models.Config{
		Organization:          c.String("org"),
		EnvType:              c.String("env-type"),
		OutputDir:            c.String("output"),
		Verbose:              c.Bool("verbose"),
		CSVOutput:            c.Bool("csv"),
		NoCache:              c.Bool("no-cache"),
		IncludeClosedFindings: c.Bool("include-closed"),
		Token:                token,
	}

	// Load repository assignments if file exists
	assignmentsFile := c.String("assignments-file")
	if _, err := os.Stat(assignmentsFile); err == nil {
		assignments, err := loadRepositoryAssignments(assignmentsFile)
		if err != nil {
			logrus.Warnf("Failed to load repository assignments from %s: %v", assignmentsFile, err)
		} else {
			config.RepoAssignments = assignments
			logrus.Infof("Loaded manual assignments for %d repositories from %s", len(assignments), assignmentsFile)
		}
	}

	// Special handling for debugging - empty env-type includes all repos
	if config.EnvType == "" {
		logrus.Info("Empty env-type specified - will include ALL repositories")
	}

	if repos := c.String("repos"); repos != "" {
		config.SpecificRepos = strings.Split(repos, ",")
		for i := range config.SpecificRepos {
			config.SpecificRepos[i] = strings.TrimSpace(config.SpecificRepos[i])
		}
	}

	if pods := c.String("pod"); pods != "" {
		config.PodFilter = strings.Split(pods, ",")
		for i := range config.PodFilter {
			config.PodFilter[i] = strings.TrimSpace(config.PodFilter[i])
		}
	}

	logrus.Infof("Starting GitHub findings collection for organization: %s", config.Organization)
	logrus.Infof("Environment type filter: %s", config.EnvType)
	
	if len(config.SpecificRepos) > 0 {
		logrus.Infof("Analyzing specific repositories: %v", config.SpecificRepos)
	}
	
	if len(config.PodFilter) > 0 {
		logrus.Infof("Pod filter: %v", config.PodFilter)
	}

	// Create output directory
	if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Initialize collector
	col := collector.New(config)

	// Collect findings
	logrus.Info("Collecting security findings...")
	startTime := time.Now()
	
	results, err := col.CollectFindings()
	if err != nil {
		return fmt.Errorf("failed to collect findings: %w", err)
	}

	duration := time.Since(startTime)
	logrus.Infof("Collection completed in %v", duration)
	
	// Enhanced debugging output
	logrus.Infof("Collection Results Summary:")
	logrus.Infof("- Repositories found: %d", len(results.Repositories))
	logrus.Infof("- Total findings: %d", len(results.Findings))
	logrus.Infof("- Code scanning findings: %d", results.Stats.CodeScanningFindings)
	logrus.Infof("- Secret scanning findings: %d", results.Stats.SecretsFindings)
	logrus.Infof("- Dependabot findings: %d", results.Stats.DependabotFindings)
	logrus.Infof("- API calls made: %d", results.Stats.APICallsTotal)
	logrus.Infof("- Errors encountered: %d", len(results.Errors))

	// Debug repository information
	if c.Bool("debug") {
		logrus.Debug("Repository Details:")
		for name, repo := range results.Repositories {
			logrus.Debugf("- %s: env=%s, pod=%s, code_scan=%v, secrets=%v, dependabot=%v", 
				name, repo.EnvironmentType, repo.Pod, 
				repo.CodeScanningEnabled, repo.SecretsEnabled, repo.DependabotEnabled)
		}

		if len(results.Errors) > 0 {
			logrus.Debug("Errors encountered:")
			for _, err := range results.Errors {
				logrus.Debugf("- %s (%s): %s [%d]", err.Repository, err.Type, err.Message, err.StatusCode)
			}
		}
	}

	// Show warning if no findings
	if len(results.Findings) == 0 {
		logrus.Warn("⚠️  No findings collected. This could be due to:")
		logrus.Warn("   1. No repositories match the environment filter ('%s')", config.EnvType)
		logrus.Warn("   2. Repositories don't have security features enabled")
		logrus.Warn("   3. GitHub token lacks required permissions (repo:security_events)")
		logrus.Warn("   4. Organization doesn't have security features configured")
		logrus.Warn("")
		logrus.Warn("💡 Try running with --debug for detailed information")
		logrus.Warn("💡 Or specify specific repos with --repos 'repo1,repo2'")
		logrus.Warn("💡 Or try a different --env-type (default is 'Production')")
	}

	// Generate reports
	logrus.Info("Generating reports...")
	reporter := reports.New(config)

	if err := reporter.GenerateExcelReport(results); err != nil {
		logrus.Errorf("Failed to generate Excel report: %v", err)
	}

	if err := reporter.GenerateMarkdownReport(results); err != nil {
		logrus.Errorf("Failed to generate Markdown report: %v", err)
	}

	if config.CSVOutput {
		if err := reporter.GenerateCSVReport(results); err != nil {
			logrus.Errorf("Failed to generate CSV report: %v", err)
		}
	}

	logrus.Infof("Reports generated successfully in %s", config.OutputDir)
	return nil
}

// RepoAssignmentFile represents the structure of the repository assignments JSON file
type RepoAssignmentFile struct {
	Comment      string                           `json:"comment"`
	Repositories map[string]models.RepoAssignment `json:"repositories"`
}

// loadRepositoryAssignments loads repository assignments from a JSON file
func loadRepositoryAssignments(filename string) (map[string]models.RepoAssignment, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read assignments file: %w", err)
	}

	var assignmentFile RepoAssignmentFile
	if err := json.Unmarshal(data, &assignmentFile); err != nil {
		return nil, fmt.Errorf("failed to parse assignments file: %w", err)
	}

	return assignmentFile.Repositories, nil
} 