package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	
	"github-findings-manager/internal/config"
	"github-findings-manager/internal/github"
	"github-findings-manager/internal/storage"
	"github-findings-manager/internal/reporting"
)

var (
	cfgFile string
	org     string
	envType string
	output  string
	verbose bool
	repos   string
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "github-findings-manager",
	Short: "High-performance GitHub security findings manager",
	Long: `A high-performance tool to fetch and report on GitHub security findings 
from an organization's repositories with advanced filtering and reporting capabilities.

Examples:
  # Scan all repositories in an organization
  github-findings-manager --org myorg

  # Scan specific repositories only
  github-findings-manager --org myorg --repos "repo1,repo2,repo3"
  
  # Scan with custom environment type and output
  github-findings-manager --org myorg --env-type Development --output dev-report.xlsx`,
	RunE: runMain,
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.github-findings-manager.yaml)")
	rootCmd.PersistentFlags().StringVar(&org, "org", "", "GitHub organization (required)")
	rootCmd.PersistentFlags().StringVar(&envType, "env-type", "Production", "Environment type filter")
	rootCmd.PersistentFlags().StringVar(&output, "output", "findings-report.xlsx", "Output file path")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	rootCmd.PersistentFlags().StringVar(&repos, "repos", "", "Comma-separated list of specific repositories (e.g., repo1,repo2,repo3)")

	rootCmd.MarkPersistentFlagRequired("org")

	viper.BindPFlag("org", rootCmd.PersistentFlags().Lookup("org"))
	viper.BindPFlag("env-type", rootCmd.PersistentFlags().Lookup("env-type"))
	viper.BindPFlag("output", rootCmd.PersistentFlags().Lookup("output"))
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	viper.BindPFlag("repos", rootCmd.PersistentFlags().Lookup("repos"))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".github-findings-manager")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}

	// Setup logging
	if viper.GetBool("verbose") {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}
	
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
}

func runMain(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	logFields := logrus.Fields{
		"org":      cfg.Organization,
		"env-type": cfg.EnvType,
		"output":   cfg.OutputPath,
	}
	
	if cfg.Repositories != "" {
		logFields["repos"] = cfg.Repositories
		logrus.WithFields(logFields).Info("Starting GitHub findings collection for specific repositories")
	} else {
		logrus.WithFields(logFields).Info("Starting GitHub findings collection for entire organization")
	}

	// Initialize storage
	db, err := storage.NewSQLiteStorage("findings.db")
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}
	defer db.Close()

	// Initialize GitHub client
	ghClient, err := github.NewClient(cfg.GitHubToken)
	if err != nil {
		return fmt.Errorf("failed to initialize GitHub client: %w", err)
	}

	// Initialize collector
	collector := github.NewCollector(ghClient, db, cfg)

	// Collect findings
	start := time.Now()
	logrus.Info("Starting data collection...")
	
	findings, err := collector.CollectFindings(ctx)
	if err != nil {
		return fmt.Errorf("failed to collect findings: %w", err)
	}

	duration := time.Since(start)
	logrus.WithFields(logrus.Fields{
		"findings": len(findings),
		"duration": duration,
	}).Info("Data collection completed")

	// Generate report
	logrus.Info("Generating Excel report...")
	reporter := reporting.NewExcelReporter(cfg.OutputPath)
	
	if err := reporter.GenerateReport(findings); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	logrus.WithField("output", cfg.OutputPath).Info("Report generated successfully")
	
	// Generate CSV fallback
	csvPath := cfg.OutputPath[:len(cfg.OutputPath)-5] + ".csv"
	if err := reporter.GenerateCSV(findings, csvPath); err != nil {
		logrus.WithError(err).Warn("Failed to generate CSV fallback")
	} else {
		logrus.WithField("csv", csvPath).Info("CSV fallback generated")
	}

	return nil
} 