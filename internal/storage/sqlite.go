package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"

	"github-findings-manager/internal/models"
)

// SQLiteStorage implements storage using SQLite database
type SQLiteStorage struct {
	db     *sql.DB
	logger *logrus.Logger
}

// NewSQLiteStorage creates a new SQLite storage instance
func NewSQLiteStorage(dbPath string) (*SQLiteStorage, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_synchronous=NORMAL&_cache_size=1000&_temp_store=memory")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Set connection pool settings
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(5 * time.Minute)

	storage := &SQLiteStorage{
		db:     db,
		logger: logrus.New(),
	}

	if err := storage.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return storage, nil
}

// Close closes the database connection
func (s *SQLiteStorage) Close() error {
	return s.db.Close()
}

// initSchema creates the database tables
func (s *SQLiteStorage) initSchema() error {
	schemas := []string{
		`CREATE TABLE IF NOT EXISTS repositories (
			id INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			full_name TEXT UNIQUE NOT NULL,
			owner TEXT NOT NULL,
			url TEXT NOT NULL,
			is_private BOOLEAN NOT NULL,
			default_branch TEXT NOT NULL,
			custom_properties TEXT,
			pod TEXT,
			environment_type TEXT,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL,
			last_scanned_at DATETIME
		)`,

		`CREATE TABLE IF NOT EXISTS findings (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			repo_id INTEGER NOT NULL,
			number INTEGER NOT NULL,
			title TEXT NOT NULL,
			description TEXT,
			severity TEXT NOT NULL,
			state TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL,
			fixed_at DATETIME,
			dismissed_at DATETIME,
			rule_name TEXT,
			rule_id TEXT,
			tool TEXT,
			location TEXT,
			html_url TEXT,
			raw_data TEXT,
			metadata TEXT,
			FOREIGN KEY (repo_id) REFERENCES repositories (id)
		)`,

		`CREATE TABLE IF NOT EXISTS cache_entries (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			etag TEXT,
			expires_at DATETIME NOT NULL,
			created_at DATETIME NOT NULL
		)`,

		// Indexes for performance
		`CREATE INDEX IF NOT EXISTS idx_findings_repo_id ON findings (repo_id)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_type ON findings (type)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (severity)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_state ON findings (state)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_created_at ON findings (created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_repositories_environment_type ON repositories (environment_type)`,
		`CREATE INDEX IF NOT EXISTS idx_repositories_pod ON repositories (pod)`,
		`CREATE INDEX IF NOT EXISTS idx_cache_expires_at ON cache_entries (expires_at)`,
	}

	for _, schema := range schemas {
		if _, err := s.db.Exec(schema); err != nil {
			return fmt.Errorf("failed to execute schema: %w", err)
		}
	}

	return nil
}

// SaveRepository saves a repository to the database
func (s *SQLiteStorage) SaveRepository(repo *models.Repository) error {
	customPropsJSON, _ := json.Marshal(repo.CustomProperties)

	query := `
		INSERT OR REPLACE INTO repositories 
		(id, name, full_name, owner, url, is_private, default_branch, custom_properties, pod, environment_type, created_at, updated_at, last_scanned_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := s.db.Exec(query,
		repo.ID,
		repo.Name,
		repo.FullName,
		repo.Owner,
		repo.URL,
		repo.IsPrivate,
		repo.DefaultBranch,
		string(customPropsJSON),
		repo.Pod,
		repo.EnvironmentType,
		repo.CreatedAt,
		repo.UpdatedAt,
		time.Now(),
	)

	if err != nil {
		return fmt.Errorf("failed to save repository: %w", err)
	}

	return nil
}

// SaveFinding saves a finding to the database
func (s *SQLiteStorage) SaveFinding(finding *models.Finding) error {
	metadataJSON, _ := json.Marshal(finding.Metadata)
	rawDataJSON := string(finding.RawData)

	query := `
		INSERT OR REPLACE INTO findings 
		(id, type, repo_id, number, title, description, severity, state, created_at, updated_at, 
		 fixed_at, dismissed_at, rule_name, rule_id, tool, location, html_url, raw_data, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := s.db.Exec(query,
		finding.ID,
		finding.Type,
		finding.RepoID,
		finding.Number,
		finding.Title,
		finding.Description,
		finding.Severity,
		finding.State,
		finding.CreatedAt,
		finding.UpdatedAt,
		finding.FixedAt,
		finding.DismissedAt,
		finding.RuleName,
		finding.RuleID,
		finding.Tool,
		finding.Location,
		finding.HTMLURL,
		rawDataJSON,
		string(metadataJSON),
	)

	if err != nil {
		return fmt.Errorf("failed to save finding: %w", err)
	}

	return nil
}

// GetRepositories retrieves repositories with optional filtering
func (s *SQLiteStorage) GetRepositories(envType string) ([]*models.Repository, error) {
	query := `
		SELECT id, name, full_name, owner, url, is_private, default_branch, 
		       custom_properties, pod, environment_type, created_at, updated_at
		FROM repositories
	`
	args := []interface{}{}

	if envType != "" {
		query += " WHERE environment_type = ?"
		args = append(args, envType)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query repositories: %w", err)
	}
	defer rows.Close()

	var repositories []*models.Repository
	for rows.Next() {
		repo := &models.Repository{}
		var customPropsJSON string

		err := rows.Scan(
			&repo.ID,
			&repo.Name,
			&repo.FullName,
			&repo.Owner,
			&repo.URL,
			&repo.IsPrivate,
			&repo.DefaultBranch,
			&customPropsJSON,
			&repo.Pod,
			&repo.EnvironmentType,
			&repo.CreatedAt,
			&repo.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan repository: %w", err)
		}

		if customPropsJSON != "" {
			json.Unmarshal([]byte(customPropsJSON), &repo.CustomProperties)
		}

		repositories = append(repositories, repo)
	}

	return repositories, nil
}

// GetFindings retrieves findings with repository information
func (s *SQLiteStorage) GetFindings() ([]*models.Finding, error) {
	query := `
		SELECT f.id, f.type, f.repo_id, f.number, f.title, f.description, f.severity, f.state,
		       f.created_at, f.updated_at, f.fixed_at, f.dismissed_at, f.rule_name, f.rule_id,
		       f.tool, f.location, f.html_url, f.raw_data, f.metadata,
		       r.id, r.name, r.full_name, r.owner, r.url, r.is_private, r.default_branch,
		       r.custom_properties, r.pod, r.environment_type, r.created_at, r.updated_at
		FROM findings f
		JOIN repositories r ON f.repo_id = r.id
		ORDER BY f.created_at DESC
	`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query findings: %w", err)
	}
	defer rows.Close()

	var findings []*models.Finding
	for rows.Next() {
		finding := &models.Finding{Repository: &models.Repository{}}
		var metadataJSON, rawDataJSON, customPropsJSON string

		err := rows.Scan(
			&finding.ID,
			&finding.Type,
			&finding.RepoID,
			&finding.Number,
			&finding.Title,
			&finding.Description,
			&finding.Severity,
			&finding.State,
			&finding.CreatedAt,
			&finding.UpdatedAt,
			&finding.FixedAt,
			&finding.DismissedAt,
			&finding.RuleName,
			&finding.RuleID,
			&finding.Tool,
			&finding.Location,
			&finding.HTMLURL,
			&rawDataJSON,
			&metadataJSON,
			&finding.Repository.ID,
			&finding.Repository.Name,
			&finding.Repository.FullName,
			&finding.Repository.Owner,
			&finding.Repository.URL,
			&finding.Repository.IsPrivate,
			&finding.Repository.DefaultBranch,
			&customPropsJSON,
			&finding.Repository.Pod,
			&finding.Repository.EnvironmentType,
			&finding.Repository.CreatedAt,
			&finding.Repository.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan finding: %w", err)
		}

		if metadataJSON != "" {
			json.Unmarshal([]byte(metadataJSON), &finding.Metadata)
		}

		if rawDataJSON != "" {
			finding.RawData = json.RawMessage(rawDataJSON)
		}

		if customPropsJSON != "" {
			json.Unmarshal([]byte(customPropsJSON), &finding.Repository.CustomProperties)
		}

		findings = append(findings, finding)
	}

	return findings, nil
}

// SetCache stores a value in the cache with optional ETag
func (s *SQLiteStorage) SetCache(key, value, etag string, expiry time.Duration) error {
	expiresAt := time.Now().Add(expiry)

	query := `
		INSERT OR REPLACE INTO cache_entries (key, value, etag, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?)
	`

	_, err := s.db.Exec(query, key, value, etag, expiresAt, time.Now())
	if err != nil {
		return fmt.Errorf("failed to set cache: %w", err)
	}

	return nil
}

// GetCache retrieves a value from the cache
func (s *SQLiteStorage) GetCache(key string) (value, etag string, found bool, err error) {
	query := `
		SELECT value, etag FROM cache_entries 
		WHERE key = ? AND expires_at > ?
	`

	err = s.db.QueryRow(query, key, time.Now()).Scan(&value, &etag)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", "", false, nil
		}
		return "", "", false, fmt.Errorf("failed to get cache: %w", err)
	}

	return value, etag, true, nil
}

// CleanupExpiredCache removes expired cache entries
func (s *SQLiteStorage) CleanupExpiredCache() error {
	query := `DELETE FROM cache_entries WHERE expires_at <= ?`
	
	result, err := s.db.Exec(query, time.Now())
	if err != nil {
		return fmt.Errorf("failed to cleanup cache: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		s.logger.WithField("rows", rowsAffected).Debug("Cleaned up expired cache entries")
	}

	return nil
}

// GetStats returns database statistics
func (s *SQLiteStorage) GetStats() (map[string]int64, error) {
	stats := make(map[string]int64)

	queries := map[string]string{
		"repositories": "SELECT COUNT(*) FROM repositories",
		"findings":     "SELECT COUNT(*) FROM findings",
		"cache_entries": "SELECT COUNT(*) FROM cache_entries",
	}

	for name, query := range queries {
		var count int64
		err := s.db.QueryRow(query).Scan(&count)
		if err != nil {
			return nil, fmt.Errorf("failed to get %s count: %w", name, err)
		}
		stats[name] = count
	}

	return stats, nil
} 