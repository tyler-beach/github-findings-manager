package cache

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
)

// Cache handles local caching of API responses and ETags
type Cache struct {
	db       *sql.DB
	cacheDir string
}

// CacheEntry represents a cached API response
type CacheEntry struct {
	Key       string    `json:"key"`
	ETag      string    `json:"etag"`
	Data      []byte    `json:"data"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// New creates a new cache instance
func New(cacheDir string) *Cache {
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		logrus.Warnf("Failed to create cache directory: %v", err)
		return nil
	}

	dbPath := filepath.Join(cacheDir, "cache.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		logrus.Warnf("Failed to open cache database: %v", err)
		return nil
	}

	cache := &Cache{
		db:       db,
		cacheDir: cacheDir,
	}

	if err := cache.initDB(); err != nil {
		logrus.Warnf("Failed to initialize cache database: %v", err)
		return nil
	}

	return cache
}

// initDB initializes the cache database schema
func (c *Cache) initDB() error {
	query := `
	CREATE TABLE IF NOT EXISTS cache_entries (
		key TEXT PRIMARY KEY,
		etag TEXT,
		data BLOB,
		expires_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_expires_at ON cache_entries(expires_at);
	`

	_, err := c.db.Exec(query)
	return err
}

// Get retrieves a cached entry
func (c *Cache) Get(key string) (*CacheEntry, bool) {
	if c.db == nil {
		return nil, false
	}

	var entry CacheEntry
	var expiresAt, createdAt string

	query := `SELECT key, etag, data, expires_at, created_at FROM cache_entries WHERE key = ? AND expires_at > datetime('now')`
	err := c.db.QueryRow(query, key).Scan(&entry.Key, &entry.ETag, &entry.Data, &expiresAt, &createdAt)
	if err != nil {
		if err != sql.ErrNoRows {
			logrus.Debugf("Cache get error: %v", err)
		}
		return nil, false
	}

	// Parse timestamps
	entry.ExpiresAt, _ = time.Parse("2006-01-02 15:04:05", expiresAt)
	entry.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)

	return &entry, true
}

// Set stores an entry in the cache
func (c *Cache) Set(key, etag string, data []byte, ttl time.Duration) error {
	if c.db == nil {
		return fmt.Errorf("cache database not available")
	}

	expiresAt := time.Now().Add(ttl)
	
	query := `INSERT OR REPLACE INTO cache_entries (key, etag, data, expires_at) VALUES (?, ?, ?, ?)`
	_, err := c.db.Exec(query, key, etag, data, expiresAt.Format("2006-01-02 15:04:05"))
	
	return err
}

// GetETag retrieves only the ETag for a cache key
func (c *Cache) GetETag(key string) (string, bool) {
	if c.db == nil {
		return "", false
	}

	var etag string
	query := `SELECT etag FROM cache_entries WHERE key = ? AND expires_at > datetime('now')`
	err := c.db.QueryRow(query, key).Scan(&etag)
	if err != nil {
		return "", false
	}

	return etag, true
}

// Delete removes an entry from the cache
func (c *Cache) Delete(key string) error {
	if c.db == nil {
		return fmt.Errorf("cache database not available")
	}

	query := `DELETE FROM cache_entries WHERE key = ?`
	_, err := c.db.Exec(query, key)
	return err
}

// CleanExpired removes expired entries from the cache
func (c *Cache) CleanExpired() error {
	if c.db == nil {
		return fmt.Errorf("cache database not available")
	}

	query := `DELETE FROM cache_entries WHERE expires_at <= datetime('now')`
	_, err := c.db.Exec(query)
	return err
}

// Close closes the cache database connection
func (c *Cache) Close() error {
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}

// GenerateKey generates a cache key from components
func GenerateKey(components ...string) string {
	combined := ""
	for _, comp := range components {
		combined += comp + ":"
	}
	
	hash := md5.Sum([]byte(combined))
	return hex.EncodeToString(hash[:])
}

// CacheFindings stores findings data in a JSON file for reprocessing
func (c *Cache) CacheFindings(org string, data interface{}) error {
	if c.cacheDir == "" {
		return fmt.Errorf("cache directory not set")
	}

	filename := fmt.Sprintf("findings_%s_%d.json", org, time.Now().Unix())
	filepath := filepath.Join(c.cacheDir, filename)

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal findings: %w", err)
	}

	return os.WriteFile(filepath, jsonData, 0644)
}

// LoadCachedFindings loads findings from a cached JSON file
func (c *Cache) LoadCachedFindings(filepath string, target interface{}) error {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("failed to read cached findings: %w", err)
	}

	return json.Unmarshal(data, target)
} 