// Package store owns the SQLite file and every write the service performs.
package store

import (
	"database/sql"
	"errors"
	"fmt"

	_ "modernc.org/sqlite"

	"github.com/luwa07832/vuln-registry/internal/vuln"
)

// ErrNotFound means no vulnerability has the requested id.
var ErrNotFound = errors.New("vulnerability not found")

// ErrDuplicate means a vulnerability with the requested id already exists.
var ErrDuplicate = errors.New("duplicate vulnerability")

// Store wraps the SQLite handle so callers never touch database/sql directly.
type Store struct {
	db *sql.DB
}

// Open prepares the database file and the schema this service needs.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable wal: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Ping reports whether the storage layer is usable.
func (s *Store) Ping() error { return s.db.Ping() }

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

// CreateVulnerability inserts one record and all of its affected ranges as a
// single transaction. It fails with ErrDuplicate when the id already exists;
// the failure leaves no partial data behind.
func (s *Store) CreateVulnerability(record *vuln.Vulnerability) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin create: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.Exec(
		"INSERT INTO vulnerabilities (id, component, severity, fixed_version, status) VALUES (?, ?, ?, ?, ?) "+
			"ON CONFLICT(id) DO NOTHING",
		record.ID, record.Component, record.Severity, record.Fixed, record.Status,
	)
	if err != nil {
		return fmt.Errorf("insert vulnerability: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check insert: %w", err)
	}
	if inserted == 0 {
		return ErrDuplicate
	}
	for index, affected := range record.Ranges {
		var lower, upper any
		var lowerInclusive, upperInclusive int
		if affected.Lower != nil {
			lower = *affected.Lower
			if affected.LowerInclusive {
				lowerInclusive = 1
			}
		}
		if affected.Upper != nil {
			upper = *affected.Upper
			if affected.UpperInclusive {
				upperInclusive = 1
			}
		}
		if _, err := tx.Exec(
			"INSERT INTO affected_ranges (vulnerability_id, position, lower_bound, lower_inclusive, upper_bound, upper_inclusive) VALUES (?, ?, ?, ?, ?, ?)",
			record.ID, index, lower, lowerInclusive, upper, upperInclusive,
		); err != nil {
			return fmt.Errorf("insert range: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit create: %w", err)
	}
	return nil
}

// GetVulnerability returns the full record for id or ErrNotFound.
func (s *Store) GetVulnerability(id string) (*vuln.Vulnerability, error) {
	rows, err := s.queryRows("WHERE v.id = ? ORDER BY r.position", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records, err := scanRecords(rows)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, ErrNotFound
	}
	return records[0], nil
}

// ListByComponent returns every record whose component name is exactly equal
// (case-sensitive) to component, ordered by id ascending.
func (s *Store) ListByComponent(component string) ([]*vuln.Vulnerability, error) {
	rows, err := s.queryRows(
		"WHERE v.component = ? COLLATE BINARY ORDER BY v.id ASC, r.position",
		component,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRecords(rows)
}

// SetVulnStatus updates only the disposition status of id and returns the
// resulting full record. Unknown ids fail with ErrNotFound without writes.
func (s *Store) SetVulnStatus(id, status string) (*vuln.Vulnerability, error) {
	result, err := s.db.Exec("UPDATE vulnerabilities SET status = ? WHERE id = ?", status, id)
	if err != nil {
		return nil, fmt.Errorf("update status: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("check update: %w", err)
	}
	if affected == 0 {
		return nil, ErrNotFound
	}
	return s.GetVulnerability(id)
}

func (s *Store) queryRows(whereAndOrder string, args ...any) (*sql.Rows, error) {
	query := "SELECT v.id, v.component, v.severity, v.fixed_version, v.status, " +
		"r.lower_bound, r.lower_inclusive, r.upper_bound, r.upper_inclusive " +
		"FROM vulnerabilities AS v JOIN affected_ranges AS r ON r.vulnerability_id = v.id " +
		whereAndOrder
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query vulnerabilities: %w", err)
	}
	return rows, nil
}

func scanRecords(rows *sql.Rows) ([]*vuln.Vulnerability, error) {
	records := make([]*vuln.Vulnerability, 0)
	byID := make(map[string]*vuln.Vulnerability)
	for rows.Next() {
		var id, component, severity, fixed, status string
		var lower, upper sql.NullString
		var lowerInclusive, upperInclusive int
		if err := rows.Scan(&id, &component, &severity, &fixed, &status,
			&lower, &lowerInclusive, &upper, &upperInclusive); err != nil {
			return nil, fmt.Errorf("scan vulnerability: %w", err)
		}
		record, exists := byID[id]
		if !exists {
			record = &vuln.Vulnerability{
				ID:        id,
				Component: component,
				Ranges:    make([]vuln.Range, 0),
				Severity:  severity,
				Fixed:     fixed,
				Status:    status,
			}
			byID[id] = record
			records = append(records, record)
		}
		affected := vuln.Range{
			LowerInclusive: lowerInclusive == 1,
			UpperInclusive: upperInclusive == 1,
		}
		if lower.Valid {
			value := lower.String
			affected.Lower = &value
		}
		if upper.Valid {
			value := upper.String
			affected.Upper = &value
		}
		record.Ranges = append(record.Ranges, affected)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read vulnerabilities: %w", err)
	}
	return records, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS service_metadata (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
	id            TEXT PRIMARY KEY,
	component     TEXT NOT NULL,
	severity      TEXT NOT NULL,
	fixed_version TEXT NOT NULL,
	status        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS affected_ranges (
	vulnerability_id TEXT NOT NULL,
	position         INTEGER NOT NULL,
	lower_bound      TEXT,
	lower_inclusive  INTEGER NOT NULL DEFAULT 0,
	upper_bound      TEXT,
	upper_inclusive  INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (vulnerability_id, position),
	FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_component ON vulnerabilities(component);
`
