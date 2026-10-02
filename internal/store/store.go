// Package store owns the SQLite file and every write the service performs.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
	libsqlite "modernc.org/sqlite"

	"github.com/luwa07832/vuln-registry/internal/vuln"
)

var (
	// ErrDuplicateVulnerability means a vulnerability with the same id is
	// already registered.
	ErrDuplicateVulnerability = errors.New("duplicate vulnerability")
	// ErrVulnerabilityNotFound means no vulnerability carries the given id.
	ErrVulnerabilityNotFound = errors.New("vulnerability not found")
)

// Store wraps the SQLite handle so callers never touch database/sql directly.
type Store struct {
	db *sql.DB
}

// Open prepares the database file and the schema this service needs.
func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("%s?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
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

// CreateVulnerability inserts the record and all of its affected ranges in a
// single transaction: either every row is written or none is.
func (s *Store) CreateVulnerability(ctx context.Context, vulnerability *vuln.Vulnerability) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin create: %w", err)
	}
	defer tx.Rollback()

	if err := insertVulnerabilityTx(ctx, tx, vulnerability); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicateVulnerability
		}
		return fmt.Errorf("commit create: %w", err)
	}
	return nil
}

// CreateVulnerabilities inserts every record and all of their affected ranges
// in a single transaction: either all records are written or none is. Input
// validation and intra-batch duplicate detection belong to the caller; this
// method still rejects an id that already exists in the database.
func (s *Store) CreateVulnerabilities(ctx context.Context, vulnerabilities []*vuln.Vulnerability) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin create: %w", err)
	}
	defer tx.Rollback()

	for _, vulnerability := range vulnerabilities {
		if err := insertVulnerabilityTx(ctx, tx, vulnerability); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicateVulnerability
		}
		return fmt.Errorf("commit create: %w", err)
	}
	return nil
}

// insertVulnerabilityTx inserts one record with all of its affected ranges
// into the open transaction, returning ErrDuplicateVulnerability when the id
// is already stored.
func insertVulnerabilityTx(ctx context.Context, tx *sql.Tx, vulnerability *vuln.Vulnerability) error {
	var existing int
	switch err := tx.QueryRowContext(ctx,
		"SELECT 1 FROM vulnerabilities WHERE id = ?", vulnerability.ID,
	).Scan(&existing); {
	case err == nil:
		return ErrDuplicateVulnerability
	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("check duplicate: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO vulnerabilities (id, component, severity, fixed_version, status)
		VALUES (?, ?, ?, ?, ?)`,
		vulnerability.ID, vulnerability.Component,
		string(vulnerability.Severity), vulnerability.FixedVersion, string(vulnerability.Status),
	); err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicateVulnerability
		}
		return fmt.Errorf("insert vulnerability: %w", err)
	}

	for index, affected := range vulnerability.Ranges {
		var lower, upper any
		if text := affected.LowerText(); text != "" {
			lower = text
		}
		if text := affected.UpperText(); text != "" {
			upper = text
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO affected_ranges
				(vulnerability_id, position, lower_version, lower_include, upper_version, upper_include)
			VALUES (?, ?, ?, ?, ?, ?)`,
			vulnerability.ID, index,
			lower, boolToInt(affected.LowerInclude),
			upper, boolToInt(affected.UpperInclude),
		); err != nil {
			return fmt.Errorf("insert affected range: %w", err)
		}
	}
	return nil
}

// GetVulnerability loads one record with all of its ranges in registration
// order. It returns ErrVulnerabilityNotFound when the id is unknown.
func (s *Store) GetVulnerability(ctx context.Context, id string) (*vuln.Vulnerability, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, component, severity, fixed_version, status
		FROM vulnerabilities WHERE id = ?`, id)
	vulnerability, err := scanVulnerability(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrVulnerabilityNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := s.loadRanges(ctx, vulnerability); err != nil {
		return nil, err
	}
	return vulnerability, nil
}

// ListByComponent returns every record whose component matches exactly
// (case-sensitive), ordered by id ascending.
func (s *Store) ListByComponent(ctx context.Context, component string) ([]*vuln.Vulnerability, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, component, severity, fixed_version, status
		FROM vulnerabilities WHERE component = ?
		ORDER BY id ASC`, component)
	if err != nil {
		return nil, fmt.Errorf("list by component: %w", err)
	}
	defer rows.Close()

	var vulnerabilities []*vuln.Vulnerability
	for rows.Next() {
		record, err := scanVulnerability(rows)
		if err != nil {
			return nil, err
		}
		vulnerabilities = append(vulnerabilities, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan vulnerabilities: %w", err)
	}
	for _, record := range vulnerabilities {
		if err := s.loadRanges(ctx, record); err != nil {
			return nil, err
		}
	}
	return vulnerabilities, nil
}

// UpdateStatus changes only the disposition status of one record. It returns
// ErrVulnerabilityNotFound when the id is unknown; every other column stays
// untouched.
func (s *Store) UpdateStatus(ctx context.Context, id string, status vuln.Status) (*vuln.Vulnerability, error) {
	result, err := s.db.ExecContext(ctx,
		"UPDATE vulnerabilities SET status = ? WHERE id = ?", string(status), id)
	if err != nil {
		return nil, fmt.Errorf("update status: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("update status rows: %w", err)
	}
	if affected == 0 {
		return nil, ErrVulnerabilityNotFound
	}
	return s.GetVulnerability(ctx, id)
}

// ListFilter carries the optional equality filters accepted by
// ListVulnerabilities. A nil field means the column is not filtered; every
// set field must match, so the filters intersect.
type ListFilter struct {
	Component *string
	Severity  *vuln.Severity
	Status    *vuln.Status
}

// clause renders the filter as a WHERE fragment with positional arguments.
func (f ListFilter) clause() (string, []any) {
	conditions := []string{}
	args := []any{}
	if f.Component != nil {
		conditions = append(conditions, "component = ?")
		args = append(args, *f.Component)
	}
	if f.Severity != nil {
		conditions = append(conditions, "severity = ?")
		args = append(args, string(*f.Severity))
	}
	if f.Status != nil {
		conditions = append(conditions, "status = ?")
		args = append(args, string(*f.Status))
	}
	if len(conditions) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conditions, " AND "), args
}

// ListVulnerabilities returns the records matching every given filter,
// ordered by id ascending and sliced to the requested 1-based page, along
// with the total number of matching records before slicing. A page past the
// end yields an empty slice with the total still reported.
func (s *Store) ListVulnerabilities(ctx context.Context, filter ListFilter, page, pageSize int) ([]*vuln.Vulnerability, int, error) {
	where, args := filter.clause()

	var total int
	if err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM vulnerabilities"+where, args...,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count vulnerabilities: %w", err)
	}

	pageArgs := append(append([]any{}, args...), pageSize, (page-1)*pageSize)
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, component, severity, fixed_version, status
		FROM vulnerabilities`+where+`
		ORDER BY id ASC LIMIT ? OFFSET ?`, pageArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list vulnerabilities: %w", err)
	}
	defer rows.Close()

	vulnerabilities := []*vuln.Vulnerability{}
	for rows.Next() {
		record, err := scanVulnerability(rows)
		if err != nil {
			return nil, 0, err
		}
		vulnerabilities = append(vulnerabilities, record)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("scan vulnerabilities: %w", err)
	}
	for _, record := range vulnerabilities {
		if err := s.loadRanges(ctx, record); err != nil {
			return nil, 0, err
		}
	}
	return vulnerabilities, total, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanVulnerability(scanner rowScanner) (*vuln.Vulnerability, error) {
	record := &vuln.Vulnerability{}
	var severity, status string
	if err := scanner.Scan(
		&record.ID, &record.Component, &severity, &record.FixedVersion, &status,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("scan vulnerability: %w", err)
	}
	record.Severity = vuln.Severity(severity)
	record.Status = vuln.Status(status)
	return record, nil
}

func (s *Store) loadRanges(ctx context.Context, record *vuln.Vulnerability) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT lower_version, lower_include, upper_version, upper_include
		FROM affected_ranges WHERE vulnerability_id = ?
		ORDER BY position ASC`, record.ID)
	if err != nil {
		return fmt.Errorf("load ranges: %w", err)
	}
	defer rows.Close()

	record.Ranges = []vuln.Range{}
	for rows.Next() {
		var lower, upper sql.NullString
		var lowerInclude, upperInclude int
		if err := rows.Scan(&lower, &lowerInclude, &upper, &upperInclude); err != nil {
			return fmt.Errorf("scan range: %w", err)
		}
		affected := vuln.Range{}
		if lower.Valid {
			text := lower.String
			included := lowerInclude == 1
			affected.Lower = &text
			affected.LowerInclude = &included
		}
		if upper.Valid {
			text := upper.String
			included := upperInclude == 1
			affected.Upper = &text
			affected.UpperInclude = &included
		}
		record.Ranges = append(record.Ranges, affected)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("scan ranges: %w", err)
	}
	if err := record.PrepareRanges(); err != nil {
		return fmt.Errorf("prepare stored ranges: %w", err)
	}
	return nil
}

func boolToInt(value *bool) int {
	if value != nil && *value {
		return 1
	}
	return 0
}

func isUniqueViolation(err error) bool {
	var sqliteErr *libsqlite.Error
	if errors.As(err, &sqliteErr) {
		// 19 is SQLITE_CONSTRAINT, 2067/2062 are UNIQUE/PK extended codes.
		code := sqliteErr.Code()
		if code == 19 || code == 2067 || code == 2062 {
			return true
		}
	}
	return false
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
	vulnerability_id TEXT    NOT NULL
		REFERENCES vulnerabilities(id) ON DELETE CASCADE,
	position         INTEGER NOT NULL,
	lower_version    TEXT,
	lower_include    INTEGER NOT NULL DEFAULT 0,
	upper_version    TEXT,
	upper_include    INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (vulnerability_id, position)
);
`
