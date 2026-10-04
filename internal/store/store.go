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

// Status history sources recorded with every event.
const (
	StatusSourceCreate       = "create"
	StatusSourceStatusUpdate = "status_update"
	StatusSourceReplace      = "replace"
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

	if err := insertStatusEventTx(ctx, tx, vulnerability.ID, nil, vulnerability.Status, StatusSourceCreate); err != nil {
		return err
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

// insertStatusEventTx appends one event to the status history of id inside
// the open transaction, assigning the next per-record sequence number. A nil
// previous marks the initial registration event.
func insertStatusEventTx(ctx context.Context, tx *sql.Tx, id string, previous *vuln.Status, status vuln.Status, source string) error {
	var sequence int
	if err := tx.QueryRowContext(ctx,
		"SELECT COALESCE(MAX(sequence), 0) + 1 FROM status_history WHERE vulnerability_id = ?", id,
	).Scan(&sequence); err != nil {
		return fmt.Errorf("next status sequence: %w", err)
	}

	var previousArg any
	if previous != nil {
		previousArg = string(*previous)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO status_history (vulnerability_id, sequence, previous_status, status, source)
		VALUES (?, ?, ?, ?, ?)`,
		id, sequence, previousArg, string(status), source,
	); err != nil {
		return fmt.Errorf("insert status event: %w", err)
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

// UpdateStatus changes only the disposition status of one record and records
// the transition in the status history when the value actually changes, all
// in a single transaction. It returns ErrVulnerabilityNotFound when the id
// is unknown; every other column stays untouched.
func (s *Store) UpdateStatus(ctx context.Context, id string, status vuln.Status) (*vuln.Vulnerability, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin status update: %w", err)
	}
	defer tx.Rollback()

	if err := updateStatusTx(ctx, tx, id, status, StatusSourceStatusUpdate); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit status update: %w", err)
	}
	return s.GetVulnerability(ctx, id)
}

// updateStatusTx applies one disposition change inside the open transaction
// and appends a history event with the given source when the value actually
// changes. It returns ErrVulnerabilityNotFound when the id is unknown.
func updateStatusTx(ctx context.Context, tx *sql.Tx, id string, status vuln.Status, source string) error {
	var previous string
	switch err := tx.QueryRowContext(ctx,
		"SELECT status FROM vulnerabilities WHERE id = ?", id,
	).Scan(&previous); {
	case errors.Is(err, sql.ErrNoRows):
		return ErrVulnerabilityNotFound
	case err != nil:
		return fmt.Errorf("load current status: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		"UPDATE vulnerabilities SET status = ? WHERE id = ?", string(status), id,
	); err != nil {
		return fmt.Errorf("update status: %w", err)
	}

	if vuln.Status(previous) == status {
		return nil
	}
	previousStatus := vuln.Status(previous)
	return insertStatusEventTx(ctx, tx, id, &previousStatus, status, source)
}

// StatusUpdate pairs one vulnerability id with the disposition status it
// should carry after a batch update.
type StatusUpdate struct {
	ID     string
	Status vuln.Status
}

// UpdateStatuses applies every given status change in a single transaction:
// either all records are updated or none is. Every actual change appends a
// status-history event in submission order inside the same transaction. It returns
// ErrVulnerabilityNotFound when any id is unknown, leaving every record
// untouched, and only the status column changes. On success the updated
// records are returned in the order the updates were given.
func (s *Store) UpdateStatuses(ctx context.Context, updates []StatusUpdate) ([]*vuln.Vulnerability, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin status update: %w", err)
	}
	defer tx.Rollback()

	for _, update := range updates {
		if err := updateStatusTx(ctx, tx, update.ID, update.Status, StatusSourceStatusUpdate); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit status update: %w", err)
	}

	records := make([]*vuln.Vulnerability, 0, len(updates))
	for _, update := range updates {
		record, err := s.GetVulnerability(ctx, update.ID)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

// UpdateVulnerability replaces every column except the id and all of the
// record's affected ranges in a single transaction. When the replacement
// changes the disposition status, the transition is appended to the status
// history inside the same transaction. It returns
// ErrVulnerabilityNotFound when the id is unknown; on any failure the
// transaction rolls back and the stored record stays byte-for-byte intact.
// The id on vulnerability must already equal the path id; callers validate
// the payload before calling.
func (s *Store) UpdateVulnerability(ctx context.Context, vulnerability *vuln.Vulnerability) (*vuln.Vulnerability, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin update: %w", err)
	}
	defer tx.Rollback()

	var previous string
	switch err := tx.QueryRowContext(ctx,
		"SELECT status FROM vulnerabilities WHERE id = ?", vulnerability.ID,
	).Scan(&previous); {
	case errors.Is(err, sql.ErrNoRows):
		return nil, ErrVulnerabilityNotFound
	case err != nil:
		return nil, fmt.Errorf("load current status: %w", err)
	}

	result, err := tx.ExecContext(ctx, `
		UPDATE vulnerabilities
		SET component = ?, severity = ?, fixed_version = ?, status = ?
		WHERE id = ?`,
		vulnerability.Component, string(vulnerability.Severity),
		vulnerability.FixedVersion, string(vulnerability.Status), vulnerability.ID)
	if err != nil {
		return nil, fmt.Errorf("update vulnerability: %w", err)
	}
	affectedRows, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("update vulnerability rows: %w", err)
	}
	if affectedRows == 0 {
		return nil, ErrVulnerabilityNotFound
	}

	if vuln.Status(previous) != vulnerability.Status {
		previousStatus := vuln.Status(previous)
		if err := insertStatusEventTx(ctx, tx, vulnerability.ID, &previousStatus, vulnerability.Status, StatusSourceReplace); err != nil {
			return nil, err
		}
	}

	if _, err := tx.ExecContext(ctx,
		"DELETE FROM affected_ranges WHERE vulnerability_id = ?", vulnerability.ID,
	); err != nil {
		return nil, fmt.Errorf("delete affected ranges: %w", err)
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
			return nil, fmt.Errorf("insert affected range: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit update: %w", err)
	}
	return s.GetVulnerability(ctx, vulnerability.ID)
}

// StatusEvent is one recorded transition in the status history of a
// vulnerability. PreviousStatus is nil only for the initial registration
// event.
type StatusEvent struct {
	Sequence       int
	PreviousStatus *vuln.Status
	Status         vuln.Status
	Source         string
}

// ListStatusHistory returns the recorded status transitions of one record,
// ordered by sequence ascending and sliced to the requested 1-based page,
// along with the total number of events before slicing. A page past the end
// yields an empty slice with the total still reported. It returns
// ErrVulnerabilityNotFound when the id is unknown.
func (s *Store) ListStatusHistory(ctx context.Context, id string, page, pageSize int) ([]StatusEvent, int, error) {
	var existing int
	switch err := s.db.QueryRowContext(ctx,
		"SELECT 1 FROM vulnerabilities WHERE id = ?", id,
	).Scan(&existing); {
	case errors.Is(err, sql.ErrNoRows):
		return nil, 0, ErrVulnerabilityNotFound
	case err != nil:
		return nil, 0, fmt.Errorf("check vulnerability: %w", err)
	}

	var total int
	if err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM status_history WHERE vulnerability_id = ?", id,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count status history: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT sequence, previous_status, status, source
		FROM status_history WHERE vulnerability_id = ?
		ORDER BY sequence ASC LIMIT ? OFFSET ?`, id, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, fmt.Errorf("list status history: %w", err)
	}
	defer rows.Close()

	events := []StatusEvent{}
	for rows.Next() {
		var event StatusEvent
		var previous sql.NullString
		var status, source string
		if err := rows.Scan(&event.Sequence, &previous, &status, &source); err != nil {
			return nil, 0, fmt.Errorf("scan status event: %w", err)
		}
		if previous.Valid {
			previousStatus := vuln.Status(previous.String)
			event.PreviousStatus = &previousStatus
		}
		event.Status = vuln.Status(status)
		event.Source = source
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("scan status history: %w", err)
	}
	return events, total, nil
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

CREATE TABLE IF NOT EXISTS status_history (
	vulnerability_id TEXT    NOT NULL
		REFERENCES vulnerabilities(id) ON DELETE CASCADE,
	sequence         INTEGER NOT NULL,
	previous_status  TEXT,
	status           TEXT    NOT NULL,
	source           TEXT    NOT NULL,
	PRIMARY KEY (vulnerability_id, sequence)
);
`
