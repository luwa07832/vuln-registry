package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/luwa07832/vuln-registry/internal/vuln"
)

func mustListHistory(t *testing.T, st *Store, id string, page, pageSize int) ([]StatusEvent, int) {
	t.Helper()
	events, total, err := st.ListStatusHistory(context.Background(), id, page, pageSize)
	if err != nil {
		t.Fatalf("list history %s: %v", id, err)
	}
	return events, total
}

func requireEvent(t *testing.T, event StatusEvent, sequence int, previous *vuln.Status, status vuln.Status, source string) {
	t.Helper()
	if event.Sequence != sequence {
		t.Fatalf("sequence = %d, want %d", event.Sequence, sequence)
	}
	if previous == nil {
		if event.PreviousStatus != nil {
			t.Fatalf("previous = %v, want nil", *event.PreviousStatus)
		}
	} else {
		if event.PreviousStatus == nil || *event.PreviousStatus != *previous {
			t.Fatalf("previous = %v, want %v", event.PreviousStatus, *previous)
		}
	}
	if event.Status != status || event.Source != source {
		t.Fatalf("event = (%s, %s), want (%s, %s)", event.Status, event.Source, status, source)
	}
}

func statusPtr(status vuln.Status) *vuln.Status { return &status }

func TestCreateWritesInitialEvent(t *testing.T) {
	st := openTestStore(t)
	mustCreateSample(t, st, "CVE-2024-5001")

	events, total := mustListHistory(t, st, "CVE-2024-5001", 1, 20)
	if total != 1 || len(events) != 1 {
		t.Fatalf("total = %d, len = %d, want 1/1", total, len(events))
	}
	requireEvent(t, events[0], 1, nil, vuln.StatusOpen, StatusSourceCreate)
}

func TestBatchCreateWritesInitialEvents(t *testing.T) {
	st := openTestStore(t)
	first, second := sampleVulnerability("CVE-2024-5002"), sampleVulnerability("CVE-2024-5003")
	second.Status = vuln.StatusAccepted
	for _, record := range []*vuln.Vulnerability{first, second} {
		if err := record.PrepareRanges(); err != nil {
			t.Fatalf("prepare: %v", err)
		}
	}
	if err := st.CreateVulnerabilities(context.Background(), []*vuln.Vulnerability{first, second}); err != nil {
		t.Fatalf("batch create: %v", err)
	}

	for id, status := range map[string]vuln.Status{
		"CVE-2024-5002": vuln.StatusOpen,
		"CVE-2024-5003": vuln.StatusAccepted,
	} {
		events, total := mustListHistory(t, st, id, 1, 20)
		if total != 1 || len(events) != 1 {
			t.Fatalf("%s total = %d, len = %d, want 1/1", id, total, len(events))
		}
		requireEvent(t, events[0], 1, nil, status, StatusSourceCreate)
	}
}

func TestUpdateStatusAppendsEventOnChange(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	mustCreateSample(t, st, "CVE-2024-5004")

	if _, err := st.UpdateStatus(ctx, "CVE-2024-5004", vuln.StatusFixed); err != nil {
		t.Fatalf("update: %v", err)
	}
	events, total := mustListHistory(t, st, "CVE-2024-5004", 1, 20)
	if total != 2 || len(events) != 2 {
		t.Fatalf("total = %d, len = %d, want 2/2", total, len(events))
	}
	requireEvent(t, events[0], 1, nil, vuln.StatusOpen, StatusSourceCreate)
	requireEvent(t, events[1], 2, statusPtr(vuln.StatusOpen), vuln.StatusFixed, StatusSourceStatusUpdate)
}

func TestUpdateStatusSameValueWritesNoEvent(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	mustCreateSample(t, st, "CVE-2024-5005")

	record, err := st.UpdateStatus(ctx, "CVE-2024-5005", vuln.StatusOpen)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if record.Status != vuln.StatusOpen {
		t.Fatalf("status = %s, want open", record.Status)
	}
	events, total := mustListHistory(t, st, "CVE-2024-5005", 1, 20)
	if total != 1 || len(events) != 1 {
		t.Fatalf("unchanged update must not append events: total = %d, len = %d", total, len(events))
	}
}

func TestUpdateStatusesAppendsInSubmissionOrder(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	for _, id := range []string{"CVE-2024-5006", "CVE-2024-5007"} {
		mustCreateSample(t, st, id)
	}

	if _, err := st.UpdateStatuses(ctx, []StatusUpdate{
		{ID: "CVE-2024-5007", Status: vuln.StatusFixed},
		{ID: "CVE-2024-5006", Status: vuln.StatusAccepted},
	}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if _, err := st.UpdateStatuses(ctx, []StatusUpdate{
		{ID: "CVE-2024-5006", Status: vuln.StatusOpen},
	}); err != nil {
		t.Fatalf("second update: %v", err)
	}

	events, total := mustListHistory(t, st, "CVE-2024-5006", 1, 20)
	if total != 3 || len(events) != 3 {
		t.Fatalf("total = %d, len = %d, want 3/3", total, len(events))
	}
	requireEvent(t, events[0], 1, nil, vuln.StatusOpen, StatusSourceCreate)
	requireEvent(t, events[1], 2, statusPtr(vuln.StatusOpen), vuln.StatusAccepted, StatusSourceStatusUpdate)
	requireEvent(t, events[2], 3, statusPtr(vuln.StatusAccepted), vuln.StatusOpen, StatusSourceStatusUpdate)

	events, total = mustListHistory(t, st, "CVE-2024-5007", 1, 20)
	if total != 2 || len(events) != 2 {
		t.Fatalf("total = %d, len = %d, want 2/2", total, len(events))
	}
	requireEvent(t, events[1], 2, statusPtr(vuln.StatusOpen), vuln.StatusFixed, StatusSourceStatusUpdate)
}

func TestUpdateStatusesUnknownIDLeavesNoEvents(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	mustCreateSample(t, st, "CVE-2024-5008")

	_, err := st.UpdateStatuses(ctx, []StatusUpdate{
		{ID: "CVE-2024-5008", Status: vuln.StatusFixed},
		{ID: "CVE-9999-0000", Status: vuln.StatusOpen},
	})
	if !errors.Is(err, ErrVulnerabilityNotFound) {
		t.Fatalf("unknown id: %v, want ErrVulnerabilityNotFound", err)
	}
	events, total := mustListHistory(t, st, "CVE-2024-5008", 1, 20)
	if total != 1 || len(events) != 1 {
		t.Fatalf("rolled back batch must not append events: total = %d, len = %d", total, len(events))
	}
}

func TestReplaceAppendsEventOnlyOnStatusChange(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	mustCreateSample(t, st, "CVE-2024-5009")

	same := sampleVulnerability("CVE-2024-5009")
	same.Component = "openssl"
	if err := same.PrepareRanges(); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if _, err := st.UpdateVulnerability(ctx, same); err != nil {
		t.Fatalf("replace same status: %v", err)
	}
	events, total := mustListHistory(t, st, "CVE-2024-5009", 1, 20)
	if total != 1 || len(events) != 1 {
		t.Fatalf("replace without status change must not append events: total = %d", total)
	}

	changed := sampleVulnerability("CVE-2024-5009")
	changed.Status = vuln.StatusWontFix
	if err := changed.PrepareRanges(); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if _, err := st.UpdateVulnerability(ctx, changed); err != nil {
		t.Fatalf("replace changed status: %v", err)
	}
	events, total = mustListHistory(t, st, "CVE-2024-5009", 1, 20)
	if total != 2 || len(events) != 2 {
		t.Fatalf("total = %d, len = %d, want 2/2", total, len(events))
	}
	requireEvent(t, events[1], 2, statusPtr(vuln.StatusOpen), vuln.StatusWontFix, StatusSourceReplace)
}

func TestListStatusHistoryPagination(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	mustCreateSample(t, st, "CVE-2024-5010")
	for _, status := range []vuln.Status{
		vuln.StatusInProgress, vuln.StatusFixed, vuln.StatusAccepted, vuln.StatusOpen,
	} {
		if _, err := st.UpdateStatus(ctx, "CVE-2024-5010", status); err != nil {
			t.Fatalf("update to %s: %v", status, err)
		}
	}

	events, total := mustListHistory(t, st, "CVE-2024-5010", 2, 2)
	if total != 5 || len(events) != 2 {
		t.Fatalf("total = %d, len = %d, want 5/2", total, len(events))
	}
	if events[0].Sequence != 3 || events[1].Sequence != 4 {
		t.Fatalf("page 2 sequences = %d, %d, want 3, 4", events[0].Sequence, events[1].Sequence)
	}

	events, total = mustListHistory(t, st, "CVE-2024-5010", 4, 2)
	if total != 5 || len(events) != 0 {
		t.Fatalf("past-end page: total = %d, len = %d, want 5/0", total, len(events))
	}
}

func TestListStatusHistoryUnknownID(t *testing.T) {
	st := openTestStore(t)
	if _, _, err := st.ListStatusHistory(context.Background(), "CVE-9999-0000", 1, 20); !errors.Is(err, ErrVulnerabilityNotFound) {
		t.Fatalf("unknown id: %v, want ErrVulnerabilityNotFound", err)
	}
}

func TestPreUpgradeRecordStartsHistoryOnFirstChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	if _, err := raw.Exec(`
		CREATE TABLE vulnerabilities (
			id            TEXT PRIMARY KEY,
			component     TEXT NOT NULL,
			severity      TEXT NOT NULL,
			fixed_version TEXT NOT NULL,
			status        TEXT NOT NULL
		);
		CREATE TABLE affected_ranges (
			vulnerability_id TEXT    NOT NULL
				REFERENCES vulnerabilities(id) ON DELETE CASCADE,
			position         INTEGER NOT NULL,
			lower_version    TEXT,
			lower_include    INTEGER NOT NULL DEFAULT 0,
			upper_version    TEXT,
			upper_include    INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (vulnerability_id, position)
		);
		INSERT INTO vulnerabilities (id, component, severity, fixed_version, status)
		VALUES ('CVE-2024-5011', 'libxml2', 'high', '2.10.0', 'accepted');
		INSERT INTO affected_ranges
			(vulnerability_id, position, lower_version, lower_include, upper_version, upper_include)
		VALUES ('CVE-2024-5011', 0, '2.0', 1, NULL, 0);
	`); err != nil {
		t.Fatalf("seed legacy schema: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw: %v", err)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatalf("open upgraded store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	events, total := mustListHistory(t, st, "CVE-2024-5011", 1, 20)
	if total != 0 || len(events) != 0 {
		t.Fatalf("upgrade must not fabricate history: total = %d, len = %d", total, len(events))
	}

	if _, err := st.UpdateStatus(context.Background(), "CVE-2024-5011", vuln.StatusFixed); err != nil {
		t.Fatalf("update: %v", err)
	}
	events, total = mustListHistory(t, st, "CVE-2024-5011", 1, 20)
	if total != 1 || len(events) != 1 {
		t.Fatalf("total = %d, len = %d, want 1/1", total, len(events))
	}
	requireEvent(t, events[0], 1, statusPtr(vuln.StatusAccepted), vuln.StatusFixed, StatusSourceStatusUpdate)
}
