package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/luwa07832/vuln-registry/internal/vuln"
)

func assertEvent(t *testing.T, event StatusHistoryEvent, sequence int, previous *vuln.Status, status vuln.Status, source HistorySource) {
	t.Helper()
	if event.Sequence != sequence {
		t.Fatalf("sequence = %d, want %d", event.Sequence, sequence)
	}
	if event.Status != status {
		t.Fatalf("status = %q, want %q", event.Status, status)
	}
	if event.Source != source {
		t.Fatalf("source = %q, want %q", event.Source, source)
	}
	if (event.PreviousStatus == nil) != (previous == nil) {
		t.Fatalf("previous_status presence = %v, want %v", event.PreviousStatus != nil, previous != nil)
	}
	if previous != nil && *event.PreviousStatus != *previous {
		t.Fatalf("previous_status = %q, want %q", *event.PreviousStatus, *previous)
	}
}

func TestStatusHistoryInitialCreateEvent(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	mustCreateSample(t, st, "CVE-2024-1001")

	events, total, err := st.StatusHistory(ctx, "CVE-2024-1001", 1, 20)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if total != 1 || len(events) != 1 {
		t.Fatalf("total=%d len=%d, want 1/1", total, len(events))
	}
	assertEvent(t, events[0], 1, nil, vuln.StatusOpen, SourceCreate)
}

func TestStatusHistoryTracksSingleUpdateAndNoops(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	mustCreateSample(t, st, "CVE-2024-1002")

	if _, err := st.UpdateStatus(ctx, "CVE-2024-1002", vuln.StatusOpen); err != nil {
		t.Fatalf("noop update: %v", err)
	}
	if _, err := st.UpdateStatus(ctx, "CVE-2024-1002", vuln.StatusFixed); err != nil {
		t.Fatalf("update fixed: %v", err)
	}
	if _, err := st.UpdateStatus(ctx, "CVE-2024-1002", vuln.StatusFixed); err != nil {
		t.Fatalf("second noop update: %v", err)
	}

	events, total, err := st.StatusHistory(ctx, "CVE-2024-1002", 1, 20)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if total != 2 || len(events) != 2 {
		t.Fatalf("total=%d len=%d, want 2/2", total, len(events))
	}
	assertEvent(t, events[0], 1, nil, vuln.StatusOpen, SourceCreate)
	open := vuln.StatusOpen
	assertEvent(t, events[1], 2, &open, vuln.StatusFixed, SourceStatusUpdate)

	if _, err := st.UpdateStatus(ctx, "CVE-2024-missing", vuln.StatusFixed); !errors.Is(err, ErrVulnerabilityNotFound) {
		t.Fatalf("unknown update err = %v, want ErrVulnerabilityNotFound", err)
	}
}

func TestStatusHistoryBatchFollowsSubmissionOrder(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	mustCreateSample(t, st, "CVE-2024-1010")
	mustCreateSample(t, st, "CVE-2024-1011")

	updates := []StatusUpdate{
		{ID: "CVE-2024-1011", Status: vuln.StatusFixed},
		{ID: "CVE-2024-1010", Status: vuln.StatusAccepted},
		{ID: "CVE-2024-1010", Status: vuln.StatusWontFix},
	}
	if _, err := st.UpdateStatuses(ctx, updates); err != nil {
		t.Fatalf("batch: %v", err)
	}

	events, total, err := st.StatusHistory(ctx, "CVE-2024-1010", 1, 20)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if total != 3 || len(events) != 3 {
		t.Fatalf("total=%d len=%d, want 3/3", total, len(events))
	}
	open := vuln.StatusOpen
	accepted := vuln.StatusAccepted
	assertEvent(t, events[0], 1, nil, vuln.StatusOpen, SourceCreate)
	assertEvent(t, events[1], 2, &open, vuln.StatusAccepted, SourceStatusUpdate)
	assertEvent(t, events[2], 3, &accepted, vuln.StatusWontFix, SourceStatusUpdate)

	events, total, err = st.StatusHistory(ctx, "CVE-2024-1011", 1, 20)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if total != 2 || len(events) != 2 {
		t.Fatalf("total=%d len=%d, want 2/2", total, len(events))
	}
	assertEvent(t, events[1], 2, &open, vuln.StatusFixed, SourceStatusUpdate)
}

func TestStatusHistoryBatchUnknownRollsBackEvents(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	mustCreateSample(t, st, "CVE-2024-1020")

	_, err := st.UpdateStatuses(ctx, []StatusUpdate{
		{ID: "CVE-2024-1020", Status: vuln.StatusFixed},
		{ID: "CVE-2024-9999", Status: vuln.StatusFixed},
	})
	if !errors.Is(err, ErrVulnerabilityNotFound) {
		t.Fatalf("batch err = %v, want ErrVulnerabilityNotFound", err)
	}

	events, total, err := st.StatusHistory(ctx, "CVE-2024-1020", 1, 20)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if total != 1 || len(events) != 1 {
		t.Fatalf("total=%d len=%d, want only create event after rollback", total, len(events))
	}
	loaded, err := st.GetVulnerability(ctx, "CVE-2024-1020")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if loaded.Status != vuln.StatusOpen {
		t.Fatalf("status changed despite rollback: %q", loaded.Status)
	}
}

func TestStatusHistoryReplaceEvents(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	mustCreateSample(t, st, "CVE-2024-1030")

	same := sampleVulnerability("CVE-2024-1030")
	if err := same.PrepareRanges(); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if _, err := st.UpdateVulnerability(ctx, same); err != nil {
		t.Fatalf("replace same status: %v", err)
	}

	changed := sampleVulnerability("CVE-2024-1030")
	changed.Status = vuln.StatusAccepted
	if err := changed.PrepareRanges(); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if _, err := st.UpdateVulnerability(ctx, changed); err != nil {
		t.Fatalf("replace changed: %v", err)
	}

	events, total, err := st.StatusHistory(ctx, "CVE-2024-1030", 1, 20)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if total != 2 || len(events) != 2 {
		t.Fatalf("total=%d len=%d, want 2/2", total, len(events))
	}
	assertEvent(t, events[0], 1, nil, vuln.StatusOpen, SourceCreate)
	open := vuln.StatusOpen
	assertEvent(t, events[1], 2, &open, vuln.StatusAccepted, SourceReplace)
}

func TestStatusHistoryPagination(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	mustCreateSample(t, st, "CVE-2024-1040")
	for _, status := range []vuln.Status{vuln.StatusFixed, vuln.StatusAccepted, vuln.StatusWontFix} {
		if _, err := st.UpdateStatus(ctx, "CVE-2024-1040", status); err != nil {
			t.Fatalf("update %s: %v", status, err)
		}
	}

	events, total, err := st.StatusHistory(ctx, "CVE-2024-1040", 2, 2)
	if err != nil {
		t.Fatalf("history page: %v", err)
	}
	if total != 4 {
		t.Fatalf("total = %d, want 4", total)
	}
	if len(events) != 2 || events[0].Sequence != 3 || events[1].Sequence != 4 {
		t.Fatalf("page contents wrong: %#v", events)
	}

	events, total, err = st.StatusHistory(ctx, "CVE-2024-1040", 5, 2)
	if err != nil {
		t.Fatalf("history past end: %v", err)
	}
	if total != 4 || len(events) != 0 {
		t.Fatalf("past end total=%d len=%d, want 4/0", total, len(events))
	}
}

func TestStatusHistoryUnknownID(t *testing.T) {
	st := openTestStore(t)
	_, _, err := st.StatusHistory(context.Background(), "CVE-2024-nope", 1, 20)
	if !errors.Is(err, ErrVulnerabilityNotFound) {
		t.Fatalf("err = %v, want ErrVulnerabilityNotFound", err)
	}
}

func TestStatusHistoryOldRecordStartsFromFirstChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.db")

	st, err := Open(path)
	if err != nil {
		t.Fatalf("open v1: %v", err)
	}
	ctx := context.Background()
	mustCreateSample(t, st, "CVE-2024-1050")
	if _, err := st.db.ExecContext(ctx,
		"DELETE FROM status_history WHERE vulnerability_id = ?", "CVE-2024-1050",
	); err != nil {
		t.Fatalf("erase backfilled history: %v", err)
	}
	if _, err := st.db.ExecContext(ctx,
		"UPDATE vulnerabilities SET status = ? WHERE id = ?", string(vuln.StatusFixed), "CVE-2024-1050",
	); err != nil {
		t.Fatalf("simulate legacy status write: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close v1: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	events, total, err := reopened.StatusHistory(ctx, "CVE-2024-1050", 1, 20)
	if err != nil {
		t.Fatalf("history after reopen: %v", err)
	}
	if total != 0 || len(events) != 0 {
		t.Fatalf("old record must not get backfilled history: total=%d len=%d", total, len(events))
	}

	if _, err := reopened.UpdateStatus(ctx, "CVE-2024-1050", vuln.StatusAccepted); err != nil {
		t.Fatalf("first real change: %v", err)
	}
	events, total, err = reopened.StatusHistory(ctx, "CVE-2024-1050", 1, 20)
	if err != nil {
		t.Fatalf("history after change: %v", err)
	}
	if total != 1 || len(events) != 1 {
		t.Fatalf("total=%d len=%d, want 1/1", total, len(events))
	}
	fixed := vuln.StatusFixed
	assertEvent(t, events[0], 1, &fixed, vuln.StatusAccepted, SourceStatusUpdate)

	var eventCount int
	if err := reopened.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM status_history WHERE vulnerability_id = ?", "CVE-2024-1050",
	).Scan(&eventCount); err != nil && err != sql.ErrNoRows {
		t.Fatalf("count raw events: %v", err)
	}
}

func TestBatchCreateWritesInitialEvents(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	records := []*vuln.Vulnerability{}
	for _, id := range []string{"CVE-2024-1060", "CVE-2024-1061"} {
		record := sampleVulnerability(id)
		if err := record.PrepareRanges(); err != nil {
			t.Fatalf("prepare: %v", err)
		}
		records = append(records, record)
	}
	if err := st.CreateVulnerabilities(ctx, records); err != nil {
		t.Fatalf("batch create: %v", err)
	}
	for _, id := range []string{"CVE-2024-1060", "CVE-2024-1061"} {
		events, total, err := st.StatusHistory(ctx, id, 1, 20)
		if err != nil {
			t.Fatalf("history %s: %v", id, err)
		}
		if total != 1 || len(events) != 1 {
			t.Fatalf("%s total=%d len=%d, want 1/1", id, total, len(events))
		}
		assertEvent(t, events[0], 1, nil, vuln.StatusOpen, SourceCreate)
	}
}
