package store

import (
	"context"
	"errors"
	"testing"

	"github.com/luwa07832/vuln-registry/internal/vuln"
)

func seedVulnerabilities(t *testing.T, st *Store, ids ...string) {
	t.Helper()
	ctx := context.Background()
	for _, id := range ids {
		record := sampleVulnerability(id)
		if err := record.PrepareRanges(); err != nil {
			t.Fatalf("prepare %s: %v", id, err)
		}
		if err := st.CreateVulnerability(ctx, record); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}
}

func TestUpdateStatusesAppliesChangesAndMirrorsOrder(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	seedVulnerabilities(t, st, "CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003")

	updates := []StatusUpdate{
		{ID: "CVE-2024-0003", Status: vuln.StatusAccepted},
		{ID: "CVE-2024-0001", Status: vuln.StatusFixed},
		{ID: "CVE-2024-0002", Status: vuln.StatusInProgress},
	}
	records, err := st.UpdateStatuses(ctx, updates)
	if err != nil {
		t.Fatalf("update statuses: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("records = %d, want 3", len(records))
	}
	wantOrder := []struct {
		id     string
		status vuln.Status
	}{
		{"CVE-2024-0003", vuln.StatusAccepted},
		{"CVE-2024-0001", vuln.StatusFixed},
		{"CVE-2024-0002", vuln.StatusInProgress},
	}
	for index, want := range wantOrder {
		if records[index].ID != want.id {
			t.Fatalf("record %d id = %q, want %q (must mirror input order)", index, records[index].ID, want.id)
		}
		if records[index].Status != want.status {
			t.Fatalf("%s status = %q, want %q", want.id, records[index].Status, want.status)
		}
		if records[index].Component != "libxml2" || records[index].Severity != vuln.SeverityHigh ||
			records[index].FixedVersion != "2.10.0" {
			t.Fatalf("%s non-status fields changed: %#v", want.id, records[index])
		}
		if len(records[index].Ranges) != 2 {
			t.Fatalf("%s ranges changed: %#v", want.id, records[index].Ranges)
		}
	}

	for _, want := range wantOrder {
		stored, err := st.GetVulnerability(ctx, want.id)
		if err != nil {
			t.Fatalf("get %s: %v", want.id, err)
		}
		if stored.Status != want.status {
			t.Fatalf("stored %s status = %q, want %q", want.id, stored.Status, want.status)
		}
	}
}

func TestUpdateStatusesUnknownIdRollsBack(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	seedVulnerabilities(t, st, "CVE-2024-0001", "CVE-2024-0002")

	_, err := st.UpdateStatuses(ctx, []StatusUpdate{
		{ID: "CVE-2024-0002", Status: vuln.StatusFixed},
		{ID: "CVE-2024-9999", Status: vuln.StatusAccepted},
	})
	if !errors.Is(err, ErrVulnerabilityNotFound) {
		t.Fatalf("err = %v, want ErrVulnerabilityNotFound", err)
	}

	for _, id := range []string{"CVE-2024-0001", "CVE-2024-0002"} {
		stored, err := st.GetVulnerability(ctx, id)
		if err != nil {
			t.Fatalf("get %s: %v", id, err)
		}
		if stored.Status != vuln.StatusOpen {
			t.Fatalf("%s must keep status open after rollback, got %q", id, stored.Status)
		}
	}
}

func TestUpdateStatusesCaseSensitiveId(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	seedVulnerabilities(t, st, "CVE-2024-0001")

	if _, err := st.UpdateStatuses(ctx, []StatusUpdate{
		{ID: "cve-2024-0001", Status: vuln.StatusFixed},
	}); !errors.Is(err, ErrVulnerabilityNotFound) {
		t.Fatalf("err = %v, want ErrVulnerabilityNotFound", err)
	}
	stored, err := st.GetVulnerability(ctx, "CVE-2024-0001")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if stored.Status != vuln.StatusOpen {
		t.Fatalf("status = %q, want open", stored.Status)
	}
}
