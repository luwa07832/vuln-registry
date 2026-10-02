package store

import (
	"context"
	"testing"

	"github.com/luwa07832/vuln-registry/internal/vuln"
)

func mustCreateListRecord(t *testing.T, st *Store, id, component string, severity vuln.Severity, status vuln.Status) {
	t.Helper()
	record := sampleVulnerability(id)
	record.Component = component
	record.Severity = severity
	record.Status = status
	if err := record.PrepareRanges(); err != nil {
		t.Fatalf("prepare %s: %v", id, err)
	}
	if err := st.CreateVulnerability(context.Background(), record); err != nil {
		t.Fatalf("create %s: %v", id, err)
	}
}

func seedListRecords(t *testing.T, st *Store) {
	t.Helper()
	mustCreateListRecord(t, st, "CVE-2024-0003", "libxml2", vuln.SeverityHigh, vuln.StatusOpen)
	mustCreateListRecord(t, st, "CVE-2024-0001", "libxml2", vuln.SeverityLow, vuln.StatusFixed)
	mustCreateListRecord(t, st, "CVE-2024-0002", "openssl", vuln.SeverityHigh, vuln.StatusOpen)
	mustCreateListRecord(t, st, "CVE-2024-0004", "libxml2", vuln.SeverityHigh, vuln.StatusFixed)
}

func listIDs(records []*vuln.Vulnerability) []string {
	ids := []string{}
	for _, record := range records {
		ids = append(ids, record.ID)
	}
	return ids
}

func assertListResult(t *testing.T, records []*vuln.Vulnerability, total int, wantIDs []string, wantTotal int) {
	t.Helper()
	if total != wantTotal {
		t.Fatalf("total = %d, want %d", total, wantTotal)
	}
	got := listIDs(records)
	if len(got) != len(wantIDs) {
		t.Fatalf("ids = %v, want %v", got, wantIDs)
	}
	for index := range wantIDs {
		if got[index] != wantIDs[index] {
			t.Fatalf("ids = %v, want %v", got, wantIDs)
		}
	}
}

func TestListVulnerabilitiesFiltersSortsAndCounts(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	seedListRecords(t, st)

	all := []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004"}

	records, total, err := st.ListVulnerabilities(ctx, ListFilter{}, 1, 20)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	assertListResult(t, records, total, all, 4)

	libxml2 := "libxml2"
	records, total, err = st.ListVulnerabilities(ctx, ListFilter{Component: &libxml2}, 1, 20)
	if err != nil {
		t.Fatalf("list component: %v", err)
	}
	assertListResult(t, records, total, []string{"CVE-2024-0001", "CVE-2024-0003", "CVE-2024-0004"}, 3)

	upper := "LIBXML2"
	records, total, err = st.ListVulnerabilities(ctx, ListFilter{Component: &upper}, 1, 20)
	if err != nil {
		t.Fatalf("list case: %v", err)
	}
	assertListResult(t, records, total, []string{}, 0)

	high := vuln.SeverityHigh
	records, total, err = st.ListVulnerabilities(ctx, ListFilter{Severity: &high}, 1, 20)
	if err != nil {
		t.Fatalf("list severity: %v", err)
	}
	assertListResult(t, records, total, []string{"CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004"}, 3)

	open := vuln.StatusOpen
	records, total, err = st.ListVulnerabilities(ctx, ListFilter{Status: &open}, 1, 20)
	if err != nil {
		t.Fatalf("list status: %v", err)
	}
	assertListResult(t, records, total, []string{"CVE-2024-0002", "CVE-2024-0003"}, 2)

	fixed := vuln.StatusFixed
	records, total, err = st.ListVulnerabilities(ctx, ListFilter{Component: &libxml2, Severity: &high, Status: &fixed}, 1, 20)
	if err != nil {
		t.Fatalf("list combined: %v", err)
	}
	assertListResult(t, records, total, []string{"CVE-2024-0004"}, 1)
}

func TestListVulnerabilitiesPaginatesAndReportsTotal(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	seedListRecords(t, st)

	records, total, err := st.ListVulnerabilities(ctx, ListFilter{}, 1, 2)
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	assertListResult(t, records, total, []string{"CVE-2024-0001", "CVE-2024-0002"}, 4)

	records, total, err = st.ListVulnerabilities(ctx, ListFilter{}, 2, 2)
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	assertListResult(t, records, total, []string{"CVE-2024-0003", "CVE-2024-0004"}, 4)

	records, total, err = st.ListVulnerabilities(ctx, ListFilter{}, 3, 2)
	if err != nil {
		t.Fatalf("page 3: %v", err)
	}
	if records == nil {
		t.Fatalf("empty page must stay a non-nil slice")
	}
	assertListResult(t, records, total, []string{}, 4)
}

func TestListVulnerabilitiesLoadsRangesInOrder(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	mustCreateListRecord(t, st, "CVE-2024-0010", "libxml2", vuln.SeverityHigh, vuln.StatusOpen)

	records, total, err := st.ListVulnerabilities(ctx, ListFilter{}, 1, 20)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 1 || len(records) != 1 {
		t.Fatalf("total = %d len = %d, want 1", total, len(records))
	}
	ranges := records[0].Ranges
	if len(ranges) != 2 {
		t.Fatalf("ranges = %d, want 2", len(ranges))
	}
	if ranges[0].LowerText() != "2.0" || ranges[0].UpperText() != "" {
		t.Fatalf("first range wrong: %#v", ranges[0])
	}
	if ranges[1].LowerText() != "2.4" || ranges[1].UpperText() != "2.9.9" {
		t.Fatalf("second range wrong: %#v", ranges[1])
	}
}
