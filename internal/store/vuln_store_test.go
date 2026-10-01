package store

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/luwa07832/vuln-registry/internal/vuln"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func sampleRecord() *vuln.Vulnerability {
	return &vuln.Vulnerability{
		ID:        "CVE-2026-0001",
		Component: "libdemo",
		Ranges: []vuln.Range{
			{Lower: strp("1.0.0"), LowerInclusive: true, Upper: strp("1.2.0"), UpperInclusive: false},
			{Upper: strp("0.9.0"), UpperInclusive: true},
		},
		Severity: "high",
		Fixed:    "1.2.0",
		Status:   "open",
	}
}

func strp(s string) *string { return &s }

func TestCreateGetDuplicateRoundTrip(t *testing.T) {
	st := testStore(t)
	record := sampleRecord()
	if err := st.CreateVulnerability(record); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := st.CreateVulnerability(record); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("second create: err = %v, want ErrDuplicate", err)
	}
	got, err := st.GetVulnerability(record.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Component != record.Component || got.Severity != "high" || got.Fixed != "1.2.0" || got.Status != "open" {
		t.Fatalf("scalar fields mismatch: %+v", got)
	}
	if len(got.Ranges) != 2 {
		t.Fatalf("ranges = %d, want 2", len(got.Ranges))
	}
	first := got.Ranges[0]
	if first.Lower == nil || *first.Lower != "1.0.0" || !first.LowerInclusive {
		t.Fatalf("lower bound mismatch: %+v", first)
	}
	if first.Upper == nil || *first.Upper != "1.2.0" || first.UpperInclusive {
		t.Fatalf("upper bound mismatch: %+v", first)
	}
	second := got.Ranges[1]
	if second.Lower != nil || second.LowerInclusive {
		t.Fatalf("open lower must stay open: %+v", second)
	}
}

func TestGetUnknownVulnerabilityReturnsNotFound(t *testing.T) {
	st := testStore(t)
	if _, err := st.GetVulnerability("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestSetVulnStatusUpdatesOnlyStatus(t *testing.T) {
	st := testStore(t)
	if err := st.CreateVulnerability(sampleRecord()); err != nil {
		t.Fatalf("create: %v", err)
	}
	updated, err := st.SetVulnStatus("CVE-2026-0001", "fixed")
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Status != "fixed" || updated.Fixed != "1.2.0" || len(updated.Ranges) != 2 {
		t.Fatalf("update changed other fields: %+v", updated)
	}
	if _, err := st.SetVulnStatus("missing", "open"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown update: err = %v, want ErrNotFound", err)
	}
	persisted, err := st.GetVulnerability("CVE-2026-0001")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if persisted.Status != "fixed" {
		t.Fatalf("status = %q, want fixed", persisted.Status)
	}
}

func TestListByComponentIsExactAndSorted(t *testing.T) {
	st := testStore(t)
	records := []*vuln.Vulnerability{
		{ID: "CVE-b", Component: "libdemo", Ranges: []vuln.Range{{Upper: strp("2.0"), UpperInclusive: false}}, Severity: "low", Fixed: "2.0", Status: "open"},
		{ID: "CVE-a", Component: "libdemo", Ranges: []vuln.Range{{}}, Severity: "low", Fixed: "3.0", Status: "open"},
		{ID: "CVE-c", Component: "LibDemo", Ranges: []vuln.Range{{}}, Severity: "low", Fixed: "3.0", Status: "open"},
	}
	for _, record := range records {
		if err := st.CreateVulnerability(record); err != nil {
			t.Fatalf("create %s: %v", record.ID, err)
		}
	}
	got, err := st.ListByComponent("libdemo")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 || got[0].ID != "CVE-a" || got[1].ID != "CVE-b" {
		t.Fatalf("list mismatch: %+v", got)
	}
}
