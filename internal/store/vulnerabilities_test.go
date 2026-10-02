package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/luwa07832/vuln-registry/internal/vuln"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func sampleVulnerability(id string) *vuln.Vulnerability {
	lowerTrue := true
	upperFalse := false
	return &vuln.Vulnerability{
		ID:           id,
		Component:    "libxml2",
		Severity:     vuln.SeverityHigh,
		FixedVersion: "2.10.0",
		Status:       vuln.StatusOpen,
		Ranges: []vuln.Range{
			{Lower: &[]string{"2.0"}[0], LowerInclude: &lowerTrue},
			{Lower: &[]string{"2.4"}[0], LowerInclude: &lowerTrue, Upper: &[]string{"2.9.9"}[0], UpperInclude: &upperFalse},
		},
	}
}

func TestCreateGetAndListRoundTrip(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	record := sampleVulnerability("CVE-2024-0001")
	if err := record.PrepareRanges(); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := st.CreateVulnerability(ctx, record); err != nil {
		t.Fatalf("create: %v", err)
	}

	loaded, err := st.GetVulnerability(ctx, record.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if loaded.Component != "libxml2" || loaded.FixedVersion != "2.10.0" {
		t.Fatalf("loaded scalar fields wrong: %#v", loaded)
	}
	if len(loaded.Ranges) != 2 {
		t.Fatalf("ranges = %d, want 2", len(loaded.Ranges))
	}
	if loaded.Ranges[0].UpperText() != "" || loaded.Ranges[1].UpperText() != "2.9.9" {
		t.Fatalf("range bounds wrong: %#v", loaded.Ranges)
	}
	if *loaded.Ranges[1].UpperInclude {
		t.Fatalf("second upper bound should be exclusive")
	}
	if !loaded.Contains(mustParse(t, "2.0")) || !loaded.Contains(mustParse(t, "2.5")) {
		t.Fatalf("stored ranges do not match expected versions")
	}
}

func TestCreateRejectsDuplicateID(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	first := sampleVulnerability("CVE-2024-0002")
	if err := first.PrepareRanges(); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := st.CreateVulnerability(ctx, first); err != nil {
		t.Fatalf("create first: %v", err)
	}

	second := sampleVulnerability("CVE-2024-0002")
	second.Component = "openssl"
	if err := second.PrepareRanges(); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := st.CreateVulnerability(ctx, second); !errors.Is(err, ErrDuplicateVulnerability) {
		t.Fatalf("create second: %v, want ErrDuplicateVulnerability", err)
	}

	loaded, err := st.GetVulnerability(ctx, first.ID)
	if err != nil || loaded.Component != "libxml2" {
		t.Fatalf("duplicate registration changed the record: %v %#v", err, loaded)
	}
}

func TestComponentMatchIsCaseSensitiveAndIDSorted(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	for index, id := range []string{"CVE-2024-0010", "CVE-2024-0003"} {
		record := sampleVulnerability(id)
		if index == 1 {
			record.Component = "LIBXML2"
		}
		if err := record.PrepareRanges(); err != nil {
			t.Fatalf("prepare: %v", err)
		}
		if err := st.CreateVulnerability(ctx, record); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}
	matches, err := st.ListByComponent(ctx, "libxml2")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(matches) != 1 || matches[0].ID != "CVE-2024-0010" {
		t.Fatalf("case-sensitive match failed: %#v", matches)
	}
}

func TestUpdateStatusChangesOnlyStatus(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	record := sampleVulnerability("CVE-2024-0020")
	if err := record.PrepareRanges(); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := st.CreateVulnerability(ctx, record); err != nil {
		t.Fatalf("create: %v", err)
	}

	updated, err := st.UpdateStatus(ctx, record.ID, vuln.StatusFixed)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Status != vuln.StatusFixed {
		t.Fatalf("status = %q, want fixed", updated.Status)
	}
	if updated.Component != "libxml2" || updated.FixedVersion != "2.10.0" || len(updated.Ranges) != 2 {
		t.Fatalf("update touched other fields: %#v", updated)
	}

	if _, err := st.UpdateStatus(ctx, "CVE-9999-0000", vuln.StatusFixed); !errors.Is(err, ErrVulnerabilityNotFound) {
		t.Fatalf("unknown id: %v, want ErrVulnerabilityNotFound", err)
	}
	if _, err := st.GetVulnerability(ctx, "CVE-9999-0000"); !errors.Is(err, ErrVulnerabilityNotFound) {
		t.Fatalf("get unknown: %v, want not found", err)
	}
}

func TestListVulnerabilitiesFiltersPaginatesAndCounts(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	specs := []struct {
		id       string
		severity vuln.Severity
		status   vuln.Status
	}{
		{"CVE-2024-0003", vuln.SeverityHigh, vuln.StatusFixed},
		{"CVE-2024-0001", vuln.SeverityLow, vuln.StatusOpen},
		{"CVE-2024-0002", vuln.SeverityHigh, vuln.StatusOpen},
	}
	for _, spec := range specs {
		record := sampleVulnerability(spec.id)
		record.Severity = spec.severity
		record.Status = spec.status
		if err := record.PrepareRanges(); err != nil {
			t.Fatalf("prepare: %v", err)
		}
		if err := st.CreateVulnerability(ctx, record); err != nil {
			t.Fatalf("create %s: %v", spec.id, err)
		}
	}

	all, total, err := st.ListVulnerabilities(ctx, VulnerabilityFilter{}, 1, 20)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 3 || len(all) != 3 {
		t.Fatalf("unfiltered list wrong: total=%d len=%d", total, len(all))
	}
	if all[0].ID != "CVE-2024-0001" || all[1].ID != "CVE-2024-0002" || all[2].ID != "CVE-2024-0003" {
		t.Fatalf("ids not sorted: %#v", all)
	}

	openHigh, filteredTotal, err := st.ListVulnerabilities(ctx, VulnerabilityFilter{
		Component: "libxml2",
		Severity:  vuln.SeverityHigh,
		Status:    vuln.StatusOpen,
	}, 1, 20)
	if err != nil {
		t.Fatalf("filtered list: %v", err)
	}
	if filteredTotal != 1 || len(openHigh) != 1 || openHigh[0].ID != "CVE-2024-0002" {
		t.Fatalf("filtered list wrong: total=%d records=%#v", filteredTotal, openHigh)
	}

	firstPage, firstTotal, err := st.ListVulnerabilities(ctx, VulnerabilityFilter{}, 1, 2)
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if firstTotal != 3 || len(firstPage) != 2 || firstPage[0].ID != "CVE-2024-0001" || firstPage[1].ID != "CVE-2024-0002" {
		t.Fatalf("first page wrong: total=%d page=%#v", firstTotal, firstPage)
	}
	secondPage, _, err := st.ListVulnerabilities(ctx, VulnerabilityFilter{}, 2, 2)
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if len(secondPage) != 1 || secondPage[0].ID != "CVE-2024-0003" {
		t.Fatalf("second page wrong: %#v", secondPage)
	}
	beyond, beyondTotal, err := st.ListVulnerabilities(ctx, VulnerabilityFilter{}, 3, 2)
	if err != nil {
		t.Fatalf("beyond range: %v", err)
	}
	if len(beyond) != 0 || beyondTotal != 3 {
		t.Fatalf("beyond-range page wrong: len=%d total=%d", len(beyond), beyondTotal)
	}
}

func mustParse(t *testing.T, value string) vuln.Version {
	t.Helper()
	parsed, err := vuln.ParseVersion(value)
	if err != nil {
		t.Fatalf("parse %q: %v", value, err)
	}
	return parsed
}
