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

func mustParse(t *testing.T, value string) vuln.Version {
	t.Helper()
	parsed, err := vuln.ParseVersion(value)
	if err != nil {
		t.Fatalf("parse %q: %v", value, err)
	}
	return parsed
}

func TestReplaceVulnerabilityOverwritesEverythingButID(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	original := sampleVulnerability("CVE-2024-2000")
	if err := original.PrepareRanges(); err != nil {
		t.Fatalf("prepare original: %v", err)
	}
	if err := st.CreateVulnerability(ctx, original); err != nil {
		t.Fatalf("create: %v", err)
	}

	lowerFalse := false
	upperTrue := true
	replacement := &vuln.Vulnerability{
		ID:           "CVE-2024-2000",
		Component:    "openssl",
		Severity:     vuln.SeverityCritical,
		FixedVersion: "3.2.2",
		Status:       vuln.StatusInProgress,
		Ranges: []vuln.Range{
			{Upper: &[]string{"1.0.0"}[0], UpperInclude: &lowerFalse},
			{Lower: &[]string{"2.0.0"}[0], LowerInclude: &upperTrue},
		},
	}
	if err := replacement.PrepareRanges(); err != nil {
		t.Fatalf("prepare replacement: %v", err)
	}
	replaced, err := st.ReplaceVulnerability(ctx, replacement)
	if err != nil {
		t.Fatalf("replace: %v", err)
	}
	if replaced.Component != "openssl" || replaced.Severity != vuln.SeverityCritical ||
		replaced.FixedVersion != "3.2.2" || replaced.Status != vuln.StatusInProgress {
		t.Fatalf("scalar fields not replaced: %#v", replaced)
	}
	if len(replaced.Ranges) != 2 || replaced.Ranges[0].LowerText() != "" ||
		replaced.Ranges[0].UpperText() != "1.0.0" || replaced.Ranges[1].UpperText() != "" ||
		replaced.Ranges[1].LowerText() != "2.0.0" {
		t.Fatalf("ranges not replaced in order: %#v", replaced.Ranges)
	}

	loaded, err := st.GetVulnerability(ctx, "CVE-2024-2000")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if loaded.Component != "openssl" || len(loaded.Ranges) != 2 {
		t.Fatalf("stored record not replaced: %#v", loaded)
	}
	if loaded.Contains(mustParse(t, "1.5")) || !loaded.Contains(mustParse(t, "2.0")) || loaded.Contains(mustParse(t, "1.0")) {
		t.Fatalf("stored ranges behave like the old record: %#v", loaded.Ranges)
	}

	oldComponent, err := st.ListByComponent(ctx, "libxml2")
	if err != nil {
		t.Fatalf("list old component: %v", err)
	}
	if len(oldComponent) != 0 {
		t.Fatalf("old component rows survived: %#v", oldComponent)
	}

	if _, err := st.ReplaceVulnerability(ctx, replacement); err != nil {
		t.Fatalf("idempotent re-replace should keep working: %v", err)
	}
	if _, err := st.ReplaceVulnerability(ctx, &vuln.Vulnerability{
		ID:           "CVE-9999-9999",
		Component:    "openssl",
		Severity:     vuln.SeverityLow,
		FixedVersion: "9.9.9",
		Status:       vuln.StatusOpen,
		Ranges:       []vuln.Range{{Lower: &[]string{"1.0"}[0], LowerInclude: &upperTrue}},
	}); !errors.Is(err, ErrVulnerabilityNotFound) {
		t.Fatalf("unknown id replace: %v, want ErrVulnerabilityNotFound", err)
	}
}
