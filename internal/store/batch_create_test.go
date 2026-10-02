package store

import (
	"context"
	"errors"
	"testing"

	"github.com/luwa07832/vuln-registry/internal/vuln"
)

func TestCreateVulnerabilitiesBatchRoundTrip(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	records := []*vuln.Vulnerability{
		sampleVulnerability("CVE-2024-5002"),
		sampleVulnerability("CVE-2024-5001"),
	}
	for _, record := range records {
		if err := record.PrepareRanges(); err != nil {
			t.Fatalf("prepare: %v", err)
		}
	}
	if err := st.CreateVulnerabilities(ctx, records); err != nil {
		t.Fatalf("batch create: %v", err)
	}

	loaded, total, err := st.ListVulnerabilities(ctx, ListFilter{}, 1, 20)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 2 || len(loaded) != 2 {
		t.Fatalf("stored = %d (total %d), want 2", len(loaded), total)
	}
	if loaded[0].ID != "CVE-2024-5001" || loaded[1].ID != "CVE-2024-5002" {
		t.Fatalf("list order wrong: %q %q", loaded[0].ID, loaded[1].ID)
	}
	if len(loaded[0].Ranges) != 2 {
		t.Fatalf("ranges not persisted: %#v", loaded[0].Ranges)
	}
}

func TestCreateVulnerabilitiesRejectsDuplicateWithinBatch(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	records := []*vuln.Vulnerability{
		sampleVulnerability("CVE-2024-5010"),
		sampleVulnerability("CVE-2024-5010"),
	}
	for _, record := range records {
		if err := record.PrepareRanges(); err != nil {
			t.Fatalf("prepare: %v", err)
		}
	}
	if err := st.CreateVulnerabilities(ctx, records); !errors.Is(err, ErrDuplicateVulnerability) {
		t.Fatalf("err = %v, want ErrDuplicateVulnerability", err)
	}
	if _, err := st.GetVulnerability(ctx, "CVE-2024-5010"); !errors.Is(err, ErrVulnerabilityNotFound) {
		t.Fatalf("duplicate batch left a record: %v", err)
	}
}

func TestCreateVulnerabilitiesRejectsStoredDuplicateAtomically(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	existing := sampleVulnerability("CVE-2024-5020")
	if err := existing.PrepareRanges(); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := st.CreateVulnerability(ctx, existing); err != nil {
		t.Fatalf("seed create: %v", err)
	}

	batch := []*vuln.Vulnerability{
		sampleVulnerability("CVE-2024-5021"),
		sampleVulnerability("CVE-2024-5020"),
	}
	for _, record := range batch {
		if err := record.PrepareRanges(); err != nil {
			t.Fatalf("prepare: %v", err)
		}
	}
	if err := st.CreateVulnerabilities(ctx, batch); !errors.Is(err, ErrDuplicateVulnerability) {
		t.Fatalf("err = %v, want ErrDuplicateVulnerability", err)
	}

	if _, err := st.GetVulnerability(ctx, "CVE-2024-5021"); !errors.Is(err, ErrVulnerabilityNotFound) {
		t.Fatalf("batch partially committed CVE-2024-5021: %v", err)
	}
	loaded, err := st.GetVulnerability(ctx, "CVE-2024-5020")
	if err != nil {
		t.Fatalf("existing record vanished: %v", err)
	}
	if loaded.Component != "libxml2" {
		t.Fatalf("existing record was modified: %#v", loaded)
	}
}
