package store

import (
	"context"
	"errors"
	"testing"

	"github.com/luwa07832/vuln-registry/internal/vuln"
)

func mustCreateSample(t *testing.T, st *Store, id string) {
	t.Helper()
	record := sampleVulnerability(id)
	if err := record.PrepareRanges(); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := st.CreateVulnerability(context.Background(), record); err != nil {
		t.Fatalf("create %s: %v", id, err)
	}
}

func TestUpdateStatusesRoundTrip(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	for _, id := range []string{"CVE-2024-0030", "CVE-2024-0031", "CVE-2024-0032"} {
		mustCreateSample(t, st, id)
	}

	updates := []StatusUpdate{
		{ID: "CVE-2024-0032", Status: vuln.StatusFixed},
		{ID: "CVE-2024-0030", Status: vuln.StatusAccepted},
	}
	records, err := st.UpdateStatuses(ctx, updates)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if len(records) != 2 || records[0].ID != "CVE-2024-0032" || records[1].ID != "CVE-2024-0030" {
		t.Fatalf("records must follow update order: %#v", records)
	}
	if records[0].Status != vuln.StatusFixed || records[1].Status != vuln.StatusAccepted {
		t.Fatalf("statuses wrong: %#v", records)
	}
	if records[0].Component != "libxml2" || records[0].FixedVersion != "2.10.0" || len(records[0].Ranges) != 2 {
		t.Fatalf("update touched other fields: %#v", records[0])
	}

	untouched, err := st.GetVulnerability(ctx, "CVE-2024-0031")
	if err != nil {
		t.Fatalf("get untouched: %v", err)
	}
	if untouched.Status != vuln.StatusOpen {
		t.Fatalf("unlisted record changed: %#v", untouched)
	}
}

func TestUpdateStatusesUnknownIDRollsBack(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	mustCreateSample(t, st, "CVE-2024-0033")

	updates := []StatusUpdate{
		{ID: "CVE-2024-0033", Status: vuln.StatusFixed},
		{ID: "CVE-9999-0000", Status: vuln.StatusOpen},
	}
	if _, err := st.UpdateStatuses(ctx, updates); !errors.Is(err, ErrVulnerabilityNotFound) {
		t.Fatalf("unknown id: %v, want ErrVulnerabilityNotFound", err)
	}

	stored, err := st.GetVulnerability(ctx, "CVE-2024-0033")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if stored.Status != vuln.StatusOpen {
		t.Fatalf("failed batch must not change anything: %#v", stored)
	}
}
