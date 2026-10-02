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

	first := sampleVulnerability("CVE-2024-0001")
	first.PrepareRanges()
	if err := st.CreateVulnerability(ctx, first); err != nil {
		t.Fatalf("seed: %v", err)
	}

	second := sampleVulnerability("CVE-2024-0002")
	third := sampleVulnerability("CVE-2024-0003")
	if err := second.PrepareRanges(); err != nil {
		t.Fatalf("prepare second: %v", err)
	}
	if err := third.PrepareRanges(); err != nil {
		t.Fatalf("prepare third: %v", err)
	}
	if err := st.CreateVulnerabilities(ctx, []*vuln.Vulnerability{second, third}); err != nil {
		t.Fatalf("batch create: %v", err)
	}
	for _, id := range []string{"CVE-2024-0002", "CVE-2024-0003"} {
		if _, err := st.GetVulnerability(ctx, id); err != nil {
			t.Fatalf("get %s: %v", id, err)
		}
	}
}

func TestCreateVulnerabilitiesBatchDuplicateRollsBack(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	seed := sampleVulnerability("CVE-EXISTING")
	seed.PrepareRanges()
	if err := st.CreateVulnerability(ctx, seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	fresh := sampleVulnerability("CVE-FRESH")
	duplicate := sampleVulnerability("CVE-EXISTING")
	after := sampleVulnerability("CVE-AFTER")
	for index, record := range []*vuln.Vulnerability{fresh, duplicate, after} {
		if err := record.PrepareRanges(); err != nil {
			t.Fatalf("prepare %d: %v", index, err)
		}
	}
	err := st.CreateVulnerabilities(ctx, []*vuln.Vulnerability{fresh, duplicate, after})
	if !errors.Is(err, ErrDuplicateVulnerability) {
		t.Fatalf("err = %v, want ErrDuplicateVulnerability", err)
	}
	for _, id := range []string{"CVE-FRESH", "CVE-AFTER"} {
		if _, err := st.GetVulnerability(ctx, id); !errors.Is(err, ErrVulnerabilityNotFound) {
			t.Fatalf("%s must not survive the rollback: %v", id, err)
		}
	}
}
