package vuln

import (
	"errors"
	"testing"

	"github.com/luwa07832/vuln-registry/internal/version"
)

func strp(s string) *string { return &s }

func TestRegisterInputValidateAcceptsFullRecord(t *testing.T) {
	input := RegisterInput{
		ID:        strp("CVE-2026-0001"),
		Component: strp("libdemo"),
		Ranges: &[]Range{
			{Lower: strp("1.0.0"), LowerInclusive: true, Upper: strp("1.2.0"), UpperInclusive: false},
			{Upper: strp("0.9"), UpperInclusive: true},
			{Lower: strp("2.0"), LowerInclusive: false},
			{},
		},
		Severity: strp("high"),
		Fixed:    strp("1.2.0"),
		Status:   strp("open"),
	}
	record, err := input.Validate()
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if record.ID != "CVE-2026-0001" || len(record.Ranges) != 4 {
		t.Fatalf("unexpected record: %+v", record)
	}
}

func TestRegisterInputValidateRejectsMissingFields(t *testing.T) {
	valid := func() RegisterInput {
		return RegisterInput{
			ID:        strp("CVE-1"),
			Component: strp("libdemo"),
			Ranges:    &[]Range{{Lower: strp("1.0"), LowerInclusive: true}},
			Severity:  strp("low"),
			Fixed:     strp("1.1"),
			Status:    strp("open"),
		}
	}
	mutators := map[string]func(*RegisterInput){
		"missing id":     func(in *RegisterInput) { in.ID = nil },
		"empty id":       func(in *RegisterInput) { in.ID = strp("") },
		"missing comp":   func(in *RegisterInput) { in.Component = nil },
		"empty comp":     func(in *RegisterInput) { in.Component = strp("") },
		"missing ranges": func(in *RegisterInput) { in.Ranges = nil },
		"empty ranges":   func(in *RegisterInput) { in.Ranges = &[]Range{} },
		"missing sev":    func(in *RegisterInput) { in.Severity = nil },
		"bad severity":   func(in *RegisterInput) { in.Severity = strp("urgent") },
		"missing fixed":  func(in *RegisterInput) { in.Fixed = nil },
		"bad fixed":      func(in *RegisterInput) { in.Fixed = strp("nope") },
		"missing status": func(in *RegisterInput) { in.Status = nil },
		"bad status":     func(in *RegisterInput) { in.Status = strp("done") },
		"bad lower":      func(in *RegisterInput) { in.Ranges = &[]Range{{Lower: strp("x"), LowerInclusive: true}} },
		"bad upper":      func(in *RegisterInput) { in.Ranges = &[]Range{{Upper: strp("1.x")}} },
		"reversed bounds": func(in *RegisterInput) {
			in.Ranges = &[]Range{{Lower: strp("2.0"), LowerInclusive: true, Upper: strp("1.0"), UpperInclusive: true}}
		},
	}
	for name, mutate := range mutators {
		input := valid()
		mutate(&input)
		if _, err := input.Validate(); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%s: err = %v, want ErrInvalidInput", name, err)
		}
	}
}

func TestValidateAllowsEqualBoundsAndOpenBounds(t *testing.T) {
	input := RegisterInput{
		ID:        strp("CVE-2"),
		Component: strp("libdemo"),
		Ranges: &[]Range{
			{Lower: strp("1.0"), LowerInclusive: true, Upper: strp("1.0"), UpperInclusive: true},
			{},
		},
		Severity: strp("critical"),
		Fixed:    strp("2.0"),
		Status:   strp("fixed"),
	}
	if _, err := input.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestContainsRespectsBoundInclusion(t *testing.T) {
	parse := func(s string) version.Version {
		v, err := version.Parse(s)
		if err != nil {
			t.Fatalf("Parse(%s): %v", s, err)
		}
		return v
	}
	affected := Range{Lower: strp("1.0"), LowerInclusive: false, Upper: strp("2.0"), UpperInclusive: true}
	if affected.Contains(parse("1.0")) {
		t.Fatal("exclusive lower bound must not be included")
	}
	if !affected.Contains(parse("1.0.1")) {
		t.Fatal("interior version must be included")
	}
	if !affected.Contains(parse("2.0")) {
		t.Fatal("inclusive upper bound must be included")
	}
	if affected.Contains(parse("2.0.1")) {
		t.Fatal("version above upper bound must not be included")
	}

	openLower := Range{Upper: strp("1.0"), UpperInclusive: false}
	if !openLower.Contains(parse("0.9.9")) || openLower.Contains(parse("1.0")) {
		t.Fatal("open-lower range membership wrong")
	}
	fullyOpen := Range{}
	if !fullyOpen.Contains(parse("999.999")) {
		t.Fatal("fully open range must contain every version")
	}
}

func TestMatchReturnsOnlyHitRangesAndIsNilOnMiss(t *testing.T) {
	record := &Vulnerability{
		ID:        "CVE-3",
		Component: "libdemo",
		Ranges: []Range{
			{Lower: strp("1.0"), LowerInclusive: true, Upper: strp("1.5"), UpperInclusive: true},
			{Lower: strp("2.0"), LowerInclusive: true, Upper: strp("2.5"), UpperInclusive: true},
		},
		Severity: "medium",
		Fixed:    "2.5",
		Status:   "ignored",
	}
	target, _ := version.Parse("2.1")
	hit := record.Match(target)
	if hit == nil {
		t.Fatal("expected a match")
	}
	if len(hit.MatchedRanges) != 1 || hit.MatchedRanges[0].Lower == nil || *hit.MatchedRanges[0].Lower != "2.0" {
		t.Fatalf("unexpected matched ranges: %+v", hit.MatchedRanges)
	}
	if record.Match(mustParse(t, "3.0")) != nil {
		t.Fatal("version outside every range must not match")
	}
}

func mustParse(t *testing.T, text string) version.Version {
	t.Helper()
	v, err := version.Parse(text)
	if err != nil {
		t.Fatalf("Parse(%s): %v", text, err)
	}
	return v
}
