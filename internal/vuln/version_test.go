package vuln

import "testing"

func TestParseVersionRejectsIllegalInput(t *testing.T) {
	for _, value := range []string{"", "1.", ".1", "1..2", "1.a", "v1", "-1", "1.2.x", "01-2"} {
		if _, err := ParseVersion(value); err == nil {
			t.Fatalf("ParseVersion(%q) succeeded, want error", value)
		}
	}
}

func TestParseVersionAcceptsLegalInput(t *testing.T) {
	for _, value := range []string{"0", "1", "1.0", "10.2.3", "1.0.0.0"} {
		if parsed, err := ParseVersion(value); err != nil || parsed.String() != value {
			t.Fatalf("ParseVersion(%q) = %v, %v", value, parsed, err)
		}
	}
}

func TestCompareUsesNumericSegmentsAndMissingZero(t *testing.T) {
	cases := []struct {
		left, right string
		want        int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"1.2", "1.10", -1},
		{"2.0", "10.0", -1},
		{"1.10.2", "1.10.1", 1},
		{"0.9", "1.0", -1},
	}
	for _, tc := range cases {
		left := mustParse(t, tc.left)
		right := mustParse(t, tc.right)
		if got := left.Compare(right); got != tc.want {
			t.Fatalf("Compare(%q,%q) = %d, want %d", tc.left, tc.right, got, tc.want)
		}
	}
}

func ptrBool(v bool) *bool     { return &v }
func ptrText(v string) *string { return &v }

func TestPrepareRangesRejectsIllegalRanges(t *testing.T) {
	validSeverityStatus := func(v *Vulnerability) {
		v.Severity = SeverityHigh
		v.Status = StatusOpen
	}

	oneZeroOne := []Range{{Lower: ptrText("1.0"), LowerInclude: ptrBool(true),
		Upper: ptrText("1.1"), UpperInclude: ptrBool(false)}}

	bad := []*Vulnerability{
		{ID: "x", Ranges: nil},
		{ID: "x", Ranges: []Range{{Lower: ptrText("1..0"), LowerInclude: ptrBool(true)}}},
		{ID: "x", Ranges: []Range{{Lower: ptrText("1.2"), LowerInclude: ptrBool(true),
			Upper: ptrText("1.1"), UpperInclude: ptrBool(true)}}},
		{ID: "x", Ranges: []Range{{Lower: ptrText("1.0"), // missing include flag
			Upper: ptrText("1.1"), UpperInclude: ptrBool(true)}}},
		{ID: "x", Ranges: []Range{{Lower: ptrText("1.0"), LowerInclude: ptrBool(true), // missing upper flag
			Upper: ptrText("1.1")}}},
		// Equal bounds with either side exclusive describe an empty interval.
		{ID: "x", Ranges: []Range{{Lower: ptrText("1.0"), LowerInclude: ptrBool(false),
			Upper: ptrText("1.0"), UpperInclude: ptrBool(true)}}},
	}
	for _, record := range bad {
		validSeverityStatus(record)
		if err := record.PrepareRanges(); err == nil {
			t.Fatalf("PrepareRanges succeeded for %#v", record.Ranges)
		}
	}

	good := &Vulnerability{ID: "x", Ranges: oneZeroOne}
	validSeverityStatus(good)
	if err := good.PrepareRanges(); err != nil {
		t.Fatalf("PrepareRanges: %v", err)
	}
	// Equal inclusive bounds describe a single version.
	single := &Vulnerability{Ranges: []Range{{Lower: ptrText("1.0"), LowerInclude: ptrBool(true),
		Upper: ptrText("1.0"), UpperInclude: ptrBool(true)}}}
	if err := single.PrepareRanges(); err != nil {
		t.Fatalf("equal inclusive bounds: %v", err)
	}
}

func TestContainsHonorsBoundsAndUnion(t *testing.T) {
	record := &Vulnerability{Ranges: []Range{
		{Lower: ptrText("1.0"), LowerInclude: ptrBool(false), Upper: ptrText("2.0"), UpperInclude: ptrBool(true)},
		{Lower: ptrText("3.1"), LowerInclude: ptrBool(true)},
	}}
	if err := record.PrepareRanges(); err != nil {
		t.Fatalf("prepare: %v", err)
	}

	cases := map[string]bool{
		"1.0":   false, // lower excluded
		"1.0.1": true,
		"2.0":   true, // upper included
		"2.5":   false,
		"3.0.9": false,
		"3.1":   true, // lower included, open upper
		"9.9":   true,
	}
	for version, want := range cases {
		parsed := mustParse(t, version)
		if got := record.Contains(parsed); got != want {
			t.Fatalf("Contains(%q) = %v, want %v", version, got, want)
		}
	}
}

func TestMatchedRangesReturnsOnlyHits(t *testing.T) {
	record := &Vulnerability{Ranges: []Range{
		{Upper: ptrText("1.0"), UpperInclude: ptrBool(false)},
		{Lower: ptrText("2.0"), LowerInclude: ptrBool(true), Upper: ptrText("2.0"), UpperInclude: ptrBool(true)},
	}}
	if err := record.PrepareRanges(); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if matched := record.MatchedRanges(mustParse(t, "0.9")); len(matched) != 1 || matched[0].Lower != nil {
		t.Fatalf("0.9 matched %#v, want only open-lower range", matched)
	}
	if matched := record.MatchedRanges(mustParse(t, "2.0.0")); len(matched) != 1 || matched[0].Lower == nil {
		t.Fatalf("2.0 matched %#v, want only second range", matched)
	}
	if matched := record.MatchedRanges(mustParse(t, "1.5")); len(matched) != 0 {
		t.Fatalf("1.5 matched %#v, want none", matched)
	}
}

func mustParse(t *testing.T, value string) Version {
	t.Helper()
	parsed, err := ParseVersion(value)
	if err != nil {
		t.Fatalf("ParseVersion(%q): %v", value, err)
	}
	return parsed
}

func TestIntersectingRanges(t *testing.T) {
	record := &Vulnerability{Ranges: []Range{
		// open lower, exclusive upper 2.0
		{Upper: ptrText("2.0"), UpperInclude: ptrBool(false)},
		// inclusive 3.0 to inclusive 4.0
		{Lower: ptrText("3.0"), LowerInclude: ptrBool(true), Upper: ptrText("4.0"), UpperInclude: ptrBool(true)},
		// inclusive lower 5.0, open upper
		{Lower: ptrText("5.0"), LowerInclude: ptrBool(true)},
	}}
	if err := record.PrepareRanges(); err != nil {
		t.Fatalf("prepare: %v", err)
	}

	match := func(lower, upper string, lowerInclude, upperInclude bool) []Range {
		return record.IntersectingRanges(mustParse(t, lower), mustParse(t, upper), lowerInclude, upperInclude)
	}

	if matched := match("1.0", "1.5", true, true); len(matched) != 1 || matched[0].Lower != nil {
		t.Fatalf("1.0..1.5 matched %#v, want only open-lower range", matched)
	}
	// Query touching the exclusive registered upper only at 2.0 must not hit.
	if matched := match("2.0", "2.5", true, true); len(matched) != 0 {
		t.Fatalf("2.0..2.5 matched %#v, want none at excluded endpoint", matched)
	}
	// An exclusive query bound at a shared included registered endpoint misses
	// when that endpoint is the only common version; an overlap below an
	// excluded registered upper still intersects.
	if matched := match("4.0", "4.5", false, true); len(matched) != 0 {
		t.Fatalf("(4.0..4.5] matched %#v, want none at excluded query endpoint", matched)
	}
	if matched := match("1.5", "2.0", true, false); len(matched) != 1 {
		t.Fatalf("1.5..<2.0 matched %#v, want shared interior overlap", matched)
	}
	// Gap between 2.0 (exclusive) and 3.0 yields no shared version.
	if matched := match("2.0", "2.5", false, true); len(matched) != 0 {
		t.Fatalf("(2.0..2.5] matched %#v, want none in gap", matched)
	}
	// Shared inclusive endpoint 3.0 intersects when both include it.
	if matched := match("2.5", "3.0", true, true); len(matched) != 1 || matched[0].Lower == nil {
		t.Fatalf("2.5..3.0 matched %#v, want only inclusive range", matched)
	}
	// Query inside the bounded range intersects only that range.
	if matched := match("3.5", "3.8", false, false); len(matched) != 1 || matched[0].Lower == nil {
		t.Fatalf("3.5..3.8 matched %#v, want only bounded range", matched)
	}
	// A wide query overlaps every registered range.
	if matched := match("1.0", "9.0", true, true); len(matched) != 3 {
		t.Fatalf("1.0..9.0 matched %d ranges, want 3", len(matched))
	}
	// Single-version queries at included and excluded endpoints.
	if matched := match("4.0", "4.0", true, true); len(matched) != 1 {
		t.Fatalf("[4.0] matched %#v, want bounded range", matched)
	}
	if matched := match("5.0", "5.0", true, true); len(matched) != 1 {
		t.Fatalf("[5.0] matched %#v, want open-upper range", matched)
	}
	if matched := match("4.5", "4.9", true, true); len(matched) != 0 {
		t.Fatalf("4.5..4.9 matched %#v, want none in gap", matched)
	}
}
