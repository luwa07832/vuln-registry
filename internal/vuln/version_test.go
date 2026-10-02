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

func TestNewIntervalQueryValidatesBounds(t *testing.T) {
	if query, err := NewIntervalQuery("1.0", "1.0.0", true, true); err != nil || query.Lower.Compare(query.Upper) != 0 {
		t.Fatalf("equal numeric bounds should be legal: %v %v", query, err)
	}
	bad := []struct {
		lower, upper string
		lowerInclude bool
		upperInclude bool
	}{
		{"", "1.0", true, true},
		{"1.x", "1.0", true, true},
		{"1.0", "", true, true},
		{"2.0", "1.0", true, true},
		{"1.0", "1.0", false, true},
		{"1.0", "1.0", true, false},
	}
	for _, tc := range bad {
		if _, err := NewIntervalQuery(tc.lower, tc.upper, tc.lowerInclude, tc.upperInclude); err == nil {
			t.Fatalf("NewIntervalQuery(%+v) succeeded, want error", tc)
		}
	}
}

func TestMatchedRangesInIntervalSemantics(t *testing.T) {
	record := &Vulnerability{Ranges: []Range{
		{Lower: ptrText("1.0"), LowerInclude: ptrBool(false), Upper: ptrText("2.0"), UpperInclude: ptrBool(true)},
		{Upper: ptrText("3.0"), UpperInclude: ptrBool(false)},
		{Lower: ptrText("4.0"), LowerInclude: ptrBool(true)},
	}}
	if err := record.PrepareRanges(); err != nil {
		t.Fatalf("prepare: %v", err)
	}

	query := func(lower, upper string, lowerInclude, upperInclude bool) IntervalQuery {
		parsed, err := NewIntervalQuery(lower, upper, lowerInclude, upperInclude)
		if err != nil {
			t.Fatalf("query %s..%s: %v", lower, upper, err)
		}
		return parsed
	}
	indices := func(matched []Range) []int {
		got := []int{}
		for _, hit := range matched {
			for index, candidate := range record.Ranges {
				if candidate == hit {
					got = append(got, index)
				}
			}
		}
		return got
	}

	cases := []struct {
		name           string
		query          IntervalQuery
		wantRangeIndex []int
	}{
		{"open overlap below excluded lower", query("0", "1.0", true, true), []int{1}},
		{"shared included upper endpoint", query("2.0", "2.5", true, true), []int{0, 1}},
		{"query excludes shared endpoint", query("2.0", "2.5", false, true), []int{1}},
		{"gap between exclusive endpoints", query("3.0", "3.5", true, true), nil},
		{"shared included lower endpoint", query("3.5", "4.0", true, true), []int{2}},
		{"range excludes shared upper endpoint", query("3.5", "3.9", true, true), nil},
		{"open upper side extends forever", query("5.0", "6.0", true, true), []int{2}},
		{"wide query covers everything", query("0", "9.0", true, false), []int{0, 1, 2}},
	}
	for _, tc := range cases {
		got := indices(record.MatchedRangesInInterval(tc.query))
		if len(got) != len(tc.wantRangeIndex) {
			t.Fatalf("%s: matched indices %v, want %v", tc.name, got, tc.wantRangeIndex)
		}
		for index := range got {
			if got[index] != tc.wantRangeIndex[index] {
				t.Fatalf("%s: matched indices %v, want %v", tc.name, got, tc.wantRangeIndex)
			}
		}
	}
}
