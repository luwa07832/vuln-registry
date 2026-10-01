package version

import "testing"

func TestParseRejectsInvalidVersions(t *testing.T) {
	for _, text := range []string{"", "1.", ".1", "1..2", "abc", "1.2.x", "v1.2", "1.0-beta"} {
		if _, err := Parse(text); err == nil {
			t.Fatalf("Parse(%q) succeeded, want error", text)
		}
	}
}

func TestCompareFollowsDottedNumericOrder(t *testing.T) {
	cases := []struct {
		left     string
		right    string
		expected int
	}{
		{"1", "1", 0},
		{"1", "1.0", 0},
		{"1.0.0", "1.0.0.0", 0},
		{"1.2", "1.10", -1},
		{"1.10", "1.9", 1},
		{"2.0", "1.99.99", 1},
		{"1.0.1", "1.0.0", 1},
		{"01.002", "1.2", 0},
	}
	for _, tc := range cases {
		left, err := Parse(tc.left)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.left, err)
		}
		right, err := Parse(tc.right)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.right, err)
		}
		if got := left.Compare(right); got != tc.expected {
			t.Fatalf("Compare(%q, %q) = %d, want %d", tc.left, tc.right, got, tc.expected)
		}
	}
}

func TestStringRoundTripsInput(t *testing.T) {
	parsed, err := Parse("1.02.3")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.String() != "1.02.3" {
		t.Fatalf("String() = %q", parsed.String())
	}
}
