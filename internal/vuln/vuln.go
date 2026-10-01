// Package vuln owns the vulnerability domain model, the allowed severity and
// disposition status sets, input validation and affected-range matching.
package vuln

import (
	"errors"

	"github.com/luwa07832/vuln-registry/internal/version"
)

var ErrInvalidInput = errors.New("invalid input")

var severities = map[string]bool{
	"low":      true,
	"medium":   true,
	"high":     true,
	"critical": true,
}

var statuses = map[string]bool{
	"open":        true,
	"in_progress": true,
	"fixed":       true,
	"ignored":     true,
}

// ValidSeverity reports whether severity is in the allowed set.
func ValidSeverity(severity string) bool { return severities[severity] }

// ValidStatus reports whether status is in the allowed disposition set.
func ValidStatus(status string) bool { return statuses[status] }

// Range is one affected version interval. A nil boundary means the bound is
// open; otherwise the boundary is taken when Inclusive is true.
type Range struct {
	Lower          *string `json:"lower"`
	LowerInclusive bool    `json:"lowerInclusive"`
	Upper          *string `json:"upper"`
	UpperInclusive bool    `json:"upperInclusive"`
}

// Vulnerability is one registered record.
type Vulnerability struct {
	ID        string  `json:"id"`
	Component string  `json:"component"`
	Ranges    []Range `json:"ranges"`
	Severity  string  `json:"severity"`
	Fixed     string  `json:"fixedVersion"`
	Status    string  `json:"status"`
}

// RegisterInput is the registration request body. Pointer scalar fields let
// validation distinguish a missing field from an empty value.
type RegisterInput struct {
	ID        *string  `json:"id"`
	Component *string  `json:"component"`
	Ranges    *[]Range `json:"ranges"`
	Severity  *string  `json:"severity"`
	Fixed     *string  `json:"fixedVersion"`
	Status    *string  `json:"status"`
}

// Validate converts a registration request into a record or returns
// ErrInvalidInput. No partial value is produced on failure.
func (in RegisterInput) Validate() (*Vulnerability, error) {
	if in.ID == nil || *in.ID == "" ||
		in.Component == nil || *in.Component == "" ||
		in.Ranges == nil ||
		in.Severity == nil ||
		in.Fixed == nil ||
		in.Status == nil {
		return nil, ErrInvalidInput
	}
	if !ValidSeverity(*in.Severity) || !ValidStatus(*in.Status) {
		return nil, ErrInvalidInput
	}
	if _, err := version.Parse(*in.Fixed); err != nil {
		return nil, ErrInvalidInput
	}
	if len(*in.Ranges) == 0 {
		return nil, ErrInvalidInput
	}
	ranges := make([]Range, 0, len(*in.Ranges))
	for _, inputRange := range *in.Ranges {
		parsed, err := validateRange(inputRange)
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, parsed)
	}
	return &Vulnerability{
		ID:        *in.ID,
		Component: *in.Component,
		Ranges:    ranges,
		Severity:  *in.Severity,
		Fixed:     *in.Fixed,
		Status:    *in.Status,
	}, nil
}

func validateRange(input Range) (Range, error) {
	result := Range{
		LowerInclusive: input.LowerInclusive,
		UpperInclusive: input.UpperInclusive,
	}
	var lower, upper *version.Version
	if input.Lower != nil {
		parsed, err := version.Parse(*input.Lower)
		if err != nil {
			return Range{}, ErrInvalidInput
		}
		lower = &parsed
		value := parsed.String()
		result.Lower = &value
	} else {
		result.LowerInclusive = false
	}
	if input.Upper != nil {
		parsed, err := version.Parse(*input.Upper)
		if err != nil {
			return Range{}, ErrInvalidInput
		}
		upper = &parsed
		value := parsed.String()
		result.Upper = &value
	} else {
		result.UpperInclusive = false
	}
	if lower != nil && upper != nil && lower.Compare(*upper) > 0 {
		return Range{}, ErrInvalidInput
	}
	return result, nil
}

// Contains reports whether version falls inside affectedRange.
func (affected Range) Contains(target version.Version) bool {
	if affected.Lower != nil {
		lower, err := version.Parse(*affected.Lower)
		if err != nil {
			return false
		}
		if affected.LowerInclusive {
			if target.Compare(lower) < 0 {
				return false
			}

		} else if target.Compare(lower) <= 0 {
			return false
		}
	}
	if affected.Upper != nil {
		upper, err := version.Parse(*affected.Upper)
		if err != nil {
			return false
		}
		if affected.UpperInclusive {
			if target.Compare(upper) > 0 {
				return false
			}
		} else if target.Compare(upper) >= 0 {
			return false
		}
	}
	return true
}

// Match is one query hit: the full record plus the ranges the queried
// version landed in, preserving registration order.
type Match struct {
	ID            string  `json:"id"`
	Component     string  `json:"component"`
	MatchedRanges []Range `json:"matchedRanges"`
	Severity      string  `json:"severity"`
	Fixed         string  `json:"fixedVersion"`
	Status        string  `json:"status"`
}

// Match returns a hit when target is in any of the record's affected ranges;
// nil means the record is not affected by the query.
func (v *Vulnerability) Match(target version.Version) *Match {
	hits := make([]Range, 0)
	for _, affected := range v.Ranges {
		if affected.Contains(target) {
			hits = append(hits, affected)
		}
	}
	if len(hits) == 0 {
		return nil
	}
	return &Match{
		ID:            v.ID,
		Component:     v.Component,
		MatchedRanges: hits,
		Severity:      v.Severity,
		Fixed:         v.Fixed,
		Status:        v.Status,
	}
}
