package vuln

// Severity is the impact level assigned to a vulnerability.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Status is the disposition state of a vulnerability.
type Status string

const (
	StatusOpen       Status = "open"
	StatusInProgress Status = "in_progress"
	StatusFixed      Status = "fixed"
	StatusWontFix    Status = "wont_fix"
	StatusAccepted   Status = "accepted"
)

// Severities lists every severity accepted on registration.
var Severities = []Severity{
	SeverityLow,
	SeverityMedium,
	SeverityHigh,
	SeverityCritical,
}

// Statuses lists every disposition status accepted on registration and update.
var Statuses = []Status{
	StatusOpen,
	StatusInProgress,
	StatusFixed,
	StatusWontFix,
	StatusAccepted,
}

// ValidSeverity reports whether severity is one of the published values.
func ValidSeverity(severity Severity) bool {
	for _, candidate := range Severities {
		if severity == candidate {
			return true
		}
	}
	return false
}

// ValidStatus reports whether status is one of the published values.
func ValidStatus(status Status) bool {
	for _, candidate := range Statuses {
		if status == candidate {
			return true
		}
	}
	return false
}

// Range is one affected-version interval. A null lower or upper bound means
// the interval is open on that side. The include flags state explicitly
// whether a present bound is inclusive.
type Range struct {
	Lower        *string `json:"lower"`
	LowerInclude *bool   `json:"lower_include"`
	Upper        *string `json:"upper"`
	UpperInclude *bool   `json:"upper_include"`
}

// LowerText returns the lower bound or "" when the side is open.
func (r Range) LowerText() string {
	if r.Lower == nil {
		return ""
	}
	return *r.Lower
}

// UpperText returns the upper bound or "" when the side is open.
func (r Range) UpperText() string {
	if r.Upper == nil {
		return ""
	}
	return *r.Upper
}

// Vulnerability is the full stored record returned by create, update and
// affected-lookup entries.
type Vulnerability struct {
	ID           string    `json:"id"`
	Component    string    `json:"component"`
	Ranges       []Range   `json:"affected_ranges"`
	Severity     Severity  `json:"severity"`
	FixedVersion string    `json:"fixed_version"`
	Status       Status    `json:"status"`
	lowerParsed  []Version `json:"-"`
	upperParsed  []Version `json:"-"`
}

// PrepareRanges parses every bound and rejects malformed versions or inverted
// intervals. On success the parsed bounds are cached for Contains and
// MatchedRanges. Stored records are already valid, so the same call prepares
// them for matching without risk.
func (v *Vulnerability) PrepareRanges() error {
	count := len(v.Ranges)
	if count == 0 {
		return errInvalidVersion
	}
	lowerParsed := make([]Version, count)
	upperParsed := make([]Version, count)
	for index, affected := range v.Ranges {
		if lower := affected.LowerText(); lower != "" {
			if affected.LowerInclude == nil {
				return errInvalidVersion
			}
			parsed, err := ParseVersion(lower)
			if err != nil {
				return err
			}
			lowerParsed[index] = parsed
		}
		if upper := affected.UpperText(); upper != "" {
			if affected.UpperInclude == nil {
				return errInvalidVersion
			}
			parsed, err := ParseVersion(upper)
			if err != nil {
				return err
			}
			upperParsed[index] = parsed
		}
		if lower, upper := affected.LowerText(), affected.UpperText(); lower != "" && upper != "" {
			switch lowerParsed[index].Compare(upperParsed[index]) {
			case 1:
				return errInvalidVersion
			case 0:
				if !*affected.LowerInclude || !*affected.UpperInclude {
					return errInvalidVersion
				}
			}
		}
	}
	v.lowerParsed = lowerParsed
	v.upperParsed = upperParsed
	return nil
}

// Contains reports whether version lies in the union of affected ranges.
// Ranges must have been prepared first.
func (v *Vulnerability) Contains(version Version) bool {
	return len(v.MatchedRanges(version)) > 0
}

// MatchedRanges returns the affected ranges that contain version, preserving
// registration order.
func (v *Vulnerability) MatchedRanges(version Version) []Range {
	matched := []Range{}
	for index, affected := range v.Ranges {
		if lower := affected.LowerText(); lower != "" {
			compare := v.lowerParsed[index].Compare(version)
			if compare > 0 || (compare == 0 && !*affected.LowerInclude) {
				continue
			}
		}
		if upper := affected.UpperText(); upper != "" {
			compare := version.Compare(v.upperParsed[index])
			if compare > 0 || (compare == 0 && !*affected.UpperInclude) {
				continue
			}
		}
		matched = append(matched, affected)
	}
	return matched
}

// IntersectingRanges returns the affected ranges that share at least one
// legal version with the closed-or-half-open interval described by the
// given finite bounds, preserving registration order. Ranges must have been
// prepared first. Open registered bounds act as unbounded, and intervals
// meeting only at a shared endpoint intersect only when both sides include
// that endpoint.
func (v *Vulnerability) IntersectingRanges(lower, upper Version, lowerInclude, upperInclude bool) []Range {
	matched := []Range{}
	for index, affected := range v.Ranges {
		if affected.Lower != nil {
			compare := v.lowerParsed[index].Compare(upper)
			if compare > 0 || (compare == 0 && (!*affected.LowerInclude || !upperInclude)) {
				continue
			}
		}
		if affected.Upper != nil {
			compare := lower.Compare(v.upperParsed[index])
			if compare > 0 || (compare == 0 && (!lowerInclude || !*affected.UpperInclude)) {
				continue
			}
		}
		matched = append(matched, affected)
	}
	return matched
}
