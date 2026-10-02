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

// IntervalQuery is a finite, closed-or-open version interval supplied by a
// range-match request. Both bounds are present; the include flags state
// whether each endpoint belongs to the interval.
type IntervalQuery struct {
	Lower        Version
	Upper        Version
	LowerInclude bool
	UpperInclude bool
}

// NewIntervalQuery parses and validates one finite interval: both bounds must
// be legal versions, lower must not exceed upper, and equal bounds require
// both ends to be inclusive.
func NewIntervalQuery(lowerText, upperText string, lowerInclude, upperInclude bool) (IntervalQuery, error) {
	lower, err := ParseVersion(lowerText)
	if err != nil {
		return IntervalQuery{}, err
	}
	upper, err := ParseVersion(upperText)
	if err != nil {
		return IntervalQuery{}, err
	}
	switch lower.Compare(upper) {
	case 1:
		return IntervalQuery{}, errInvalidVersion
	case 0:
		if !lowerInclude || !upperInclude {
			return IntervalQuery{}, errInvalidVersion
		}
	}
	return IntervalQuery{
		Lower:        lower,
		Upper:        upper,
		LowerInclude: lowerInclude,
		UpperInclude: upperInclude,
	}, nil
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

// MatchedRangesInInterval returns the affected ranges that share at least one
// legal version with query, preserving registration order. A registered open
// bound is treated as unbounded; ranges only touch at a shared endpoint when
// both sides include it. Ranges must have been prepared first.
func (v *Vulnerability) MatchedRangesInInterval(query IntervalQuery) []Range {
	matched := []Range{}
	for index, affected := range v.Ranges {
		if text := affected.LowerText(); text != "" {
			compare := v.lowerParsed[index].Compare(query.Upper)
			if compare > 0 || (compare == 0 && (!*affected.LowerInclude || !query.UpperInclude)) {
				continue
			}
		}
		if text := affected.UpperText(); text != "" {
			compare := query.Lower.Compare(v.upperParsed[index])
			if compare > 0 || (compare == 0 && (!query.LowerInclude || !*affected.UpperInclude)) {
				continue
			}
		}
		matched = append(matched, affected)
	}
	return matched
}
