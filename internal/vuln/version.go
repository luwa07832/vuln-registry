// Package vuln owns the vulnerability domain model: version parsing, ordering
// and affected-range matching rules shared by the API and storage layers.
package vuln

import (
	"errors"
	"strconv"
	"strings"
)

// Version is a dotted numeric version, e.g. "1.2.3". Segments are compared
// numerically from left to right; a missing segment compares as 0.
type Version struct {
	segments []int64
	text     string
}

var errInvalidVersion = errors.New("invalid version")

// ParseVersion validates and parses version. A legal version is a non-empty
// dot-separated sequence of non-empty decimal segments, for example "1",
// "1.0.3" or "10.2.0". Every segment must consist of decimal digits only.
func ParseVersion(version string) (Version, error) {
	if version == "" {
		return Version{}, errInvalidVersion
	}
	parts := strings.Split(version, ".")
	segments := make([]int64, len(parts))
	for index, part := range parts {
		if part == "" {
			return Version{}, errInvalidVersion
		}
		value, err := strconv.ParseInt(part, 10, 64)
		if err != nil || value < 0 {
			return Version{}, errInvalidVersion
		}
		segments[index] = value
	}
	return Version{segments: segments, text: version}, nil
}

// String returns the canonical text the version was parsed from.
func (v Version) String() string { return v.text }

// Compare returns -1, 0 or 1 when v is lower than, equal to or higher than
// other. Missing trailing segments compare as 0, so "1" == "1.0" == "1.0.0".
func (v Version) Compare(other Version) int {
	count := len(v.segments)
	if len(other.segments) > count {
		count = len(other.segments)
	}
	for index := 0; index < count; index++ {
		left, right := int64(0), int64(0)
		if index < len(v.segments) {
			left = v.segments[index]
		}
		if index < len(other.segments) {
			right = other.segments[index]
		}
		switch {
		case left < right:
			return -1
		case left > right:
			return 1
		}
	}
	return 0
}
