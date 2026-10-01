// Package version defines the public version ordering used by this service:
// versions split into dot-separated numeric segments, compared from left to
// right, and missing segments compare as 0. Only dotted numeric versions are
// valid; anything else is invalid input.
package version

import (
	"errors"
	"strconv"
	"strings"
)

var ErrInvalidVersion = errors.New("invalid version")

// Version is a parsed dotted numeric version.
type Version struct {
	text     string
	segments []uint64
}

// Parse validates and parses a version string.
func Parse(text string) (Version, error) {
	if text == "" {
		return Version{}, ErrInvalidVersion
	}
	parts := strings.Split(text, ".")
	segments := make([]uint64, len(parts))
	for index, part := range parts {
		if part == "" {
			return Version{}, ErrInvalidVersion
		}
		value, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return Version{}, ErrInvalidVersion
		}
		segments[index] = value
	}
	return Version{text: text, segments: segments}, nil
}

// String returns the canonical representation, which equals the accepted input.
func (v Version) String() string { return v.text }

// Compare returns -1, 0 or 1 when v is below, equal to or above other. Missing
// segments on either side compare as 0.
func (v Version) Compare(other Version) int {
	length := len(v.segments)
	if len(other.segments) > length {
		length = len(other.segments)
	}
	for index := 0; index < length; index++ {
		var left, right uint64
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

// Less reports whether v sorts before other.
func (v Version) Less(other Version) bool { return v.Compare(other) < 0 }
