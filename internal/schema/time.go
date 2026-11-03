package schema

import (
	"strconv"
	"strings"
	"time"
)

// timeLayouts are tried in order by ParseTime. Layouts with zone information
// come first so that an explicit offset is honoured; zone-less layouts are
// interpreted as UTC.
var timeLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.999999999Z0700",
	"2006-01-02T15:04:05Z0700",
	"2006-01-02 15:04:05.999999999Z07:00",
	"2006-01-02 15:04:05Z07:00",
	"2006-01-02T15:04:05.999999999", // no zone -> UTC
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02 15:04:05",
	"02/Jan/2006:15:04:05 -0700",      // NCSA
	"Mon Jan _2 15:04:05 2006 MST",    // osquery calendarTime
	"Mon Jan _2 15:04:05 2006",        // osquery without zone
	"Jan _2 15:04:05 2006",            // syslog with year
	"Mon, 02 Jan 2006 15:04:05 MST",   // RFC 1123
	"Mon, 02 Jan 2006 15:04:05 -0700", // RFC 1123Z
	"2006/01/02 15:04:05",             // nginx error log
	"Mon Jan 02 15:04:05.000000 2006", // apache error log
	"Mon Jan 02 15:04:05 2006",        // apache error log (no micros)
	"01/02/2006 15:04:05",             // US
	"2006-01-02",                      // date only
	"20060102T150405Z",                // basic ISO
}

// ParseTime parses the formats Argus sources emit. Numeric strings are
// treated as epoch seconds, milliseconds, microseconds or nanoseconds by
// magnitude. The second return value is false when nothing matched.
func ParseTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return time.Time{}, false
	}
	if t, ok := parseEpoch(s); ok {
		return t, true
	}
	for _, layout := range timeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	// Windows "SystemTime" sometimes carries 7 fractional digits with a Z; RFC3339Nano handles it.
	// Syslog RFC 3164 without year: "Jan  2 15:04:05" -> assume current year (handled by caller).
	return time.Time{}, false
}

// ParseEpoch interprets a numeric string as an epoch by magnitude.
func parseEpoch(s string) (time.Time, bool) {
	if len(s) == 0 {
		return time.Time{}, false
	}
	for i, r := range s {
		if (r < '0' || r > '9') && r != '.' && !(i == 0 && r == '-') {
			return time.Time{}, false
		}
	}
	if strings.Contains(s, ".") {
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return time.Time{}, false
		}
		return EpochFloat(f), true
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return EpochInt(n), true
}

// EpochInt converts an integer epoch of unknown unit to a time by magnitude:
// seconds (< 1e11), milliseconds (< 1e14), microseconds (< 1e17), else nanoseconds.
func EpochInt(n int64) time.Time {
	abs := n
	if abs < 0 {
		abs = -abs
	}
	switch {
	case abs < 1e11:
		return time.Unix(n, 0).UTC()
	case abs < 1e14:
		return time.UnixMilli(n).UTC()
	case abs < 1e17:
		return time.UnixMicro(n).UTC()
	default:
		return time.Unix(0, n).UTC()
	}
}

// EpochFloat converts a fractional epoch (seconds, or ms/µs by magnitude).
func EpochFloat(f float64) time.Time {
	switch {
	case f < 1e11:
		sec := int64(f)
		nsec := int64((f - float64(sec)) * 1e9)
		return time.Unix(sec, nsec).UTC()
	case f < 1e14:
		return time.UnixMilli(int64(f)).UTC()
	case f < 1e17:
		return time.UnixMicro(int64(f)).UTC()
	default:
		return time.Unix(0, int64(f)).UTC()
	}
}

// ParseSyslogTime parses an RFC 3164 timestamp ("Jan  2 15:04:05") using
// reference to pick the year: the year of reference, or the previous year when
// the result would be more than 48 hours in the future (New Year rollover).
func ParseSyslogTime(s string, reference time.Time) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{"Jan _2 15:04:05.999999", "Jan _2 15:04:05", "Jan 02 15:04:05"} {
		t, err := time.Parse(layout, s)
		if err != nil {
			continue
		}
		ref := reference.UTC()
		if ref.IsZero() {
			ref = time.Now().UTC()
		}
		t = time.Date(ref.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.UTC)
		if t.After(ref.Add(48 * time.Hour)) {
			t = t.AddDate(-1, 0, 0)
		}
		return t, true
	}
	return time.Time{}, false
}

// Duration formats a duration as nanoseconds for event.duration.
func Duration(d time.Duration) int64 { return d.Nanoseconds() }

// SecondsToNanos converts a floating-point second count to nanoseconds.
func SecondsToNanos(sec float64) int64 { return int64(sec * 1e9) }
