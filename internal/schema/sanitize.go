package schema

import (
	"strings"
	"unicode/utf8"
)

// MaxFieldBytes is the cap applied to any single string field by Sanitize.
// Longer values are truncated and the field path recorded in
// argus.pipeline.truncated_fields (THREAT_MODEL T1.3, T2.2).
const MaxFieldBytes = 32 * 1024

// MaxOriginalBytes caps event.original separately so that very large raw
// payloads (CloudTrail records, Kubernetes request objects) are still stored.
const MaxOriginalBytes = 256 * 1024

// Sanitize strips C0 control characters (except tab) from every string field,
// repairs invalid UTF-8, and truncates oversize values. It is idempotent.
func Sanitize(e *Event) {
	var truncated []string
	for k, v := range e.m {
		limit := MaxFieldBytes
		if k == FieldEventOriginal {
			limit = MaxOriginalBytes
		}
		switch t := v.(type) {
		case string:
			s, cut := sanitizeString(t, limit)
			if cut {
				truncated = append(truncated, k)
			}
			if s == "" {
				delete(e.m, k)
			} else {
				e.m[k] = s
			}
		case []string:
			out := make([]string, 0, len(t))
			for _, item := range t {
				s, cut := sanitizeString(item, limit)
				if cut {
					truncated = append(truncated, k)
				}
				if s != "" {
					out = append(out, s)
				}
			}
			if len(out) == 0 {
				delete(e.m, k)
			} else {
				e.m[k] = out
			}
		}
	}
	if len(truncated) > 0 {
		e.Append(FieldTruncatedFields, truncated...)
	}
}

func sanitizeString(s string, limit int) (string, bool) {
	cut := false
	if len(s) > limit {
		s = s[:limit]
		// do not split a multi-byte rune
		for !utf8.ValidString(s) && len(s) > 0 {
			s = s[:len(s)-1]
		}
		cut = true
	}
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	if !hasControl(s) {
		return s, cut
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\t' || r >= 0x20 && r != 0x7f {
			b.WriteRune(r)
		}
	}
	return b.String(), cut
}

func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 && c != '\t' || c == 0x7f {
			return true
		}
	}
	return false
}

// StripControl removes control characters from a single string without
// touching length; useful for values that go into messages.
func StripControl(s string) string {
	out, _ := sanitizeString(s, len(s)+1)
	return out
}
