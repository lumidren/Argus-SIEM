package schema

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
)

// hashSep separates the hash inputs so that moving bytes between fields
// cannot produce a collision (ADR-0004).
const hashSep = 0x1F

// ComputeHash returns the content hash used as event.hash and as the
// OpenSearch _id. providerID is the source's own unique id when it has one
// (CloudTrail eventID, Windows EventRecordID+Computer, Okta uuid, ...), and
// empty otherwise.
func ComputeHash(tenantID, sourceID string, raw []byte, providerID string) string {
	h := sha256.New()
	h.Write([]byte(tenantID))
	h.Write([]byte{hashSep})
	h.Write([]byte(sourceID))
	h.Write([]byte{hashSep})
	h.Write(bytes.TrimRight(raw, " \t\r\n"))
	h.Write([]byte{hashSep})
	h.Write([]byte(providerID))
	return hex.EncodeToString(h.Sum(nil))
}

// HashBytes returns the hex SHA-256 of b.
func HashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
