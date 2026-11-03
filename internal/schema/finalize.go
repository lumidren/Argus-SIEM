package schema

import (
	"net"
	"strings"
	"time"
)

// ipFields are the ECS fields whose values feed related.ip.
var ipFields = []string{
	"source.ip", "destination.ip", "client.ip", "server.ip", "host.ip",
	"source.nat.ip", "destination.nat.ip", "observer.ip", "network.forwarded_ip",
	"dns.resolved_ip", "threat.indicator.ip",
}

// userFields feed related.user.
var userFields = []string{
	"user.name", "user.target.name", "user.effective.name", "source.user.name",
	"destination.user.name", "user.email", "user.target.email",
}

// hostFields feed related.hosts.
var hostFields = []string{
	"host.name", "host.hostname", "source.domain", "destination.domain",
	"observer.hostname", "url.domain", "destination.address",
}

// hashFields feed related.hash.
var hashFields = []string{
	"process.hash.md5", "process.hash.sha1", "process.hash.sha256", "process.hash.imphash",
	"file.hash.md5", "file.hash.sha1", "file.hash.sha256", "file.hash.ssdeep",
	"threat.indicator.file.hash.md5", "threat.indicator.file.hash.sha1", "threat.indicator.file.hash.sha256",
	"tls.server.hash.sha1", "tls.server.hash.sha256",
}

// Finalize fills the derived fields every event must carry: related.*,
// lower-cased host.name, ecs.version, argus.schema.version, event.kind and
// event.ingested. It is called by the processor after parsing and enrichment.
func Finalize(e *Event, ingested time.Time) {
	if h := e.String(FieldHostName); h != "" {
		e.m[FieldHostName] = strings.ToLower(h)
	}
	for _, f := range ipFields {
		for _, v := range e.Strings(f) {
			if ip := net.ParseIP(v); ip != nil {
				e.Append(FieldRelatedIP, ip.String())
			}
		}
	}
	for _, f := range userFields {
		e.Append(FieldRelatedUser, e.Strings(f)...)
	}
	for _, f := range hostFields {
		for _, v := range e.Strings(f) {
			if v != "" && net.ParseIP(v) == nil {
				e.Append(FieldRelatedHosts, strings.ToLower(v))
			}
		}
	}
	for _, f := range hashFields {
		for _, v := range e.Strings(f) {
			e.Append(FieldRelatedHash, strings.ToLower(v))
		}
	}
	if !e.Has(FieldEventKind) {
		e.m[FieldEventKind] = KindEvent
	}
	e.m[FieldECSVersion] = ECSVersion
	e.m[FieldSchemaVersion] = int64(Version)
	if !ingested.IsZero() {
		e.m[FieldEventIngested] = ingested.UTC().Format("2006-01-02T15:04:05.000Z")
	}
	if !e.Has(FieldEntityKey) {
		e.m[FieldEntityKey] = EntityKey(e)
	}
}

// EntityKey derives the correlation/partition key: the primary user when
// present, else the primary host, else the source IP, scoped by tenant.
func EntityKey(e *Event) string {
	tenant := e.String(FieldTenantID)
	if u := e.String("user.name"); u != "" {
		d := e.String("user.domain")
		if d != "" {
			return tenant + "|user:" + strings.ToLower(d+"\\"+u)
		}
		return tenant + "|user:" + strings.ToLower(u)
	}
	if h := e.String(FieldHostName); h != "" {
		return tenant + "|host:" + strings.ToLower(h)
	}
	if ip := e.String("source.ip"); ip != "" {
		return tenant + "|ip:" + ip
	}
	return tenant + "|none"
}
