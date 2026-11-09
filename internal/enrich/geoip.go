// Package enrich holds the pipeline enrichers: GeoIP/ASN, asset and identity
// context, PII masking, and the threat-intel matcher hook. Every enricher is
// served from local data (mmdb files, in-memory tables) so the hot path never
// blocks on network I/O.
package enrich

import (
	"context"
	"net/netip"
	"sync/atomic"

	"github.com/oschwald/maxminddb-golang/v2"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/schema"
)

// geoFields are the address fields that receive *.geo and *.as enrichment.
var geoFields = []string{"source", "destination", "client", "server"}

// GeoRecord is the subset of a city/ASN mmdb record Argus uses. It decodes
// MaxMind GeoLite2-City, GeoLite2-ASN and DB-IP Lite layouts.
type GeoRecord struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Continent struct {
		Code string `maxminddb:"code"`
	} `maxminddb:"continent"`
	Subdivisions []struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
		TimeZone  string  `maxminddb:"time_zone"`
	} `maxminddb:"location"`
	Postal struct {
		Code string `maxminddb:"code"`
	} `maxminddb:"postal"`
	ASN   uint   `maxminddb:"autonomous_system_number"`
	ASOrg string `maxminddb:"autonomous_system_organization"`
}

// GeoLookup resolves an IP to a record.
type GeoLookup interface {
	Lookup(ip netip.Addr) (GeoRecord, bool)
}

// MMDB is a GeoLookup backed by one or more mmdb files (city + ASN).
// Readers can be swapped atomically when a newer database is downloaded.
type MMDB struct {
	city atomic.Pointer[maxminddb.Reader]
	asn  atomic.Pointer[maxminddb.Reader]
}

// OpenMMDB opens the city and (optional) ASN databases.
func OpenMMDB(cityPath, asnPath string) (*MMDB, error) {
	m := &MMDB{}
	if cityPath != "" {
		r, err := maxminddb.Open(cityPath)
		if err != nil {
			return nil, err
		}
		m.city.Store(r)
	}
	if asnPath != "" {
		r, err := maxminddb.Open(asnPath)
		if err != nil {
			return nil, err
		}
		m.asn.Store(r)
	}
	return m, nil
}

// Lookup implements GeoLookup.
func (m *MMDB) Lookup(ip netip.Addr) (GeoRecord, bool) {
	var rec GeoRecord
	found := false
	if r := m.city.Load(); r != nil {
		if res := r.Lookup(ip); res.Found() {
			if res.Decode(&rec) == nil {
				found = true
			}
		}
	}
	if r := m.asn.Load(); r != nil {
		var a GeoRecord
		if res := r.Lookup(ip); res.Found() && res.Decode(&a) == nil {
			rec.ASN, rec.ASOrg = a.ASN, a.ASOrg
			found = true
		}
	}
	return rec, found
}

// Close releases the databases.
func (m *MMDB) Close() error {
	if r := m.city.Load(); r != nil {
		_ = r.Close()
	}
	if r := m.asn.Load(); r != nil {
		_ = r.Close()
	}
	return nil
}

// Geo enriches public IPs with *.geo.* and *.as.* fields.
type Geo struct{ DB GeoLookup }

// Name implements pipeline.Enricher.
func (g *Geo) Name() string { return "geoip" }

// Enrich implements pipeline.Enricher.
func (g *Geo) Enrich(_ context.Context, e *schema.Event) {
	if g.DB == nil {
		return
	}
	for _, f := range geoFields {
		s := e.String(f + ".ip")
		if s == "" || !parsers.IsPublicIP(s) || e.Has(f+".geo.country_iso_code") {
			continue
		}
		ip, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		rec, ok := g.DB.Lookup(ip)
		if !ok {
			continue
		}
		p := f + ".geo."
		e.Set(p+"country_iso_code", rec.Country.ISOCode)
		e.Set(p+"country_name", rec.Country.Names["en"])
		e.Set(p+"continent_code", rec.Continent.Code)
		e.Set(p+"city_name", rec.City.Names["en"])
		e.Set(p+"postal_code", rec.Postal.Code)
		e.Set(p+"timezone", rec.Location.TimeZone)
		if len(rec.Subdivisions) > 0 {
			e.Set(p+"region_iso_code", rec.Subdivisions[0].ISOCode)
			e.Set(p+"region_name", rec.Subdivisions[0].Names["en"])
		}
		if rec.Location.Latitude != 0 || rec.Location.Longitude != 0 {
			e.Set(p+"location", map[string]any{"lat": rec.Location.Latitude, "lon": rec.Location.Longitude})
		}
		if rec.ASN != 0 {
			e.Set(f+".as.number", int64(rec.ASN))
			e.Set(f+".as.organization.name", rec.ASOrg)
		}
	}
}

// StaticGeo is an in-memory GeoLookup keyed by prefix; used in tests and for
// operators who maintain their own site/office ranges.
type StaticGeo struct {
	entries []staticGeoEntry
}

type staticGeoEntry struct {
	prefix netip.Prefix
	rec    GeoRecord
}

// Add registers a record for a CIDR prefix.
func (s *StaticGeo) Add(cidr string, rec GeoRecord) error {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return err
	}
	s.entries = append(s.entries, staticGeoEntry{prefix: p, rec: rec})
	return nil
}

// Lookup implements GeoLookup (longest prefix wins).
func (s *StaticGeo) Lookup(ip netip.Addr) (GeoRecord, bool) {
	best := -1
	var rec GeoRecord
	for _, en := range s.entries {
		if en.prefix.Contains(ip) && en.prefix.Bits() > best {
			best = en.prefix.Bits()
			rec = en.rec
		}
	}
	return rec, best >= 0
}
