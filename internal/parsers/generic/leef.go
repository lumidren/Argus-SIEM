package generic

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/schema"
)

var errLEEFHeader = errors.New("generic: LEEF header is incomplete")

var leefMap = map[string]string{
	"srcMAC": "source.mac", "dstMAC": "destination.mac", "usrName": "user.name", "accountName": "user.name",
	"identHostName": "source.domain", "domain": "user.domain", "policy": "rule.name",
	"cat": "leef.attributes.cat", "identSrc": "leef.attributes.ident_src",
}

var leefInts = map[string]string{
	"totalPackets": "network.packets", "srcBytes": "source.bytes", "dstBytes": "destination.bytes",
	"srcPackets": "source.packets", "dstPackets": "destination.packets",
}

var leefIPs = map[string]string{
	"src": "source.ip", "dst": "destination.ip", "srcPreNAT": "source.nat.ip", "dstPreNAT": "destination.nat.ip",
	"srcPostNAT": "source.nat.ip", "dstPostNAT": "destination.nat.ip",
}

var leefPorts = map[string]string{
	"srcPort": "source.port", "dstPort": "destination.port", "srcPreNATPort": "source.nat.port",
	"dstPreNATPort": "destination.nat.port", "srcPostNATPort": "source.nat.port", "dstPostNATPort": "destination.nat.port",
}

func parseLEEF(in *parsers.Input, body string) (*schema.Event, error) {
	// LEEF:1.0|Vendor|Product|Version|EventID|attrs
	// LEEF:2.0|Vendor|Product|Version|EventID|<delim>|attrs
	parts := strings.SplitN(body, "|", 7)
	if len(parts) < 6 {
		return nil, errLEEFHeader
	}
	ver := strings.TrimPrefix(parts[0], "LEEF:")
	delim := "\t"
	attrs := ""
	if strings.HasPrefix(ver, "2") && len(parts) == 7 {
		d := parts[5]
		switch {
		case len(d) == 1:
			delim = d
		case strings.HasPrefix(strings.ToLower(d), "0x") || strings.HasPrefix(strings.ToLower(d), "x"):
			h := strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(d), "0"), "x")
			if n, err := strconv.ParseUint(h, 16, 8); err == nil {
				delim = string(rune(n))
			}
		case d == "":
			delim = "\t"
		}
		attrs = parts[6]
	} else {
		attrs = strings.Join(parts[5:], "|")
	}
	e := parsers.Base(in, "generic", "generic.leef")
	e.Set("leef.version", ver)
	e.Set("observer.vendor", parts[1])
	e.Set("observer.product", parts[2])
	e.Set("observer.version", parts[3])
	e.Set("leef.event_id", parts[4])
	e.Set(schema.FieldEventCode, parts[4])
	kv := map[string]string{}
	var order []string
	for _, a := range strings.Split(attrs, delim) {
		k, v, ok := strings.Cut(a, "=")
		if !ok || k == "" {
			continue
		}
		k = strings.TrimSpace(k)
		if _, dup := kv[k]; !dup {
			order = append(order, k)
		}
		kv[k] = v
	}
	for _, k := range order {
		v := kv[k]
		if v == "" {
			continue
		}
		if dst, ok := leefMap[k]; ok {
			e.Set(dst, v)
			continue
		}
		if dst, ok := leefInts[k]; ok {
			parsers.SetInt(e, dst, v)
			continue
		}
		if dst, ok := leefIPs[k]; ok {
			parsers.SetIP(e, dst, v)
			continue
		}
		if dst, ok := leefPorts[k]; ok {
			parsers.SetPort(e, dst, v)
			continue
		}
		switch k {
		case "devTime":
			setLEEFTime(e, v, kv["devTimeFormat"])
		case "devTimeFormat":
		case "proto":
			parsers.SetTransport(e, v)
		case "sev":
			if sev, ok := severityFromNumber(v); ok {
				e.Set(schema.FieldEventSeverity, sev)
			}
		case "url":
			parsers.SetURL(e, v)
		default:
			e.Set("leef.attributes."+parsers.Snake(k), v)
		}
	}
	if e.Has("source.ip") || e.Has("destination.ip") {
		e.SetCategory(schema.CategoryNetwork)
	}
	return e, nil
}

// javaLayouts converts common Java SimpleDateFormat patterns to Go layouts.
var javaLayouts = map[string]string{
	"MMM dd yyyy HH:mm:ss":         "Jan 02 2006 15:04:05",
	"MMM dd yyyy HH:mm:ss.SSS":     "Jan 02 2006 15:04:05.000",
	"MMM dd yyyy HH:mm:ss.SSS zzz": "Jan 02 2006 15:04:05.000 MST",
	"MMM dd yyyy HH:mm:ss zzz":     "Jan 02 2006 15:04:05 MST",
	"yyyy-MM-dd HH:mm:ss":          "2006-01-02 15:04:05",
	"yyyy-MM-dd'T'HH:mm:ss.SSSZ":   "2006-01-02T15:04:05.000-0700",
	"yyyy-MM-dd'T'HH:mm:ssZ":       "2006-01-02T15:04:05-0700",
	"dd/MM/yyyy HH:mm:ss":          "02/01/2006 15:04:05",
	"MM/dd/yyyy HH:mm:ss":          "01/02/2006 15:04:05",
}

func setLEEFTime(e *schema.Event, v, format string) {
	if format != "" {
		if layout, ok := javaLayouts[strings.TrimSpace(format)]; ok {
			if t, err := time.Parse(layout, strings.TrimSpace(v)); err == nil {
				e.SetTimestamp(t)
				return
			}
		}
	}
	if !parsers.SetTime(e, schema.FieldTimestamp, v) {
		parsers.SetTime(e, schema.FieldTimestamp, cefTime(v))
	}
}
