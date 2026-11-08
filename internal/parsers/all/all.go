// Package all builds the default parser registry with every shipped source
// integration and the sniffing order used when a record arrives without an
// explicit source kind.
package all

import (
	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/parsers/apache"
	"github.com/lumidren/argus/internal/parsers/azure"
	"github.com/lumidren/argus/internal/parsers/cloudtrail"
	"github.com/lumidren/argus/internal/parsers/fortinet"
	"github.com/lumidren/argus/internal/parsers/gcp"
	"github.com/lumidren/argus/internal/parsers/generic"
	"github.com/lumidren/argus/internal/parsers/googleworkspace"
	"github.com/lumidren/argus/internal/parsers/kubernetes"
	"github.com/lumidren/argus/internal/parsers/linux"
	"github.com/lumidren/argus/internal/parsers/nginx"
	"github.com/lumidren/argus/internal/parsers/o365"
	"github.com/lumidren/argus/internal/parsers/okta"
	"github.com/lumidren/argus/internal/parsers/osquery"
	"github.com/lumidren/argus/internal/parsers/paloalto"
	"github.com/lumidren/argus/internal/parsers/suricata"
	"github.com/lumidren/argus/internal/parsers/windows"
	"github.com/lumidren/argus/internal/parsers/zeek"
)

// SniffOrder lists parsers from most to least specific. Structured formats
// with unique markers come first; formats that can wrap others (syslog-borne
// firewalls, auth lines, web logs) follow; generic is always last.
var SniffOrder = []string{
	"windows", "suricata", "zeek", "aws", "gcp", "o365", "okta", "google_workspace",
	"azure", "kubernetes", "osquery", "panw", "fortinet", "linux", "apache", "nginx", "generic",
}

// Registry returns a registry holding every shipped parser.
func Registry() *parsers.Registry {
	r := parsers.NewRegistry()
	for _, p := range []parsers.Parser{
		windows.New(), suricata.New(), zeek.New(), cloudtrail.New(), gcp.New(), o365.New(), okta.New(),
		googleworkspace.New(), azure.New(), kubernetes.New(), osquery.New(), paloalto.New(), fortinet.New(),
		linux.New(), apache.New(), nginx.New(), generic.New(),
	} {
		r.Register(p)
	}
	r.SetSniffOrder(SniffOrder...)
	return r
}
