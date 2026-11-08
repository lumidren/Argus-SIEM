package paloalto

// Column orders for PAN-OS 10.x/11.x syslog CSV bodies. Index 0 is the
// FUTURE_USE / receive-time slot; names beginning with "_" are FUTURE_USE.
// Types without a table (USERID, HIPMATCH, DECRYPTION, CORRELATION, TUNNEL,
// GTP, SCTP, IPTAG) keep their type-specific columns positionally under
// panw.panos.<type>.col_<n>.
var prefix = []string{"_0", "receive_time", "serial", "type", "subtype", "_5", "generated_time"}

var trafficCols = append(append([]string{}, prefix...),
	"src", "dst", "natsrc", "natdst", "rule", "srcuser", "dstuser", "app", "vsys", "from", "to",
	"inbound_if", "outbound_if", "logset", "_21", "sessionid", "repeatcnt", "sport", "dport", "natsport",
	"natdport", "flags", "proto", "action", "bytes", "bytes_sent", "bytes_received", "packets", "start",
	"elapsed", "category", "_38", "seqno", "actionflags", "srcloc", "dstloc", "_43", "pkts_sent",
	"pkts_received", "session_end_reason", "dg_hier_level_1", "dg_hier_level_2", "dg_hier_level_3",
	"dg_hier_level_4", "vsys_name", "device_name", "action_source", "src_uuid", "dst_uuid", "tunnelid",
	"monitortag", "parent_session_id", "parent_start_time", "tunnel", "assoc_id", "chunks", "chunks_sent",
	"chunks_received", "rule_uuid", "http2_connection", "link_change_count", "policy_id", "link_switches",
	"sdwan_cluster", "sdwan_device_type", "sdwan_cluster_type", "sdwan_site", "dynusergroup_name", "xff_ip",
	"src_category", "src_profile", "src_model", "src_vendor", "src_osfamily", "src_osversion", "src_host",
	"src_mac", "dst_category", "dst_profile", "dst_model", "dst_vendor", "dst_osfamily", "dst_osversion",
	"dst_host", "dst_mac", "container_id", "pod_namespace", "pod_name", "src_edl", "dst_edl", "hostid",
	"serialnumber", "src_dag", "dst_dag", "session_owner", "high_res_timestamp",
)

var threatCols = append(append([]string{}, prefix...),
	"src", "dst", "natsrc", "natdst", "rule", "srcuser", "dstuser", "app", "vsys", "from", "to",
	"inbound_if", "outbound_if", "logset", "_21", "sessionid", "repeatcnt", "sport", "dport", "natsport",
	"natdport", "flags", "proto", "action", "misc", "threatid", "category", "severity", "direction", "seqno",
	"actionflags", "srcloc", "dstloc", "_40", "contenttype", "pcap_id", "filedigest", "cloud", "url_idx",
	"user_agent", "filetype", "xff", "referer", "sender", "subject", "recipient", "reportid",
	"dg_hier_level_1", "dg_hier_level_2", "dg_hier_level_3", "dg_hier_level_4", "vsys_name", "device_name",
	"_60", "src_uuid", "dst_uuid", "http_method", "tunnel_id", "monitortag", "parent_session_id",
	"parent_start_time", "tunnel", "thr_category", "contentver", "_71", "sig_flags", "rule_uuid",
	"http2_connection", "dynusergroup_name", "xff_ip", "src_category", "src_profile", "src_model", "src_vendor",
	"src_osfamily", "src_osversion", "src_host", "src_mac", "dst_category", "dst_profile", "dst_model",
	"dst_vendor", "dst_osfamily", "dst_osversion", "dst_host", "dst_mac", "partial_hash", "high_res_timestamp",
)

var systemCols = append(append([]string{}, prefix...),
	"vsys", "eventid", "object", "_10", "_11", "module", "severity", "opaque", "seqno", "actionflags",
	"dg_hier_level_1", "dg_hier_level_2", "dg_hier_level_3", "dg_hier_level_4", "vsys_name", "device_name",
	"high_res_timestamp",
)

var configCols = append(append([]string{}, prefix...),
	"host", "vsys", "cmd", "admin", "client", "result", "path", "before_change_detail", "after_change_detail",
	"seqno", "actionflags", "dg_hier_level_1", "dg_hier_level_2", "dg_hier_level_3", "dg_hier_level_4",
	"vsys_name", "device_name", "dg_id", "comment", "high_res_timestamp",
)

var authCols = append(append([]string{}, prefix...),
	"vsys", "ip", "user", "normalize_user", "object", "authpolicy", "repeatcnt", "authid", "vendor", "logset",
	"serverprofile", "desc", "clienttype", "event", "factorno", "seqno", "actionflags", "dg_hier_level_1",
	"dg_hier_level_2", "dg_hier_level_3", "dg_hier_level_4", "vsys_name", "device_name", "vsys_id",
	"authproto", "rule_uuid", "high_res_timestamp",
)

var gpCols = append(append([]string{}, prefix...),
	"vsys", "eventid", "stage", "auth_method", "tunnel_type", "srcuser", "srcregion", "machinename",
	"public_ip", "public_ipv6", "private_ip", "private_ipv6", "hostid", "serialnumber", "client_ver",
	"client_os", "client_os_ver", "repeatcnt", "reason", "error", "opaque", "status", "location",
	"login_duration", "connect_method", "error_code", "portal", "seqno", "actionflags", "high_res_timestamp",
	"selection_type", "response_time", "priority", "attempted_gateways", "gateway", "dg_hier_level_1",
	"dg_hier_level_2", "dg_hier_level_3", "dg_hier_level_4", "vsys_name", "device_name", "vsys_id",
)

var tables = map[string][]string{
	"TRAFFIC": trafficCols, "THREAT": threatCols, "SYSTEM": systemCols, "CONFIG": configCols,
	"AUTHENTICATION": authCols, "GLOBALPROTECT": gpCols,
}

var knownTypes = map[string]bool{
	"TRAFFIC": true, "THREAT": true, "SYSTEM": true, "CONFIG": true, "USERID": true, "HIPMATCH": true,
	"GLOBALPROTECT": true, "DECRYPTION": true, "AUTHENTICATION": true, "CORRELATION": true, "GTP": true,
	"TUNNEL": true, "SCTP": true, "IPTAG": true,
}
