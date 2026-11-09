-- Wraps a Fluent Bit record in the Argus envelope and selects the topic.
-- The raw line is taken from "log" (tail) or "message" (syslog).
local tenant = os.getenv("ARGUS_TENANT") or ""
local hostname = os.getenv("HOSTNAME") or ""

function envelope(tag, timestamp, record)
  local raw = record["log"] or record["message"]
  if raw == nil or raw == "" then
    return -1, 0, 0 -- drop empty records
  end
  local kind = tag
  if kind == "generic" then kind = "" end
  local file = record["file"]
  local hints = {}
  local provider = ""
  if file ~= nil then
    hints["path"] = file
    if record["offset"] ~= nil then
      provider = "file:" .. file .. ":" .. tostring(record["offset"])
    end
  end
  local topic = "argus.raw." .. (kind ~= "" and kind or "generic")
  local out = {
    tenant_id = tenant,
    source_id = "fluent-bit-" .. tag,
    kind = kind,
    collector = { Name = "fluent-bit", Type = "fluent-bit", Host = hostname },
    received_at = os.date("!%Y-%m-%dT%H:%M:%SZ", math.floor(timestamp)),
    hints = hints,
    provider_id = provider,
    raw = raw,
    topic = topic,
  }
  return 1, timestamp, out
end
