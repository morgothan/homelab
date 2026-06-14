-- ollama-info.nse
-- Enumerates an Ollama AI inference server: version, installed models,
-- running models, and optionally pulls model details.
--
-- Usage:
--   nmap -p 11434 --script ollama-info <target>
--   nmap -p 11434 --script ollama-info --script-args ollama-info.details=true <target>

local http   = require "http"
local json   = require "json"
local nmap   = require "nmap"
local stdnse = require "stdnse"
local table  = require "table"

description = [[
Detects and enumerates an Ollama REST API server (default port 11434).

Retrieves:
  - Server version
  - Installed models (name, parameter size, quantization, family, modified date)
  - Currently loaded / running models and their VRAM usage
  - Per-model details when ollama-info.details=true

Ollama exposes no authentication by default. When this script succeeds, the
host is running an unauthenticated AI model server.
]]

---
-- @usage
--   nmap -sV -p 11434 --script ollama-info <target>
--   nmap -p 11434 --script ollama-info --script-args ollama-info.details=true <target>
--
-- @args ollama-info.details  If true, fetch /api/show for every installed model.
--                            Produces verbose output; use sparingly against large
--                            model libraries. Default: false.
--
-- @output
-- PORT      STATE SERVICE VERSION
-- 11434/tcp open  http    Ollama 0.5.12
-- | ollama-info:
-- |   version: 0.5.12
-- |   models (3):
-- |     llama3.2:3b
-- |       family:        llama
-- |       params:        3.2B
-- |       quant:         Q4_K_M
-- |       size:          2.0 GB
-- |       modified:      2025-04-01T12:34:56Z
-- |     mistral:7b-instruct-v0.3-q4_K_M
-- |       ...
-- |   running (1):
-- |     llama3.2:3b
-- |       expires:       2025-04-01T13:00:00Z
-- |_      vram:          2.1 GB

author     = "nat (morgothan@gmail.com)"
license    = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = { "discovery", "safe", "default" }

-- Only run against HTTP services, or when the port is 11434.
portrule = function(host, port)
  return port.number == 11434
      or (port.service == "http" and port.state == "open")
end

-- ── helpers ──────────────────────────────────────────────────────────────────

local function get_json(host, port, path)
  local resp = http.get(host, port, path, { header = { Accept = "application/json" } })
  if not resp or resp.status ~= 200 then
    return nil, string.format("HTTP %s on %s", tostring(resp and resp.status), path)
  end
  local ok, parsed = json.parse(resp.body)
  if not ok then
    return nil, "JSON parse error on " .. path
  end
  return parsed
end

local function bytes_to_gb(n)
  if type(n) ~= "number" then return "?" end
  return string.format("%.1f GB", n / 1073741824)
end

-- ── main ─────────────────────────────────────────────────────────────────────

action = function(host, port)
  local output = stdnse.output_table()

  -- 1. Confirm Ollama is running (/  returns plain-text "Ollama is running")
  local root = http.get(host, port, "/")
  if not root or root.status ~= 200 or not root.body:match("Ollama is running") then
    return nil
  end

  -- 2. Version
  local ver_data, ver_err = get_json(host, port, "/api/version")
  if ver_data and ver_data.version then
    output.version = ver_data.version
    -- Feed version string back to Nmap's version detection
    port.version.name    = "http"
    port.version.product = "Ollama"
    port.version.version = ver_data.version
    nmap.set_port_version(host, port)
  else
    stdnse.debug1("version fetch failed: %s", ver_err or "unknown")
  end

  -- 3. Installed models (/api/tags)
  local tags_data, tags_err = get_json(host, port, "/api/tags")
  if tags_data and tags_data.models then
    local models_out = stdnse.output_table()
    local want_details = stdnse.get_script_args("ollama-info.details")

    for _, m in ipairs(tags_data.models) do
      local entry  = stdnse.output_table()
      local di     = m.details or {}

      entry.family   = di.family       or "?"
      entry.params   = di.parameter_size   or "?"
      entry.quant    = di.quantization_level or "?"
      entry.size     = bytes_to_gb(m.size)
      entry.modified = m.modified_at   or "?"

      if want_details then
        -- POST /api/show for richer metadata
        local show_resp = http.post(host, port, "/api/show",
          { header = { ["Content-Type"] = "application/json" } },
          nil,
          json.generate({ name = m.name })
        )
        if show_resp and show_resp.status == 200 then
          local ok, sd = json.parse(show_resp.body)
          if ok and sd.modelinfo then
            -- Pull a few useful keys from the flat modelinfo map
            local arch = sd.modelinfo["general.architecture"]
            if arch then entry.arch = arch end
            local ctx = sd.modelinfo[arch and (arch .. ".context_length") or nil]
            if ctx then entry.context_length = tostring(ctx) end
          end
          if ok and sd.license then
            -- Truncate long license blobs
            local lic = sd.license:gsub("\n.*", "")  -- first line only
            entry.license = lic
          end
        end
      end

      models_out[m.name] = entry
    end

    output[string.format("models (%d)", #tags_data.models)] = models_out
  else
    stdnse.debug1("tags fetch failed: %s", tags_err or "unknown")
  end

  -- 4. Running / loaded models (/api/ps)
  local ps_data, ps_err = get_json(host, port, "/api/ps")
  if ps_data and ps_data.models and #ps_data.models > 0 then
    local running_out = stdnse.output_table()
    for _, m in ipairs(ps_data.models) do
      local entry = stdnse.output_table()
      entry.expires   = m.expires_at  or "?"
      entry.vram      = bytes_to_gb(m.size_vram)
      running_out[m.name] = entry
    end
    output[string.format("running (%d)", #ps_data.models)] = running_out
  elseif ps_err then
    stdnse.debug1("ps fetch failed: %s", ps_err)
  end

  return output
end
