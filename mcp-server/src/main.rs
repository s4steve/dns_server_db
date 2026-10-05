//! MCP server for the DNS control plane, over stdio.
//!
//! A thin client of the REST API (`CONTROL_PLANE_URL`, default http://127.0.0.1:8053, with
//! the bearer token in `CONTROL_PLANE_TOKEN`; the token's grants decide what tools can do): each
//! tool is one HTTP call, and all validation stays in the API. When the API rejects a
//! change, the tool result is an error carrying the API's messages, so the model can fix
//! the request and retry.
//!
//! Protocol: JSON-RPC 2.0, one message per line on stdin/stdout (MCP stdio transport).
//! Tools only. Logs go to stderr; stdout carries nothing but protocol messages.

use std::io::{BufRead, Write};

use serde_json::{Value, json};

/// Newest first. We answer with the client's version if we know it, else our newest.
const PROTOCOL_VERSIONS: [&str; 4] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

const LUA_HELP: &str = "LUA records: type \"LUA\", data \"<TYPE> <script>\" where TYPE is A, AAAA, TXT, MX or CAA. \
The script runs per query and returns record data as a string or list of strings (nil = serve the static records). \
It reads q.name, q.type, q.client (EDNS client subnet address, else source IP), q.client_prefix, q.source, q.node \
and q.static, and can call in_cidr(ip, \"10.0.0.0/8\"). q.client comes from the query's EDNS client subnet, which any \
client can set: use it to tailor answers, never to decide who may see internal addresses. Example data: \
\"A if in_cidr(q.client, '198.51.100.0/24') then return '192.0.2.10' end return '192.0.2.20'\".";

fn tools() -> Value {
    let zone = json!({ "type": "string", "description": "Zone name, e.g. \"example.com\"" });
    let ttl = json!({ "type": "integer", "minimum": 0, "maximum": 2147483647 });
    let soa = json!({
        "type": "object",
        "description": "SOA fields. refresh/retry: seconds between nodes' serial checks; expire: seconds a node may serve the zone without reaching the control plane.",
        "properties": {
            "mname": { "type": "string" }, "rname": { "type": "string" },
            "refresh": { "type": "integer", "minimum": 1 }, "retry": { "type": "integer", "minimum": 1 },
            "expire": { "type": "integer", "minimum": 1 }, "minimum": { "type": "integer", "minimum": 0 },
        },
        "additionalProperties": false,
    });
    let spf_name = json!({ "type": "string", "description": "Name in the zone: \"@\" for the apex, or relative (\"mail\")" });
    let read_only = json!({ "readOnlyHint": true, "openWorldHint": false });
    let write = |destructive: bool| json!({ "readOnlyHint": false, "destructiveHint": destructive, "openWorldHint": false });
    json!([
        {
            "name": "list_zones",
            "title": "List zones",
            "description": "List every zone with its serial and SOA settings.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
            "annotations": read_only,
        },
        {
            "name": "get_zone",
            "title": "Get zone",
            "description": "Get one zone: SOA settings, serial and all records (including LUA scripts).",
            "inputSchema": { "type": "object", "properties": { "zone": zone }, "required": ["zone"], "additionalProperties": false },
            "annotations": read_only,
        },
        {
            "name": "create_zone",
            "title": "Create zone",
            "description": "Create a zone with its name servers. The SOA is created automatically (mname defaults to the first NS); its serial is managed for you.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": zone,
                    "ns": { "type": "array", "items": { "type": "string" }, "minItems": 1, "description": "Fully qualified name server names, ending in '.'" },
                    "default_ttl": ttl,
                    "soa": soa,
                },
                "required": ["name", "ns"],
                "additionalProperties": false,
            },
            "annotations": write(false),
        },
        {
            "name": "update_zone",
            "title": "Update zone settings",
            "description": "Change a zone's default TTL or SOA fields. Bumps the serial.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "zone": zone, "default_ttl": ttl,
                    "mname": { "type": "string" }, "rname": { "type": "string" },
                    "refresh": { "type": "integer", "minimum": 1 }, "retry": { "type": "integer", "minimum": 1 },
                    "expire": { "type": "integer", "minimum": 1 }, "minimum": { "type": "integer", "minimum": 0 },
                },
                "required": ["zone"],
                "additionalProperties": false,
            },
            "annotations": write(false),
        },
        {
            "name": "delete_zone",
            "title": "Delete zone",
            "description": "Delete a zone and all its records. DNS nodes stop answering for it within seconds.",
            "inputSchema": { "type": "object", "properties": { "zone": zone }, "required": ["zone"], "additionalProperties": false },
            "annotations": write(true),
        },
        {
            "name": "apply_changes",
            "title": "Apply record changes",
            "description": format!(
                "Apply record changes to a zone atomically: all succeed or none do, with every problem reported. \
                 Names may be \"@\" (apex), relative (\"www\") or absolute (\"www.example.com.\"); names inside record data \
                 (CNAME/MX/NS targets) must be absolute. Types: A, AAAA, CNAME, MX, TXT, NS, CAA, LUA. A delete without data \
                 removes the whole RRset. A record added without ttl takes its RRset's TTL, else the zone default. {LUA_HELP}"
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "zone": zone,
                    "changes": {
                        "type": "array",
                        "minItems": 1,
                        "items": {
                            "type": "object",
                            "properties": {
                                "action": { "type": "string", "enum": ["add", "delete"] },
                                "name": { "type": "string" },
                                "type": { "type": "string" },
                                "ttl": ttl,
                                "data": { "type": "string", "description": "Record data in zone-file syntax, e.g. \"192.0.2.1\", \"10 mail.example.com.\", \"\\\"some text\\\"\"" },
                            },
                            "required": ["action", "name", "type"],
                            "additionalProperties": false,
                        },
                    },
                },
                "required": ["zone", "changes"],
                "additionalProperties": false,
            },
            "annotations": write(true),
        },
        {
            "name": "get_changelog",
            "title": "Read changelog",
            "description": "Read changelog entries after a sequence number, oldest first, for the zones this token can see. Each entry has the zone, its new serial, the token that made the change (actor), and the complete new record set of every name it touched. Continue from next_after.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "after": { "type": "integer", "minimum": 0, "description": "Return entries with seq greater than this (default 0)" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 10000, "description": "Default 100" },
                },
                "additionalProperties": false,
            },
            "annotations": read_only,
        },
        {
            "name": "get_spf_policy",
            "title": "Get managed SPF policy",
            "description": "Get the managed SPF policy at a name: its senders, qualifier, the flattened ip4/ip6 terms currently published, and last_error if the latest background refresh failed.",
            "inputSchema": { "type": "object", "properties": { "zone": zone, "name": spf_name }, "required": ["zone", "name"], "additionalProperties": false },
            "annotations": read_only,
        },
        {
            "name": "set_spf_policy",
            "title": "Set managed SPF policy",
            "description": "Create or replace the managed SPF policy at a name. The control plane resolves each sender's SPF record now (following includes, redirects, a and mx) into ip4/ip6 terms and publishes them as plain TXT records that stay under SPF's 10-lookup limit: the name's v=spf1 record, which includes up to 9 chunk records named _spf0.<name> to _spf8.<name>. It replaces any existing v=spf1 TXT record at the name and keeps other TXT records. It re-resolves periodically. Senders whose records use exists:, ptr or macros are rejected. Needs editor on the zone.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "zone": zone,
                    "name": spf_name,
                    "senders": {
                        "type": "array", "minItems": 1, "items": { "type": "string" },
                        "description": "Domains to flatten (e.g. \"_spf.google.com\", \"sendgrid.net\"), or literal \"ip4:192.0.2.0/24\", \"ip6:2001:db8::/32\", bare IPs or CIDRs",
                    },
                    "qualifier": { "type": "string", "enum": ["~all", "-all", "?all"], "description": "How to treat senders not listed (default ~all)" },
                },
                "required": ["zone", "name", "senders"],
                "additionalProperties": false,
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": true, "openWorldHint": true },
        },
        {
            "name": "delete_spf_policy",
            "title": "Delete managed SPF policy",
            "description": "Delete the managed SPF policy at a name, along with the TXT records it published (the name's v=spf1 record and its _spfN chunks). Other TXT records are kept. The name then has no SPF record.",
            "inputSchema": { "type": "object", "properties": { "zone": zone, "name": spf_name }, "required": ["zone", "name"], "additionalProperties": false },
            "annotations": write(true),
        },
        {
            "name": "whoami",
            "title": "Show my permissions",
            "description": "Show this server's API token: its name, whether it is an admin, and its grants (zone pattern, role viewer/editor/owner, and whether it may write LUA scripts). Check this before changing zones.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
            "annotations": read_only,
        },
    ])
}

struct Api {
    base: String,
    token: Option<String>,
    agent: ureq::Agent,
}

impl Api {
    fn new(base: &str, token: Option<String>) -> Self {
        // 4xx responses carry the API's validation messages; read them instead of failing.
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build();
        Self {
            base: base.trim_end_matches('/').to_string(),
            token,
            agent: config.into(),
        }
    }

    /// One API call. `Err` holds a message for the model: the API's errors, or why the call failed.
    fn call(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value, String> {
        let url = format!("{}{path}", self.base);
        let auth = self
            .token
            .as_ref()
            .map(|t| format!("Bearer {t}"))
            .unwrap_or_default();
        let sent = match (method, body) {
            ("GET", _) => self.agent.get(&url).header("Authorization", &auth).call(),
            ("DELETE", _) => self
                .agent
                .delete(&url)
                .header("Authorization", &auth)
                .call(),
            ("POST", Some(b)) => self
                .agent
                .post(&url)
                .header("Authorization", &auth)
                .send_json(b),
            ("PUT", Some(b)) => self
                .agent
                .put(&url)
                .header("Authorization", &auth)
                .send_json(b),
            ("PATCH", Some(b)) => self
                .agent
                .patch(&url)
                .header("Authorization", &auth)
                .send_json(b),
            _ => unreachable!("{method} {path}"),
        };
        let mut resp =
            sent.map_err(|e| format!("Could not reach the control plane at {}: {e}", self.base))?;
        let status = resp.status();
        let body: Value = resp.body_mut().read_json().unwrap_or(Value::Null);
        if status.is_success() {
            return Ok(body);
        }
        let errors: Vec<String> = body["errors"]
            .as_array()
            .map(|e| {
                e.iter()
                    .filter_map(|m| m.as_str().map(|m| format!("- {m}")))
                    .collect()
            })
            .unwrap_or_default();
        Err(format!(
            "The control plane rejected this ({status}):\n{}",
            errors.join("\n")
        ))
    }
}

/// A zone name for a URL path. Zone names never need escaping; anything else is refused.
fn zone_arg(args: &Value) -> Result<String, String> {
    let zone = args["zone"]
        .as_str()
        .ok_or("missing required argument: zone")?;
    if zone.is_empty()
        || !zone
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c))
    {
        return Err(format!("invalid zone name {zone:?}"));
    }
    Ok(zone.to_string())
}

/// `/zones/{zone}/spf/{name}`. Names never need escaping; anything else is refused.
fn spf_path(args: &Value) -> Result<String, String> {
    let zone = zone_arg(args)?;
    let name = args["name"]
        .as_str()
        .ok_or("missing required argument: name")?;
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-_@".contains(c))
    {
        return Err(format!("invalid name {name:?}"));
    }
    Ok(format!("/zones/{zone}/spf/{name}"))
}

/// Runs a tool. `None` = no such tool.
fn call_tool(api: &Api, name: &str, args: &Value) -> Option<Result<Value, String>> {
    let with_zone = |f: &dyn Fn(String) -> Result<Value, String>| zone_arg(args).and_then(f);
    Some(match name {
        "list_zones" => api.call("GET", "/zones", None),
        "whoami" => api.call("GET", "/whoami", None),
        "get_zone" => with_zone(&|z| api.call("GET", &format!("/zones/{z}"), None)),
        "create_zone" => api.call("POST", "/zones", Some(args)),
        "update_zone" => with_zone(&|z| {
            let mut body = args.clone();
            body.as_object_mut().map(|o| o.remove("zone"));
            api.call("PATCH", &format!("/zones/{z}"), Some(&body))
        }),
        "delete_zone" => with_zone(&|z| api.call("DELETE", &format!("/zones/{z}"), None)),
        "apply_changes" => with_zone(&|z| {
            let body = json!({ "changes": args["changes"] });
            api.call("POST", &format!("/zones/{z}/changes"), Some(&body))
        }),
        "get_spf_policy" => spf_path(args).and_then(|p| api.call("GET", &p, None)),
        "set_spf_policy" => spf_path(args).and_then(|p| {
            let mut body = json!({ "senders": args["senders"] });
            if let Some(q) = args.get("qualifier") {
                body["qualifier"] = q.clone();
            }
            api.call("PUT", &p, Some(&body))
        }),
        "delete_spf_policy" => spf_path(args).and_then(|p| api.call("DELETE", &p, None)),
        "get_changelog" => {
            let after = args["after"].as_u64().unwrap_or(0);
            let limit = args["limit"].as_u64().unwrap_or(100);
            api.call(
                "GET",
                &format!("/changelog?after={after}&limit={limit}"),
                None,
            )
        }
        _ => return None,
    })
}

fn error(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// Handles one JSON-RPC message. Returns the response, or None for notifications.
fn handle(api: &Api, msg: &Value) -> Option<Value> {
    let id = msg.get("id")?.clone(); // no id: a notification, never answered
    let params = &msg["params"];
    let result = match msg["method"].as_str().unwrap_or_default() {
        "initialize" => {
            let asked = params["protocolVersion"].as_str().unwrap_or_default();
            let version = PROTOCOL_VERSIONS
                .iter()
                .find(|v| **v == asked)
                .unwrap_or(&PROTOCOL_VERSIONS[0]);
            json!({
                "protocolVersion": version,
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": { "name": "dns-server-db", "title": "DNS control plane", "version": env!("CARGO_PKG_VERSION") },
                "instructions": "Manages authoritative DNS zones. Changes are validated and applied atomically, then reach every DNS node within seconds. Use get_zone to see current records before changing them.",
            })
        }
        "ping" => json!({}),
        "tools/list" => json!({ "tools": tools() }),
        "tools/call" => {
            let name = params["name"].as_str().unwrap_or_default();
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            match call_tool(api, name, &args) {
                None => return Some(error(&id, -32602, &format!("unknown tool: {name}"))),
                Some(Ok(v)) => json!({
                    "content": [{ "type": "text", "text": serde_json::to_string_pretty(&v).unwrap() }],
                    "isError": false,
                }),
                Some(Err(e)) => {
                    json!({ "content": [{ "type": "text", "text": e }], "isError": true })
                }
            }
        }
        other => return Some(error(&id, -32601, &format!("method not found: {other}"))),
    };
    Some(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

/// Whether `url` is safe to send the token and changelog to: `https://`, or plain `http://`
/// only to a loopback host unless `allow_http` (CONTROL_PLANE_ALLOW_HTTP=1, for trusted
/// networks such as the compose setup). Tokens and LUA scripts must not cross a network in
/// the clear.
// ponytail: the same check lives in dns-server/src/main.rs; share a crate if a third client appears.
fn check_transport(url: &str, allow_http: bool) -> Result<(), String> {
    let uri: ureq::http::Uri = url
        .parse()
        .map_err(|e| format!("invalid control plane URL {url:?}: {e}"))?;
    let host = uri.host().unwrap_or("");
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    match uri.scheme_str() {
        Some("https") => Ok(()),
        Some("http") if loopback || allow_http => Ok(()),
        Some("http") => Err(format!(
            "refusing plain http:// to {host}: use https:// (TLS), or set CONTROL_PLANE_ALLOW_HTTP=1 on a trusted network"
        )),
        _ => Err(format!(
            "control plane URL {url:?} must start with https://"
        )),
    }
}

fn allow_http() -> bool {
    std::env::var("CONTROL_PLANE_ALLOW_HTTP").is_ok_and(|v| v == "1")
}

fn main() {
    let base =
        std::env::var("CONTROL_PLANE_URL").unwrap_or_else(|_| "http://127.0.0.1:8053".into());
    eprintln!("dns-server-db MCP server: control plane {base}");
    let token = std::env::var("CONTROL_PLANE_TOKEN")
        .ok()
        .filter(|t| !t.is_empty());
    if token.is_none() {
        eprintln!("warning: CONTROL_PLANE_TOKEN is not set; the API will refuse every call");
    }
    if let Err(e) = check_transport(&base, allow_http()) {
        eprintln!("{e}");
        std::process::exit(1);
    }
    let api = Api::new(&base, token);
    let mut out = std::io::stdout().lock();
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(msg) => handle(&api, &msg),
            Err(e) => Some(error(&Value::Null, -32700, &format!("parse error: {e}"))),
        };
        if let Some(r) = response {
            let _ = writeln!(out, "{r}");
            let _ = out.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport() {
        for ok in [
            "https://cp.example.net",
            "http://127.0.0.1:8053",
            "http://localhost:8053",
            "http://[::1]:8053",
        ] {
            assert!(check_transport(ok, false).is_ok(), "{ok}");
        }
        for bad in [
            "http://cp.example.net",
            "http://192.0.2.1:8053",
            "ftp://127.0.0.1",
            "nonsense",
        ] {
            assert!(check_transport(bad, false).is_err(), "{bad}");
        }
        assert!(check_transport("http://control-plane:8053", true).is_ok());
    }
}
