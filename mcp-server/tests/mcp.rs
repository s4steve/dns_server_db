//! Drives the real binary over stdio, as an MCP client would, against a real control plane
//! (in-process, on Postgres from `docker compose up -d`).

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{Value, json};

/// Starts the control plane on a free port in a background runtime. Returns its URL and a
/// function that mints tokens: (name prefix, admin, grants as "PATTERN:ROLE[:scripts]").
fn control_plane() -> (String, impl Fn(&str, bool, &[&str]) -> String) {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let url = std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://dns:dns@127.0.0.1:5432/dns".into());
            let pool = control_plane::connect(&url).await.unwrap_or_else(|e| {
                panic!("can't reach Postgres at {url} (run `docker compose up -d`): {e}")
            });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send((
                format!("http://{}", listener.local_addr().unwrap()),
                pool.clone(),
            ))
            .unwrap();
            axum::serve(listener, control_plane::api::router(pool))
                .await
                .unwrap();
        });
    });
    let (url, pool) = rx.recv().unwrap();
    let mint = move |name: &str, admin: bool, grants: &[&str]| {
        let grants: Vec<_> = grants
            .iter()
            .map(|g| control_plane::auth::Grant::parse_cli(g).unwrap())
            .collect();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let (pool, name) = (pool.clone(), format!("{name}{nanos}"));
        // On its own thread: the pool belongs to the server's runtime, not this one.
        std::thread::spawn(move || {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async move {
                    control_plane::auth::create_token(
                        &pool, &name, admin, &grants, None, None, false,
                    )
                    .await
                    .unwrap()
                    .unwrap()
                })
        })
        .join()
        .unwrap()
    };
    (url, mint)
}

struct Client {
    _child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl Client {
    fn start(control_plane: &str, token: &str) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_mcp-server"))
            .env("CONTROL_PLANE_TOKEN", token)
            .env("CONTROL_PLANE_URL", control_plane)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self {
            _child: child,
            stdin,
            stdout,
            next_id: 1,
        }
    }

    fn send(&mut self, msg: &Value) {
        writeln!(self.stdin, "{msg}").unwrap();
        self.stdin.flush().unwrap();
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        let resp: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(resp["id"], id, "{resp}");
        resp
    }

    /// Calls a tool; returns (is_error, text).
    fn tool(&mut self, name: &str, arguments: Value) -> (bool, String) {
        let resp = self.request(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        );
        let result = &resp["result"];
        assert!(result.is_object(), "{resp}");
        (
            result["isError"].as_bool().unwrap(),
            result["content"][0]["text"].as_str().unwrap().to_string(),
        )
    }
}

#[test]
fn mcp_round_trip() {
    let (url, mint) = control_plane();
    let mut c = Client::start(&url, &mint("mcp-admin-", true, &[]));

    // Handshake: our version echoed back; tools capability; then the initialized notification
    // must produce no response (the next line read belongs to the next request).
    let init = c.request("initialize", json!({
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "test", "version": "0" },
    }));
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    assert!(init["result"]["capabilities"]["tools"].is_object());
    c.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
    assert_eq!(c.request("ping", json!({}))["result"], json!({}));
    let unknown_version = c.request("initialize", json!({ "protocolVersion": "1999-01-01" }));
    assert_eq!(unknown_version["result"]["protocolVersion"], "2025-11-25");

    let tools = c.request("tools/list", json!({}));
    let names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "list_zones",
            "get_zone",
            "create_zone",
            "update_zone",
            "delete_zone",
            "apply_changes",
            "get_changelog",
            "whoami"
        ]
    );
    for t in tools["result"]["tools"].as_array().unwrap() {
        assert_eq!(t["inputSchema"]["type"], "object", "{t}");
    }

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let zone = format!("mcp{nanos}.test");

    let (err, text) = c.tool(
        "create_zone",
        json!({ "name": zone, "ns": ["ns1.example.net."], "soa": { "expire": 3600 } }),
    );
    assert!(!err, "{text}");
    let created: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(created["serial"], 1);

    // A valid changeset, including a LUA record.
    let (err, text) = c.tool(
        "apply_changes",
        json!({ "zone": zone, "changes": [
            { "action": "add", "name": "www", "type": "A", "data": "192.0.2.10" },
            { "action": "add", "name": "geo", "type": "LUA", "data": "A return '192.0.2.20'" },
        ]}),
    );
    assert!(!err, "{text}");

    // An invalid one comes back as a tool error listing every problem, so the model can fix it.
    let (err, text) = c.tool(
        "apply_changes",
        json!({ "zone": zone, "changes": [
            { "action": "add", "name": "www", "type": "A", "data": "not-an-ip" },
            { "action": "add", "name": "mx", "type": "MX", "data": "10 relative" },
        ]}),
    );
    assert!(err);
    assert!(
        text.contains("rejected")
            && text.contains("invalid A data")
            && text.contains("fully qualified"),
        "{text}"
    );

    let (err, text) = c.tool("get_zone", json!({ "zone": zone }));
    assert!(!err, "{text}");
    let z: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(z["serial"], 2);
    assert!(
        z["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["type"] == "LUA")
    );

    let (err, text) = c.tool("update_zone", json!({ "zone": zone, "expire": 7200 }));
    assert!(!err, "{text}");
    let (_, text) = c.tool("list_zones", json!({}));
    let listed: Value = serde_json::from_str(&text).unwrap();
    let mine = listed["zones"]
        .as_array()
        .unwrap()
        .iter()
        .find(|z| z["name"] == format!("{zone}."))
        .unwrap();
    assert_eq!(
        (mine["serial"].as_i64(), mine["soa"]["expire"].as_i64()),
        (Some(3), Some(7200))
    );

    let (err, text) = c.tool(
        "get_changelog",
        json!({ "after": created["seq"], "limit": 10000 }),
    );
    assert!(!err, "{text}");
    let log: Value = serde_json::from_str(&text).unwrap();
    let serials: Vec<i64> = log["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["zone"] == format!("{zone}."))
        .map(|e| e["serial"].as_i64().unwrap())
        .collect();
    assert_eq!(serials, [2, 3]);

    // Bad input and unknown names are errors, not crashes.
    assert!(c.tool("get_zone", json!({ "zone": "../zones" })).0);
    assert!(c.tool("get_zone", json!({})).0);
    assert!(
        c.tool("get_zone", json!({ "zone": "missing.invalid" }))
            .1
            .contains("not found")
    );
    assert_eq!(
        c.request("tools/call", json!({ "name": "nope", "arguments": {} }))["error"]["code"],
        -32602
    );
    assert_eq!(
        c.request("resources/list", json!({}))["error"]["code"],
        -32601
    );

    // whoami reports the token; a viewer token's changes come back as a 403 tool error, and
    // no token at all as a 401.
    let (err, text) = c.tool("whoami", json!({}));
    assert!(!err && text.contains("\"admin\": true"), "{text}");
    let mut viewer = Client::start(
        &url,
        &mint("mcp-viewer-", false, &[&format!("{zone}:viewer")]),
    );
    assert!(!viewer.tool("get_zone", json!({ "zone": zone })).0);
    let (err, text) = viewer.tool(
        "apply_changes",
        json!({ "zone": zone, "changes": [
            { "action": "add", "name": "x", "type": "A", "data": "192.0.2.1" },
        ]}),
    );
    assert!(err && text.contains("403"), "{text}");
    let mut anonymous = Client::start(&url, "");
    let (err, text) = anonymous.tool("list_zones", json!({}));
    assert!(err && text.contains("401"), "{text}");

    let (err, text) = c.tool("delete_zone", json!({ "zone": zone }));
    assert!(!err, "{text}");
    assert!(c.tool("get_zone", json!({ "zone": zone })).0);
}

#[test]
fn reports_unreachable_control_plane() {
    let mut c = Client::start("http://127.0.0.1:9", "unused"); // discard port: nothing listens
    let (err, text) = c.tool("list_zones", json!({}));
    assert!(err);
    assert!(text.contains("Could not reach the control plane"), "{text}");
}
