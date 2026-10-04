//! End-to-end API test against a real Postgres (`docker compose up -d`).
//! Uses a unique zone name per run, so it never collides with other data.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

async fn app() -> Router {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://dns:dns@127.0.0.1:5432/dns".into());
    let pool = control_plane::connect(&url)
        .await
        .unwrap_or_else(|e| panic!("can't reach Postgres at {url} (run `docker compose up -d`): {e}"));
    control_plane::api::router(pool)
}

async fn call(app: &Router, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(body.map_or(Body::empty(), |b| Body::from(b.to_string())))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn add(name: &str, rtype: &str, data: &str) -> Value {
    json!({ "action": "add", "name": name, "type": rtype, "data": data })
}

fn errors(body: &Value) -> String {
    body["errors"].to_string()
}

/// Changelog entries for `zone` with seq > `after`.
async fn log_after(app: &Router, zone: &str, after: i64) -> Vec<Value> {
    let (_, body) = call(app, "GET", &format!("/changelog?after={after}&limit=10000"), None).await;
    body["entries"].as_array().unwrap().iter().filter(|e| e["zone"] == zone).cloned().collect()
}

#[tokio::test]
async fn changesets_validate_bump_serial_and_reach_the_changelog() {
    let app = app().await;
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let zone = format!("t{nanos}.test.");
    let changes = format!("/zones/{zone}/changes");

    // Create: serial 1, changelog entry with the apex SOA + NS.
    let (status, created) = call(&app, "POST", "/zones", Some(json!({
        "name": zone, "ns": ["ns1.example.net.", "ns2.example.net."], "soa": { "expire": 3600 },
    }))).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["serial"], 1);
    let start = created["seq"].as_i64().unwrap();
    let (status, _) = call(&app, "POST", "/zones", Some(json!({ "name": zone, "ns": ["ns1.example.net."] }))).await;
    assert_eq!(status, StatusCode::CONFLICT);

    // A valid changeset: serial 2, one new changelog entry with each touched name's full set.
    let (status, ok) = call(&app, "POST", &changes, Some(json!({ "changes": [
        add("www", "A", "192.0.2.10"),
        add("www", "A", "192.0.2.11"),
        add("alias", "CNAME", &format!("www.{zone}")),
        add("txt", "TXT", r#""hello world""#),
    ]}))).await;
    assert_eq!(status, StatusCode::OK, "{ok}");
    assert_eq!(ok["serial"], 2);
    assert!(ok["seq"].as_i64().unwrap() > start);

    let log = log_after(&app, &zone, start).await;
    assert_eq!(log.len(), 1);
    let p = &log[0]["payload"];
    assert_eq!(log[0]["op"], "names");
    assert_eq!(log[0]["serial"], 2);
    assert_eq!(p[format!("www.{zone}")], json!([
        { "type": "A", "ttl": 300, "data": "192.0.2.10" },
        { "type": "A", "ttl": 300, "data": "192.0.2.11" },
    ]));
    assert_eq!(p[format!("txt.{zone}")][0]["data"], r#""hello world""#);
    let apex = p[&zone].as_array().unwrap();
    assert_eq!(apex[0]["type"], "SOA");
    assert_eq!(apex[0]["data"], format!("ns1.example.net. hostmaster.{zone} 2 3600 600 3600 300"));
    assert_eq!(apex.iter().filter(|r| r["type"] == "NS").count(), 2);

    // Invalid changesets: 400, every problem reported, nothing applied, no changelog entry.
    let rejected = [
        (json!([add("alias", "A", "192.0.2.1")]), "CNAME cannot coexist"),
        (json!([add("www", "A", "not-an-ip")]), "invalid A data"),
        (json!([add("www.example.org.", "A", "192.0.2.1")]), "not in zone"),
        (json!([add("@", "CNAME", "x.example.net.")]), "not allowed at the zone apex"),
        (json!([{ "action": "delete", "name": "@", "type": "NS" }]), "at least one NS"),
        (json!([{ "action": "delete", "name": "nope", "type": "A" }]), "no matching A record"),
        (json!([add("www", "A", "192.0.2.12"), { "action": "add", "name": "www", "type": "A", "ttl": 60, "data": "192.0.2.13" }]), "share one TTL"),
        (json!([add("x", "SOA", "a. b. 1 2 3 4 5")]), "SOA is managed through the zone"),
        // One good change plus one bad one: the good one must not be applied either.
        (json!([add("new", "A", "192.0.2.50"), add("bad", "MX", "10 relative")]), "fully qualified"),
    ];
    for (batch, expected) in rejected {
        let (status, body) = call(&app, "POST", &changes, Some(json!({ "changes": batch }))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{batch} -> {body}");
        assert!(errors(&body).contains(expected), "{batch}: expected {expected:?} in {body}");
    }
    let (_, multi) = call(&app, "POST", &changes, Some(json!({ "changes": [
        add("a", "A", "bad"), add("b", "AAAA", "bad"),
    ]}))).await;
    assert_eq!(multi["errors"].as_array().unwrap().len(), 2, "{multi}");

    let (_, z) = call(&app, "GET", &format!("/zones/{zone}"), None).await;
    assert_eq!(z["serial"], 2, "rejected changes must not bump the serial");
    assert!(!z["records"].to_string().contains("192.0.2.50"), "partial changeset leaked");
    assert_eq!(log_after(&app, &zone, start).await.len(), 1, "rejected changes must not log");

    // Deleting a name's last record logs it with an empty set, so nodes remove it.
    let (status, del) = call(&app, "POST", &changes, Some(json!({ "changes": [
        { "action": "delete", "name": "txt", "type": "TXT" },
    ]}))).await;
    assert_eq!(status, StatusCode::OK, "{del}");
    let log = log_after(&app, &zone, start).await;
    assert_eq!(log.last().unwrap()["payload"][format!("txt.{zone}")], json!([]));

    // Records inside a hosted child zone must be changed there, not in the parent.
    let child = format!("sub.{zone}");
    let (status, _) = call(&app, "POST", "/zones", Some(json!({ "name": child, "ns": ["ns1.example.net."] }))).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, body) = call(&app, "POST", &changes, Some(json!({ "changes": [add("x.sub", "A", "192.0.2.1")] }))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(errors(&body).contains("belongs to hosted zone"), "{body}");

    // PATCH bumps the serial and logs the new SOA.
    let (status, patched) = call(&app, "PATCH", &format!("/zones/{zone}"), Some(json!({ "expire": 7200 }))).await;
    assert_eq!(status, StatusCode::OK, "{patched}");
    let log = log_after(&app, &zone, start).await;
    let soa = &log.last().unwrap()["payload"][&zone][0]["data"];
    assert!(soa.as_str().unwrap().ends_with(" 3600 600 7200 300"), "{soa}");

    // Deleting zones logs delete_zone.
    for z in [&child, &zone] {
        let (status, _) = call(&app, "DELETE", &format!("/zones/{z}"), None).await;
        assert_eq!(status, StatusCode::OK);
    }
    assert_eq!(log_after(&app, &zone, start).await.last().unwrap()["op"], "delete_zone");
    let (status, _) = call(&app, "GET", &format!("/zones/{zone}"), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
