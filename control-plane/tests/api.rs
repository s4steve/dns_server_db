//! End-to-end API test against a real Postgres (`docker compose up -d`).
//! Uses a unique zone name per run, so it never collides with other data.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

/// The router plus the token requests are sent with.
#[derive(Clone)]
struct Api {
    router: Router,
    pool: sqlx::PgPool,
    token: String,
}

impl Api {
    /// The same API, called with another token ("" sends none).
    fn as_token(&self, token: &str) -> Api {
        Api {
            token: token.to_string(),
            ..self.clone()
        }
    }

    /// Mints a token directly (as the CLI does) and returns an Api that uses it.
    async fn with_new_token(&self, name: &str, admin: bool, grants: &[(&str, &str)]) -> Api {
        let grants: Vec<control_plane::auth::Grant> = grants
            .iter()
            .map(|(p, r)| control_plane::auth::Grant::parse_cli(&format!("{p}:{r}")).unwrap())
            .collect();
        let secret =
            control_plane::auth::create_token(&self.pool, name, admin, &grants, None, None, false)
                .await
                .unwrap()
                .unwrap();
        self.as_token(&secret)
    }
}

fn unique(prefix: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{prefix}{nanos}")
}

/// Connects, and mints a fresh admin token to call with.
async fn app() -> Api {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://dns:dns@127.0.0.1:5432/dns".into());
    let pool = control_plane::connect(&url).await.unwrap_or_else(|e| {
        panic!("can't reach Postgres at {url} (run `docker compose up -d`): {e}")
    });
    let api = Api {
        router: control_plane::api::router(pool.clone()),
        pool,
        token: String::new(),
    };
    api.with_new_token(&unique("test-admin-"), true, &[]).await
}

async fn call(app: &Api, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if !app.token.is_empty() {
        req = req.header("authorization", format!("Bearer {}", app.token));
    }
    let req = req
        .body(body.map_or(Body::empty(), |b| Body::from(b.to_string())))
        .unwrap();
    let resp = app.router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn add(name: &str, rtype: &str, data: &str) -> Value {
    json!({ "action": "add", "name": name, "type": rtype, "data": data })
}

fn errors(body: &Value) -> String {
    body["errors"].to_string()
}

/// Changelog entries for `zone` with seq > `after`.
async fn log_after(app: &Api, zone: &str, after: i64) -> Vec<Value> {
    let (_, body) = call(
        app,
        "GET",
        &format!("/changelog?after={after}&limit=10000"),
        None,
    )
    .await;
    body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["zone"] == zone)
        .cloned()
        .collect()
}

#[tokio::test]
async fn changesets_validate_bump_serial_and_reach_the_changelog() {
    let app = app().await;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let zone = format!("t{nanos}.test.");
    let changes = format!("/zones/{zone}/changes");

    // Create: serial 1, changelog entry with the apex SOA + NS.
    let (status, created) = call(
        &app,
        "POST",
        "/zones",
        Some(json!({
            "name": zone, "ns": ["ns1.example.net.", "ns2.example.net."], "soa": { "expire": 3600 },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["serial"], 1);
    let start = created["seq"].as_i64().unwrap();
    let (status, _) = call(
        &app,
        "POST",
        "/zones",
        Some(json!({ "name": zone, "ns": ["ns1.example.net."] })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // The zone list carries the changelog head, for nodes' serial checks.
    let (_, list) = call(&app, "GET", "/zones", None).await;
    assert!(list["seq"].as_i64().unwrap() >= start, "{list}");
    assert!(
        list["zones"]
            .as_array()
            .unwrap()
            .iter()
            .any(|z| z["name"] == zone && z["serial"] == 1)
    );

    // A valid changeset: serial 2, one new changelog entry with each touched name's full set.
    let (status, ok) = call(
        &app,
        "POST",
        &changes,
        Some(json!({ "changes": [
            add("www", "A", "192.0.2.10"),
            add("www", "A", "192.0.2.11"),
            add("alias", "CNAME", &format!("www.{zone}")),
            add("txt", "TXT", r#""hello world""#),
        ]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{ok}");
    assert_eq!(ok["serial"], 2);
    assert!(ok["seq"].as_i64().unwrap() > start);

    let log = log_after(&app, &zone, start).await;
    assert_eq!(log.len(), 1);
    let p = &log[0]["payload"];
    assert_eq!(log[0]["op"], "names");
    assert_eq!(log[0]["serial"], 2);
    assert_eq!(
        p[format!("www.{zone}")],
        json!([
            { "type": "A", "ttl": 300, "data": "192.0.2.10" },
            { "type": "A", "ttl": 300, "data": "192.0.2.11" },
        ])
    );
    assert_eq!(p[format!("txt.{zone}")][0]["data"], r#""hello world""#);
    let apex = p[&zone].as_array().unwrap();
    assert_eq!(apex[0]["type"], "SOA");
    assert_eq!(
        apex[0]["data"],
        format!("ns1.example.net. hostmaster.{zone} 2 3600 600 3600 300")
    );
    assert_eq!(apex.iter().filter(|r| r["type"] == "NS").count(), 2);

    // Invalid changesets: 400, every problem reported, nothing applied, no changelog entry.
    let rejected = [
        (
            json!([add("alias", "A", "192.0.2.1")]),
            "CNAME cannot coexist",
        ),
        (json!([add("www", "A", "not-an-ip")]), "invalid A data"),
        (
            json!([add("www.example.org.", "A", "192.0.2.1")]),
            "not in zone",
        ),
        (
            json!([add("@", "CNAME", "x.example.net.")]),
            "not allowed at the zone apex",
        ),
        (
            json!([{ "action": "delete", "name": "@", "type": "NS" }]),
            "at least one NS",
        ),
        (
            json!([{ "action": "delete", "name": "nope", "type": "A" }]),
            "no matching A record",
        ),
        (
            json!([add("www", "A", "192.0.2.12"), { "action": "add", "name": "www", "type": "A", "ttl": 60, "data": "192.0.2.13" }]),
            "share one TTL",
        ),
        (
            json!([add("x", "SOA", "a. b. 1 2 3 4 5")]),
            "SOA is managed through the zone",
        ),
        (
            json!([add("alias", "LUA", "A return '192.0.2.1'")]),
            "CNAME cannot coexist",
        ),
        (json!([add("geo", "LUA", "A return (")]), "does not compile"),
        (json!([add("geo", "LUA", "NS return 'x.'")]), "can answer"),
        // One good change plus one bad one: the good one must not be applied either.
        (
            json!([
                add("new", "A", "192.0.2.50"),
                add("bad", "MX", "10 relative")
            ]),
            "fully qualified",
        ),
    ];
    for (batch, expected) in rejected {
        let (status, body) = call(&app, "POST", &changes, Some(json!({ "changes": batch }))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{batch} -> {body}");
        assert!(
            errors(&body).contains(expected),
            "{batch}: expected {expected:?} in {body}"
        );
    }
    let (_, multi) = call(
        &app,
        "POST",
        &changes,
        Some(json!({ "changes": [
            add("a", "A", "bad"), add("b", "AAAA", "bad"),
        ]})),
    )
    .await;
    assert_eq!(multi["errors"].as_array().unwrap().len(), 2, "{multi}");

    let (_, z) = call(&app, "GET", &format!("/zones/{zone}"), None).await;
    assert_eq!(z["serial"], 2, "rejected changes must not bump the serial");
    assert!(
        !z["records"].to_string().contains("192.0.2.50"),
        "partial changeset leaked"
    );
    assert_eq!(
        log_after(&app, &zone, start).await.len(),
        1,
        "rejected changes must not log"
    );

    // LUA records go through the same path and reach the changelog as type "LUA".
    let script = "A if in_cidr(q.client, '10.0.0.0/8') then return '192.0.2.10' end";
    let (status, body) = call(
        &app,
        "POST",
        &changes,
        Some(json!({ "changes": [add("geo", "LUA", script)] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let log = log_after(&app, &zone, start).await;
    assert_eq!(
        log.last().unwrap()["payload"][format!("geo.{zone}")],
        json!([{ "type": "LUA", "ttl": 300, "data": script }])
    );

    // Deleting a name's last record logs it with an empty set, so nodes remove it.
    let (status, del) = call(
        &app,
        "POST",
        &changes,
        Some(json!({ "changes": [
            { "action": "delete", "name": "txt", "type": "TXT" },
        ]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{del}");
    let log = log_after(&app, &zone, start).await;
    assert_eq!(
        log.last().unwrap()["payload"][format!("txt.{zone}")],
        json!([])
    );

    // Records inside a hosted child zone must be changed there, not in the parent.
    let child = format!("sub.{zone}");
    let (status, _) = call(
        &app,
        "POST",
        "/zones",
        Some(json!({ "name": child, "ns": ["ns1.example.net."] })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, body) = call(
        &app,
        "POST",
        &changes,
        Some(json!({ "changes": [add("x.sub", "A", "192.0.2.1")] })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(errors(&body).contains("belongs to hosted zone"), "{body}");

    // PATCH bumps the serial and logs the new SOA.
    let (status, patched) = call(
        &app,
        "PATCH",
        &format!("/zones/{zone}"),
        Some(json!({ "expire": 7200 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{patched}");
    let log = log_after(&app, &zone, start).await;
    let soa = &log.last().unwrap()["payload"][&zone][0]["data"];
    assert!(
        soa.as_str().unwrap().ends_with(" 3600 600 7200 300"),
        "{soa}"
    );

    // Deleting zones logs delete_zone.
    for z in [&child, &zone] {
        let (status, _) = call(&app, "DELETE", &format!("/zones/{z}"), None).await;
        assert_eq!(status, StatusCode::OK);
    }
    assert_eq!(
        log_after(&app, &zone, start).await.last().unwrap()["op"],
        "delete_zone"
    );
    let (status, _) = call(&app, "GET", &format!("/zones/{zone}"), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn permissions() {
    let admin = app().await;
    let team = unique("team");
    let (zone, other) = (format!("{team}.test"), format!("other-{team}.test"));
    let changes = format!("/zones/{zone}/changes");
    for z in [&zone, &other] {
        let (status, body) = call(
            &admin,
            "POST",
            "/zones",
            Some(json!({ "name": z, "ns": ["ns1.example.net."] })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }

    // No token, or a bad one: 401 with a Bearer challenge.
    for anon in [admin.as_token(""), admin.as_token("dnsdb_nonsense")] {
        let (status, body) = call(&anon, "GET", "/zones", None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    }

    let viewer = admin
        .with_new_token(&unique("viewer-"), false, &[(&zone, "viewer")])
        .await;
    let editor = admin
        .with_new_token(&unique("editor-"), false, &[(&zone, "editor")])
        .await;
    let scripter = admin
        .with_new_token(&unique("scripter-"), false, &[(&zone, "editor:scripts")])
        .await;
    let owner = admin
        .with_new_token(
            &unique("owner-"),
            false,
            &[(&format!("*.{team}.test"), "owner")],
        )
        .await;

    // Viewer: reads its zone; other zones don't exist for it; can't change anything.
    assert_eq!(
        call(&viewer, "GET", &format!("/zones/{zone}"), None)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        call(&viewer, "GET", &format!("/zones/{other}"), None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let (_, list) = call(&viewer, "GET", "/zones", None).await;
    let names: Vec<&str> = list["zones"]
        .as_array()
        .unwrap()
        .iter()
        .map(|z| z["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, [format!("{zone}.")], "viewer sees only its zone");
    let (_, log) = call(&viewer, "GET", "/changelog?after=0&limit=10000", None).await;
    assert!(
        log["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["zone"] == format!("{zone}."))
    );
    assert!(log["next_after"].as_i64().unwrap() > 0);
    let a_record = json!({ "changes": [add("www", "A", "192.0.2.1")] });
    assert_eq!(
        call(&viewer, "POST", &changes, Some(a_record.clone()))
            .await
            .0,
        StatusCode::FORBIDDEN
    );

    // Editor: records yes; LUA scripts and zone settings no.
    let (status, body) = call(&editor, "POST", &changes, Some(a_record)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let lua = json!({ "changes": [add("geo", "LUA", "A return '192.0.2.9'")] });
    let (status, body) = call(&editor, "POST", &changes, Some(lua.clone())).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(errors(&body).contains("scripts"), "{body}");
    assert_eq!(
        call(
            &editor,
            "PATCH",
            &format!("/zones/{zone}"),
            Some(json!({ "expire": 7200 }))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(&editor, "DELETE", &format!("/zones/{zone}"), None)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &editor,
            "POST",
            &format!("/zones/{other}/changes"),
            Some(json!({ "changes": [add("x", "A", "192.0.2.1")] }))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );

    // Editor with scripts: LUA allowed, and the changelog names who did it.
    let (status, body) = call(&scripter, "POST", &changes, Some(lua)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let entry = log_after(&admin, &format!("{zone}."), 0)
        .await
        .pop()
        .unwrap();
    let (_, me) = call(&scripter, "GET", "/whoami", None).await;
    assert_eq!(entry["actor"], me["name"]);
    assert_eq!(me["grants"][0]["scripts"], true);

    // Owner of *.team.test: creates zones below it, not the apex itself or elsewhere.
    let sub = format!("a.{team}.test");
    let (status, body) = call(
        &owner,
        "POST",
        "/zones",
        Some(json!({ "name": sub, "ns": ["ns1.example.net."] })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(
        call(
            &owner,
            "POST",
            "/zones",
            Some(json!({ "name": format!("{team}.test"), "ns": ["ns1.example.net."] }))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &owner,
            "POST",
            "/zones",
            Some(json!({ "name": format!("x{team}.test"), "ns": ["ns1.example.net."] }))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &owner,
            "PATCH",
            &format!("/zones/{sub}"),
            Some(json!({ "expire": 7200 }))
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(&owner, "DELETE", &format!("/zones/{sub}"), None)
            .await
            .0,
        StatusCode::OK
    );

    // Token management is admin-only; tokens list without secrets; revoked tokens stop working.
    assert_eq!(
        call(&owner, "GET", "/tokens", None).await.0,
        StatusCode::FORBIDDEN
    );
    let name = unique("made-by-api-");
    let (status, made) = call(
        &admin,
        "POST",
        "/tokens",
        Some(json!({
            "name": name, "grants": [{ "pattern": zone, "role": "viewer" }],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{made}");
    let fresh = admin.as_token(made["token"].as_str().unwrap());
    assert_eq!(
        call(&fresh, "GET", &format!("/zones/{zone}"), None).await.0,
        StatusCode::OK
    );
    let (_, tokens) = call(&admin, "GET", "/tokens", None).await;
    assert!(
        !tokens.to_string().contains(made["token"].as_str().unwrap()),
        "secret leaked in listing"
    );
    assert!(
        tokens["tokens"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == name)
    );
    assert_eq!(
        call(&admin, "DELETE", &format!("/tokens/{name}"), None)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        call(&fresh, "GET", &format!("/zones/{zone}"), None).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (status, body) = call(&admin, "POST", "/tokens", Some(json!({ "name": name }))).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}"); // names stay taken after revocation

    for z in [&zone, &other] {
        assert_eq!(
            call(&admin, "DELETE", &format!("/zones/{z}"), None).await.0,
            StatusCode::OK
        );
    }
}
