//! REST API. Every write is one transaction that validates the result, bumps the zone's
//! SOA serial, and appends one changelog entry; nothing is half-applied. Every request is
//! authenticated and authorized per zone (see `auth.rs`).

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use axum::extract::{Path, Query, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use hickory_proto::rr::{Name, RecordType};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{FromRow, PgConnection, PgPool};

use crate::auth::{self, Caller, Grant, Role};
use crate::{spf, validate};

// ponytail: one global lock serializes changelog inserts so seq order == commit order.
// Ceiling: total write throughput; switch to a per-zone outbox if that ever matters.
const CHANGELOG_LOCK: i64 = 0x646e_735f_6c6f_67; // "dns_log"
/// Changes per changeset: big enough for any real edit, small enough to bound one transaction.
const MAX_CHANGES: usize = 1000;
// ponytail: global limits only. Per-client rate limiting and TLS belong in the reverse proxy
// in front of this; slow request headers are also the proxy's job.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONCURRENT_REQUESTS: usize = 64;

pub fn router(pool: PgPool) -> Router {
    Router::new()
        .route("/zones", get(list_zones).post(create_zone))
        .route(
            "/zones/{zone}",
            get(get_zone).patch(patch_zone).delete(delete_zone),
        )
        .route("/zones/{zone}/changes", post(apply_changes))
        .route(
            "/zones/{zone}/spf/{name}",
            get(get_spf).put(put_spf).delete(delete_spf),
        )
        .route("/changelog", get(changelog))
        .route("/whoami", get(whoami))
        .route("/tokens", get(list_tokens).post(create_token))
        .route("/tokens/{name}", axum::routing::delete(revoke_token))
        .layer(middleware::from_fn(limits))
        .with_state(pool)
}

/// Sheds load past MAX_CONCURRENT_REQUESTS and cuts off requests (body reads included) that
/// run longer than REQUEST_TIMEOUT. A cut-off request's transaction is rolled back.
async fn limits(req: Request, next: Next) -> Response {
    static SLOTS: tokio::sync::Semaphore =
        tokio::sync::Semaphore::const_new(MAX_CONCURRENT_REQUESTS);
    let unavailable = |e: &str| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "errors": [e] })),
        )
            .into_response()
    };
    let Ok(_slot) = SLOTS.try_acquire() else {
        return unavailable("too many concurrent requests; retry shortly");
    };
    tokio::time::timeout(REQUEST_TIMEOUT, next.run(req))
        .await
        .unwrap_or_else(|_| unavailable("request timed out"))
}

// ---------- errors ----------

#[derive(Debug)]
pub enum ApiError {
    BadRequest(Vec<String>),
    Unauthorized(String),
    Forbidden(String),
    NotFound(String),
    Conflict(String),
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, errors) = match self {
            ApiError::BadRequest(e) => (StatusCode::BAD_REQUEST, e),
            ApiError::Unauthorized(e) => {
                let body = Json(json!({ "errors": [e] }));
                return (
                    StatusCode::UNAUTHORIZED,
                    [(header::WWW_AUTHENTICATE, "Bearer")],
                    body,
                )
                    .into_response();
            }
            ApiError::Forbidden(e) => (StatusCode::FORBIDDEN, vec![e]),
            ApiError::NotFound(e) => (StatusCode::NOT_FOUND, vec![e]),
            ApiError::Conflict(e) => (StatusCode::CONFLICT, vec![e]),
            ApiError::Internal(e) => {
                eprintln!("internal error: {e}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    vec!["internal error".into()],
                )
            }
        };
        (status, Json(json!({ "errors": errors }))).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        ApiError::Internal(e.to_string())
    }
}

fn bad(e: impl Into<String>) -> ApiError {
    ApiError::BadRequest(vec![e.into()])
}

type ApiResult<T> = Result<T, ApiError>;

// ---------- rows ----------

#[derive(FromRow)]
struct ZoneRow {
    id: i64,
    name: String,
    default_ttl: i32,
    mname: String,
    rname: String,
    serial: i64,
    refresh: i32,
    retry: i32,
    expire: i32,
    minimum: i32,
}

impl ZoneRow {
    fn soa_data(&self) -> String {
        let z = self;
        format!(
            "{} {} {} {} {} {} {}",
            z.mname, z.rname, z.serial, z.refresh, z.retry, z.expire, z.minimum
        )
    }

    fn json(&self) -> Value {
        json!({
            "name": self.name,
            "default_ttl": self.default_ttl,
            "serial": self.serial,
            "soa": {
                "mname": self.mname, "rname": self.rname, "refresh": self.refresh,
                "retry": self.retry, "expire": self.expire, "minimum": self.minimum,
            },
        })
    }
}

#[derive(FromRow)]
struct RecordRow {
    name: String,
    #[sqlx(rename = "type")]
    rtype: String,
    ttl: i32,
    data: String,
}

async fn lock_zone(db: &mut PgConnection, zone: &Name) -> ApiResult<ZoneRow> {
    sqlx::query_as::<_, ZoneRow>(
        "SELECT id, name, default_ttl, mname, rname, serial, refresh, retry, expire, minimum
         FROM zones WHERE name = $1 FOR UPDATE",
    )
    .bind(zone.to_string())
    .fetch_optional(&mut *db)
    .await?
    .ok_or_else(|| ApiError::NotFound(format!("zone {zone} not found")))
}

/// Bumps the serial (RFC 1982 wraparound), then appends a changelog entry carrying the
/// complete new record set of every name in `names` plus the apex (whose SOA changed).
async fn commit_change(
    db: &mut PgConnection,
    zone: &ZoneRow,
    mut names: BTreeSet<String>,
    actor: &str,
) -> ApiResult<Value> {
    let zone: ZoneRow = sqlx::query_as(
        "UPDATE zones SET serial = (serial + 1) % 4294967296 WHERE id = $1
         RETURNING id, name, default_ttl, mname, rname, serial, refresh, retry, expire, minimum",
    )
    .bind(zone.id)
    .fetch_one(&mut *db)
    .await?;
    names.insert(zone.name.clone());

    let names: Vec<String> = names.into_iter().collect();
    let rows: Vec<RecordRow> = sqlx::query_as(
        "SELECT name, type, ttl, data FROM records
         WHERE zone_id = $1 AND name = ANY($2) ORDER BY name, type, data",
    )
    .bind(zone.id)
    .bind(&names)
    .fetch_all(&mut *db)
    .await?;

    let mut payload: BTreeMap<String, Vec<Value>> =
        names.into_iter().map(|n| (n, vec![])).collect();
    payload.get_mut(&zone.name).unwrap().push(json!({
        "type": "SOA", "ttl": zone.default_ttl, "data": zone.soa_data(),
    }));
    for r in rows {
        payload
            .get_mut(&r.name)
            .unwrap()
            .push(json!({ "type": r.rtype, "ttl": r.ttl, "data": r.data }));
    }

    append_changelog(
        db,
        &zone.name,
        Some(zone.serial),
        "names",
        json!(payload),
        actor,
    )
    .await
}

async fn append_changelog(
    db: &mut PgConnection,
    zone: &str,
    serial: Option<i64>,
    op: &str,
    payload: Value,
    actor: &str,
) -> ApiResult<Value> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(CHANGELOG_LOCK)
        .execute(&mut *db)
        .await?;
    let seq: i64 = sqlx::query_scalar(
        "INSERT INTO changelog (zone, serial, op, payload, actor) VALUES ($1, $2, $3, $4, $5)
         RETURNING seq",
    )
    .bind(zone)
    .bind(serial)
    .bind(op)
    .bind(payload)
    .bind(actor)
    .fetch_one(&mut *db)
    .await?;
    Ok(json!({ "zone": zone, "seq": seq, "serial": serial }))
}

// ---------- zones ----------

/// The zones the caller can see, plus `seq`: the changelog head in the same snapshot. A node
/// whose applied seq equals `seq` can compare serials without a change in flight causing a
/// false mismatch.
async fn list_zones(caller: Caller, State(pool): State<PgPool>) -> ApiResult<Json<Value>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *tx)
        .await?;
    let zones: Vec<ZoneRow> = sqlx::query_as(
        "SELECT id, name, default_ttl, mname, rname, serial, refresh, retry, expire, minimum
         FROM zones ORDER BY name",
    )
    .fetch_all(&mut *tx)
    .await?;
    let seq: i64 = sqlx::query_scalar("SELECT COALESCE(max(seq), 0) FROM changelog")
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    let visible = |z: &&ZoneRow| {
        caller.sees_all() || validate::parse_zone(&z.name).is_ok_and(|n| caller.role(&n).is_some())
    };
    Ok(Json(json!({
        "seq": seq,
        "zones": zones.iter().filter(visible).map(ZoneRow::json).collect::<Vec<_>>(),
    })))
}

async fn get_zone(
    caller: Caller,
    State(pool): State<PgPool>,
    Path(zone): Path<String>,
) -> ApiResult<Json<Value>> {
    let zone = validate::parse_zone(&zone).map_err(bad)?;
    caller.require(&zone, Role::Viewer)?;
    // One snapshot, so the serial always matches the records (nodes re-fetch from here).
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *tx)
        .await?;
    let row: ZoneRow = sqlx::query_as(
        "SELECT id, name, default_ttl, mname, rname, serial, refresh, retry, expire, minimum
         FROM zones WHERE name = $1",
    )
    .bind(zone.to_string())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::NotFound(format!("zone {zone} not found")))?;
    let records: Vec<RecordRow> = sqlx::query_as(
        "SELECT name, type, ttl, data FROM records WHERE zone_id = $1 ORDER BY name, type, data",
    )
    .bind(row.id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    let mut body = row.json();
    body["records"] = records
        .iter()
        .map(|r| json!({ "name": r.name, "type": r.rtype, "ttl": r.ttl, "data": r.data }))
        .collect();
    Ok(Json(body))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct SoaFields {
    mname: Option<String>,
    rname: Option<String>,
    refresh: Option<i32>,
    retry: Option<i32>,
    expire: Option<i32>,
    minimum: Option<i32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateZone {
    name: String,
    ns: Vec<String>,
    default_ttl: Option<i64>,
    #[serde(default)]
    soa: SoaFields,
}

/// Validates the SOA fields that were supplied; returns normalized mname/rname.
fn check_soa(soa: &SoaFields) -> Result<(Option<String>, Option<String>), Vec<String>> {
    let mut errors = vec![];
    let mut fqdn = |field: &str, v: &Option<String>| -> Option<String> {
        let v = v.as_ref()?;
        match validate::parse_data(RecordType::NS, v) {
            Ok(n) => Some(n),
            Err(_) => {
                errors.push(format!("soa.{field} {v:?} must be a fully qualified name"));
                None
            }
        }
    };
    let mname = fqdn("mname", &soa.mname);
    let rname = fqdn("rname", &soa.rname);
    for (field, v, min) in [
        ("refresh", soa.refresh, 1),
        ("retry", soa.retry, 1),
        ("expire", soa.expire, 1),
        ("minimum", soa.minimum, 0),
    ] {
        if v.is_some_and(|v| v < min) {
            errors.push(format!("soa.{field} must be at least {min}"));
        }
    }
    if errors.is_empty() {
        Ok((mname, rname))
    } else {
        Err(errors)
    }
}

async fn create_zone(
    caller: Caller,
    State(pool): State<PgPool>,
    Json(req): Json<CreateZone>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let zone = validate::parse_zone(&req.name).map_err(bad)?;
    if caller.role(&zone) < Some(Role::Owner) {
        return Err(ApiError::Forbidden(format!(
            "token {:?} can't create zone {zone}: that needs owner on a pattern covering it",
            caller.name
        )));
    }
    let mut errors = vec![];
    let (mname, rname) = check_soa(&req.soa).unwrap_or_else(|e| {
        errors.extend(e);
        (None, None)
    });
    if req.ns.is_empty() {
        errors.push("ns: at least one name server is required".into());
    }
    let ns: Vec<String> = req
        .ns
        .iter()
        .filter_map(|n| {
            validate::parse_data(RecordType::NS, n)
                .map_err(|e| errors.push(e))
                .ok()
        })
        .collect();
    let default_ttl = match req.default_ttl.map(validate::parse_ttl).transpose() {
        Ok(ttl) => ttl.unwrap_or(300) as i32,
        Err(e) => {
            errors.push(e);
            0
        }
    };
    if !errors.is_empty() {
        return Err(ApiError::BadRequest(errors));
    }
    let mname = mname.unwrap_or_else(|| ns[0].clone());
    let rname = rname.unwrap_or_else(|| format!("hostmaster.{zone}"));

    let mut tx = pool.begin().await?;
    // A new zone takes over every name at and below its apex. If a parent zone already has
    // records there, the caller must be able to edit that parent: owning `*.example.com` must
    // not let a token capture names that live in someone else's `example.com`.
    let parents: Vec<String> = sqlx::query_scalar(
        "SELECT z.name FROM zones z WHERE right($1, length(z.name) + 1) = '.' || z.name
         AND EXISTS (SELECT 1 FROM records r WHERE r.zone_id = z.id
                     AND (r.name = $1 OR right(r.name, length($1) + 1) = '.' || $1))",
    )
    .bind(zone.to_string())
    .fetch_all(&mut *tx)
    .await?;
    for parent in parents.iter().filter_map(|p| validate::parse_zone(p).ok()) {
        if caller.role(&parent) < Some(Role::Editor) {
            return Err(ApiError::Forbidden(format!(
                "zone {zone} would take over existing records of a parent zone; that needs editor on the parent"
            )));
        }
    }
    let id: Option<i64> = sqlx::query_scalar(
        "INSERT INTO zones (name, default_ttl, mname, rname, serial, refresh, retry, expire, minimum)
         VALUES ($1, $2, $3, $4, 0,
                 COALESCE($5, 3600), COALESCE($6, 600), COALESCE($7, 604800), COALESCE($8, 300))
         ON CONFLICT (name) DO NOTHING RETURNING id",
    )
    .bind(zone.to_string())
    .bind(default_ttl)
    .bind(&mname)
    .bind(&rname)
    .bind(req.soa.refresh)
    .bind(req.soa.retry)
    .bind(req.soa.expire)
    .bind(req.soa.minimum)
    .fetch_optional(&mut *tx)
    .await?;
    if id.is_none() {
        return Err(ApiError::Conflict(format!("zone {zone} already exists")));
    }
    for n in &ns {
        sqlx::query(
            "INSERT INTO records (zone_id, name, type, ttl, data) VALUES ($1, $2, 'NS', $3, $4)
             ON CONFLICT DO NOTHING",
        )
        .bind(id)
        .bind(zone.to_string())
        .bind(default_ttl)
        .bind(n)
        .execute(&mut *tx)
        .await?;
    }
    // Serial starts at 0 so this first committed change makes it 1.
    let row = lock_zone(&mut tx, &zone).await?;
    let result = commit_change(&mut tx, &row, BTreeSet::new(), &caller.name).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(result)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchZone {
    default_ttl: Option<i64>,
    #[serde(flatten)]
    soa: SoaFields,
}

async fn patch_zone(
    caller: Caller,
    State(pool): State<PgPool>,
    Path(zone): Path<String>,
    Json(req): Json<PatchZone>,
) -> ApiResult<Json<Value>> {
    let zone = validate::parse_zone(&zone).map_err(bad)?;
    caller.require(&zone, Role::Owner)?;
    let (mname, rname) = check_soa(&req.soa).map_err(ApiError::BadRequest)?;
    let default_ttl = req
        .default_ttl
        .map(validate::parse_ttl)
        .transpose()
        .map_err(bad)?;

    let mut tx = pool.begin().await?;
    let row = lock_zone(&mut tx, &zone).await?;
    sqlx::query(
        "UPDATE zones SET default_ttl = COALESCE($2, default_ttl),
            mname = COALESCE($3, mname), rname = COALESCE($4, rname),
            refresh = COALESCE($5, refresh), retry = COALESCE($6, retry),
            expire = COALESCE($7, expire), minimum = COALESCE($8, minimum)
         WHERE id = $1",
    )
    .bind(row.id)
    .bind(default_ttl.map(|t| t as i32))
    .bind(mname)
    .bind(rname)
    .bind(req.soa.refresh)
    .bind(req.soa.retry)
    .bind(req.soa.expire)
    .bind(req.soa.minimum)
    .execute(&mut *tx)
    .await?;
    let result = commit_change(&mut tx, &row, BTreeSet::new(), &caller.name).await?;
    tx.commit().await?;
    Ok(Json(result))
}

async fn delete_zone(
    caller: Caller,
    State(pool): State<PgPool>,
    Path(zone): Path<String>,
) -> ApiResult<Json<Value>> {
    let zone = validate::parse_zone(&zone).map_err(bad)?;
    caller.require(&zone, Role::Owner)?;
    let mut tx = pool.begin().await?;
    let row = lock_zone(&mut tx, &zone).await?;
    sqlx::query("DELETE FROM zones WHERE id = $1")
        .bind(row.id)
        .execute(&mut *tx)
        .await?;
    let result = append_changelog(
        &mut tx,
        &row.name,
        None,
        "delete_zone",
        json!({}),
        &caller.name,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(result))
}

// ---------- changes ----------

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "lowercase", deny_unknown_fields)]
enum Change {
    Add {
        name: String,
        #[serde(rename = "type")]
        rtype: String,
        ttl: Option<i64>,
        data: String,
    },
    /// Without `data`, deletes the whole RRset.
    Delete {
        name: String,
        #[serde(rename = "type")]
        rtype: String,
        data: Option<String>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangeSet {
    changes: Vec<Change>,
}

enum Parsed {
    Add {
        name: Name,
        rtype: RecordType,
        ttl: Option<u32>,
        data: String,
    },
    Delete {
        name: Name,
        rtype: RecordType,
        data: Option<String>,
    },
}

fn parse_change(zone: &Name, change: &Change) -> Result<Parsed, String> {
    Ok(match change {
        Change::Add {
            name,
            rtype,
            ttl,
            data,
        } => {
            let rtype = validate::parse_type(rtype)?;
            Parsed::Add {
                name: validate::parse_name(name, zone)?,
                rtype,
                ttl: ttl.map(validate::parse_ttl).transpose()?,
                data: validate::parse_data(rtype, data)?,
            }
        }
        Change::Delete { name, rtype, data } => {
            let rtype = validate::parse_type(rtype)?;
            Parsed::Delete {
                name: validate::parse_name(name, zone)?,
                rtype,
                data: data
                    .as_deref()
                    .map(|d| validate::parse_data(rtype, d))
                    .transpose()?,
            }
        }
    })
}

async fn apply_changes(
    caller: Caller,
    State(pool): State<PgPool>,
    Path(zone): Path<String>,
    Json(req): Json<ChangeSet>,
) -> ApiResult<Json<Value>> {
    let zone = validate::parse_zone(&zone).map_err(bad)?;
    caller.require(&zone, Role::Editor)?;
    if req.changes.is_empty() {
        return Err(bad("changes: at least one change is required"));
    }
    if req.changes.len() > MAX_CHANGES {
        return Err(bad(format!(
            "changes: at most {MAX_CHANGES} per changeset; split it up"
        )));
    }
    let mut errors = vec![];
    let parsed: Vec<Parsed> = req
        .changes
        .iter()
        .enumerate()
        .filter_map(|(i, c)| {
            parse_change(&zone, c)
                .map_err(|e| errors.push(format!("changes[{i}]: {e}")))
                .ok()
        })
        .collect();
    if !errors.is_empty() {
        return Err(ApiError::BadRequest(errors));
    }
    let touches_scripts = parsed.iter().any(|p| match p {
        Parsed::Add { rtype, .. } | Parsed::Delete { rtype, .. } => *rtype == validate::LUA,
    });
    if touches_scripts && !caller.can_script(&zone) {
        return Err(ApiError::Forbidden(format!(
            "token {:?} may not add or delete LUA records in {zone}: that needs the scripts grant",
            caller.name
        )));
    }

    let mut tx = pool.begin().await?;
    let result = apply_parsed(&mut tx, &zone, &parsed, &caller.name).await?;
    tx.commit().await?;
    Ok(Json(result))
}

/// Applies parsed changes inside the caller's transaction, validates every touched name, and
/// commits them as one changelog entry. Any error leaves the transaction to be rolled back.
async fn apply_parsed(
    tx: &mut PgConnection,
    zone: &Name,
    parsed: &[Parsed],
    actor: &str,
) -> ApiResult<Value> {
    let mut errors = vec![];
    let row = lock_zone(tx, zone).await?;
    let mut touched = BTreeSet::new();

    for (i, change) in parsed.iter().enumerate() {
        match change {
            Parsed::Add {
                name,
                rtype,
                ttl,
                data,
            } => {
                // TTL: explicit, else the existing RRset's, else the zone default.
                let ttl: i32 = match ttl {
                    Some(t) => *t as i32,
                    None => sqlx::query_scalar(
                        "SELECT ttl FROM records WHERE zone_id = $1 AND name = $2 AND type = $3 LIMIT 1",
                    )
                    .bind(row.id)
                    .bind(name.to_string())
                    .bind(validate::type_name(*rtype))
                    .fetch_optional(&mut *tx)
                    .await?
                    .unwrap_or(row.default_ttl),
                };
                sqlx::query(
                    "INSERT INTO records (zone_id, name, type, ttl, data) VALUES ($1, $2, $3, $4, $5)
                     ON CONFLICT (zone_id, name, type, data) DO UPDATE SET ttl = EXCLUDED.ttl",
                )
                .bind(row.id)
                .bind(name.to_string())
                .bind(validate::type_name(*rtype))
                .bind(ttl)
                .bind(data)
                .execute(&mut *tx)
                .await?;
                touched.insert(name.to_string());
            }
            Parsed::Delete { name, rtype, data } => {
                let deleted = sqlx::query(
                    "DELETE FROM records WHERE zone_id = $1 AND name = $2 AND type = $3
                     AND ($4::text IS NULL OR data = $4)",
                )
                .bind(row.id)
                .bind(name.to_string())
                .bind(validate::type_name(*rtype))
                .bind(data)
                .execute(&mut *tx)
                .await?
                .rows_affected();
                if deleted == 0 {
                    errors.push(format!(
                        "changes[{i}]: no matching {rtype} record at {name}"
                    ));
                }
                touched.insert(name.to_string());
            }
        }
    }

    // Validate the resulting state of every touched name.
    let children: Vec<String> =
        sqlx::query_scalar("SELECT name FROM zones WHERE right(name, length($1) + 1) = '.' || $1")
            .bind(&row.name)
            .fetch_all(&mut *tx)
            .await?;
    let children: Vec<Name> = children
        .iter()
        .filter_map(|c| validate::parse_zone(c).ok())
        .collect();

    for name in &touched {
        let records: Vec<(String, i32, String)> =
            sqlx::query_as("SELECT type, ttl, data FROM records WHERE zone_id = $1 AND name = $2")
                .bind(row.id)
                .bind(name)
                .fetch_all(&mut *tx)
                .await?;
        let owner = validate::parse_zone(name).map_err(bad)?;
        if !records.is_empty() {
            if let Some(child) = children.iter().find(|c| c.zone_of(&owner)) {
                errors.push(format!(
                    "{name} belongs to hosted zone {child}; change it there"
                ));
            }
        }
        let records: Vec<(RecordType, u32, &str)> = records
            .iter()
            .filter_map(|(t, ttl, data)| {
                Some((validate::parse_type(t).ok()?, *ttl as u32, data.as_str()))
            })
            .collect();
        errors.extend(validate::check_name(zone, &owner, &records));
    }

    if !errors.is_empty() {
        return Err(ApiError::BadRequest(errors)); // the caller's tx rolls back
    }
    commit_change(tx, &row, touched, actor).await
}

// ---------- managed SPF ----------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SpfPolicy {
    senders: Vec<String>,
    qualifier: Option<String>,
}

/// Makes the managed TXT records for `name` (its `v=spf1` record and the `_spfN` chunks)
/// match `desired`, as one change. Other TXT records at `name` are left alone. Returns
/// `None` when nothing differs, so refreshes don't bump the serial.
async fn sync_spf_records(
    tx: &mut PgConnection,
    zone: &Name,
    name: &Name,
    desired: &[(String, String)],
    actor: &str,
) -> ApiResult<Option<Value>> {
    let row = lock_zone(tx, zone).await?;
    let existing: Vec<(String, String)> = sqlx::query_as(
        "SELECT name, data FROM records WHERE zone_id = $1 AND type = 'TXT'
         AND ((name = $2 AND lower(data) LIKE '\"v=spf1%') OR name = ANY($3))",
    )
    .bind(row.id)
    .bind(name.to_string())
    .bind(spf::chunk_names(name))
    .fetch_all(&mut *tx)
    .await?;
    let mut want = vec![];
    for (owner, text) in desired {
        let data = validate::parse_data(RecordType::TXT, &spf::txt_data(text)).map_err(bad)?;
        want.push((owner.clone(), data));
    }
    let to_name = |owner: &str| validate::parse_name(owner, zone).map_err(bad);
    let mut parsed = vec![];
    for (owner, data) in existing.iter().filter(|r| !want.contains(r)) {
        parsed.push(Parsed::Delete {
            name: to_name(owner)?,
            rtype: RecordType::TXT,
            data: Some(data.clone()),
        });
    }
    for (owner, data) in want.iter().filter(|r| !existing.contains(r)) {
        parsed.push(Parsed::Add {
            name: to_name(owner)?,
            rtype: RecordType::TXT,
            ttl: None,
            data: data.clone(),
        });
    }
    if parsed.is_empty() {
        return Ok(None);
    }
    apply_parsed(tx, zone, &parsed, actor).await.map(Some)
}

fn spf_path(caller: &Caller, zone: &str, name: &str, role: Role) -> ApiResult<(Name, Name)> {
    let zone = validate::parse_zone(zone).map_err(bad)?;
    caller.require(&zone, role)?;
    let name = validate::parse_name(name, &zone).map_err(bad)?;
    Ok((zone, name))
}

/// Flattens the senders now; on success stores the policy and publishes its records.
async fn put_spf(
    caller: Caller,
    State(pool): State<PgPool>,
    Path((zone, name)): Path<(String, String)>,
    Json(req): Json<SpfPolicy>,
) -> ApiResult<Json<Value>> {
    let (zone, name) = spf_path(&caller, &zone, &name, Role::Editor)?;
    let qualifier = req.qualifier.unwrap_or_else(|| "~all".into());
    if !spf::QUALIFIERS.contains(&qualifier.as_str()) {
        return Err(bad(format!(
            "qualifier must be one of {:?}",
            spf::QUALIFIERS
        )));
    }
    if req.senders.is_empty() {
        return Err(bad("senders: at least one sender is required"));
    }
    let terms = spf::flatten_live(&req.senders).await.map_err(bad)?;
    let desired = spf::render(&name, &terms, &qualifier).map_err(bad)?;

    let mut tx = pool.begin().await?;
    let change = sync_spf_records(&mut tx, &zone, &name, &desired, &caller.name).await?;
    sqlx::query(
        "INSERT INTO spf_policies (zone_id, name, senders, qualifier, terms)
         SELECT id, $2, $3, $4, $5 FROM zones WHERE name = $1
         ON CONFLICT (zone_id, name) DO UPDATE SET senders = EXCLUDED.senders,
           qualifier = EXCLUDED.qualifier, terms = EXCLUDED.terms, last_error = NULL,
           updated_at = now()",
    )
    .bind(zone.to_string())
    .bind(name.to_string())
    .bind(&req.senders)
    .bind(&qualifier)
    .bind(&terms)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(json!({
        "name": name.to_string(), "terms": terms, "records": desired.len(), "change": change,
    })))
}

async fn get_spf(
    caller: Caller,
    State(pool): State<PgPool>,
    Path((zone, name)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let (zone, name) = spf_path(&caller, &zone, &name, Role::Viewer)?;
    let (senders, qualifier, terms, last_error, updated_at): (
        Vec<String>,
        String,
        Vec<String>,
        Option<String>,
        String,
    ) = sqlx::query_as(
        "SELECT p.senders, p.qualifier, p.terms, p.last_error, p.updated_at::text
         FROM spf_policies p JOIN zones z ON z.id = p.zone_id WHERE z.name = $1 AND p.name = $2",
    )
    .bind(zone.to_string())
    .bind(name.to_string())
    .fetch_optional(&pool)
    .await?
    .ok_or_else(|| ApiError::NotFound(format!("no SPF policy at {name}")))?;
    Ok(Json(json!({
        "name": name.to_string(), "senders": senders, "qualifier": qualifier, "terms": terms,
        "last_error": last_error, "updated_at": updated_at,
    })))
}

/// Removes the policy and the records it published.
async fn delete_spf(
    caller: Caller,
    State(pool): State<PgPool>,
    Path((zone, name)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let (zone, name) = spf_path(&caller, &zone, &name, Role::Editor)?;
    let mut tx = pool.begin().await?;
    let deleted = sqlx::query(
        "DELETE FROM spf_policies p USING zones z
         WHERE z.id = p.zone_id AND z.name = $1 AND p.name = $2",
    )
    .bind(zone.to_string())
    .bind(name.to_string())
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if deleted == 0 {
        return Err(ApiError::NotFound(format!("no SPF policy at {name}")));
    }
    let change = sync_spf_records(&mut tx, &zone, &name, &[], &caller.name).await?;
    tx.commit().await?;
    Ok(Json(json!({ "name": name.to_string(), "change": change })))
}

/// Re-flattens every policy and publishes whatever changed, as actor `spf-refresh`. A
/// policy that fails to flatten keeps its last good records and gets `last_error`, so a
/// sender's DNS outage never removes authorized addresses.
pub async fn refresh_spf(pool: &PgPool) -> Result<(), sqlx::Error> {
    let policies: Vec<(String, String, Vec<String>, String)> = sqlx::query_as(
        "SELECT z.name, p.name, p.senders, p.qualifier
         FROM spf_policies p JOIN zones z ON z.id = p.zone_id ORDER BY z.name, p.name",
    )
    .fetch_all(pool)
    .await?;
    for (zone, name, senders, qualifier) in policies {
        let (Ok(zone), Ok(name)) = (validate::parse_zone(&zone), validate::parse_zone(&name))
        else {
            continue;
        };
        let result = match spf::flatten_live(&senders).await {
            Ok(terms) => spf::render(&name, &terms, &qualifier).map(|d| (terms, d)),
            Err(e) => Err(e),
        };
        let mut tx = pool.begin().await?;
        // Skip a policy deleted or replaced while we were resolving.
        let current: Option<i64> = sqlx::query_scalar(
            "SELECT p.zone_id FROM spf_policies p JOIN zones z ON z.id = p.zone_id
             WHERE z.name = $1 AND p.name = $2 AND p.senders = $3 AND p.qualifier = $4
             FOR UPDATE OF p",
        )
        .bind(zone.to_string())
        .bind(name.to_string())
        .bind(&senders)
        .bind(&qualifier)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(zone_id) = current else { continue };
        let error = match result {
            Ok((terms, desired)) => {
                match sync_spf_records(&mut tx, &zone, &name, &desired, "spf-refresh").await {
                    Ok(_) => {
                        sqlx::query(
                            "UPDATE spf_policies SET terms = $3, last_error = NULL, updated_at = now()
                             WHERE zone_id = $1 AND name = $2",
                        )
                        .bind(zone_id)
                        .bind(name.to_string())
                        .bind(&terms)
                        .execute(&mut *tx)
                        .await?;
                        tx.commit().await?;
                        continue;
                    }
                    Err(e) => {
                        tx.rollback().await?;
                        tx = pool.begin().await?;
                        format!("{e:?}")
                    }
                }
            }
            Err(e) => e,
        };
        eprintln!("spf refresh of {name}: {error}");
        sqlx::query("UPDATE spf_policies SET last_error = $3 WHERE zone_id = $1 AND name = $2")
            .bind(zone_id)
            .bind(name.to_string())
            .bind(&error)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
    }
    Ok(())
}

// ---------- changelog ----------

#[derive(Deserialize)]
struct ChangelogQuery {
    #[serde(default)]
    after: i64,
    limit: Option<i64>,
}

/// Entries with seq > `after`, oldest first, for zones the caller can see. `next_after` is
/// the last seq scanned: pass it as `after` to continue, even when filtering hid entries.
/// Nodes poll this (Stage 3) with a token that sees every zone.
async fn changelog(
    caller: Caller,
    State(pool): State<PgPool>,
    Query(q): Query<ChangelogQuery>,
) -> ApiResult<Json<Value>> {
    let limit = q.limit.unwrap_or(1000).clamp(1, 10_000);
    let rows: Vec<(
        i64,
        String,
        Option<i64>,
        String,
        Value,
        Option<String>,
        String,
    )> = sqlx::query_as(
        "SELECT seq, zone, serial, op, payload, actor, created_at::text FROM changelog
         WHERE seq > $1 ORDER BY seq LIMIT $2",
    )
    .bind(q.after)
    .bind(limit)
    .fetch_all(&pool)
    .await?;
    let next_after = rows.last().map_or(q.after, |r| r.0);
    let entries: Vec<Value> = rows
        .into_iter()
        .filter(|r| {
            caller.sees_all() || validate::parse_zone(&r.1).is_ok_and(|z| caller.role(&z).is_some())
        })
        .map(|(seq, zone, serial, op, payload, actor, created_at)| {
            json!({ "seq": seq, "zone": zone, "serial": serial, "op": op, "payload": payload,
                    "actor": actor, "created_at": created_at })
        })
        .collect();
    Ok(Json(
        json!({ "entries": entries, "next_after": next_after }),
    ))
}

// ---------- tokens ----------

async fn whoami(caller: Caller) -> Json<Value> {
    Json(json!({ "name": caller.name, "admin": caller.admin, "grants": caller.grants }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateToken {
    name: String,
    #[serde(default)]
    admin: bool,
    #[serde(default)]
    grants: Vec<Grant>,
    expires_in_days: Option<u32>,
}

async fn create_token(
    caller: Caller,
    State(pool): State<PgPool>,
    Json(req): Json<CreateToken>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    caller.require_admin()?;
    let grants = req
        .grants
        .iter()
        .map(|g| Grant::new(&g.pattern, g.role, g.scripts))
        .collect::<Result<Vec<_>, _>>()
        .map_err(bad)?;
    let secret = auth::create_token(
        &pool,
        &req.name,
        req.admin,
        &grants,
        None,
        req.expires_in_days,
        false,
    )
    .await?
    .expect("if_missing is false");
    Ok((
        StatusCode::CREATED,
        Json(json!({ "name": req.name, "token": secret, "grants": grants })),
    ))
}

#[derive(FromRow)]
struct TokenInfo {
    id: i64,
    name: String,
    prefix: String,
    admin: bool,
    created_at: String,
    last_used_at: Option<String>,
    expires_at: Option<String>,
    revoked_at: Option<String>,
}

/// Every token, without secrets.
async fn list_tokens(caller: Caller, State(pool): State<PgPool>) -> ApiResult<Json<Value>> {
    caller.require_admin()?;
    let rows: Vec<TokenInfo> = sqlx::query_as(
        "SELECT id, name, prefix, admin, created_at::text, last_used_at::text, expires_at::text,
                revoked_at::text
         FROM tokens ORDER BY name",
    )
    .fetch_all(&pool)
    .await?;
    let mut tokens = vec![];
    for t in rows {
        tokens.push(json!({
            "name": t.name, "prefix": t.prefix, "admin": t.admin,
            "grants": auth::load_grants(&pool, t.id).await?,
            "created_at": t.created_at, "last_used_at": t.last_used_at,
            "expires_at": t.expires_at, "revoked_at": t.revoked_at,
        }));
    }
    Ok(Json(json!({ "tokens": tokens })))
}

/// Revokes a token. The row stays, so changelog actors keep naming a known token.
async fn revoke_token(
    caller: Caller,
    State(pool): State<PgPool>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    caller.require_admin()?;
    let revoked =
        sqlx::query("UPDATE tokens SET revoked_at = now() WHERE name = $1 AND revoked_at IS NULL")
            .bind(&name)
            .execute(&pool)
            .await?
            .rows_affected();
    if revoked == 0 {
        return Err(ApiError::NotFound(format!(
            "no active token named {name:?}"
        )));
    }
    Ok(Json(json!({ "revoked": name })))
}
