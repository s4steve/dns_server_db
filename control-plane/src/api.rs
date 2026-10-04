//! REST API. Every write is one transaction that validates the result, bumps the zone's
//! SOA serial, and appends one changelog entry; nothing is half-applied.

use std::collections::{BTreeMap, BTreeSet};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use hickory_proto::rr::{Name, RecordType};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{FromRow, PgConnection, PgPool};

use crate::validate;

// ponytail: one global lock serializes changelog inserts so seq order == commit order.
// Ceiling: total write throughput; switch to a per-zone outbox if that ever matters.
const CHANGELOG_LOCK: i64 = 0x646e_735f_6c6f_67; // "dns_log"

pub fn router(pool: PgPool) -> Router {
    Router::new()
        .route("/zones", get(list_zones).post(create_zone))
        .route(
            "/zones/{zone}",
            get(get_zone).patch(patch_zone).delete(delete_zone),
        )
        .route("/zones/{zone}/changes", post(apply_changes))
        .route("/changelog", get(changelog))
        .with_state(pool)
}

// ---------- errors ----------

pub enum ApiError {
    BadRequest(Vec<String>),
    NotFound(String),
    Conflict(String),
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, errors) = match self {
            ApiError::BadRequest(e) => (StatusCode::BAD_REQUEST, e),
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

    append_changelog(db, &zone.name, Some(zone.serial), "names", json!(payload)).await
}

async fn append_changelog(
    db: &mut PgConnection,
    zone: &str,
    serial: Option<i64>,
    op: &str,
    payload: Value,
) -> ApiResult<Value> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(CHANGELOG_LOCK)
        .execute(&mut *db)
        .await?;
    let seq: i64 = sqlx::query_scalar(
        "INSERT INTO changelog (zone, serial, op, payload) VALUES ($1, $2, $3, $4) RETURNING seq",
    )
    .bind(zone)
    .bind(serial)
    .bind(op)
    .bind(payload)
    .fetch_one(&mut *db)
    .await?;
    Ok(json!({ "zone": zone, "seq": seq, "serial": serial }))
}

// ---------- zones ----------

/// All zones, plus `seq`: the changelog head in the same snapshot. A node whose applied seq
/// equals `seq` can compare serials without a change in flight causing a false mismatch.
async fn list_zones(State(pool): State<PgPool>) -> ApiResult<Json<Value>> {
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
    Ok(Json(json!({
        "seq": seq,
        "zones": zones.iter().map(ZoneRow::json).collect::<Vec<_>>(),
    })))
}

async fn get_zone(State(pool): State<PgPool>, Path(zone): Path<String>) -> ApiResult<Json<Value>> {
    let zone = validate::parse_zone(&zone).map_err(bad)?;
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
    State(pool): State<PgPool>,
    Json(req): Json<CreateZone>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let zone = validate::parse_zone(&req.name).map_err(bad)?;
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
    let result = commit_change(&mut tx, &row, BTreeSet::new()).await?;
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
    State(pool): State<PgPool>,
    Path(zone): Path<String>,
    Json(req): Json<PatchZone>,
) -> ApiResult<Json<Value>> {
    let zone = validate::parse_zone(&zone).map_err(bad)?;
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
    let result = commit_change(&mut tx, &row, BTreeSet::new()).await?;
    tx.commit().await?;
    Ok(Json(result))
}

async fn delete_zone(
    State(pool): State<PgPool>,
    Path(zone): Path<String>,
) -> ApiResult<Json<Value>> {
    let zone = validate::parse_zone(&zone).map_err(bad)?;
    let mut tx = pool.begin().await?;
    let row = lock_zone(&mut tx, &zone).await?;
    sqlx::query("DELETE FROM zones WHERE id = $1")
        .bind(row.id)
        .execute(&mut *tx)
        .await?;
    let result = append_changelog(&mut tx, &row.name, None, "delete_zone", json!({})).await?;
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
    State(pool): State<PgPool>,
    Path(zone): Path<String>,
    Json(req): Json<ChangeSet>,
) -> ApiResult<Json<Value>> {
    let zone = validate::parse_zone(&zone).map_err(bad)?;
    if req.changes.is_empty() {
        return Err(bad("changes: at least one change is required"));
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

    let mut tx = pool.begin().await?;
    let row = lock_zone(&mut tx, &zone).await?;
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
                    .bind(rtype.to_string())
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
                .bind(rtype.to_string())
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
                .bind(rtype.to_string())
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
        let records: Vec<(String, i32)> =
            sqlx::query_as("SELECT type, ttl FROM records WHERE zone_id = $1 AND name = $2")
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
        let records: Vec<(RecordType, u32)> = records
            .iter()
            .filter_map(|(t, ttl)| Some((validate::parse_type(t).ok()?, *ttl as u32)))
            .collect();
        errors.extend(validate::check_name(&zone, &owner, &records));
    }

    if !errors.is_empty() {
        return Err(ApiError::BadRequest(errors)); // tx drops -> rollback
    }
    let result = commit_change(&mut tx, &row, touched).await?;
    tx.commit().await?;
    Ok(Json(result))
}

// ---------- changelog ----------

#[derive(Deserialize)]
struct ChangelogQuery {
    #[serde(default)]
    after: i64,
    limit: Option<i64>,
}

/// Entries with seq > `after`, oldest first. Nodes poll this (Stage 3).
async fn changelog(
    State(pool): State<PgPool>,
    Query(q): Query<ChangelogQuery>,
) -> ApiResult<Json<Value>> {
    let limit = q.limit.unwrap_or(1000).clamp(1, 10_000);
    let rows: Vec<(i64, String, Option<i64>, String, Value, String)> = sqlx::query_as(
        "SELECT seq, zone, serial, op, payload, created_at::text FROM changelog
         WHERE seq > $1 ORDER BY seq LIMIT $2",
    )
    .bind(q.after)
    .bind(limit)
    .fetch_all(&pool)
    .await?;
    let entries: Vec<Value> = rows
        .into_iter()
        .map(|(seq, zone, serial, op, payload, created_at)| {
            json!({ "seq": seq, "zone": zone, "serial": serial, "op": op, "payload": payload, "created_at": created_at })
        })
        .collect();
    Ok(Json(json!({ "entries": entries })))
}
