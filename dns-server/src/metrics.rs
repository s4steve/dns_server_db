//! Prometheus metrics and the health check, served over HTTP (`--http`).
//!
//! Counters are plain atomics bumped on the query path; zone counts and sync state are read
//! from the store at scrape time.

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use hickory_proto::op::ResponseCode;

use crate::store::{self, Store, APPLIED_SEQ, LAST_SYNC};
use crate::Transport;

const RCODES: [&str; 7] = [
    "NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED", "FORMERR", "NOTIMP", "OTHER",
];
/// Upper bounds of the latency histogram, in microseconds.
const BUCKETS_US: [u64; 11] = [
    10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 50_000,
];

pub static QUERIES: [[AtomicU64; RCODES.len()]; 2] =
    [const { [const { AtomicU64::new(0) }; RCODES.len()] }; 2];
pub static TRUNCATED: AtomicU64 = AtomicU64::new(0);
pub static RRL_DROPPED: AtomicU64 = AtomicU64::new(0);
pub static RRL_SLIPPED: AtomicU64 = AtomicU64::new(0);
pub static COOKIES_VALID: AtomicU64 = AtomicU64::new(0);
pub static LUA_RUNS: AtomicU64 = AtomicU64::new(0);
pub static LUA_ERRORS: AtomicU64 = AtomicU64::new(0);
pub static FOLLOW_ERRORS: AtomicU64 = AtomicU64::new(0);
pub static REFRESH_REPAIRS: AtomicU64 = AtomicU64::new(0);
static LATENCY: [AtomicU64; BUCKETS_US.len() + 1] =
    [const { AtomicU64::new(0) }; BUCKETS_US.len() + 1];
static LATENCY_SUM_NS: AtomicU64 = AtomicU64::new(0);

pub fn inc(counter: &AtomicU64) {
    counter.fetch_add(1, Relaxed);
}

/// Records one answered query: its rcode, transport, and the time spent building the answer.
pub fn record(transport: Transport, rcode: ResponseCode, took: Duration) {
    let rcode = match rcode {
        ResponseCode::NoError => 0,
        ResponseCode::NXDomain => 1,
        ResponseCode::ServFail => 2,
        ResponseCode::Refused => 3,
        ResponseCode::FormErr => 4,
        ResponseCode::NotImp => 5,
        _ => 6,
    };
    inc(&QUERIES[transport as usize][rcode]);
    let us = took.as_micros() as u64;
    let bucket = BUCKETS_US
        .iter()
        .position(|&b| us <= b)
        .unwrap_or(BUCKETS_US.len());
    inc(&LATENCY[bucket]);
    LATENCY_SUM_NS.fetch_add(took.as_nanos() as u64, Relaxed);
}

pub struct Health {
    pub healthy: bool,
    pub zones: usize,
    pub expired: usize,
    pub applied_seq: Option<u64>,
    pub last_sync_age: Option<u64>,
}

/// Healthy = serving at least one zone. With `--follow`, a zone past its SOA EXPIRE doesn't
/// count, so a node cut off from the control plane turns unhealthy once everything expires.
/// Anycast speakers withdraw the route while this is false.
pub fn health(store: &Store) -> store::Result<Health> {
    let txn = store.read_txn()?;
    let zones = store.zones(&txn)?;
    let mut expired = 0;
    for (zone, _) in &zones {
        expired += usize::from(store.zone_expired(&txn, zone)?);
    }
    let last_sync = store.get_meta(&txn, LAST_SYNC)?;
    Ok(Health {
        healthy: zones.len() > expired,
        zones: zones.len(),
        expired,
        applied_seq: store.get_meta(&txn, APPLIED_SEQ)?,
        last_sync_age: last_sync.map(|t| store::now().saturating_sub(t)),
    })
}

pub fn render(store: &Store) -> String {
    let mut out = String::new();
    let o = &mut out;
    let get = |c: &AtomicU64| c.load(Relaxed);

    let _ = writeln!(
        o,
        "# HELP dns_queries_total Queries answered, by transport and response code."
    );
    let _ = writeln!(o, "# TYPE dns_queries_total counter");
    for (t, transport) in ["udp", "tcp"].iter().enumerate() {
        for (r, rcode) in RCODES.iter().enumerate() {
            let _ = writeln!(
                o,
                "dns_queries_total{{transport=\"{transport}\",rcode=\"{rcode}\"}} {}",
                get(&QUERIES[t][r])
            );
        }
    }

    let _ = writeln!(
        o,
        "# HELP dns_query_duration_seconds Time to build an answer, excluding network I/O."
    );
    let _ = writeln!(o, "# TYPE dns_query_duration_seconds histogram");
    let mut cumulative = 0;
    for (i, bound) in BUCKETS_US.iter().enumerate() {
        cumulative += get(&LATENCY[i]);
        let _ = writeln!(
            o,
            "dns_query_duration_seconds_bucket{{le=\"{}\"}} {cumulative}",
            *bound as f64 / 1e6
        );
    }
    cumulative += get(&LATENCY[BUCKETS_US.len()]);
    let _ = writeln!(
        o,
        "dns_query_duration_seconds_bucket{{le=\"+Inf\"}} {cumulative}"
    );
    let _ = writeln!(
        o,
        "dns_query_duration_seconds_sum {}",
        get(&LATENCY_SUM_NS) as f64 / 1e9
    );
    let _ = writeln!(o, "dns_query_duration_seconds_count {cumulative}");

    for (name, help, counter) in [
        (
            "dns_responses_truncated_total",
            "UDP responses truncated (TC) for size.",
            &TRUNCATED,
        ),
        (
            "dns_rrl_dropped_total",
            "Responses dropped by response rate limiting.",
            &RRL_DROPPED,
        ),
        (
            "dns_rrl_slipped_total",
            "Rate-limited responses sent truncated so clients retry over TCP.",
            &RRL_SLIPPED,
        ),
        (
            "dns_cookies_valid_total",
            "Queries carrying a valid server cookie.",
            &COOKIES_VALID,
        ),
        ("dns_lua_runs_total", "LUA script runs.", &LUA_RUNS),
        (
            "dns_lua_errors_total",
            "LUA script runs that failed (error, bad output, budget).",
            &LUA_ERRORS,
        ),
        (
            "dns_follow_errors_total",
            "Failed changelog polls.",
            &FOLLOW_ERRORS,
        ),
        (
            "dns_refresh_repairs_total",
            "Zones re-fetched or removed by SOA REFRESH checks.",
            &REFRESH_REPAIRS,
        ),
    ] {
        let _ = writeln!(
            o,
            "# HELP {name} {help}\n# TYPE {name} counter\n{name} {}",
            get(counter)
        );
    }

    if let Ok(h) = health(store) {
        let gauges = [
            (
                "dns_zones",
                "Zones in the local store.",
                Some(h.zones as u64),
            ),
            (
                "dns_zones_expired",
                "Zones past SOA EXPIRE (answering SERVFAIL).",
                Some(h.expired as u64),
            ),
            (
                "dns_healthy",
                "1 while serving at least one unexpired zone.",
                Some(u64::from(h.healthy)),
            ),
            (
                "dns_follow_applied_seq",
                "Last changelog seq applied.",
                h.applied_seq,
            ),
            (
                "dns_follow_sync_age_seconds",
                "Seconds since the node was last fully caught up.",
                h.last_sync_age,
            ),
        ];
        for (name, help, value) in gauges {
            if let Some(v) = value {
                let _ = writeln!(o, "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {v}");
            }
        }
    }
    out
}

pub fn router(store: Arc<Store>) -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/health", get(health_handler))
        .with_state(store)
}

async fn metrics_handler(State(store): State<Arc<Store>>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        render(&store),
    )
}

async fn health_handler(State(store): State<Arc<Store>>) -> impl IntoResponse {
    match health(&store) {
        Ok(h) => {
            let status = if h.healthy {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            let body = serde_json::json!({
                "healthy": h.healthy, "zones": h.zones, "expired": h.expired,
                "applied_seq": h.applied_seq, "last_sync_age_seconds": h.last_sync_age,
            });
            (status, axum::Json(body))
        }
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({ "healthy": false, "error": e.to_string() })),
        ),
    }
}
