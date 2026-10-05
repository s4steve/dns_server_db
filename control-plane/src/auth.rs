//! Access control: bearer tokens with per-zone roles.
//!
//! Every request carries `Authorization: Bearer <token>`. A token has a name (recorded as the
//! actor on every change it makes), an optional `admin` flag, and grants of the form
//! (zone pattern, role, scripts):
//!
//! - patterns: `example.com.` (that zone), `*.example.com.` (zones below it, not the apex),
//!   `*` (every zone);
//! - roles: viewer (read) < editor (change records) < owner (zone settings, delete, create
//!   zones under the pattern). A token's role on a zone is the highest matching grant.
//! - `scripts`: may add/delete LUA records, which run code on every DNS node (needs editor).
//! - admin: owner with scripts on every zone, plus token management.
//!
//! Secrets are `dnsdb_` + 32 random bytes in hex, shown once and stored as SHA-256 hashes.

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use hickory_proto::rr::Name;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool};

use crate::api::ApiError;
use crate::validate;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Viewer,
    Editor,
    Owner,
}

impl Role {
    fn parse(s: &str) -> Result<Role, String> {
        match s {
            "viewer" => Ok(Role::Viewer),
            "editor" => Ok(Role::Editor),
            "owner" => Ok(Role::Owner),
            _ => Err(format!("unknown role {s:?} (viewer, editor or owner)")),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Editor => "editor",
            Role::Owner => "owner",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Grant {
    pub pattern: String,
    pub role: Role,
    #[serde(default)]
    pub scripts: bool,
}

impl Grant {
    /// Validates and normalizes a grant (pattern to lowercase FQDN form).
    pub fn new(pattern: &str, role: Role, scripts: bool) -> Result<Grant, String> {
        let pattern = if pattern == "*" {
            "*".to_string()
        } else if let Some(below) = pattern.strip_prefix("*.") {
            format!("*.{}", validate::parse_zone(below)?)
        } else {
            validate::parse_zone(pattern)?.to_string()
        };
        if scripts && role == Role::Viewer {
            return Err(format!("grant {pattern}: scripts needs editor or owner"));
        }
        Ok(Grant {
            pattern,
            role,
            scripts,
        })
    }

    /// `PATTERN:ROLE[:scripts]`, as given to `create-token --grant`.
    pub fn parse_cli(s: &str) -> Result<Grant, String> {
        let parts: Vec<&str> = s.split(':').collect();
        match parts[..] {
            [pattern, role] => Grant::new(pattern, Role::parse(role)?, false),
            [pattern, role, "scripts"] => Grant::new(pattern, Role::parse(role)?, true),
            _ => Err(format!(
                "grant {s:?} must be PATTERN:ROLE or PATTERN:ROLE:scripts"
            )),
        }
    }

    fn matches(&self, zone: &Name) -> bool {
        if self.pattern == "*" {
            return true;
        }
        if let Some(below) = self.pattern.strip_prefix("*.") {
            return Name::from_ascii(below)
                .is_ok_and(|parent| parent.zone_of(zone) && parent != *zone);
        }
        Name::from_ascii(&self.pattern).is_ok_and(|z| z == *zone)
    }
}

/// The authenticated caller of a request.
#[derive(Debug)]
pub struct Caller {
    pub name: String,
    pub admin: bool,
    pub grants: Vec<Grant>,
    /// None: the token never expires (CLI-minted tokens, such as the nodes').
    pub expires_at: Option<String>,
}

impl Caller {
    pub fn role(&self, zone: &Name) -> Option<Role> {
        if self.admin {
            return Some(Role::Owner);
        }
        self.grants
            .iter()
            .filter(|g| g.matches(zone))
            .map(|g| g.role)
            .max()
    }

    pub fn can_script(&self, zone: &Name) -> bool {
        self.admin
            || self
                .grants
                .iter()
                .any(|g| g.scripts && g.role >= Role::Editor && g.matches(zone))
    }

    /// Whether the caller can see every zone (lets list/changelog skip per-row checks).
    pub fn sees_all(&self) -> bool {
        self.admin || self.grants.iter().any(|g| g.pattern == "*")
    }

    /// Errors with 404 if the caller can't see the zone at all (so its existence doesn't
    /// leak), and 403 if it can see it but lacks `need`.
    pub fn require(&self, zone: &Name, need: Role) -> Result<(), ApiError> {
        match self.role(zone) {
            None => Err(ApiError::NotFound(format!("zone {zone} not found"))),
            Some(have) if have < need => Err(ApiError::Forbidden(format!(
                "token {:?} is {} on {zone}; this needs {}",
                self.name,
                have.as_str(),
                need.as_str()
            ))),
            Some(_) => Ok(()),
        }
    }

    pub fn require_admin(&self) -> Result<(), ApiError> {
        if self.admin {
            Ok(())
        } else {
            Err(ApiError::Forbidden(format!(
                "token {:?} is not an admin",
                self.name
            )))
        }
    }
}

/// Estimated strength of a supplied secret in bits: length × log2(distinct characters).
/// Generated secrets are 256 random bits; this keeps supplied ones from being guessable.
// ponytail: blind to dictionary words and keyboard patterns; generated secrets (e.g.
// `openssl rand -hex 32`) remain the advice.
fn strength_bits(secret: &str) -> f64 {
    let distinct = secret
        .chars()
        .collect::<std::collections::HashSet<_>>()
        .len();
    secret.chars().count() as f64 * (distinct as f64).log2()
}

fn hash(secret: &str) -> Vec<u8> {
    Sha256::digest(secret.as_bytes()).to_vec()
}

#[derive(FromRow)]
struct TokenRow {
    id: i64,
    name: String,
    admin: bool,
    expires_at: Option<String>,
}

impl FromRequestParts<PgPool> for Caller {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, pool: &PgPool) -> Result<Self, ApiError> {
        let secret = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim)
            .ok_or_else(|| {
                ApiError::Unauthorized(
                    "missing bearer token (Authorization: Bearer <token>)".into(),
                )
            })?;
        let token: TokenRow = sqlx::query_as(
            "SELECT id, name, admin, expires_at::text FROM tokens
             WHERE hash = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())",
        )
        .bind(hash(secret))
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("invalid, expired or revoked token".into()))?;
        let grants = load_grants(pool, token.id).await?;
        // At most one write a minute per token, however often it polls.
        sqlx::query(
            "UPDATE tokens SET last_used_at = now()
             WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')",
        )
        .bind(token.id)
        .execute(pool)
        .await?;
        Ok(Caller {
            name: token.name,
            admin: token.admin,
            grants,
            expires_at: token.expires_at,
        })
    }
}

pub async fn load_grants(pool: &PgPool, token_id: i64) -> Result<Vec<Grant>, ApiError> {
    let rows: Vec<(String, String, bool)> = sqlx::query_as(
        "SELECT pattern, role, scripts FROM grants WHERE token_id = $1 ORDER BY pattern",
    )
    .bind(token_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|(pattern, role, scripts)| {
            Ok(Grant {
                pattern,
                role: Role::parse(&role).map_err(ApiError::Internal)?,
                scripts,
            })
        })
        .collect()
}

/// Creates a token and returns its secret. With `secret`, registers that value instead of a
/// random one (for automation). With `if_missing`, an existing token of that name is left
/// alone and `None` is returned.
pub async fn create_token(
    pool: &PgPool,
    name: &str,
    admin: bool,
    grants: &[Grant],
    secret: Option<&str>,
    expires_in_days: Option<u32>,
    if_missing: bool,
) -> Result<Option<String>, ApiError> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
    {
        return Err(ApiError::BadRequest(vec![format!(
            "token name {name:?} must be 1-64 characters of letters, digits, '.', '_' or '-'"
        )]));
    }
    let secret = match secret {
        Some(s) if s.len() < 32 || strength_bits(s) < 128.0 => {
            return Err(ApiError::BadRequest(vec![
                "a supplied secret must be at least 32 characters and about 128 bits strong \
                 (length × log2 of its distinct characters); generate one with `openssl rand -hex 32`"
                    .into(),
            ]));
        }
        Some(s) => s.to_string(),
        None => {
            let mut bytes = [0u8; 32];
            getrandom::fill(&mut bytes).map_err(|e| ApiError::Internal(e.to_string()))?;
            format!(
                "dnsdb_{}",
                bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
            )
        }
    };

    let mut tx = pool.begin().await?;
    let id: Option<i64> = sqlx::query_scalar(
        "INSERT INTO tokens (name, hash, prefix, admin, expires_at)
         VALUES ($1, $2, $3, $4, now() + make_interval(days => $5))
         ON CONFLICT (name) DO NOTHING RETURNING id",
    )
    .bind(name)
    .bind(hash(&secret))
    .bind(secret.chars().take(12).collect::<String>())
    .bind(admin)
    .bind(expires_in_days.map(|d| d as i32))
    .fetch_optional(&mut *tx)
    .await
    .map_err(
        |e| match e.as_database_error().and_then(|d| d.constraint()) {
            Some("tokens_hash_key") => {
                ApiError::Conflict("that secret is already in use by another token".into())
            }
            _ => e.into(),
        },
    )?;
    let Some(id) = id else {
        return if if_missing {
            Ok(None)
        } else {
            Err(ApiError::Conflict(format!("token {name:?} already exists")))
        };
    };
    for g in grants {
        sqlx::query(
            "INSERT INTO grants (token_id, pattern, role, scripts) VALUES ($1, $2, $3, $4)",
        )
        .bind(id)
        .bind(&g.pattern)
        .bind(g.role.as_str())
        .bind(g.scripts)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(Some(secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone(s: &str) -> Name {
        validate::parse_zone(s).unwrap()
    }

    fn caller(grants: &[(&str, Role, bool)]) -> Caller {
        Caller {
            name: "t".into(),
            admin: false,
            expires_at: None,
            grants: grants
                .iter()
                .map(|(p, r, s)| Grant::new(p, *r, *s).unwrap())
                .collect(),
        }
    }

    #[test]
    fn patterns_and_roles() {
        let c = caller(&[
            ("Example.com", Role::Viewer, false),
            ("*.example.com", Role::Editor, false),
            ("team.example.com", Role::Owner, true),
        ]);
        assert_eq!(c.role(&zone("example.com")), Some(Role::Viewer)); // `*.` excludes the apex
        assert_eq!(c.role(&zone("a.example.com")), Some(Role::Editor));
        assert_eq!(c.role(&zone("a.b.example.com")), Some(Role::Editor));
        assert_eq!(c.role(&zone("team.example.com")), Some(Role::Owner)); // highest wins
        assert_eq!(c.role(&zone("example.org")), None);
        assert_eq!(c.role(&zone("notexample.com")), None);
        assert!(c.can_script(&zone("team.example.com")));
        assert!(!c.can_script(&zone("a.example.com")));
        assert!(!c.sees_all());

        let everything = caller(&[("*", Role::Viewer, false)]);
        assert_eq!(everything.role(&zone("anything.test")), Some(Role::Viewer));
        assert!(everything.sees_all());
        let admin = Caller {
            name: "a".into(),
            admin: true,
            expires_at: None,
            grants: vec![],
        };
        assert_eq!(admin.role(&zone("x.test")), Some(Role::Owner));
        assert!(admin.can_script(&zone("x.test")));

        assert!(matches!(
            c.require(&zone("example.org"), Role::Viewer),
            Err(ApiError::NotFound(_))
        ));
        assert!(matches!(
            c.require(&zone("example.com"), Role::Editor),
            Err(ApiError::Forbidden(_))
        ));
        assert!(c.require(&zone("a.example.com"), Role::Editor).is_ok());
    }

    #[test]
    fn grant_parsing() {
        assert_eq!(Grant::parse_cli("*:viewer").unwrap().pattern, "*");
        assert_eq!(
            Grant::parse_cli("*.Team.test:owner:scripts").unwrap(),
            Grant {
                pattern: "*.team.test.".into(),
                role: Role::Owner,
                scripts: true
            }
        );
        assert!(Grant::parse_cli("x.test:viewer:scripts").is_err()); // scripts needs editor
        assert!(Grant::parse_cli("x.test:superuser").is_err());
        assert!(Grant::parse_cli("x.test").is_err());
        assert!(Grant::parse_cli("bad..name:viewer").is_err());
        assert_eq!(hash("abc"), hash("abc"));
        assert_ne!(hash("abc"), hash("abd"));

        // Supplied secrets: repetitive ones are too weak, random or varied ones pass.
        assert!(strength_bits(&"a".repeat(64)) < 128.0);
        assert!(strength_bits(&"ab".repeat(32)) < 128.0);
        assert!(strength_bits("0123456789abcdef0123456789abcdef") >= 128.0);
        assert!(strength_bits("dnsdb_dev_nodes_token_do_not_use_in_production") >= 128.0);
    }
}
