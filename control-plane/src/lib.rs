pub mod api;
pub mod auth;
pub mod spf;
pub mod validate;

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

/// Connects to Postgres and applies any pending migrations.
pub async fn connect(database_url: &str) -> Result<PgPool, Box<dyn std::error::Error>> {
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await?;
    sqlx::migrate!().run(&pool).await?;
    Ok(pool)
}
