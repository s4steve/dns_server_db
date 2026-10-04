use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://dns:dns@127.0.0.1:5432/dns".into());
    let listen = std::env::var("LISTEN").unwrap_or_else(|_| "127.0.0.1:8053".into());

    let pool = control_plane::connect(&database_url).await?;
    let listener = TcpListener::bind(&listen).await?;
    println!("control plane listening on http://{listen}");
    axum::serve(listener, control_plane::api::router(pool)).await?;
    Ok(())
}
