use control_plane::auth::{self, Grant};
use tokio::net::TcpListener;

const USAGE: &str = "usage:
  control-plane                serve the API (DATABASE_URL required; LISTEN, SPF_REFRESH_SECS=900)
  control-plane create-token --name NAME [--admin] [--grant PATTERN:ROLE[:scripts]]...
                             [--secret-env VAR | --secret VALUE] [--if-missing]

  create-token prints the new token's secret. Use it to mint the first admin token.
  --grant      e.g. 'example.com:editor', '*.team.test:owner:scripts', '*:viewer' (DNS nodes)
  --secret-env register the value of environment variable VAR instead of a random one
               (automation; 32+ characters)
  --secret     the same, given directly; it shows up in ps and shell history, so prefer --secret-env
  --if-missing leave an existing token with this name alone (prints nothing)";

fn usage() -> ! {
    eprintln!("{USAGE}");
    std::process::exit(2);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // No default: falling back to well-known credentials is how a misconfigured deployment
    // ends up talking to the wrong database.
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        eprintln!(
            "set DATABASE_URL (for the compose Postgres: postgres://dns:dns@127.0.0.1:5432/dns)\n\n{USAGE}"
        );
        std::process::exit(2);
    });
    let args: Vec<String> = std::env::args().skip(1).collect();
    let pool = control_plane::connect(&database_url).await?;

    match args.first().map(String::as_str) {
        None => {
            let listen = std::env::var("LISTEN").unwrap_or_else(|_| "127.0.0.1:8053".into());
            let listener = TcpListener::bind(&listen).await?;
            println!("control plane listening on http://{listen}");
            let every = std::env::var("SPF_REFRESH_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(900);
            let refresh_pool = pool.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(every));
                loop {
                    tick.tick().await;
                    if let Err(e) = control_plane::api::refresh_spf(&refresh_pool).await {
                        eprintln!("spf refresh: {e}");
                    }
                }
            });
            axum::serve(listener, control_plane::api::router(pool)).await?;
        }
        Some("create-token") => {
            let (mut name, mut admin, mut grants, mut secret, mut if_missing) =
                (None, false, vec![], None, false);
            let mut rest = args[1..].iter();
            while let Some(flag) = rest.next() {
                let mut value = || rest.next().cloned().unwrap_or_else(|| usage());
                match flag.as_str() {
                    "--name" => name = Some(value()),
                    "--admin" => admin = true,
                    "--grant" => grants.push(Grant::parse_cli(&value()).unwrap_or_else(|e| {
                        eprintln!("{e}");
                        std::process::exit(2)
                    })),
                    "--secret" => secret = Some(value()),
                    "--secret-env" => {
                        let var = value();
                        secret = Some(std::env::var(&var).unwrap_or_else(|_| {
                            eprintln!("--secret-env: environment variable {var} is not set");
                            std::process::exit(2)
                        }))
                    }
                    "--if-missing" => if_missing = true,
                    _ => usage(),
                }
            }
            let name = name.unwrap_or_else(|| usage());
            match auth::create_token(
                &pool,
                &name,
                admin,
                &grants,
                secret.as_deref(),
                None,
                if_missing,
            )
            .await
            {
                Ok(Some(secret)) => println!("{secret}"),
                Ok(None) => eprintln!("token {name:?} already exists; left unchanged"),
                Err(e) => return Err(format!("{e:?}").into()),
            }
        }
        Some(_) => usage(),
    }
    Ok(())
}
