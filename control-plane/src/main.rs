use control_plane::auth::{self, Grant};
use tokio::net::TcpListener;

const USAGE: &str = "usage:
  control-plane                serve the API (LISTEN, DATABASE_URL)
  control-plane create-token --name NAME [--admin] [--grant PATTERN:ROLE[:scripts]]...
                             [--secret VALUE] [--if-missing]

  create-token prints the new token's secret. Use it to mint the first admin token.
  --grant      e.g. 'example.com:editor', '*.team.test:owner:scripts', '*:viewer' (DNS nodes)
  --secret     register this value instead of a random one (automation; 32+ characters)
  --if-missing leave an existing token with this name alone (prints nothing)";

fn usage() -> ! {
    eprintln!("{USAGE}");
    std::process::exit(2);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://dns:dns@127.0.0.1:5432/dns".into());
    let args: Vec<String> = std::env::args().skip(1).collect();
    let pool = control_plane::connect(&database_url).await?;

    match args.first().map(String::as_str) {
        None => {
            let listen = std::env::var("LISTEN").unwrap_or_else(|_| "127.0.0.1:8053".into());
            let listener = TcpListener::bind(&listen).await?;
            println!("control plane listening on http://{listen}");
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
