# One image with both binaries; compose picks which to run.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p dns-server -p control-plane

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/dns-server /src/target/release/control-plane /usr/local/bin/
# Unprivileged: nodes listen on 5300 inside the container (map host port 53 to it), and own /data.
RUN useradd --system --uid 10001 --home-dir /data --create-home dns
USER dns
