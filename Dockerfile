# Multi-stage Rust + browser WASM build. No OAuth/admin secrets at image build time.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN rustup target add wasm32-unknown-unknown \
 && cargo install wasm-pack --locked --version 0.13.1 \
 && wasm-pack build frontend-crypto --target web --out-dir ../web/wasm --release
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install --no-install-recommends -y ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 sso \
 && useradd --system --uid 10001 --gid sso --home-dir /app sso \
 && mkdir -p /app/data \
 && chown 10001:10001 /app/data
WORKDIR /app
COPY --from=build /src/target/release/sso /app/sso
COPY --from=build /src/web /app/web
USER 10001:10001
ENV SSO_BIND=0.0.0.0:3000 \
    SSO_PUBLIC_URL=http://localhost:3000 \
    SSO_AUTO_PORT=false \
    DATABASE_URL=sqlite://data/sso.db
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -fsS http://127.0.0.1:3000/healthz || exit 1
ENTRYPOINT ["/app/sso"]
