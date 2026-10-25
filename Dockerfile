FROM node:22-bookworm-slim AS frontend
WORKDIR /theme
COPY web/package.json web/monet-entry.js ./
RUN npm install --no-audit --no-fund && npm run build:monet

FROM rust:bookworm AS build
WORKDIR /app
COPY . .
COPY --from=frontend /theme/monet.bundle.js ./web/monet.bundle.js
RUN rustup target add wasm32-unknown-unknown \
 && cargo install wasm-pack --locked \
 && wasm-pack build crypto-wasm --target web --out-dir pkg \
 && cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -r -u 10001 -m sso && mkdir -p /var/lib/sso && chown sso:sso /var/lib/sso
WORKDIR /app
COPY --from=build /app/target/release/sso /usr/local/bin/sso
COPY --from=build /app/web /app/web
COPY --from=build /app/crypto-wasm/pkg /app/crypto-wasm/pkg
USER sso
ENV SSO_BIND=0.0.0.0:8080 SSO_DATA_DIR=/var/lib/sso SSO_DATABASE_URL=sqlite:///var/lib/sso/sso.db?mode=rwc
EXPOSE 8080
CMD ["/usr/local/bin/sso"]
