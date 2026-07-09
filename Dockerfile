# syntax=docker/dockerfile:1
#
# GoatCoin (GOAT) — the `goatd` async daemon.
# Multi-stage: an official Rust image compiles the release binary; a lean Debian image runs it.
#
#   Build:  docker build -t goatcoin/goatd:1.0 .
#   Run:    docker run --rm -p 4646:4646/udp goatcoin/goatd:1.0
#
# The builder carries the Rust toolchain, so the runtime host needs *no* Rust to build or run.

# ============================================================================
# Stage 1 — builder: compile `goat-core` + the `goatd` binary in --release.
# ============================================================================
FROM rust:1-bookworm AS builder
WORKDIR /build

# Manifests + source. (A .dockerignore keeps target/, goatcoin-rs/, and the docs out of the context.)
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# BuildKit cache mounts keep the crates.io registry and the target/ dir warm across rebuilds. The
# finished binary is copied OUT of the cache-mounted target/ so it persists into the image layer.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked --bin goatd \
    && cp /build/target/release/goatd /usr/local/bin/goatd

# ============================================================================
# Stage 2 — runner: a minimal Debian image with just the binary.
# ============================================================================
FROM debian:bookworm-slim AS runner

# Unprivileged, no-login system user.
RUN groupadd --system --gid 10001 goat \
 && useradd  --system --uid 10001 --gid goat --no-create-home --shell /usr/sbin/nologin goat

# `goatd` is a self-contained glibc binary; bookworm-slim already ships the matching libc.
COPY --from=builder /usr/local/bin/goatd /usr/local/bin/goatd

# Mount point for the runtime config (genesis.json, future per-node keys) — see docker-compose.yml.
RUN mkdir -p /etc/goatd && chown goat:goat /etc/goatd
VOLUME ["/etc/goatd"]

USER goat
# The daemon binds 0.0.0.0:4646/udp (compiled-in). EXPOSE is documentation; compose does the mapping.
EXPOSE 4646/udp
ENTRYPOINT ["/usr/local/bin/goatd"]
