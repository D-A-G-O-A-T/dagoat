# MIGRATION.md — Transferring the GoatCoin Containerized Build to a New Host

This guide moves the fully-built GoatCoin testnet (the `goatd` daemon + the 5-node cluster) from one
machine to another — e.g., a local laptop → a cloud VPS — **without requiring a Rust toolchain on the
destination**. Read [`DEPLOY.md`](DEPLOY.md) and [`ARCHITECTURE.md`](ARCHITECTURE.md) §6 for the
runtime model.

---

## 1. What "the build" actually is (the transfer set)

The GoatCoin build is fully described by a small set of files — **not** by any compiled artifact,
which is always regenerated:

| Transfer | Path(s) | Why |
|----------|---------|-----|
| **Source** | `Cargo.toml`, `Cargo.lock`, `src/` (incl. `src/bin/goatd.rs`) | Rebuild the image from a pinned dependency graph. |
| **Container recipes** | `Dockerfile`, `.dockerignore`, `docker-compose.yml` | Reproduce the image and the 5-node cluster. |
| **Runtime config** | `genesis.json` | Bind-mounted read-only into every node. |
| **Secrets (production)** | `keys/` (per-node identity) | Migrated separately and securely — see §4. |
| **DO NOT transfer** | `target/`, `goatcoin-rs/target/`, Docker layer caches | Rebuilt on the destination; transferring them wastes bandwidth and can be stale/arch-mismatched. |

> **`Cargo.lock` is committed and load-bearing.** The Dockerfile builds with `--locked`, so the
> destination compiles the *exact* dependency versions the source did — reproducible, byte-for-byte
> equivalent binaries.

## 2. Destination prerequisites

Only two, on the new host:

- **Docker Engine ≥ 24** with **BuildKit** (default in modern Docker; the Dockerfile uses cache mounts).
- **Docker Compose v2** (`docker compose …`).

**No Rust, no `cargo`, no C toolchain** on the destination — the builder stage (`rust:1-bookworm`)
carries everything, and the runtime image (`debian:bookworm-slim`) carries only the binary + glibc.

---

## 3. Path A — Rebuild from source on the destination *(recommended, self-contained)*

Best when the destination has outbound internet (to pull base images + crates once) and you want a
clean, provenance-checkable build.

1. **Copy the transfer set** (a subset of the repo) to the new host — via `git clone`, `rsync`, or
   `scp`. Minimum required:
   ```
   Cargo.toml  Cargo.lock  Dockerfile  .dockerignore  docker-compose.yml  genesis.json  src/
   ```
   Example (rsync, excluding build junk):
   ```
   rsync -av --exclude target/ --exclude goatcoin-rs/ --exclude '.git/' \
         ./ user@new-host:/opt/goatcoin/
   ```
2. **Build the image** on the destination (Rust lives *inside* the builder stage):
   ```
   cd /opt/goatcoin
   docker compose build            # or: docker build -t goatcoin/goatd:1.0 .
   ```
3. **Launch the 5-node cluster:**
   ```
   docker compose up -d
   docker compose ps               # expect goat-node-0 … goat-node-4 = running
   ```
4. **Verify** each node answers (the RECON-11 stateless cookie handshake works end-to-end): send a
   UDP `INITIATION` to a mapped host port and expect a cookie-challenge reply (`tag = 0x81`,
   `len = 41`). Any small UDP client works; e.g., confirm the listeners are up:
   ```
   docker compose logs --tail=2 node-0     # "goatd: listening on 0.0.0.0:4646"
   ```

## 4. Path B — Transfer the prebuilt image *(air-gapped / no rebuild on destination)*

Best when the destination has no internet, or you want the *identical* image bytes rather than a
fresh compile.

1. **On the source host**, build then export the image:
   ```
   docker compose build
   docker save goatcoin/goatd:1.0 | gzip > goatd-1.0.tar.gz
   ```
2. **Copy** `goatd-1.0.tar.gz`, `docker-compose.yml`, and `genesis.json` to the destination:
   ```
   scp goatd-1.0.tar.gz docker-compose.yml genesis.json user@new-host:/opt/goatcoin/
   ```
3. **On the destination**, load the image and start — Compose sees the pinned `image:` tag already
   present and does **not** rebuild:
   ```
   cd /opt/goatcoin
   gunzip -c goatd-1.0.tar.gz | docker load
   docker compose up -d            # uses the loaded image; no build, no Rust needed
   ```
   > A private registry is the scalable alternative: `docker tag goatcoin/goatd:1.0 <registry>/goatd:1.0`,
   > `docker push …` on the source, `docker pull …` on the destination.

> **Architecture note.** A saved image is CPU-architecture-specific. If the destination differs (e.g.
> Apple-Silicon laptop → amd64 VPS), either use **Path A** (rebuild natively) or build a multi-arch
> image on the source with `docker buildx build --platform linux/amd64,linux/arm64 …`.

---

## 5. Persistent state & key migration

**Reality — there is no persistent node state to migrate, but there ARE inputs you must provide.**
The reference `goatd`:
- derives no on-disk data — sessions (`Aes256GcmChannel` + `last_seen`) are **volatile in RAM** and
  wiped on stop/restart by design (nonce discipline assumes volatile keys — see `DEPLOY.md` C-12);
- writes nothing to `/etc/goatd`.

> **Security quick-fixes (Track A) changed the startup contract — the old "compiled-in `[0u8; 32]`
> node_secret + accept-all registry" default is GONE.** By default `goatd` is now **fail-closed**:
> it refuses to boot without a valid `genesis.json` (strict: exactly 1952-byte ML-DSA-65 keys) and a
> real **node secret** (`GOATD_NODE_SECRET` = 64 hex, or `--node-secret-file` / `GOATD_NODE_SECRET_FILE`
> / `/etc/goatd/node_secret`). Accept-all is available only behind the explicit, loopback-only
> `--dev-accept-all-registry` flag (refused on non-loopback binds, `GOATD_ENV=production`, and
> mainnet). So a migration must carry **two secret-bearing inputs per node**, not zero:

So a migration is "copy the transfer set + `genesis.json`, **provide each node's `GOATD_NODE_SECRET`**,
then `docker compose up`." The local compose ships distinct dev/test `GOATD_NODE_SECRET` values per
node; a real deployment supplies real per-node secrets (below). **Do not** carry Docker volume state
between hosts.

**Signing identity (ML-DSA-65) — identity-hardening (required for Alpha / off-host):**

- **Precedence:** `GOATD_SIGNING_SEED` (64 hex secret) **first**. Only if unset may the daemon use a
  deterministic `testnet_signing_seed(node-index)` — and only on **loopback**, or with explicit
  `GOATD_ALLOW_TESTNET_SEEDS=1` on a lab non-loopback bind. **Always refused** under
  `GOATD_ENV=production` or `--features mainnet`.
- **Generate Alpha keys (random, non-derivable):**
  ```
  cargo run --bin goat-keygen -- --random --count 5 --out-dir keys/
  # → keys/node-N/signing_seed  (export as GOATD_SIGNING_SEED; never commit)
  # → prints genesis_orchestrators JSON fragment (paste into genesis.json)
  ```
- **Lab-only forgeable path:** omit `GOATD_SIGNING_SEED`, set `--node-index`, and either bind
  loopback or set `GOATD_ALLOW_TESTNET_SEEDS=1`. Expect the multi-line **FORGEABLE NODE IDENTITY** banner.

**Production key tree (cookie secret + signing seed — `DEPLOY.md` C-8/C-12):**

- Store outside the image as `keys/node-N/` (or Compose secrets), bind-mounted **read-only**.
  ```
  # on the source: package keys with permissions preserved
  tar --numeric-owner -czf goat-keys.tgz keys/
  # transfer over an encrypted channel only (scp/age/gpg), then on the destination:
  tar -xzf goat-keys.tgz && chmod 700 keys && chmod 600 keys/*/node_secret keys/*/signing_seed
  ```
  Keys are **never baked into the image** and never committed to VCS. Prefer re-provisioning from a
  KMS/HSM over copying raw key material where possible; rotate on any suspicion of exposure.
- **Persistent session storage** (if a future iteration adds it) must migrate the nonce Write-Ahead
  Log **atomically**, and on restore the sequence counters must **never roll backward or repeat**
  (`DEPLOY.md` C-12). A safe restart re-derives sessions from scratch, so when in doubt, migrate the
  keys only and let sessions re-establish.

---

## 6. Post-migration verification checklist

- [ ] `docker compose ps` — all of `goat-node-0 … goat-node-4` are `running`.
- [ ] `docker compose logs node-0 | grep "listening on 0.0.0.0:4646"` present on every node.
- [ ] A UDP `INITIATION` to each mapped host port (`localhost:4640 … 4644`) returns a cookie
      challenge (`tag = 0x81`, `len = 41`).
- [ ] `docker compose logs` show **PQ host crypto ACTIVE** (Track C). Lab deterministic seeds should
      also show the **FORGEABLE NODE IDENTITY** banner (identity-hardening). Production must use
      `GOATD_SIGNING_SEED` and must **not** set `GOATD_ALLOW_TESTNET_SEEDS`.
- [ ] Production migrations must have
      completed the Backend Swap Checklist *before* transfer.
- [ ] No `keys/` material landed in VCS or the image (`git status`, `docker history goatcoin/goatd:1.0`).

---

*A GoatCoin migration is intentionally boring: the daemon is a single self-contained binary with no
hidden local state, so the whole network is reproducible from `Cargo.lock` + the container recipes +
`genesis.json`. The only thing that ever needs careful, secure handling is per-node key material —
and at V1.0 there is none.*
