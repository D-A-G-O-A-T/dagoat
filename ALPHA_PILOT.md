# D.A. G.O.A.T. Engine — local multi-node lab guide (`goatd` + Docker)

How to run the **D.A. G.O.A.T. Engine** (the `goatd` verification-mesh runtime) on your machine:
what the node does, how to limit CPU (power/noise dial), and how containers stay isolated from the host.

> **This is an experimental verification mesh — not yet a secured compute marketplace.** It is safe
> to run and easy to stop, but it is *not* finished: **ML-DSA-65 / ML-KEM-768 / AES-256-GCM are real
> on the wire (Track C)**, yet there is still no useful-work marketplace, no economic settlement, and
> no real value at stake. On the **default lab testnet**, node signing seeds are **deterministic and
> publicly derivable** (anyone with the repo can forge a node's identity); that is a deliberate lab
> convenience gated by loopback or `GOATD_ALLOW_TESTNET_SEEDS=1`. **Off-host / Alpha requires unique
> `GOATD_SIGNING_SEED` secrets** (see below). Things may restart or behave oddly. Please run it on a
> machine you're comfortable experimenting with. Nothing here is final.
>
> *Exact shipped-vs-designed capability list: [`RUNTIME_VS_SPEC.md`](RUNTIME_VS_SPEC.md).*

---

## 1. The Mission — what your node actually does

Your node runs a small background program called `goatd`. Overnight, it does exactly two things:

1. **Talks to a few peers** over an encrypted, post-quantum connection (it dials a bootstrap node,
   completes a handshake, and joins the mesh).
2. **Verifies and gossips telemetry.** When a neighbour sends a signed "capability record" (a tiny
   description of a node's measured availability), your node checks it and passes it along to the
   other peers it knows — the way a rumour spreads through a crowd. Anything that fails verification is
   dropped and never forwarded.

That's it. No mining, no wallets, no personal data leaves your machine. It is a few kilobytes of
signed gossip flowing between a handful of nodes. **You can stop it any time** with `docker compose
down` — it leaves nothing behind.

---

## 2. The Power Dial — absolute control over fan noise and heat

We know the #1 worry with overnight software is a screaming fan. So instead of a fragile in-app
"go slower" hack, we hand the decision to your operating system's kernel, which enforces a **hard CPU
ceiling** the program cannot exceed.

**How to set it:**

1. In the project folder, copy the example environment file:
   ```
   cp .env.example .env
   ```
2. Open `.env` and set your comfort level. The value is a **decimal fraction of one CPU core**:

   | `GOATD_CPU_LIMIT` | What you get | Feel |
   |-------------------|--------------|------|
   | `0.1`             | 10% of one core | Whisper quiet, barely warm |
   | `0.5`             | 50% of one core | A good overnight default |
   | `1.0`             | One full core   | Fastest (the default if unset) |

   ```env
   # Alpha Pilot: CPU limit as a decimal (e.g. 0.5 = 50% of one core)
   GOATD_CPU_LIMIT=0.5
   ```
3. Start it: `docker compose up -d`.

**Why this is real control, not a promise.** The limit is applied by Docker as an OS-level **cgroups
v2 CPU quota** — the same mechanism the kernel uses to isolate any container. Even if the program
*wanted* to use more, the kernel will not let it. On startup each node prints a friendly confirmation
of the quota it was handed, e.g.:

```
goatd: Alpha Pilot — operating at 50% CPU quota (0.5 core(s)); OS-enforced via docker cgroups, not application throttling
```

If your machine still runs warmer than you'd like, lower the number and run `docker compose up -d`
again. You are always in charge of the dial.

---

## 3. The Sandbox — how your personal files stay protected

`goatd` runs inside a deliberately tiny, locked-down box. These are not aspirations — they are the
actual settings applied to every node in `docker-compose.yml`, and you can read them yourself:

- **It is not root.** Each node runs as an unprivileged user (`goat`, uid `10001`) with no login shell
  and no home directory — not as an administrator on your machine.
- **The filesystem is read-only.** The container's root filesystem is mounted **immutable**
  (`read_only: true`); the program literally cannot write files. Its only writable spot is a small
  scratch area that lives in RAM and vanishes on stop.
- **Every kernel capability is dropped.** We strip **all** Linux capabilities (`cap_drop: ["ALL"]`),
  so the process can't do privileged things like change the clock, load modules, or touch raw
  devices — even in theory.
- **No privilege escalation, ever.** `no-new-privileges` is set, so nothing inside can gain new
  powers via `setuid`/`setgid` tricks.
- **It's on its own network island.** All nodes share a private, isolated Docker bridge network
  (`goatnet`). The only doorway to your host is the specific UDP port you see mapped in the compose
  file — nothing else.
- **It reads exactly one file of yours, read-only.** The genesis configuration (`genesis.json`) is
  mounted read-only. The node cannot modify it or reach anything else on your disk.
- **It fails closed on misconfiguration.** The daemon refuses to start without a valid `genesis.json`
  and a node secret — it will not silently fall back to an "accept anyone" mode on a network bind.
  That insecure mode exists only behind an explicit `--dev-accept-all-registry` flag that is rejected
  unless you're on localhost, and never on the real network.

In plain terms: the worst a misbehaving node can do is send some UDP packets on its own little
network and print logs. It cannot read your documents, write to your disk, or gain control of your
computer.

---

## Node identity seeds (identity-hardening — read this)

| Mode | How | Identity secrecy |
|------|-----|------------------|
| **Local lab compose (default)** | Deterministic `testnet_signing_seed(node-index)` + `GOATD_ALLOW_TESTNET_SEEDS=1` on non-loopback binds | **Forgeable** — repo-derived; loud banner every boot |
| **Alpha / any bind reachable off the host** | Unique `GOATD_SIGNING_SEED` (64 hex) per node; genesis pubkeys from `cargo run --bin goat-keygen -- --random --count 5 --out-dir keys/` | **Secret** if seeds stay offline |

Never commit `keys/*/signing_seed`. Production and `--features mainnet` **always refuse** deterministic seeds.

### Network note (handshake size / MTU — MTU-chunking)

Logical handshake messages are multi-kilobyte (CookieEcho ~6.5 KB), but the daemon **chunks** them into
**≤ 1200-byte** UDP datagrams so a 1500-byte path does not depend on IP fragmentation. You should see
log lines like `sent HandshakeInitiation (3 MTU-safe fragment(s))`. See `DEPLOY.md` C-9.

## Quick reference

```
cp .env.example .env         # 1. create your config
# edit GOATD_CPU_LIMIT in .env to taste (0.1 – 1.0)
docker compose up -d         # 2. start the cluster in the background
docker compose logs -f       # 3. watch it talk (Ctrl-C to stop watching)
docker compose down          # 4. stop everything cleanly — leaves nothing behind

# Alpha secret identities (optional replace of lab seeds):
cargo run --bin goat-keygen -- --random --count 5 --out-dir keys/
# paste printed genesis_orchestrators into genesis.json; set GOATD_SIGNING_SEED per node;
# remove GOATD_ALLOW_TESTNET_SEEDS from compose environment.
```

Questions, weird behaviour, or a fan that won't quiet down? That's exactly what an Alpha is for —
please tell us. Thank you for helping GoatCoin take its first steps. 🐐
