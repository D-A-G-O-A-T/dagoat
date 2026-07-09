# GoatHAL Execution Isolation — Threat Model (execution-isolation / Vector 1.1)

**Status:** design + Phase-0 containment proof (AR96)  
**Scope:** host-edge worker isolation only — not marketplace, not CET, not multi-OS production parity.

---

## 1. Adversary

| Actor | Capabilities |
|-------|----------------|
| **Hostile task submitter** | Crafts an **opaque** payload (model bytes, inputs, or adversarial ML-runtime trigger). Payload is content-neutral (CP7) — protocol cannot inspect semantics. |
| **Compromised device backend** | Below the HAL trait, any compute may run; treated as adversarial *data source* (Threat Model §2). Isolation prevents that compute from owning the host OS. |

**Not modeled here:** physical access to the machine; a malicious `goatd` binary (supply chain); privileged OS compromise prior to node start.

---

## 2. Assets

| Asset | Why it matters |
|-------|----------------|
| Host filesystem (user docs, credentials, SSH keys) | Household trust; legal/liability surface |
| Host network (non-mesh) | Lateral movement / exfiltration |
| Other user processes | Session hijack / crypto wallet processes |
| `goatd` process & keys | Mesh identity, node_secret, signing seed |
| Isolation supervisor integrity | Failure here re-opens full host blast radius |

---

## 3. Trust boundary

```
┌──────────────── goatd (network daemon, trusted for mesh) ────────────────┐
│  crypto / gossip / cookie / reassembly                                   │
│         │ spawn + supervise (IPC stdin/stdout, timeout, resource caps)     │
│         ▼                                                                  │
│  ┌──────────── isolation boundary (OS process + sandbox) ───────────────┐  │
│  │  goat-worker  │  opaque payload execution only                        │  │
│  │  scratch dir  │  no mesh keys, no host home, no unrestricted net      │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────┘
```

- **Above the line:** protocol, identity, mesh transport.  
- **Below the line:** untrusted payload compute.  
- **Only aperture:** length-bounded IPC messages + explicit scratch path.  
- Device class is an **opaque tag** — never branched on in protocol or isolation contract.

---

## 4. Required security property (normative)

> A payload executing in a worker **cannot** read/write the host beyond an explicit scratch directory, **cannot** open network connections beyond any future mesh-egress allowlist (default: **none**), **cannot** escalate privileges or spawn unbounded child processes, and **cannot** crash or corrupt `goatd`. A worker crash kills only the worker; the supervisor reports a contained failure and continues mesh duties.

---

## 5. Attack → response (Phase-0)

| Attack | Required response |
|--------|-------------------|
| Host path read/write (`../`, absolute home paths) | Denied at worker policy and/or OS sandbox; never reaches host secrets |
| Network connect | Denied (no socket capability / policy reject) |
| Spawn extra processes | Job/rlimit active-process = 1 (or equivalent); denied |
| Infinite loop / CPU burn | Wall-clock timeout; worker killed |
| Memory bomb | Memory cap; worker killed |
| Hard abort / panic | Supervisor sees non-zero exit; `goatd` lives |
| Isolation primitive missing | **Fail-closed:** refuse payload execution (verification-only) |

---

## 6. Residual (honest)

- Phase-0 proof uses a **cooperative worker binary** plus OS process isolation; full Linux seccomp/namespace hardening is the production backend (design doc).  
- Windows/macOS production parity is design-only until dedicated backends land.  
- Does **not** prove immunity to all ML-runtime bugs inside the worker — only that the **blast radius is the worker**, not the household host or `goatd`.
