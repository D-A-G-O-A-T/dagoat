# GoatHAL Isolation Design (execution-isolation / Vector 1.1)

**Status:** contract + Phase-0 portable proof (AR96); Linux production backend design-first  
**Related:** `GoatHAL_Threat_Model.md`, `goatcoin-rs` `GoatBackend` trait (oracle), AR86 container hardening

---

## 1. Device/OS-agnostic contract

### 1.1 Roles

| Role | Responsibility |
|------|----------------|
| **Supervisor** (`goatd` host edge or library used by it) | Decides whether isolation is available; creates scratch; spawns worker; enforces timeout/caps; interprets exit codes; **never** runs payload code in-process |
| **Worker** (`goat-worker` binary) | Receives opaque task via IPC; may only touch scratch + policy-allowed ops; exits with structured status |
| **Payload** | Fully opaque bytes — no content inspection in protocol |

### 1.2 API surface (logical)

```text
check_isolation() -> Available { caps } | Unavailable { reason }
execute(task: OpaqueTask, policy: ExecPolicy) -> Result<WorkerReport, IsolationError>
```

`ExecPolicy` (device-agnostic): max wall time, max memory bytes, max CPU fraction (ties to power dial / cgroups), scratch path, network allowlist (default empty).

`OpaqueTask`: `task_id`, `class_tag: OpaqueTag` (**never inspected**), `payload: bytes` (bounded).

### 1.3 Fail-closed rule

| Condition | Behavior |
|-----------|----------|
| Isolation unavailable (OS lacks primitives, worker binary missing, policy refuses) | **Do not execute** payloads; mesh verification/gossip may continue |
| Dev escape | Only with explicit flag **and** loopback-class bind (mirror Track-A / identity-hardening discipline) — never on public bind |
| Worker crash / timeout / OOM | Contained failure report; restart policy optional; **no** host unsandboxed fallback |

### 1.4 Neutrality

- No device-type names or branches in protocol or isolation **contract** code.  
- Device backends plug in **below** a future HAL trait; isolation wraps *any* backend the same way.

---

## 2. Out-of-process worker model

```
goatd  --spawn-->  goat-worker
         stdin:  framed request
         stdout: framed response
         env:    GOAT_SCRATCH=<temp>
         cwd:    <temp>
         kill:   on timeout / parent drop
```

Justification for a **second binary:** `goatd` remains the only async network daemon; the worker is a short-lived, **network-policy-denied**, non-daemon executor. This preserves the sealed core’s `#![no_std]` boundary and matches DEPLOY’s “crypto at host edge” pattern.

---

## 3. Resource caps ↔ power dial

| Cap | Source |
|-----|--------|
| CPU | Docker `GOATD_CPU_LIMIT` / cgroups; desktop Power Dial → process priority (existing); worker wall-time hard kill |
| Memory | rlimit / Job Object memory limit; default Phase-0: 256 MiB (configurable) |
| Time | ExecPolicy wall-clock (default 5 s for probes; longer for real tasks later) |
| Disk | Scratch quota (Phase-0: OS temp dir + size check; production: quota/loop mount) |

---

## 4. Concrete backends

### 4.1 Phase-0 (shipped proof) — portable process isolation

| Control | Mechanism |
|---------|-----------|
| Separate process | Always |
| Scratch-only FS policy | Worker refuses paths outside `GOAT_SCRATCH` |
| No network | Worker policy rejects connect; no mesh keys in env |
| No multi-process spawn | Worker rejects spawn probes; Unix: optional `RLIMIT_NPROC`; Windows: Job active-process limit when available |
| Crash isolation | Parent waits; exit status → `WorkerReport::Crashed` |
| Timeout | Kill child after deadline |

This is **sufficient to prove the boundary property** for opaque probe payloads; it is **not** a full production sandbox.

### 4.2 Linux production (design — next turn)

- User namespace + mount namespace (scratch bind-mount only)  
- Network namespace empty (no net)  
- `seccomp-bpf` default-deny with allowlist for compute syscalls  
- `cap_drop: ALL`, `no_new_privs`, unprivileged uid  
- cgroups v2 CPU/memory matching power dial  
- Optional: Landlock LSM for path confinement  

### 4.3 Windows / macOS (design-only)

| OS | Direction |
|----|-----------|
| Windows | AppContainer / Job Object + restricted token; same IPC contract |
| macOS | `sandbox-exec` / App Sandbox profile; same IPC contract |

---

## 5. Mapping to AR86 container posture

Container hardening (non-root, read-only root, `cap_drop: ALL`, `no-new-privileges`, tmpfs scratch) applies to **`goatd`**. Worker isolation is a **second** concentric ring: even if a payload breaks the worker, it should not reach `goatd` or the host home directory.

---

## 6. Integration path (future, not this directive)

1. `goatd` loads isolation at boot → `check_isolation()`.  
2. Task assignment path calls `execute()` only if Available.  
3. Result commitment / attestation remains protocol-layer (device-blind).  
4. Crashes feed content-blind submitter throttling (Threat Model V5) — later.

---

## 7. Honesty

Phase-0 proves **process containment + policy denials + goatd survival**, not “secure multi-tenant GPU sandbox product.” `RUNTIME_VS_SPEC` must remain PARTIAL/design-honest until Linux production backend is verified under hostile payloads on real hardware.
