# goat-attestor — Clippy Cleanup Report

**Date:** 2026-07-17
**Package:** `tools/goat-attestor` (standalone Cargo package, not in the root workspace; untracked in git)
**Toolchain:** rustc 1.96.1 (31fca3adb 2026-06-26) · clippy 1.96
**Scope:** 4 files · 6 lints · 0 `#[allow]` added · no behavior change

---

## Summary

Six clippy lints were blocking `cargo clippy --all-targets -- -D warnings` in `goat-attestor`.
All of them pre-date the 2026-07-16/17 keeper-fee and ordering-barrier changes — the package was
verified byte-identical before and after those changes, so this is unrelated maintenance.

Every fix is the idiomatic rewrite clippy suggests, with **one justified deviation** (documented
below). No lint was silenced with `#[allow]`, and no runtime behavior changed.

### Verdicts

| Command | Result |
|---|---|
| `cargo clippy --all-targets -- -D warnings` | **exit 0** — no issues found |
| `cargo test` | **73 passed · 1 ignored** (env-gated) · 0 failed |

---

## Findings at a glance

| Location | Lint | Fix |
|---|---|---|
| `src/chain.rs:24` | `derivable_impls` | Manual `Default` impl → `#[derive(Default)]` + `#[default]` |
| `src/chain.rs:293` | `manual_repeat_n` | `repeat(0u8).take(pad)` → `repeat_n(0u8, pad)` |
| `src/challenger.rs:171` | `collapsible_if` | Nested `if` collapsed; inner check was tautological |
| `src/challenger.rs:199` | `into_iter_on_ref` | `.into_iter()` on a slice ref → `.iter()` |
| `src/registry.rs:104` | `doc_lazy_continuation` | Blank `///` line so "Returns …" is its own paragraph |
| `src/merkle.rs:298` | `needless_range_loop` | Index loop → `iter().enumerate()` (test-only) |

---

## src/chain.rs

### Derive `Default` for `BatchStatus` — `derivable_impls`

The manual impl only restated what the derive expresses: `None` is the default variant.
The `#[repr(u8)]` discriminants are untouched.

```diff
-#[derive(Debug, Clone, Copy, PartialEq, Eq)]
+#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
 #[repr(u8)]
 pub enum BatchStatus {
+    #[default]
     None = 0,
     ...
 }
-
-impl Default for BatchStatus {
-    fn default() -> Self {
-        Self::None
-    }
-}
```

### Zero-padding in `abi_encode_bytes` — `manual_repeat_n`

Same iterator, expressed with the dedicated constructor. Identical output bytes.

```diff
     let pad = (32 - (data.len() % 32)) % 32;
-    out.extend(std::iter::repeat(0u8).take(pad));
+    out.extend(std::iter::repeat_n(0u8, pad));
```

---

## src/challenger.rs

### Redundant nested status check in `review_epoch` — `collapsible_if`

The inner condition (`status != Proposed`) is always true whenever the outer one
(`status != Proposed && status != None`) holds, so the collapse is behavior-identical:
epochs that are already challenged, settled, or finalized short-circuit to
`ChallengeDecision::Ok`, exactly as before.

```diff
-        if batch.status != BatchStatus::Proposed && batch.status != BatchStatus::None {
-            if batch.status != BatchStatus::Proposed {
-                return Ok(ChallengeDecision::Ok);
-            }
-        }
+        if batch.status != BatchStatus::Proposed && batch.status != BatchStatus::None {
+            return Ok(ChallengeDecision::Ok);
+        }
```

> **Deviation from clippy's literal suggestion.** Clippy proposed joining the two conditions
> with `&&`, which duplicates the `!= Proposed` term and would immediately trip `nonminimal_bool`.
> Dropping the tautological inner check reaches the same fixed point in one step. This is the only
> place the fix isn't clippy's verbatim rewrite.

### Iterating a returned slice — `into_iter_on_ref`

`all_bound()` returns `&[WorkerEntry]`; on a shared slice reference, `.into_iter()` already yields
`&WorkerEntry`, so `.iter()` is the same iterator under its honest name.

```diff
         let reg_lookup: HashMap<String, bool> = registry
             .all_bound()
-            .into_iter()
+            .iter()
             .map(|w| (w.wallet.to_ascii_lowercase(), w.baseline_batched))
             .collect();
```

---

## src/registry.rs

### Doc comment on `sync_from_bound_workers` — `doc_lazy_continuation`

Markdown was folding the "Returns …" line into the last bullet as a lazy continuation.
A blank doc line makes it the standalone paragraph it was meant to be — rendered docs change,
code doesn't.

```diff
 /// - Existing: refresh `username` if changed; keep `baseline_batched` / `fah_id`.
+///
 /// Returns how many **new** workers were added.
```

---

## src/merkle.rs (test)

### Index loop in `odd_node_carry_three_leaves` — `needless_range_loop`

`leaves` holds exactly three entries, so `iter().enumerate()` visits the same indices as `0..3`.
The proof index `i` is still available for `tree.proof(i)` and the assertion message.

```diff
-        for i in 0..3 {
-            let proof = tree.proof(i).unwrap();
-            assert!(
-                verify(leaf_hash(&leaves[i]), &proof, tree.root()),
-                "proof failed for leaf {i}"
-            );
-        }
+        for (i, leaf) in leaves.iter().enumerate() {
+            let proof = tree.proof(i).unwrap();
+            assert!(
+                verify(leaf_hash(leaf), &proof, tree.root()),
+                "proof failed for leaf {i}"
+            );
+        }
```

---

## Verification evidence

Both gates were run after the last edit, from the package root:

```
$ cargo clippy --all-targets -- -D warnings
No issues found            (exit 0)

$ cargo test
73 passed, 1 ignored, 0 failed    (5 suites)
```

The single ignored test is the known env-gated case and was ignored before this change as well.
The baseline expectation was ~71+ passed; 73 passed matches the current suite.

---

## Housekeeping notes

- `tools/goat-attestor` is **not tracked** in the `F:\` git repository (it shows as a single
  untracked directory). These fixes exist on disk only — there is no commit, and the branch
  worktree checkout does not contain the package at all.
- No `#[allow]` attributes were introduced; every lint got its idiomatic rewrite.
- Scope was strictly mechanical: 4 files, 6 lints, no API, logic, or dependency changes.
