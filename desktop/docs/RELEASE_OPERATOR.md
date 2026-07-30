# Stream D0 — Operator release checklist

**Audience:** founder packaging the pilot Windows build.  
**Decisions (locked 2026-07-20):** NSIS+MSI · GitHub Releases/private · minisign on `SHA256SUMS.txt` · **no** Authenticode · **no** updater.

---

## 0. Hard gates before you build

- [ ] **B-live freeze:** `src/chain/deployments/84532.json` core addresses non-null (not placeholders).  
- [ ] **No redeploy** of those contracts after freeze (G-B2) unless you reinstall all volunteers.  
- [ ] **Stream E:** tunnel hostname final (baked into `VITE_ATTESTOR_RELAYER_URL`).  
- [ ] **Stream C env:** `.env.production.local` with at least:
  - `VITE_DEFAULT_NETWORK_ID=84532`
  - `VITE_PILOT=1`
  - `VITE_ATTESTOR_RELAYER_URL=https://…`
  - optional `VITE_CF_ACCESS_CLIENT_ID` / `VITE_CF_ACCESS_CLIENT_SECRET` (both or neither)
- [ ] Versions aligned (`package.json` / `tauri.conf.json` / `Cargo.toml` / `version.js`)

Fail-closed check (must exit 0 only when freeze is real):

```powershell
cd desktop
powershell -ExecutionPolicy Bypass -File scripts\release-check.ps1
# after env is ready for pilot:
powershell -ExecutionPolicy Bypass -File scripts\release-check.ps1 -StrictEnv
```

Today (pre B-live) this **must FAIL** on null 84532 — that proves the gate.

---

## 1. Tooling: WiX (MSI) + minisign

### WiX Toolset v3 (for MSI)

Tauri MSI needs **candle.exe** + **light.exe** on PATH.

```powershell
winget install --id WiXToolset.WiX -e
# or: choco install wixtoolset
# NEW shell, then:
where.exe candle
where.exe light
```

If WiX is missing, `release-check` **warns** and `release-build` builds **NSIS only** (valid pilot).  
Hard dual-installer gate: `release-check.ps1 -RequireWix`.

### Minisign keypair (once) — **outside the repo**

```powershell
# NEVER create minisign.key under desktop/ (gitignored but still a leak risk)
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.secrets" | Out-Null
minisign -G -p "$env:USERPROFILE\.secrets\minisign.pub" -s "$env:USERPROFILE\.secrets\minisign.key"
$env:MINISIGN_SECRET_KEY = "$env:USERPROFILE\.secrets\minisign.key"
# Publish only minisign.pub with the GitHub Release
```

`release-hash.ps1` **refuses** to sign if the secret key path is under `desktop/`.  
If `minisign` is missing, it still writes `SHA256SUMS.txt` and warns.

### Parallel installs (currentUser)

Pilotset uses **`installMode: currentUser`** (`%LOCALAPPDATA%`). An older **machine-wide** (Program Files) install will **not** upgrade — Windows keeps both. Tell testers to uninstall Program Files builds first (`VOLUNTEER_INSTALL.md`).

---

## 2. Build + stage

```powershell
cd desktop
powershell -ExecutionPolicy Bypass -File scripts\release-build.ps1 -StrictEnv
```

Produces `desktop/dist-release/<version>/` with:

- NSIS `.exe` and MSI `.msi`  
- `SHA256SUMS.txt`  
- `SHA256SUMS.txt.minisig` (if minisign + key available)  
- `VOLUNTEER_INSTALL.md`  

`dist-release/` is gitignored.

---

## 3. Scrub before upload

- [ ] No `.env.production.local` in the stage folder  
- [ ] No `minisign.key` / `.pfx`  
- [ ] No internal strategy-tree paths / monorepo paths / deployer keys in any text you attach  
- [ ] Public GitHub: only the **export** repo after scrub — not raw `F:\` monorepo dump  

---

## 4. Publish (GitHub Releases / private)

- [ ] Create a **private** or unlisted Release for the pilot org/repo  
- [ ] Upload all files from `dist-release/<version>/`  
- [ ] Paste **SHA256SUMS.txt** body into the Release notes  
- [ ] Attach `minisign.pub` (public key only)  

---

## 5. Invite volunteers

- [ ] Send Release link + instruct: **verify hash before install**  
- [ ] Point them at `VOLUNTEER_INSTALL.md` (SmartScreen “More info → Run anyway”)  
- [ ] Remind: testnet only; Access is not a login  

---

## 6. After the pilot week

- [ ] Rotate CF Access token if it was embedded  
- [ ] Do **not** redeploy 84532 contracts without a reinstall plan  
- D1 Authenticode / D2 updater remain **out of scope** until reopened  

---

## Scripts reference

| Script | Role |
|---|---|
| `scripts/release-check.ps1` | Version + 84532 freeze + targets |
| `scripts/release-build.ps1` | Check → env → `tauri build` → stage → hash |
| `scripts/release-hash.ps1` | SHA-256 + optional minisign |
| `scripts/release-check.mjs` | Node CLI used by the PS1 wrapper |
| `scripts/release-gates.mjs` | Pure gates (unit-tested) |
