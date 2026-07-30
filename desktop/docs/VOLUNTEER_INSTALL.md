# D.A. G.O.A.T. — Volunteer install (Windows pilot)

**Testnet pilot only.** This app is for a small private trial on **Base Sepolia**.  
GOAT here is a **testnet** pilot token. Trade price is a posted session bid and may find **zero buyers**.  
Nothing here is a wage, salary, income, or guaranteed return.

---

## 1. What you need

- Windows 10/11 x64  
- A download link from the pilot operator (GitHub Release or private share)  
- The matching **SHA256SUMS.txt** from the **same** release  

Artifacts (names may vary slightly by Tauri version):

- `…-setup.exe` — **NSIS** installer (usual choice)  
- `….msi` — **MSI** installer (optional; same app)  
- `SHA256SUMS.txt` — checksums  
- `SHA256SUMS.txt.minisig` — optional minisign signature (if the operator published a public key)

This pilot build is **not Authenticode-signed**. Windows may show **“Windows protected your PC”** (SmartScreen). That is expected.

---

## 2. Verify the file (do this before install)

In PowerShell, in the folder where you downloaded the installer:

```powershell
Get-FileHash .\YOUR-INSTALLER-NAME.exe -Algorithm SHA256
```

Open `SHA256SUMS.txt` and confirm the hash matches the line for that filename  
(format: `<hash>  <filename>`, hash is lowercase hex).

**If the hash does not match: do not install.** Delete the file and contact the operator.

Optional (if `minisign` and the operator’s public key are available):

```powershell
minisign -Vm SHA256SUMS.txt -p minisign.pub
```

---

## 3. SmartScreen (“Unknown publisher”)

Because this pilot is **unsigned**:

1. If Windows shows **Windows protected your PC** → click **More info**.  
2. Click **Run anyway**.  

Wording can vary by Windows version. You are trusting the **operator + hash**, not Microsoft’s publisher reputation.

---

## 4. Install

1. **If you installed an older pilot build “for all users” (Program Files):** uninstall it first  
   (**Settings → Apps**). This pilot uses a **current-user** install (`%LOCALAPPDATA%`).  
   Leaving both installs side-by-side creates **two apps** and confusing shortcuts.  
2. Run the **NSIS** `*-setup.exe` (or the `.msi` if the operator published one).  
3. Prefer **current user** / no admin when offered.  
4. Launch **D.A. G.O.A.T.** from the Start menu / desktop shortcut.

---

## 5. First launch checklist

1. Network should be **Base Sepolia** (Local anvil is hidden in pilot builds).  
2. Create or unlock a **testnet** wallet — never paste a key that holds real funds.  
3. Set a FAH username starting with `GOAT-` if you join the GOAT pilot path.  
4. **Bind & enroll** uses the pilot relayer (gasless). New wallets often have **0 ETH**; gas top-up is limited per day.  
5. Selling GOAT uses **mock** USDT on testnet — not real dollars.

If you see an **access gate** or relayer error, contact the pilot operator (build may need Cloudflare Access credentials). That is **not** a wallet bug.

---

## 6. Honesty / what this is not

- Not mainnet. Not a securities offering. Not employment.  
- Cloudflare Access tokens (if any) inside the app are **bot friction**, not a personal login.  
- Holding GOAT forever is a first-class outcome; no one is forced to sell.

---

## 7. Uninstall

Windows **Settings → Apps** → find **D.A. G.O.A.T.** → Uninstall.  
Or use the uninstaller from the install folder / Start menu if provided.

---

## 8. Support

Contact the pilot operator who sent the download link. Include:

- App version (footer, e.g. `v0.1.0 · testnet`)  
- Whether hash verification passed  
- Exact error text (no private keys, no seed phrases)
