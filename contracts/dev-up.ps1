# contracts/dev-up.ps1 — one-command local Season-0 dev chain (runbook §1, automated).
# Starts anvil if needed, deploys + wires the free-market v2 contracts, deploys + wires
# the optimistic EpochSettlement lane (fresh HoldbackEscrow, FounderResolver, a watcher,
# and one demo enrolled worker), refreshes the desktop app's address configs, and seeds
# the founder with test tokens:
#   - 10,000 mockUSDT (public test faucet mint)
#   - 100 GOAT via the REAL mint path (a dev-seed job + one founder-signed mintBatch;
#     GoatCoin's "WorkMinter is the only mint path" stays true — there is no dev mint).
# The season0-fah job is intentionally NOT created here so the Ops-tab button can be
# exercised in the UI. Re-runnable: each run redeploys and refreshes the copied JSONs.
$ErrorActionPreference = "Stop"
$env:PATH = "$env:USERPROFILE\.foundry\bin;$env:PATH"

$RPC         = "http://127.0.0.1:8545"
$SAFE        = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"   # anvil account 0
$SAFE_KEY    = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
$RESERVE     = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"   # anvil account 2
$WATCHER     = "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"   # anvil account 4
$WATCHER_KEY = "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a"
$WORKER      = "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc"   # anvil account 5 (demo enrolled worker)
$WORKER_KEY  = "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba"
$ZERO32      = "0x" + ("0" * 64)

function Test-Rpc {
    # $ErrorActionPreference = "Stop" (set below) would otherwise turn the
    # redirected-stderr NativeCommandError from a refused connection into a
    # terminating error on PowerShell 5.1 — this is the expected "anvil not
    # up yet" case, so relax it for just this call.
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $null = cast block-number --rpc-url $RPC 2>$null
    } finally {
        $ErrorActionPreference = $prevEap
    }
    return ($LASTEXITCODE -eq 0)
}

# --- 1. anvil ---------------------------------------------------------------
if (-not (Test-Rpc)) {
    Write-Host "Starting anvil in a new window..."
    Start-Process -FilePath "anvil"
    $up = $false
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 500
        if (Test-Rpc) { $up = $true; break }
    }
    if (-not $up) { throw "anvil did not answer on $RPC within 20s" }
} else {
    Write-Host "anvil already running on $RPC"
}

# --- 2. deploy ---------------------------------------------------------------
Push-Location $PSScriptRoot
try {
    $env:SAFE_ADDRESS         = $SAFE
    $env:FOUNDER_ADDRESS      = $SAFE
    $env:RESERVE_ADDRESS      = $RESERVE
    $env:DEPLOYER_PRIVATE_KEY = $SAFE_KEY
    forge script script/DeployFreeMarket.s.sol --rpc-url $RPC --broadcast
    if ($LASTEXITCODE -ne 0) { throw "deploy failed" }

    # --- 3. addresses ---------------------------------------------------------
    $d = Get-Content (Join-Path $PSScriptRoot "deployments\31337.json") -Raw | ConvertFrom-Json
    $REGISTRY = $d.enrollmentRegistry; $GOAT = $d.goatCoin; $ESCROW = $d.holdbackEscrow
    $MINTER   = $d.workMinter;         $DESK = $d.buyDesk;  $USDT   = $d.mockUSDT

    # --- 4. wire (runbook §1) ---------------------------------------------------
    cast send $ESCROW "setVault(address)" $MINTER --private-key $SAFE_KEY --rpc-url $RPC | Out-Null
    cast send $GOAT "setMinter(address,bool)" $MINTER true --private-key $SAFE_KEY --rpc-url $RPC | Out-Null
    foreach ($a in @($ESCROW, $MINTER, $DESK, $SAFE, $RESERVE)) {
        cast send $REGISTRY "setSystemAddress(address,bool)" $a true --private-key $SAFE_KEY --rpc-url $RPC | Out-Null
    }

    # --- 5. refresh the app's address config ------------------------------------
    Copy-Item (Join-Path $PSScriptRoot "deployments\31337.json") `
              (Join-Path $PSScriptRoot "..\desktop\src\chain\deployments\31337.json") -Force

    # --- 6. seed ------------------------------------------------------------------
    # 10,000 mockUSDT (6 decimals) to founder/safe
    cast send $USDT "mint(address,uint256)" $SAFE 10000000000 --private-key $SAFE_KEY --rpc-url $RPC | Out-Null
    # 1,000 mockUSDT to anvil #2 (lab RELAYER key / RESERVE) so the gasless relayer is "funded"
    # for desk/test flows that need USDT on that address. Relayer gas is still ETH (anvil seeds).
    cast send $USDT "mint(address,uint256)" $RESERVE 1000000000 --private-key $SAFE_KEY --rpc-url $RPC | Out-Null
    # 100 GOAT through the real mint path: dev-seed job (0 holdback) + one mintBatch.
    $DEV_JOB      = (cast keccak "dev-seed").Trim()
    $DEV_CATALOG  = (cast keccak "dev-seed-catalog").Trim()
    $DEV_MANIFEST = (cast keccak "dev-seed-manifest").Trim()
    # Re-run friendly: skip if this manifestRoot was already minted (WorkMinter
    # blocks replay on-chain anyway; usedManifest is the simple check for us).
    $used = cast call $MINTER "usedManifest(bytes32)(bool)" $DEV_MANIFEST --rpc-url $RPC
    if ($used.Trim() -ne "true") {
        cast send $MINTER "createJob(bytes32,bytes32,uint256,uint16,address,bool)" `
            $DEV_JOB $DEV_CATALOG 1000000000000000000 0 0x0000000000000000000000000000000000000000 true `
            --private-key $SAFE_KEY --rpc-url $RPC | Out-Null
        cast send $MINTER "mintBatch(bytes32,bytes32,address[],uint256[])" `
            $DEV_JOB $DEV_MANIFEST "[$SAFE]" "[100]" `
            --private-key $SAFE_KEY --rpc-url $RPC | Out-Null
    } else {
        Write-Host "dev-seed job already minted - skipping GOAT seed"
    }

    # --- 6b. BuyDeskFactory (donor multi-desk design, 2026-07-13): any
    #     enrolled wallet can become a donor from its own wallet via
    #     factory.createDesk(); the founder's desk is created THROUGH the
    #     factory too, so founder + donor desks share one DeskCreated index. --
    $env:GOAT_ADDRESS     = $GOAT
    $env:REGISTRY_ADDRESS = $REGISTRY
    $env:USDT_ADDRESS     = $USDT
    forge script script/DeployBuyDeskFactory.s.sol --rpc-url $RPC --broadcast
    if ($LASTEXITCODE -ne 0) { throw "BuyDeskFactory deploy failed" }

    $f = Get-Content (Join-Path $PSScriptRoot "deployments\31337.factory.json") -Raw | ConvertFrom-Json
    $FACTORY = $f.buyDeskFactory

    # founder's desk, created via the factory (not a standalone BuyDesk).
    cast send $FACTORY "createDesk(string)" "Founder Desk" --private-key $SAFE_KEY --rpc-url $RPC | Out-Null
    $FOUNDER_DESK = (cast call $FACTORY "deskOf(address)(address)" $SAFE --rpc-url $RPC).Trim()

    # Allowance model (spec 2026-07-13-allowance-buydesk-design): a desk spends
    # the owner's WALLET USDT up to an approved cap — there is NO fund step and
    # the desk never custodies USDT. Set the founder desk's cap to 5,000 USDT
    # (approve) and open a long trade session with no per-seller limit, so the
    # app boots with a live, sellable-to desk instead of an empty one.
    $CAP_MAX = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    cast send $USDT "approve(address,uint256)" $FOUNDER_DESK 5000000000 --private-key $SAFE_KEY --rpc-url $RPC | Out-Null
    $sesNow = [int][double]::Parse((Get-Date -UFormat %s)) - 3600     # 1h in the past for clock-skew safety
    $sesEnd = $sesNow + 31536000                                       # ~1 year window
    cast send $FOUNDER_DESK "openSession(uint64,uint64,uint256)" $sesNow $sesEnd $CAP_MAX --private-key $SAFE_KEY --rpc-url $RPC | Out-Null

    Copy-Item (Join-Path $PSScriptRoot "deployments\31337.factory.json") `
              (Join-Path $PSScriptRoot "..\desktop\src\chain\deployments\31337.factory.json") -Force

    # --- 7. EpochSettlement deploy (optimistic FAH-payout lane, spec 2026-07-13) ---
    # Fresh HoldbackEscrow — the free-market one above is vault-locked to WorkMinter
    # (setVault is one-shot), so the settlement lane needs its own.
    $env:GOAT_ADDRESS     = $GOAT
    $env:REGISTRY_ADDRESS = $REGISTRY
    $env:WATCHER_ADDRESS  = $WATCHER
    forge script script/DeployEpochSettlement.s.sol --rpc-url $RPC --broadcast
    if ($LASTEXITCODE -ne 0) { throw "EpochSettlement deploy failed" }

    $e = Get-Content (Join-Path $PSScriptRoot "deployments\31337.epoch.json") -Raw | ConvertFrom-Json
    $EPOCH_ESCROW   = $e.epochHoldbackEscrow
    $EPOCH_SETTLE   = $e.epochSettlement
    $EPOCH_RESOLVER = $e.founderResolver

    # --- 8. wire EpochSettlement (the five NEXT calls the script prints) ----------
    cast send $EPOCH_ESCROW "setVault(address)" $EPOCH_SETTLE --private-key $SAFE_KEY --rpc-url $RPC | Out-Null
    cast send $GOAT "setMinter(address,bool)" $EPOCH_SETTLE true --private-key $SAFE_KEY --rpc-url $RPC | Out-Null
    cast send $REGISTRY "setSystemAddress(address,bool)" $EPOCH_SETTLE true --private-key $SAFE_KEY --rpc-url $RPC | Out-Null
    cast send $REGISTRY "setSystemAddress(address,bool)" $EPOCH_ESCROW true --private-key $SAFE_KEY --rpc-url $RPC | Out-Null
    cast send $EPOCH_SETTLE "setResolver(address)" $EPOCH_RESOLVER --private-key $SAFE_KEY --rpc-url $RPC | Out-Null

    # Enroll founder (anvil #0) + demo worker so Wallet import of #0 is immediately usable.
    # Workers/donors can also call enrollSelf() (permissionless; pays own ETH gas).
    cast send $REGISTRY "setEnrolled(address,bool,bytes32)" $SAFE true $ZERO32 --private-key $SAFE_KEY --rpc-url $RPC | Out-Null
    cast send $REGISTRY "setEnrolled(address,bool,bytes32)" $WORKER true $ZERO32 --private-key $SAFE_KEY --rpc-url $RPC | Out-Null

    # --- 9. refresh the app's epoch address config ---------------------------------
    Copy-Item (Join-Path $PSScriptRoot "deployments\31337.epoch.json") `
              (Join-Path $PSScriptRoot "..\desktop\src\chain\deployments\31337.epoch.json") -Force

    # --- 10. checklist ---------------------------------------------------------------
    $goatBal = cast call $GOAT "balanceOf(address)(uint256)" $SAFE --rpc-url $RPC
    $usdtBal = cast call $USDT "balanceOf(address)(uint256)" $SAFE --rpc-url $RPC
    $relayerUsdt = cast call $USDT "balanceOf(address)(uint256)" $RESERVE --rpc-url $RPC
    Write-Host ""
    Write-Host "=== dev-up complete ==============================================="
    Write-Host " RPC          : $RPC (chain 31337)"
    Write-Host " workMinter   : $MINTER"
    Write-Host " founder GOAT : $goatBal (wei, expect 100000000000000000000)"
    Write-Host " founder USDT : $usdtBal (6dp, expect 10000000000)"
    Write-Host " relayer USDT : $relayerUsdt (6dp, expect 1000000000 = 1000 MockUSDT on anvil #2 $RESERVE)"
    Write-Host " relayer key  : anvil#2 (RELAYER_PRIVATE_KEY only; do not import as a worker wallet)"
    Write-Host " app config   : desktop\src\chain\deployments\31337.json refreshed"
    Write-Host " ---- BuyDeskFactory (donor multi-desk) ----------------------------"
    Write-Host " factory      : $FACTORY"
    Write-Host " founder desk : $FOUNDER_DESK (cap 5000 USDT via approve, session open ~1yr)"
    Write-Host " factory cfg  : desktop\src\chain\deployments\31337.factory.json refreshed"
    Write-Host " ---- EpochSettlement (optimistic FAH-payout lane) ----------------"
    Write-Host " epochEscrow  : $EPOCH_ESCROW"
    Write-Host " epochSettle  : $EPOCH_SETTLE"
    Write-Host " founderRslvr : $EPOCH_RESOLVER"
    Write-Host " watcher      : $WATCHER"
    Write-Host " watcher key  : $WATCHER_KEY"
    Write-Host " founder/safe : $SAFE (enrolled) key=anvil#0"
    Write-Host " demo worker  : $WORKER (enrolled)"
    Write-Host " worker key   : $WORKER_KEY"
    Write-Host " epoch config : desktop\src\chain\deployments\31337.epoch.json refreshed"
    Write-Host " next         : import anvil #0 in Wallet (auto-enrolls if needed); donor desk = Market"
    Write-Host "==================================================================="
} finally {
    Pop-Location
}
