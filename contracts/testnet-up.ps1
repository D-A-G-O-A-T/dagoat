# contracts/testnet-up.ps1 - Stream B deploy+wire for Base Sepolia (84532) or anvil (31337).
#
# Port of contracts/dev-up.ps1 with env-driven keys/RPC (no hardcoded anvil keys).
# Does NOT start anvil. Does NOT assume funded accounts - you must fund deployer/SAFE first.
#
# Usage (Base Sepolia pilot):
#   $env:RPC_URL = "https://sepolia.base.org"   # or Alchemy
#   $env:CHAIN_ID = "84532"
#   $env:SAFE_ADDRESS = "0x..."
#   $env:FOUNDER_ADDRESS = "0x..."              # may equal SAFE
#   $env:RESERVE_ADDRESS = "0x..."
#   $env:WATCHER_ADDRESS = "0x..."
#   $env:DEPLOYER_PRIVATE_KEY = "0x..."         # funded on target chain
#   # optional: SAFE_PRIVATE_KEY if SAFE != deployer (defaults to DEPLOYER_PRIVATE_KEY)
#   powershell -ExecutionPolicy Bypass -File contracts\testnet-up.ps1
#
# Dry-run (print plan, no forge/cast broadcast):
#   powershell -ExecutionPolicy Bypass -File contracts\testnet-up.ps1 -DryRun
#
# After success:
#   - contracts/deployments/<chainId>.{json,factory.json,epoch.json}
#   - desktop copies refreshed
#   - epoch JSON gains workerBindingDeployBlock for G-B1
#   - run: tools/goat-attestor/sync-env-from-desktop.ps1 -ChainId 84532
#
# Fresh v2 stack only (B2) - do not set EXISTING_GOAT / EXISTING_REGISTRY / EXISTING_USDT.
# Founder freeze: this script mutates local files; it does not git commit.

param(
    [switch]$DryRun,
    [switch]$SkipSeed,
    [switch]$SkipEpoch
)

$ErrorActionPreference = "Stop"
$env:PATH = "$env:USERPROFILE\.foundry\bin;$env:PATH"

function Require-Env([string]$Name) {
    $v = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($v)) {
        throw "Missing required env $Name"
    }
    return $v.Trim()
}

function Get-EnvOr([string]$Name, [string]$Default) {
    $v = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($v)) { return $Default }
    return $v.Trim()
}

function Invoke-Step {
    param([string]$Label, [scriptblock]$Action, [string]$Preview)
    if ($DryRun) {
        Write-Host "[dry-run] $Label"
        if ($Preview) { Write-Host "         $Preview" }
        return
    }
    Write-Host ">>> $Label"
    & $Action
    if ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        throw "Step failed ($Label) exit=$LASTEXITCODE"
    }
    # Settle after EVERY step. See Wait-ForMempoolDrain: against a load-balanced
    # public RPC the next nonce read can be stale even with a receipt in hand,
    # and the failure surfaces one step later as a confusing "replacement
    # transaction underpriced" rather than at the step that actually raced.
    # A step that broadcast nothing settles immediately, so this is nearly free.
    if ($script:RPC -and $script:SAFE) {
        Wait-ForMempoolDrain -Rpc $script:RPC -Address $script:SAFE
    }
}

# 🔴 THE ANVIL-ONLY ASSUMPTION THAT BROKE THIS SCRIPT ON A REAL CHAIN.
#
# `forge script --broadcast` fires every deploy transaction without waiting for
# receipts. The `cast send` that follows computes its nonce from the LATEST
# (mined) block, so while the tail of the deploy is still pending it reuses a
# nonce that is already in the mempool, with no gas bump, and the node answers:
#
#   error code -32000: replacement transaction underpriced
#
# On anvil this race CANNOT happen -- mining is instant, so `latest` is never
# behind `pending`. That is exactly why it survived every 31337 run and failed
# on the first Base Sepolia attempt (2026-07-30): the standup twins had never
# been exercised against a real testnet, which was a recorded gap, not a
# surprise.
#
# Two layers, because a public RPC can lag its own mempool:
#   1. `--slow` on every `forge script` (below) -- send one transaction at a
#      time, waiting for each receipt.
#   2. This wait -- poll until the node agrees with itself that nothing of ours
#      is pending, before the first `cast send` of each phase.
#
# 🔴 AND `cast send` WAITING FOR ITS OWN RECEIPT IS NOT ENOUGH EITHER.
#
# An earlier revision of this comment claimed "cast send already waits for its
# own receipt, so consecutive sends are safe; only the forge -> cast transition
# needs this." Measured false on attempt 3: with the drain in place
# escrow.setVault landed and the very next send, goat.setMinter, died on the
# same -32000. sepolia.base.org is LOAD-BALANCED -- a receipt in hand does not
# mean the next `eth_getTransactionCount(latest)` is answered by a node that has
# seen it. So the wait runs after EVERY broadcasting step, not just after forge.
#
# It also requires the reading to be STABLE: latest == pending observed twice in
# a row, separated by a sleep. One agreeing reading can be two stale answers
# from the same lagging backend, which is a check that passes for the wrong
# reason -- the exact shape of vacuous assertion this repo keeps finding.
function Wait-ForMempoolDrain {
    param(
        [string] $Rpc,
        [string] $Address,
        [int] $TimeoutSeconds = 180,
        [int] $StableReadings = 2
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $agreed = 0
    $lastSeen = ""
    while ($true) {
        $latest = (cast nonce $Address --rpc-url $Rpc 2>$null | Out-String).Trim()
        $pending = (cast nonce $Address --rpc-url $Rpc --block pending 2>$null | Out-String).Trim()
        if ($latest -ne "" -and $latest -eq $pending -and $latest -eq $lastSeen) {
            $agreed++
            if ($agreed -ge $StableReadings) {
                Write-Host "    nonce settled at $latest ($agreed stable readings)"
                return
            }
        } elseif ($latest -ne "" -and $latest -eq $pending) {
            $agreed = 1
        } else {
            $agreed = 0
        }
        $lastSeen = $latest
        if ((Get-Date) -gt $deadline) {
            throw "nonce did not settle within ${TimeoutSeconds}s (latest=$latest pending=$pending). Re-running deploys a SECOND stack; do not retry blindly."
        }
        Start-Sleep -Seconds 2
    }
}

# Every state-changing send goes through here, and the settle is INSIDE it.
#
# Attempt 4 put the settle in Invoke-Step, which fixed every single-send step
# and then failed on `dev-seed GOAT`, a step that issues TWO sends -- the wait
# ran after the step, never between them. Putting it at the send is the level
# that has no such gap, and it is one implementation rather than a patch per
# multi-send step.
#
# Deliberately a SIMPLE function (no [CmdletBinding()]) so `$args` collects
# `--private-key` and friends verbatim; an advanced function would try to bind
# those as its own parameters. Array splatting into a NATIVE command passes
# arguments through correctly -- it is only PowerShell functions where an array
# splat binds positionally, which is the trap that caused the accidental
# deployment earlier today.
function Send-Tx {
    # NOT `Send-Tx @args` -- a sweep that rewrote every `cast send` call site
    # rewrote this line too and made the helper call itself. Caught by reading
    # the diff, not by running it; it would have recursed until the stack blew.
    cast send @args | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "cast send failed (exit=$LASTEXITCODE): $($args -join ' ')"
    }
    if ($script:RPC -and $script:SAFE) {
        Wait-ForMempoolDrain -Rpc $script:RPC -Address $script:SAFE
    }
}

function Get-WorkerBindingDeployBlock {
    param([string]$ContractsRoot, [string]$ChainId)
    $runPath = Join-Path $ContractsRoot "broadcast\DeployEpochSettlement.s.sol\$ChainId\run-latest.json"
    if (-not (Test-Path $runPath)) { return $null }
    try {
        $run = Get-Content $runPath -Raw | ConvertFrom-Json
    } catch {
        return $null
    }
    if (-not $run.transactions -or -not $run.receipts) { return $null }
    $n = [Math]::Min($run.transactions.Count, $run.receipts.Count)
    for ($i = 0; $i -lt $n; $i++) {
        $name = [string]$run.transactions[$i].contractName
        if ($name -eq "WorkerBinding" -or $name -like "*WorkerBinding*") {
            $bn = $run.receipts[$i].blockNumber
            if ($null -eq $bn) { continue }
            $s = [string]$bn
            if ($s.StartsWith("0x") -or $s.StartsWith("0X")) {
                return [Convert]::ToUInt64($s.Substring(2), 16)
            }
            return [uint64]$s
        }
    }
    # Fallback: earliest receipt block among this run
    $min = $null
    foreach ($r in $run.receipts) {
        if ($null -eq $r.blockNumber) { continue }
        $s = [string]$r.blockNumber
        $v = if ($s.StartsWith("0x") -or $s.StartsWith("0X")) {
            [Convert]::ToUInt64($s.Substring(2), 16)
        } else {
            [uint64]$s
        }
        if ($null -eq $min -or $v -lt $min) { $min = $v }
    }
    return $min
}

function Write-EpochWithDeployBlock {
    param([string]$EpochPath, $DeployBlock)
    if ($null -eq $DeployBlock) { return }
    if (-not (Test-Path $EpochPath)) { return }
    $obj = Get-Content $EpochPath -Raw | ConvertFrom-Json
    $obj | Add-Member -NotePropertyName workerBindingDeployBlock -NotePropertyValue ([int64]$DeployBlock) -Force
    # 🔴 NOT `Set-Content -Encoding utf8`. On Windows PowerShell 5.1 that writes a
    # UTF-8 BOM, and `JSON.parse` rejects a leading BOM outright. This is the ONLY
    # manifest PowerShell rewrites -- forge writes the other two -- so 84532.epoch.json
    # and its desktop copy were the only two files in the deployment carrying one,
    # which is exactly the kind of asymmetry that gets found by a reader rather
    # than by the writer. Found 2026-07-30 when the bytecode verifier choked on it.
    [System.IO.File]::WriteAllText(
        $EpochPath,
        ($obj | ConvertTo-Json -Depth 6),
        (New-Object System.Text.UTF8Encoding($false))
    )
}

# --- resolve config ----------------------------------------------------------
$RPC       = Get-EnvOr "RPC_URL" ""
$CHAIN_ID  = Get-EnvOr "CHAIN_ID" "84532"
$SAFE      = Get-EnvOr "SAFE_ADDRESS" ""
$FOUNDER   = Get-EnvOr "FOUNDER_ADDRESS" ""
$RESERVE   = Get-EnvOr "RESERVE_ADDRESS" ""
$WATCHER   = Get-EnvOr "WATCHER_ADDRESS" ""
$DEPLOY_KEY = Get-EnvOr "DEPLOYER_PRIVATE_KEY" ""
$SAFE_KEY  = Get-EnvOr "SAFE_PRIVATE_KEY" $DEPLOY_KEY

if ($CHAIN_ID -ne "84532" -and $CHAIN_ID -ne "31337") {
    throw "CHAIN_ID must be 84532 (Base Sepolia) or 31337 (anvil); got $CHAIN_ID"
}

if (-not $DryRun) {
    if ([string]::IsNullOrWhiteSpace($RPC)) { throw "RPC_URL required (unless -DryRun)" }
    Require-Env "SAFE_ADDRESS" | Out-Null
    Require-Env "FOUNDER_ADDRESS" | Out-Null
    Require-Env "RESERVE_ADDRESS" | Out-Null
    Require-Env "WATCHER_ADDRESS" | Out-Null
    Require-Env "DEPLOYER_PRIVATE_KEY" | Out-Null
    $SAFE = Require-Env "SAFE_ADDRESS"
    $FOUNDER = Require-Env "FOUNDER_ADDRESS"
    $RESERVE = Require-Env "RESERVE_ADDRESS"
    $WATCHER = Require-Env "WATCHER_ADDRESS"
    $DEPLOY_KEY = Require-Env "DEPLOYER_PRIVATE_KEY"
    $SAFE_KEY = Get-EnvOr "SAFE_PRIVATE_KEY" $DEPLOY_KEY
} else {
    if ([string]::IsNullOrWhiteSpace($RPC)) { $RPC = "<RPC_URL>" }
    if ([string]::IsNullOrWhiteSpace($SAFE)) { $SAFE = "<SAFE_ADDRESS>" }
    if ([string]::IsNullOrWhiteSpace($FOUNDER)) { $FOUNDER = "<FOUNDER_ADDRESS>" }
    if ([string]::IsNullOrWhiteSpace($RESERVE)) { $RESERVE = "<RESERVE_ADDRESS>" }
    if ([string]::IsNullOrWhiteSpace($WATCHER)) { $WATCHER = "<WATCHER_ADDRESS>" }
    if ([string]::IsNullOrWhiteSpace($DEPLOY_KEY)) { $DEPLOY_KEY = "<DEPLOYER_PRIVATE_KEY>" }
    if ([string]::IsNullOrWhiteSpace($SAFE_KEY)) { $SAFE_KEY = "<SAFE_PRIVATE_KEY|DEPLOYER>" }
}

$ZERO32 = "0x" + ("0" * 64)
$ContractsRoot = $PSScriptRoot
$DesktopDep = Join-Path $ContractsRoot "..\desktop\src\chain\deployments"
$DepBase = Join-Path $ContractsRoot "deployments\$CHAIN_ID.json"
$DepFactory = Join-Path $ContractsRoot "deployments\$CHAIN_ID.factory.json"
$DepEpoch = Join-Path $ContractsRoot "deployments\$CHAIN_ID.epoch.json"

Write-Host "=== testnet-up (Stream B) =========================================="
Write-Host " chain        : $CHAIN_ID"
Write-Host " RPC          : $RPC"
Write-Host " SAFE/FOUNDER : $SAFE / $FOUNDER"
Write-Host " RESERVE      : $RESERVE"
Write-Host " WATCHER      : $WATCHER"
Write-Host " DryRun       : $DryRun  SkipSeed=$SkipSeed  SkipEpoch=$SkipEpoch"
Write-Host " B2           : fresh stack (do not set EXISTING_*)"
Write-Host "===================================================================="

# Refuse leftover EXISTING_* so we never silently reuse v1 (B2).
foreach ($k in @("EXISTING_GOAT", "EXISTING_REGISTRY", "EXISTING_USDT")) {
    $v = [Environment]::GetEnvironmentVariable($k)
    if (-not [string]::IsNullOrWhiteSpace($v) -and $v -ne "0x0000000000000000000000000000000000000000") {
        throw "B2: unset $k for a fresh v2 deploy (got $v). Reusing v1 is not supported by this script."
    }
}

Push-Location $ContractsRoot
try {
    $env:SAFE_ADDRESS = $SAFE
    $env:FOUNDER_ADDRESS = $FOUNDER
    $env:RESERVE_ADDRESS = $RESERVE
    $env:DEPLOYER_PRIVATE_KEY = $DEPLOY_KEY
    $env:WATCHER_ADDRESS = $WATCHER

    # --- free-market deploy --------------------------------------------------
    Invoke-Step "DeployFreeMarket" {
        forge script script/DeployFreeMarket.s.sol --rpc-url $RPC --broadcast --slow
    } "forge script script/DeployFreeMarket.s.sol --rpc-url $RPC --broadcast --slow"
    if (-not $DryRun) { Wait-ForMempoolDrain -Rpc $RPC -Address $SAFE }

    if (-not $DryRun) {
        if (-not (Test-Path $DepBase)) { throw "missing $DepBase after deploy" }
        $d = Get-Content $DepBase -Raw | ConvertFrom-Json
        $REGISTRY = $d.enrollmentRegistry
        $GOAT = $d.goatCoin
        $ESCROW = $d.holdbackEscrow
        $MINTER = $d.workMinter
        $DESK = $d.buyDesk
        $USDT = $d.mockUSDT
    } else {
        $REGISTRY = $GOAT = $ESCROW = $MINTER = $DESK = $USDT = "<from deployments/$CHAIN_ID.json>"
    }

    # --- wire free-market ----------------------------------------------------
    Invoke-Step "wire escrow.setVault(workMinter)" {
        Send-Tx $ESCROW "setVault(address)" $MINTER --private-key $SAFE_KEY --rpc-url $RPC
    } "cast send ESCROW setVault(MINTER)"

    Invoke-Step "wire goat.setMinter(workMinter,true)" {
        Send-Tx $GOAT "setMinter(address,bool)" $MINTER true --private-key $SAFE_KEY --rpc-url $RPC
    } "cast send GOAT setMinter(MINTER,true)"

    $sys = @($ESCROW, $MINTER, $DESK, $FOUNDER, $RESERVE, $SAFE)
    foreach ($a in $sys) {
        $addr = $a
        Invoke-Step "wire registry.setSystemAddress($addr)" {
            Send-Tx $REGISTRY "setSystemAddress(address,bool)" $addr true --private-key $SAFE_KEY --rpc-url $RPC
        } "cast send REGISTRY setSystemAddress($addr, true)"
    }

    # --- seed (optional) -----------------------------------------------------
    if (-not $SkipSeed) {
        Invoke-Step "mint mockUSDT to founder (10_000 * 1e6)" {
            Send-Tx $USDT "mint(address,uint256)" $FOUNDER 10000000000 --private-key $DEPLOY_KEY --rpc-url $RPC
        } "cast send USDT mint(FOUNDER, 10000000000)"

        if ($CHAIN_ID -eq "31337") {
            # Lab-only: seed reserve like dev-up.ps1. Skip on public testnet.
            Invoke-Step "mint mockUSDT to reserve (lab)" {
                Send-Tx $USDT "mint(address,uint256)" $RESERVE 1000000000 --private-key $DEPLOY_KEY --rpc-url $RPC
            } "cast send USDT mint(RESERVE, 1000000000)"
        }

        $DEV_JOB = if ($DryRun) { "<keccak dev-seed>" } else { (cast keccak "dev-seed").Trim() }
        $DEV_CATALOG = if ($DryRun) { "<keccak dev-seed-catalog>" } else { (cast keccak "dev-seed-catalog").Trim() }
        $DEV_MANIFEST = if ($DryRun) { "<keccak dev-seed-manifest>" } else { (cast keccak "dev-seed-manifest").Trim() }

        Invoke-Step "dev-seed GOAT via WorkMinter (100 GOAT to FOUNDER)" {
            $used = cast call $MINTER "usedManifest(bytes32)(bool)" $DEV_MANIFEST --rpc-url $RPC
            if ($used.Trim() -ne "true") {
                Send-Tx $MINTER "createJob(bytes32,bytes32,uint256,uint16,address,bool)" `
                    $DEV_JOB $DEV_CATALOG 1000000000000000000 0 0x0000000000000000000000000000000000000000 true `
                    --private-key $SAFE_KEY --rpc-url $RPC | Out-Null
                Send-Tx $MINTER "mintBatch(bytes32,bytes32,address[],uint256[])" `
                    $DEV_JOB $DEV_MANIFEST "[$FOUNDER]" "[100]" `
                    --private-key $SAFE_KEY --rpc-url $RPC | Out-Null
            } else {
                Write-Host "dev-seed already minted - skip"
            }
        } "WorkMinter createJob + mintBatch 100 GOAT -> FOUNDER"
    }

    # --- BuyDeskFactory + founder desk ---------------------------------------
    if (-not $DryRun) {
        $env:GOAT_ADDRESS = $GOAT
        $env:REGISTRY_ADDRESS = $REGISTRY
        $env:USDT_ADDRESS = $USDT
    }

    Invoke-Step "DeployBuyDeskFactory" {
        forge script script/DeployBuyDeskFactory.s.sol --rpc-url $RPC --broadcast --slow
    } "forge script script/DeployBuyDeskFactory.s.sol --rpc-url $RPC --broadcast --slow"
    if (-not $DryRun) { Wait-ForMempoolDrain -Rpc $RPC -Address $SAFE }

    if (-not $DryRun) {
        $f = Get-Content $DepFactory -Raw | ConvertFrom-Json
        $FACTORY = $f.buyDeskFactory
    } else {
        $FACTORY = "<buyDeskFactory>"
    }

    Invoke-Step "factory.createDesk(Founder Desk)" {
        Send-Tx $FACTORY "createDesk(string)" "Founder Desk" --private-key $SAFE_KEY --rpc-url $RPC
    } "cast send FACTORY createDesk('Founder Desk')"

    if (-not $DryRun) {
        $FOUNDER_DESK = (cast call $FACTORY "deskOf(address)(address)" $FOUNDER --rpc-url $RPC).Trim()
    } else {
        $FOUNDER_DESK = "<deskOf(FOUNDER)>"
    }

    # System-flag founder desk so sells are not TransferRestricted on owner path edge cases.
    Invoke-Step "registry.setSystemAddress(founderDesk)" {
        Send-Tx $REGISTRY "setSystemAddress(address,bool)" $FOUNDER_DESK true --private-key $SAFE_KEY --rpc-url $RPC
    } "setSystemAddress(FOUNDER_DESK)"

    $CAP_MAX = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    Invoke-Step "USDT.approve(founderDesk, 5000e6) + openSession ~1yr" {
        Send-Tx $USDT "approve(address,uint256)" $FOUNDER_DESK 5000000000 --private-key $SAFE_KEY --rpc-url $RPC
        $sesNow = [int][double]::Parse((Get-Date -UFormat %s)) - 3600
        $sesEnd = $sesNow + 31536000
        Send-Tx $FOUNDER_DESK "openSession(uint64,uint64,uint256)" $sesNow $sesEnd $CAP_MAX --private-key $SAFE_KEY --rpc-url $RPC
    } "approve + openSession"

    # --- EpochSettlement lane ------------------------------------------------
    $EPOCH_ESCROW = $EPOCH_SETTLE = $EPOCH_RESOLVER = $WORKER_BINDING = $null
    $bindingDeployBlock = $null
    if (-not $SkipEpoch) {
        # --sig is REQUIRED, not decorative -- same reason as dev-up.ps1's copy of this
        # line. `de4a875` gave DeployEpochSettlement a second entry point,
        # `run(string manifestPath)` alongside `run()`, so the two deploy tests could
        # stop racing on one tracked manifest. The overload makes `forge script`
        # ambiguous and this line died with
        # "Multiple functions with the same name `run` found in the ABI".
        #
        # `737cfa4` fixed exactly this break in dev-up.ps1 and did not fix it here, so
        # the TESTNET standup stayed broken for a further session while the local one
        # worked. Neither script is invoked by run-full-gate.ps1, so nothing went red.
        # Reproduced 2026-07-29 against this exact command; the matched control with
        # --sig reaches DeployEpochSettlement::run() and reverts ChainNotAllowed()
        # instead, which is what proves the flag is the difference.
        Invoke-Step "DeployEpochSettlement" {
            forge script script/DeployEpochSettlement.s.sol --sig "run()" --rpc-url $RPC --broadcast --slow
        } "forge script script/DeployEpochSettlement.s.sol --sig `"run()`" --rpc-url $RPC --broadcast --slow"
        if (-not $DryRun) { Wait-ForMempoolDrain -Rpc $RPC -Address $SAFE }

        if (-not $DryRun) {
            $e = Get-Content $DepEpoch -Raw | ConvertFrom-Json
            $EPOCH_ESCROW = $e.epochHoldbackEscrow
            $EPOCH_SETTLE = $e.epochSettlement
            $EPOCH_RESOLVER = $e.founderResolver
            $WORKER_BINDING = $e.workerBinding
            $bindingDeployBlock = Get-WorkerBindingDeployBlock -ContractsRoot $ContractsRoot -ChainId $CHAIN_ID
            if ($null -eq $bindingDeployBlock) {
                # Last resort: current head (slightly late but better than 0 on L2).
                $bindingDeployBlock = [uint64](cast block-number --rpc-url $RPC).Trim()
                Write-Host "WARN: could not parse forge broadcast for WorkerBinding block; using head $bindingDeployBlock"
            }
            Write-EpochWithDeployBlock -EpochPath $DepEpoch -DeployBlock $bindingDeployBlock
        } else {
            $EPOCH_ESCROW = $EPOCH_SETTLE = $EPOCH_RESOLVER = $WORKER_BINDING = "<epoch>"
            $bindingDeployBlock = "<from broadcast WorkerBinding receipt>"
        }

        # --- verify the resolver pin BEFORE wiring ----------------------------
        # FounderResolver.settlement is immutable and was set from a PREDICTED CREATE
        # address in DeployEpochSettlement.s.sol. That script's equality guard is a
        # local comparison inside a Script contract that is never deployed: it runs
        # only in forge's simulation EVM and emits no transaction. setResolver below
        # validates only non-zero, so an unchecked pin would be re-blessed here rather
        # than caught. Assert it on-chain before anything is wired. (String -ne is
        # case-insensitive in PowerShell: one side may be EIP-55 checksummed, one not.)
        Invoke-Step "verify founderResolver.settlement() == epochSettlement" {
            $pinned = ([string](cast call $EPOCH_RESOLVER "settlement()(address)" --rpc-url $RPC)).Trim()
            if ($pinned -ne $EPOCH_SETTLE) {
                throw "founderResolver.settlement() = '$pinned' but epochSettlement = '$EPOCH_SETTLE' - resolver is mis-pinned; refusing to wire"
            }
            Write-Host "    resolver pin verified: $EPOCH_RESOLVER -> $pinned"
        } "cast call RESOLVER settlement()(address) must equal EPOCH_SETTLE (hard throw on mismatch)"

        Invoke-Step "wire epoch escrow.setVault(settlement)" {
            Send-Tx $EPOCH_ESCROW "setVault(address)" $EPOCH_SETTLE --private-key $SAFE_KEY --rpc-url $RPC
        } "epochHoldbackEscrow.setVault(epochSettlement)"

        Invoke-Step "wire goat.setMinter(epochSettlement,true)" {
            Send-Tx $GOAT "setMinter(address,bool)" $EPOCH_SETTLE true --private-key $SAFE_KEY --rpc-url $RPC
        } "goat.setMinter(epochSettlement,true)"

        Invoke-Step "wire registry system flags (epoch)" {
            Send-Tx $REGISTRY "setSystemAddress(address,bool)" $EPOCH_SETTLE true --private-key $SAFE_KEY --rpc-url $RPC
            Send-Tx $REGISTRY "setSystemAddress(address,bool)" $EPOCH_ESCROW true --private-key $SAFE_KEY --rpc-url $RPC
            Send-Tx $EPOCH_SETTLE "setResolver(address)" $EPOCH_RESOLVER --private-key $SAFE_KEY --rpc-url $RPC
        } "setSystemAddress + setResolver"

        # Enroll founder (SAFE path) so desk owner is not blocked.
        Invoke-Step "registry.setEnrolled(FOUNDER)" {
            Send-Tx $REGISTRY "setEnrolled(address,bool,bytes32)" $FOUNDER true $ZERO32 --private-key $SAFE_KEY --rpc-url $RPC
        } "setEnrolled(FOUNDER)"
    }

    # --- publish to desktop --------------------------------------------------
    Invoke-Step "copy deployments -> desktop/src/chain/deployments" {
        New-Item -ItemType Directory -Force -Path $DesktopDep | Out-Null
        Copy-Item $DepBase (Join-Path $DesktopDep "$CHAIN_ID.json") -Force
        if (Test-Path $DepFactory) {
            Copy-Item $DepFactory (Join-Path $DesktopDep "$CHAIN_ID.factory.json") -Force
        }
        if (-not $SkipEpoch -and (Test-Path $DepEpoch)) {
            Copy-Item $DepEpoch (Join-Path $DesktopDep "$CHAIN_ID.epoch.json") -Force
        }
    } "Copy-Item contracts/deployments/$CHAIN_ID*.json -> desktop"

    Write-Host ""
    Write-Host "=== testnet-up complete =========================================="
    Write-Host " chainId                 : $CHAIN_ID"
    Write-Host " goatCoin                : $GOAT"
    Write-Host " enrollmentRegistry      : $REGISTRY"
    Write-Host " buyDesk (standalone)    : $DESK"
    Write-Host " buyDeskFactory          : $FACTORY"
    Write-Host " founderDesk             : $FOUNDER_DESK"
    if (-not $SkipEpoch) {
        Write-Host " workerBinding           : $WORKER_BINDING"
        Write-Host " workerBindingDeployBlock: $bindingDeployBlock   <- set WORKER_BINDING_DEPLOY_BLOCK"
        Write-Host " epochSettlement         : $EPOCH_SETTLE"
    }
    Write-Host " desktop copies          : desktop\src\chain\deployments\$CHAIN_ID*.json"
    Write-Host " next                    : tools\goat-attestor\sync-env-from-desktop.ps1 -ChainId $CHAIN_ID"
    Write-Host " G-B2                    : freeze these addresses before any volunteer installer"
    Write-Host "=================================================================="
} finally {
    Pop-Location
}
