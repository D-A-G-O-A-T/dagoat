#Requires -Version 5.1
# .SYNOPSIS
#     Executes a standup script -- contracts/dev-up.ps1 and/or
#     contracts/testnet-up.ps1 -- end to end against an EPHEMERAL anvil, in an
#     isolated copy of the tree, and asserts the resulting chain state.
#
# .DESCRIPTION
#     WHY THIS EXISTS. Gate steps 8, 9 and 10 are all STATIC. Step 8 proves each
#     .ps1 parses and means one thing under both decodings; step 9 proves every
#     `cast` signature and `forge script` entry point still resolves against the
#     compiled ABIs; step 10 pins four code hashes. None of them RUNS a standup.
#     The gate covers what it runs, and it never ran these -- which is exactly how
#     the two recorded standup defects survived a green gate:
#
#       * contracts/dev-up.ps1 could not deploy EpochSettlement at all (ambiguous
#         run() after a test-isolation overload). Fixed in 737cfa4.
#       * contracts/testnet-up.ps1 carried the IDENTICAL break, because that fix
#         went to one caller and not the other, and the testnet standup stayed
#         broken for a further session.
#
#     BOTH TWINS ARE COVERED HERE, AND THAT IS THE POINT. The recorded defect was
#     an ASYMMETRY -- one caller repaired, its twin left broken -- so a harness
#     that tested one and not the other would reproduce that exact shape one level
#     up, in the test. -Script defaults to `both` for that reason: covering only
#     dev-up.ps1 has to be asked for explicitly.
#
#     WHAT STATIC CHECKING CANNOT REACH is the class this file exists for: a
#     revert, a wrong address, a mis-ordered wiring call, a one-shot setter already
#     consumed, a balance that never arrives. Measured: deleting ONE
#     setSystemAddress call leaves dev-up.ps1 exiting 0 while this harness goes red
#     and names the missing wiring.
#
#     WHAT ISOLATION MEANS HERE, and why both halves are mandatory:
#
#       1. AN EPHEMERAL PORT, never 8545. A full Season-0 dev chain commonly runs
#          on 8545 with live state a human is using, and both standups are
#          re-runnable -- they would happily redeploy over it. Each target binds
#          its own free port, gets its OWN anvil, and reaps it in a finally.
#          -Port 8545 is refused outright.
#
#       2. A COPY OF THE TREE, one per target. Both scripts write three tracked
#          deployment JSONs (via `forge script`'s vm.writeJson into ./deployments)
#          and copy each into desktop/src/chain/deployments/. Six tracked files,
#          none of which a smoke test may touch. Everything both scripts resolve
#          comes from $PSScriptRoot, so a copy at <temp>/contracts/ writes into the
#          copy. contracts/broadcast is EXCLUDED and it is not an optimisation: it
#          was measured at 1.56 GB across 7,634 files, against ~32 MB for
#          everything else. out/ and cache/ ARE copied, so forge does not
#          recompile 67 contracts under via_ir.
#
#     THE ACCOUNT CONSTANTS ARE READ OUT OF contracts/dev-up.ps1, not restated
#     here. That file is the only place in the tree holding the anvil founder key,
#     and duplicating it would create a second copy to keep in step -- plus a
#     second key literal for the export scanner to classify. Reading them also
#     BINDS the two files: if dev-up.ps1's account choices change, this harness
#     follows, and if a constant disappears the run is a BLOCKER rather than a
#     suite of assertions quietly aimed at the wrong addresses.
#
#     WHAT IT ASSERTS, and why not just "the script exited 0". Both standups end by
#     PRINTING a checklist -- balances, addresses, the resolver pin -- and printing
#     is not asserting. Several of their `cast send` calls are piped to Out-Null, so
#     a wiring call that silently did nothing still leaves the script exiting 0. So
#     every post-condition is re-read FROM THE CHAIN here, after the run.
#
#     THE TWO PROFILES DIFFER, and the differences were derived by reading both
#     scripts rather than assumed -- a shared assertion set would have been a FALSE
#     RED on the first testnet-up run:
#
#       SHARED: founder GOAT == 100e18 through the REAL mint path; founder and
#       reserve mockUSDT; vault() on both escrows (one-shot setters, so this also
#       proves the run was not a second one); isMinter twice; enrolled(founder);
#       systemAddress for escrow, minter, buyDesk, founder, reserve,
#       epochSettlement and epochEscrow; founderResolver.settlement() and
#       epochSettlement.resolver(); a non-zero factory.deskOf(founder); and all
#       three deployment JSONs written AND mirrored into the desktop config.
#
#       dev-up.ps1 ONLY: enrolled(demo worker). It enrols anvil #5 as well as the
#       founder; testnet-up.ps1 enrols the founder alone.
#
#       testnet-up.ps1 ONLY: systemAddress(founderDesk) -- it wires the desk as a
#       system address and dev-up.ps1 does not -- and workerBindingDeployBlock
#       present in the epoch JSON, which it adds for G-B1 by parsing the forge
#       broadcast receipt.
#
#     EVERY ASSERTION IS ALSO A VACUITY RISK. A `cast call` that fails returns an
#     empty string, and "" -ne "true" is trivially satisfied by a broken call. So
#     each read is checked for emptiness FIRST and reported as COULD-NOT-RUN, not
#     as a finding -- the same 1-vs-2 distinction the other children draw.
#
#     AND `cast call ...(uint256)` APPENDS A MAGNITUDE: "100000000000000000000
#     [1e20]". That is a rendering detail, and comparing the raw string against a
#     decimal literal produced a FALSE RED on this file's first run -- two correct
#     balances reported as defects. A false red is as damaging as a false green,
#     because the check that cries wolf is the check someone switches off.
#
# .PARAMETER Script
#     Which standup to exercise: dev-up, testnet-up, or both (the default, for the
#     asymmetry reason above).
#
# .PARAMETER Port
#     TCP port for the ephemeral anvil. 0 means "pick a free one", which is the
#     default and the only sensible setting for CI. Never defaults to 8545, and
#     8545 is refused. Only valid with a single -Script, since two targets need two
#     nodes.
#
# .PARAMETER KeepWorkspace
#     Do not delete the temp copies. For debugging a red run.
#
# .PARAMETER SkipCleanup
#     Do not reap the anvil processes this script started. Debug only. The default
#     reaps on every path including Ctrl-C, because a leaked node holds a port and
#     the next run then binds a different one and looks fine.
#
# .NOTES
#     EXIT CONTRACT, the same one check-aux-scripts.ps1 and
#     check-role-code-hashes.ps1 use, for the same reason:
#
#       0  every selected standup RAN and every post-condition held.
#       1  a standup RAN and a post-condition FAILED, or it exited non-zero.
#       2  the smoke test COULD NOT RUN -- no anvil/forge/cast on PATH, a node
#          never answered, a workspace could not be built, a required constant is
#          missing from dev-up.ps1, or a chain read came back empty so nothing
#          could be concluded. NEVER 0.
#
#     2 OUTRANKS 1. "Could not test the standup" must never read as "the standup is
#     fine", and must not be triaged as a defect in the standup either.
#
#     EVERY finding and blocker is PREFIXED WITH ITS TARGET, so a red names which
#     twin failed. With -Script both, a failure in one does not stop the other:
#     both run, and the report covers both.
#
#     STDOUT CONTRACT. Findings and blockers print one per line prefixed
#     `[FAIL] `. Immediately before the summary:
#
#         GATE-DETAIL smokestandup <PASS|FAIL|COULD-NOT-RUN> <detail text>
#
#     THIS FILE IS IN CHECK 8's SWEPT SET -- BOM-less and pure ASCII, "--" for an
#     em-dash, and every `cast`/`forge` example above sits on a comment line so it
#     contributes no call-site to check 9.
#
#     RUNTIME. Roughly 45-90 s per target. It is NOT wired into run-full-gate.ps1
#     -- that is a founder decision about gate runtime, and an unrun check is worth
#     little, so it should be made deliberately.
#
# .EXAMPLE
#     powershell -NoProfile -File .\smoke-standup.ps1
#
# .EXAMPLE
#     powershell -NoProfile -File .\smoke-standup.ps1 -Script testnet-up -Port 8600

[CmdletBinding()]
param(
    [ValidateSet('dev-up', 'testnet-up', 'both')]
    [string] $Script = 'both',
    [int]    $Port = 0,
    [switch] $KeepWorkspace,
    [switch] $SkipCleanup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot     = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$ContractsSrc = Join-Path $RepoRoot 'contracts'

$AllFindings = New-Object System.Collections.ArrayList
$AllBlockers = New-Object System.Collections.ArrayList
$Started     = New-Object System.Collections.ArrayList   # processes to reap
$Workspaces  = New-Object System.Collections.ArrayList
$script:Target = '(none)'

function Add-Finding { param([string]$Text) [void]$AllFindings.Add("[$($script:Target)] $Text") }
function Add-Blocker { param([string]$Text) [void]$AllBlockers.Add("[$($script:Target)] $Text") }

function Get-FreeTcpPort {
    # Bind port 0, read what the OS assigned, release it. There is a race between
    # release and anvil's bind, which is why the caller may pin -Port instead.
    $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $l.Start()
    try { return ([System.Net.IPEndPoint]$l.LocalEndpoint).Port } finally { $l.Stop() }
}

function Invoke-Cast {
    # Returns trimmed stdout, or $null when cast failed. $null means "could not
    # read", which the caller MUST turn into a blocker -- never into a comparison,
    # because "" compares unequal to everything and would manufacture a finding
    # out of a failed read.
    param([string[]]$CastArgs)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $o = & cast @CastArgs 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
        if ($null -eq $o) { return $null }
        $t = ([string]($o -join "`n")).Trim()
        if ([string]::IsNullOrWhiteSpace($t)) { return $null }
        return $t
    } finally { $ErrorActionPreference = $prev }
}

function Assert-ChainValue {
    param([string]$What, [string[]]$CastArgs, [string]$Expected, [switch]$CaseInsensitive)
    $raw = Invoke-Cast -CastArgs $CastArgs
    if ($null -eq $raw) {
        Add-Blocker "$What -- the chain read failed or returned nothing, so nothing can be concluded about it"
        return
    }
    # Strip cast's magnitude suffix ONLY when the tail has exactly that shape.
    # Anything else is left intact and will fail the comparison, because an
    # unrecognised suffix means cast printed something this function does not
    # understand, and quietly discarding it is how a real mismatch would get
    # normalised away.
    $actual = $raw
    $m = [regex]::Match($raw, '^(?<v>\S+)\s+\[[^\]]*\]$')
    if ($m.Success) { $actual = $m.Groups['v'].Value }
    $same = if ($CaseInsensitive) { $actual -eq $Expected } else { $actual -ceq $Expected }
    $shown = $actual
    if ($actual -ne $raw) { $shown = "$actual   (cast printed: $raw)" }
    Write-Output ("  {0,-46} = {1}" -f $What, $shown)
    if (-not $same) { Add-Finding "$What is '$actual', expected '$Expected'" }
}

function Get-DevUpConstants {
    # The single source of truth for the anvil accounts is contracts/dev-up.ps1.
    # Restating them here would mean two copies of the founder key to keep in step
    # and a second key literal for the export scanner to classify.
    param([string]$Path)
    $txt = [System.IO.File]::ReadAllText($Path)
    $want = @('SAFE', 'SAFE_KEY', 'RESERVE', 'WATCHER', 'WORKER')
    $found = @{}
    foreach ($n in $want) {
        # `\$SAFE\s*=` cannot match `$SAFE_KEY    =`: after SAFE comes an
        # underscore, not whitespace or '='.
        $m = [regex]::Match($txt, ('(?m)^\$' + $n + '\s*=\s*"(?<v>0x[0-9a-fA-F]+)"'))
        if ($m.Success) { $found[$n] = $m.Groups['v'].Value }
    }
    return $found
}

function New-SmokeWorkspace {
    param([string]$Tag)
    $ws = Join-Path ([System.IO.Path]::GetTempPath()) ("goat-standup-smoke-$Tag-" + [System.Guid]::NewGuid().ToString('N').Substring(0, 8))
    $wsContracts = Join-Path $ws 'contracts'
    New-Item -ItemType Directory -Force -Path $wsContracts | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $ws 'desktop\src\chain\deployments') | Out-Null
    [void]$Workspaces.Add($ws)
    # robocopy, because Copy-Item -Recurse has no exclude.
    $null = & robocopy $ContractsSrc $wsContracts /E /XD broadcast /NFL /NDL /NJH /NJS /NP
    if ($LASTEXITCODE -ge 8) {
        Add-Blocker "could not copy contracts/ into the workspace (robocopy exit $LASTEXITCODE)."
        return $null
    }
    return $ws
}

function Start-EphemeralAnvil {
    param([int]$OnPort)
    # WITHOUT --disable-code-size-limit, matching the anvil harness: with the limit
    # lifted an over-24,576-byte contract deploys happily and a standup that could
    # never work on Base passes here.
    $p = Start-Process -FilePath 'anvil' `
        -ArgumentList @('--port', "$OnPort", '--chain-id', '31337', '--silent') `
        -PassThru -WindowStyle Hidden
    [void]$Started.Add($p)
    $rpc = "http://127.0.0.1:${OnPort}"
    for ($i = 0; $i -lt 60; $i++) {
        Start-Sleep -Milliseconds 500
        if ($null -ne (Invoke-Cast -CastArgs @('chain-id', '--rpc-url', $rpc))) {
            $cid = Invoke-Cast -CastArgs @('chain-id', '--rpc-url', $rpc)
            if ($cid -ne '31337') {
                Add-Blocker "the ephemeral node reports chain id '$cid', expected 31337."
                return $null
            }
            return $rpc
        }
    }
    Add-Blocker "the ephemeral anvil never answered on $rpc within 30s."
    return $null
}

function Invoke-StandupTarget {
    param([string]$Name, [hashtable]$Const, [int]$OnPort)

    $script:Target = $Name
    Write-Output ''
    Write-Output "=============================================================================="
    Write-Output ("  TARGET: contracts/{0}.ps1" -f $Name)
    Write-Output "=============================================================================="

    $ws = New-SmokeWorkspace -Tag $Name
    if ($null -eq $ws) { return }
    $wsContracts  = Join-Path $ws 'contracts'
    $wsDesktopCfg = Join-Path $ws 'desktop\src\chain\deployments'
    $wsScript     = Join-Path $wsContracts "$Name.ps1"
    if (-not (Test-Path -LiteralPath $wsScript)) {
        Add-Blocker "the workspace copy has no $Name.ps1 -- the copy did not land."
        return
    }
    Write-Output ("  workspace   : {0}" -f $ws)

    $rpc = Start-EphemeralAnvil -OnPort $OnPort
    if ($null -eq $rpc) { return }
    Write-Output ("  ephemeral   : {0}" -f $rpc)

    $psExe = $null
    try { $psExe = [string](Get-Process -Id $PID).Path } catch { $psExe = 'powershell.exe' }
    if ([string]::IsNullOrWhiteSpace($psExe)) { $psExe = 'powershell.exe' }
    $log = Join-Path $ws "$Name.log"

    # testnet-up.ps1 is env-driven and takes no RPC parameter, so its inputs are
    # set here and RESTORED afterwards -- this process must not leak deploy keys
    # or a chain id into anything that runs later.
    $envNames = @('RPC_URL', 'CHAIN_ID', 'SAFE_ADDRESS', 'FOUNDER_ADDRESS', 'RESERVE_ADDRESS',
                  'WATCHER_ADDRESS', 'DEPLOYER_PRIVATE_KEY', 'SAFE_PRIVATE_KEY',
                  'EXISTING_GOAT', 'EXISTING_REGISTRY', 'EXISTING_USDT')
    $envSaved = @{}
    foreach ($n in $envNames) { $envSaved[$n] = [Environment]::GetEnvironmentVariable($n) }

    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        if ($Name -eq 'dev-up') {
            & $psExe -NoProfile -ExecutionPolicy Bypass -File $wsScript -RpcUrl $rpc *>&1 |
                Tee-Object -FilePath $log
        }
        else {
            # FOUNDER == SAFE is explicitly allowed by that script's own usage
            # block ("may equal SAFE"), and it is what makes the balance
            # assertions comparable across the two targets.
            $env:RPC_URL              = $rpc
            $env:CHAIN_ID             = '31337'
            $env:SAFE_ADDRESS         = $Const['SAFE']
            $env:FOUNDER_ADDRESS      = $Const['SAFE']
            $env:RESERVE_ADDRESS      = $Const['RESERVE']
            $env:WATCHER_ADDRESS      = $Const['WATCHER']
            $env:DEPLOYER_PRIVATE_KEY = $Const['SAFE_KEY']
            # It REFUSES to run with any EXISTING_* set (fresh v2 stack only), so
            # clear them rather than inherit a stale shell.
            foreach ($k in @('EXISTING_GOAT', 'EXISTING_REGISTRY', 'EXISTING_USDT', 'SAFE_PRIVATE_KEY')) {
                [Environment]::SetEnvironmentVariable($k, $null)
            }
            & $psExe -NoProfile -ExecutionPolicy Bypass -File $wsScript *>&1 |
                Tee-Object -FilePath $log
        }
        $exit = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $prevEap
        foreach ($n in $envNames) { [Environment]::SetEnvironmentVariable($n, $envSaved[$n]) }
    }
    Write-Output ("-- {0}.ps1 exited {1} (full output: {2})" -f $Name, $exit, $log)
    if ($exit -ne 0) {
        Add-Finding "contracts/$Name.ps1 exited $exit. Its output is in $log; the assertions below are still attempted so a partial standup is reported in full."
    }

    # ---- the manifests it wrote ---------------------------------------------
    Write-Output ''
    Write-Output '-- asserting chain state ----------------------------------------------------'
    $mainJson    = Join-Path $wsContracts 'deployments\31337.json'
    $factoryJson = Join-Path $wsContracts 'deployments\31337.factory.json'
    $epochJson   = Join-Path $wsContracts 'deployments\31337.epoch.json'
    $haveAll = $true
    foreach ($j in @($mainJson, $factoryJson, $epochJson)) {
        if (-not (Test-Path -LiteralPath $j)) {
            $haveAll = $false
            Add-Blocker "the standup did not write $j, so its addresses cannot be read and nothing downstream can be asserted."
        }
    }
    # The desktop copy is what the app depends on and nothing else checks it.
    foreach ($n in @('31337.json', '31337.factory.json', '31337.epoch.json')) {
        if (-not (Test-Path -LiteralPath (Join-Path $wsDesktopCfg $n))) {
            Add-Finding "the standup did not mirror $n into desktop/src/chain/deployments/, so the app would boot against stale addresses"
        }
    }
    if (-not $haveAll) { return }

    $d = Get-Content -LiteralPath $mainJson -Raw | ConvertFrom-Json
    $e = Get-Content -LiteralPath $epochJson -Raw | ConvertFrom-Json
    $f = Get-Content -LiteralPath $factoryJson -Raw | ConvertFrom-Json

    $REGISTRY = $d.enrollmentRegistry; $GOAT = $d.goatCoin; $ESCROW = $d.holdbackEscrow
    $MINTER   = $d.workMinter;         $DESK = $d.buyDesk;  $USDT   = $d.mockUSDT
    $EPOCH_ESCROW = $e.epochHoldbackEscrow; $EPOCH_SETTLE = $e.epochSettlement
    $EPOCH_RESOLVER = $e.founderResolver;   $FACTORY = $f.buyDeskFactory
    $SAFE = $Const['SAFE']; $RESERVE = $Const['RESERVE']; $WORKER = $Const['WORKER']

    # ---- shared profile ------------------------------------------------------
    Assert-ChainValue -What 'founder GOAT balance (wei)' -Expected '100000000000000000000' `
        -CastArgs @('call', $GOAT, 'balanceOf(address)(uint256)', $SAFE, '--rpc-url', $rpc)
    Assert-ChainValue -What 'founder mockUSDT balance (6dp)' -Expected '10000000000' `
        -CastArgs @('call', $USDT, 'balanceOf(address)(uint256)', $SAFE, '--rpc-url', $rpc)
    Assert-ChainValue -What 'reserve mockUSDT balance (6dp)' -Expected '1000000000' `
        -CastArgs @('call', $USDT, 'balanceOf(address)(uint256)', $RESERVE, '--rpc-url', $rpc)

    # setVault is ONE-SHOT, so these double as proof the run was not a second one
    # against a chain that had already consumed it.
    Assert-ChainValue -What 'holdbackEscrow.vault() == workMinter' -Expected ([string]$MINTER) -CaseInsensitive `
        -CastArgs @('call', $ESCROW, 'vault()(address)', '--rpc-url', $rpc)
    Assert-ChainValue -What 'epochEscrow.vault() == epochSettlement' -Expected ([string]$EPOCH_SETTLE) -CaseInsensitive `
        -CastArgs @('call', $EPOCH_ESCROW, 'vault()(address)', '--rpc-url', $rpc)

    Assert-ChainValue -What 'goat.isMinter(workMinter)' -Expected 'true' `
        -CastArgs @('call', $GOAT, 'isMinter(address)(bool)', $MINTER, '--rpc-url', $rpc)
    Assert-ChainValue -What 'goat.isMinter(epochSettlement)' -Expected 'true' `
        -CastArgs @('call', $GOAT, 'isMinter(address)(bool)', $EPOCH_SETTLE, '--rpc-url', $rpc)

    Assert-ChainValue -What 'registry.enrolled(founder)' -Expected 'true' `
        -CastArgs @('call', $REGISTRY, 'enrolled(address)(bool)', $SAFE, '--rpc-url', $rpc)

    $sysSet = @(
        @{ N = 'holdbackEscrow';  A = $ESCROW },
        @{ N = 'workMinter';      A = $MINTER },
        @{ N = 'buyDesk';         A = $DESK },
        @{ N = 'founder';         A = $SAFE },
        @{ N = 'reserve';         A = $RESERVE },
        @{ N = 'epochSettlement'; A = $EPOCH_SETTLE },
        @{ N = 'epochEscrow';     A = $EPOCH_ESCROW })
    foreach ($s in $sysSet) {
        Assert-ChainValue -What ("registry.systemAddress({0})" -f $s.N) -Expected 'true' `
            -CastArgs @('call', $REGISTRY, 'systemAddress(address)(bool)', $s.A, '--rpc-url', $rpc)
    }

    # Immutable, set from a PREDICTED CREATE address, and the deploy script's own
    # equality guard runs in forge's simulation EVM and emits no transaction -- so
    # it is asserted on chain, by both standups and again here.
    Assert-ChainValue -What 'founderResolver.settlement() == epochSettlement' -Expected ([string]$EPOCH_SETTLE) -CaseInsensitive `
        -CastArgs @('call', $EPOCH_RESOLVER, 'settlement()(address)', '--rpc-url', $rpc)
    Assert-ChainValue -What 'epochSettlement.resolver() == founderResolver' -Expected ([string]$EPOCH_RESOLVER) -CaseInsensitive `
        -CastArgs @('call', $EPOCH_SETTLE, 'resolver()(address)', '--rpc-url', $rpc)

    $deskOf = Invoke-Cast -CastArgs @('call', $FACTORY, 'deskOf(address)(address)', $SAFE, '--rpc-url', $rpc)
    if ($null -eq $deskOf) {
        Add-Blocker 'factory.deskOf(founder) -- the chain read failed, so nothing can be concluded about the founder desk'
    } else {
        Write-Output ("  {0,-46} = {1}" -f 'factory.deskOf(founder)', $deskOf)
        if ($deskOf -match '^0x0{40}$') {
            Add-Finding 'factory.deskOf(founder) is the zero address -- createDesk did not take effect, so the app boots with no sellable desk'
        }
    }

    # ---- per-target profile --------------------------------------------------
    if ($Name -eq 'dev-up') {
        # dev-up enrols anvil #5 as a demo worker so Wallet import is immediately
        # usable. testnet-up enrols the founder alone, so this is NOT shared --
        # asserting it there would be a false red.
        Assert-ChainValue -What 'registry.enrolled(demo worker)' -Expected 'true' `
            -CastArgs @('call', $REGISTRY, 'enrolled(address)(bool)', $WORKER, '--rpc-url', $rpc)
    }
    else {
        # testnet-up wires the founder desk as a system address; dev-up does not.
        if ($null -ne $deskOf -and $deskOf -notmatch '^0x0{40}$') {
            Assert-ChainValue -What 'registry.systemAddress(founderDesk)' -Expected 'true' `
                -CastArgs @('call', $REGISTRY, 'systemAddress(address)(bool)', $deskOf, '--rpc-url', $rpc)
        }
        # It adds workerBindingDeployBlock for G-B1 by parsing the forge broadcast
        # receipt -- a step with no other check anywhere.
        $names = @($e.PSObject.Properties.Name)
        if ($names -notcontains 'workerBindingDeployBlock') {
            Add-Finding ("the epoch JSON carries no workerBindingDeployBlock (keys: " +
                         "$($names -join ', ')). testnet-up derives it from the forge broadcast " +
                         "receipt and nothing else verifies that step.")
        } else {
            Write-Output ("  {0,-46} = {1}" -f 'epoch.workerBindingDeployBlock', $e.workerBindingDeployBlock)
            if ([int64]$e.workerBindingDeployBlock -le 0) {
                Add-Finding "workerBindingDeployBlock is $($e.workerBindingDeployBlock), which is not a real block number"
            }
        }
    }
}

try {
    Write-Output '=============================================================================='
    Write-Output '  STANDUP SMOKE TEST -- both standups against ephemeral anvil nodes'
    Write-Output '=============================================================================='
    Write-Output ("  targets     : {0}" -f $Script)

    foreach ($tool in @('anvil', 'forge', 'cast', 'robocopy')) {
        if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
            Add-Blocker "$tool is not on PATH. This smoke test CANNOT RUN, which is not the same as a standup being healthy."
        }
    }
    $devUpSrc = Join-Path $ContractsSrc 'dev-up.ps1'
    if (-not (Test-Path -LiteralPath $devUpSrc)) {
        Add-Blocker "missing: $devUpSrc -- it is both a target and the source of the account constants."
    }
    if ($AllBlockers.Count -gt 0) { throw 'PREFLIGHT' }

    # dev-up.ps1 must accept -RpcUrl. Without it PowerShell would bind the value
    # to $args and the script would run against its DEFAULT port -- the live dev
    # chain -- and this test would report on the wrong node.
    $duAst = [System.Management.Automation.Language.Parser]::ParseFile($devUpSrc, [ref]$null, [ref]$null)
    $duParams = @()
    if ($null -ne $duAst.ParamBlock) {
        $duParams = @($duAst.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
    }
    if ($duParams -notcontains 'RpcUrl') {
        Add-Blocker ("contracts/dev-up.ps1 declares no -RpcUrl parameter (found: $($duParams -join ', ')). " +
                     "Without it this test would drive the DEFAULT port, which is the live dev chain, " +
                     "so it refuses to run rather than redeploy over someone's session.")
        throw 'PREFLIGHT'
    }

    $Const = Get-DevUpConstants -Path $devUpSrc
    foreach ($n in @('SAFE', 'SAFE_KEY', 'RESERVE', 'WATCHER', 'WORKER')) {
        if (-not $Const.ContainsKey($n)) {
            Add-Blocker ("contracts/dev-up.ps1 no longer defines `$$n as a 0x literal. Every balance, " +
                         "enrolment and key-dependent step here derives from it, so this test refuses " +
                         "to run rather than assert against addresses it guessed.")
        }
    }
    if ($AllBlockers.Count -gt 0) { throw 'PREFLIGHT' }
    Write-Output ("  founder     : {0}" -f $Const['SAFE'])
    Write-Output ("  reserve     : {0}" -f $Const['RESERVE'])
    Write-Output ("  demo worker : {0}" -f $Const['WORKER'])

    # NOT `$targets = if (...) { ... } else { @($Script) }`. Assigning the output of
    # a STATEMENT sends it through the pipeline, which UNWRAPS a single-element
    # array to a scalar -- so with one target $targets became the string 'dev-up',
    # and `.Count` on a string throws under Set-StrictMode -Version Latest. Caught
    # by this file's own -Port 8545 control on its first run, which reported
    # "unexpected error: The property 'Count' cannot be found" instead of the
    # refusal it exists to prove. An array LITERAL assignment is not unwrapped.
    $targets = @('dev-up', 'testnet-up')
    if ($Script -ne 'both') { $targets = @($Script) }
    if (($Port -ne 0) -and (@($targets).Count -gt 1)) {
        Add-Blocker "-Port pins ONE port but $(@($targets).Count) targets were selected, and each needs its own node. Pass a single -Script with -Port."
        throw 'PREFLIGHT'
    }
    if ($Port -eq 8545) {
        Add-Blocker 'refusing to run on port 8545: that is the default dev chain and both standups redeploy.'
        throw 'PREFLIGHT'
    }

    foreach ($t in $targets) {
        $p = if ($Port -ne 0) { $Port } else { Get-FreeTcpPort }
        if ($p -eq 8545) {
            $script:Target = $t
            Add-Blocker 'the OS handed back port 8545, which is the default dev chain. Refusing.'
            continue
        }
        Invoke-StandupTarget -Name $t -Const $Const -OnPort $p
    }
}
catch {
    if ("$_" -ne 'PREFLIGHT') { Add-Blocker "unexpected error: $_" }
}
finally {
    # Reap on EVERY path, including Ctrl-C. A leaked anvil holds its port; the next
    # run then binds a different one and looks perfectly healthy while the machine
    # accumulates nodes.
    if (-not $SkipCleanup) {
        foreach ($p in $Started) {
            try {
                if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction Stop }
                Write-Output ("  reaped anvil pid {0}" -f $p.Id)
            } catch {
                Write-Output ("  WARNING: could not reap anvil pid {0}: {1}" -f $p.Id, $_)
            }
        }
    }
    if (-not $KeepWorkspace) {
        foreach ($w in $Workspaces) {
            if (Test-Path -LiteralPath $w) { Remove-Item -LiteralPath $w -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
}

Write-Output ''
foreach ($b in $AllBlockers) { Write-Output ("[FAIL] standup smoke COULD NOT RUN -- {0}" -f $b) }
foreach ($f2 in $AllFindings) { Write-Output ("[FAIL] standup smoke -- {0}" -f $f2) }

$status = 'PASS'
$detail = "every selected standup ($Script) ran on an ephemeral node and every post-condition held"
$exitCode = 0
if ($AllFindings.Count -gt 0) {
    $exitCode = 1
    $status = 'FAIL'
    $detail = "$($AllFindings.Count) finding(s) -- see the [FAIL] line(s) above"
}
if ($AllBlockers.Count -gt 0) {
    $exitCode = 2
    $status = 'COULD-NOT-RUN'
    $detail = "$($AllBlockers.Count) blocker(s) -- see the [FAIL] line(s) above"
}

Write-Output ''
Write-Output ("GATE-DETAIL smokestandup {0} {1}" -f $status, $detail)
Write-Output ("STANDUP-SMOKE SUMMARY: targets = {0}; standup smoke = {1}; findings = {2}; blockers = {3}; exit {4}" -f `
    $Script, $status, $AllFindings.Count, $AllBlockers.Count, $exitCode)

exit $exitCode
