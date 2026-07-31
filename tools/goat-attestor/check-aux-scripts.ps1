#Requires -Version 5.1
# .SYNOPSIS
#     The gate's step 8 (auxiliary script integrity) and step 9 (script call-site
#     ABI consistency), as ONE implementation that both run-full-gate.ps1 and
#     GitHub Actions call.
#
# .DESCRIPTION
#     WHY THIS IS A SEPARATE FILE.
#
#     These two checks were ~900 lines inline in run-full-gate.ps1, and they need
#     to run in CI as well. Pasting their logic into a workflow YAML would create a
#     SECOND implementation of a check whose entire value is being exact. This
#     repository already carries that scar: the migration freeze table lives in two
#     places and needed a test asserting the two agree. So the logic lives here,
#     once, and the gate shells out to it. CI runs the same file with the same
#     defaults.
#
#     THE PINS LIVE HERE TOO, in the param() block below, not in the caller. A pin
#     left behind in run-full-gate.ps1 would be a pin CI does not honour, which is
#     the same two-implementations defect one level down. Every floor and every
#     required-set literal is a param default, so a caller MAY override one, and no
#     caller has to know one exists in order to get the pinned behaviour.
#
#     WHAT THE TWO CHECKS ASSERT.
#
#     CHECK 8 -- THE FILE THE HOST EXECUTES IS THE FILE THE AUTHOR WROTE. The gate
#     covers what it runs, and it runs none of the standup, release or publish
#     scripts. That gap shipped three separate defects, none of which turned the
#     gate a single shade of red:
#
#       1. contracts/dev-up.ps1 could not deploy EpochSettlement (ambiguous run()
#          after a test-isolation overload). Fixed in 737cfa4.
#       2. contracts/testnet-up.ps1 carried the IDENTICAL break -- 737cfa4 fixed
#          one caller and not the other, so testnet standup stayed broken for a
#          further session. Found 2026-07-29.
#       3. desktop/scripts/release-build.ps1 could not be PARSED at all, and
#          desktop/scripts/release-hash.ps1 parsed fine and silently lost a
#          command. Both found 2026-07-29.
#
#     This check cannot execute those scripts -- they deploy contracts and build
#     installers -- so it asserts the weaker property that would still have caught
#     2 of the 3, in two parts:
#
#       (a) It parses, read the way the host reads it.
#
#       (b) Its command graph is the same under UTF-8 as under the encoding the
#           host actually uses. THIS IS NOT IMPLIED BY (a). Windows PowerShell 5.1
#           reads a BOM-less file as the ANSI code page, not UTF-8, and a UTF-8
#           em-dash (E2 80 94) decodes under CP1252 to an a-tilde, a euro sign,
#           and 0x94 -- which is U+201D RIGHT DOUBLE QUOTATION MARK, and
#           PowerShell accepts smart quotes AS STRING DELIMITERS. Two em-dashes
#           inside two nearby double-quoted strings therefore pair up, swallow
#           everything between them into one string literal, and the file still
#           parses clean. That is exactly what release-hash.ps1 did: 21 commands
#           as written, 20 as executed, and the one that vanished was the warning
#           telling an operator their release was going out UNSIGNED. A parse
#           check alone reads that file as healthy.
#
#       A file with a UTF-8 BOM is exempt from (b) by construction: the BOM makes
#       the host read UTF-8, so the two decodings cannot disagree. A pure-ASCII
#       file is exempt for the same reason from the other direction.
#
#       "THE HOST" IS WHICHEVER POWERSHELL RUNS THIS FILE, and that is a real
#       dependency rather than a detail: leg one of (b) is
#       Parser::ParseFile, which decodes with the host's own rules. Under Windows
#       PowerShell 5.1 on this machine that is Windows-1252 and the two legs can
#       disagree (verified: a 3-command BOM-less file with two em-dashes reads as
#       2 commands). Under a host whose default encoding is already UTF-8 the two
#       legs CANNOT disagree and (b) is vacuous, so the run prints the host and
#       its default encoding, and warns when they make (b) vacuous. run-full-gate
#       launches this file with its OWN executable so that "the host" means the
#       same thing on both sides of the call.
#
#     CHECK 9 -- EVERY CONTRACT CALL-SITE IN EVERY SCRIPT STILL NAMES SOMETHING
#     THE COMPILED CONTRACTS ACTUALLY HAVE. Check 8 proves a script PARSES and
#     means one thing; it does not prove the script would still WORK. A
#     syntax-valid script fails at runtime when the contract ABIs move underneath
#     it, and check 8 reads such a file as healthy because nothing about it is
#     malformed -- it is merely calling something that no longer exists. Defects 1
#     and 2 above are exactly that shape and neither is visible to check 8. Two
#     parts:
#
#       (A) every `cast send` / `cast call` signature resolves against the ABI of
#           some compiled artifact;
#       (B) every `forge script` invocation whose target declares more than one
#           run( carries a --sig, and that --sig NAMES ONE OF THE TARGET'S
#           DECLARED run(...) ENTRY POINTS.
#
#     SCOPE IS SHARED, DELIBERATELY. Both checks judge the SAME swept set, built
#     once by the walk below, so they CANNOT DISAGREE about which scripts are in
#     scope. The walk and its two vacuity guards therefore run even when one check
#     is skipped: a short walk makes check 9 vacuous exactly as it makes check 8
#     vacuous, and a skipped check must not exempt the shared scope from proof.
#
# .PARAMETER RepoRoot
#     Root of the tree to sweep. Defaults to this script's grandparent, which is
#     the repository root when the file sits in tools/goat-attestor/.
#
# .PARAMETER ContractsDir
#     Foundry project. Defaults to <RepoRoot>\contracts. Check 9 reads its
#     out/**/*.json for the ABI universe and resolves `forge script` targets
#     relative to it, because that is the working directory both standup scripts
#     run forge from.
#
# .PARAMETER Skip8
#     Do not run check 8's per-file parse/encoding pass. The shared scope guards
#     still run.
#
# .PARAMETER Skip9
#     Do not run check 9. For a caller with no compiled artifacts. The run then
#     reports check 9 as SKIPPED on stdout and in the summary line -- never as a
#     pass.
#
# .NOTES
#     EXIT CONTRACT (machine-readable; this is what a caller keys off):
#
#       0  every SELECTED check RAN and PASSED.
#       1  at least one selected check RAN and FAILED.
#       2  a selected check COULD NOT RUN (contracts/out missing, a directory that
#          could not be enumerated, no check selected at all, or an unexpected
#          error). DISTINCT FROM 1 ON PURPOSE: "could not check" must never be
#          reportable as "checked and fine", and it must not be confused with a
#          real finding either. NEVER 0.
#
#     2 OUTRANKS 1 when both occur: a run with a blocked check has not produced a
#     verdict on the whole surface, so it must not be reported as a plain red that
#     someone could triage from the findings alone. Every finding is still printed
#     in full.
#
#     0 MEANS EVERY CHECK THAT RAN PASSED. It does NOT mean every check ran. Read
#     the SUMMARY line, which names each check's status including SKIPPED.
#
#     STDOUT CONTRACT. Findings print one per line, prefixed `[FAIL] ` so that
#     run-full-gate's own Get-FailureExcerpt (which matches ^\s*\[FAIL) quotes them
#     at the bottom of a red gate without parsing anything. Immediately before the
#     summary, one line per check:
#
#         GATE-DETAIL check8 <PASS|FAIL|COULD-NOT-RUN|SKIPPED> <detail text>
#         GATE-DETAIL check9 <PASS|FAIL|COULD-NOT-RUN|SKIPPED> <detail text>
#
#     run-full-gate reads ONLY the <detail text> off those two lines, to reproduce
#     the SUMMARY row it printed before this file existed. THE EXIT CODE REMAINS
#     THE SOLE AUTHORITY FOR PASS/FAIL: if the line is absent the gate falls back
#     to a generic detail string and still reports the exit code's verdict, so a
#     lost or renamed marker cannot turn a red into a green.
#
#     THIS FILE IS IN ITS OWN SWEPT SET. It is a .ps1 under the repository root
#     that no prune-list entry hides, so check 8 checks it. That is why it is
#     BOM-LESS and PURE ASCII (use "--" for an em-dash, never the character) and
#     why it must parse: a non-ASCII byte in a BOM-less .ps1 is the exact defect
#     check 8 exists to catch, and the checker must not be its own first finding.
#     It is also why $ExpectedAuxScriptsMin went 13 -> 14 when this file landed.
#     Check 9 sweeps it too: every literal `forge script ...s.sol` and
#     `cast send ...` example below therefore sits on a COMMENT line, which the
#     harvest skips, so this file contributes 0 call-sites to either check.
#
# .EXAMPLE
#     powershell -NoProfile -File .\check-aux-scripts.ps1
#
# .EXAMPLE
#     powershell -NoProfile -File .\check-aux-scripts.ps1 -Skip9
#     # step 8 only -- for a caller with no contracts/out

[CmdletBinding()]
param(
    # Empty means "this script's grandparent", i.e. the repository root when the
    # file sits in tools/goat-attestor/. RESOLVED IN THE BODY, not as a param
    # default: measured on this machine, `$PSScriptRoot` is EMPTY inside the
    # param() block of this file when it is launched with
    # `powershell -File <path>`, and `Join-Path ''` then throws before a single
    # check runs -- a script that dies in its own signature reports nothing at
    # all, which is the one outcome the exit contract exists to prevent.
    [string] $RepoRoot = '',

    # Empty means "<RepoRoot>\contracts", resolved in the body. NOT a param
    # default referring to $RepoRoot: that only works while nobody reorders the
    # block, and a silently-wrong contracts directory makes check 9 report on the
    # wrong tree.
    [string] $ContractsDir = '',

    [switch] $Skip8,
    [switch] $Skip9,

    # ---------------------------------------------------------------------
    # CHECK 8's PINS
    # ---------------------------------------------------------------------
    # A floor on the COUNT is what stops a walk that finds nothing from reading
    # as a clean tree. 13 .ps1 files were measured before this file existed; it
    # is the 14th. 15 since 2026-07-29, when step 10 was extracted into
    # check-role-code-hashes.ps1, and 16 the same day with smoke-standup.ps1 --
    # both land in this swept set exactly as this file did, so both are BOM-less
    # and pure ASCII for the same reason. Lower it deliberately, in the same
    # commit, if a script was genuinely deleted.
    [int] $ExpectedAuxScriptsMin = 16,

    # The floor is not enough on its own: a broken exclusion could drop the two
    # scripts that have actually shipped a defect and still clear the floor by
    # sweeping thirteen others. These four are NAMED, so a missing one is a red
    # run rather than a quieter sweep.
    [string[]] $RequiredAuxScripts = @(
        'contracts/dev-up.ps1'
        'contracts/testnet-up.ps1'
        'desktop/scripts/release-build.ps1'
        'desktop/scripts/release-hash.ps1'
    ),

    # ---------------------------------------------------------------------
    # CHECK 9's PINS
    #
    # Measured by the architect over the same swept set: 43 `cast send`/`cast
    # call` signature call-sites, 15 DISTINCT signatures, in exactly 2 files
    # (contracts/dev-up.ps1, contracts/testnet-up.ps1), and 6 forge script
    # invocations at command position (3 per standup script) plus 3 display-label
    # echoes of those commands, which are not invocations and are excluded.
    #
    # These are FLOORS, not exact pins, and the gap is deliberate in both
    # directions: set just below the measurement so removing ONE call-site does
    # not turn the run red for the wrong reason, and far enough above zero that a
    # broken extractor cannot clear them. That is the whole point -- checks A and
    # B are LOOPS over whatever the extractor found, and a loop over an empty set
    # is green.
    #
    # The two floors on the cast side are not independent at today's distribution
    # (the least-used spelling appears twice, so losing two spellings also costs
    # four sites and trips the site floor first). $ExpectedCastSigsMin is the one
    # that still bites as call-sites GROW: it is what fails if the extractor is
    # ever reduced to recognising one spelling repeated forty times.
    # ---------------------------------------------------------------------
    [int] $ExpectedCastSitesMin    = 40,
    [int] $ExpectedCastSigsMin     = 14,
    [int] $ExpectedForgeInvokesMin = 3,

    # The CONTRIBUTING-ARTIFACT floor. This number used to be printed and never
    # asserted, and both literal pins below live in two of the SMALLEST artifacts
    # while out/Vm.sol/Vm.json is 669 KB -- so a size- or depth-related parse
    # regression could shrink the universe from the top and leave both pins
    # standing. Measured: 132 of 143 out/**/*.json files carry an `abi`; the
    # other 11 are out/build-info/*.json, which are not contract artifacts and
    # never had one.
    [int] $ExpectedAbiArtifactsMin = 100,

    # A floor on the SIZE OF THE UNIVERSE ITSELF, which is a different
    # measurement from the artifact count above and was added because the
    # artifact count alone is not enough. The artifact counter increments once an
    # artifact PARSES and carries an `abi` field -- before a single signature is
    # extracted from it. So a regression that opens all 132 artifacts and
    # harvests almost nothing from them keeps that counter at 132 and its guard
    # green.
    #
    # Measured 2026-07-29 by execution rather than by argument: a probe that let
    # every artifact parse but skipped all but seventeen contract names collapsed
    # the universe from 1,143 signatures to 164 and STEP 9 STILL REPORTED PASS --
    # the non-empty guard was satisfied, and the literal pins were satisfied
    # because the probe happened to retain the pins' owners. Guards that check
    # existence cannot see a universe that is merely far too small.
    #
    # 900 against 1,143 measured. Wide, on purpose: `forge build` output
    # legitimately varies with the OZ/forge-std version, and a floor that trips
    # on a dependency bump is a floor someone deletes. It is still five and a
    # half times the collapse that got through.
    [int] $ExpectedAbiSigsMin = 900,

    # PER-FILE, PER-TARGET forge pins, and why a tree total is not enough. BOTH
    # recorded defects were PER-FILE -- 737cfa4 repaired contracts/dev-up.ps1 and
    # left contracts/testnet-up.ps1 broken for a further session -- while every
    # guard step 9 originally shipped with measured the TREE. Reproduced by
    # execution 2026-07-29: rewriting dev-up.ps1's EpochSettlement invocation to
    # a variable target with no --sig gave "5 forge script invocation(s) checked"
    # and STEP 9 PASS. The floor of 3 was cleared, and the guard that requires
    # the overloaded target to be reached was satisfied by testnet-up.ps1's
    # surviving copy -- so the file that shipped the defect left check B's scope
    # entirely and the step reported green. This is $RequiredAuxScripts' argument
    # one level down: name the PAIRS, not the count. Both standup scripts deploy
    # EpochSettlement, so both pairs are required.
    [string[]] $RequiredForgeCallSites = @(
        'contracts/dev-up.ps1|DeployEpochSettlement.s.sol'
        'contracts/testnet-up.ps1|DeployEpochSettlement.s.sol'
    ),

    # The same blindness applies to check A, so its call-sites are floored per
    # file as well: 43 sites tree-wide clears $ExpectedCastSitesMin even if one
    # of the two standup scripts contributes NOTHING. Measured 2026-07-29:
    # dev-up.ps1 = 23, testnet-up.ps1 = 20. Pinned two below each, for exactly
    # the reason the tree floor sits three below its measurement.
    [System.Collections.Specialized.OrderedDictionary] $RequiredCastSitesPerFileMin = ([ordered]@{
        'contracts/dev-up.ps1'     = 21
        'contracts/testnet-up.ps1' = 18
    }),

    # ABI-universe sanity pins, WRITTEN OUT AS LITERALS on purpose. A count is
    # not enough: a universe of 1,142 correctly-counted junk strings clears the
    # non-empty guard. These two are read from no expression the extractor uses,
    # so a parser that reads the wrong JSON field produces a full-looking set
    # that no longer contains them.
    [string[]] $RequiredAbiSignatures = @(
        'setVault(address)'
        'mintBatch(bytes32,bytes32,address[],uint256[])'
    ),

    # THE SAME TWO PINS, CONTRACT-QUALIFIED, because the set above is keyed by
    # SIGNATURE ALONE and a signature can have more than one declarer. Measured:
    # mintBatch(bytes32,bytes32,address[],uint256[]) is declared by BOTH
    # WorkMinter and the legacy JobVault, so renaming WorkMinter.mintBatch leaves
    # the unqualified pin resolving through the sibling and the guard whose entire
    # job is catching well-formed nonsense cannot notice.
    # openSession(uint64,uint64,uint256) has the identical shape (BuyDesk and
    # SponsoredBuyDesk). The contract name is the artifact FILENAME, which
    # Foundry writes as out/<Source.sol>/<ContractName>.json.
    [string[]] $RequiredAbiSignaturesQualified = @(
        'HoldbackEscrow|setVault(address)'
        'WorkMinter|mintBatch(bytes32,bytes32,address[],uint256[])'
    ),

    # Check B's interesting branch has exactly ONE subject in this tree, and a
    # check that stops reaching it keeps passing while proving nothing. Named
    # here so that losing it is a red run rather than a quieter sweep.
    [string] $RequiredAmbiguousTarget = 'DeployEpochSettlement.s.sol',

    # Directory NAMES the walk never descends into, so it never reads build
    # output. A recursive walk from the repository root spends most of its time
    # in target/ and node_modules/, and neither check is worth 30 seconds.
    [string[]] $PruneDirNames = @('target', 'node_modules', '.git', '.claude',
                                  '.superpowers', '.agents', 'out', 'cache',
                                  'broadcast', 'lib', 'dist', 'build')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}
# Normalised so that the relative paths every finding prints -- and every
# $Required* pin is written against -- are computed by stripping exactly this
# prefix. A trailing separator or a `..` segment left in place shifts every
# relative path by a character and silently empties the required-set guard.
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path.TrimEnd('\', '/')
if ([string]::IsNullOrWhiteSpace($ContractsDir)) {
    $ContractsDir = Join-Path $RepoRoot 'contracts'
}

# ---------------------------------------------------------------------------
# Reporting. Findings and blockers are ACCUMULATED, never thrown: a run that
# stops at the first bad file names one defect where it could have named six,
# and the whole point of a static check is that it costs nothing to finish.
# ---------------------------------------------------------------------------
$script:Findings = New-Object System.Collections.ArrayList
$script:Blockers = New-Object System.Collections.ArrayList

function Add-Finding {
    param([string]$Check, [string]$Text)
    [void]$script:Findings.Add([pscustomobject]@{ Check = $Check; Text = $Text })
}

function Add-Blocker {
    param([string]$Check, [string]$Text)
    [void]$script:Blockers.Add([pscustomobject]@{ Check = $Check; Text = $Text })
}

# EVERY CALLER WRAPS THESE IN @(...) AGAIN, and that is not belt-and-braces.
# `return @()` from a PowerShell function emits NOTHING, so a filter that matched
# nothing hands the caller $null, and `Set-StrictMode -Version Latest` then throws
# PropertyNotFoundStrict on `.Count`. Observed here on the very first run: the
# no-findings path -- the ONLY path that should exit 0 -- died with "The property
# 'Count' cannot be found on this object" and the process exited 1 with no
# GATE-DETAIL lines at all, i.e. a clean tree reported as a red with no reason.
# run-full-gate carries the identical note above its own Get-FailureExcerpt call
# for the identical reason.
function Get-CheckFindings {
    param([string]$Check)
    return @($script:Findings | Where-Object { $_.Check -eq $Check })
}

function Get-CheckBlockers {
    param([string]$Check)
    return @($script:Blockers | Where-Object { $_.Check -eq $Check })
}

# ---------------------------------------------------------------------------
# CHECK 9's READERS
#
# Six small readers, factored out of the harvest because that harvest used to
# judge a PHYSICAL LINE AS A WHOLE, and an adversarial review demonstrated both
# failure directions of that shortcut:
#
#   * a flag read off text sitting BESIDE the command -- green on a live defect;
#   * a correct command reformatted across two lines read as broken, or dropped
#     from the count altogether -- red on nothing, or silence.
#
# They are functions rather than inline blocks so that the harvest's own comments
# can name what does the work, and so the `#`/quote scanner exists ONCE. All of
# them are line-level string readers, not a PowerShell parser: `<# ... #>` block
# comments and here-strings are NOT modelled. Neither appears on a call-site line
# in this tree, and a failure names the file and line either way.
# ---------------------------------------------------------------------------

# Index of the first $StopChars character that is NOT inside a string literal,
# scanning from $Start; $Line.Length if there is none. Quote state is tracked so
# that a `#`, `;` or `}` INSIDE a string does not stop the scan, and a backtick
# escapes the next character except inside a single-quoted string, where
# PowerShell has no escape character.
function Find-PsUnquotedStop {
    param([string]$Line, [int]$Start, [string]$StopChars)
    $bt  = [char]0x60
    $nul = [char]0
    $q   = $nul
    $i   = $Start
    while ($i -lt $Line.Length) {
        $c = $Line[$i]
        if ($q -eq "'") {
            if ($c -eq "'") { $q = $nul }
            $i++
            continue
        }
        if ($c -eq $bt) { $i += 2; continue }
        if ($q -eq '"') {
            if ($c -eq '"') { $q = $nul }
            $i++
            continue
        }
        if (($c -eq '"') -or ($c -eq "'")) { $q = $c; $i++; continue }
        # `${...}` is a brace-quoted VARIABLE NAME, not a script block, so its
        # closing brace must not stop the scan.
        #
        # This one is worth the four lines. `}` is a stop character because it is
        # what makes the one-line `Invoke-Step "x" { forge script ... } "label"`
        # form work -- the span has to end at the block's close so a `--sig` in
        # the label cannot be read as the command's. But the same rule truncated
        #
        #     forge script script/DeployEpochSettlement.s.sol --rpc-url ${RPC} --sig "run()"
        #
        # at the brace, so `--sig` fell outside the span and check 9 reported
        # AMBIGUOUS ENTRY POINT -- the exact defect it exists to catch -- against
        # a command that works. A false red with the most alarming possible
        # message. It matters here specifically because this repository's own
        # PowerShell 5.1 rules push authors toward `${var}` (a bare `$var` before
        # a colon is a parse error), so the spelling is encouraged in the very
        # files this check reads.
        #
        # Only the UNQUOTED, `$`-prefixed form is skipped. `"${RPC}"` and
        # `'${RPC}'` were already safe via quote state, and a bare `@{a=1}` still
        # stops the scan -- a hashtable literal on a call-site line is not a case
        # this reader claims to model.
        if (($c -eq '$') -and (($i + 1) -lt $Line.Length) -and ($Line[$i + 1] -eq '{')) {
            $close = $Line.IndexOf('}', $i + 2)
            if ($close -lt 0) { return $Line.Length }
            $i = $close + 1
            continue
        }
        if ($StopChars.IndexOf($c) -ge 0) {
            # `#` opens a comment only at a token boundary. `--rpc-url
            # http://host#frag` is ONE argument, and truncating there would be a
            # false failure of the very kind this whole reader exists to prevent.
            if (($c -ne '#') -or ($i -eq 0) -or [char]::IsWhiteSpace($Line[$i - 1])) { return $i }
        }
        $i++
    }
    return $Line.Length
}

# Is the character at $Index inside a string literal? Used to tell a real command
# from an echo of that command sitting inside a display-label string.
#
# This is a QUOTE-STATE SCAN, not a parity count, and the difference is a false
# red that an adversarial review demonstrated. Counting `"` and `'` occurrences
# independently and testing each for oddness reads
#
#     Write-Host "founder's epoch deploy"; forge script script/Deploy...s.sol --sig "run()"
#
# as dq=2 (even) but sq=1 (ODD), so the invocation is filed as a display label
# and silently leaves check B -- and because the tree-wide floors still clear,
# the operator is then told a *different* guard failed for a reason that is not
# true. An apostrophe inside a double-quoted string is ordinary English, and this
# repository's own messages are full of possessives.
#
# A single-quoted string has no escape character in PowerShell; a doubled `''` is
# a literal quote and self-balances, which this scan gets right for free.
function Test-PsInsideString {
    param([string]$Line, [int]$Index)
    $bt  = [char]0x60
    $nul = [char]0
    $q   = $nul
    $i   = 0
    while (($i -lt $Index) -and ($i -lt $Line.Length)) {
        $c = $Line[$i]
        if ($q -eq "'") {
            if ($c -eq "'") { $q = $nul }
            $i++
            continue
        }
        if ($c -eq $bt) { $i += 2; continue }
        if ($q -eq '"') {
            if ($c -eq '"') { $q = $nul }
            $i++
            continue
        }
        if (($c -eq '"') -or ($c -eq "'")) { $q = $c; $i++; continue }
        $i++
    }
    return ($q -ne $nul)
}

# The text of the ONE command that starts at $Start. A PowerShell line can carry
# a command AND text that is not part of it: a trailing `#` comment, a second
# statement after `;`, or the `}` that closes a one-line script block, followed
# by the display-label argument both standup scripts hand to `Invoke-Step`. A
# flag searched for across the WHOLE line is therefore read off whatever sits
# beside the command. Measured -- both of these were green with the defect LIVE
# before this reader existed:
#
#   forge script script/DeployEpochSettlement.s.sol --broadcast  # --sig no longer needed
#   Invoke-Step "X" { forge script ...EpochSettlement... } "forge script ... --sig 'run()'"
function Get-PsCommandSpan {
    param([string]$Line, [int]$Start)
    $end = Find-PsUnquotedStop -Line $Line -Start $Start -StopChars ';}#'
    return $Line.Substring($Start, $end - $Start)
}

# The line with any trailing `#` comment removed, by the same rule. Applied
# BEFORE anything is harvested, so a signature or a flag that is commented out
# cannot be counted as something the shell would run.
function Remove-PsLineComment {
    param([string]$Line)
    $end = Find-PsUnquotedStop -Line $Line -Start 0 -StopChars '#'
    if ($end -ge $Line.Length) { return $Line }
    return $Line.Substring(0, $end)
}

# PowerShell line continuations folded into LOGICAL lines. A line ending in a
# backtick continues onto the next, so
#
#     forge script script/DeployEpochSettlement.s.sol `
#         --sig "run()" --rpc-url $RPC --broadcast
#
# is ONE command that a per-physical-line scan sees as two. Measured, on a
# command that is entirely CORRECT: the first half reads as carrying no --sig and
# check 9 reported AMBIGUOUS ENTRY POINT -- a false red, and a check whose red is
# not believable gets switched off. A `cast send` whose signature moves to the
# continuation line does not false-red, it VANISHES (43 sites -> 42, which a
# floor of 40 never notices).
#
# `.No` is the FIRST physical line number of the logical line, so a failure still
# names the line an operator would open.
#
# A COMMENT NEVER CONTINUES, and that exclusion is load-bearing rather than tidy.
# PowerShell reads a trailing backtick inside a `#` comment as part of the
# comment text, so folding one would splice the comment onto the command on the
# next line -- and the harvest skips anything matching `^\s*#`, so that command
# would leave its scope silently. This very file contains such a comment: the
# worked example in this function's own header.
function Get-PsLogicalLines {
    param([string]$Path)
    $phys   = [System.IO.File]::ReadAllLines($Path)
    $out    = New-Object System.Collections.ArrayList
    $contRe = [regex]([string][char]0x60 + '[ \t]*$')
    $k = 0
    while ($k -lt $phys.Count) {
        $firstNo = $k + 1
        $buf     = $phys[$k]
        if ($buf -notmatch '^\s*#') {
            while ($contRe.IsMatch($buf) -and (($k + 1) -lt $phys.Count)) {
                $k++
                $buf = $contRe.Replace($buf, ' ') + $phys[$k].TrimStart()
            }
        }
        [void]$out.Add([pscustomobject]@{ No = $firstNo; Text = $buf })
        $k++
    }
    return $out
}

# A Solidity parameter list reduced to the ABI TYPES a selector is built from.
# `run(string memory manifestPath)` in a deploy script and `run(string)` on a
# `forge script --sig` command line are THE SAME ENTRY POINT, so a comparison
# that keeps parameter names or data-location keywords reports a mismatch that is
# not one. The type is the first whitespace-delimited token of each parameter:
# `address payable to` -> `address`, `address[] calldata xs` -> `address[]`.
function ConvertTo-SolCanonicalSig {
    param([string]$Name, [string]$Params)
    $types = New-Object System.Collections.ArrayList
    foreach ($piece in ($Params -split ',')) {
        $t = $piece.Trim()
        if ($t.Length -eq 0) { continue }
        $t = ($t -split '\s+')[0]
        if ($t.Length -eq 0) { continue }
        [void]$types.Add($t)
    }
    return ('{0}({1})' -f $Name.Trim(), ($types -join ','))
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
$hostExe = ''
try { $hostExe = [string](Get-Process -Id $PID).Path } catch { $hostExe = '<unknown>' }

Write-Output 'check-aux-scripts.ps1 -- gate steps 8 and 9, one implementation'
Write-Output ("  repo root   : {0}" -f $RepoRoot)
Write-Output ("  contracts   : {0}" -f $ContractsDir)
Write-Output ("  host        : {0} (PowerShell {1})" -f $hostExe, $PSVersionTable.PSVersion.ToString())
Write-Output ("  host default encoding: {0} -- this is what check 8(b) means by 'as the host reads it'" -f `
    [System.Text.Encoding]::Default.WebName)
Write-Output ("  checks      : 8={0} 9={1}" -f `
    $(if ($Skip8) { 'SKIPPED' } else { 'run' }), $(if ($Skip9) { 'SKIPPED' } else { 'run' }))
Write-Output ''

# A run that selects nothing must not exit 0. This is the same argument the
# exit contract makes about a missing artifact directory: no verdict is not a
# green verdict.
if ($Skip8 -and $Skip9) {
    Add-Blocker -Check 'run' -Text (
        'both checks were skipped (-Skip8 -Skip9), so this run verified NOTHING. ' +
        'A run that checks nothing must not report success; exiting 2.')
}

$aux8Status = 'SKIPPED'
$aux9Status = 'SKIPPED'
$aux8Detail = 'not run (-Skip8) -- NOTHING about script parse or encoding integrity was verified'
$aux9Detail = 'not run (-Skip9) -- NOTHING about call-site ABI consistency was verified'
$auxFiles   = New-Object System.Collections.ArrayList
$scopeOk    = $false
# Initialised here, not in the block below: with both checks skipped that block
# never runs, and under Set-StrictMode reading an unassigned variable throws --
# which would surface as "unexpected error" instead of the "nothing was checked"
# blocker that is the actual finding.
$walkOk     = $false

try {
    if (-not ($Skip8 -and $Skip9)) {

        # ===================================================================
        # SHARED SCOPE -- the swept set both checks judge.
        # ===================================================================
        $auxStack = New-Object System.Collections.Stack
        $auxStack.Push($RepoRoot)
        $walkOk   = $true
        while ($auxStack.Count -gt 0) {
            $dir = $auxStack.Pop()
            try {
                foreach ($f in [System.IO.Directory]::EnumerateFiles($dir, '*.ps1')) {
                    [void]$auxFiles.Add($f)
                }
                foreach ($d in [System.IO.Directory]::EnumerateDirectories($dir)) {
                    if ($PruneDirNames -notcontains (Split-Path $d -Leaf)) { $auxStack.Push($d) }
                }
            } catch {
                # An unreadable directory must not be mistaken for an empty one.
                # This is a COULD-NOT-RUN, not a finding: the swept set is
                # incomplete, so neither check has a scope it can stand behind.
                Add-Blocker -Check 'scope' -Text ("could not enumerate {0} : {1}" -f $dir, $_)
                $walkOk = $false
                break
            }
        }

        if ($walkOk) {
            # VACUITY GUARD 1 -- a walk that finds nothing must not read as a
            # clean tree.
            if ($auxFiles.Count -lt $ExpectedAuxScriptsMin) {
                Add-Finding -Check 'scope' -Text (
                    ("found only {0} .ps1 file(s), expected at least {1} -- the walk or its prune " -f `
                        $auxFiles.Count, $ExpectedAuxScriptsMin) +
                    'list is wrong, and a green run over a shrunken set proves nothing. Lower ' +
                    '-ExpectedAuxScriptsMin deliberately if a script was genuinely deleted.')
            }

            # VACUITY GUARD 2 -- the count could be met while the scripts that
            # have actually shipped defects are the ones excluded.
            $auxRel = @($auxFiles | ForEach-Object {
                $_.Substring($RepoRoot.Length).TrimStart('\', '/').Replace('\', '/')
            })
            $auxMissing = @($RequiredAuxScripts | Where-Object { $auxRel -notcontains $_ })
            if ($auxMissing.Count -gt 0) {
                Add-Finding -Check 'scope' -Text (
                    "required script(s) not reached by the walk: $($auxMissing -join ', ')")
            }

            $scopeOk = (@(Get-CheckFindings -Check 'scope').Count -eq 0)
            Write-Output ("scope: {0} .ps1 file(s) swept from {1}" -f $auxFiles.Count, $RepoRoot)
        }
    }

    # =======================================================================
    # CHECK 8 -- auxiliary script integrity
    # =======================================================================
    if ((-not $Skip8) -and $walkOk) {
        $vacuousEncoding = ([System.Text.Encoding]::Default.WebName -eq 'utf-8')
        if ($vacuousEncoding) {
            Write-Output (
                'WARNING: this host decodes a BOM-less file as UTF-8, so check 8(b) cannot ' +
                'disagree with itself and is VACUOUS in this run. Run it under Windows ' +
                'PowerShell 5.1 (ANSI code page) to exercise it.')
        }

        $auxBad = New-Object System.Collections.ArrayList
        foreach ($path in $auxFiles) {
            $rel = $path.Substring($RepoRoot.Length).TrimStart('\', '/').Replace('\', '/')
            $bytes = [System.IO.File]::ReadAllBytes($path)

            # (a) Parses as the host reads it.
            $hostErr = $null
            $hostAst = [System.Management.Automation.Language.Parser]::ParseFile(
                $path, [ref]$null, [ref]$hostErr)
            if (@($hostErr).Count -gt 0) {
                $e0 = @($hostErr)[0]
                [void]$auxBad.Add(
                    "$rel -- DOES NOT PARSE as the host reads it. L$($e0.Extent.StartLineNumber): $($e0.Message)")
                continue
            }

            # (b) Same meaning under both decodings. Skipped only where the two
            #     decodings are identical by construction.
            $hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and
                       $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
            if ($hasBom) { continue }
            $nonAscii = $false
            foreach ($b in $bytes) { if ($b -gt 127) { $nonAscii = $true; break } }
            if (-not $nonAscii) { continue }

            $utf8Err = $null
            $utf8Ast = [System.Management.Automation.Language.Parser]::ParseInput(
                [System.Text.Encoding]::UTF8.GetString($bytes), [ref]$null, [ref]$utf8Err)
            if (@($utf8Err).Count -gt 0) {
                [void]$auxBad.Add(
                    "$rel -- has no BOM and does not parse as UTF-8; its bytes are not a coherent script under either encoding")
                continue
            }

            $pred = { param($n) $n -is [System.Management.Automation.Language.CommandAst] }
            $cmdsHost = (@($hostAst.FindAll($pred, $true)) | ForEach-Object { $_.GetCommandName() }) -join '|'
            $cmdsUtf8 = (@($utf8Ast.FindAll($pred, $true)) | ForEach-Object { $_.GetCommandName() }) -join '|'
            if ($cmdsHost -ne $cmdsUtf8) {
                $nH = @($hostAst.FindAll($pred, $true)).Count
                $nU = @($utf8Ast.FindAll($pred, $true)).Count
                [void]$auxBad.Add(
                    ("$rel -- PARSES CLEAN BUT MEANS SOMETHING ELSE. The host builds $nH command(s); " +
                     "the file as written has $nU. It has no BOM, so PowerShell 5.1 reads it as the " +
                     "ANSI code page and a non-ASCII character inside a quoted string is acting as a " +
                     "delimiter. Fix by making the file ASCII, or by giving it a UTF-8 BOM."))
            }
        }

        foreach ($bad in $auxBad) { Add-Finding -Check '8' -Text $bad }

        if ($auxBad.Count -gt 0) {
            $aux8Status = 'FAIL'
            $aux8Detail = "$($auxBad.Count) auxiliary script(s) would not run as written"
        } elseif (-not $scopeOk) {
            # The per-file pass found nothing wrong over a set that is not the
            # set it was supposed to judge. That is not a pass.
            $aux8Status = 'FAIL'
            $aux8Detail = 'the swept set failed its own scope guards -- see the scope finding(s) above'
        } else {
            $aux8Status = 'PASS'
            $aux8Detail = "$($auxFiles.Count) script(s) parse, and mean the same thing the host reads"
        }
    }

    # =======================================================================
    # CHECK 9 -- script call-site ABI consistency
    #
    # THE ABI UNIVERSE IS ONLY AS FRESH AS THE CALLER MADE IT. In the gate this
    # runs after `forge test` and `forge build --sizes`, so the artifacts are the
    # ones this gate produced; a CI job must build before calling, or it is
    # reading whatever the checkout contained.
    #
    # THE RETURN-TYPE FORM IS THE TRAP. `cast call` takes
    # "balanceOf(address)(uint256)": the SECOND parenthesis group is the RETURN
    # type and is not part of the ABI signature, which is `balanceOf(address)`.
    # The regex below consumes it and throws it away. Measured: build the key
    # WITHOUT stripping it and all 9 `cast call` sites stop resolving -- 9
    # findings that are all false. A check whose red is not believable gets
    # switched off.
    #
    # WHY SIGNATURES ARE MATCHED AS A WHOLE QUOTED TOKEN. Both standup scripts
    # repeat their commands as human-readable display labels. Requiring the
    # quotes to sit immediately around `name(types)` excludes those by
    # construction: a label is a sentence, so its opening quote is not followed by
    # a signature.
    #
    # DUPLICATES ON THE FORGE SIDE, and why they are dropped rather than checked.
    # testnet-up.ps1 echoes each `forge script` command as a label argument too,
    # so 9 occurrences are really 6 invocations and 3 echoes. A label is not what
    # runs, so failing on one would be a false failure -- red on a line that
    # cannot break a deploy. An occurrence is therefore treated as an invocation
    # only at COMMAND POSITION. Measured, honestly: checking the 3 echoes as well
    # is ALSO green today, so this exclusion is defensive rather than
    # load-bearing. It cannot mask a real one, and that is asserted rather than
    # asserted-about: every line is judged independently, so removing --sig from a
    # real invocation is red no matter what any label says; and VACUITY GUARD 6
    # requires each excluded label to echo a target this check actually CHECKED
    # in the same file. Without guard 6 the classifier would be an unfalsifiable
    # filter.
    #
    # ONE KNOWN RESIDUE, stated rather than papered over: a tuple parameter
    # enters the universe as `tuple`, so a call-site spelling it out as
    # `(uint256,bool)` would not resolve. No call-site uses one today (41
    # compiled functions do), and the failure names the file, line and signature,
    # so it is diagnosable in seconds. Expanding tuple components was NOT added:
    # it would be code no assertion in this repository can turn red, which is
    # decoration.
    #
    # GUARD NUMBERS ARE IN THE ORDER THE GUARDS WERE ADDED, NOT THE ORDER THEY
    # RUN. 0 and 7-10 came from the 2026-07-29 hardening and sit at the points
    # where the data each one judges first exists; 1-6 keep the numbers their own
    # comments and mutation notes already refer to.
    # =======================================================================
    if ((-not $Skip9) -and $walkOk) {

        # ---- the reference set: every function signature the contracts compile to
        $AbiOutDir = Join-Path $ContractsDir 'out'
        $abiCanRun = $true
        if (-not (Test-Path -LiteralPath $AbiOutDir)) {
            $abiCanRun = $false
            Add-Blocker -Check '9' -Text (
                "the compiled-artifact directory does not exist: $AbiOutDir. This check CANNOT RUN, " +
                "which is NOT the same as passing -- with no ABI universe every call-site would " +
                "resolve against nothing and the check would report green over an unchecked tree. " +
                # BACKTICK-f IS A FORM FEED. This line read "`forge build`" until
                # 2026-07-29 and emitted 0x0C followed by "orge build" -- the only
                # backtick-quoted token in a runtime message in this file, and the
                # message is the one CI sees when its artifact of out/ fails to
                # arrive. Quote command names with ' inside a "..." string here.
                "'forge build' (or the gate's forge test step) populates out/.")
        }

        $abiArtifactPaths = @()
        if ($abiCanRun) {
            # Materialised inside a try for the reason the walk gives: an
            # unreadable directory must not be mistaken for an empty one.
            try {
                $abiArtifactPaths = @([System.IO.Directory]::GetFiles(
                    $AbiOutDir, '*.json', [System.IO.SearchOption]::AllDirectories))
            } catch {
                $abiCanRun = $false
                Add-Blocker -Check '9' -Text ("could not enumerate {0} : {1}" -f $AbiOutDir, $_)
            }
        }

        if ($abiCanRun) {
            # ORDINAL string maps, NOT `@{}`. A PowerShell hashtable literal uses
            # a case-INSENSITIVE comparer, and Solidity selectors are
            # case-SENSITIVE: measured, `cast sig 'setVault(address)'` is
            # 0x6817031b while `cast sig 'setvault(address)'` is 0x2a2662af --
            # two genuinely different functions. With `@{}`, a call-site that
            # mis-cased a name resolved against the universe, passed check A, and
            # would have REVERTED ON CHAIN, which is exactly the class this check
            # exists to catch. Reproduced before this change: mis-casing
            # dev-up.ps1's setVault site gave STEP 9 PASS. GUARD 0 below is what
            # stops the fix from rotting back to a literal unnoticed.
            $abiSigs     = [System.Collections.Hashtable]::new(0, [StringComparer]::Ordinal)
            $abiSigsQual = [System.Collections.Hashtable]::new(0, [StringComparer]::Ordinal)
            $castSigSeen = [System.Collections.Hashtable]::new(0, [StringComparer]::Ordinal)

            # VACUITY GUARD 0 -- THE COMPARER IS ORDINAL, ASSERTED RATHER THAN
            # INTENDED. Without this the paragraph above is a comment: a future
            # refactor back to `@{}` silently restores the case-insensitive
            # lookup and nothing in this repository goes red. This assertion is
            # what makes the fix non-vacuous.
            # MUTATION that turns it red: change any of the three constructors to
            # `@{}`.
            $cmpProbeKey = 'GateOrdinalComparerProbe(address)'
            $cmpProbeAlt = 'gateordinalcomparerprobe(address)'
            $cmpBad      = New-Object System.Collections.ArrayList
            foreach ($cmpProbe in @(
                [pscustomobject]@{ Name = 'abiSigs';     Table = $abiSigs }
                [pscustomobject]@{ Name = 'abiSigsQual'; Table = $abiSigsQual }
                [pscustomobject]@{ Name = 'castSigSeen'; Table = $castSigSeen }
            )) {
                if ($cmpProbe.Table.Count -ne 0) {
                    [void]$cmpBad.Add("$($cmpProbe.Name) did not start empty")
                }
                $cmpProbe.Table[$cmpProbeKey] = $true
                if (-not $cmpProbe.Table.ContainsKey($cmpProbeKey)) {
                    [void]$cmpBad.Add("$($cmpProbe.Name) cannot find a key it just stored")
                }
                if ($cmpProbe.Table.ContainsKey($cmpProbeAlt)) {
                    [void]$cmpBad.Add("$($cmpProbe.Name) is CASE-INSENSITIVE")
                }
                $cmpProbe.Table.Remove($cmpProbeKey)
                if ($cmpProbe.Table.Count -ne 0) {
                    [void]$cmpBad.Add("$($cmpProbe.Name) did not release the probe key")
                }
            }
            if ($cmpBad.Count -gt 0) {
                Add-Finding -Check '9' -Text (
                    "check 9's signature lookups are not ordinal string maps: $($cmpBad -join '; '). " +
                    "Solidity selectors are CASE-SENSITIVE -- setVault(address) is 0x6817031b and " +
                    "setvault(address) is 0x2a2662af, two different functions -- so a " +
                    "case-insensitive table resolves a mis-cased call-site that will revert on " +
                    "chain, and check A reports green over it. Restore " +
                    "[System.Collections.Hashtable]::new(0, [StringComparer]::Ordinal).")
            }

            $abiFnEntries = 0
            $abiWithAbi   = 0
            foreach ($artPath in $abiArtifactPaths) {
                # A single unparseable artifact is skipped, not fatal: out/ also
                # holds build-info and metadata JSON that is not an artifact at
                # all. The guards below are what make "skipped them ALL"
                # impossible to report as a pass.
                $j = $null
                try { $j = [System.IO.File]::ReadAllText($artPath) | ConvertFrom-Json } catch { $j = $null }
                if ($null -eq $j) { continue }
                if (-not ($j.PSObject.Properties.Name -contains 'abi')) { continue }
                $abiWithAbi++
                # Foundry writes every artifact as
                # out/<Source.sol>/<ContractName>.json, so the FILENAME is the
                # contract name. That is what makes guard 8's qualified pins
                # possible without parsing Solidity.
                $artContract = [System.IO.Path]::GetFileNameWithoutExtension($artPath)
                foreach ($entry in @($j.abi)) {
                    if ($null -eq $entry) { continue }
                    # Property presence is tested, not assumed: Set-StrictMode
                    # -Version Latest THROWS on a missing property, and a
                    # malformed artifact would then surface as an unhandled
                    # error attributed to the run rather than to this check.
                    $props = $entry.PSObject.Properties.Name
                    if (($props -notcontains 'type') -or ($props -notcontains 'name')) { continue }
                    if ([string]$entry.type -ne 'function') { continue }
                    $abiFnEntries++
                    $argTypes = @()
                    if ($props -contains 'inputs') {
                        foreach ($inp in @($entry.inputs)) {
                            if ($null -eq $inp) { continue }
                            if ($inp.PSObject.Properties.Name -notcontains 'type') { continue }
                            $argTypes += [string]$inp.type
                        }
                    }
                    $sigText = '{0}({1})' -f [string]$entry.name, ($argTypes -join ',')
                    $abiSigs[$sigText] = $true
                    $abiSigsQual[('{0}|{1}' -f $artContract, $sigText)] = $true
                }
            }
            Write-Output ("ABI universe: {0} distinct function signature(s) from {1} function entr(ies) in {2} of {3} artifact(s)" -f `
                $abiSigs.Count, $abiFnEntries, $abiWithAbi, $abiArtifactPaths.Count)

            # VACUITY GUARD 1 -- "could not check" must never render as "checked
            # and fine".
            # MUTATION that turns it red: make the artifact reader select nothing
            # (e.g. compare $entry.type against a misspelling of 'function').
            if ($abiSigs.Count -eq 0) {
                Add-Finding -Check '9' -Text (
                    "read $($abiArtifactPaths.Count) artifact(s) under $AbiOutDir and extracted ZERO " +
                    "function signatures. A check that cannot build its reference set has checked " +
                    "NOTHING, and must not report the same green as a check that checked everything " +
                    "and found nothing wrong. Run forge build in contracts/ and look at out/.")
            }

            # VACUITY GUARD 7 -- A FLOOR ON THE ARTIFACTS THAT ACTUALLY
            # CONTRIBUTED. Guard 1 rules out ZERO and nothing else, and this
            # count used to be PRINTED AND NEVER ASSERTED. Both of guard 2's
            # literal pins live in two of the smallest artifacts in out/, while
            # out/Vm.sol/Vm.json is 669 KB -- so a size- or depth-related parse
            # regression could shrink the universe from the TOP with both pins
            # still standing, and guards 1 and 2 would both stay green.
            # MUTATION that turns it red: cap the reader by size (skip any
            # artifact over 100 KB), or make the ConvertFrom-Json call fail on
            # the large ones.
            if ($abiWithAbi -lt $ExpectedAbiArtifactsMin) {
                Add-Finding -Check '9' -Text (
                    "only $abiWithAbi of $($abiArtifactPaths.Count) artifact(s) under $AbiOutDir " +
                    "contributed an abi field, expected at least $ExpectedAbiArtifactsMin (132 " +
                    "measured; the other 11 are out/build-info/*.json, which are not contract " +
                    "artifacts and never had one). The reference set is being built from a " +
                    "shrinking share of the tree, and the literal pins alone cannot see that -- " +
                    "they sit in two of the smallest files.")
            }

            # VACUITY GUARD 7b -- the size of the UNIVERSE, which guard 7 does
            # not measure. Guard 7 counts artifacts that PARSED and carried an
            # `abi` field. The counter is incremented before a single signature
            # is read out of them, so a regression that opens all 132 and
            # harvests almost nothing keeps guard 7 green. Not hypothetical: the
            # architect probed exactly that shape on 2026-07-29 -- every artifact
            # parsed, all but seventeen contract names skipped -- and the
            # universe fell from 1,143 signatures to 164 while STEP 9 reported
            # PASS. Guard 1 saw a non-empty set; guards 2 and 8 saw their pins,
            # because the probe retained the pins' owners. Existence guards
            # cannot see "far too small".
            # MUTATION that turns it red: skip artifacts by contract name (or by
            # size) anywhere in the reader loop while leaving HoldbackEscrow and
            # WorkMinter in, so guards 1, 2, 7 and 8 all stay green and only this
            # one fires.
            if ($abiSigs.Count -lt $ExpectedAbiSigsMin) {
                Add-Finding -Check '9' -Text (
                    "the ABI universe holds only $($abiSigs.Count) distinct signature(s), expected " +
                    "at least $ExpectedAbiSigsMin (1,143 measured 2026-07-29). Every artifact may " +
                    "have parsed and the literal pins may both still resolve while the reference " +
                    "set check A consults has collapsed -- a call-site can then only be checked " +
                    "against the fraction that survived. Raise or lower -ExpectedAbiSigsMin " +
                    "deliberately if the contract set genuinely changed size.")
            }

            # VACUITY GUARD 2 -- guard 1 only proves the set is non-empty; a set
            # of 1,142 correctly-counted JUNK strings clears it. These literals
            # are not derived from anything the extractor computes.
            # MUTATION that turns it red: read the signature from the wrong ABI
            # field (`$inp.name` instead of `$inp.type`) -- the universe stays
            # large (1,046) and loses both pins.
            $abiPinMissing = @($RequiredAbiSignatures | Where-Object { -not $abiSigs.ContainsKey($_) })
            if ($abiPinMissing.Count -gt 0) {
                Add-Finding -Check '9' -Text (
                    "the ABI universe holds $($abiSigs.Count) signature(s) but is missing " +
                    "known-good literal(s): $($abiPinMissing -join ', '). The artifact reader is " +
                    "producing well-formed nonsense. Update -RequiredAbiSignatures only if the " +
                    "contract genuinely renamed the function, in the same commit.")
            }

            # VACUITY GUARD 8 -- THE SAME PINS, UNMASKABLE BY A SIBLING
            # DECLARER. Guard 2 keys on the SIGNATURE ALONE, and the universe is
            # a flat union: a signature with two owners resolves through either.
            # Measured: mintBatch(bytes32,bytes32,address[],uint256[]) is
            # declared by BOTH WorkMinter AND the legacy JobVault, so renaming
            # WorkMinter.mintBatch leaves the call-sites AND GUARD 2'S OWN PIN
            # resolving -- the guard whose entire job is catching well-formed
            # nonsense cannot notice its subject disappear.
            # openSession(uint64,uint64,uint256) has the same shape (BuyDesk and
            # SponsoredBuyDesk). This guard names the OWNER, so the mask does not
            # work.
            #
            # The FLAT universe is still what check A resolves against,
            # deliberately: a `cast send $GOAT "setMinter(address,bool)"`
            # call-site carries no contract name a static reader can trust
            # ($GOAT is a runtime address), so qualifying check A would be
            # guesswork. This guard is only about the vacuity pins.
            # MUTATION that turns it red: rename WorkMinter's mintBatch (guard 2
            # stays green through JobVault and only this fails), or derive the
            # contract name from the wrong part of the artifact path (e.g. the
            # parent directory, which is <Source>.sol and not the contract).
            $abiQualMissing = @($RequiredAbiSignaturesQualified |
                Where-Object { -not $abiSigsQual.ContainsKey($_) })
            if ($abiQualMissing.Count -gt 0) {
                Add-Finding -Check '9' -Text (
                    "the contract-qualified ABI index holds $($abiSigsQual.Count) entr(ies) but is " +
                    "missing known-good literal(s): $($abiQualMissing -join ', '). Each is " +
                    "<ContractName>|<signature>, and the contract name is the artifact filename. A " +
                    "hit in the flat universe is NOT enough here: both of these signatures have " +
                    "more than one declarer, so the unqualified pin survives a rename of the owner " +
                    "this check cares about. Update -RequiredAbiSignaturesQualified only alongside " +
                    "a genuine rename.")
            }

            # ---- HARVEST: extract call-sites, judge nothing yet -------------
            # Extraction and adjudication are separate passes on purpose, so that
            # every vacuity guard runs BEFORE the first verdict is drawn from a
            # set that might be empty.
            # $castSigSeen is declared with the ABI tables above, so that GUARD 0
            # can prove its comparer is ordinal before anything is put in it.
            $castSites   = New-Object System.Collections.ArrayList
            $forgeSites  = New-Object System.Collections.ArrayList
            $forgeLabels = New-Object System.Collections.ArrayList
            $abiBad      = New-Object System.Collections.ArrayList
            # Deploy-script path -> its declared run(...) signatures. A plain
            # `@{}` ON PURPOSE, and NOT covered by GUARD 0: its keys are Windows
            # FILE PATHS, which are case-insensitive, so the case-insensitive
            # comparer is the correct one here. Only the SIGNATURE maps must be
            # ordinal.
            $runSigCache = @{}

            # The quoted-token forms cast accepts: "name(types)" and, for `cast
            # call`, "name(types)(returntypes)". Either quote character is
            # honoured -- a scanner that knows one spelling reads zero while the
            # defect is live. The trailing group is matched so it can be
            # DISCARDED; the ABI signature has no return type. \k<q> forces the
            # closing quote to match the opening one, so a match can never span
            # two adjacent strings.
            $castSigRe = [regex]'(?<q>["''])(?<name>[A-Za-z_][A-Za-z0-9_]*)\((?<args>[^()"'']*)\)(?:\([^()"'']*\))?\k<q>'
            $forgeRe   = [regex]'forge\s+script\s+(?<target>[^\s"'']+\.s\.sol)'

            # ANCHORED to a line start, and therefore blind to a commented-out
            # declaration. Unanchored it counted those, which keeps check B's
            # ambiguous branch alive as DEAD CODE: the run count stays at 2 while
            # forge sees ONE entry point, so the branch is "exercised" by a
            # declaration that does not exist and guard 5's pin asserts nothing.
            # The parameter list is captured as well -- check B compares the
            # --sig VALUE against it.
            $runDeclRe = [regex]'(?m)^[ \t]*function\s+run\s*\((?<params>[^)]*)\)'

            # `--sig` AND ITS VALUE, in the three spellings a call-site can use.
            # Only checking the flag's PRESENCE accepts `--sig "runn()"` and a
            # --sig naming an overload that has since been renamed: forge
            # dispatches on the VALUE.
            $sigFlagRe = [regex]'--sig\s+(?:"(?<dq>[^"]*)"|''(?<sq>[^'']*)''|(?<bare>[^\s"'']+))'

            # A signature value as written on a command line, e.g. `run(string)`.
            $sigValRe  = [regex]'^\s*(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?<params>[^)]*)\)\s*$'

            foreach ($sPath in $auxFiles) {
                $sRel = $sPath.Substring($RepoRoot.Length).TrimStart('\', '/').Replace('\', '/')
                # LOGICAL lines, not physical ones: a backtick continuation is
                # one command, and reading its halves separately both false-reds
                # a correct `forge script` and silently drops a `cast send`. See
                # Get-PsLogicalLines. `.No` is the first physical line, so
                # failures still name a line an operator can open.
                foreach ($sLogical in (Get-PsLogicalLines -Path $sPath)) {
                    $sNo = $sLogical.No
                    if ($sLogical.Text -match '^\s*#') { continue }
                    # Trailing comments go BEFORE any harvesting, so a signature
                    # or a flag that is commented out cannot be counted as
                    # something that runs.
                    $sLine = Remove-PsLineComment -Line $sLogical.Text

                    # `Send-Tx` is `cast send` behind a wrapper, and it must be
                    # harvested as one. When testnet-up.ps1 routed all 17 of its
                    # sends through that helper on 2026-07-30 -- to settle the
                    # nonce after each one against a load-balanced public RPC --
                    # this extractor stopped seeing them: the tree total fell
                    # 43 -> 26 and testnet-up.ps1's own contribution fell 20 -> 3.
                    #
                    # Check A then had nothing left to check in the file, which
                    # is the vacuity the two floors below exist to catch, and
                    # they did catch it. Signature verification for a script that
                    # broadcasts to a public chain is exactly what must not go
                    # quiet, so the extractor follows the wrapper rather than the
                    # floors being lowered to match a blinded extractor.
                    if ($sLine -match 'cast\s+(send|call)' -or $sLine -match '(^|\s)Send-Tx\s') {
                        foreach ($mm in $castSigRe.Matches($sLine)) {
                            $sigArgs = $mm.Groups['args'].Value -replace '\s', ''
                            $sig     = '{0}({1})' -f $mm.Groups['name'].Value, $sigArgs
                            [void]$castSites.Add([pscustomobject]@{ Rel = $sRel; Line = $sNo; Sig = $sig })
                            $castSigSeen[$sig] = $true
                        }
                    }

                    foreach ($mm in $forgeRe.Matches($sLine)) {
                        # Command position, or inside a display-label string?
                        # Decided by a quote-state scan rather than by counting
                        # quote characters -- see Test-PsInsideString for the
                        # false red that parity counting caused on an ordinary
                        # English apostrophe.
                        $target = $mm.Groups['target'].Value
                        if (Test-PsInsideString -Line $sLine -Index $mm.Index) {
                            [void]$forgeLabels.Add([pscustomobject]@{
                                Rel  = $sRel
                                Line = $sNo
                                Leaf = [System.IO.Path]::GetFileName($target)
                            })
                            continue
                        }
                        # THE SPAN OF THIS COMMAND, not the whole line. `--sig`
                        # used to be a substring test on the raw line, so a
                        # trailing comment saying the flag was no longer needed
                        # -- and, in the one-line form, the display label sitting
                        # after the closing brace -- both supplied the flag while
                        # the defect was live. Measured: PASS on both. See
                        # Get-PsCommandSpan.
                        $span = Get-PsCommandSpan -Line $sLine -Start $mm.Index
                        # Resolved against contracts/, which is the working
                        # directory both standup scripts run forge from.
                        $fullPath = Join-Path $ContractsDir $target
                        $exists   = Test-Path -LiteralPath $fullPath
                        $runs     = -1
                        $runSigs  = @()
                        if ($exists) {
                            # Cached because both standup scripts invoke the same
                            # targets, and each miss reads a source file.
                            if (-not $runSigCache.ContainsKey($fullPath)) {
                                $runDecls = New-Object System.Collections.ArrayList
                                foreach ($dm in $runDeclRe.Matches([System.IO.File]::ReadAllText($fullPath))) {
                                    [void]$runDecls.Add(
                                        (ConvertTo-SolCanonicalSig -Name 'run' -Params $dm.Groups['params'].Value))
                                }
                                $runSigCache[$fullPath] = @($runDecls)
                            }
                            $runSigs = @($runSigCache[$fullPath])
                            $runs    = $runSigs.Count
                        }
                        # The flag AND its value, both read from the command span.
                        $sigMatch = $sigFlagRe.Match($span)
                        $sigValue = ''
                        if ($sigMatch.Success) {
                            foreach ($sigGroup in @('dq', 'sq', 'bare')) {
                                if ($sigMatch.Groups[$sigGroup].Success) {
                                    $sigValue = $sigMatch.Groups[$sigGroup].Value
                                    break
                                }
                            }
                        }
                        [void]$forgeSites.Add([pscustomobject]@{
                            Rel      = $sRel
                            Line     = $sNo
                            Target   = $target
                            Leaf     = [System.IO.Path]::GetFileName($target)
                            Exists   = $exists
                            RunCount = $runs
                            RunSigs  = $runSigs
                            HasSig   = [bool]$sigMatch.Success
                            SigValue = $sigValue
                        })
                    }
                }
            }
            Write-Output ("call-sites: {0} cast signature site(s), {1} distinct; {2} forge script invocation(s), {3} display-label echo(es) skipped" -f `
                $castSites.Count, $castSigSeen.Count, $forgeSites.Count, $forgeLabels.Count)

            # VACUITY GUARD 3 -- check A is a LOOP over what the extractor found,
            # and a loop over nothing is green.
            # MUTATION that turns it red: narrow the line filter to `cast send`
            # only, or drop the return-type group from $castSigRe (43 -> 34).
            if ($castSites.Count -lt $ExpectedCastSitesMin) {
                Add-Finding -Check '9' -Text (
                    "extracted only $($castSites.Count) cast call-site(s), expected at least " +
                    "$ExpectedCastSitesMin (43 measured). Check A over a gutted extractor passes " +
                    "by vacuity. Lower -ExpectedCastSitesMin deliberately, in the same commit, if " +
                    "call-sites were genuinely removed.")
            }
            # MUTATION that turns this second arm red while the first stays
            # green: replace the signature key with a constant -- 43 sites, 1
            # distinct spelling.
            if ($castSigSeen.Count -lt $ExpectedCastSigsMin) {
                Add-Finding -Check '9' -Text (
                    "extracted $($castSites.Count) call-site(s) but only $($castSigSeen.Count) " +
                    "DISTINCT signature(s), expected at least $ExpectedCastSigsMin (15 measured). " +
                    "The site floor alone is satisfied by one spelling repeated forty times.")
            }

            # VACUITY GUARD 9 -- PER FILE, because both recorded defects were
            # per-file. Guard 3 is a TREE TOTAL, and a tree total cannot see one
            # caller leave scope: 43 sites clears a floor of 40 even if one of
            # the two standup scripts contributes NOTHING and check A is green
            # over a file it never read. Same argument as $RequiredAuxScripts,
            # one level down.
            # MUTATION that turns it red: drop three of contracts/dev-up.ps1's
            # 23 cast sites -- 40 survive tree-wide, so guard 3's floor is
            # exactly met and only this guard fails. Skipping the whole file
            # fails guard 3 as well.
            $castByFile = @{}
            foreach ($site in $castSites) {
                if (-not $castByFile.ContainsKey($site.Rel)) { $castByFile[$site.Rel] = 0 }
                $castByFile[$site.Rel] = $castByFile[$site.Rel] + 1
            }
            $castFileShort = New-Object System.Collections.ArrayList
            foreach ($castFileRel in $RequiredCastSitesPerFileMin.Keys) {
                $castFileSeen = 0
                if ($castByFile.ContainsKey($castFileRel)) { $castFileSeen = $castByFile[$castFileRel] }
                if ($castFileSeen -lt $RequiredCastSitesPerFileMin[$castFileRel]) {
                    [void]$castFileShort.Add(("{0} contributed {1}, expected at least {2}" -f `
                        $castFileRel, $castFileSeen, $RequiredCastSitesPerFileMin[$castFileRel]))
                }
            }
            if ($castFileShort.Count -gt 0) {
                Add-Finding -Check '9' -Text (
                    "check A's call-sites are not distributed the way they were measured: " +
                    ($castFileShort -join '; ') + ". Measured 2026-07-29: contracts/dev-up.ps1 = " +
                    "23, contracts/testnet-up.ps1 = 20. The tree total of $($castSites.Count) " +
                    "clears the tree-wide floor even when one of the two files that have ACTUALLY " +
                    "SHIPPED A DEFECT contributes nothing at all. Lower a row in " +
                    "-RequiredCastSitesPerFileMin deliberately, in the same commit, if that file " +
                    "genuinely lost call-sites.")
            }

            # VACUITY GUARD 4 -- the same argument for check B's set.
            # MUTATION that turns it red: require a suffix $forgeRe cannot match,
            # or classify every occurrence as a label.
            if ($forgeSites.Count -lt $ExpectedForgeInvokesMin) {
                Add-Finding -Check '9' -Text (
                    "found only $($forgeSites.Count) forge script invocation(s), expected at least " +
                    "$ExpectedForgeInvokesMin (6 measured, plus $($forgeLabels.Count) " +
                    "display-label echo(es) deliberately excluded). Check B iterates this set; " +
                    "empty proves nothing.")
            }

            # VACUITY GUARD 5 -- THE IMPORTANT ONE. $RequiredAmbiguousTarget is
            # the only overloaded deploy script in the tree, so it is the only
            # thing that exercises check B's ambiguous branch. If it leaves
            # scope, check B passes over targets that CANNOT be ambiguous while
            # staying green.
            # MUTATION that turns it red: invoke it through a variable, which
            # $forgeRe cannot see -- 4 invocations survive, so guard 4 stays
            # green and only this fails.
            $ambiguousReached = @($forgeSites | Where-Object { $_.Leaf -eq $RequiredAmbiguousTarget })
            if ($ambiguousReached.Count -eq 0) {
                Add-Finding -Check '9' -Text (
                    "no checked forge script invocation targets $RequiredAmbiguousTarget. It is " +
                    "the ONLY overloaded deploy script in the tree, so with it out of scope check " +
                    "B iterates over targets that cannot be ambiguous and asserts nothing. This is " +
                    "the exact shape the 737cfa4 defect would hide behind.")
            } else {
                # Reaching it is not enough: the branch must still be REACHABLE.
                # MUTATION that turns this arm red on its own: narrow $runDeclRe
                # so the overload stops being counted (2 -> 1).
                $ambiguousStillOverloaded = @($ambiguousReached | Where-Object { $_.RunCount -gt 1 })
                if ($ambiguousStillOverloaded.Count -eq 0) {
                    Add-Finding -Check '9' -Text (
                        "$RequiredAmbiguousTarget is reached by $($ambiguousReached.Count) " +
                        "invocation(s) but no longer declares more than one run(...) -- the " +
                        "run-count reader returned $($ambiguousReached[0].RunCount). Either the " +
                        "overload was removed (retire this pin in that commit and say why) or the " +
                        "reader is broken; until then check B's ambiguous branch is DEAD CODE.")
                }
            }

            # VACUITY GUARD 10 -- PER FILE, PER TARGET, and the hole guard 5
            # leaves open. Guard 5 asks whether ANY checked invocation ANYWHERE
            # reaches the overloaded target. Both standup scripts invoke it, so
            # EITHER ONE satisfies guard 5 for the other, and the file that
            # shipped the defect can leave check B's scope unnoticed. REPRODUCED
            # BY EXECUTION 2026-07-29: replacing dev-up.ps1's invocation with a
            # variable target and no --sig left 5 checked invocations (floor 3,
            # green), guard 5 satisfied by testnet-up.ps1's copy, and STEP 9 PASS
            # -- carrying the 737cfa4 defect in the very file it originally
            # shipped in.
            # MUTATION that turns it red: exactly that rewrite, in either file.
            #
            # CASE-INSENSITIVE on purpose, and it is the exception that proves
            # the rule stated where `$runSigCache` is declared: only the
            # SIGNATURE maps must be ordinal, because Solidity selectors are
            # keccak over the exact string. This key is `<script path>|<target
            # file name>` -- two Windows FILE PATHS, which are case-insensitive
            # on this platform. Guard 9's `$castByFile` already followed that
            # rule; guard 10 was the single place that did not, and the
            # inconsistency was a false red: a lower-cased target filename still
            # runs, still resolves on disk, still reads two run() overloads and
            # still validates its `--sig` -- so every other guard stays green and
            # only this one fires, blaming a variable target that is plainly not
            # there.
            $forgePairsSeen = [System.Collections.Hashtable]::new(0, [StringComparer]::OrdinalIgnoreCase)
            foreach ($site in $forgeSites) {
                $forgePairsSeen[('{0}|{1}' -f $site.Rel, $site.Leaf)] = $true
            }
            $forgePairMissing = @($RequiredForgeCallSites |
                Where-Object { -not $forgePairsSeen.ContainsKey($_) })
            if ($forgePairMissing.Count -gt 0) {
                Add-Finding -Check '9' -Text (
                    "required <script>|<target> forge call-site(s) were not found as CHECKED " +
                    "invocations: " + ($forgePairMissing -join ', ') + ". Every other guard here " +
                    "measures a TREE TOTAL, and a tree total cannot see ONE CALLER drop out of " +
                    "scope -- which is precisely how 737cfa4 repaired contracts/dev-up.ps1 and " +
                    "left contracts/testnet-up.ps1 broken for another session. A variable target " +
                    "is invisible to the extractor and is the shape that reproduces this. If a " +
                    "standup script genuinely stopped deploying that contract, retire its row from " +
                    "-RequiredForgeCallSites in the same commit and say why.")
            }

            # VACUITY GUARD 6 -- what keeps the label exclusion honest. An
            # excluded occurrence must be an ECHO of a target this check actually
            # checked in the same file; otherwise the classifier has removed a
            # real call-site from check B.
            # MUTATION that turns it red: invert the command-position test, which
            # swaps the 6 invocations and the 3 echoes -- 3 invocations survive,
            # so guard 4 and guard 5 both stay green and only this fails.
            $labelOrphans = New-Object System.Collections.ArrayList
            foreach ($lbl in $forgeLabels) {
                $echoed = @($forgeSites | Where-Object { $_.Rel -eq $lbl.Rel -and $_.Leaf -eq $lbl.Leaf })
                if ($echoed.Count -eq 0) {
                    [void]$labelOrphans.Add(("{0}:{1} names {2}" -f $lbl.Rel, $lbl.Line, $lbl.Leaf))
                }
            }
            if ($labelOrphans.Count -gt 0) {
                Add-Finding -Check '9' -Text (
                    "$($labelOrphans.Count) forge script occurrence(s) were classified as display " +
                    "labels, but no CHECKED invocation of the same target exists in the same file " +
                    "-- so the classifier dropped a real call-site rather than a duplicate of one: " +
                    ($labelOrphans -join '; '))
            }

            # ---- CHECK A -- every cast signature exists in the compiled ABIs
            # MUTATION that turns it red: change one signature in
            # contracts/dev-up.ps1 (e.g. setVault(address) ->
            # setVault(address,uint256)), or delete the function from the
            # contract. Measured: withdrawing mint(address,uint256) from the
            # universe names all 4 of its call-sites, in both files.
            foreach ($site in $castSites) {
                if (-not $abiSigs.ContainsKey($site.Sig)) {
                    [void]$abiBad.Add(("{0}:{1} -- cast call-site names {2}, which no compiled contract declares" -f `
                        $site.Rel, $site.Line, $site.Sig))
                }
            }

            # ---- CHECK B -- an ambiguous entry point must carry --sig -------
            foreach ($site in $forgeSites) {
                # A target that cannot be read is not a target that is fine.
                # MUTATION: rename contracts/script/DeployFreeMarket.s.sol.
                if (-not $site.Exists) {
                    [void]$abiBad.Add(("{0}:{1} -- forge script target {2} does not exist under contracts/, so this invocation cannot be checked" -f `
                        $site.Rel, $site.Line, $site.Target))
                    continue
                }
                # No entry point at all, and nothing naming one: forge has
                # nothing to call. The --sig arm matters -- a target invoked with
                # an explicit --sig legitimately needs no run(), and failing that
                # would be a false red.
                # MUTATION: delete `function run()` from DeployFreeMarket.s.sol.
                if ($site.RunCount -eq 0 -and -not $site.HasSig) {
                    [void]$abiBad.Add(("{0}:{1} -- {2} declares no run(...) entry point and this invocation carries no --sig" -f `
                        $site.Rel, $site.Line, $site.Target))
                }
                # THE 737cfa4 DEFECT.
                # MUTATION: delete --sig "run()" from contracts/dev-up.ps1's
                # DeployEpochSettlement invocation. Measured: names both files'
                # sites.
                if ($site.RunCount -gt 1 -and -not $site.HasSig) {
                    [void]$abiBad.Add(("{0}:{1} -- AMBIGUOUS ENTRY POINT: {2} declares {3} run(...) overloads and this invocation carries no --sig, so forge script cannot choose one" -f `
                        $site.Rel, $site.Line, $site.Target, $site.RunCount))
                }
                # THE --sig VALUE, not merely its presence. A flag whose value
                # forge cannot dispatch is the same outage as no flag at all, and
                # a presence test accepts a misspelled entry point as well as a
                # --sig still naming an overload the contract has since renamed.
                # Compared as CANONICAL TYPES, so `run(string memory
                # manifestPath)` in the source and `run(string)` on the command
                # line are recognised as the same entry point, and compared
                # CASE-SENSITIVELY (-cnotcontains) for the reason guard 0 exists.
                #
                # Enforced only where the target declares at least one run(...).
                # With none, an explicit --sig naming a different entry point is
                # a legitimate command -- the arm above already covers
                # no-run/no-sig -- and failing it here would be a false red.
                #
                # RESIDUE, stated rather than papered over: `--sig "run(string)"`
                # against DeployEpochSettlement passes this test and still fails
                # at runtime, because forge then wants a positional argument the
                # line does not supply. Deciding statically which trailing token
                # is a positional and which belongs to a forge flag is not
                # reliable, and an unbelievable red gets a check switched off.
                # MUTATION that turns it red: change contracts/dev-up.ps1's
                # --sig "run()" to a name the target does not declare, or to
                # --sig "run(uint256)".
                if ($site.HasSig -and ($site.RunCount -gt 0)) {
                    $sigCanon = ''
                    $sigParsed = $sigValRe.Match($site.SigValue)
                    if ($sigParsed.Success) {
                        $sigCanon = ConvertTo-SolCanonicalSig -Name $sigParsed.Groups['name'].Value `
                            -Params $sigParsed.Groups['params'].Value
                    }
                    if ($sigCanon.Length -eq 0) {
                        [void]$abiBad.Add(("{0}:{1} -- {2} is invoked with --sig '{3}', which is not a function signature forge can dispatch" -f `
                            $site.Rel, $site.Line, $site.Target, $site.SigValue))
                    } elseif (@($site.RunSigs) -cnotcontains $sigCanon) {
                        [void]$abiBad.Add(("{0}:{1} -- --sig '{2}' resolves to {3}, but {4} declares only: {5}" -f `
                            $site.Rel, $site.Line, $site.SigValue, $sigCanon, $site.Target, (@($site.RunSigs) -join ', ')))
                    }
                }
            }

            foreach ($bad in $abiBad) { Add-Finding -Check '9' -Text $bad }

            $nine = @(Get-CheckFindings -Check '9')
            if ($nine.Count -gt 0) {
                $aux9Status = 'FAIL'
                $aux9Detail = "$($nine.Count) call-site or guard finding(s) -- see the [FAIL] lines above"
            } elseif (-not $scopeOk) {
                $aux9Status = 'FAIL'
                $aux9Detail = 'the swept set failed its own scope guards -- see the scope finding(s) above'
            } else {
                $aux9Status = 'PASS'
                $aux9Detail = (
                    "$($castSites.Count) cast site(s) / $($castSigSeen.Count) signature(s) resolve " +
                    "against $($abiSigs.Count) ordinal ABI signature(s) from $abiWithAbi " +
                    "artifact(s); $($forgeSites.Count) forge script invocation(s) checked, every " +
                    "required <script>|<target> pair present, --sig read from the command span and " +
                    "its value matched against the target's declared run(...) entry points")
            }
        } else {
            $aux9Status = 'COULD-NOT-RUN'
            $aux9Detail = 'the ABI universe could not be built -- see the [FAIL] line(s) above'
        }
    }
}
catch {
    # An unexpected error is a COULD-NOT-RUN, never a pass and never a plain
    # finding: nothing here knows how much of the surface was judged before it
    # threw.
    Add-Blocker -Check 'run' -Text ("unexpected error: {0}`n  at {1}" -f `
        $_, $_.ScriptStackTrace)
}

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
# The `[FAIL] ` prefix is a contract, not decoration: run-full-gate's
# Get-FailureExcerpt matches ^\s*\[FAIL and re-quotes these lines at the bottom
# of a red gate, so a caller gets the findings named without parsing anything.
Write-Output ''
foreach ($b in $script:Blockers) {
    Write-Output ("[FAIL] check {0} COULD NOT RUN -- {1}" -f $b.Check, $b.Text)
}
foreach ($f in $script:Findings) {
    Write-Output ("[FAIL] check {0} -- {1}" -f $f.Check, $f.Text)
}

# Scope failures belong to whichever check was SELECTED: a short, mis-pruned or
# half-enumerated sweep makes both checks vacuous, so neither may report PASS
# over it -- and neither may report SKIPPED either, which would read as "the
# caller did not ask for it" when in fact the caller asked and it could not be
# answered. The FINDING arm (guards 1 and 2) is already handled inside each
# check via $scopeOk; this is the BLOCKER arm, where the walk itself died and
# neither check body ran at all.
$scopeBlocked = (@(Get-CheckBlockers -Check 'scope').Count -gt 0)
if ($scopeBlocked) {
    if (-not $Skip8) {
        $aux8Status = 'COULD-NOT-RUN'
        $aux8Detail = 'the .ps1 sweep could not be completed -- see the [FAIL] line(s) above'
    }
    if (-not $Skip9) {
        $aux9Status = 'COULD-NOT-RUN'
        $aux9Detail = 'the .ps1 sweep could not be completed -- see the [FAIL] line(s) above'
    }
}

if ($aux8Status -eq 'SKIPPED') {
    Write-Output (
        'NOTE: check 8 (aux script integrity) was SKIPPED. It did NOT pass -- nothing about ' +
        'script parse or encoding integrity was verified by this run.')
}
if ($aux9Status -eq 'SKIPPED') {
    Write-Output (
        'NOTE: check 9 (script ABI consistency) was SKIPPED. It did NOT pass -- nothing about ' +
        'call-site ABI consistency was verified by this run.')
}

$exitCode = 0
if ($script:Findings.Count -gt 0) { $exitCode = 1 }
# 2 OUTRANKS 1: a blocked check means no verdict was produced over the whole
# surface, which is a different report from "checked, and here is what is wrong".
if ($script:Blockers.Count -gt 0) { $exitCode = 2 }

Write-Output ''
Write-Output ("GATE-DETAIL check8 {0} {1}" -f $aux8Status, $aux8Detail)
Write-Output ("GATE-DETAIL check9 {0} {1}" -f $aux9Status, $aux9Detail)
Write-Output ("AUX-CHECK SUMMARY: aux script integrity = {0}; script ABI consistency = {1}; findings = {2}; blockers = {3}; exit {4}" -f `
    $aux8Status, $aux9Status, $script:Findings.Count, $script:Blockers.Count, $exitCode)

exit $exitCode
