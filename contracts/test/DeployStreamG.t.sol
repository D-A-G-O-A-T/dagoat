// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {DeployStreamG} from "../script/DeployStreamG.s.sol";
import {GoatRelayGateway} from "../src/GoatRelayGateway.sol";
import {WalletSponsorshipRegistry} from "../src/WalletSponsorshipRegistry.sol";
import {SponsoredBuyDesk} from "../src/SponsoredBuyDesk.sol";
import {FeeTokenRegistry} from "../src/FeeTokenRegistry.sol";

contract DeployStreamGTest is Test {
    /// The digest of the schedule this repo ships,
    /// `tools/goat-attestor/fixtures/stream_g_fee_schedule.json`:
    /// `keccak256(UTF8(RFC8785(payload)))` over that file's `payload` object,
    /// per the "Stream G -- USDT Gas Abstraction and Multi-Wallet Sponsoring"
    /// spec, §8.1 "Quote construction".
    /// Pinned on the Rust side, over the real file, by
    /// `tools/goat-attestor/src/stream_g/quotes.rs`'s
    /// `shipped_placeholder_fee_schedule_is_published_and_serves_no_price`
    /// (which also pins the 1100 canonical bytes it is taken over).
    ///
    /// It replaced `keccak256("stream-g-fee-schedule-g1")`. That was a label,
    /// and no schedule payload hashes to it; `test_writes_only_31337_stream_g_json`
    /// below **rewrites** `contracts/deployments/31337.stream-g.json` from these
    /// params, so whatever sits here is what the committed lab artifact carries
    /// after any `forge test` run. Leaving the old tag here would silently
    /// restore it into that artifact and `goat-attestor` would refuse to start
    /// against the lab deployment.
    bytes32 internal constant SHIPPED_FEE_SCHEDULE_HASH =
        0x2681f70d84c3a644290b622f42fc1fa6977c66da4343213f9967c8204ad91bf2;

    /// The digest of the deployment payload this repo ships,
    /// `tools/goat-attestor/fixtures/stream_g_deployment_payload.json`:
    /// `keccak256(UTF8(RFC8785(payload)))` over that file's `payload` object
    /// with every hex-valued field lowercased, per
    /// the "Stream G -- USDT Gas Abstraction and Multi-Wallet Sponsoring" spec,
    /// §5.1 "FeeTokenRegistry".
    /// Pinned on the Rust side, over the real file, by
    /// `tools/goat-attestor/src/stream_g/deployment_payload.rs`'s
    /// `shipped_deployment_payload_is_published_and_binds_the_manifest`, and on
    /// the JavaScript side by `contracts/test/StreamGManifest.test.mjs`.
    ///
    /// It replaced `keccak256("stream-g-manifest-g1")` =
    /// `0x1b374be1dc6a6416a2467a1e997571b6e91998cd5971dcf6cabb0cb384187f32`.
    /// That was a label over no content at all: every address and every runtime
    /// code hash in the deployment could change and it would not move.
    /// `test_writes_only_31337_stream_g_json` below **rewrites** both
    /// `contracts/deployments/31337.stream-g.json` and
    /// `contracts/deployments/31337.stream-g.payload.json` from these params,
    /// so whatever sits here is what the committed lab artifacts carry after
    /// any `forge test` run. Leaving a stale value here makes `goat-attestor`
    /// refuse to start against the lab deployment with
    /// `DeploymentManifestHashSelfMismatch` -- which is the point, and is how
    /// an operator learns the payload moved.
    bytes32 internal constant SHIPPED_DEPLOYMENT_MANIFEST_HASH =
        0xd888dfcea8b9ad292dab408ae0a81e84752506668d813aff10ea901e44c8a65f;

    DeployStreamG internal deployer;

    function setUp() public {
        deployer = new DeployStreamG();
    }

    /// Params that publish to whatever `DeployStreamG` resolves by default —
    /// `./deployments`, the committed pair. Only ONE test in this contract may
    /// pass `writeManifest = true` here; see `_scratchDeploymentsDir`.
    function _params(bool writeManifest) internal returns (DeployStreamG.Params memory p) {
        return _params(writeManifest, "");
    }

    function _params(bool writeManifest, string memory deploymentsDir)
        internal
        returns (DeployStreamG.Params memory p)
    {
        p = DeployStreamG.Params({
            policySafe: address(this),
            feeSafe: makeAddr("feeSafe"),
            recoverySafe: makeAddr("recoverySafe"),
            deskOwner: address(this),
            quoteSigner: makeAddr("quoteSigner"),
            dailyRootCapGoat: 10_000e18,
            recoveryTimelock: 7 days,
            deploymentManifestHash: SHIPPED_DEPLOYMENT_MANIFEST_HASH,
            feeScheduleHash: SHIPPED_FEE_SCHEDULE_HASH,
            writeManifest: writeManifest,
            deploymentsDir: deploymentsDir
        });
    }

    /// A private output directory for one execution of one test: named after
    /// that test, and after the millisecond and the random draw that make the
    /// name unrepeatable by any other process. See "Why the name is NOT just
    /// the test's name" below — that is what it used to be, and it flaked.
    ///
    /// ## Why any test needs one
    ///
    /// `forge` runs a contract's test functions CONCURRENTLY (29 suites, ~100s
    /// of CPU in ~6.4s of wall clock on this repo). `deploy(_params(true))`
    /// ends in `vm.writeJson`, which TRUNCATES before it writes, and both
    /// artifact tests below then read their document back. While both published
    /// to `./deployments` they raced on BOTH files — `writeManifest` writes the
    /// payload document too — and a reader could catch a file between the
    /// truncate and the write. That is
    /// `vm.parseJsonUint: EOF while parsing a value at line 1 column 0` on a
    /// path whose `vm.exists` assert passed one line earlier, measured at 2
    /// failed `forge test` runs in 3.
    ///
    /// ## Why the split is asymmetric, and must be
    ///
    /// `test_writes_only_31337_stream_g_json` deliberately KEEPS the default
    /// directory: a plain `forge test` regenerating the committed
    /// `contracts/deployments/31337.stream-g{,.payload}.json` is the loop that
    /// makes a contract edit surface as a byte-identity failure in
    /// `tools/goat-attestor/src/stream_g/deployment_payload.rs` rather than as
    /// a stale document, and `writeManifest` publishes both files, so that one
    /// test regenerates the whole pair. Moving every writer to a scratch
    /// directory would have removed the race and the regeneration loop
    /// together. A race needs two writers; leaving exactly one is enough.
    ///
    /// So the invariant this contract keeps is: **at most one test may pass
    /// `writeManifest = true` with an empty `deploymentsDir`.** Any further
    /// artifact test must take a scratch directory from here.
    ///
    /// The directory lives UNDER `./deployments` because `foundry.toml` grants
    /// `read-write` on exactly that path. Widening `fs_permissions` for test
    /// convenience would hand every test in the suite write access to the
    /// source tree, which is a far larger blast radius than the flake being
    /// fixed. Gitignored as `deployments/.streamg-t-*/`, beside the anvil
    /// harness's `deployments/.harness-*/`, which is under `./deployments` for
    /// exactly the same reason.
    ///
    /// ## Why the name is NOT just the test's name, which is what it used to be
    ///
    /// The first version of this function took the FIXED path
    /// `./deployments/.streamg-t-<testName>` and opened with
    /// `try vm.removeDir(dir, true) {} catch {}` before `vm.createDir`, on the
    /// reasoning that a test's own name is unique by construction. It is —
    /// **within one process.** `forge test` is not one process: a developer's
    /// `forge test`, a second terminal's `forge test`, and
    /// `run-full-gate.ps1`'s step 4 are three OS processes that all run this
    /// test against the same absolute path, and the first thing each of them
    /// does to that path is DELETE IT RECURSIVELY.
    ///
    /// The interleave that produces is: process A creates the directory, spends
    /// the next tens of milliseconds inside `deploy()` creating seven
    /// contracts, and reaches `vm.writeJson` — while process B, between its own
    /// `removeDir` and its own `createDir`, has the directory momentarily
    /// deleted. A's write then lands on a path that does not exist:
    ///   `[FAIL: vm.writeJson: failed to open file
    ///    "...\deployments\.streamg-t-payloaddoc\31337.stream-g.json":
    ///    The system cannot find the path specified. (os error 3)]`
    /// Observed in the wild at 1 failed run in 8 full `run-full-gate.ps1`
    /// executions, with 8 of 8 standalone `forge test` runs green. REPRODUCED
    /// ON DEMAND, with that exact error text, by holding one process inside the
    /// deploy window while a second sat between its `removeDir` and its
    /// `createDir` — so this is a measured mechanism, not an inferred one.
    ///
    /// Note what would NOT have been enough: simply dropping the `removeDir`.
    /// Two processes sharing one directory still share the two documents inside
    /// it, and B's `vm.writeJson` truncating a file that A is about to
    /// `vm.readFile` is the original `EOF while parsing a value at line 1
    /// column 0` all over again, one process boundary out. The sharing has to
    /// go, not the delete.
    ///
    /// ## So the name is unique per process AND per instant
    ///
    /// All three components are load-bearing, and which axis each one covers
    /// was MEASURED here rather than assumed:
    ///
    ///  * `vm.unixTime()` + `vm.randomUint(32)` cover the CROSS-PROCESS axis.
    ///    The timestamp is milliseconds — the `gas_drips` collision this repo
    ///    already fixed was one-second granularity, two test processes starting
    ///    inside the same second — and the random draw comes from a seed
    ///    Foundry picks per run, so two concurrent `forge test` processes would
    ///    have to reach this line in the same millisecond AND draw the same
    ///    32-bit value.
    ///  * `testName` covers the IN-PROCESS axis, and it is not decoration.
    ///    Foundry seeds one RNG per run and hands every test function the same
    ///    stream, so two test functions of the same contract executing
    ///    concurrently get the SAME first `randomUint()` — and, being
    ///    concurrent, usually the same millisecond too. A probe built while
    ///    fixing this had two such functions collide on one generated name
    ///    within a single process, and the short one's cleanup deleted the long
    ///    one's directory: `os error 3` again, from the "unique" name. The
    ///    test's own name is the only component that is unique by construction
    ///    inside a process.
    ///
    /// Nothing outside this call can produce the resulting name, so nothing can
    /// delete the directory, truncate its contents, or read them.
    ///
    /// The cost is the one the earlier version's doc objected to: a per-run
    /// name leaves a directory behind when the test fails, instead of reusing
    /// one. That is now the better trade, and mostly it is the point — the
    /// documents of a FAILING run survive for inspection instead of being
    /// deleted by the next run's cleanup. A passing run removes its own
    /// directory on the way out (see the end of the test), and because the name
    /// is unique that removal cannot race anything: no other process will ever
    /// create, read or delete that path.
    function _scratchDeploymentsDir(string memory testName) internal returns (string memory dir) {
        dir = string.concat(
            "./deployments/.streamg-t-", testName, "-", vm.toString(vm.unixTime()), "-", vm.toString(vm.randomUint(32))
        );
        // A name that has never existed cannot be stale, so there is nothing to
        // clear first -- which is the whole point of generating one.
        // `vm.writeJson` will not create the parent directory; this does.
        vm.createDir(dir, true);
    }

    /// Read a document the deploy just published, failing with a message that
    /// names the file and the likely cause rather than a bare parser error.
    ///
    /// `vm.parseJson*` reports an empty file as
    /// `EOF while parsing a value at line 1 column 0`, which names neither the
    /// path nor the reason and reads exactly like a flaky test. A phantom flake
    /// attached to a suite is worse than a red one: it becomes a standing
    /// licence to dismiss the signal the gate exists to produce. Same argument,
    /// and same guard, as `DeployEpochSettlement.t.sol::_readEpochManifest`.
    function _readPublished(string memory path) internal view returns (string memory raw) {
        raw = vm.readFile(path);
        require(
            bytes(raw).length > 0,
            string.concat(
                "stream-g deployment document is EMPTY at ",
                path,
                " -- the deploy did not reach its vm.writeJson, or another writer truncated it. ",
                "Every writing test must own its output directory: see _scratchDeploymentsDir."
            )
        );
    }

    function test_deploy_rejects_chain_id_1() public {
        vm.chainId(1);
        vm.expectRevert(DeployStreamG.ChainNotAllowed.selector);
        deployer.deploy(_params(false));
    }

    function test_base_sepolia_phase_gated_in_g1() public {
        vm.chainId(84532);
        vm.expectRevert(DeployStreamG.BaseSepoliaPhaseGated.selector);
        deployer.deploy(_params(false));
    }

    function test_deploy_succeeds_on_31337() public {
        vm.chainId(31337);
        DeployStreamG.Deployed memory d = deployer.deploy(_params(false));
        assertTrue(d.goatRelayGateway != address(0));
        assertTrue(d.feeTokenRegistry != address(0));
        assertTrue(d.walletSponsorshipRegistry != address(0));
        assertTrue(d.sponsoredBuyDesk != address(0));
        assertEq(d.deploymentManifestHash, SHIPPED_DEPLOYMENT_MANIFEST_HASH);
        assertEq(d.feeScheduleHash, SHIPPED_FEE_SCHEDULE_HASH);
    }

    function test_bind_gateway_once_and_activation_atomic() public {
        vm.chainId(31337);
        DeployStreamG.Deployed memory d = deployer.deploy(_params(false));

        GoatRelayGateway gateway = GoatRelayGateway(d.goatRelayGateway);
        WalletSponsorshipRegistry sidecar = WalletSponsorshipRegistry(d.walletSponsorshipRegistry);
        SponsoredBuyDesk desk = SponsoredBuyDesk(d.sponsoredBuyDesk);
        FeeTokenRegistry feeRegistry = FeeTokenRegistry(d.feeTokenRegistry);

        assertTrue(gateway.activated());
        assertTrue(gateway.paused()); // activated while paused
        assertEq(sidecar.gateway(), address(gateway));
        assertTrue(desk.gatewayBound());
        assertEq(desk.gateway(), address(gateway));
        assertEq(gateway.sponsoredBuyDesk(), address(desk));
        assertEq(feeRegistry.activeManifestHash(), d.deploymentManifestHash);
        assertEq(gateway.feeScheduleHash(), d.feeScheduleHash);

        // One-shot binds cannot be repeated.
        vm.expectRevert(WalletSponsorshipRegistry.GatewayAlreadyBound.selector);
        sidecar.bindGatewayOnce(address(gateway));
        vm.expectRevert(SponsoredBuyDesk.GatewayAlreadyBound.selector);
        desk.bindGatewayOnce(address(gateway));
        vm.expectRevert(GoatRelayGateway.AlreadyActivated.selector);
        gateway.activate();
        vm.expectRevert(GoatRelayGateway.DeskAlreadySet.selector);
        gateway.setSponsoredBuyDesk(address(desk));
    }

    /// THE regeneration loop, and the only test in this contract that publishes
    /// to `./deployments`.
    ///
    /// It rewrites the committed `31337.stream-g.json` AND — because
    /// `writeManifest` writes both documents — the committed
    /// `31337.stream-g.payload.json` beside it, which is how a contract edit
    /// reaches `tools/goat-attestor/fixtures/` as a byte-identity failure
    /// instead of sitting stale. Nothing else may write those paths during a
    /// `forge test` run: see `_scratchDeploymentsDir`.
    function test_writes_only_31337_stream_g_json() public {
        vm.chainId(31337);
        // Ensure clean slate for this assertion.
        try vm.removeFile("./deployments/31337.stream-g.json") {} catch {}
        try vm.removeFile("./deployments/84532.stream-g.json") {} catch {}

        DeployStreamG.Deployed memory d = deployer.deploy(_params(true));
        assertTrue(d.goatRelayGateway != address(0));

        string memory path31337 = "./deployments/31337.stream-g.json";
        string memory path84532 = "./deployments/84532.stream-g.json";
        assertTrue(vm.exists(path31337));
        assertFalse(vm.exists(path84532));

        string memory raw = _readPublished(path31337);
        assertEq(vm.parseJsonUint(raw, ".chainId"), 31337);
        assertEq(vm.parseJsonUint(raw, ".schemaVersion"), 1);
        assertEq(vm.parseJsonAddress(raw, ".goatRelayGateway"), d.goatRelayGateway);
        assertEq(vm.parseJsonAddress(raw, ".feeTokenRegistry"), d.feeTokenRegistry);
        assertEq(vm.parseJsonAddress(raw, ".sponsoredBuyDesk"), d.sponsoredBuyDesk);
    }

    /// The payload document `deploymentManifestHash` is the digest **of**.
    ///
    /// This asserts the two things Solidity is the only place that can prove:
    /// that the four role entries carry the addresses this deploy actually
    /// created, and that each `runtimeCodeHash` is that address's live
    /// `EXTCODEHASH` -- i.e. the same value `deploy()` wrote into
    /// `FeeTokenRegistry.setRoleCommitment`. Nothing here recomputes the
    /// digest: Solidity has no JCS canonicaliser, and a Solidity
    /// reimplementation would be a second canonicaliser to keep in step. The
    /// digest is pinned in Rust
    /// (`deployment_payload.rs::shipped_deployment_payload_is_published_and_binds_the_manifest`)
    /// and in JavaScript (`StreamGManifest.test.mjs`); this test pins the
    /// INPUTS those two hash.
    ///
    /// This test asserts CONTENT, which is the same wherever the document
    /// lands, so it publishes into its own directory rather than into
    /// `./deployments`: it and `test_writes_only_31337_stream_g_json` run
    /// concurrently and used to truncate each other's documents mid-read. The
    /// committed pair is regenerated by that test, not by this one. See
    /// `_scratchDeploymentsDir`.
    function test_writes_deployment_payload_document() public {
        vm.chainId(31337);
        string memory dir = _scratchDeploymentsDir("payloaddoc");

        DeployStreamG.Deployed memory d = deployer.deploy(_params(true, dir));

        string memory path = string.concat(dir, "/31337.stream-g.payload.json");
        assertTrue(vm.exists(path));
        string memory raw = _readPublished(path);

        // Container: approval metadata, outside `payload`.
        assertEq(vm.parseJsonUint(raw, ".schemaVersion"), 1);
        assertEq(vm.parseJsonBytes32(raw, ".deploymentManifestHash"), SHIPPED_DEPLOYMENT_MANIFEST_HASH);

        // Payload: integers are decimal STRINGS, because the canonicaliser on
        // the reading side refuses JSON numbers outright.
        // Schema 2: schema 1 had no `accounts` map, so eight of the twelve
        // manifest addresses were bound by nothing.
        assertEq(vm.parseJsonString(raw, ".payload.schemaVersion"), "2");
        assertEq(vm.parseJsonString(raw, ".payload.chainId"), "31337");

        // The four committed roles, address AND live code hash.
        assertEq(vm.parseJsonAddress(raw, ".payload.contracts.GATEWAY.address"), d.goatRelayGateway);
        assertEq(vm.parseJsonBytes32(raw, ".payload.contracts.GATEWAY.runtimeCodeHash"), d.goatRelayGateway.codehash);
        assertEq(vm.parseJsonAddress(raw, ".payload.contracts.FEE_TOKEN_REGISTRY.address"), d.feeTokenRegistry);
        assertEq(
            vm.parseJsonBytes32(raw, ".payload.contracts.FEE_TOKEN_REGISTRY.runtimeCodeHash"),
            d.feeTokenRegistry.codehash
        );
        assertEq(vm.parseJsonAddress(raw, ".payload.contracts.SPONSORED_BUY_DESK.address"), d.sponsoredBuyDesk);
        assertEq(
            vm.parseJsonBytes32(raw, ".payload.contracts.SPONSORED_BUY_DESK.runtimeCodeHash"),
            d.sponsoredBuyDesk.codehash
        );
        assertEq(
            vm.parseJsonAddress(raw, ".payload.contracts.WALLET_SPONSORSHIP_REGISTRY.address"),
            d.walletSponsorshipRegistry
        );
        assertEq(
            vm.parseJsonBytes32(raw, ".payload.contracts.WALLET_SPONSORSHIP_REGISTRY.runtimeCodeHash"),
            d.walletSponsorshipRegistry.codehash
        );

        // A role's `runtimeCodeHash` must be the value the registry itself
        // commits, or the payload would attest to code the chain never bound.
        FeeTokenRegistry feeRegistry = FeeTokenRegistry(d.feeTokenRegistry);
        (address gwAddr, bytes32 gwCode) = feeRegistry.getRoleCommitment(feeRegistry.ROLE_GATEWAY());
        assertEq(gwAddr, d.goatRelayGateway);
        assertEq(gwCode, vm.parseJsonBytes32(raw, ".payload.contracts.GATEWAY.runtimeCodeHash"));

        // A non-empty code hash: `keccak256("")` would mean the entry describes
        // an account with no code, which no committed role may be.
        assertTrue(d.goatRelayGateway.codehash != keccak256(""));
        assertTrue(d.goatRelayGateway.codehash != bytes32(0));

        // The other eight addresses, address-only. Before schema 2 these were
        // in no digest and in no comparison, and an auditor started the relayer
        // clean four times out of four against an artifact with `quoteSigner`,
        // `goatCoin`, `policySafe` or `enrollmentRegistry` edited by one nibble.
        assertEq(vm.parseJsonAddress(raw, ".payload.accounts.DESK_OWNER"), d.deskOwner);
        assertEq(vm.parseJsonAddress(raw, ".payload.accounts.ENROLLMENT_REGISTRY"), d.enrollmentRegistry);
        assertEq(vm.parseJsonAddress(raw, ".payload.accounts.FEE_SAFE"), d.feeSafe);
        assertEq(vm.parseJsonAddress(raw, ".payload.accounts.FEE_TOKEN"), d.feeToken);
        assertEq(vm.parseJsonAddress(raw, ".payload.accounts.GOAT_COIN"), d.goatCoin);
        assertEq(vm.parseJsonAddress(raw, ".payload.accounts.POLICY_SAFE"), d.policySafe);
        assertEq(vm.parseJsonAddress(raw, ".payload.accounts.QUOTE_SIGNER"), d.quoteSigner);
        assertEq(vm.parseJsonAddress(raw, ".payload.accounts.RECOVERY_SAFE"), d.recoverySafe);

        // Spec `:244`: "addresses are lowercase 0x plus 40 hex digits". This is
        // asserted on the STRING, not on the parsed address, because
        // `parseJsonAddress` is case-insensitive and would pass either way.
        // The reader (`deployment_payload::require_lowercase_hex`) refuses
        // uppercase outright, so a regression to `vm.serializeAddress` here
        // makes the relayer unable to hash its own deployment's document.
        assertEq(
            vm.parseJsonString(raw, ".payload.contracts.GATEWAY.address"),
            vm.toLowercase(vm.toString(d.goatRelayGateway))
        );
        assertEq(vm.parseJsonString(raw, ".payload.accounts.QUOTE_SIGNER"), vm.toLowercase(vm.toString(d.quoteSigner)));

        // The injection routed BOTH documents, not just the one read above.
        // `writeManifest` publishes the flat manifest and the payload together,
        // and a split between the two directories would leave this test's
        // manifest landing on the committed path — i.e. the race back again,
        // silently, with every assertion above still green.
        assertTrue(vm.exists(string.concat(dir, "/31337.stream-g.json")));

        // Reached only when the assertions passed; a failure deliberately
        // leaves the documents on disk to be inspected. The directory is
        // gitignored, and because `_scratchDeploymentsDir` gave it a name no
        // other process can produce, this removal cannot be the delete that
        // some other `forge test` is standing in the middle of.
        vm.removeDir(dir, true);
    }

    // NOTE on what is deliberately NOT tested here: `STREAM_G_DEPLOYMENTS_DIR`.
    //
    // The obvious test — `vm.setEnv(...)`, deploy, assert both documents landed
    // in the override directory — mutates the REAL process environment, and
    // `forge test` executes tests concurrently. The two tests above write the
    // committed `contracts/deployments/` pair, so a leaked override would send
    // their output somewhere else and leave the committed artifacts stale while
    // every suite stayed green. That is the same class of shared-mutable-state
    // defect the override exists to remove, so writing it here would be a net
    // loss.
    //
    // `Params.deploymentsDir` — used by the payload test above — is NOT that
    // variable and is not an alternative spelling of it. It is an argument on
    // the stack of one `deploy()` call, so it cannot be observed by any other
    // test, whereas `vm.setEnv` writes state every concurrent test reads. The
    // env override remains the only way an out-of-process caller
    // (`forge script`, the anvil harness) can redirect the output, and it is
    // untouched: `run()` passes an empty `deploymentsDir`, and
    // `_resolveDeploymentsDir` falls through to `_deploymentsDir()`.
    //
    // The override is proved by execution elsewhere, and harder: EVERY test in
    // `tools/goat-attestor/src/stream_g/anvil_harness.rs` (17 of them) runs a
    // real `forge script --broadcast` with `STREAM_G_DEPLOYMENTS_DIR` pointed at
    // a private temporary directory and reads its manifest back from there. If
    // `_deploymentsDir()` stopped honouring the variable, `deploy_stream_g`
    // would find no file and panic naming it.

    // ------------------------------------------------------------------
    // HOW A DETERMINISM CLAIM ABOUT THIS FILE MUST BE MEASURED
    //
    // NOT with repeated `forge test`. That measurement has already been made
    // and has already been wrong once, in a way worth writing down: a previous
    // repair of the flake below reported "10/10 clean, mutation-proven" on the
    // strength of ten consecutive green standalone `forge test` runs, and an
    // independent re-measurement then got 8 of 8 standalone runs green
    // (248 passed, 6.28-6.81 s wall, 76-121 s CPU) alongside 3 of 8 FAILED
    // full-gate runs. Every failure of this file's tests that has ever been
    // observed occurred inside `tools/goat-attestor/run-full-gate.ps1`, after
    // the live-Anvil hazard suite -- never in an idle standalone run.
    //
    // The reason is mechanical rather than mysterious. The remaining hazards
    // here are filesystem-timing hazards (a delete that lands late, a handle
    // still open), and an idle machine running one `forge test` closes those
    // windows in microseconds. The gate runs `cargo test --lib`, a full
    // `cargo clippy --all-targets`, a real Anvil node and 17 live hazard tests
    // before it ever reaches `forge test`, which leaves the file cache, the
    // on-access scanner and the disk queue in a state a standalone run never
    // produces.
    //
    // So: any future determinism claim about `DeployStreamG.t.sol` must be
    // backed by repeated FULL `run-full-gate.ps1` executions. A standalone
    // `forge test` streak, however long, is not evidence and must not be
    // reported as if it were.
}
