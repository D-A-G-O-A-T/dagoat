// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {GoatCoin} from "../src/GoatCoin.sol";
import {FeeTokenRegistry} from "../src/FeeTokenRegistry.sol";
import {WalletSponsorshipRegistry} from "../src/WalletSponsorshipRegistry.sol";
import {SponsoredBuyDesk} from "../src/SponsoredBuyDesk.sol";
import {GoatRelayGateway} from "../src/GoatRelayGateway.sol";
import {PermitMockUSDT} from "../test/mocks/PermitMockUSDT.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {StreamGEnroll} from "../src/libraries/StreamGEnroll.sol";
import {StreamGSell} from "../src/libraries/StreamGSell.sol";
import {StreamGXfer} from "../src/libraries/StreamGXfer.sol";

/// Stream G Anvil-only deploy helper + script entrypoint.
/// G1 hard-gates Base Sepolia and all non-31337 chains.
/// Writes two documents and no others: `31337.stream-g.json` (the flat address
/// manifest) and `31337.stream-g.payload.json` (the document
/// `deploymentManifestHash` is the digest OF). Both land in `./deployments`
/// unless `STREAM_G_DEPLOYMENTS_DIR` redirects them -- see `_deploymentsDir` --
/// or the caller redirects them for that ONE call through
/// `Params.deploymentsDir`, which the concurrent unit tests use and which
/// `run()` leaves empty.
///
/// ## Library deployment and linking (EIP-170 refactor)
///
/// `GoatRelayGateway` used to be 33,914 runtime bytes -- 9,338 over EIP-170 --
/// and could not be deployed to any limit-enforcing node. Four entrypoint
/// bodies were moved into `public` library functions, which the gateway
/// reaches by `DELEGATECALL` (so `address(this)`, and therefore the EIP-712
/// domain separator and every pinned digest, is preserved). The gateway is now
/// 12,944 bytes. Three libraries carry `public` functions and must therefore be
/// deployed as their own contracts and linked into the gateway's bytecode:
/// `StreamGEnroll`, `StreamGSell`, `StreamGXfer`. (`StreamGCommon`,
/// `StreamGHashes`, `StreamGTransfers` and `StreamGTypes` are `internal`-only:
/// they are inlined, compile to 57-byte stubs, and are neither deployed nor
/// linked.)
///
/// **This script deliberately contains no explicit library-deployment code:
/// `forge` already does it, correctly, and there is no Solidity expression that
/// could do it better.** A library cannot be instantiated with `new`, and
/// hand-rolling `vm.getCode` + raw `create` would still leave the gateway's
/// bytecode unlinked. What forge does instead, verified against a real Anvil
/// with the code-size limit ENFORCED (no `--disable-code-size-limit`):
///
///  * under `forge script --broadcast`, forge sees the unlinked
///    `linkReferences` in the gateway artifact and prepends three `CREATE2`
///    deployments (through the deterministic deployer
///    `0x4e59b44847b379578588920cA78FbF26c0B4956C`) to the broadcast, then
///    links their addresses into the gateway initcode before the `CREATE`. The
///    library addresses are salt-deterministic and do not depend on the
///    deployer;
///  * under `forge test` / a direct `deploy()` call, the in-memory linker does
///    the same thing off-chain, so unit-test semantics are unchanged.
///
/// **Address-shift consequence, and it is real:** those three library
/// transactions consume three of the broadcasting EOA's nonces before any
/// project contract is created, so on a live `--broadcast` every subsequent
/// `CREATE` address shifts by three. Anything holding a Stream G address from a
/// stale copy of `31337.stream-g.json` must re-read the manifest after a fresh
/// deploy. The `forge test` path is unaffected (its deployer is the test
/// contract, whose nonce sequence the linker never touches), which is why the
/// checked-in manifest did not move.
///
/// The library addresses are *not* written to the manifest: nothing on chain or
/// in `tools/goat-attestor` resolves them at runtime -- they are baked into the
/// gateway's deployed bytecode -- so adding them would be a manifest schema
/// change with no consumer. They are logged by `run()` because a block-explorer
/// source verification of the gateway requires them.
contract DeployStreamG is Script {
    error ChainNotAllowed();
    error BaseSepoliaPhaseGated();
    error ZeroAddress();

    /// Set by `run()` only, i.e. only under `forge script`.
    ///
    /// `deploy()` performs the policy-/owner-gated configuration through
    /// `vm.startPrank`, which is correct when a unit test calls `deploy()`
    /// directly (the caller there is the test contract, so without the prank
    /// the gated calls would arrive from *this* script contract and revert).
    /// Under `forge script --broadcast` that same prank is rejected outright
    /// by Foundry —
    ///   `vm.startPrank: cannot `prank` for a broadcasted transaction;`
    ///   `pass the desired `tx.origin` into the `broadcast` cheatcode call`
    /// — which made `run()` unusable against a live node (the deploys land,
    /// then the script aborts at the first prank). It is also unnecessary
    /// there: while a broadcast is active every depth-1 call this contract
    /// makes already originates from the broadcast wallet, and `run()`
    /// defaults `policySafe`/`deskOwner` to `msg.sender`. So the prank is
    /// skipped in broadcast mode and kept everywhere else; unit tests never
    /// set this flag and are unaffected.
    ///
    /// Fail-closed note: if `STREAM_G_POLICY_SAFE`/`STREAM_G_DESK_OWNER` are
    /// overridden to something other than the broadcasting wallet, the gated
    /// calls revert on the contracts' own authorization checks rather than
    /// silently configuring the wrong safe.
    bool internal broadcasting;

    struct Params {
        address policySafe;
        address feeSafe;
        address recoverySafe;
        address deskOwner;
        address quoteSigner;
        uint256 dailyRootCapGoat;
        uint256 recoveryTimelock;
        bytes32 deploymentManifestHash;
        bytes32 feeScheduleHash;
        bool writeManifest;
        /// Per-CALL override of the output directory. Empty means "resolve it
        /// the way `_deploymentsDir()` always has" -- `STREAM_G_DEPLOYMENTS_DIR`
        /// if set, else `./deployments` -- so `run()`, the operator script and
        /// the anvil harness are all unaffected by this field's existence.
        ///
        /// It exists because `forge` executes a contract's test functions
        /// CONCURRENTLY and both artifact tests in `DeployStreamG.t.sol` used to
        /// publish to the one committed pair of paths and then read it back:
        /// `vm.writeJson` truncates before it writes, so one test could read the
        /// other's file mid-write and observe it empty
        /// (`vm.parseJsonUint: EOF while parsing a value at line 1 column 0`,
        /// measured at 2 failures in 3 full `forge test` runs).
        ///
        /// The fix has to be per call and cannot be `vm.setEnv`: that mutates
        /// the REAL process environment, which every concurrently-running test
        /// in the run shares. Overriding the directory that way would relocate
        /// another test's output at random -- the same shared-mutable-state
        /// defect one level up, and a worse one, because a leaked override
        /// would silently stop `forge test` regenerating the committed
        /// artifacts while every suite stayed green. A struct field is
        /// call-local and cannot leak.
        string deploymentsDir;
    }

    struct Deployed {
        address enrollmentRegistry;
        address goatCoin;
        address feeToken;
        address feeTokenRegistry;
        address walletSponsorshipRegistry;
        address sponsoredBuyDesk;
        address goatRelayGateway;
        address policySafe;
        address feeSafe;
        address recoverySafe;
        address deskOwner;
        address quoteSigner;
        bytes32 deploymentManifestHash;
        bytes32 feeScheduleHash;
    }

    /// ## `STREAM_G_FEE_SCHEDULE_HASH` is required and has no default
    ///
    /// It used to read
    /// `vm.envOr("STREAM_G_FEE_SCHEDULE_HASH", keccak256("stream-g-fee-schedule-g1"))`.
    /// That default was safe only while `feeScheduleHash` was an opaque
    /// governance tag. It is now a digest of the schedule's own tariff values --
    /// `keccak256(UTF8(RFC8785(schedulePayload)))`, the rule published verbatim
    /// in the "Stream G -- USDT Gas Abstraction and Multi-Wallet Sponsoring" spec,
    /// section 8.1 "Quote construction",
    /// and implemented by `tools/goat-attestor/src/stream_g/quotes.rs`'s
    /// `FeeSchedule::from_json`. **No schedule payload hashes to
    /// `keccak256("stream-g-fee-schedule-g1")`**, so a deploy that fell through
    /// to the default published a value no file could ever produce: the gateway
    /// would then answer `feeScheduleHash()` with a tag, `goat-attestor` would
    /// refuse to start against it (`StreamGStartupError::FeeScheduleHashMismatch`),
    /// and the failure would surface at service startup rather than at the
    /// deploy that caused it.
    ///
    /// `vm.envBytes32` makes the deploy itself the thing that fails, loudly and
    /// before any contract is created. This matches
    /// `contracts/script/PublishStreamG.s.sol:27`, which has always required the
    /// same variable for the same field.
    ///
    /// ## `STREAM_G_DEPLOYMENT_MANIFEST_HASH` is now required too
    ///
    /// This doc used to end "`deploymentManifestHash` on the line above keeps
    /// its `envOr` default on purpose: it is still a tag, and giving it the
    /// same treatment is a separate change." That change is this one.
    ///
    /// The retired default was `keccak256("stream-g-manifest-g1")` =
    /// `0x1b374be1dc6a6416a2467a1e997571b6e91998cd5971dcf6cabb0cb384187f32`,
    /// and that literal is exactly what both committed copies of the manifest
    /// carried. It hashed **nothing**: every address and every runtime code
    /// hash in the deployment could change and the published value would not
    /// move, so a drifted address was not merely unlikely, it was undetectable
    /// by construction. `deploymentManifestHash` is now
    /// `keccak256(UTF8(RFC8785(payload)))` over the payload document this
    /// script writes beside the manifest -- the rule published verbatim at
    /// in the "Stream G -- USDT Gas Abstraction and Multi-Wallet Sponsoring" spec,
    /// section 5.1 "FeeTokenRegistry",
    /// and implemented by
    /// `tools/goat-attestor/src/stream_g/deployment_payload.rs`.
    ///
    /// The value to publish for the lab deployment this repo ships is pinned by
    /// `contracts/test/DeployStreamG.t.sol`'s `SHIPPED_DEPLOYMENT_MANIFEST_HASH`
    /// and, Rust-side, by
    /// `tools/goat-attestor/src/stream_g/deployment_payload.rs`'s
    /// `shipped_deployment_payload_is_published_and_binds_the_manifest`.
    /// `goat-attestor deployment-manifest-hash --payload-json <file>` prints it.
    ///
    /// ## The ordering the two-pass deploy resolves
    ///
    /// The schedule payload pre-exists its deploy, so hash-then-deploy is a
    /// straight line. This payload does **not**: its content is addresses and
    /// runtime code hashes that do not exist until after the deploy, yet
    /// `setActiveManifestHash` runs during it. The resolution is two passes and
    /// nothing cleverer: run once (the manifest hash published in that pass is
    /// whatever was supplied and is expected to be wrong), read the payload
    /// document this script writes, compute its digest with
    /// `goat-attestor deployment-manifest-hash`, then either re-run with
    /// `STREAM_G_DEPLOYMENT_MANIFEST_HASH` set or -- against an already-live
    /// deployment -- publish it with `PublishStreamG.s.sol`, whose
    /// `FeeTokenRegistry.setActiveManifestHash` is `onlySafe`. Re-pointing a
    /// live gateway is a Policy Safe transaction, not a redeploy, and it is a
    /// DIFFERENT contract and function from the schedule's
    /// `GoatRelayGateway.setFeeScheduleHash`.
    ///
    /// The value to publish for the schedule this repo ships is pinned by
    /// `tools/goat-attestor/src/stream_g/quotes.rs`'s
    /// `shipped_placeholder_fee_schedule_is_published_and_serves_no_price`.
    function run() external returns (Deployed memory d) {
        _assertChainAllowed(block.chainid);
        Params memory p = Params({
            policySafe: vm.envOr("STREAM_G_POLICY_SAFE", msg.sender),
            feeSafe: vm.envOr("STREAM_G_FEE_SAFE", msg.sender),
            recoverySafe: vm.envOr("STREAM_G_RECOVERY_SAFE", msg.sender),
            deskOwner: vm.envOr("STREAM_G_DESK_OWNER", msg.sender),
            quoteSigner: vm.envOr("STREAM_G_QUOTE_SIGNER", msg.sender),
            dailyRootCapGoat: vm.envOr("STREAM_G_DAILY_ROOT_CAP", uint256(10_000e18)),
            recoveryTimelock: vm.envOr("STREAM_G_RECOVERY_TIMELOCK", uint256(7 days)),
            // Both REQUIRED, deliberately with no default -- see `run()`'s doc.
            deploymentManifestHash: vm.envBytes32("STREAM_G_DEPLOYMENT_MANIFEST_HASH"),
            feeScheduleHash: vm.envBytes32("STREAM_G_FEE_SCHEDULE_HASH"),
            writeManifest: true,
            // Empty: the script keeps resolving its output directory from
            // `STREAM_G_DEPLOYMENTS_DIR` / `./deployments`, unchanged.
            deploymentsDir: ""
        });

        uint256 pk = vm.envOr("DEPLOYER_PRIVATE_KEY", uint256(0));
        broadcasting = true;
        if (pk != 0) vm.startBroadcast(pk);
        else vm.startBroadcast();
        d = deploy(p);
        vm.stopBroadcast();
        broadcasting = false;

        console.log("Stream G deployed on", block.chainid);
        console.log("gateway", d.goatRelayGateway);
        // Linked library addresses -- required to verify the gateway's source on
        // a block explorer, and the only place they are surfaced (see the
        // contract-level note: they are not manifest fields).
        console.log("lib StreamGEnroll", address(StreamGEnroll));
        console.log("lib StreamGSell", address(StreamGSell));
        console.log("lib StreamGXfer", address(StreamGXfer));
        console.log("manifest", _manifestPath());
        console.log("manifest payload", _payloadPath());
    }

    /// The directory `writeManifest` and `writeDeploymentPayload` write into.
    ///
    /// ## Why this is an override and not a constant
    ///
    /// `contracts/deployments/31337.stream-g.json` (and, since 2026-07-28, the
    /// payload document beside it) are **committed repository files that this
    /// script rewrites unconditionally**. Three unrelated things ran deploys
    /// against that one pair of paths: `forge test`'s two artifact tests,
    /// `forge script --broadcast` driven by an operator, and
    /// `tools/goat-attestor/src/stream_g/anvil_harness.rs`'s `deploy_stream_g`,
    /// which used to snapshot the bytes, deploy, read the result back and
    /// restore. That save/deploy/read/restore window is shared mutable state
    /// with no lock spanning the processes that touch it, and the failure it
    /// produced was silent: the harness read back the COMMITTED lab manifest
    /// instead of its own fresh deploy, and every hazard test then ran against
    /// lab addresses that do not exist on its node. Two of the seventeen
    /// happened to carry a precondition assert and went red (2 failures in 8
    /// suite runs, on two different tests); the other fifteen would have passed
    /// vacuously.
    ///
    /// With this override the harness points the deploy at a private temporary
    /// directory, so it reads back a file **no other process can write** and
    /// leaves the committed artifacts untouched — there is nothing to save and
    /// nothing to restore. The default keeps `forge test`'s regeneration of the
    /// committed artifacts working exactly as before, which is the loop that
    /// makes a contract edit surface as a byte-identity failure in
    /// `deployment_payload.rs` rather than as a stale document.
    function _deploymentsDir() internal view returns (string memory) {
        return vm.envOr("STREAM_G_DEPLOYMENTS_DIR", string("./deployments"));
    }

    /// `dirOverride` when a caller supplied one, else the process-wide default.
    ///
    /// The override arrives through `Params.deploymentsDir`, i.e. per call and
    /// on the stack — see that field's doc for why an environment variable
    /// could not be used for this.
    function _resolveDeploymentsDir(string memory dirOverride) internal view returns (string memory) {
        if (bytes(dirOverride).length != 0) return dirOverride;
        return _deploymentsDir();
    }

    function _manifestPath(string memory dir) internal pure returns (string memory) {
        return string.concat(dir, "/31337.stream-g.json");
    }

    function _payloadPath(string memory dir) internal pure returns (string memory) {
        return string.concat(dir, "/31337.stream-g.payload.json");
    }

    function _manifestPath() internal view returns (string memory) {
        return _manifestPath(_deploymentsDir());
    }

    function _payloadPath() internal view returns (string memory) {
        return _payloadPath(_deploymentsDir());
    }

    /// Chain-gated deploy used by both script and unit tests.
    /// Policy/owner ops are pranked so tests work when DeployStreamG is a separate contract.
    function deploy(Params memory p) public returns (Deployed memory d) {
        _assertChainAllowed(block.chainid);
        if (
            p.policySafe == address(0) || p.feeSafe == address(0) || p.recoverySafe == address(0)
                || p.deskOwner == address(0) || p.quoteSigner == address(0)
        ) {
            revert ZeroAddress();
        }

        // Anvil harness primitives only; does not touch pilot Deploy*.s.sol artifacts.
        EnrollmentRegistry reg = new EnrollmentRegistry(p.policySafe);
        GoatCoin goat = new GoatCoin("GoatCoin", "GOAT", p.policySafe, reg);
        PermitMockUSDT feeToken = new PermitMockUSDT();

        FeeTokenRegistry feeRegistry = new FeeTokenRegistry(p.policySafe);
        WalletSponsorshipRegistry sidecar = new WalletSponsorshipRegistry(
            address(reg), address(feeRegistry), p.policySafe, p.recoverySafe, p.recoveryTimelock
        );
        SponsoredBuyDesk desk = new SponsoredBuyDesk(
            p.deskOwner, IERC20(address(feeToken)), goat, reg, sidecar, p.feeSafe, p.dailyRootCapGoat
        );
        GoatRelayGateway gateway = new GoatRelayGateway(
            address(reg), address(feeRegistry), address(sidecar), address(goat), p.policySafe, p.feeSafe
        );

        // Policy-gated configuration and binds. See `broadcasting`.
        if (!broadcasting) vm.startPrank(p.policySafe);
        feeRegistry.setRoleCommitment(
            feeRegistry.ROLE_FEE_TOKEN_REGISTRY(), address(feeRegistry), address(feeRegistry).codehash
        );
        feeRegistry.setRoleCommitment(
            feeRegistry.ROLE_WALLET_SPONSORSHIP_REGISTRY(), address(sidecar), address(sidecar).codehash
        );
        feeRegistry.setRoleCommitment(
            feeRegistry.ROLE_SPONSORED_BUY_DESK(), address(desk), address(desk).codehash
        );
        feeRegistry.setRoleCommitment(feeRegistry.ROLE_GATEWAY(), address(gateway), address(gateway).codehash);
        sidecar.bindGatewayOnce(address(gateway));
        feeRegistry.setActiveManifestHash(p.deploymentManifestHash);
        gateway.setFeeScheduleHash(p.feeScheduleHash);
        gateway.setQuoteSigner(p.quoteSigner);
        gateway.setSponsoredBuyDesk(address(desk));
        // Activate while paused remains true (default).
        gateway.activate();
        if (!broadcasting) vm.stopPrank();

        // Desk bind is owner-gated. See `broadcasting`.
        if (!broadcasting) vm.prank(p.deskOwner);
        desk.bindGatewayOnce(address(gateway));

        d = Deployed({
            enrollmentRegistry: address(reg),
            goatCoin: address(goat),
            feeToken: address(feeToken),
            feeTokenRegistry: address(feeRegistry),
            walletSponsorshipRegistry: address(sidecar),
            sponsoredBuyDesk: address(desk),
            goatRelayGateway: address(gateway),
            policySafe: p.policySafe,
            feeSafe: p.feeSafe,
            recoverySafe: p.recoverySafe,
            deskOwner: p.deskOwner,
            quoteSigner: p.quoteSigner,
            deploymentManifestHash: p.deploymentManifestHash,
            feeScheduleHash: p.feeScheduleHash
        });

        if (p.writeManifest) {
            writeManifest(d, _resolveDeploymentsDir(p.deploymentsDir));
        }
    }

    /// Publish to the default directory. Unchanged entrypoint: `run()` reaches
    /// the manifest through `deploy()` with an empty `Params.deploymentsDir`,
    /// which resolves here.
    function writeManifest(Deployed memory d) public {
        writeManifest(d, _deploymentsDir());
    }

    function writeManifest(Deployed memory d, string memory deploymentsDir) public {
        if (block.chainid != 31337) revert ChainNotAllowed();
        string memory k = "streamg";
        vm.serializeUint(k, "schemaVersion", 1);
        vm.serializeUint(k, "chainId", block.chainid);
        vm.serializeString(k, "phase", "G1");
        vm.serializeAddress(k, "enrollmentRegistry", d.enrollmentRegistry);
        vm.serializeAddress(k, "goatCoin", d.goatCoin);
        vm.serializeAddress(k, "feeToken", d.feeToken);
        vm.serializeAddress(k, "feeTokenRegistry", d.feeTokenRegistry);
        vm.serializeAddress(k, "walletSponsorshipRegistry", d.walletSponsorshipRegistry);
        vm.serializeAddress(k, "sponsoredBuyDesk", d.sponsoredBuyDesk);
        vm.serializeAddress(k, "goatRelayGateway", d.goatRelayGateway);
        vm.serializeAddress(k, "policySafe", d.policySafe);
        vm.serializeAddress(k, "feeSafe", d.feeSafe);
        vm.serializeAddress(k, "recoverySafe", d.recoverySafe);
        vm.serializeAddress(k, "deskOwner", d.deskOwner);
        vm.serializeAddress(k, "quoteSigner", d.quoteSigner);
        vm.serializeBytes32(k, "deploymentManifestHash", d.deploymentManifestHash);
        string memory finalJson = vm.serializeBytes32(k, "feeScheduleHash", d.feeScheduleHash);
        vm.writeJson(finalJson, _manifestPath(deploymentsDir));
        // Same directory as the manifest it belongs to, always: the two
        // documents are read as a pair and a split between them would be a
        // deployment described by one file and hashed by another.
        writeDeploymentPayload(d, deploymentsDir);
    }

    /// The operator note embedded in the payload document.
    ///
    /// Deliberately short and fixed: it is written by a machine on every
    /// `forge test` run, so anything that had to be edited by hand would be
    /// silently reverted. The long-form explanation lives in
    /// `tools/goat-attestor/src/stream_g/deployment_payload.rs`.
    string internal constant PAYLOAD_NOTE =
        "MACHINE-WRITTEN by contracts/script/DeployStreamG.s.sol::writeDeploymentPayload on every "
        "forge test run. `deploymentManifestHash` here is DECLARED, not computed: it is whatever "
        "Params carried into this deploy. The computed value is "
        "keccak256(UTF8(RFC8785(payload))) per "
        "the Stream G USDT Gas Abstraction and Multi-Wallet Sponsoring spec, section 5.1 "
        "(FeeTokenRegistry), and "
        "goat-attestor refuses to start when the two disagree "
        "(StreamGStartupError::DeploymentManifestHashSelfMismatch). Approval metadata -- this "
        "note and deploymentManifestHash itself -- is OUTSIDE `payload` per the same section"
        ", so editing the note does not move the digest. `payload.contracts` carries the four "
        "roles FeeTokenRegistry commits on chain (address AND runtimeCodeHash); "
        "`payload.accounts` carries the deployment's other eight addresses, address only. Every "
        "hex value is lowercase per that section, so the bytes hashed are the bytes written. "
        "Recompute "
        "with `goat-attestor deployment-manifest-hash --payload-json <this file>`.";

    /// Write `./deployments/31337.stream-g.payload.json` -- the document
    /// `deploymentManifestHash` is the digest **of**.
    ///
    /// ## Why this file exists
    ///
    /// The spec's normative payload
    /// (the "Stream G -- USDT Gas Abstraction and Multi-Wallet Sponsoring" spec,
    /// section 5.1 "FeeTokenRegistry")
    /// is a five-key, deny-unknown-fields schema -- `schemaVersion`,
    /// `deploymentVersion`, `chainId`, `releaseCommit`, and a role-keyed
    /// `contracts` object whose entries carry `address` and `runtimeCodeHash`.
    /// The shipped `31337.stream-g.json` is a flat 17-key address map with none
    /// of that nesting and no runtime code hash anywhere. Rather than migrate
    /// the flat artifact -- which two independent Rust deserializers, a
    /// JavaScript fixture and every operator runbook read by their existing
    /// field names -- the payload gets its own document, exactly as the fee
    /// schedule already does. The flat artifact keeps all 17 keys and
    /// `deploymentManifestHash` keeps its name, type and position; only its
    /// *derivation* changes.
    ///
    /// ## Two maps, because there are two KINDS of claim
    ///
    /// `payload.contracts` carries `{address, runtimeCodeHash}` for exactly the
    /// four role ids `FeeTokenRegistry` commits on chain
    /// (`ROLE_FEE_TOKEN_REGISTRY`, `ROLE_WALLET_SPONSORSHIP_REGISTRY`,
    /// `ROLE_SPONSORED_BUY_DESK`, `ROLE_GATEWAY` -- `FeeTokenRegistry.sol:13-16`),
    /// written above by `deploy()` from these same `address(x).codehash`
    /// values. Every entry there is a claim `getRoleCommitment` can contradict.
    ///
    /// `payload.accounts` carries the deployment's other eight addresses --
    /// `deskOwner`, `enrollmentRegistry`, `feeSafe`, `feeToken`, `goatCoin`,
    /// `policySafe`, `quoteSigner`, `recoverySafe` -- as ADDRESS ONLY, with no
    /// `runtimeCodeHash`.
    ///
    /// The asymmetry is deliberate and is not laziness. `runtimeCodeHash` is
    /// `EXTCODEHASH`, which for an EOA or Safe is zero before the account exists
    /// and `keccak256("")` after it is funded -- a value that FLIPS over a
    /// chain's lifetime. Claiming one for `policySafe` would make this digest
    /// depend on chain state rather than on the deployment, and every operator
    /// would eventually be unable to start against their own approved payload.
    /// `goatCoin`, `feeToken` and `enrollmentRegistry` do have stable code
    /// hashes, but nothing on chain commits a role id for them, so a
    /// `runtimeCodeHash` there would be a claim nothing could check.
    ///
    /// What the eight DO get is the thing that was missing: their addresses are
    /// inside the hashed payload, so editing one moves `deploymentManifestHash`,
    /// and `StreamGState::start` compares each of them against the flat
    /// artifact's field of the same name. Until 2026-07-28 they were bound by
    /// neither: an auditor edited `quoteSigner`, `goatCoin`, `policySafe` and
    /// `enrollmentRegistry` in the artifact by one nibble each and the relayer
    /// started clean four times out of four, with no warning.
    ///
    /// ## Address casing
    ///
    /// The spec is normative at `:244` -- "addresses are lowercase 0x plus 40
    /// hex digits". This function therefore writes
    /// `vm.toLowercase(vm.toString(addr))` rather than `vm.serializeAddress`,
    /// which emits EIP-55 mixed case.
    ///
    /// The earlier version of this file did use `vm.serializeAddress` and the
    /// reader lowercased before hashing, justified here and in
    /// `deployment_payload.rs` on the grounds that "the only tool that can write
    /// the document writes one no tool in this repository can hash". That
    /// justification was **false**: `vm.toLowercase` is right there in the
    /// vendored `lib/forge-std/src/Vm.sol:1351`. The consequence of the
    /// deviation was real -- the canonical bytes were a PROJECTION of the file
    /// rather than a slice of it, so an operator diffing the document against
    /// the bytes `goat-attestor deployment-manifest-hash` prints saw different
    /// text, which is exactly the hazard the spec's lowercase rule removes. The
    /// reader now REFUSES mixed case, the way the fee schedule's `feeToken`
    /// rule always has.
    ///
    /// ## `deploymentVersion` and `releaseCommit`
    ///
    /// Neither exists anywhere else in this repository, and `releaseCommit`
    /// cannot be self-referential: this document is copied byte-for-byte into
    /// `tools/goat-attestor/fixtures/`, which is compiled into the binary, so
    /// it cannot contain the hash of the commit that contains it. Both are
    /// therefore `vm.envOr` with lab defaults -- `"1"` and forty zeros, the
    /// documented sentinel for "this deployment is not pinned to a release
    /// commit". A real deployment sets `STREAM_G_RELEASE_COMMIT` to the parent
    /// commit sha, and doing so moves the digest, which is correct.
    /// An address spelled the one way the payload schema admits: lowercase
    /// `0x` + 40 hex. See the "Address casing" section on
    /// `writeDeploymentPayload`.
    function _lc(address a) internal pure returns (string memory) {
        return vm.toLowercase(vm.toString(a));
    }

    function writeDeploymentPayload(Deployed memory d) public {
        writeDeploymentPayload(d, _deploymentsDir());
    }

    function writeDeploymentPayload(Deployed memory d, string memory deploymentsDir) public {
        if (block.chainid != 31337) revert ChainNotAllowed();

        string memory ftr = "role_fee_token_registry";
        vm.serializeString(ftr, "address", _lc(d.feeTokenRegistry));
        string memory ftrJson = vm.serializeBytes32(ftr, "runtimeCodeHash", d.feeTokenRegistry.codehash);

        string memory gw = "role_gateway";
        vm.serializeString(gw, "address", _lc(d.goatRelayGateway));
        string memory gwJson = vm.serializeBytes32(gw, "runtimeCodeHash", d.goatRelayGateway.codehash);

        string memory desk = "role_sponsored_buy_desk";
        vm.serializeString(desk, "address", _lc(d.sponsoredBuyDesk));
        string memory deskJson = vm.serializeBytes32(desk, "runtimeCodeHash", d.sponsoredBuyDesk.codehash);

        string memory wsr = "role_wallet_sponsorship_registry";
        vm.serializeString(wsr, "address", _lc(d.walletSponsorshipRegistry));
        string memory wsrJson =
            vm.serializeBytes32(wsr, "runtimeCodeHash", d.walletSponsorshipRegistry.codehash);

        // Role keys are the four `FeeTokenRegistry.ROLE_*` preimages verbatim.
        // They are `[A-Za-z0-9_]` by construction, which is what makes them
        // hashable at all: `canonical_json::is_portable_key` refuses anything
        // else, because RFC 8785 orders keys by UTF-16 code unit while
        // serde_json orders by UTF-8 byte and the two agree only within ASCII.
        string memory c = "payload_contracts";
        vm.serializeString(c, "FEE_TOKEN_REGISTRY", ftrJson);
        vm.serializeString(c, "GATEWAY", gwJson);
        vm.serializeString(c, "SPONSORED_BUY_DESK", deskJson);
        string memory contractsJson = vm.serializeString(c, "WALLET_SPONSORSHIP_REGISTRY", wsrJson);

        // The other eight manifest addresses, address only. Key names are the
        // SCREAMING_SNAKE_CASE spelling of the flat artifact's camelCase field
        // of the same meaning, so the pairing `StreamGState::start` checks is
        // readable off the two documents side by side.
        string memory acc = "payload_accounts";
        vm.serializeString(acc, "DESK_OWNER", _lc(d.deskOwner));
        vm.serializeString(acc, "ENROLLMENT_REGISTRY", _lc(d.enrollmentRegistry));
        vm.serializeString(acc, "FEE_SAFE", _lc(d.feeSafe));
        vm.serializeString(acc, "FEE_TOKEN", _lc(d.feeToken));
        vm.serializeString(acc, "GOAT_COIN", _lc(d.goatCoin));
        vm.serializeString(acc, "POLICY_SAFE", _lc(d.policySafe));
        vm.serializeString(acc, "QUOTE_SIGNER", _lc(d.quoteSigner));
        string memory accountsJson = vm.serializeString(acc, "RECOVERY_SAFE", _lc(d.recoverySafe));

        // Every integer is a decimal STRING, per spec `:244` ("chainId and all
        // integers are decimal strings"). `canonical_json::validate` refuses a
        // JSON number outright, so a `vm.serializeUint` here would produce a
        // payload no reader in this repository could hash.
        //
        // `payload.schemaVersion` is "2", not "1": schema 1 had no `accounts`
        // map, so a schema-1 document read by a build that requires the eight
        // account binds would be a payload silently missing two thirds of the
        // deployment. The reader refuses any version but its own.
        string memory p = "payload_body";
        vm.serializeString(p, "schemaVersion", "2");
        vm.serializeString(p, "deploymentVersion", vm.envOr("STREAM_G_DEPLOYMENT_VERSION", string("1")));
        vm.serializeString(p, "chainId", vm.toString(block.chainid));
        vm.serializeString(
            p,
            "releaseCommit",
            vm.toLowercase(
                vm.envOr("STREAM_G_RELEASE_COMMIT", string("0000000000000000000000000000000000000000"))
            )
        );
        vm.serializeString(p, "accounts", accountsJson);
        string memory payloadJson = vm.serializeString(p, "contracts", contractsJson);

        // The container. `schemaVersion` here IS a JSON number: it is approval
        // metadata outside `payload` and is never canonicalised, exactly like
        // the fee schedule container's own numeric `schemaVersion`.
        string memory root = "payload_document";
        vm.serializeUint(root, "schemaVersion", 1);
        vm.serializeBytes32(root, "deploymentManifestHash", d.deploymentManifestHash);
        vm.serializeString(root, "note", PAYLOAD_NOTE);
        string memory finalJson = vm.serializeString(root, "payload", payloadJson);
        vm.writeJson(finalJson, _payloadPath(deploymentsDir));
    }

    function _assertChainAllowed(uint256 chainId) internal pure {
        if (chainId == 84532) revert BaseSepoliaPhaseGated();
        if (chainId != 31337) revert ChainNotAllowed();
    }
}
