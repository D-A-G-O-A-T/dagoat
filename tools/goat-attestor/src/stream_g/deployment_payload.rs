//! `deploymentManifestHash`, bound to the CONTENT of the deployment.
//!
//! # The rule
//!
//! the "Stream G — USDT Gas Abstraction and Multi-Wallet Sponsoring" spec,
//! §5.1 "FeeTokenRegistry":
//!
//! > "It also records the active deployment-manifest payload hash approved by
//! > the Policy Safe. Canonicalization is RFC 8785 JSON Canonicalization Scheme
//! > over UTF-8 with a versioned, deny-unknown-fields schema. The payload
//! > contains schemaVersion, deploymentVersion, chainId, releaseCommit, and a
//! > role-keyed contracts object whose entries contain address and
//! > runtimeCodeHash […] Approval metadata is outside the payload."
//! >
//! > `manifestHash = keccak256(UTF8(RFC8785(payload)))`
//!
//! (That formula is INLINE CODE, not an indented block, and the difference is
//! not cosmetic. Five spaces after the `>` made it a Markdown indented code
//! block, which rustdoc compiles as a Rust doctest -- so a quoted spec formula
//! became the crate's only doctest and failed to compile with five `cannot find
//! value` errors. It was invisible to the local gate, which runs
//! `cargo test --lib`, and surfaced on the first CI run to reach `cargo test`.
//! Keep quoted formulae inline.)
//!
//! This is the ORIGINAL of the rule `feeScheduleHash` inherits: `:808` says the
//! schedule payload "uses the same RFC 8785/UTF-8 rules as the deployment
//! manifest", 562 lines later. The canonicaliser is
//! [`crate::canonical_json`] and there is deliberately no second one.
//!
//! # What this replaced, and why it mattered
//!
//! Until this module existed, `deploymentManifestHash` was a **literal tag**.
//! `contracts/script/DeployStreamG.s.sol` set it from
//! `vm.envOr("STREAM_G_DEPLOYMENT_MANIFEST_HASH", keccak256("stream-g-manifest-g1"))`,
//! and both committed copies of the manifest carried exactly that default,
//! `0x1b374be1dc6a6416a2467a1e997571b6e91998cd5971dcf6cabb0cb384187f32`. Every
//! address and every runtime code hash in the deployment could change and the
//! published value would not move. A drifted address was not "unlikely" — it
//! was **undetectable by construction**, in a value that is a field of every
//! EIP-712 action core, every intent, and `FeeQuote`.
//!
//! # Why a separate document rather than a migrated artifact
//!
//! The spec's payload is a five-key nested schema; the shipped
//! `contracts/deployments/31337.stream-g.json` is a flat 17-key address map
//! with no `contracts` object, no `deploymentVersion`, no `releaseCommit` and
//! no `runtimeCodeHash` anywhere. Migrating that artifact would break two
//! independent Rust deserializers ([`super::token_manifest::DeploymentManifest`]
//! and `super::anvil_harness::StreamGDeployment`, both of which require every
//! field they declare), a JavaScript fixture, and every operator runbook that
//! names those keys. So the payload gets its own document —
//! `{schemaVersion, deploymentManifestHash, note, payload}` — exactly the
//! container the fee schedule already uses
//! (`fixtures/stream_g_fee_schedule.json`). The flat artifact keeps all 17 keys
//! and `deploymentManifestHash` keeps its name, type and position; only its
//! **derivation** changes. Nothing that reads the artifact had to change.
//!
//! # Where enforcement lives, and where it cannot
//!
//! [`super::runtime::StreamGState::start`] performs four refusals, all of them
//! **offline and pure** — it builds no RPC client until after this whole block,
//! and under `GOAT_ATTESTOR_MOCK=1` it builds none at all:
//!
//! 0. the payload came from the BUILT-IN lab copy while the manifest did not ⇒
//!    `DeploymentPayloadNotConfigured`
//! 1. computed ≠ declared ⇒ `DeploymentManifestHashSelfMismatch`
//! 2. `payload.chainId` ≠ `manifest.chain_id` ⇒ `DeploymentManifestChainMismatch`
//! 3. computed ≠ `manifest.deployment_manifest_hash` ⇒ `DeploymentManifestHashMismatch`
//! 4. `payload.contracts[ROLE].address` / `payload.accounts[ROLE]` ≠ the
//!    manifest's flat address for that role ⇒ `DeploymentManifestAddressMismatch`
//!    — for all **twelve** addresses.
//!
//! (4) is the one that closes the stated hazard from the artifact side: a
//! digest binds a payload to ITSELF, so without it, editing `goatRelayGateway`
//! in the flat artifact would still start cleanly. (1) closes it from the
//! payload side, because editing an address or a code hash inside `payload`
//! moves the digest.
//!
//! The declared-vs-**live-chain** comparison is structurally impossible at
//! startup and already exists per-action: `super::preflight`'s
//! `Check::ManifestHashMismatch` forces four-way agreement between the
//! gateway's live `activeManifestHash()` at a pinned block, the nonce
//! snapshot, the intent and the quote.
//!
//! # Two maps, because there are two kinds of claim
//!
//! `payload.contracts` carries `{address, runtimeCodeHash}` for the four roles
//! `FeeTokenRegistry` commits on chain (`FeeTokenRegistry.sol:13-16`). Each is a
//! claim `getRoleCommitment` can contradict.
//!
//! `payload.accounts` carries the deployment's other eight addresses —
//! [`CANONICAL_ACCOUNTS`] — with **no** `runtimeCodeHash`. `runtimeCodeHash` is
//! `EXTCODEHASH`, which for `policySafe`, `feeSafe`, `recoverySafe`, `deskOwner`
//! and `quoteSigner` is zero before the account exists and `keccak256("")` after
//! it is funded: a value that flips over a chain's lifetime, so claiming one
//! would make this digest depend on chain state rather than on the deployment.
//! `goatCoin`, `feeToken` and `enrollmentRegistry` have stable code hashes but
//! no on-chain role commitment, so a `runtimeCodeHash` there would be a claim
//! nothing could contradict.
//!
//! Until 2026-07-28 those eight were in neither map, and the consequence was
//! measured rather than theorised: with `quoteSigner`, `goatCoin`, `policySafe`
//! or `enrollmentRegistry` edited by one nibble in the flat artifact, this
//! binary started clean — four silent starts out of four. Their addresses are
//! now inside the hashed payload (so an edit there moves the digest) and are
//! compared field-for-field against the artifact by refusal (4) (so an edit
//! there is refused). Twelve of twelve.
//!
//! # What is NOT covered, stated plainly
//!
//! * **The eight `accounts` addresses carry no code-hash commitment**, for the
//!   reason above. A Safe replaced by a different Safe *at the same address* is
//!   outside what any digest can see; only the four `contracts` roles bind code.
//! * **It is not a signature.** Nothing here proves who authored the payload.
//!   The on-chain `activeManifestHash()` is what proves which payload the
//!   deployment approved.
//! * The `note` and the declared hash are outside `payload`, so editing them
//!   does not move the digest — the spec's "Approval metadata is outside the
//!   payload", which is what keeps the digest free of self-reference.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

/// The container `schemaVersion` this build reads. A JSON **number**, because
/// it is approval metadata outside `payload` and is never canonicalised.
pub const DEPLOYMENT_PAYLOAD_SCHEMA_VERSION: u64 = 1;

/// The `payload.schemaVersion` this build reads. A decimal **string**: the
/// payload is canonicalised, and [`crate::canonical_json`] refuses JSON numbers
/// outright.
///
/// **"2" since 2026-07-28.** Schema 1 carried only `contracts` — the four roles
/// `FeeTokenRegistry` commits on chain — which left eight of the manifest's
/// twelve addresses bound by nothing: an auditor edited `quoteSigner`,
/// `goatCoin`, `policySafe` and `enrollmentRegistry` in the flat artifact by one
/// nibble each and this binary started clean four times out of four, no warning.
/// Schema 2 adds [`PayloadBody::accounts`]. A schema-1 document read by this
/// build is refused rather than accepted-with-eight-holes.
pub const PAYLOAD_SCHEMA_VERSION: &str = "2";

/// The role keys `payload.contracts` must carry — no more, no fewer.
///
/// These are the four `FeeTokenRegistry.ROLE_*` preimages verbatim
/// (`contracts/src/FeeTokenRegistry.sol:13-16`), so each entry maps 1:1 onto an
/// on-chain `RoleCommitment {addr, runtimeCodeHash}` that
/// `DeployStreamG.deploy` writes from the same `address(x).codehash`. They are
/// `[A-Za-z0-9_]` by construction, which is what makes them hashable at all:
/// `canonical_json::is_portable_key` refuses anything else.
///
/// Listed in the order the canonical bytes will carry them (ASCII byte order),
/// so a reader comparing this constant to a canonical string is not sorting in
/// their head.
pub const CANONICAL_ROLES: [&str; 4] = [
    "FEE_TOKEN_REGISTRY",
    "GATEWAY",
    "SPONSORED_BUY_DESK",
    "WALLET_SPONSORSHIP_REGISTRY",
];

/// The role keys `payload.accounts` must carry — no more, no fewer.
///
/// These are the manifest's other EIGHT addresses, spelled SCREAMING_SNAKE_CASE
/// so each maps by eye onto the flat artifact's camelCase field of the same
/// meaning (`DESK_OWNER` ↔ `deskOwner`, and so on). They carry an **address
/// only**, deliberately: see the module docs' "Two maps, because there are two
/// kinds of claim".
///
/// Listed in the order the canonical bytes will carry them (ASCII byte order);
/// note `FEE_SAFE` precedes `FEE_TOKEN` because `'S'` (0x53) < `'T'` (0x54).
pub const CANONICAL_ACCOUNTS: [&str; 8] = [
    "DESK_OWNER",
    "ENROLLMENT_REGISTRY",
    "FEE_SAFE",
    "FEE_TOKEN",
    "GOAT_COIN",
    "POLICY_SAFE",
    "QUOTE_SIGNER",
    "RECOVERY_SAFE",
];

/// `keccak256("")` — the `EXTCODEHASH` of an account that exists and has no
/// code.
///
/// A committed role must have code, so this value in a `runtimeCodeHash` means
/// the payload is describing an EOA (or a contract that has since
/// self-destructed) as a committed role, and is refused. Cross-checked against
/// `contracts/test/keccak256.mjs` over the empty string.
const EMPTY_CODE_HASH: [u8; 32] = [
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
];

/// The 31337 lab deployment payload, compiled into the binary.
///
/// Same rule as [`super::token_manifest::BUILTIN_DEPLOYMENT_MANIFEST_JSON`]:
/// `include_str!` cannot reach the sibling `contracts/` tree, so this is a
/// hand-synced copy and
/// [`tests::builtin_payload_is_byte_identical_to_the_committed_deployment_artifact`]
/// pins it byte-for-byte against
/// `contracts/deployments/31337.stream-g.payload.json`, which
/// `DeployStreamG.writeDeploymentPayload` rewrites on every `forge test` run.
/// A redeploy that moves an address — or a contract edit that moves a runtime
/// code hash — fails that test instead of leaving a stale built-in behind.
pub const BUILTIN_DEPLOYMENT_PAYLOAD_JSON: &str =
    include_str!("../../fixtures/stream_g_deployment_payload.json");

/// Refusals. Every variant means "this document cannot be trusted to say what
/// the deployment is", never "the process may continue and find out later".
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DeploymentPayloadError {
    #[error("read deployment payload {path}: {detail}")]
    Io { path: String, detail: String },

    #[error("deployment payload {path}: {detail}")]
    Parse { path: String, detail: String },
}

/// One `payload.contracts` entry, decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleCommitment {
    /// The 20 address bytes. Decoded rather than kept as text so a comparison
    /// against [`super::token_manifest::DeploymentManifest`]'s `[u8; 20]`
    /// fields cannot report a mismatch for one address spelled two legal ways.
    pub address: [u8; 20],
    /// `EXTCODEHASH` of that address at deploy time — the same value
    /// `FeeTokenRegistry.setRoleCommitment` received.
    pub runtime_code_hash: [u8; 32],
}

/// A loaded, validated deployment payload document.
#[derive(Debug, Clone)]
pub struct DeploymentPayload {
    declared_deployment_manifest_hash: [u8; 32],
    computed_deployment_manifest_hash: [u8; 32],
    payload_chain_id: u128,
    roles: BTreeMap<String, RoleCommitment>,
    accounts: BTreeMap<String, [u8; 20]>,
    #[allow(dead_code)]
    note: Option<String>,
}

// ---------------------------------------------------------------------------
// Wire schema. `deny_unknown_fields` at BOTH levels, per the spec's "versioned,
// deny-unknown-fields schema". Every declared field is required: a missing key
// is a parse error, never a silently-defaulted value.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeploymentPayloadFile {
    schema_version: u64,
    deployment_manifest_hash: String,
    /// Operator prose. Optional, outside `payload`, and hashed by nothing.
    #[serde(default)]
    note: Option<String>,
    payload: PayloadBody,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PayloadBody {
    schema_version: String,
    deployment_version: String,
    chain_id: String,
    release_commit: String,
    contracts: BTreeMap<String, RoleEntry>,
    /// The other eight manifest addresses, address only — see the module docs.
    /// Required, not `#[serde(default)]`: an omitted map would be a payload
    /// that silently commits to a third of the deployment.
    accounts: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RoleEntry {
    address: String,
    runtime_code_hash: String,
}

impl DeploymentPayload {
    /// Read and parse the document at `path`.
    ///
    /// A four-line wrapper around [`DeploymentPayload::from_json`], which is
    /// where every rule lives — same split, and for the same reason, as
    /// `quotes::FeeSchedule::load`: `runtime::StreamGState::start` resolves the
    /// document through `runtime::read_startup_document` (which may answer with
    /// [`BUILTIN_DEPLOYMENT_PAYLOAD_JSON`] rather than a file, so there is no
    /// path to hand this function) and calls `from_json` on the bytes.
    pub fn load(path: &std::path::Path) -> Result<Self, DeploymentPayloadError> {
        let raw = std::fs::read_to_string(path).map_err(|e| DeploymentPayloadError::Io {
            path: path.display().to_string(),
            detail: e.to_string(),
        })?;
        Self::from_json(&raw, &path.display().to_string())
    }

    /// Parse and validate a deployment payload document, computing
    /// `keccak256(UTF8(RFC8785(normalised payload)))`.
    ///
    /// `source` is only ever a label for error messages — a path for a real
    /// file, a `<built-in …>` string for the embedded copy. Nothing here opens
    /// it.
    ///
    /// # What is refused, and why each rule exists
    ///
    /// * a container `schemaVersion` other than
    ///   [`DEPLOYMENT_PAYLOAD_SCHEMA_VERSION`], or a `payload.schemaVersion`
    ///   other than [`PAYLOAD_SCHEMA_VERSION`];
    /// * any unknown field at either level (`deny_unknown_fields`);
    /// * a `contracts` map that is not exactly [`CANONICAL_ROLES`] — a
    ///   misspelled role would otherwise become an unexplained digest
    ///   disagreement with nothing pointing at the typo;
    /// * a `deploymentVersion` or `chainId` that is not a canonical decimal
    ///   string (`"07"` and `"7"` mean one number and hash differently, so only
    ///   the shortest spelling may be published);
    /// * a `releaseCommit` that is not exactly 40 hex digits with no `0x`;
    /// * an `address` that is not `0x` + 40 hex, or a `runtimeCodeHash` that is
    ///   not `0x` + 64 hex;
    /// * a `runtimeCodeHash` of zero or of [`EMPTY_CODE_HASH`] — a committed
    ///   role that has no code is a payload describing an EOA as a contract.
    ///
    /// * any hex value inside `payload` spelled with an uppercase digit — see
    ///   [`require_lowercase_hex`], which runs before the digest is taken.
    ///
    /// # What is NOT compared here
    ///
    /// Neither hash comparison. This function sees one document, and a payload
    /// that fails a comparison is a *deployment* condition rather than a parse
    /// error. `runtime::StreamGState::start` owns all four refusals — see this
    /// module's docs.
    pub fn from_json(raw: &str, source: &str) -> Result<Self, DeploymentPayloadError> {
        let parse_err = |detail: String| DeploymentPayloadError::Parse {
            path: source.to_string(),
            detail,
        };

        // Parsed as a `Value` first, for the same two reasons the fee schedule
        // does it: the digest must be taken over the payload as WRITTEN (after
        // the one documented normalisation) rather than over a re-serialised
        // Rust struct, and `CanonicalJsonError` carries a JSONPath breadcrumb
        // that `serde_json::from_value` cannot ("invalid type: integer `1`,
        // expected a string" names no field).
        let doc: Value = serde_json::from_str(raw).map_err(|e| parse_err(e.to_string()))?;

        // The schema version is probed from the `Value` BEFORE the typed parse,
        // and that ordering is load-bearing rather than tidy. `accounts` is a
        // required field of schema 2 and did not exist in schema 1, so a
        // schema-1 document handed to the typed parse first reports
        // "missing field `accounts`" — true, and useless: it names a symptom of
        // the version gap rather than the gap. Probing here makes the message
        // the one an operator can act on.
        if let Some(declared) = doc.pointer("/payload/schemaVersion") {
            let ok = declared.as_str() == Some(PAYLOAD_SCHEMA_VERSION);
            if !ok {
                return Err(parse_err(format!(
                    "payload.schemaVersion {declared} is not the deployment payload schema this \
                     build reads ({PAYLOAD_SCHEMA_VERSION:?}). Schema 1 had no `accounts` map, so \
                     eight of the deployment's twelve addresses were bound by nothing; re-run \
                     DeployStreamG to write a schema-2 payload and republish its digest"
                )));
            }
        }

        let computed = match doc.get("payload") {
            Some(payload_value) => {
                require_lowercase_hex(payload_value).map_err(parse_err)?;
                Some(crate::canonical_hash(payload_value).map_err(|e| {
                    parse_err(format!(
                        "payload cannot be canonicalised, so no deploymentManifestHash can be \
                         computed for it: {e}"
                    ))
                })?)
            }
            None => None,
        };

        let file: DeploymentPayloadFile =
            serde_json::from_value(doc).map_err(|e| parse_err(e.to_string()))?;
        let computed_deployment_manifest_hash = computed.ok_or_else(|| {
            parse_err("payload is absent after a successful typed parse".to_string())
        })?;

        if file.schema_version != DEPLOYMENT_PAYLOAD_SCHEMA_VERSION {
            return Err(parse_err(format!(
                "unsupported schemaVersion {} (this build reads \
                 {DEPLOYMENT_PAYLOAD_SCHEMA_VERSION})",
                file.schema_version
            )));
        }
        let p = &file.payload;
        if p.schema_version != PAYLOAD_SCHEMA_VERSION {
            return Err(parse_err(format!(
                "payload.schemaVersion {:?} is not the deployment payload schema this build \
                 reads ({PAYLOAD_SCHEMA_VERSION:?})",
                p.schema_version
            )));
        }

        canonical_decimal("payload.deploymentVersion", &p.deployment_version)
            .map_err(parse_err)?;
        let payload_chain_id =
            canonical_decimal("payload.chainId", &p.chain_id).map_err(parse_err)?;
        release_commit("payload.releaseCommit", &p.release_commit).map_err(parse_err)?;

        require_exact_key_set("payload.contracts", &CANONICAL_ROLES, &p.contracts)
            .map_err(parse_err)?;
        require_exact_key_set("payload.accounts", &CANONICAL_ACCOUNTS, &p.accounts)
            .map_err(parse_err)?;

        let mut accounts = BTreeMap::new();
        for role in CANONICAL_ACCOUNTS {
            let spelled = match p.accounts.get(role) {
                Some(v) => v,
                None => continue,
            };
            let address =
                hex_bytes::<20>(&format!("payload.accounts.{role}"), spelled, true)
                    .map_err(parse_err)?;
            accounts.insert(role.to_string(), address);
        }

        let mut roles = BTreeMap::new();
        for role in CANONICAL_ROLES {
            // `require_exact_key_set` proves the key is present; written as a
            // lookup rather than indexing so a future edit cannot turn a
            // missing key into a panic.
            let entry = match p.contracts.get(role) {
                Some(entry) => entry,
                None => continue,
            };
            let address =
                hex_bytes::<20>(&format!("payload.contracts.{role}.address"), &entry.address, true)
                    .map_err(parse_err)?;
            let runtime_code_hash = hex_bytes::<32>(
                &format!("payload.contracts.{role}.runtimeCodeHash"),
                &entry.runtime_code_hash,
                true,
            )
            .map_err(parse_err)?;
            if runtime_code_hash == [0u8; 32] || runtime_code_hash == EMPTY_CODE_HASH {
                return Err(parse_err(format!(
                    "payload.contracts.{role}.runtimeCodeHash = {:?} is the code hash of an \
                     account with no code (zero, or keccak256(\"\")). A committed role must be a \
                     contract: FeeTokenRegistry.setRoleCommitment stores this value and the \
                     registry compares it against the live EXTCODEHASH",
                    entry.runtime_code_hash
                )));
            }
            roles.insert(
                role.to_string(),
                RoleCommitment {
                    address,
                    runtime_code_hash,
                },
            );
        }

        // Metadata, outside the payload: case-insensitive because nothing
        // hashes it.
        let declared_deployment_manifest_hash =
            hex_bytes::<32>("deploymentManifestHash", &file.deployment_manifest_hash, false)
                .map_err(parse_err)?;

        Ok(Self {
            declared_deployment_manifest_hash,
            computed_deployment_manifest_hash,
            payload_chain_id,
            roles,
            accounts,
            note: file.note,
        })
    }

    /// The digest the file **declared** for its own payload. An operator's
    /// claim, nothing more, until `runtime::StreamGState::start` has checked it
    /// against [`DeploymentPayload::computed_deployment_manifest_hash`].
    pub fn declared_deployment_manifest_hash(&self) -> [u8; 32] {
        self.declared_deployment_manifest_hash
    }

    /// `keccak256(UTF8(RFC8785(normalised payload)))` over the payload actually
    /// loaded — the spec's rule at `:246`.
    pub fn computed_deployment_manifest_hash(&self) -> [u8; 32] {
        self.computed_deployment_manifest_hash
    }

    /// `payload.chainId`, as the number it parsed to.
    ///
    /// `u128` because that is what [`canonical_decimal`] answers and the field
    /// is a `uint256` on the wire; the manifest's `chain_id` is a `u64`, so the
    /// comparison in `runtime::StreamGState::start` widens the manifest side
    /// rather than narrowing this one — a payload declaring a chain id past
    /// `u64::MAX` must fail that comparison, not wrap into agreement with it.
    pub fn payload_chain_id(&self) -> u128 {
        self.payload_chain_id
    }

    /// The decoded commitment for one of [`CANONICAL_ROLES`].
    ///
    /// `None` is unreachable for a canonical role after a successful parse
    /// (`require_exact_key_set` proves every key is present); it is returned
    /// rather than panicking so a future edit cannot turn a schema change into
    /// an abort at startup.
    pub fn role(&self, role: &str) -> Option<&RoleCommitment> {
        self.roles.get(role)
    }

    /// The decoded address for one of [`CANONICAL_ACCOUNTS`].
    ///
    /// `None` is unreachable for a canonical account after a successful parse,
    /// and is returned rather than panicking for the same reason
    /// [`DeploymentPayload::role`] does.
    pub fn account(&self, role: &str) -> Option<[u8; 20]> {
        self.accounts.get(role).copied()
    }
}

/// The bytes the digest is taken over, for the **ops leg** — `main.rs`'s
/// `deployment-manifest-hash` subcommand.
///
/// A founder computing the value to publish as
/// `STREAM_G_DEPLOYMENT_MANIFEST_HASH` needs to see *what was hashed*, not
/// merely the result. This is a thin extractor on purpose: the casing rule is
/// [`require_lowercase_hex`] and the canonicalisation is
/// [`crate::canonical_bytes`], the same two functions
/// [`DeploymentPayload::from_json`] hashes with, so the CLI cannot drift from
/// the loader. Pinned by
/// [`tests::canonical_deployment_payload_bytes_are_the_bytes_the_loader_hashes`].
pub fn canonical_deployment_payload_bytes(
    raw: &str,
    source: &str,
) -> Result<Vec<u8>, DeploymentPayloadError> {
    let parse_err = |detail: String| DeploymentPayloadError::Parse {
        path: source.to_string(),
        detail,
    };
    let doc: Value = serde_json::from_str(raw).map_err(|e| parse_err(e.to_string()))?;
    let payload = doc.get("payload").ok_or_else(|| {
        parse_err(
            "the file has no `payload` object, so there is nothing to canonicalise; a \
             deployment payload file is {schemaVersion, deploymentManifestHash, note, payload}"
                .to_string(),
        )
    })?;
    require_lowercase_hex(payload).map_err(parse_err)?;
    crate::canonical_bytes(payload).map_err(|e| {
        parse_err(format!(
            "payload cannot be canonicalised, so no deploymentManifestHash can be computed for \
             it: {e}"
        ))
    })
}

/// Refuse any hex-valued payload field that is not spelled lowercase.
///
/// # Why a refusal and not a normalisation
///
/// `0xAbC…` and `0xabc…` are the same address and different bytes, so exactly
/// one spelling can be hashed. The spec picks one, normatively, at
/// the "Stream G — USDT Gas Abstraction and Multi-Wallet Sponsoring" spec,
/// §5.1 (FeeTokenRegistry): *"addresses
/// are lowercase 0x plus 40 hex digits"*. The fee schedule has always enforced
/// that (`quotes::canonical_lowercase_address`).
///
/// The first version of this module did **not**. It lowercased every hex field
/// before canonicalising, and justified the deviation like this:
///
/// > It is not available here. This payload has exactly one producer —
/// > `DeployStreamG.s.sol::writeDeploymentPayload` — and `vm.serializeAddress`
/// > emits EIP-55 checksummed, mixed case. A refusal rule would mean the only
/// > tool that can write the document writes one no tool in this repository can
/// > hash.
///
/// **That was false.** The vendored `contracts/lib/forge-std/src/Vm.sol`
/// declares `toLowercase` — `function toLowercase(string calldata input)
/// external pure returns (string memory output)` — and always did.
/// `writeDeploymentPayload` now emits `vm.toLowercase(vm.toString(addr))` and is
/// spec-conformant, so the accommodation has no reason to exist.
///
/// The cost of the deviation was not cosmetic. With a normalisation the
/// canonical bytes were a **projection** of the file rather than a slice of it:
/// an operator diffing the document against the bytes
/// `goat-attestor deployment-manifest-hash` prints saw different text, which is
/// precisely the hazard the spec's lowercase rule exists to remove. Every VALUE
/// in the canonical bytes is now verbatim from the file; JCS reorders members
/// and strips whitespace and does nothing else.
///
/// # What is checked
///
/// Schema-directed, deliberately, rather than "anything that looks like hex": a
/// pattern rule would silently start policing a future field nobody checked, in
/// one runtime before the other. The paths are `releaseCommit`, every
/// `contracts[*].address`, every `contracts[*].runtimeCodeHash`, and every
/// `accounts[*]`. Shape beyond what the check needs is not validated here — a
/// malformed document is reported by the typed parse in
/// [`DeploymentPayload::from_json`], and anything unhashable by
/// [`crate::canonical_json`] with a JSONPath breadcrumb.
///
/// The JavaScript half of the parity pair
/// (`contracts/test/StreamGManifest.test.mjs`) applies the same refusal over the
/// same paths, because a payload one runtime hashes and the other rejects would
/// ship as "parity verified" on whichever side ran.
fn require_lowercase_hex(payload: &Value) -> Result<(), String> {
    fn check(field: &str, value: &Value) -> Result<(), String> {
        let Value::String(s) = value else {
            return Ok(());
        };
        if s.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(format!(
                "{field} = {s:?} is not lowercase. The deployment payload spells every hex value \
                 lowercase (spec :244, \"addresses are lowercase 0x plus 40 hex digits\") so that \
                 the bytes hashed are the bytes written; two spellings of one address would give \
                 one approved deployment two legitimate digests. \
                 DeployStreamG.writeDeploymentPayload emits vm.toLowercase(vm.toString(addr))"
            ));
        }
        Ok(())
    }

    let obj = payload.as_object().ok_or_else(|| {
        "payload is not a JSON object; the deployment payload schema is \
         {schemaVersion, deploymentVersion, chainId, releaseCommit, contracts, accounts}"
            .to_string()
    })?;

    if let Some(commit) = obj.get("releaseCommit") {
        check("payload.releaseCommit", commit)?;
    }

    if let Some(contracts) = obj.get("contracts") {
        let contracts = contracts.as_object().ok_or_else(|| {
            "payload.contracts is not a JSON object; it is a role-keyed map of \
             {address, runtimeCodeHash}"
                .to_string()
        })?;
        for (role, entry) in contracts {
            let entry_obj = entry.as_object().ok_or_else(|| {
                format!("payload.contracts.{role} is not a JSON object; it is {{address, runtimeCodeHash}}")
            })?;
            for field in ["address", "runtimeCodeHash"] {
                if let Some(v) = entry_obj.get(field) {
                    check(&format!("payload.contracts.{role}.{field}"), v)?;
                }
            }
        }
    }

    if let Some(accounts) = obj.get("accounts") {
        let accounts = accounts.as_object().ok_or_else(|| {
            "payload.accounts is not a JSON object; it is a role-keyed map of address strings"
                .to_string()
        })?;
        for (role, entry) in accounts {
            check(&format!("payload.accounts.{role}"), entry)?;
        }
    }

    Ok(())
}

/// A canonical decimal string: ASCII digits only, no sign, no whitespace, no
/// leading zero unless the value *is* `"0"`, and in `u128` range.
///
/// Same rule and same reason as `quotes::canonical_decimal`, written here
/// rather than shared because this crate's `stream_g` modules are
/// self-contained by convention: `"07"` and `"7"` mean the same number and hash
/// differently, so accepting both would give one approved deployment two
/// legitimate digests. Rust's `str::parse::<u128>` accepts a leading `+` and
/// leading zeros, so it cannot be the rule on its own.
fn canonical_decimal(field: &str, s: &str) -> Result<u128, String> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "{field} = {s:?} is not a decimal string; the deployment payload encodes chainId \
             and every integer as ASCII digits"
        ));
    }
    if s.len() > 1 && s.starts_with('0') {
        return Err(format!(
            "{field} = {s:?} has a leading zero; {:?} and {s:?} would hash differently while \
             meaning the same number, so only the shortest spelling is canonical",
            s.trim_start_matches('0')
        ));
    }
    s.parse::<u128>()
        .map_err(|_| format!("{field} = {s:?} does not fit in a u128"))
}

/// Exactly 40 hex digits, no `0x` — a git commit sha.
///
/// Uppercase is refused before hashing (see [`require_lowercase_hex`]); length
/// and alphabet are not negotiable either, because a free-text `releaseCommit`
/// would let one deployment publish under two digests that differ only in how
/// somebody typed the sha.
///
/// Forty zeros is the documented lab sentinel for "this deployment is not
/// pinned to a release commit", and is accepted like any other value: it is
/// what `DeployStreamG`'s `vm.envOr` default writes, and the payload cannot
/// carry the sha of the commit that contains it (this file is compiled into
/// the binary that reads it).
fn release_commit(field: &str, s: &str) -> Result<(), String> {
    let ok = s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit());
    if !ok {
        return Err(format!(
            "{field} = {s:?} is not 40 hex digits; it is a git commit sha with no 0x prefix \
             (forty zeros is the documented sentinel for an unpinned lab deployment)"
        ));
    }
    Ok(())
}

/// `0x` + exactly `2 * N` hex digits, decoded.
///
/// `lowercase_is_canonical` only changes the *message*. The casing RULE for
/// hashed fields is enforced by [`require_lowercase_hex`], which runs first and
/// over the whole payload; this decode is case-insensitive either way, so a
/// field whose spelling is hashed says where the real rule lives and one that is
/// pure metadata (the declared `deploymentManifestHash`, outside `payload`)
/// says nothing.
fn hex_bytes<const N: usize>(
    field: &str,
    s: &str,
    lowercase_is_canonical: bool,
) -> Result<[u8; N], String> {
    let hint = if lowercase_is_canonical {
        " (and inside `payload`, so it must be spelled lowercase)"
    } else {
        ""
    };
    let body = s.strip_prefix("0x").ok_or_else(|| {
        format!("{field} = {s:?} is not a 0x-prefixed {N}-byte hex string{hint}")
    })?;
    if body.len() != N * 2 || !body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "{field} = {s:?} is not a 0x-prefixed {N}-byte hex string{hint}"
        ));
    }
    let decoded = hex::decode(body)
        .map_err(|e| format!("{field} = {s:?} is not hex after the 0x prefix: {e}"))?;
    let mut out = [0u8; N];
    if decoded.len() != N {
        return Err(format!(
            "{field} = {s:?} decoded to {} bytes, not {N}",
            decoded.len()
        ));
    }
    out.copy_from_slice(&decoded);
    Ok(out)
}

/// Exactly the expected role names — no more, no fewer.
///
/// The "no more" half matters as much as the "no less": an extra key is a
/// commitment nothing can check, and it would move the digest, so it would
/// surface as an unexplained startup refusal with nothing pointing at the extra
/// key. Naming it here is the only message that leads anywhere. A missing key
/// is worse still — it is an address the deployment stops binding at all, which
/// is the exact hole `payload.accounts` was added to close.
fn require_exact_key_set<T>(
    field: &str,
    expected: &[&'static str],
    map: &BTreeMap<String, T>,
) -> Result<(), String> {
    let missing: Vec<&str> = expected
        .iter()
        .copied()
        .filter(|role| !map.contains_key(*role))
        .collect();
    let unrecognised: Vec<&str> = map
        .keys()
        .map(String::as_str)
        .filter(|k| !expected.contains(k))
        .collect();
    if missing.is_empty() && unrecognised.is_empty() {
        return Ok(());
    }
    Err(format!(
        "{field} must carry exactly {:?}; missing {:?}, unrecognised {:?}. Every entry is an \
         address this deployment commits to and that StreamGState::start compares against the \
         deployment manifest",
        expected, missing, unrecognised
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const A40: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B40: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const C40: &str = "0xcccccccccccccccccccccccccccccccccccccccc";
    const D40: &str = "0xdddddddddddddddddddddddddddddddddddddddd";
    const A64: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B64: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const C64: &str = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const D64: &str = "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    /// A minimal well-formed document.
    ///
    /// Every hex value is spelled with LETTERS, deliberately: an all-digit
    /// fixture would make
    /// [`tests::refuses_uppercase_hex_in_every_hashed_field`] vacuous —
    /// uppercasing `"0x2222…"` is the identity, so the test would report a
    /// clean parse and prove nothing about whether the casing rule exists.
    fn doc_with(mutate: impl FnOnce(&mut Value)) -> String {
        let mut doc = json!({
            "schemaVersion": 1,
            "deploymentManifestHash":
                "0x0000000000000000000000000000000000000000000000000000000000000001",
            "note": "test",
            "payload": {
                "schemaVersion": "2",
                "deploymentVersion": "1",
                "chainId": "31337",
                "releaseCommit": "abcdef0123456789abcdef0123456789abcdef01",
                "contracts": {
                    "FEE_TOKEN_REGISTRY": { "address": A40, "runtimeCodeHash": A64 },
                    "GATEWAY": { "address": B40, "runtimeCodeHash": B64 },
                    "SPONSORED_BUY_DESK": { "address": C40, "runtimeCodeHash": C64 },
                    "WALLET_SPONSORSHIP_REGISTRY": { "address": D40, "runtimeCodeHash": D64 }
                },
                "accounts": {
                    "DESK_OWNER": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee01",
                    "ENROLLMENT_REGISTRY": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee02",
                    "FEE_SAFE": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee03",
                    "FEE_TOKEN": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee04",
                    "GOAT_COIN": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee05",
                    "POLICY_SAFE": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee06",
                    "QUOTE_SIGNER": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee07",
                    "RECOVERY_SAFE": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee08"
                }
            }
        });
        mutate(&mut doc);
        doc.to_string()
    }

    fn parse_detail(raw: &str) -> String {
        match DeploymentPayload::from_json(raw, "<test>").unwrap_err() {
            DeploymentPayloadError::Parse { detail, .. } => detail,
            other => panic!("expected a parse refusal, got {other:?}"),
        }
    }

    fn digest_of(raw: &str) -> [u8; 32] {
        DeploymentPayload::from_json(raw, "<test>")
            .expect("fixture must load")
            .computed_deployment_manifest_hash()
    }

    /// KNOWN-ANSWER TEST. The bytes and the digest the JavaScript and ops legs
    /// must reproduce, pinned as LITERALS.
    ///
    /// `EXPECTED_BYTES` is written out by hand in canonical order rather than
    /// captured from the code under test, and `EXPECTED_HASH` is cross-checked
    /// against `contracts/test/keccak256.mjs` over exactly those bytes — an
    /// independent keccak implementation, so the constant is not merely
    /// self-consistent with this crate's own `tiny-keccak` call.
    #[test]
    fn known_answer_hash() {
        let raw = doc_with(|_| {});
        let bytes = canonical_deployment_payload_bytes(&raw, "<test>").expect("canonicalises");
        let canonical = String::from_utf8(bytes).unwrap();

        // Member order is ASCII byte order at every level:
        // "accounts" < "chainId" < "contracts" < "deploymentVersion" <
        // "releaseCommit" < "schemaVersion", and within each role entry
        // "address" < "runtimeCodeHash". Inside `accounts`, note that
        // "FEE_SAFE" precedes "FEE_TOKEN" ('S' 0x53 < 'T' 0x54).
        const EXPECTED_BYTES: &str = concat!(
            r#"{"accounts":{"DESK_OWNER":"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee01","#,
            r#""ENROLLMENT_REGISTRY":"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee02","#,
            r#""FEE_SAFE":"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee03","#,
            r#""FEE_TOKEN":"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee04","#,
            r#""GOAT_COIN":"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee05","#,
            r#""POLICY_SAFE":"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee06","#,
            r#""QUOTE_SIGNER":"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee07","#,
            r#""RECOVERY_SAFE":"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee08"},"#,
            r#""chainId":"31337","contracts":{"#,
            r#""FEE_TOKEN_REGISTRY":{"address":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","#,
            r#""runtimeCodeHash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"#,
            r#""GATEWAY":{"address":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","#,
            r#""runtimeCodeHash":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"#,
            r#""SPONSORED_BUY_DESK":{"address":"0xcccccccccccccccccccccccccccccccccccccccc","#,
            r#""runtimeCodeHash":"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"#,
            r#""WALLET_SPONSORSHIP_REGISTRY":{"address":"0xdddddddddddddddddddddddddddddddddddddddd","#,
            r#""runtimeCodeHash":"0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}},"#,
            r#""deploymentVersion":"1","releaseCommit":"abcdef0123456789abcdef0123456789abcdef01","#,
            r#""schemaVersion":"2"}"#
        );
        assert_eq!(canonical, EXPECTED_BYTES);
        assert_eq!(
            EXPECTED_BYTES.len(),
            1282,
            "canonical byte length is part of the fixture"
        );

        // Cross-checked against `contracts/test/keccak256.mjs` — a
        // dependency-free JavaScript keccak256, vector-tested against foundry's
        // `cast keccak` — over these exact 1229 UTF-8 bytes, so this constant is
        // not merely self-consistent with this crate's own `tiny-keccak` call.
        const EXPECTED_HASH: &str =
            "a12e1fdc329e77af55c7161c244246f954ce485ecf1487c5f5a5fa66a79d0abb";
        assert_eq!(hex::encode(digest_of(&raw)), EXPECTED_HASH);
    }

    /// The spec's lowercase rule (`:244`), enforced as a REFUSAL rather than
    /// normalised away — so the canonical bytes are the file's own values, not
    /// a projection of them.
    ///
    /// Every hashed hex path is exercised individually. A single loop over "the
    /// payload" would pass while three of the four paths went unchecked.
    #[test]
    fn refuses_uppercase_hex_in_every_hashed_field() {
        for (label, mutate) in [
            (
                "releaseCommit",
                Box::new(|doc: &mut Value| {
                    doc["payload"]["releaseCommit"] =
                        json!("ABCDEF0123456789abcdef0123456789abcdef01");
                }) as Box<dyn FnOnce(&mut Value)>,
            ),
            (
                "contracts[*].address",
                Box::new(|doc: &mut Value| {
                    doc["payload"]["contracts"]["GATEWAY"]["address"] =
                        json!("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
                }),
            ),
            (
                "contracts[*].runtimeCodeHash",
                Box::new(|doc: &mut Value| {
                    doc["payload"]["contracts"]["GATEWAY"]["runtimeCodeHash"] = json!(
                        "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
                    );
                }),
            ),
            (
                "accounts[*]",
                Box::new(|doc: &mut Value| {
                    doc["payload"]["accounts"]["QUOTE_SIGNER"] =
                        json!("0xEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE07");
                }),
            ),
        ] {
            let detail = parse_detail(&doc_with(mutate));
            assert!(detail.contains("is not lowercase"), "{label}: {detail}");
        }
    }

    /// One NIBBLE moves the digest. Paired with the refusal above: without this
    /// arm, a canonicaliser that discarded the addresses entirely would satisfy
    /// every casing assertion in this module.
    #[test]
    fn one_nibble_moves_the_digest() {
        let base = doc_with(|_| {});
        let nudged = doc_with(|doc| {
            doc["payload"]["contracts"]["GATEWAY"]["address"] =
                json!("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbc");
        });
        assert_ne!(digest_of(&base), digest_of(&nudged));
    }

    /// The eight `accounts` addresses are inside the digest. Each one
    /// individually, because a loop asserting "some account edit moves it"
    /// would pass with seven of them unhashed.
    #[test]
    fn editing_any_account_address_moves_the_digest() {
        let base = digest_of(&doc_with(|_| {}));
        for role in CANONICAL_ACCOUNTS {
            let after = doc_with(|doc| {
                doc["payload"]["accounts"][role] =
                    json!("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeff");
            });
            assert_ne!(base, digest_of(&after), "{role} is not bound by the digest");
        }
    }

    /// Key order is the canonicaliser's job; this pins that it applies to the
    /// nested `contracts` map and the role entries too, not just the payload
    /// root. The scrambled document is supplied as TEXT so the insertion order
    /// really is the input order.
    #[test]
    fn key_order_does_not_move_the_digest() {
        let normal = doc_with(|_| {});
        let scrambled = r#"{
            "payload": {
                "contracts": {
                    "WALLET_SPONSORSHIP_REGISTRY": {
                        "runtimeCodeHash": "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                        "address": "0xdddddddddddddddddddddddddddddddddddddddd"
                    },
                    "GATEWAY": {
                        "runtimeCodeHash": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                        "address": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    },
                    "SPONSORED_BUY_DESK": {
                        "address": "0xcccccccccccccccccccccccccccccccccccccccc",
                        "runtimeCodeHash": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                    },
                    "FEE_TOKEN_REGISTRY": {
                        "address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "runtimeCodeHash": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    }
                },
                "accounts": {
                    "RECOVERY_SAFE": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee08",
                    "DESK_OWNER": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee01",
                    "QUOTE_SIGNER": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee07",
                    "FEE_TOKEN": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee04",
                    "ENROLLMENT_REGISTRY": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee02",
                    "POLICY_SAFE": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee06",
                    "FEE_SAFE": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee03",
                    "GOAT_COIN": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee05"
                },
                "releaseCommit": "abcdef0123456789abcdef0123456789abcdef01",
                "schemaVersion": "2",
                "chainId": "31337",
                "deploymentVersion": "1"
            },
            "note": "test",
            "deploymentManifestHash": "0x0000000000000000000000000000000000000000000000000000000000000001",
            "schemaVersion": 1
        }"#;

        assert_ne!(normal.as_str(), scrambled, "the two must differ as TEXT");
        assert_eq!(digest_of(&normal), digest_of(scrambled));
        assert_eq!(
            canonical_deployment_payload_bytes(&normal, "<test>").unwrap(),
            canonical_deployment_payload_bytes(scrambled, "<test>").unwrap()
        );
    }

    /// Editing an ADDRESS moves the digest. This is the whole point: under the
    /// retired `keccak256("stream-g-manifest-g1")` tag this assertion could not
    /// have been written at all, because no edit to anything could move that
    /// value.
    #[test]
    fn editing_one_address_moves_the_digest() {
        let after = doc_with(|doc| {
            doc["payload"]["contracts"]["GATEWAY"]["address"] =
                json!("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbc");
        });
        assert_ne!(digest_of(&doc_with(|_| {})), digest_of(&after));
    }

    /// Editing a RUNTIME CODE HASH moves the digest — the other half of what
    /// the payload commits to, and the half that catches a redeployed contract
    /// at the same address.
    #[test]
    fn editing_one_runtime_code_hash_moves_the_digest() {
        let after = doc_with(|doc| {
            doc["payload"]["contracts"]["GATEWAY"]["runtimeCodeHash"] =
                json!("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbc");
        });
        assert_ne!(digest_of(&doc_with(|_| {})), digest_of(&after));
    }

    /// Approval metadata is outside the payload, so editing it must NOT move
    /// the computed digest — otherwise the digest would have to reference
    /// itself and could never be made to match.
    #[test]
    fn approval_metadata_is_outside_the_payload() {
        let mutated = doc_with(|doc| {
            doc["deploymentManifestHash"] =
                json!("0x00000000000000000000000000000000000000000000000000000000000000ff");
            doc["note"] = json!("a completely different note");
        });
        assert_eq!(digest_of(&doc_with(|_| {})), digest_of(&mutated));

        let loaded = DeploymentPayload::from_json(&mutated, "<test>").unwrap();
        assert_ne!(
            loaded.declared_deployment_manifest_hash(),
            loaded.computed_deployment_manifest_hash(),
            "the mutated declaration must now disagree — that is what start() refuses on"
        );
    }

    #[test]
    fn refuses_a_wrong_container_schema_version() {
        let detail = parse_detail(&doc_with(|doc| doc["schemaVersion"] = json!(2)));
        assert!(detail.contains("unsupported schemaVersion 2"), "{detail}");
    }

    /// A schema-1 payload — the shape that shipped before `accounts` existed —
    /// is refused by VERSION, naming the hole, rather than by
    /// "missing field `accounts`".
    #[test]
    fn refuses_a_wrong_payload_schema_version() {
        let detail = parse_detail(&doc_with(|doc| doc["payload"]["schemaVersion"] = json!("1")));
        assert!(detail.contains("payload.schemaVersion"), "{detail}");
        assert!(
            detail.contains("Schema 1 had no `accounts` map"),
            "the refusal must say what a schema-1 document is missing: {detail}"
        );
    }

    /// A schema-1 document in full — no `accounts` key at all — must still be
    /// refused by version, which is the ordering the probe in `from_json`
    /// exists to guarantee.
    #[test]
    fn refuses_a_whole_schema_1_document_by_version_not_by_missing_field() {
        let detail = parse_detail(&doc_with(|doc| {
            doc["payload"]["schemaVersion"] = json!("1");
            doc["payload"].as_object_mut().unwrap().remove("accounts");
        }));
        assert!(detail.contains("payload.schemaVersion"), "{detail}");
        assert!(!detail.contains("missing field"), "{detail}");
    }

    /// ...and a schema-2 document that simply forgot `accounts` is refused too,
    /// rather than starting with eight unbound addresses.
    #[test]
    fn refuses_a_payload_with_no_accounts_map() {
        let detail = parse_detail(&doc_with(|doc| {
            doc["payload"].as_object_mut().unwrap().remove("accounts");
        }));
        assert!(detail.contains("accounts"), "{detail}");
    }

    #[test]
    fn refuses_unknown_fields_at_every_level() {
        for detail in [
            parse_detail(&doc_with(|doc| doc["surprise"] = json!("x"))),
            parse_detail(&doc_with(|doc| doc["payload"]["surprise"] = json!("x"))),
            parse_detail(&doc_with(|doc| {
                doc["payload"]["contracts"]["GATEWAY"]["surprise"] = json!("x")
            })),
        ] {
            assert!(detail.contains("unknown field"), "{detail}");
        }
    }

    #[test]
    fn refuses_a_role_map_that_is_not_exactly_the_four_committed_roles() {
        let detail = parse_detail(&doc_with(|doc| {
            doc["payload"]["contracts"]
                .as_object_mut()
                .unwrap()
                .remove("GATEWAY");
        }));
        assert!(detail.contains("missing [\"GATEWAY\"]"), "{detail}");

        let detail = parse_detail(&doc_with(|doc| {
            doc["payload"]["contracts"]["GOAT_COIN"] =
                json!({ "address": A40, "runtimeCodeHash": A64 });
        }));
        assert!(detail.contains("unrecognised [\"GOAT_COIN\"]"), "{detail}");
    }

    #[test]
    fn refuses_an_account_map_that_is_not_exactly_the_eight_addresses() {
        let detail = parse_detail(&doc_with(|doc| {
            doc["payload"]["accounts"]
                .as_object_mut()
                .unwrap()
                .remove("QUOTE_SIGNER");
        }));
        assert!(detail.contains("missing [\"QUOTE_SIGNER\"]"), "{detail}");

        let detail = parse_detail(&doc_with(|doc| {
            doc["payload"]["accounts"]["GATEWAY"] = json!(B40);
        }));
        assert!(detail.contains("unrecognised [\"GATEWAY\"]"), "{detail}");
    }

    #[test]
    fn refuses_a_non_canonical_decimal() {
        let detail = parse_detail(&doc_with(|doc| doc["payload"]["chainId"] = json!("031337")));
        assert!(detail.contains("leading zero"), "{detail}");
        // A JSON number is caught by the canonicaliser first, with a JSONPath
        // breadcrumb the typed parse could not produce.
        let detail = parse_detail(&doc_with(|doc| doc["payload"]["chainId"] = json!(31337)));
        assert!(detail.contains("JSON number at $.chainId"), "{detail}");
    }

    #[test]
    fn refuses_a_release_commit_that_is_not_forty_hex() {
        for bad in ["HEAD", "0x0000000000000000000000000000000000000000", ""] {
            let detail = parse_detail(&doc_with(|doc| doc["payload"]["releaseCommit"] = json!(bad)));
            assert!(detail.contains("40 hex digits"), "{bad}: {detail}");
        }
    }

    /// A committed role must be a contract. `keccak256("")` is the EXTCODEHASH
    /// of a funded EOA and zero is that of an account that does not exist; both
    /// mean the payload is describing a non-contract as a committed role, and
    /// `FeeTokenRegistry` would never have stored either.
    #[test]
    fn refuses_a_code_hash_that_describes_an_account_with_no_code() {
        for bad in [
            "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
        ] {
            let detail = parse_detail(&doc_with(|doc| {
                doc["payload"]["contracts"]["GATEWAY"]["runtimeCodeHash"] = json!(bad);
            }));
            assert!(detail.contains("no code"), "{bad}: {detail}");
        }
    }

    /// `EMPTY_CODE_HASH` is `keccak256("")`, verified against this crate's own
    /// keccak rather than trusted as a transcribed constant.
    #[test]
    fn empty_code_hash_constant_is_keccak_of_the_empty_string() {
        assert_eq!(crate::keccak256(b""), EMPTY_CODE_HASH);
    }

    #[test]
    fn refuses_a_malformed_address() {
        for bad in [
            "0x22",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        ] {
            let detail = parse_detail(&doc_with(|doc| {
                doc["payload"]["contracts"]["GATEWAY"]["address"] = json!(bad);
            }));
            assert!(detail.contains("20-byte hex string"), "{bad}: {detail}");
        }
    }

    /// The CLI must print the bytes the loader hashed, not a second
    /// canonicalisation that could drift from it.
    #[test]
    fn canonical_deployment_payload_bytes_are_the_bytes_the_loader_hashes() {
        let raw = doc_with(|_| {});
        let bytes = canonical_deployment_payload_bytes(&raw, "<test>").unwrap();
        assert_eq!(crate::keccak256(&bytes), digest_of(&raw));
    }

    /// The built-in copy and the committed deploy artifact must be the same
    /// bytes, or the binary would start against a payload the lab deployment
    /// never wrote. Byte-for-byte, deliberately: a semantic comparison would
    /// tolerate a reformat that moves the digest.
    #[test]
    fn builtin_payload_is_byte_identical_to_the_committed_deployment_artifact() {
        let path = std::path::Path::new("../../contracts/deployments/31337.stream-g.payload.json");
        if !path.exists() {
            eprintln!("skipping: {path:?} not found in this checkout");
            return;
        }
        let committed = std::fs::read_to_string(path).expect("read the committed artifact");
        assert_eq!(
            BUILTIN_DEPLOYMENT_PAYLOAD_JSON, committed,
            "fixtures/stream_g_deployment_payload.json has drifted from \
             contracts/deployments/31337.stream-g.payload.json. DeployStreamG rewrites the \
             latter on every `forge test` run; re-copy it rather than editing either by hand"
        );
    }

    /// The shipped lab payload, pinned by VALUE, and pinned AGAINST the shipped
    /// manifest. This is the Rust leg of the three-way fixture; the JavaScript
    /// leg is `contracts/test/StreamGManifest.test.mjs` and the ops leg is
    /// `goat-attestor deployment-manifest-hash`.
    #[test]
    fn shipped_deployment_payload_is_published_and_binds_the_manifest() {
        let payload =
            DeploymentPayload::from_json(BUILTIN_DEPLOYMENT_PAYLOAD_JSON, "<built-in>").unwrap();
        assert_eq!(
            hex::encode(payload.computed_deployment_manifest_hash()),
            hex::encode(payload.declared_deployment_manifest_hash()),
            "the shipped payload must declare the digest of its own content"
        );
        assert_eq!(payload.payload_chain_id(), 31337);

        for role in CANONICAL_ROLES {
            let commitment = payload.role(role).expect("role present");
            assert_ne!(commitment.address, [0u8; 20], "{role} address is zero");
            assert_ne!(
                commitment.runtime_code_hash, EMPTY_CODE_HASH,
                "{role} has no code"
            );
        }

        let manifest = super::super::token_manifest::parse_deployment_manifest(
            super::super::token_manifest::BUILTIN_DEPLOYMENT_MANIFEST_JSON,
            "<built-in>",
            31337,
        )
        .expect("built-in manifest parses");
        assert_eq!(
            hex::encode(manifest.deployment_manifest_hash),
            hex::encode(payload.computed_deployment_manifest_hash()),
            "the shipped manifest must publish the digest of the shipped payload"
        );
        for (role, manifest_address) in [
            ("GATEWAY", manifest.goat_relay_gateway),
            ("FEE_TOKEN_REGISTRY", manifest.fee_token_registry),
            ("SPONSORED_BUY_DESK", manifest.sponsored_buy_desk),
            (
                "WALLET_SPONSORSHIP_REGISTRY",
                manifest.wallet_sponsorship_registry,
            ),
        ] {
            assert_eq!(
                payload.role(role).unwrap().address,
                manifest_address,
                "{role} address disagrees with the manifest"
            );
        }

        // ...and the eight that were bound by nothing before schema 2.
        for (role, manifest_address) in [
            ("DESK_OWNER", manifest.desk_owner),
            ("ENROLLMENT_REGISTRY", manifest.enrollment_registry),
            ("FEE_SAFE", manifest.fee_safe),
            ("FEE_TOKEN", manifest.fee_token),
            ("GOAT_COIN", manifest.goat_coin),
            ("POLICY_SAFE", manifest.policy_safe),
            ("QUOTE_SIGNER", manifest.quote_signer),
            ("RECOVERY_SAFE", manifest.recovery_safe),
        ] {
            assert_eq!(
                payload.account(role).expect("account present"),
                manifest_address,
                "{role} address disagrees with the manifest"
            );
        }
        assert_eq!(
            CANONICAL_ROLES.len() + CANONICAL_ACCOUNTS.len(),
            12,
            "the payload must bind every address the flat artifact carries"
        );
    }

    /// `load` is the path-taking wrapper; exercised here so the filesystem arm
    /// is not dead code, and so a missing file is an `Io` refusal rather than a
    /// `Parse` one.
    #[test]
    fn load_reads_a_real_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.json");
        std::fs::write(&path, doc_with(|_| {})).unwrap();
        assert_eq!(
            DeploymentPayload::load(&path)
                .expect("loads from disk")
                .payload_chain_id(),
            31337
        );
        assert!(matches!(
            DeploymentPayload::load(&dir.path().join("nope.json")).unwrap_err(),
            DeploymentPayloadError::Io { .. }
        ));
    }
}
