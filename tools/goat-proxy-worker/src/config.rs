//! The sidecar's entire configuration surface: seven environment variables,
//! read from a map that is handed in.
//!
//! # Why seven, not six
//!
//! [`ENV_OPERATOR_WALLET`] carries the address the supervisor believes is the
//! active operator key. Without it, consent verification can only check that a
//! record's signature matches *the address the record itself names* — so a
//! "valid" record is any self-consistent self-signed blob. Any process running
//! as the user then generates a throwaway keypair, writes a consent record,
//! flips the limits file on, and residential egress is authorised without the
//! operator ever unlocking a key or reading the disclosure. A refusal test for
//! a foreign signature is not writable at all against a verifier with no notion
//! of which key is foreign.
//!
//! # `load_from_map` never touches the process environment
//!
//! It reads **only** the seven declared names, and only out of the map it is
//! given. That is what makes it testable, and it is what makes the supervisor's
//! `env_clear()` mean something: if this function could reach around the map to
//! `std::env::var`, clearing the child's environment would be decoration.
//!
//! # Design authority
//!
//! The "Residential Proxy Network — Worker & Tunnel Spec (Tasks 18-36, 44, 45,
//! 47)", Task 28 and its Security invariants section (INV-8, INV-19).

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;

/// Path to the destination allowlist. Absent, empty or corrupt is a startup
/// refusal; see [`crate::policy::EgressPolicy::load_entries`].
pub const ENV_ALLOWLIST: &str = "GOAT_PROXY_ALLOWLIST";
/// Path to the signed consent record.
pub const ENV_CONSENT: &str = "GOAT_PROXY_CONSENT";
/// Directory the sidecar owns: the byte ledger and the limits file live here.
pub const ENV_STATE_DIR: &str = "GOAT_PROXY_STATE_DIR";
/// Keccak-256 of the exact disclosure text the operator was shown, as 32 bytes
/// of hex.
pub const ENV_POLICY_TEXT_HASH: &str = "GOAT_PROXY_POLICY_TEXT_HASH";
/// The consented daily ceiling, in bytes.
pub const ENV_DAILY_CEILING_BYTES: &str = "GOAT_PROXY_DAILY_CEILING_BYTES";
/// The consented throttle, in bytes per second.
pub const ENV_THROTTLE_BPS: &str = "GOAT_PROXY_THROTTLE_BPS";
/// The address the supervisor believes is the active operator key, as 20 bytes
/// of hex. See the module header for why this exists.
pub const ENV_OPERATOR_WALLET: &str = "GOAT_PROXY_OPERATOR_WALLET";

/// Every name this process will read. Nothing else reaches it, and the
/// supervisor clears the parent environment before spawning.
pub const DECLARED_ENV: [&str; 7] = [
    ENV_ALLOWLIST,
    ENV_CONSENT,
    ENV_STATE_DIR,
    ENV_POLICY_TEXT_HASH,
    ENV_DAILY_CEILING_BYTES,
    ENV_THROTTLE_BPS,
    ENV_OPERATOR_WALLET,
];

/// Refusals. Every one is a startup refusal; none has a default.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConfigError {
    #[error("required variable {0} is absent")]
    Missing(&'static str),
    #[error("{0} is present but empty")]
    Empty(&'static str),
    #[error("{name} is not a base-ten unsigned integer")]
    NotNumeric { name: &'static str },
    #[error("{0} is zero; a zero here would silently disable the thing it bounds")]
    Zero(&'static str),
    #[error("{name} must be {expected} bytes of hex, got {got}")]
    BadHexLength {
        name: &'static str,
        expected: usize,
        got: usize,
    },
    #[error("{name} contains a character that is not a hex digit")]
    BadHexDigit { name: &'static str },
}

/// The whole configuration surface.
///
/// Note what is **not** here: no tolerance, no chunk size, no path to key
/// material, no gateway URL override, no "allow all" switch. The absence of a
/// knob is the implementation of a decision that its value is fixed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyConfig {
    pub allowlist_path: PathBuf,
    pub consent_path: PathBuf,
    pub state_dir: PathBuf,
    pub policy_text_hash: [u8; 32],
    pub daily_ceiling_bytes: u64,
    pub throttle_bytes_per_sec: u64,
    pub operator_wallet: [u8; 20],
}

impl ProxyConfig {
    /// Build the configuration from a map of variable names to values.
    ///
    /// Reads only [`DECLARED_ENV`]. An undeclared key in the map is ignored;
    /// a declared key that is absent is a refusal, never a default.
    pub fn load_from_map(map: &HashMap<String, String>) -> Result<Self, ConfigError> {
        Ok(Self {
            allowlist_path: PathBuf::from(required(map, ENV_ALLOWLIST)?),
            consent_path: PathBuf::from(required(map, ENV_CONSENT)?),
            state_dir: PathBuf::from(required(map, ENV_STATE_DIR)?),
            policy_text_hash: hex_bytes::<32>(
                required(map, ENV_POLICY_TEXT_HASH)?,
                ENV_POLICY_TEXT_HASH,
            )?,
            daily_ceiling_bytes: positive_u64(
                required(map, ENV_DAILY_CEILING_BYTES)?,
                ENV_DAILY_CEILING_BYTES,
            )?,
            throttle_bytes_per_sec: positive_u64(
                required(map, ENV_THROTTLE_BPS)?,
                ENV_THROTTLE_BPS,
            )?,
            operator_wallet: hex_bytes::<20>(
                required(map, ENV_OPERATOR_WALLET)?,
                ENV_OPERATOR_WALLET,
            )?,
        })
    }
}

fn required<'a>(
    map: &'a HashMap<String, String>,
    name: &'static str,
) -> Result<&'a str, ConfigError> {
    let raw = map.get(name).ok_or(ConfigError::Missing(name))?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ConfigError::Empty(name));
    }
    Ok(trimmed)
}

/// Base ten, unsigned, non-zero.
///
/// The operator's *band* (the ceiling's 1-200 GB window and the throttle's
/// 64-100 000 kbps window) is clamped where the limits file is read, not here:
/// this value arrives from the supervisor, and re-clamping it in two places is
/// how two clamps end up disagreeing. Zero is refused here because zero reaches
/// this function only from a truncated or hand-edited source.
fn positive_u64(value: &str, name: &'static str) -> Result<u64, ConfigError> {
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ConfigError::NotNumeric { name });
    }
    let n: u64 = value
        .parse()
        .map_err(|_| ConfigError::NotNumeric { name })?;
    if n == 0 {
        return Err(ConfigError::Zero(name));
    }
    Ok(n)
}

/// Exactly `N` bytes of hex, with an optional `0x` prefix, either case.
fn hex_bytes<const N: usize>(value: &str, name: &'static str) -> Result<[u8; N], ConfigError> {
    let body = value.strip_prefix("0x").unwrap_or(value);
    if !body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ConfigError::BadHexDigit { name });
    }
    if body.len() != N * 2 {
        return Err(ConfigError::BadHexLength {
            name,
            expected: N,
            got: body.len() / 2,
        });
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(body, &mut out).map_err(|_| ConfigError::BadHexDigit { name })?;
    Ok(out)
}

/// Seconds since the Unix epoch.
///
/// A clock before the epoch is reported as `0` rather than panicking; every
/// consumer of this value compares it against a signed timestamp and a maximum
/// age, so `0` is a refusal downstream, which is the correct direction to fail.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH32: &str = "1122334455667788990011223344556677889900112233445566778899001122";
    const ADDR20: &str = "00112233445566778899aabbccddeeff00112233";

    fn full_map() -> HashMap<String, String> {
        [
            (ENV_ALLOWLIST, "/state/allowlist.json"),
            (ENV_CONSENT, "/state/proxy-consent.json"),
            (ENV_STATE_DIR, "/state"),
            (ENV_POLICY_TEXT_HASH, HASH32),
            (ENV_DAILY_CEILING_BYTES, "5000000000"),
            (ENV_THROTTLE_BPS, "125000"),
            (ENV_OPERATOR_WALLET, ADDR20),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    /// Mutations this detects: adding an eighth variable without widening the
    /// declaration the supervisor spawns against; collapsing two names to the same
    /// string, which would make one of them silently unreadable.
    #[test]
    fn declared_env_is_exactly_seven_names_and_they_are_unique() {
        assert_eq!(
            DECLARED_ENV.len(),
            7,
            "the env surface must not grow silently"
        );

        let mut sorted = DECLARED_ENV.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            7,
            "two declared names collide: {DECLARED_ENV:?}"
        );

        // Every name is namespaced, so a collision with an unrelated variable in
        // an un-cleared environment is not possible by accident.
        for name in DECLARED_ENV {
            assert!(name.starts_with("GOAT_PROXY_"), "{name} is not namespaced");
        }

        // POSITIVE CONTROL: the declaration is what `load_from_map` actually
        // reads. Building a map from DECLARED_ENV alone must succeed.
        let map = full_map();
        assert_eq!(map.len(), DECLARED_ENV.len());
        assert!(ProxyConfig::load_from_map(&map).is_ok());
    }

    /// Mutations this detects: `load_from_map` reaching `std::env::var` for any
    /// value, which would make the supervisor's `env_clear()` decorative; or a
    /// future variable being read before it is declared.
    #[test]
    fn an_undeclared_environment_variable_is_ignored_not_read() {
        let baseline = ProxyConfig::load_from_map(&full_map()).expect("baseline loads");

        let mut noisy = full_map();
        for k in [
            "GOAT_PROXY_ALLOW_ALL",
            "GOAT_PROXY_DISABLE_ALLOWLIST",
            "HTTP_PROXY",
            "GOAT_PROXY_DAILY_CEILING_BYTES_OVERRIDE",
            "PATH",
        ] {
            noisy.insert(k.to_string(), "9".to_string());
        }
        let with_noise = ProxyConfig::load_from_map(&noisy).expect("undeclared keys are ignored");

        assert_eq!(
            baseline, with_noise,
            "an undeclared variable changed the loaded configuration"
        );
    }

    /// Mutations this detects: any `unwrap_or_default()` / `unwrap_or(...)` on a
    /// required variable. A default here is a policy decision made by omission.
    #[test]
    fn a_missing_required_variable_is_a_refusal_not_a_default() {
        for name in DECLARED_ENV {
            let mut map = full_map();
            map.remove(name);
            let err = ProxyConfig::load_from_map(&map)
                .expect_err("a missing required variable must refuse");
            assert_eq!(err, ConfigError::Missing(name), "wrong refusal for {name}");
        }

        // An empty string is not a value either -- an unset variable exported as
        // "" is the shape a shell script produces by accident.
        for name in DECLARED_ENV {
            let mut map = full_map();
            map.insert(name.to_string(), "   ".to_string());
            assert_eq!(
                ProxyConfig::load_from_map(&map).expect_err("empty must refuse"),
                ConfigError::Empty(name)
            );
        }

        // POSITIVE CONTROL: the complete map loads, so the loop above is not
        // passing against a function that refuses everything.
        assert!(ProxyConfig::load_from_map(&full_map()).is_ok());
    }

    /// Mutations this detects: `parse().unwrap_or(0)`; accepting a negative or
    /// signed value; accepting hex or a unit suffix ("5GB"), which `str::parse`
    /// would reject but a hand-rolled scanner might not.
    #[test]
    fn daily_ceiling_and_throttle_reject_zero_and_non_numeric() {
        for name in [ENV_DAILY_CEILING_BYTES, ENV_THROTTLE_BPS] {
            let mut zero = full_map();
            zero.insert(name.to_string(), "0".to_string());
            assert_eq!(
                ProxyConfig::load_from_map(&zero).expect_err("zero must refuse"),
                ConfigError::Zero(name)
            );

            for bad in ["-1", "5GB", "1e9", "0x10", "1.5", "١٢٣", "+7", "9_000"] {
                let mut map = full_map();
                map.insert(name.to_string(), bad.to_string());
                let err = ProxyConfig::load_from_map(&map)
                    .expect_err("a non-numeric value must refuse, not coerce to a default");
                assert_eq!(
                    err,
                    ConfigError::NotNumeric { name },
                    "{bad:?} gave the wrong refusal"
                );
            }
        }

        // POSITIVE CONTROL: ordinary values load and round-trip exactly.
        let cfg = ProxyConfig::load_from_map(&full_map()).expect("loads");
        assert_eq!(cfg.daily_ceiling_bytes, 5_000_000_000);
        assert_eq!(cfg.throttle_bytes_per_sec, 125_000);
    }

    /// Mutations this detects: a length check on the hex STRING rather than on the
    /// decoded bytes; accepting an odd-length string; silently truncating or
    /// zero-padding a short value, which would make two different disclosure texts
    /// hash to the same accepted configuration.
    #[test]
    fn policy_text_hash_must_be_thirty_two_bytes_of_hex() {
        let cfg = ProxyConfig::load_from_map(&full_map()).expect("loads");
        assert_eq!(cfg.policy_text_hash.len(), 32);
        assert_eq!(cfg.policy_text_hash[0], 0x11);
        assert_eq!(cfg.policy_text_hash[31], 0x22);

        // POSITIVE CONTROL: the `0x` prefix and upper case are both accepted, and
        // decode to the same bytes.
        for spelling in [
            format!("0x{HASH32}"),
            HASH32.to_ascii_uppercase(),
            format!("0x{}", HASH32.to_ascii_uppercase()),
        ] {
            let mut map = full_map();
            map.insert(ENV_POLICY_TEXT_HASH.to_string(), spelling.clone());
            assert_eq!(
                ProxyConfig::load_from_map(&map)
                    .unwrap_or_else(|e| panic!("{spelling} must load: {e}"))
                    .policy_text_hash,
                cfg.policy_text_hash
            );
        }

        for (bad, want_len) in [
            (&HASH32[..62], true), // 31 bytes
            (&HASH32[..63], true), // odd length
            ("11", true),          // far too short
            (
                "zz112233445566778899001122334455667788990011223344556677889900112",
                false,
            ),
        ] {
            let mut map = full_map();
            map.insert(ENV_POLICY_TEXT_HASH.to_string(), bad.to_string());
            let err = ProxyConfig::load_from_map(&map)
                .expect_err("a hash that is not 32 bytes of hex must refuse");
            if want_len {
                assert!(
                    matches!(err, ConfigError::BadHexLength { name, .. } if name == ENV_POLICY_TEXT_HASH),
                    "{bad} gave {err:?}"
                );
            } else {
                assert!(
                    matches!(err, ConfigError::BadHexDigit { name } if name == ENV_POLICY_TEXT_HASH),
                    "{bad} gave {err:?}"
                );
            }
        }
    }

    /// Mutations this detects: the wallet made optional, which reduces consent
    /// verification to "this blob is self-consistent"; a 32-byte value accepted
    /// where 20 is required, which would let a public key stand in for an address.
    #[test]
    fn operator_wallet_must_be_a_twenty_byte_hex_address_and_is_required() {
        let cfg = ProxyConfig::load_from_map(&full_map()).expect("loads");
        assert_eq!(cfg.operator_wallet.len(), 20);
        assert_eq!(cfg.operator_wallet[0], 0x00);
        assert_eq!(cfg.operator_wallet[19], 0x33);

        let mut absent = full_map();
        absent.remove(ENV_OPERATOR_WALLET);
        assert_eq!(
            ProxyConfig::load_from_map(&absent).expect_err("required"),
            ConfigError::Missing(ENV_OPERATOR_WALLET)
        );

        // A 32-byte value is the shape of a public key, not of an address.
        let mut too_long = full_map();
        too_long.insert(ENV_OPERATOR_WALLET.to_string(), HASH32.to_string());
        assert!(matches!(
            ProxyConfig::load_from_map(&too_long).expect_err("32 bytes is not an address"),
            ConfigError::BadHexLength { name, expected: 20, .. } if name == ENV_OPERATOR_WALLET
        ));

        // POSITIVE CONTROL: the checksummed spelling decodes to the same bytes.
        let mut mixed = full_map();
        mixed.insert(
            ENV_OPERATOR_WALLET.to_string(),
            format!("0x{}", ADDR20.to_ascii_uppercase()),
        );
        assert_eq!(
            ProxyConfig::load_from_map(&mixed)
                .expect("loads")
                .operator_wallet,
            cfg.operator_wallet
        );
    }

    /// Mutations this detects: `now_unix` returning milliseconds, or panicking on a
    /// pre-epoch clock instead of failing closed downstream.
    #[test]
    fn now_unix_is_seconds_and_is_monotone_across_two_reads() {
        let a = now_unix();
        // A plausible-seconds band: after 2020-01-01 and before 2100-01-01. A
        // millisecond clock lands far above the upper bound.
        assert!(
            a > 1_577_836_800,
            "now_unix looks like it is not seconds: {a}"
        );
        assert!(
            a < 4_102_444_800,
            "now_unix looks like it is milliseconds: {a}"
        );
        assert!(now_unix() >= a);
    }
}
