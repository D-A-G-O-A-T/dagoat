//! XChaCha20-Poly1305 envelope encryption for Stream G at-rest payloads.
//!
//! Every `_enc` column in `migrations/0001_stream_g.sql` holds the output
//! of [`seal`]: a small self-describing envelope, not raw AEAD ciphertext.
//! The additional-authenticated-data ([`EnvelopeAad`]) binds each envelope
//! to the exact row/column/db/key it was sealed for, so ciphertext copied
//! into the wrong cell — or decrypted with the wrong key after a key
//! rotation — fails loudly instead of silently returning garbage.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

/// Envelope format version byte. `open` rejects anything else up front so a
/// future format change can't be silently misparsed.
pub const ENVELOPE_VERSION: u8 = 0x01;

const NONCE_LEN: usize = 24;
const VERSION_LEN: usize = 1;
const MIN_ENVELOPE_LEN: usize = VERSION_LEN + NONCE_LEN;

#[derive(Debug, Error)]
pub enum CryptoStoreError {
    #[error("data key must be exactly 32 bytes (64 hex chars), got {0} bytes")]
    InvalidKeyLength(usize),

    #[error("invalid hex in data key: {0}")]
    InvalidHex(#[from] hex::FromHexError),

    #[error("envelope too short: expected at least {expected} bytes, got {actual}")]
    EnvelopeTooShort { expected: usize, actual: usize },

    #[error("unsupported envelope version: {0}")]
    UnsupportedVersion(u8),

    #[error("decryption failed (wrong key, tampered ciphertext, or AAD mismatch)")]
    DecryptionFailed,

    #[error("encryption failed")]
    EncryptionFailed,
}

/// A 32-byte XChaCha20-Poly1305 data key held in zeroize-on-drop memory.
///
/// `key_id` (first 8 bytes of SHA-256(key), hex-encoded) identifies the key
/// without ever revealing it — safe to log, and folded into every
/// envelope's AAD so sealing under one key and opening under another fails
/// authentication instead of decrypting to garbage (see `seal`/`open`).
pub struct DataKey {
    bytes: Zeroizing<[u8; 32]>,
    key_id: String,
}

/// Manual (not derived) `Debug`: never print key bytes, even in a panic
/// message or a log line that happens to `{:?}` a `DataKey`.
impl std::fmt::Debug for DataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataKey")
            .field("key_id", &self.key_id)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl DataKey {
    /// Parse a 64-hex-char (32-byte) key. Any other decoded length is
    /// rejected — this is a fixed-size AEAD key, not a variable-length
    /// secret.
    pub fn from_hex(s: &str) -> Result<Self, CryptoStoreError> {
        let bytes = decode_key_bytes(s)?;
        let key_id = derive_key_id(&bytes);
        Ok(Self { bytes, key_id })
    }

    /// The same key, parsed from an already-validated [`SecretHex`].
    ///
    /// **Infallible on purpose.** `SecretHex` can only exist if
    /// [`SecretHex::from_hex`] accepted the string, and that constructor runs
    /// [`decode_key_bytes`] — the *same* function `from_hex` runs. So there is
    /// no reachable error here to report, and returning a `Result` would add a
    /// branch no input can take. This is the payoff for making the invalid
    /// state unrepresentable rather than re-checking at every use.
    ///
    /// This is one of the two places a `SecretHex` is unwrapped back to `str`
    /// (the other is `profile_auth::derive_domain_key`); see
    /// [`SecretHex::as_str`].
    pub fn from_secret(secret: &SecretHex) -> Self {
        let bytes = decode_key_bytes(secret.as_str())
            .expect("SecretHex validated the same bytes at construction");
        let key_id = derive_key_id(&bytes);
        Self { bytes, key_id }
    }

    /// See struct docs: derived, non-secret identifier for this key.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

/// The single hex→32-byte validation both [`DataKey::from_hex`] and
/// [`SecretHex::from_hex`] run.
///
/// Factored out so the two constructors cannot drift: "a `SecretHex` is
/// always acceptable to `DataKey`" is true *because* there is one function
/// here, not because two copies happen to agree today. Charset, even-length
/// and 32-byte rules all come from this one body, and so do the error
/// variants.
///
/// Both the raw hex-decoded `Vec` and the final fixed-size array live in
/// `Zeroizing` from the moment they exist: `[u8; 32]` is `Copy`, so a bare
/// stack array would leave the key material behind in whatever slot the
/// compiler happened to copy it through, even after wrapping the final value
/// in `Zeroizing`.
fn decode_key_bytes(s: &str) -> Result<Zeroizing<[u8; 32]>, CryptoStoreError> {
    let decoded = Zeroizing::new(hex::decode(s)?);
    if decoded.len() != 32 {
        return Err(CryptoStoreError::InvalidKeyLength(decoded.len()));
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(&decoded);
    Ok(bytes)
}

/// The at-rest data key **in its original hex form**, held in zeroize-on-drop
/// memory.
///
/// # Why this type exists at all
///
/// [`DataKey`] is deliberately one-way: it has no accessor, no `Display`, and
/// no way back to bytes. That is the right shape for the AEAD key, but it
/// cannot serve `profile_auth::derive_domain_key`, which needs the *raw hex*
/// (see that function's doc for why it decodes independently of `DataKey`).
/// Before this type, that need was met by passing `data_key_hex: &str` down
/// through 21 function parameters — a bare `String` with no zeroization, no
/// redaction, and no validation at any boundary, so a malformed key was only
/// caught at the first `DataKey::from_hex` deep inside a request.
///
/// `SecretHex` closes all three gaps at once: the string is zeroized on drop,
/// `Debug` is redacted, and [`SecretHex::from_hex`] runs the identical
/// validation `DataKey::from_hex` runs, so **an invalid key cannot be
/// represented**.
///
/// # What it does not do
///
/// It does not make the hex unreachable — [`SecretHex::as_str`] exists. It
/// makes reaching it deliberate and greppable rather than ambient.
pub struct SecretHex {
    hex: Zeroizing<String>,
}

/// Manual (not derived) `Debug`, matching [`DataKey`] and
/// `outbox::SignedRawTx`: the whole point of the type is that this value never
/// reaches a log line, a panic message, or a `{:?}` of some struct that
/// happens to contain it.
///
/// Prints `key_id` — the same derived, non-secret identifier `DataKey` prints
/// — so a redacted `SecretHex` is still useful for telling two keys apart in a
/// log without revealing either.
impl std::fmt::Debug for SecretHex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretHex")
            .field("key_id", &self.key_id())
            .field("hex", &"<redacted>")
            .finish()
    }
}

impl SecretHex {
    /// Parse and retain a 64-hex-char (32-byte) key.
    ///
    /// Validation is [`decode_key_bytes`] — byte-for-byte what
    /// [`DataKey::from_hex`] applies, same charset, same length rule, same
    /// [`CryptoStoreError`] variants. The decoded bytes are dropped (and
    /// zeroized) immediately; only the hex is kept.
    pub fn from_hex(s: &str) -> Result<Self, CryptoStoreError> {
        // Validate-and-discard: `decode_key_bytes` returns `Zeroizing`, so the
        // parsed bytes are scrubbed at the end of this statement.
        let _ = decode_key_bytes(s)?;
        Ok(Self {
            hex: Zeroizing::new(s.to_string()),
        })
    }

    /// The raw hex string.
    ///
    /// **This exists solely because `profile_auth::derive_domain_key` needs
    /// raw hex** — it feeds the decoded bytes straight to
    /// `HmacSha256::new_from_slice` and so cannot take a `DataKey`, which has
    /// no accessor by design. [`DataKey::from_secret`] is the only other
    /// caller.
    ///
    /// **It is NOT for logging, error messages, `Display`, serialization, or
    /// anything that copies the value into a `String` that outlives this
    /// borrow.** Use [`SecretHex::key_id`] for anything an operator reads.
    /// `pub(crate)` so no code outside this crate can reach the hex at all.
    pub(crate) fn as_str(&self) -> &str {
        &self.hex
    }

    /// The same derived, non-secret identifier [`DataKey::key_id`] returns
    /// (first 8 bytes of SHA-256 of the key, hex-encoded) — safe to log.
    ///
    /// Recomputed rather than cached: this is not on a hot path, and a cached
    /// field would be a second copy of key-derived state to keep in sync.
    pub fn key_id(&self) -> String {
        match decode_key_bytes(&self.hex) {
            Ok(bytes) => derive_key_id(&bytes),
            // Unreachable — `from_hex` is the only constructor and it
            // validated. Redacting rather than panicking because the sole
            // caller of this is `Debug`, and a `Debug` impl that can panic is
            // strictly worse than one that says "unknown".
            Err(_) => "<invalid>".to_string(),
        }
    }
}

fn derive_key_id(bytes: &[u8; 32]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(&digest[..8])
}

/// Canonical additional-authenticated-data for one encrypted column:
/// `db_uuid|schema_version|table|pk|column|key_id`. Every field the
/// envelope should be "pinned" to goes in here — a mismatch on any one of
/// them (wrong row, wrong column, wrong database file, wrong key) makes
/// `open` fail AEAD authentication rather than return plaintext for the
/// wrong cell.
#[derive(Debug, Clone, Copy)]
pub struct EnvelopeAad<'a> {
    pub db_uuid: &'a str,
    pub schema_version: u32,
    pub table: &'a str,
    pub pk: &'a str,
    pub column: &'a str,
}

impl EnvelopeAad<'_> {
    fn canonical_bytes(&self, key_id: &str) -> Vec<u8> {
        format!(
            "{}|{}|{}|{}|{}|{}",
            self.db_uuid, self.schema_version, self.table, self.pk, self.column, key_id
        )
        .into_bytes()
    }
}

/// Seal `plaintext` under `key`, bound to `aad`.
///
/// Output layout: `[version: 1 byte][nonce: 24 bytes][ciphertext || tag]`.
pub fn seal(
    key: &DataKey,
    aad: &EnvelopeAad,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoStoreError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.bytes.as_slice())
        .map_err(|_| CryptoStoreError::EncryptionFailed)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let aad_bytes = aad.canonical_bytes(&key.key_id);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad_bytes,
            },
        )
        .map_err(|_| CryptoStoreError::EncryptionFailed)?;

    let mut out = Vec::with_capacity(VERSION_LEN + NONCE_LEN + ciphertext.len());
    out.push(ENVELOPE_VERSION);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open an envelope produced by [`seal`]. Never panics: a truncated
/// envelope, unsupported version byte, wrong key, tampered ciphertext, or
/// AAD mismatch all return `Err`. The returned plaintext is
/// `Zeroizing`-wrapped so it is scrubbed from memory when the caller drops
/// it, same as the key material used to decrypt it.
pub fn open(
    key: &DataKey,
    aad: &EnvelopeAad,
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoStoreError> {
    if envelope.len() < MIN_ENVELOPE_LEN {
        return Err(CryptoStoreError::EnvelopeTooShort {
            expected: MIN_ENVELOPE_LEN,
            actual: envelope.len(),
        });
    }

    let version = envelope[0];
    if version != ENVELOPE_VERSION {
        return Err(CryptoStoreError::UnsupportedVersion(version));
    }

    let nonce_bytes = &envelope[VERSION_LEN..VERSION_LEN + NONCE_LEN];
    let ciphertext = &envelope[VERSION_LEN + NONCE_LEN..];
    let nonce = XNonce::from_slice(nonce_bytes);

    let cipher = XChaCha20Poly1305::new_from_slice(key.bytes.as_slice())
        .map_err(|_| CryptoStoreError::DecryptionFailed)?;
    let aad_bytes = aad.canonical_bytes(&key.key_id);

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &aad_bytes,
            },
        )
        .map_err(|_| CryptoStoreError::DecryptionFailed)?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_from_byte(b: u8) -> DataKey {
        let hex_str = hex::encode([b; 32]);
        DataKey::from_hex(&hex_str).expect("valid key")
    }

    fn aad<'a>(table: &'a str, pk: &'a str) -> EnvelopeAad<'a> {
        EnvelopeAad {
            db_uuid: "db-uuid-1",
            schema_version: 1,
            table,
            pk,
            column: "secret",
        }
    }

    #[test]
    fn roundtrip() {
        let key = key_from_byte(0xAA);
        let a = aad("profiles", "profile-1");
        let plaintext = b"hello stream g";
        let envelope = seal(&key, &a, plaintext).expect("seal");
        let opened = open(&key, &a, &envelope).expect("open");
        assert_eq!(&opened[..], &plaintext[..]);
    }

    /// Nonce regression guard: `seal` must draw a fresh random nonce every
    /// call. If the nonce ever became fixed/derived (e.g. from a counter
    /// that got reset, or accidentally zeroed), two seals of identical
    /// plaintext+AAD under the same key would produce identical envelopes —
    /// catastrophic for XChaCha20-Poly1305 (nonce reuse breaks
    /// confidentiality and authentication both).
    #[test]
    fn seal_nonce_differs_between_calls_with_identical_input() {
        let key = key_from_byte(0xAA);
        let a = aad("profiles", "profile-1");
        let envelope_1 = seal(&key, &a, b"same plaintext, same aad").expect("seal 1");
        let envelope_2 = seal(&key, &a, b"same plaintext, same aad").expect("seal 2");
        assert_ne!(
            envelope_1, envelope_2,
            "two seals of identical plaintext/AAD must differ (fresh nonce each call)"
        );
    }

    #[test]
    fn unsupported_version_byte_is_rejected_without_panicking() {
        let key = key_from_byte(0xAA);
        let a = aad("profiles", "profile-1");
        let mut envelope = seal(&key, &a, b"payload").expect("seal");
        envelope[0] = ENVELOPE_VERSION.wrapping_add(1);
        let err = open(&key, &a, &envelope).unwrap_err();
        assert!(matches!(
            err,
            CryptoStoreError::UnsupportedVersion(v) if v == ENVELOPE_VERSION.wrapping_add(1)
        ));
    }

    #[test]
    fn tamper_flips_a_ciphertext_byte_and_fails() {
        let key = key_from_byte(0xAA);
        let a = aad("profiles", "profile-1");
        let mut envelope = seal(&key, &a, b"payload").expect("seal");
        let last = envelope.len() - 1;
        envelope[last] ^= 0x01;
        let err = open(&key, &a, &envelope).unwrap_err();
        assert!(matches!(err, CryptoStoreError::DecryptionFailed));
    }

    #[test]
    fn aad_table_mismatch_fails() {
        let key = key_from_byte(0xAA);
        let seal_aad = aad("profiles", "profile-1");
        let envelope = seal(&key, &seal_aad, b"payload").expect("seal");
        let open_aad = aad("quotes", "profile-1");
        let err = open(&key, &open_aad, &envelope).unwrap_err();
        assert!(matches!(err, CryptoStoreError::DecryptionFailed));
    }

    #[test]
    fn aad_pk_mismatch_fails() {
        let key = key_from_byte(0xAA);
        let seal_aad = aad("profiles", "profile-1");
        let envelope = seal(&key, &seal_aad, b"payload").expect("seal");
        let open_aad = aad("profiles", "profile-2");
        let err = open(&key, &open_aad, &envelope).unwrap_err();
        assert!(matches!(err, CryptoStoreError::DecryptionFailed));
    }

    /// Key-rotation canary: sealing under key A and opening under key B
    /// must fail (their `key_id`s differ, which changes the AAD), and the
    /// two keys' `key_id`s must themselves differ.
    #[test]
    fn key_rotation_canary() {
        let key_a = key_from_byte(0xAA);
        let key_b = key_from_byte(0xBB);
        assert_ne!(key_a.key_id(), key_b.key_id());

        let a = aad("profiles", "profile-1");
        let envelope = seal(&key_a, &a, b"payload").expect("seal");
        let err = open(&key_b, &a, &envelope).unwrap_err();
        assert!(matches!(err, CryptoStoreError::DecryptionFailed));
    }

    #[test]
    fn truncated_envelope_errors_without_panicking() {
        let key = key_from_byte(0xAA);
        let a = aad("profiles", "profile-1");
        for len in 0..MIN_ENVELOPE_LEN {
            let short = vec![0u8; len];
            let err = open(&key, &a, &short).unwrap_err();
            assert!(matches!(err, CryptoStoreError::EnvelopeTooShort { .. }));
        }
    }

    #[test]
    fn empty_envelope_errors_without_panicking() {
        let key = key_from_byte(0xAA);
        let a = aad("profiles", "profile-1");
        let err = open(&key, &a, &[]).unwrap_err();
        assert!(matches!(err, CryptoStoreError::EnvelopeTooShort { .. }));
    }

    #[test]
    fn from_hex_rejects_wrong_length() {
        let err = DataKey::from_hex("aabb").unwrap_err();
        assert!(matches!(err, CryptoStoreError::InvalidKeyLength(2)));
    }

    #[test]
    fn from_hex_rejects_invalid_hex() {
        let err = DataKey::from_hex("zzzz").unwrap_err();
        assert!(matches!(err, CryptoStoreError::InvalidHex(_)));
    }

    // -- SecretHex (Task 11 Wave 0) ---------------------------------------

    /// The load-bearing claim of `SecretHex`: it accepts **exactly** what
    /// `DataKey::from_hex` accepts and rejects exactly what it rejects, so
    /// `DataKey::from_secret` can be infallible. Asserted over the whole
    /// interesting input space rather than on one happy case, because the
    /// property is an equivalence, not an example.
    ///
    /// **Mutation this detects (run and confirmed):** giving
    /// `SecretHex::from_hex` its own validation — e.g. replacing the
    /// `decode_key_bytes(s)?` line with `if s.len() != 64 { ... }` — makes the
    /// uppercase and odd-length rows disagree and this test fails naming the
    /// input.
    #[test]
    fn secret_hex_accepts_exactly_what_data_key_accepts() {
        let cases = [
            &"aa".repeat(32), // 32 bytes lowercase
            &"AA".repeat(32), // 32 bytes uppercase
            &"aA".repeat(32), // mixed case
            &"aa".repeat(31), // 31 bytes — too short
            &"aa".repeat(33), // 33 bytes — too long
            &"zz".repeat(32), // right length, bad charset
            &"a".repeat(63),  // odd number of hex digits
            &String::new(),   // empty
        ];
        for case in cases {
            assert_eq!(
                DataKey::from_hex(case).is_ok(),
                SecretHex::from_hex(case).is_ok(),
                "SecretHex and DataKey disagreed on {case:?}"
            );
        }
        // Discriminating control: the table above is not all-reject.
        assert!(SecretHex::from_hex(&"aa".repeat(32)).is_ok());
        assert!(SecretHex::from_hex(&"aa".repeat(31)).is_err());
    }

    /// The error variants are the *same* variants, not merely "both are
    /// errors" — the startup path matches on `CryptoStoreError::InvalidKeyLength`
    /// to tell an operator what is wrong with their key.
    #[test]
    fn secret_hex_reports_the_same_error_variants_as_data_key() {
        assert!(matches!(
            SecretHex::from_hex("aabb").unwrap_err(),
            CryptoStoreError::InvalidKeyLength(2)
        ));
        assert!(matches!(
            SecretHex::from_hex("zzzz").unwrap_err(),
            CryptoStoreError::InvalidHex(_)
        ));
    }

    /// `SecretHex` carries a secret and must never render it — the same rule
    /// `DataKey` and `outbox::SignedRawTx` follow.
    ///
    /// **Mutation this detects (run and confirmed):** replacing the manual
    /// `Debug` impl with `#[derive(Debug)]` — `Zeroizing<String>`'s own `Debug`
    /// forwards to `String`, so the key hex appears verbatim and the first
    /// assertion fails.
    #[test]
    fn secret_hex_debug_redacts_the_key_and_still_identifies_it() {
        let hex_str = "ab".repeat(32);
        let secret = SecretHex::from_hex(&hex_str).expect("valid");
        let rendered = format!("{secret:?}");
        assert!(
            !rendered.contains(&hex_str),
            "SecretHex Debug leaked the key: {rendered}"
        );
        assert!(rendered.contains("<redacted>"), "{rendered}");
        // Paired positive arm: it still prints the non-secret identifier, so
        // the assertion above is not passing on an empty render.
        assert!(rendered.contains(&secret.key_id()), "{rendered}");
    }

    /// `SecretHex` round-trips to the *same* key `DataKey::from_hex` builds —
    /// same `key_id`, and envelopes seal/open across the two constructors.
    ///
    /// **Mutation this detects (applied, run, reverted):** making
    /// `SecretHex::from_hex` store something other than the caller's string —
    /// `Zeroizing::new(s.to_lowercase())`, i.e. plausible-looking
    /// normalization. The fixture below is deliberately **uppercase**: with a
    /// lowercase fixture that mutation is a no-op and this test would pass
    /// while claiming to detect it. `as_str` must be verbatim because
    /// `derive_domain_key` HMACs over bytes decoded from exactly this string,
    /// and a caller that stored one casing while the DB was indexed under
    /// another would silently fail to authenticate.
    #[test]
    fn secret_hex_produces_an_identical_data_key() {
        let hex_str = "CD".repeat(32);
        let secret = SecretHex::from_hex(&hex_str).expect("valid");
        assert_eq!(secret.as_str(), hex_str, "as_str must be verbatim");

        let via_secret = DataKey::from_secret(&secret);
        let via_hex = DataKey::from_hex(&hex_str).expect("valid");
        assert_eq!(via_secret.key_id(), via_hex.key_id());

        // Strongest form: an envelope sealed under one opens under the other.
        let a = aad("profiles", "profile-1");
        let envelope = seal(&via_secret, &a, b"payload").expect("seal");
        let opened = open(&via_hex, &a, &envelope).expect("open");
        assert_eq!(&opened[..], b"payload");

        // Discriminating control: a *different* secret does not.
        let other = SecretHex::from_hex(&"ce".repeat(32)).expect("valid");
        assert!(open(&DataKey::from_secret(&other), &a, &envelope).is_err());
    }
}
