//! Name resolution, the deny-net, and the pin.
//!
//! # The predicate is ALLOW-BY-EXCEPTION
//!
//! [`is_public_unicast`] permits an address only when it is ordinary global
//! unicast. Everything else is refused, **including everything nobody thought
//! of**. This is not a stylistic preference. An enumerated deny-range list is
//! only ever as good as the enumerator's imagination, and the enumeration this
//! predicate replaces missed three IPv6 transition forms that each reach the
//! cloud metadata address `169.254.169.254` through an address that **is**
//! globally routable and therefore passes every range check:
//!
//! * **NAT64 `64:ff9b::/96`** (RFC 6052) — `64:ff9b::a9fe:a9fe`. On any
//!   NAT64/DNS64 network, common on mobile and increasingly on residential
//!   ISPs, that routes straight to the metadata service.
//! * **6to4 `2002::/16`** — `2002:a9fe:a9fe::` embeds the same v4 and reaches
//!   it through a relay.
//! * **Deprecated IPv4-compatible `::a.b.c.d`** — `::a9fe:a9fe`, which
//!   `to_ipv4_mapped()` does not unwrap.
//!
//! Plus six IPv4 ranges the enumeration never had: multicast `224.0.0.0/4`,
//! reserved `240.0.0.0/4`, broadcast, benchmarking `198.18.0.0/15`, IETF
//! protocol assignments `192.0.0.0/24`, and the three TEST-NETs.
//!
//! So: unwrap the embedded v4 out of every transition form first and re-run the
//! v4 predicate on it; then permit v4 only inside the ordinary unicast band and
//! outside every special-use assignment, and v6 only inside `2000::/3` and
//! outside documentation and Teredo.
//!
//! # The pin
//!
//! [`resolve_and_pin`] is the only place a name becomes an address. It resolves
//! **once**, validates **every** address in the answer, and returns a
//! [`PinnedTarget`] carrying one `IpAddr`. The dial takes
//! [`PinnedTarget::socket_addr`] — a `SocketAddr`, never a name — so there is no
//! second lookup between the check and the connect for a rebinding answer to
//! win in. The consumer never supplies an address at any point.
//!
//! # Honest bound: a network-specific NAT64 prefix is not detectable
//!
//! RFC 6052 also permits *network-specific* NAT64 prefixes, which are drawn
//! from the operator's own global address space and are therefore
//! indistinguishable from ordinary global unicast without knowing the prefix.
//! This predicate covers the well-known prefix, 6to4, IPv4-mapped and
//! IPv4-compatible. It cannot cover a network-specific prefix and does not
//! claim to. Saying so here is the point: the gap is named rather than left for
//! a reader to assume it is closed.
//!
//! # Design authority
//!
//! The "Residential Proxy Network — Worker & Tunnel Spec (Tasks 18-36, 44, 45,
//! 47)", Task 30 and its Security invariants section (INV-2, INV-3); and the
//! "Residential Proxy Network (P3) Implementation Plan", §2 and §3.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::Mutex;

use crate::policy::{DenyReason, PolicyError};

/// The longest hostname DNS will carry, in bytes, excluding the root label.
const MAX_HOST_LEN: usize = 253;

/// The longest single DNS label, in bytes.
const MAX_LABEL_LEN: usize = 63;

// ---------------------------------------------------------------------------
// The address predicate
// ---------------------------------------------------------------------------

/// `true` only for an address this node may open a socket to.
///
/// Allow-by-exception: the two arms below describe what is *permitted*, and
/// anything that does not match — an unrecognised form, a future special-use
/// assignment, an address family nobody anticipated — falls through to `false`.
pub fn is_public_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_unicast_v4(v4),
        IpAddr::V6(v6) => match unwrap_embedded_v4(v6) {
            // A transition form is judged by what it actually reaches.
            Some(v4) => is_public_unicast_v4(v4),
            None => is_public_unicast_v6(v6),
        },
    }
}

/// `!is_public_unicast(ip)`.
///
/// Kept as its own name only so call sites read the way the invariant is
/// written ("the deny-net refuses it"). It carries no independent logic, which
/// is deliberate: two predicates would be two things to keep in agreement.
pub fn is_denied_net(ip: IpAddr) -> bool {
    !is_public_unicast(ip)
}

/// The IPv4 half, written as a band plus explicit special-use carve-outs.
fn is_public_unicast_v4(a: Ipv4Addr) -> bool {
    let o = a.octets();

    // The band IS the first exception filter, and it is what makes this
    // allow-by-exception rather than a range list. `0.0.0.0/8` ("this
    // network") sits below it; multicast `224.0.0.0/4`, reserved `240.0.0.0/4`
    // and the broadcast address all sit above it. A future assignment anywhere
    // in `224.0.0.0/3` is therefore refused by the band, with nobody having to
    // notice it was made.
    if !(1..=223).contains(&o[0]) {
        return false;
    }

    // Special-use assignments inside the band. Each is a carve-out FROM the
    // permitted set, never an entry in a set of denied things.
    let special = match o[0] {
        10 => true,                        // RFC 1918 private
        100 => (64..=127).contains(&o[1]), // RFC 6598 CGNAT 100.64/10
        127 => true,                       // loopback
        169 => o[1] == 254,                // link-local, incl. metadata
        172 => (16..=31).contains(&o[1]),  // RFC 1918 private 172.16/12
        192 => match (o[1], o[2]) {
            (0, 0) => true,   // IETF protocol assignments 192.0.0/24
            (0, 2) => true,   // TEST-NET-1 192.0.2/24
            (88, 99) => true, // deprecated 6to4 relay anycast
            (168, _) => true, // RFC 1918 private 192.168/16
            _ => false,
        },
        198 => match (o[1], o[2]) {
            (18 | 19, _) => true, // benchmarking 198.18/15
            (51, 100) => true,    // TEST-NET-2 198.51.100/24
            _ => false,
        },
        203 => o[1] == 0 && o[2] == 113, // TEST-NET-3
        _ => false,
    };

    !special
}

/// The IPv6 half. Only global unicast `2000::/3`, minus documentation and
/// Teredo.
fn is_public_unicast_v6(a: Ipv6Addr) -> bool {
    let s = a.segments();

    // The band. Unspecified, loopback, unique-local `fc00::/7`, link-local
    // `fe80::/10`, multicast `ff00::/8` and every unassigned block are all
    // outside `2000::/3` and are refused without being named.
    if (s[0] & 0xE000) != 0x2000 {
        return false;
    }

    // Documentation `2001:db8::/32`.
    if s[0] == 0x2001 && s[1] == 0x0db8 {
        return false;
    }
    // Teredo `2001::/32`.
    if s[0] == 0x2001 && s[1] == 0x0000 {
        return false;
    }
    // `2002::/16` is 6to4 and never reaches here: `unwrap_embedded_v4` claims
    // it first. The guard is kept so that deleting the unwrap cannot silently
    // turn 6to4 into ordinary global unicast.
    if s[0] == 0x2002 {
        return false;
    }

    true
}

/// The IPv4 address an IPv6 transition form actually reaches, if it is one.
///
/// Covers IPv4-mapped `::ffff:a.b.c.d`, the deprecated IPv4-compatible
/// `::a.b.c.d`, the NAT64 well-known prefix `64:ff9b::/96` (RFC 6052) and its
/// RFC 8215 local-use sibling `64:ff9b:1::/48`, and 6to4 `2002::/16`.
///
/// The unspecified address `::` and loopback `::1` are deliberately **not**
/// treated as IPv4-compatible: RFC 4291 excludes them, and both are refused by
/// the `2000::/3` band anyway, so reporting them as "an embedded 0.0.0.0" would
/// be a less true answer for no gain.
pub fn unwrap_embedded_v4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = v6.segments();

    // 6to4: the v4 is bits 16..48.
    if s[0] == 0x2002 {
        return Some(v4_from(s[1], s[2]));
    }

    // NAT64 well-known prefix `64:ff9b::/96`.
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
        return Some(v4_from(s[6], s[7]));
    }
    // RFC 8215 local-use NAT64 `64:ff9b:1::/48`, at the RFC 6052 §2.2 /48
    // embedding: the v4 straddles the reserved "u" octet at bits 64..72.
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001 {
        let b = v6.octets();
        return Some(Ipv4Addr::new(b[6], b[7], b[9], b[10]));
    }

    // Everything else must have 80 leading zero bits.
    if s[0] != 0 || s[1] != 0 || s[2] != 0 || s[3] != 0 || s[4] != 0 {
        return None;
    }

    // IPv4-mapped `::ffff:a.b.c.d`.
    if s[5] == 0xffff {
        return Some(v4_from(s[6], s[7]));
    }

    // IPv4-compatible `::a.b.c.d`, excluding `::` and `::1`.
    if s[5] == 0 && !(s[6] == 0 && (s[7] == 0 || s[7] == 1)) {
        return Some(v4_from(s[6], s[7]));
    }

    None
}

fn v4_from(hi: u16, lo: u16) -> Ipv4Addr {
    Ipv4Addr::new(
        (hi >> 8) as u8,
        (hi & 0xff) as u8,
        (lo >> 8) as u8,
        (lo & 0xff) as u8,
    )
}

// ---------------------------------------------------------------------------
// Host literals
// ---------------------------------------------------------------------------

/// Classify a request host: a canonical IP literal, a syntactically valid
/// hostname, or a refusal.
///
/// * `Ok(Some(ip))` — the host is an IP address written the one canonical way.
/// * `Ok(None)` — the host is a syntactically valid DNS name.
/// * `Err(Denied(NonCanonicalIpLiteral))` — the host is an address written some
///   other way: decimal, hex, octal, leading-zero octets, a short form,
///   bracketed, or carrying the FQDN root dot.
/// * `Err(Denied(MalformedHost))` — the host is neither.
///
/// # Why the alternate encodings are a refusal and not a normalisation
///
/// A permissive parser that *normalises* `0xA9FEA9FE` into `169.254.169.254`
/// hands the deny-net an address to judge — but only **after** the allowlist has
/// already matched the string as though it were a hostname. Refusing the
/// encoding outright means the question never arises. The trailing-dot form is
/// refused for the mirror-image reason: `example.com.` resolves identically to
/// `example.com` while defeating a string-equality allowlist match.
pub fn parse_canonical_ip_literal(host: &str) -> Result<Option<IpAddr>, PolicyError> {
    let deny = |r: DenyReason| -> PolicyError { PolicyError::Denied(r) };

    if host.is_empty() || host.len() > MAX_HOST_LEN {
        return Err(deny(DenyReason::MalformedHost));
    }
    if !host.is_ascii() {
        // Internationalised names must arrive already in A-label form; a
        // Unicode host is a second spelling of a name the allowlist matched on
        // its ASCII one.
        return Err(deny(DenyReason::MalformedHost));
    }
    if host.bytes().any(|b| {
        b.is_ascii_control() || matches!(b, b' ' | b'@' | b'/' | b'\\' | b'?' | b'#' | b'%')
    }) {
        return Err(deny(DenyReason::MalformedHost));
    }

    // Brackets are a URL artifact. Accepting them here would mean this function
    // owns two spellings of the same address.
    if host.contains('[') || host.contains(']') {
        return Err(deny(DenyReason::NonCanonicalIpLiteral));
    }

    // The FQDN root dot, for names as well as for literals.
    if host.ends_with('.') {
        return Err(deny(DenyReason::NonCanonicalIpLiteral));
    }

    let lowered = host.to_ascii_lowercase();

    // IPv6, unbracketed. A host field carrying a port is malformed here: the
    // port is a separate field of `ProxyRequest` and is gated separately.
    if lowered.contains(':') {
        return match Ipv6Addr::from_str(&lowered) {
            Ok(v6) if v6.to_string() == lowered => Ok(Some(IpAddr::V6(v6))),
            Ok(_) => Err(deny(DenyReason::NonCanonicalIpLiteral)),
            Err(_) => Err(deny(DenyReason::MalformedHost)),
        };
    }

    let parts: Vec<&str> = lowered.split('.').collect();
    if parts.iter().any(|p| p.is_empty()) {
        return Err(deny(DenyReason::MalformedHost));
    }

    // If EVERY dot-separated part is something `inet_aton` would read as a
    // number, the host is an IPv4 literal attempt in some encoding. Requiring
    // *every* part to be numeric is what keeps `cafe.example.com` — whose first
    // label is entirely hex digits — a hostname.
    if parts.iter().all(|p| is_inet_aton_numeric(p)) {
        if parts.len() == 4 && parts.iter().all(|p| is_canonical_decimal_octet(p)) {
            let octets: Vec<u8> = parts.iter().map(|p| p.parse::<u8>().unwrap()).collect();
            return Ok(Some(IpAddr::V4(Ipv4Addr::new(
                octets[0], octets[1], octets[2], octets[3],
            ))));
        }
        return Err(deny(DenyReason::NonCanonicalIpLiteral));
    }

    // A hostname, then — but only if it is a well-formed one.
    for label in &parts {
        if label.len() > MAX_LABEL_LEN
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(deny(DenyReason::MalformedHost));
        }
    }
    Ok(None)
}

/// Would `inet_aton` read this part as a number? Decimal, octal (leading zero)
/// or hex (`0x` prefix).
fn is_inet_aton_numeric(p: &str) -> bool {
    if let Some(hex) = p.strip_prefix("0x") {
        return !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit());
    }
    !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())
}

/// Exactly one spelling: decimal, no leading zero unless the part IS `0`, and
/// in range.
fn is_canonical_decimal_octet(p: &str) -> bool {
    if p.len() > 1 && p.starts_with('0') {
        return false;
    }
    p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u8>().is_ok()
}

// ---------------------------------------------------------------------------
// Resolvers
// ---------------------------------------------------------------------------

/// Name resolution, behind a seam so the pin can be tested without a network.
pub trait Resolver: Send + Sync {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, PolicyError>;
}

/// The operating system's resolver.
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, PolicyError> {
        // Port 0: this is a name lookup, not a connect. The port that ends up
        // in the `SocketAddr` comes from the policy's port gate, never from
        // anything the resolver returns.
        match (host, 0u16).to_socket_addrs() {
            Ok(iter) => Ok(iter.map(|sa| sa.ip()).collect()),
            Err(_) => Err(PolicyError::Denied(DenyReason::ResolutionFailed)),
        }
    }
}

/// A resolver that answers the same way every time.
///
/// A test double, shipped in production source because the policy holds its
/// resolver behind `Arc<dyn Resolver>` and the integration suites construct one.
pub struct FixedResolver {
    answer: Vec<IpAddr>,
}

impl FixedResolver {
    pub fn new(answer: Vec<IpAddr>) -> Self {
        Self { answer }
    }
}

impl Resolver for FixedResolver {
    fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, PolicyError> {
        Ok(self.answer.clone())
    }
}

/// A resolver that answers from a queue, one answer per call.
///
/// This is how a rebinding DNS server is modelled: the same name resolves to a
/// public address the first time and to something inside the deny-net the
/// second. [`SequencedResolver::remaining`] is what lets a test assert **how
/// many** resolutions happened, which is the only way to prove a second lookup
/// did not occur.
pub struct SequencedResolver {
    answers: Mutex<VecDeque<Vec<IpAddr>>>,
}

impl SequencedResolver {
    pub fn new(answers: Vec<Vec<IpAddr>>) -> Self {
        Self {
            answers: Mutex::new(answers.into_iter().collect()),
        }
    }

    /// Answers not yet handed out.
    pub fn remaining(&self) -> usize {
        self.answers.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl Resolver for SequencedResolver {
    fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, PolicyError> {
        let mut q = self.answers.lock().unwrap_or_else(|e| e.into_inner());
        // An exhausted queue is a refusal, not a repeat of the last answer.
        // Fail closed even in a test double.
        q.pop_front()
            .ok_or(PolicyError::Denied(DenyReason::ResolutionFailed))
    }
}

// ---------------------------------------------------------------------------
// The pin
// ---------------------------------------------------------------------------

/// One validated destination: the address that was checked IS the address that
/// will be dialled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedTarget {
    /// Which allowlist entry authorised this. The only destination identifier
    /// that may ever reach a receipt.
    pub entry_id: u32,
    /// The allowlisted name, carried for TLS SNI and the `Host` header. It is
    /// the name the **policy** matched, never a consumer-supplied string.
    pub host: String,
    pub port: u16,
    pub ip: IpAddr,
}

impl PinnedTarget {
    /// The dial target. A `SocketAddr`, so the connect cannot re-resolve.
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.port)
    }

    /// The name to present in TLS SNI and in the `Host` header.
    pub fn sni_name(&self) -> &str {
        &self.host
    }
}

/// Resolve once, validate every answer, pin one address.
///
/// Three properties, all load-bearing:
///
/// 1. **One resolution.** The caller does not get a name back, so there is
///    nothing left to look up.
/// 2. **Every address, not the first.** If any address in the answer is in the
///    deny-net the whole answer is refused. Discarding the poisoned entries and
///    using the rest is exactly how a split-horizon rebind wins.
/// 3. **An empty answer is a refusal.** Not an empty success that a later
///    `is_empty()` might read as "nothing objectionable found".
pub fn resolve_and_pin(
    resolver: &dyn Resolver,
    host: &str,
    port: u16,
    entry_id: u32,
) -> Result<PinnedTarget, PolicyError> {
    let addrs = resolver.resolve(host)?;

    if addrs.is_empty() {
        return Err(PolicyError::Denied(DenyReason::NoResolvedAddress));
    }
    if addrs.iter().any(|a| is_denied_net(*a)) {
        return Err(PolicyError::Denied(DenyReason::DeniedNetwork));
    }

    Ok(PinnedTarget {
        entry_id,
        host: host.to_string(),
        port,
        ip: addrs[0],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    /// Mutations this detects:
    /// - any single denied class becoming reachable (each has its own vector)
    /// - the CGNAT 100.64/10 range narrowed to 100.64/16 (100.127.255.255 escapes)
    /// - fc00::/7 narrowed to fd00::/8 (fc00::1 escapes)
    /// - the predicate rewritten as a deny-LIST, under which anything unlisted passes
    #[test]
    fn denied_nets_refused_canonical() {
        let denied = [
            "0.0.0.0",
            "127.0.0.1",
            "127.255.255.255",
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.255.255",
            "100.64.0.1",
            "100.127.255.255",
            "169.254.0.1",
            "169.254.169.254",
            // v4 classes an enumerated deny-list did not have.
            "224.0.0.1",
            "239.255.255.255", // multicast
            "240.0.0.1",
            "255.255.255.255", // reserved / broadcast
            "198.18.0.1",
            "198.19.255.255", // benchmarking
            "192.0.0.1",      // IETF protocol assignments
            "192.0.2.10",
            "198.51.100.7",
            "203.0.113.9", // TEST-NET-1/2/3
            "::",
            "::1",
            "fc00::1",
            "fd00::1",
            "fe80::1",
            "ff02::1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
            "2001:db8::1", // documentation
            "2001::1",     // Teredo
            // THE THREE TRANSITION FORMS. Each is globally routable and each embeds
            // the cloud metadata address.
            "64:ff9b::a9fe:a9fe", // NAT64
            "2002:a9fe:a9fe::",   // 6to4
            "::a9fe:a9fe",        // IPv4-compatible (deprecated)
        ];
        for d in denied {
            let ip: IpAddr = d.parse().unwrap();
            assert!(is_denied_net(ip), "{d} must be denied");
        }

        // NEGATIVE CONTROL: without these, an `is_denied_net` that returned `true`
        // unconditionally would pass the loop above.
        let allowed = [
            "93.184.216.34",
            "151.101.1.140",
            "1.1.1.1",
            "8.8.8.8",
            "172.32.0.1",      // just outside 172.16/12
            "100.128.0.1",     // just outside 100.64/10
            "169.253.255.255", // just outside 169.254/16
            "198.20.0.1",      // just outside 198.18/15
            "2606:2800:220:1:248:1893:25c8:1946",
        ];
        for a in allowed {
            let ip: IpAddr = a.parse().unwrap();
            assert!(!is_denied_net(ip), "{a} must NOT be denied");
        }
    }

    /// Mutations this detects: the transition-form unwrap deleted, so a globally
    /// routable v6 address carrying an embedded private or link-local v4 is treated
    /// as an ordinary public address.
    #[test]
    fn v6_transition_forms_are_unwrapped_to_their_embedded_v4_before_the_check() {
        let cases = [
            ("64:ff9b::a9fe:a9fe", "169.254.169.254"),
            ("64:ff9b::7f00:1", "127.0.0.1"),
            ("2002:a9fe:a9fe::", "169.254.169.254"),
            ("2002:0a00:0001::", "10.0.0.1"),
            ("::a9fe:a9fe", "169.254.169.254"),
            ("::ffff:169.254.169.254", "169.254.169.254"),
        ];
        for (v6, v4) in cases {
            let embedded = unwrap_embedded_v4(v6.parse().unwrap())
                .unwrap_or_else(|| panic!("{v6} must unwrap"));
            assert_eq!(embedded.to_string(), v4, "{v6}");
            assert!(
                is_denied_net(v6.parse::<IpAddr>().unwrap()),
                "{v6} must be denied"
            );
        }
        // NEGATIVE CONTROL: a transition form carrying a PUBLIC v4 is still allowed,
        // so the unwrap is not simply denying every v6 address it touches.
        assert!(!is_denied_net(
            "::ffff:93.184.216.34".parse::<IpAddr>().unwrap()
        ));
        assert!(
            unwrap_embedded_v4("2606:2800:220:1:248:1893:25c8:1946".parse().unwrap()).is_none()
        );
    }

    /// The property that makes the predicate safe against the vector nobody listed.
    ///
    /// Mutations this detects: `is_public_unicast` rewritten as a deny-list, under
    /// which an unrecognised address family or a future special-use range passes.
    #[test]
    fn is_public_unicast_is_allow_by_exception_not_a_range_list() {
        // A v6 address outside 2000::/3 is refused WITHOUT being enumerated anywhere.
        for outside in ["4000::1", "8000::1", "c000::1", "1000::1", "0100::1"] {
            assert!(
                !is_public_unicast(outside.parse::<IpAddr>().unwrap()),
                "{outside} is outside 2000::/3 and must be refused by default"
            );
        }
        // POSITIVE CONTROL: an ordinary global-unicast v6 address is still permitted.
        assert!(is_public_unicast(
            "2606:2800:220:1:248:1893:25c8:1946"
                .parse::<IpAddr>()
                .unwrap()
        ));
    }

    /// Mutations this detects:
    /// - a permissive host parser that normalizes octal/decimal/hex IPv4 forms into
    ///   an address the deny-net check then evaluates AFTER the allowlist already
    ///   matched a hostname
    /// - the trailing-dot form accepted, which bypasses a string-equality allowlist
    ///   while resolving to the same address
    #[test]
    fn non_canonical_ip_literals_refused() {
        let bad = [
            "2852039166",          // decimal 169.254.169.254
            "0xA9FEA9FE",          // hex 169.254.169.254
            "0251.0376.0251.0376", // octal 169.254.169.254
            "2130706433",          // decimal 127.0.0.1
            "0177.0.0.1",          // octal 127.0.0.1
            "010.0.0.1",           // leading-zero octet
            "169.254.169.254.",    // trailing dot
            "[::ffff:a9fe:a9fe]",  // bracketed v4-mapped
            "127.1",               // short form
            "0",                   // shortest form of 0.0.0.0
        ];
        for b in bad {
            match parse_canonical_ip_literal(b) {
                Err(PolicyError::Denied(DenyReason::NonCanonicalIpLiteral)) => {}
                other => panic!("{b} must be rejected as non-canonical; got {other:?}"),
            }
        }
        // NEGATIVE CONTROL: canonical literals parse, hostnames return None.
        assert_eq!(
            parse_canonical_ip_literal("93.184.216.34").unwrap(),
            Some("93.184.216.34".parse::<IpAddr>().unwrap())
        );
        assert_eq!(parse_canonical_ip_literal("example.com").unwrap(), None);
    }

    /// The hostname arm, which the vector list above only exercises twice.
    ///
    /// Mutations this detects: the all-parts-numeric rule weakened to
    /// any-part-numeric, which would classify `cafe.example.com` as an address
    /// attempt and refuse an ordinary name; and the syntactic gate deleted, which
    /// would let a host carrying userinfo, a path separator or a control byte reach
    /// the allowlist matcher.
    #[test]
    fn a_hostname_is_a_hostname_and_a_malformed_host_is_a_refusal() {
        // POSITIVE CONTROL: names whose labels are entirely hex digits, or
        // entirely digits, are still names.
        for name in [
            "example.com",
            "cafe.example.com",
            "beef.dead.example.org",
            "1234.example.net",
            "a-b.example.com",
        ] {
            assert_eq!(
                parse_canonical_ip_literal(name).unwrap(),
                None,
                "{name} is a hostname"
            );
        }

        for bad in [
            "",
            "user@example.com",
            "example.com/admin",
            "example.com:443",
            "exa mple.com",
            "example..com",
            ".example.com",
            "-example.com",
            "example.com\r\nX",
            "exämple.com",
            "example.com#frag",
            "example.com?q=1",
            "example.com%2fadmin",
        ] {
            assert!(
                matches!(
                    parse_canonical_ip_literal(bad),
                    Err(PolicyError::Denied(
                        DenyReason::MalformedHost | DenyReason::NonCanonicalIpLiteral
                    ))
                ),
                "{bad:?} must be refused; got {:?}",
                parse_canonical_ip_literal(bad)
            );
        }
    }

    /// Mutations this detects: the `to_ipv4_mapped()` unwrap removed, so
    /// `::ffff:10.0.0.1` is treated as an ordinary global v6 address.
    #[test]
    fn ipv4_mapped_v6_is_unwrapped_before_deny_check() {
        for m in [
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:100.64.0.1",
        ] {
            assert!(
                is_denied_net(m.parse().unwrap()),
                "{m} must be denied after unwrapping"
            );
        }
        assert!(
            !is_denied_net("::ffff:93.184.216.34".parse::<IpAddr>().unwrap()),
            "negative control: a mapped PUBLIC v4 must not be denied"
        );
    }

    /// Mutations this detects: `addrs.retain(|a| !is_denied(*a))` in place of
    /// `any(is_denied)` -- i.e. silently discarding the poisoned answers and using
    /// the rest, which is exactly how a split-horizon rebind wins.
    #[test]
    fn any_denied_address_denies_the_whole_answer() {
        let r = FixedResolver::new(vec![
            "93.184.216.34".parse().unwrap(),
            "10.0.0.7".parse().unwrap(),
        ]);
        assert!(matches!(
            resolve_and_pin(&r, "mixed.example.com", 443, 1),
            Err(PolicyError::Denied(DenyReason::DeniedNetwork))
        ));
        // Positive control: an all-public answer pins.
        let ok = FixedResolver::new(vec!["93.184.216.34".parse().unwrap()]);
        let t = resolve_and_pin(&ok, "good.example.com", 443, 1).expect("must pin");
        assert_eq!(t.ip, "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(t.sni_name(), "good.example.com");
    }

    /// Mutations this detects: re-resolving after the allowlist check, which is the
    /// classic rebind window.
    #[test]
    fn a_rebinding_answer_is_denied_after_the_allowlist_passes() {
        let r = SequencedResolver::new(vec![
            vec!["93.184.216.34".parse().unwrap()],
            vec!["10.0.0.7".parse().unwrap()],
        ]);
        let first =
            resolve_and_pin(&r, "rebind.example.com", 443, 1).expect("first answer is public");
        assert_eq!(first.ip, "93.184.216.34".parse::<IpAddr>().unwrap());
        assert!(matches!(
            resolve_and_pin(&r, "rebind.example.com", 443, 1),
            Err(PolicyError::Denied(DenyReason::DeniedNetwork))
        ));
        assert_eq!(
            r.remaining(),
            0,
            "the queue proves exactly two resolutions happened"
        );
    }

    #[test]
    fn an_empty_resolution_is_a_refusal_not_an_empty_success() {
        let r = FixedResolver::new(vec![]);
        assert!(matches!(
            resolve_and_pin(&r, "nowhere.example.com", 443, 1),
            Err(PolicyError::Denied(DenyReason::NoResolvedAddress))
        ));
    }

    /// The pin's own property, stated on the type rather than on a comment.
    ///
    /// Mutations this detects: `socket_addr()` rebuilt from the host string
    /// (`(self.host.as_str(), self.port).to_socket_addrs()`), which reintroduces a
    /// second lookup between the check and the connect; and `sni_name()` returning
    /// anything other than the name the policy matched.
    #[test]
    fn connect_uses_the_pinned_ip_not_a_second_lookup() {
        let r = SequencedResolver::new(vec![
            vec!["93.184.216.34".parse().unwrap()],
            // A second answer is queued and MUST remain unconsumed: nothing
            // downstream of the pin is allowed to look the name up again.
            vec!["10.0.0.7".parse().unwrap()],
        ]);
        let t = resolve_and_pin(&r, "pinned.example.com", 443, 7).expect("pins");

        let dialled = t.socket_addr();
        assert_eq!(dialled.ip(), "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(dialled.port(), 443);
        assert_eq!(t.entry_id, 7);
        assert_eq!(t.sni_name(), "pinned.example.com");

        // Calling it repeatedly is stable and consumes no further answer.
        for _ in 0..5 {
            assert_eq!(t.socket_addr(), dialled);
        }
        assert_eq!(
            r.remaining(),
            1,
            "exactly one resolution happened; a second lookup would have drained the queue"
        );
    }

    /// Mutations this detects: an exhausted sequenced resolver repeating its last
    /// answer instead of refusing, which would make every rebind test above pass
    /// for the wrong reason.
    #[test]
    fn an_exhausted_sequenced_resolver_refuses_rather_than_repeating() {
        let r = SequencedResolver::new(vec![vec!["93.184.216.34".parse().unwrap()]]);
        assert!(resolve_and_pin(&r, "once.example.com", 443, 1).is_ok());
        assert!(matches!(
            resolve_and_pin(&r, "once.example.com", 443, 1),
            Err(PolicyError::Denied(DenyReason::ResolutionFailed))
        ));
    }
}
