//! `robots.txt` at the exit node, with RFC 9309 semantics chosen deliberately.
//!
//! # Origin path policy is enforced here, not by the consumer
//!
//! The consumer asks for a path. Whether the origin permits an automated agent
//! to fetch that path is not the consumer's decision, and it is not a courtesy:
//! it is the difference between an exit node and a scraping proxy. The check
//! runs at this node, over the **same pinned address** the request will use,
//! with the same name, and with no redirects.
//!
//! # RFC 9309 §2.3.1, and which way each failure falls
//!
//! * `2xx` — parse the body and apply the rules.
//! * `4xx` — "unavailable": the origin has no rules, so the fetch is
//!   **unrestricted**.
//! * `5xx`, a transport failure, a timeout, or a body past
//!   [`MAX_ROBOTS_BYTES`] — "unreachable": a **complete disallow**.
//!
//! The asymmetry is the standard's and it is the right way round: a 404 is a
//! positive statement that there are no rules; a 503 is the absence of any
//! statement, and acting on the absence of a statement is what a well-behaved
//! agent does not do.
//!
//! # The bytes are debited
//!
//! A robots fetch consumes the operator's connection. A fetch path that is not
//! charged against the ceiling they signed is an **uncapped** path, and
//! [`RobotsCache`]'s TTL refetches make it a recurring one. The debit lives in
//! the fetcher (see `fetch.rs`), and a ledger refusal there becomes
//! [`RobotsFetchOutcome::Unavailable`] — which §2.3.1 makes a complete disallow,
//! so running out of budget **closes** egress rather than opening it.
//!
//! # Design authority
//!
//! The "Residential Proxy Network — Worker & Tunnel Spec (Tasks 18-36, 44, 45,
//! 47)", Task 32 and its Security invariants section (INV-7).

use std::collections::HashMap;

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::policy::Scheme;
use crate::resolve::PinnedTarget;

/// The `User-Agent` this node presents, and the product token its `robots.txt`
/// groups are matched against.
///
/// **Founder decision D-6 is CLOSED and this is the ruled value.** The contact
/// is the URL below; the mailbox behind it is [`ROBOTS_CONTACT_MAILBOX`].
///
/// **This constant is only meaningful while that page resolves and that mailbox
/// is read by somebody.** An advertised contact that goes nowhere is *worse* for
/// abuse handling than no contact at all, and the reason is asymmetric: the
/// contact is where a service sends the complaint it would otherwise have sent
/// as a block. A dead address does not make the complaint disappear — it turns
/// a conversation into a silent refusal, and the operator whose home address is
/// in the origin's log is the one who pays for it. Whoever retires the page or
/// stops reading the mailbox retires this constant in the same change.
///
/// `the_user_agent_carries_the_ruled_crawler_contact` asserts the ruled value
/// and refuses the placeholder this constant used to hold.
pub const ROBOTS_UA: &str = "GoatCoin-Research-Fetcher/1.0 (+https://goatcoin.org/crawler-contact)";

/// The mailbox the contact page in [`ROBOTS_UA`] publishes.
///
/// Held as a constant, on the same domain as the URL, so that "the contact in
/// the header" and "the address a complaint is sent to" cannot be changed
/// independently of one another. It carries the same liveness obligation as
/// [`ROBOTS_UA`].
pub const ROBOTS_CONTACT_MAILBOX: &str = "crawler-contact@goatcoin.org";

/// The product token [`ROBOTS_UA`] is matched by, per RFC 9309 §2.2.1.
///
/// **Lower case, and that is load-bearing.** §2.2.1 matches product tokens
/// case-insensitively, and [`Rules::parse`] lower-cases the token it read out of
/// the file before testing it against this constant — so a mixed-case constant
/// would never match any group, and every origin's rules for this agent would be
/// silently skipped in favour of the wildcard group.
pub const ROBOTS_UA_PRODUCT_TOKEN: &str = "goatcoin-research-fetcher";

/// RFC 9309 §2.5 asks crawlers to parse at least 500 kibibytes. Anything past it
/// is treated as unreachable, which is a complete disallow — an origin that
/// answers `/robots.txt` with a gigabyte is not describing rules.
pub const MAX_ROBOTS_BYTES: usize = 512_000;

/// How long a parsed `robots.txt` is reused before it is fetched again.
pub const ROBOTS_TTL_SECS: u64 = 3_600;

/// What one fetch produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RobotsFetchOutcome {
    /// A `2xx` body, to be parsed.
    Body(String),
    /// `4xx`: the origin states there are no rules.
    AllowAll,
    /// `5xx`, transport failure, timeout, oversize, or a refused byte debit.
    /// **A complete disallow.**
    Unavailable,
}

/// Fetches one origin's `robots.txt`.
///
/// **`fetch` is `async`, and an implementation may not hold a runtime handle.**
/// A synchronous trait method that internally called `Handle::block_on` would
/// panic every time it ran, because it runs from `EgressPolicy::evaluate`,
/// called from `fetch_with_redirects`, on a tokio worker.
#[async_trait]
pub trait RobotsFetcher: Send + Sync {
    async fn fetch(&self, scheme: Scheme, target: &PinnedTarget) -> RobotsFetchOutcome;
}

/// The verdict for one path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RobotsVerdict {
    Allowed,
    /// A rule disallows this path for this agent.
    Disallowed,
    /// `robots.txt` could not be read. RFC 9309 §2.3.1 makes this a complete
    /// disallow; it is a separate verdict only so the operator's log can tell
    /// the two apart.
    Unavailable,
}

/// One origin's parsed rules, plus when they were fetched.
#[derive(Debug, Clone)]
struct Cached {
    rules: Rules,
    fetched_at_unix: u64,
}

/// A per-entry, per-scheme cache with a TTL.
///
/// Keyed on `(entry_id, scheme)` and **not** on the hostname: the entry id is
/// the only destination identifier this crate carries anywhere, and a cache
/// keyed on a name is a place a name gets written down.
pub struct RobotsCache {
    fetcher: Box<dyn RobotsFetcher>,
    ttl_secs: u64,
    entries: Mutex<HashMap<(u32, Scheme), Cached>>,
}

impl RobotsCache {
    pub fn new(fetcher: Box<dyn RobotsFetcher>) -> Self {
        Self::with_ttl(fetcher, ROBOTS_TTL_SECS)
    }

    pub fn with_ttl(fetcher: Box<dyn RobotsFetcher>, ttl_secs: u64) -> Self {
        Self {
            fetcher,
            ttl_secs,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// May this agent fetch `path` from this origin?
    ///
    /// A cache miss, or an entry older than the TTL, fetches. Note that the
    /// **failure** result is cached too: an origin that is returning 503 should
    /// not be hammered once per request, and caching a complete disallow is the
    /// safe direction to cache in.
    pub async fn allows(
        &self,
        scheme: Scheme,
        target: &PinnedTarget,
        path: &str,
        now_unix: u64,
    ) -> RobotsVerdict {
        let key = (target.entry_id, scheme);
        {
            let entries = self.entries.lock().await;
            if let Some(c) = entries.get(&key) {
                if now_unix.saturating_sub(c.fetched_at_unix) < self.ttl_secs {
                    return c.rules.verdict(path);
                }
            }
        }

        let rules = match self.fetcher.fetch(scheme, target).await {
            RobotsFetchOutcome::Body(body) => Rules::parse(&body),
            RobotsFetchOutcome::AllowAll => Rules::allow_all(),
            RobotsFetchOutcome::Unavailable => Rules::unavailable(),
        };
        let verdict = rules.verdict(path);
        self.entries.lock().await.insert(
            key,
            Cached {
                rules,
                fetched_at_unix: now_unix,
            },
        );
        verdict
    }
}

/// The rules that apply to **this** agent, after group selection.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Rules {
    /// `None` means `robots.txt` was unreachable.
    lines: Option<Vec<Rule>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Rule {
    allow: bool,
    /// The path pattern, with `*` and `$` as RFC 9309 §2.2.3 defines them.
    pattern: String,
}

impl Rules {
    fn allow_all() -> Self {
        Self {
            lines: Some(Vec::new()),
        }
    }

    fn unavailable() -> Self {
        Self { lines: None }
    }

    /// RFC 9309 §2.2: group the file by `user-agent` lines, then select the
    /// group whose product token matches this agent, falling back to `*`.
    ///
    /// Matching is case-insensitive (§2.2.1). A group with no matching token and
    /// no `*` fallback yields no rules, which is unrestricted — that is the
    /// standard's reading, and the fail-closed direction is reserved for
    /// *unreachable*, not for *silent about us*.
    fn parse(body: &str) -> Self {
        let mut named: Vec<Rule> = Vec::new();
        let mut wildcard: Vec<Rule> = Vec::new();
        let mut named_seen = false;
        let mut wildcard_seen = false;

        // Which group the lines currently being read belong to.
        let mut in_named = false;
        let mut in_wildcard = false;
        // A `user-agent` line directly after another starts one group, not two.
        let mut collecting_agents = false;

        for raw in body.lines() {
            let line = match raw.find('#') {
                Some(i) => &raw[..i],
                None => raw,
            }
            .trim();
            if line.is_empty() {
                continue;
            }
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim();

            match key.as_str() {
                "user-agent" => {
                    if !collecting_agents {
                        in_named = false;
                        in_wildcard = false;
                        collecting_agents = true;
                    }
                    let token = value.to_ascii_lowercase();
                    if token == "*" {
                        in_wildcard = true;
                        wildcard_seen = true;
                    } else if ROBOTS_UA_PRODUCT_TOKEN.starts_with(token.as_str())
                        && !token.is_empty()
                    {
                        in_named = true;
                        named_seen = true;
                    }
                }
                "allow" | "disallow" => {
                    collecting_agents = false;
                    let allow = key == "allow";
                    // An EMPTY `disallow` is "allow everything" (§2.2.2) and is
                    // not a rule matching the empty prefix -- which would match
                    // every path and disallow the whole origin.
                    if !allow && value.is_empty() {
                        continue;
                    }
                    if value.is_empty() {
                        continue;
                    }
                    let rule = Rule {
                        allow,
                        pattern: value.to_string(),
                    };
                    if in_named {
                        named.push(rule.clone());
                    }
                    if in_wildcard {
                        wildcard.push(rule);
                    }
                }
                _ => {
                    collecting_agents = false;
                }
            }
        }

        // The most specific group wins: a group naming this agent replaces the
        // wildcard group entirely rather than adding to it (§2.2.1).
        let lines = if named_seen {
            named
        } else if wildcard_seen {
            wildcard
        } else {
            Vec::new()
        };
        Self { lines: Some(lines) }
    }

    fn verdict(&self, path_and_query: &str) -> RobotsVerdict {
        let Some(rules) = &self.lines else {
            return RobotsVerdict::Unavailable;
        };
        // §2.2.2: the most specific match wins, measured by the number of
        // characters in the pattern; a tie goes to `allow`.
        let mut best: Option<&Rule> = None;
        for rule in rules {
            if !pattern_matches(&rule.pattern, path_and_query) {
                continue;
            }
            let wins = match best {
                None => true,
                Some(b) => {
                    rule.pattern.len() > b.pattern.len()
                        || (rule.pattern.len() == b.pattern.len() && rule.allow && !b.allow)
                }
            };
            if wins {
                best = Some(rule);
            }
        }
        match best {
            Some(r) if !r.allow => RobotsVerdict::Disallowed,
            _ => RobotsVerdict::Allowed,
        }
    }
}

/// RFC 9309 §2.2.3 path matching: `*` matches any run of characters, `$` at the
/// end anchors, and everything else is a literal prefix.
fn pattern_matches(pattern: &str, path: &str) -> bool {
    let (body, anchored) = match pattern.strip_suffix('$') {
        Some(b) => (b, true),
        None => (pattern, false),
    };

    let mut segments = body.split('*');
    let Some(first) = segments.next() else {
        return true;
    };
    if !path.starts_with(first) {
        return false;
    }
    let mut cursor = first.len();
    let mut had_wildcard = false;
    for seg in segments {
        had_wildcard = true;
        if seg.is_empty() {
            continue;
        }
        match path[cursor..].find(seg) {
            Some(i) => cursor += i + seg.len(),
            None => return false,
        }
    }
    if anchored {
        // With no wildcard the whole pattern must equal the path; with one, the
        // final literal must land at the end.
        if had_wildcard {
            return cursor == path.len();
        }
        return path.len() == body.len();
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    fn target() -> PinnedTarget {
        PinnedTarget {
            entry_id: 1,
            host: "example.com".to_string(),
            port: 443,
            ip: "93.184.216.34".parse::<IpAddr>().unwrap(),
        }
    }

    /// A fetcher that answers from a script and counts how many times it was
    /// asked, so "did the cache refetch" is observable rather than inferred.
    struct ScriptedFetcher {
        outcome: Mutex<RobotsFetchOutcome>,
        calls: Arc<AtomicU32>,
    }

    #[async_trait]
    impl RobotsFetcher for ScriptedFetcher {
        async fn fetch(&self, _s: Scheme, _t: &PinnedTarget) -> RobotsFetchOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.outcome.lock().await.clone()
        }
    }

    fn cache_over(outcome: RobotsFetchOutcome, ttl: u64) -> (RobotsCache, Arc<AtomicU32>) {
        let calls = Arc::new(AtomicU32::new(0));
        let f = ScriptedFetcher {
            outcome: Mutex::new(outcome),
            calls: calls.clone(),
        };
        (RobotsCache::with_ttl(Box::new(f), ttl), calls)
    }

    /// INV-7's fail-closed direction.
    ///
    /// Mutations this detects: `RobotsFetchOutcome::Unavailable` mapped onto
    /// `AllowAll`, or onto an empty rule set — both of which turn "the origin
    /// said nothing" into "the origin said yes".
    #[tokio::test]
    async fn robots_unavailable_is_a_complete_disallow() {
        let (cache, calls) = cache_over(RobotsFetchOutcome::Unavailable, ROBOTS_TTL_SECS);
        for path in ["/", "/abs/x", "/anything?q=1"] {
            assert_eq!(
                cache.allows(Scheme::Https, &target(), path, 1_000).await,
                RobotsVerdict::Unavailable,
                "path {path} was not a complete disallow"
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1, "the failure is cached too");

        // POSITIVE CONTROL: the same cache shape, given a reachable origin,
        // allows. Without it this test also passes against a cache that refuses
        // everything.
        let (ok, _) = cache_over(RobotsFetchOutcome::AllowAll, ROBOTS_TTL_SECS);
        assert_eq!(
            ok.allows(Scheme::Https, &target(), "/abs/x", 1_000).await,
            RobotsVerdict::Allowed
        );
    }

    /// RFC 9309 §2.3.1's other direction.
    ///
    /// Mutations this detects: 4xx folded in with 5xx as "could not fetch",
    /// which would refuse every origin that simply has no `robots.txt`.
    #[tokio::test]
    async fn robots_4xx_is_unrestricted() {
        let (cache, _) = cache_over(RobotsFetchOutcome::AllowAll, ROBOTS_TTL_SECS);
        for path in ["/", "/abs/x", "/private/secret"] {
            assert_eq!(
                cache.allows(Scheme::Https, &target(), path, 1_000).await,
                RobotsVerdict::Allowed
            );
        }

        // NEGATIVE CONTROL: a 200 body that disallows still disallows, so the
        // check above is reading the outcome and not returning `Allowed` blind.
        let (strict, _) = cache_over(
            RobotsFetchOutcome::Body("User-agent: *\nDisallow: /private/".into()),
            ROBOTS_TTL_SECS,
        );
        assert_eq!(
            strict
                .allows(Scheme::Https, &target(), "/private/secret", 1_000)
                .await,
            RobotsVerdict::Disallowed
        );
    }

    /// Mutations this detects: the TTL compared with `>` instead of `<`, which
    /// inverts it into "refetch while fresh, reuse while stale"; or the cache
    /// never expiring, which pins a disallow forever.
    #[tokio::test]
    async fn the_cache_honours_its_ttl_and_refetches_after_it() {
        let (cache, calls) = cache_over(RobotsFetchOutcome::AllowAll, 100);
        let t = target();

        cache.allows(Scheme::Https, &t, "/a", 1_000).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Inside the TTL: served from the cache.
        cache.allows(Scheme::Https, &t, "/b", 1_099).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1, "refetched while fresh");

        // At the TTL boundary and past it: refetched.
        cache.allows(Scheme::Https, &t, "/c", 1_100).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "did not refetch when stale"
        );
        cache.allows(Scheme::Https, &t, "/d", 5_000).await;
        assert_eq!(calls.load(Ordering::SeqCst), 3);

        // A DIFFERENT entry is a different cache key: one origin's rules are
        // never served for another's.
        let mut other = t.clone();
        other.entry_id = 2;
        cache.allows(Scheme::Https, &other, "/a", 5_000).await;
        assert_eq!(calls.load(Ordering::SeqCst), 4);
    }

    /// INV-7's "regardless of consumer instruction" half, at the robots seam.
    ///
    /// Mutations this detects: the path-scope check treated as authoritative and
    /// robots skipped when the scope allows — the two are independent gates and
    /// either one refusing is a refusal.
    #[tokio::test]
    async fn a_disallowed_prefix_is_refused_even_when_the_path_scope_allows_it() {
        let body = "User-agent: *\nDisallow: /data/private/\nAllow: /data/\n";
        let (cache, _) = cache_over(RobotsFetchOutcome::Body(body.into()), ROBOTS_TTL_SECS);
        let t = target();

        // `/data/` is inside the entry's declared prefix scope, and robots still
        // refuses the deeper path.
        assert_eq!(
            cache
                .allows(Scheme::Https, &t, "/data/private/x.json", 1_000)
                .await,
            RobotsVerdict::Disallowed
        );
        // POSITIVE CONTROL: the surrounding prefix is allowed, so the rule is
        // being applied by specificity and not blanket-refusing the origin.
        assert_eq!(
            cache
                .allows(Scheme::Https, &t, "/data/public.json", 1_000)
                .await,
            RobotsVerdict::Allowed
        );
    }

    /// Mutations this detects: group selection that ORs the wildcard group into
    /// the named one, so a permissive `*` group re-allows what our own group
    /// forbids.
    #[test]
    fn the_most_specific_user_agent_group_wins() {
        let body = "\
User-agent: *
Disallow: /

User-agent: goatcoin-research-fetcher
Disallow: /admin/
";
        let rules = Rules::parse(body);
        assert_eq!(rules.verdict("/abs/x"), RobotsVerdict::Allowed);
        assert_eq!(rules.verdict("/admin/x"), RobotsVerdict::Disallowed);

        // NEGATIVE CONTROL: with no group naming us, the wildcard group binds.
        let only_wildcard = Rules::parse("User-agent: *\nDisallow: /\n");
        assert_eq!(only_wildcard.verdict("/abs/x"), RobotsVerdict::Disallowed);
    }

    /// Mutations this detects: an empty `Disallow:` read as a rule matching the
    /// empty prefix, which matches every path and closes the whole origin; and
    /// `Allow`/`Disallow` ties resolved to disallow, which is the wrong way
    /// round in §2.2.2.
    #[test]
    fn rfc9309_rule_precedence_is_longest_match_then_allow() {
        let empty_disallow = Rules::parse("User-agent: *\nDisallow:\n");
        assert_eq!(empty_disallow.verdict("/anything"), RobotsVerdict::Allowed);

        let tie = Rules::parse("User-agent: *\nDisallow: /x/\nAllow: /x/\n");
        assert_eq!(tie.verdict("/x/y"), RobotsVerdict::Allowed);

        let longer = Rules::parse("User-agent: *\nAllow: /x/\nDisallow: /x/deep/\n");
        assert_eq!(longer.verdict("/x/y"), RobotsVerdict::Allowed);
        assert_eq!(longer.verdict("/x/deep/y"), RobotsVerdict::Disallowed);

        // Wildcards and the end anchor.
        let globbed = Rules::parse("User-agent: *\nDisallow: /*.pdf$\n");
        assert_eq!(globbed.verdict("/papers/a.pdf"), RobotsVerdict::Disallowed);
        assert_eq!(
            globbed.verdict("/papers/a.pdf?download=1"),
            RobotsVerdict::Allowed
        );

        // A comment is not a rule.
        let commented = Rules::parse("User-agent: *\n# Disallow: /\nAllow: /\n");
        assert_eq!(commented.verdict("/x"), RobotsVerdict::Allowed);
    }

    /// D-6 is CLOSED, and this constant carries the ruled contact.
    ///
    /// **This guard is INVERTED from the one it replaces.** While the decision
    /// was open, the test refused any spelling that looked resolved, because a
    /// fabricated address is worse than none. The founder has now ruled, so the
    /// same guard runs the other way: the PLACEHOLDER is what is refused, and
    /// the ruled value is asserted literally. A revert to
    /// "unresolved, founder decision D-6" is now the regression.
    ///
    /// Mutations this detects: the placeholder restored; the contact URL or the
    /// mailbox edited so the two name different domains, which is how one of
    /// them gets retired without the other; the product token left as the old
    /// crate name, which silently un-matches every `robots.txt` group that names
    /// this agent and hands the wildcard group authority over us; the product
    /// token written in mixed case, which never matches at all because
    /// `Rules::parse` compares a lower-cased token against it.
    #[test]
    fn the_user_agent_carries_the_ruled_crawler_contact() {
        assert_eq!(
            ROBOTS_UA,
            "GoatCoin-Research-Fetcher/1.0 (+https://goatcoin.org/crawler-contact)"
        );
        assert_eq!(ROBOTS_CONTACT_MAILBOX, "crawler-contact@goatcoin.org");

        // The placeholder is now the refused spelling.
        let placeholders = ["unresolved", "D-6", "founder decision", "TODO", "TBD"];
        for p in placeholders {
            assert!(
                !ROBOTS_UA.contains(p),
                "ROBOTS_UA has fallen back to the placeholder ({p}): {ROBOTS_UA}"
            );
        }
        // POSITIVE CONTROL: the scanner can see every one of those tokens when
        // they are present. A scanner with too small an alphabet reports a clean
        // constant.
        let control = "unresolved, founder decision D-6 TODO TBD";
        for p in placeholders {
            assert!(
                control.contains(p),
                "the scanner cannot see {p} in its own control string"
            );
        }

        // The contact is shaped like something a complaint can reach: the
        // conventional `(+URL)` form, an absolute https URL, and a mailbox on
        // the SAME domain, so the two cannot be retired independently.
        const CONTACT_DOMAIN: &str = "goatcoin.org";
        assert!(ROBOTS_UA.contains("(+https://"));
        assert!(ROBOTS_UA.contains(CONTACT_DOMAIN));
        assert!(ROBOTS_CONTACT_MAILBOX.ends_with(CONTACT_DOMAIN));
        assert!(ROBOTS_CONTACT_MAILBOX.contains('@'));

        // §2.2.1: the token this agent answers to is the UA's product token,
        // lower-cased, because the parser lower-cases before comparing.
        assert_eq!(
            ROBOTS_UA_PRODUCT_TOKEN,
            ROBOTS_UA_PRODUCT_TOKEN.to_ascii_lowercase()
        );
        assert!(ROBOTS_UA
            .to_ascii_lowercase()
            .starts_with(ROBOTS_UA_PRODUCT_TOKEN));

        // ...and a group naming that token really does bind, which is the
        // property a rename breaks silently.
        let named = Rules::parse(&format!(
            "User-agent: {ROBOTS_UA_PRODUCT_TOKEN}\nDisallow: /admin/\n\nUser-agent: *\nDisallow: /\n"
        ));
        assert_eq!(named.verdict("/open/x"), RobotsVerdict::Allowed);
        assert_eq!(named.verdict("/admin/x"), RobotsVerdict::Disallowed);
        // NEGATIVE CONTROL: the RETIRED token no longer selects a group, so the
        // wildcard `Disallow: /` binds. Without this the assertion above also
        // passes against a parser that matches everything.
        let retired = Rules::parse(
            "User-agent: goat-proxy-worker\nDisallow: /admin/\n\nUser-agent: *\nDisallow: /\n",
        );
        assert_eq!(retired.verdict("/open/x"), RobotsVerdict::Disallowed);

        // RFC 9309 §2.5's floor: a crawler parses at least 500 kibibytes.
        const _: () = assert!(MAX_ROBOTS_BYTES >= 500_000);
    }
}
