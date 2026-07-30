//! In-memory per-wallet + global token-bucket rate limiter (H3).
//!
//! **Pilot residual (consultant #4):** restart resets buckets. Durable money bound
//! is `spend_ledger` (H2/H2b on disk, fail-closed) — not this module.

use std::collections::HashMap;
use std::time::Instant;

use thiserror::Error;

/// Pilot defaults (user task): 30/min per wallet, 120/min global.
pub const DEFAULT_WALLET_PER_MIN: u32 = 30;
pub const DEFAULT_GLOBAL_PER_MIN: u32 = 120;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RateLimitError {
    #[error("RateLimited: wallet")]
    Wallet,
    #[error("RateLimited: global")]
    Global,
}

struct Bucket {
    tokens: f64,
    last: Instant,
    capacity: f64,
    /// Tokens refilled per second.
    refill_per_sec: f64,
}

impl Bucket {
    fn new(capacity: u32, per_min: u32, now: Instant) -> Self {
        let cap = capacity as f64;
        Self {
            tokens: cap,
            last: now,
            capacity: cap,
            refill_per_sec: per_min as f64 / 60.0,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
            self.last = now;
        }
    }

    /// Try to consume one token. Returns false if empty after refill.
    fn try_take(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Per-wallet + global token buckets.
pub struct RateLimiter {
    wallet_capacity: u32,
    wallet_per_min: u32,
    global: Bucket,
    wallets: HashMap<String, Bucket>,
}

impl RateLimiter {
    pub fn new(wallet_per_min: u32, global_per_min: u32) -> Self {
        let now = Instant::now();
        Self {
            wallet_capacity: wallet_per_min,
            wallet_per_min,
            global: Bucket::new(global_per_min, global_per_min, now),
            wallets: HashMap::new(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_WALLET_PER_MIN, DEFAULT_GLOBAL_PER_MIN)
    }

    /// Consume one token from the wallet bucket and the global bucket.
    /// Both must succeed; on wallet failure, global is not consumed (check global second
    /// after a speculative wallet take — we reverse-order: global first would unfairly
    /// burn global on a wallet-limited client. Prefer: check wallet, then global, and
    /// only commit both when both would succeed.)
    pub fn check(&mut self, wallet_key: &str, now: Instant) -> Result<(), RateLimitError> {
        let key = wallet_key.to_ascii_lowercase();
        let wallet_cap = self.wallet_capacity;
        let wallet_per_min = self.wallet_per_min;

        // Refill + peek both without committing until both OK.
        {
            let w = self
                .wallets
                .entry(key.clone())
                .or_insert_with(|| Bucket::new(wallet_cap, wallet_per_min, now));
            w.refill(now);
            if w.tokens < 1.0 {
                return Err(RateLimitError::Wallet);
            }
        }
        self.global.refill(now);
        if self.global.tokens < 1.0 {
            return Err(RateLimitError::Global);
        }

        // Commit both.
        let w = self.wallets.get_mut(&key).expect("inserted above");
        let ok_w = w.try_take(now);
        let ok_g = self.global.try_take(now);
        debug_assert!(ok_w && ok_g);
        let _ = (ok_w, ok_g);
        Ok(())
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn allows_under_limit() {
        let mut rl = RateLimiter::new(3, 10);
        let t0 = Instant::now();
        for _ in 0..3 {
            rl.check("0xabc", t0).unwrap();
        }
    }

    #[test]
    fn blocks_over_wallet_limit() {
        let mut rl = RateLimiter::new(2, 100);
        let t0 = Instant::now();
        rl.check("0xabc", t0).unwrap();
        rl.check("0xabc", t0).unwrap();
        assert_eq!(rl.check("0xabc", t0), Err(RateLimitError::Wallet));
    }

    #[test]
    fn blocks_over_global_limit() {
        let mut rl = RateLimiter::new(100, 2);
        let t0 = Instant::now();
        rl.check("0xaaa", t0).unwrap();
        rl.check("0xbbb", t0).unwrap();
        assert_eq!(rl.check("0xccc", t0), Err(RateLimitError::Global));
    }

    #[test]
    fn independent_wallet_buckets() {
        let mut rl = RateLimiter::new(1, 100);
        let t0 = Instant::now();
        rl.check("0xaaa", t0).unwrap();
        assert_eq!(rl.check("0xaaa", t0), Err(RateLimitError::Wallet));
        // Different wallet still allowed.
        rl.check("0xbbb", t0).unwrap();
    }

    #[test]
    fn refills_over_time() {
        let mut rl = RateLimiter::new(1, 100);
        let t0 = Instant::now();
        rl.check("0xabc", t0).unwrap();
        assert_eq!(rl.check("0xabc", t0), Err(RateLimitError::Wallet));
        // 61 seconds later → full refill at 1/min.
        let t1 = t0 + Duration::from_secs(61);
        rl.check("0xabc", t1).unwrap();
    }
}
