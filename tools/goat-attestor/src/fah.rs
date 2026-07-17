//! FAH public-stats reader: cached, rate-limited, fixture-testable.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Parsed FAH `/user/{name}` payload (fields we care about).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FahUserStats {
    pub name: String,
    pub id: u64,
    pub score: u64,
    pub wus: u64,
    #[serde(default)]
    pub rank: u64,
    #[serde(default)]
    pub team: u64,
}

#[derive(Debug, Error)]
pub enum FahError {
    #[error("HTTP error {status}: {body}")]
    Http { status: u16, body: String },
    #[error("JSON parse error: {0}")]
    Json(String),
    #[error("missing required field: {0}")]
    MissingField(String),
    #[error("IO error: {0}")]
    Io(String),
    #[error("rate limited: retry after {0:?}")]
    RateLimited(Duration),
}

/// Minimal injectable HTTP GET for tests and fixtures.
pub trait HttpGet: Send + Sync {
    fn get(&self, url: &str) -> Result<(u16, String), FahError>;
}

/// Fixture-backed HTTP: maps `/user/GOAT-alice` / `/user/GOAT-bob` to fixture files.
#[derive(Debug, Clone)]
pub struct FixtureHttp {
    pub fixtures_dir: PathBuf,
}

impl FixtureHttp {
    pub fn new(fixtures_dir: impl Into<PathBuf>) -> Self {
        Self {
            fixtures_dir: fixtures_dir.into(),
        }
    }

    fn map_url_to_file(&self, url: &str) -> Option<PathBuf> {
        if url.contains("/user/GOAT-alice") {
            Some(self.fixtures_dir.join("fah_user_alice.json"))
        } else if url.contains("/user/GOAT-bob") {
            Some(self.fixtures_dir.join("fah_user_bob.json"))
        } else {
            None
        }
    }
}

impl HttpGet for FixtureHttp {
    fn get(&self, url: &str) -> Result<(u16, String), FahError> {
        match self.map_url_to_file(url) {
            Some(path) => {
                let body = std::fs::read_to_string(&path).map_err(|e| {
                    FahError::Io(format!("read {}: {e}", path.display()))
                })?;
                Ok((200, body))
            }
            None => Ok((404, format!("not found: {url}"))),
        }
    }
}

/// Parse FAH user JSON; requires a present `score` field (never silent 0).
pub fn parse_user_stats(body: &str) -> Result<FahUserStats, FahError> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| FahError::Json(e.to_string()))?;

    if v.get("score").is_none() || v.get("score").map(|s| s.is_null()).unwrap_or(true) {
        return Err(FahError::MissingField("score".into()));
    }

    let stats: FahUserStats =
        serde_json::from_value(v).map_err(|e| FahError::Json(e.to_string()))?;
    Ok(stats)
}

#[derive(Debug, Clone)]
struct CacheEntry {
    stats: FahUserStats,
    raw: String,
    fetched_at: Instant,
}

/// Cached + rate-limited FAH client.
pub struct FahClient<H: HttpGet> {
    http: H,
    base: String,
    min_interval: Duration,
    cache: Mutex<HashMap<String, CacheEntry>>,
    last_live_at: Mutex<Option<Instant>>,
    live_count: Mutex<u64>,
    cache_count: Mutex<u64>,
}

impl<H: HttpGet> FahClient<H> {
    pub fn new(http: H, base: impl Into<String>, min_interval: Duration) -> Self {
        Self {
            http,
            base: base.into().trim_end_matches('/').to_string(),
            min_interval,
            cache: Mutex::new(HashMap::new()),
            last_live_at: Mutex::new(None),
            live_count: Mutex::new(0),
            cache_count: Mutex::new(0),
        }
    }

    pub fn live_count(&self) -> u64 {
        *self.live_count.lock().unwrap()
    }

    pub fn cache_count(&self) -> u64 {
        *self.cache_count.lock().unwrap()
    }

    pub fn user_url(&self, username: &str) -> String {
        format!("{}/user/{}", self.base, username)
    }

    /// Fetch user stats. Returns cached value if still fresh within `min_interval`
    /// for the same user, and enforces a global min interval between live GETs.
    pub fn fetch_user(&self, username: &str) -> Result<FahUserStats, FahError> {
        let (stats, _) = self.fetch_user_with_raw(username)?;
        Ok(stats)
    }

    pub fn fetch_user_with_raw(&self, username: &str) -> Result<(FahUserStats, String), FahError> {
        {
            let cache = self.cache.lock().unwrap();
            if let Some(entry) = cache.get(username) {
                if entry.fetched_at.elapsed() < self.min_interval {
                    *self.cache_count.lock().unwrap() += 1;
                    return Ok((entry.stats.clone(), entry.raw.clone()));
                }
            }
        }

        // Global rate limit between live HTTP calls.
        {
            let last = self.last_live_at.lock().unwrap();
            if let Some(t) = *last {
                let elapsed = t.elapsed();
                if elapsed < self.min_interval {
                    return Err(FahError::RateLimited(self.min_interval - elapsed));
                }
            }
        }

        let url = self.user_url(username);
        let (status, body) = self.http.get(&url)?;
        if status != 200 {
            return Err(FahError::Http {
                status,
                body: body.clone(),
            });
        }
        let stats = parse_user_stats(&body)?;

        *self.last_live_at.lock().unwrap() = Some(Instant::now());
        *self.live_count.lock().unwrap() += 1;

        self.cache.lock().unwrap().insert(
            username.to_string(),
            CacheEntry {
                stats: stats.clone(),
                raw: body.clone(),
                fetched_at: Instant::now(),
            },
        );

        Ok((stats, body))
    }

    /// Force a live re-read, bypassing cache freshness (still rate-limited).
    pub fn fetch_user_fresh(&self, username: &str) -> Result<(FahUserStats, String), FahError> {
        self.cache.lock().unwrap().remove(username);
        self.fetch_user_with_raw(username)
    }
}

/// Shared client type alias for Arc wrapping.
pub type SharedFahClient<H> = Arc<FahClient<H>>;

/// Resolve fixtures dir relative to crate (tests) or CWD.
pub fn default_fixtures_dir() -> PathBuf {
    // Prefer CARGO_MANIFEST_DIR/fixtures when available (tests).
    if let Ok(m) = std::env::var("CARGO_MANIFEST_DIR") {
        let p = Path::new(&m).join("fixtures");
        if p.exists() {
            return p;
        }
    }
    PathBuf::from("fixtures")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn parse_alice_score() {
        let body = r#"{"name":"GOAT-alice","id":1001,"score":51022340,"wus":2114,"rank":50,"team":1068318}"#;
        let s = parse_user_stats(body).unwrap();
        assert_eq!(s.score, 51_022_340);
        assert_eq!(s.name, "GOAT-alice");
        assert_eq!(s.wus, 2114);
    }

    #[test]
    fn missing_score_errors() {
        let body = r#"{"name":"GOAT-alice","id":1001,"wus":2114}"#;
        let err = parse_user_stats(body).unwrap_err();
        match err {
            FahError::MissingField(f) => assert_eq!(f, "score"),
            other => panic!("expected MissingField, got {other:?}"),
        }
    }

    #[test]
    fn fixture_http_alice() {
        let http = FixtureHttp::new(default_fixtures_dir());
        let (status, body) = http
            .get("https://api.foldingathome.org/user/GOAT-alice")
            .unwrap();
        assert_eq!(status, 200);
        let s = parse_user_stats(&body).unwrap();
        assert_eq!(s.score, 51_022_340);
    }

    #[test]
    fn fixture_http_unknown_404() {
        let http = FixtureHttp::new(default_fixtures_dir());
        let (status, _) = http
            .get("https://api.foldingathome.org/user/GOAT-nobody")
            .unwrap();
        assert_eq!(status, 404);
    }

    struct CountingHttp {
        hits: AtomicUsize,
        body: String,
    }

    impl HttpGet for CountingHttp {
        fn get(&self, _url: &str) -> Result<(u16, String), FahError> {
            self.hits.fetch_add(1, Ordering::SeqCst);
            Ok((200, self.body.clone()))
        }
    }

    #[test]
    fn cache_hit() {
        let body = r#"{"name":"GOAT-alice","id":1001,"score":51022340,"wus":2114,"rank":50,"team":1068318}"#;
        let http = CountingHttp {
            hits: AtomicUsize::new(0),
            body: body.into(),
        };
        let client = FahClient::new(http, "https://example.test", Duration::from_secs(60));
        let a = client.fetch_user("GOAT-alice").unwrap();
        let b = client.fetch_user("GOAT-alice").unwrap();
        assert_eq!(a.score, b.score);
        assert_eq!(client.live_count(), 1);
        assert_eq!(client.cache_count(), 1);
        // CountingHttp only hit once
        // (second call served from cache)
    }

    #[test]
    fn rate_limit_min_interval() {
        let body = r#"{"name":"GOAT-alice","id":1001,"score":1,"wus":1,"rank":1,"team":1}"#;
        let http = CountingHttp {
            hits: AtomicUsize::new(0),
            body: body.into(),
        };
        let client = FahClient::new(http, "https://example.test", Duration::from_secs(60));
        client.fetch_user("GOAT-alice").unwrap();
        // Different user, but global min_interval should fire
        let err = client.fetch_user("GOAT-bob").unwrap_err();
        match err {
            FahError::RateLimited(_) => {}
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }
}
