//! Live HTTP GET for FAH public stats (blocking reqwest).

use reqwest::blocking::Client;
use std::time::Duration;

use crate::fah::{FahError, HttpGet};

/// Production FAH transport: blocking HTTP GET with a short timeout.
#[derive(Debug, Clone)]
pub struct LiveHttp {
    client: Client,
}

impl LiveHttp {
    pub fn new() -> Result<Self, FahError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("goat-attestor/0.1")
            .build()
            .map_err(|e| FahError::Io(format!("reqwest client: {e}")))?;
        Ok(Self { client })
    }
}

impl Default for LiveHttp {
    fn default() -> Self {
        Self::new().expect("LiveHttp default client")
    }
}

impl HttpGet for LiveHttp {
    fn get(&self, url: &str) -> Result<(u16, String), FahError> {
        let resp = self
            .client
            .get(url)
            .send()
            .map_err(|e| FahError::Io(format!("GET {url}: {e}")))?;
        let status = resp.status().as_u16();
        let body = resp
            .text()
            .map_err(|e| FahError::Io(format!("read body {url}: {e}")))?;
        Ok((status, body))
    }
}

/// Dispatch fixture vs live without forcing callers to be generic over both.
#[derive(Debug)]
pub enum AnyHttp {
    Fixture(crate::fah::FixtureHttp),
    Live(LiveHttp),
}

impl HttpGet for AnyHttp {
    fn get(&self, url: &str) -> Result<(u16, String), FahError> {
        match self {
            Self::Fixture(f) => f.get(url),
            Self::Live(l) => l.get(url),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fah::FixtureHttp;
    use std::path::PathBuf;

    #[test]
    fn any_http_fixture_path() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures");
        let http = AnyHttp::Fixture(FixtureHttp::new(dir));
        let (status, body) = http
            .get("https://api.foldingathome.org/user/GOAT-alice")
            .unwrap();
        assert_eq!(status, 200);
        assert!(body.contains("score") || body.contains("name"), "{body}");
    }
}
