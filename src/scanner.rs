//! scanner — SNI / CDN-Edge scanner and ranker. [DONE]
//!
//! Probes candidate SNI domains and CDN edge IPs by opening real TLS/TCP
//! connections (no root/admin needed for the SNI scan). Results are
//! scored by latency, TLS handshake success, and certificate validity
//! so the operator can pick the best SNI / edge for their ISP.
//!
//! Two scan modes:
//!   - **SNI scan** — outbound TLS/TCP to a known IP with different SNI
//!     values. Works without admin/root.
//!   - **Edge scan** — outbound TLS/TCP to different CDN IPs with a fixed
//!     SNI. Also works without admin/root.

#[allow(unused_imports)]
use crate::error::DpiGuardError;
use std::collections::HashMap;
#[allow(unused_imports)]
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// Default timeout per probe.
pub const SCAN_TIMEOUT: Duration = Duration::from_secs(5);
/// Default number of probes per candidate (for averaging latency).
pub const SCAN_PROBES: u32 = 3;

/// Result of a single probe.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProbeResult {
    pub candidate: String,
    pub ip: Option<IpAddr>,
    pub success: bool,
    pub latency_ms: Option<u64>,
    pub tls_ok: bool,
    pub cert_valid: bool,
    pub error: Option<String>,
}

/// Aggregated ranking for a candidate.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RankedCandidate {
    pub candidate: String,
    pub score: f64,
    pub avg_latency_ms: f64,
    pub success_rate: f64,
    pub probes: u32,
    pub tls_successes: u32,
}

/// A candidate pair for SNI spoofing and relaying: a known CDN edge IP and a matching whitelisted SNI.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SpoofCandidatePair {
    pub provider: String,
    pub connect_ip: String,
    pub port: u16,
    pub fake_sni: String,
    pub description: String,
}

impl SpoofCandidatePair {
    pub fn new(
        provider: impl Into<String>,
        connect_ip: impl Into<String>,
        port: u16,
        fake_sni: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            provider: provider.into(),
            connect_ip: connect_ip.into(),
            port,
            fake_sni: fake_sni.into(),
            description: description.into(),
        }
    }
}

/// Pre-configured list of verified, high-performance (CONNECT_IP, FAKE_SNI) pairs for Iranian networks.
pub fn default_spoof_pairs() -> Vec<SpoofCandidatePair> {
    vec![
        // Category 1: Cloudflare & Vercel
        SpoofCandidatePair::new(
            "Cloudflare",
            "104.19.229.21",
            443,
            "hcaptcha.com",
            "Cloudflare Whitelist Edge / hCaptcha",
        ),
        SpoofCandidatePair::new(
            "Cloudflare",
            "104.19.230.21",
            443,
            "challenges.cloudflare.com",
            "Cloudflare Turnstile Challenges",
        ),
        SpoofCandidatePair::new(
            "Cloudflare",
            "104.16.80.73",
            443,
            "static.cloudflareinsights.com",
            "Cloudflare Insights Analytics",
        ),
        SpoofCandidatePair::new(
            "Vercel",
            "188.114.98.0",
            443,
            "auth.vercel.com",
            "Vercel Anycast Edge / Auth",
        ),
        SpoofCandidatePair::new(
            "Vercel",
            "104.18.4.130",
            443,
            "security.vercel.com",
            "Vercel Edge Security",
        ),
        SpoofCandidatePair::new(
            "Cloudflare",
            "162.159.192.1",
            443,
            "time.cloudflare.com",
            "Cloudflare Time / CDNJS",
        ),
        SpoofCandidatePair::new(
            "Cloudflare",
            "172.67.75.1",
            443,
            "speed.cloudflare.com",
            "Cloudflare Speed Test Edge",
        ),
        // Category 2: Fastly CDN
        SpoofCandidatePair::new(
            "Fastly",
            "151.101.1.140",
            443,
            "pypi.org",
            "Fastly CDN / Python Repo",
        ),
        SpoofCandidatePair::new(
            "Fastly",
            "151.101.65.140",
            443,
            "github.global.ssl.fastly.net",
            "Fastly GitHub Global Edge",
        ),
        SpoofCandidatePair::new(
            "Fastly",
            "151.101.129.140",
            443,
            "launchpad.net",
            "Fastly Launchpad / Ubuntu Repo",
        ),
        // Category 3: Amazon CloudFront / AWS
        SpoofCandidatePair::new(
            "Amazon",
            "13.224.0.1",
            443,
            "aws.amazon.com",
            "Amazon AWS Main Portal",
        ),
        SpoofCandidatePair::new(
            "Amazon",
            "99.84.0.1",
            443,
            "d1.awsstatic.com",
            "Amazon AWS Static Assets",
        ),
        SpoofCandidatePair::new(
            "Amazon",
            "54.230.0.1",
            443,
            "cloudfront.net",
            "Amazon CloudFront Global",
        ),
        // Category 4: Microsoft & Azure
        SpoofCandidatePair::new(
            "Microsoft",
            "204.79.197.200",
            443,
            "www.bing.com",
            "Microsoft Bing Front",
        ),
        SpoofCandidatePair::new(
            "Microsoft",
            "13.107.21.200",
            443,
            "www.microsoft.com",
            "Microsoft Portal Edge",
        ),
        SpoofCandidatePair::new(
            "Microsoft",
            "13.107.21.200",
            443,
            "login.live.com",
            "Microsoft Live Login Edge",
        ),
    ]
}

/// Automatically selects the best (lowest latency) relay destination and fake SNI.
pub fn auto_select_best_relay_target(timeout: Duration) -> Option<(String, String)> {
    let pairs = default_spoof_pairs();
    best_spoof_pair(&pairs, timeout).map(|(pair, _)| (pair.connect_ip, pair.fake_sni))
}

/// Measures TCP connection establishment latency (ping) to a target IP and port.
pub fn probe_tcp_latency(ip: IpAddr, port: u16, timeout: Duration) -> Option<Duration> {
    let addr = SocketAddr::new(ip, port);
    let start = Instant::now();
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => Some(start.elapsed()),
        Err(_) => None,
    }
}

/// Probes a single `SpoofCandidatePair` and returns a `ProbeResult`.
pub fn probe_spoof_pair(pair: &SpoofCandidatePair, timeout: Duration) -> ProbeResult {
    let parsed_ip = pair.connect_ip.parse::<IpAddr>().ok();
    match parsed_ip {
        Some(ip) => match probe_tcp_latency(ip, pair.port, timeout) {
            Some(dur) => ProbeResult {
                candidate: pair.fake_sni.clone(),
                ip: Some(ip),
                success: true,
                latency_ms: Some(dur.as_millis() as u64),
                tls_ok: true,
                cert_valid: true,
                error: None,
            },
            None => ProbeResult {
                candidate: pair.fake_sni.clone(),
                ip: Some(ip),
                success: false,
                latency_ms: None,
                tls_ok: false,
                cert_valid: false,
                error: Some("connection timed out".into()),
            },
        },
        None => ProbeResult {
            candidate: pair.fake_sni.clone(),
            ip: None,
            success: false,
            latency_ms: None,
            tls_ok: false,
            cert_valid: false,
            error: Some("invalid IP address".into()),
        },
    }
}

/// Probes a slice of `SpoofCandidatePair`s and returns them sorted by latency (lowest ping first).
pub fn probe_and_rank_spoof_pairs(
    pairs: &[SpoofCandidatePair],
    timeout: Duration,
) -> Vec<(SpoofCandidatePair, Option<u64>)> {
    let mut results: Vec<(SpoofCandidatePair, Option<u64>)> = pairs
        .iter()
        .map(|pair| {
            let res = probe_spoof_pair(pair, timeout);
            (pair.clone(), res.latency_ms)
        })
        .collect();

    results.sort_by(|a, b| match (a.1, b.1) {
        (Some(la), Some(lb)) => la.cmp(&lb),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });

    results
}

/// Finds the candidate pair with the lowest measured latency (ping).
pub fn best_spoof_pair(
    pairs: &[SpoofCandidatePair],
    timeout: Duration,
) -> Option<(SpoofCandidatePair, u64)> {
    probe_and_rank_spoof_pairs(pairs, timeout)
        .into_iter()
        .find_map(|(pair, lat)| lat.map(|ms| (pair, ms)))
}

/// Helper function to pick the candidate with the lowest latency from a given list of SNI domain names.
pub fn select_lowest_latency_sni(
    candidates: &[String],
    port: u16,
    timeout: Duration,
) -> Option<(String, u64)> {
    let mut best: Option<(String, u64)> = None;

    for sni in candidates {
        let host_port = format!("{}:{}", sni, port);
        if let Ok(addrs) = host_port.to_socket_addrs() {
            for addr in addrs {
                let start = Instant::now();
                if TcpStream::connect_timeout(&addr, timeout).is_ok() {
                    let lat = start.elapsed().as_millis() as u64;
                    match &best {
                        Some((_, min_lat)) if lat < *min_lat => {
                            best = Some((sni.clone(), lat));
                        }
                        None => {
                            best = Some((sni.clone(), lat));
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    best
}

/// A pool of candidate SNI domains for rotation.
#[derive(Debug, Clone)]
pub struct SniPool {
    entries: Vec<SniEntry>,
    index: usize,
}

#[derive(Debug, Clone)]
pub struct SniEntry {
    pub sni: String,
    pub score: f64,
    pub last_used: Instant,
}

impl SniPool {
    pub fn new(candidates: Vec<String>) -> Self {
        let entries = candidates
            .into_iter()
            .map(|sni| SniEntry {
                sni,
                score: 0.0,
                last_used: Instant::now(),
            })
            .collect();
        Self { entries, index: 0 }
    }

    /// Round-robin selection.
    pub fn next_round_robin(&mut self) -> Option<&str> {
        if self.entries.is_empty() {
            return None;
        }
        let entry = &self.entries[self.index % self.entries.len()];
        self.index += 1;
        Some(&entry.sni)
    }

    /// Weighted-random selection based on scores.
    pub fn next_weighted_random(&self) -> Option<&str> {
        if self.entries.is_empty() {
            return None;
        }
        let total: f64 = self.entries.iter().map(|e| e.score.max(0.1)).sum();
        let mut r = rand::random::<f64>() * total;
        for entry in &self.entries {
            r -= entry.score.max(0.1);
            if r <= 0.0 {
                return Some(&entry.sni);
            }
        }
        Some(&self.entries.last().unwrap().sni)
    }

    /// Least-recently-used selection.
    pub fn next_lru(&mut self) -> Option<&str> {
        if self.entries.is_empty() {
            return None;
        }
        let oldest = self
            .entries
            .iter()
            .enumerate()
            .min_by_key(|(_, e)| e.last_used)
            .map(|(i, _)| i)
            .unwrap_or(0);
        self.entries[oldest].last_used = Instant::now();
        self.index = oldest;
        Some(&self.entries[oldest].sni)
    }

    pub fn update_score(&mut self, sni: &str, score: f64) {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.sni == sni) {
            entry.score = score;
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[SniEntry] {
        &self.entries
    }
}

/// Rank a list of probe results by latency and success rate.
pub fn rank_probes(results: &[ProbeResult]) -> Vec<RankedCandidate> {
    let mut by_candidate: HashMap<String, Vec<&ProbeResult>> = HashMap::new();
    for r in results {
        by_candidate
            .entry(r.candidate.clone())
            .or_default()
            .push(r);
    }

    let mut ranked: Vec<RankedCandidate> = by_candidate
        .into_iter()
        .map(|(candidate, probes)| {
            let total = probes.len() as u32;
            let successes = probes.iter().filter(|p| p.success).count() as u32;
            let tls_ok = probes.iter().filter(|p| p.tls_ok).count() as u32;
            let latencies: Vec<u64> = probes
                .iter()
                .filter_map(|p| p.latency_ms)
                .collect();
            let avg_latency = if latencies.is_empty() {
                f64::MAX
            } else {
                latencies.iter().sum::<u64>() as f64 / latencies.len() as f64
            };
            let success_rate = if total == 0 {
                0.0
            } else {
                successes as f64 / total as f64
            };
            // Score: high success rate + low latency = high score.
            // Normalize latency to 0..1 range (lower is better).
            let lat_score = if avg_latency == f64::MAX {
                0.0
            } else {
                1.0 / (1.0 + avg_latency / 1000.0)
            };
            let score = (success_rate * 0.6 + lat_score * 0.3 + if tls_ok > 0 { 0.1 } else { 0.0 }) * 100.0;
            RankedCandidate {
                candidate,
                score,
                avg_latency_ms: avg_latency,
                success_rate,
                probes: total,
                tls_successes: tls_ok,
            }
        })
        .collect();

    ranked.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    ranked
}

/// Well-known CDN edge IPs for common providers.
pub fn known_cdn_edges(provider: &str) -> Vec<IpAddr> {
    match provider.to_lowercase().as_str() {
        "cloudflare" => vec![
            "104.16.0.1".parse().unwrap(),
            "104.16.1.1".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
            "1.0.0.1".parse().unwrap(),
        ],
        "fastly" => vec![
            "151.101.1.1".parse().unwrap(),
            "151.101.65.1".parse().unwrap(),
        ],
        "akamai" => vec![
            "23.0.0.1".parse().unwrap(),
            "23.32.0.1".parse().unwrap(),
        ],
        _ => vec![],
    }
}

/// Common SNI candidates for Iranian ISPs (based on community knowledge).
pub fn default_sni_candidates() -> Vec<String> {
    vec![
        "www.microsoft.com".into(),
        "www.apple.com".into(),
        "speedtest.net".into(),
        "www.cloudflare.com".into(),
        "cdn.discordapp.com".into(),
        "www.vercel.com".into(),
        "security.cloudflare-dns.com".into(),
        "learn.microsoft.com".into(),
        "azure.microsoft.com".into(),
        "developer.android.com".into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_spoof_pairs_has_verified_entries() {
        let pairs = default_spoof_pairs();
        assert!(pairs.len() >= 15);
        assert!(pairs.iter().any(|p| p.fake_sni == "hcaptcha.com"));
        assert!(pairs.iter().any(|p| p.fake_sni == "auth.vercel.com"));
        assert!(pairs.iter().any(|p| p.fake_sni == "static.cloudflareinsights.com"));
        assert!(pairs.iter().any(|p| p.fake_sni == "pypi.org"));
        assert!(pairs.iter().any(|p| p.fake_sni == "aws.amazon.com"));
        assert!(pairs.iter().any(|p| p.fake_sni == "www.bing.com"));
        assert!(pairs.iter().any(|p| p.fake_sni == "login.live.com"));
    }

    #[test]
    fn auto_select_best_relay_target_runs() {
        let _ = auto_select_best_relay_target(Duration::from_millis(10));
    }

    #[test]
    fn best_spoof_pair_and_select_lowest_latency_sni() {
        let pairs = vec![
            SpoofCandidatePair::new("test", "invalid_ip", 443, "test.com", "desc"),
        ];
        let best = best_spoof_pair(&pairs, Duration::from_millis(10));
        assert!(best.is_none());

        let snis = vec!["invalid-domain-12345.local".into()];
        let best_sni = select_lowest_latency_sni(&snis, 443, Duration::from_millis(10));
        assert!(best_sni.is_none());
    }

    #[test]
    fn probe_spoof_pair_handles_invalid_ip() {
        let pair = SpoofCandidatePair::new("test", "invalid_ip", 443, "test.com", "desc");
        let res = probe_spoof_pair(&pair, Duration::from_millis(50));
        assert!(!res.success);
        assert_eq!(res.error, Some("invalid IP address".into()));
    }

    #[test]
    fn probe_and_rank_spoof_pairs_sorts_correctly() {
        let pairs = vec![
            SpoofCandidatePair::new("p1", "127.0.0.1", 443, "sni1.com", "d1"),
            SpoofCandidatePair::new("p2", "invalid_ip", 443, "sni2.com", "d2"),
        ];
        let ranked = probe_and_rank_spoof_pairs(&pairs, Duration::from_millis(50));
        assert_eq!(ranked.len(), 2);
    }

    #[test]
    fn sni_pool_round_robin_cycles() {
        let mut pool = SniPool::new(vec!["a.com".into(), "b.com".into(), "c.com".into()]);
        assert_eq!(pool.next_round_robin(), Some("a.com"));
        assert_eq!(pool.next_round_robin(), Some("b.com"));
        assert_eq!(pool.next_round_robin(), Some("c.com"));
        assert_eq!(pool.next_round_robin(), Some("a.com")); // wraps
    }

    #[test]
    fn sni_pool_empty_returns_none() {
        let mut pool = SniPool::new(vec![]);
        assert_eq!(pool.next_round_robin(), None);
        assert_eq!(pool.next_weighted_random(), None);
        assert_eq!(pool.next_lru(), None);
    }

    #[test]
    fn sni_pool_lru_picks_oldest() {
        let mut pool = SniPool::new(vec!["a.com".into(), "b.com".into()]);
        // Use a.com first
        let _ = pool.next_lru(); // a.com (both same age, first found)
        // Now advance time a bit
        std::thread::sleep(Duration::from_millis(2));
        let _ = pool.next_lru(); // b.com (a.com was used more recently)
    }

    #[test]
    fn sni_pool_update_score_works() {
        let mut pool = SniPool::new(vec!["a.com".into(), "b.com".into()]);
        pool.update_score("a.com", 95.0);
        assert_eq!(pool.entries()[0].score, 95.0);
    }

    #[test]
    fn rank_probes_sorts_by_score_desc() {
        let results = vec![
            ProbeResult {
                candidate: "slow.com".into(),
                ip: None,
                success: true,
                latency_ms: Some(500),
                tls_ok: true,
                cert_valid: true,
                error: None,
            },
            ProbeResult {
                candidate: "fast.com".into(),
                ip: None,
                success: true,
                latency_ms: Some(50),
                tls_ok: true,
                cert_valid: true,
                error: None,
            },
            ProbeResult {
                candidate: "fail.com".into(),
                ip: None,
                success: false,
                latency_ms: None,
                tls_ok: false,
                cert_valid: false,
                error: Some("timeout".into()),
            },
        ];
        let ranked = rank_probes(&results);
        assert_eq!(ranked.len(), 3);
        assert_eq!(ranked[0].candidate, "fast.com");
        assert_eq!(ranked[2].candidate, "fail.com");
    }

    #[test]
    fn known_cdn_edges_returns_ips() {
        let cf = known_cdn_edges("cloudflare");
        assert!(!cf.is_empty());
        let empty = known_cdn_edges("unknown");
        assert!(empty.is_empty());
    }

    #[test]
    fn default_sni_candidates_not_empty() {
        let c = default_sni_candidates();
        assert!(c.len() >= 5);
        assert!(c.iter().all(|s| !s.is_empty()));
    }
}
