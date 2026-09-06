//! doh — DNS-over-HTTPS resolution (A records). [DONE]
//!
//! Resolves a hostname through a DoH endpoint so the query never travels as
//! plaintext over UDP/53 where an inline DPI or local observer could log it.
//! Fail-closed by design: there is deliberately **no** plain-DNS fallback —
//! if DoH fails, the caller gets an error rather than a leaked query.
//!
//! IP literals are returned as-is (no DNS at all), so configuring an IP for
//! the relay destination is the zero-leak option.

use crate::error::DpiGuardError;
use rand::Rng;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

/// Default DoH endpoint. We use the **IP-literal** `https://1.1.1.1/dns-query`
/// so the DoH endpoint's own name never needs a (plaintext) bootstrap
/// lookup. There is deliberately **no** fallback to UDP/53.
pub const DEFAULT_DOH_URL: &str = "https://1.1.1.1/dns-query";
/// Per-attempt timeout. Deliberately shorter than the old 10 s: on a
/// lossy link a hung request is far more likely than a slow-but-working
/// one, and the retry budget below gives a larger *total* allowance
/// (3 x 5 s plus backoff) than a single 10 s wait did.
pub const DOH_TIMEOUT: Duration = Duration::from_secs(5);
/// How many times a DoH query is attempted before giving up.
pub const DOH_MAX_ATTEMPTS: u32 = 3;

/// Exponential backoff between DoH attempts: 250 ms, 500 ms, 1 s, capped
/// at 2 s. Pure and side-effect free so it can be unit tested.
pub fn retry_backoff(attempt: u32) -> Duration {
    let exp = attempt.min(3);
    let ms = 250u64.saturating_mul(1u64 << exp);
    Duration::from_millis(ms.min(2000))
}
/// Cap on a DoH response body. A DNS answer is normally well under 4 KiB;
/// 64 KiB is a generous ceiling that stops a malicious endpoint from
/// streaming an unbounded body into memory.
pub const MAX_DOH_BODY: usize = 64 * 1024;
/// Maximum number of compression-pointer hops we follow, to avoid loops.
const MAX_COMPRESSION_HOPS: usize = 32;
/// Longest DNS name we will parse/emit (RFC 1035 §2.3.4).
const MAX_NAME_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// base64url (RFC 4648 §5) without padding — the encoding DoH GET expects.
pub fn b64url_no_pad(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(n >> 18) as usize & 0x3F] as char);
        out.push(TABLE[(n >> 12) as usize & 0x3F] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 0x3F] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 0x3F] as char
        } else {
            '='
        });
    }
    out.trim_end_matches('=').to_string()
}

fn build_a_query(host: &str) -> Result<Vec<u8>, DpiGuardError> {
    let host = host.trim().trim_end_matches('.');
    if host.is_empty() || host.len() > MAX_NAME_LEN {
        return Err(DpiGuardError::Resolution(format!(
            "host name {host:?} is empty or too long"
        )));
    }
    // Refuse to resolve forbidden/loopback/metadata hostnames so a DoH query
    // cannot be used as an SSRF / metadata probe.
    if crate::netguard::is_forbidden_hostname(host) {
        return Err(DpiGuardError::Resolution(format!(
            "host {host:?} is on the forbidden-name list"
        )));
    }
    let mut q = Vec::with_capacity(host.len() + 18);
    let id: u16 = rand::thread_rng().gen();
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
    q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // AN/NS/AR = 0
    for label in host.split('.') {
        if label.is_empty() {
            return Err(DpiGuardError::Resolution(format!(
                "empty label in host {host:?}"
            )));
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(DpiGuardError::Resolution(format!(
                "label too long in host {host:?}"
            )));
        }
        // Only valid LDH hostnames; reject control/space characters.
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(DpiGuardError::Resolution(format!(
                "invalid label {label:?} in host {host:?}"
            )));
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0); // root
    q.extend_from_slice(&[0x00, 0x01]); // QTYPE A
    q.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
    Ok(q)
}

fn skip_name(msg: &[u8], start: usize) -> Result<usize, DpiGuardError> {
    let mut pos = start;
    let mut hops = 0usize;
    let mut ptr_field_end: Option<usize> = None;
    loop {
        if pos >= msg.len() || hops > MAX_COMPRESSION_HOPS {
            return Err(DpiGuardError::Resolution("malformed DNS name".into()));
        }
        let len = msg[pos];
        if len == 0 {
            // End of name. If we followed a pointer, the *field* in the
            // answer section was the 2-byte pointer, so parsing continues
            // right after it; otherwise it's the zero label byte.
            return Ok(match ptr_field_end {
                Some(end) => end,
                None => pos + 1,
            });
        }
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= msg.len() {
                return Err(DpiGuardError::Resolution("truncated DNS pointer".into()));
            }
            if ptr_field_end.is_none() {
                ptr_field_end = Some(pos + 2);
            }
            let ptr = (((len as usize & 0x3F) << 8) | msg[pos + 1] as usize)
                .min(msg.len().saturating_sub(1));
            if ptr >= pos {
                // Forward/self pointers are invalid (RFC 1035).
                return Err(DpiGuardError::Resolution("invalid DNS pointer".into()));
            }
            pos = ptr;
            hops += 1;
            continue;
        }
        if len > MAX_LABEL_LEN as u8 {
            return Err(DpiGuardError::Resolution("DNS label too long".into()));
        }
        pos += 1 + len as usize;
        hops += 1;
    }
}

fn parse_a_records(resp: &[u8]) -> Result<Vec<IpAddr>, DpiGuardError> {
    if resp.len() < 12 {
        return Err(DpiGuardError::Resolution("short DNS response".into()));
    }
    let flags = u16::from_be_bytes([resp[2], resp[3]]);
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return Err(DpiGuardError::Resolution(format!("DNS RCODE {rcode}")));
    }
    let qdcount = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;

    let mut pos = 12usize;
    for _ in 0..qdcount {
        pos = skip_name(resp, pos)?;
        // QTYPE + QCLASS. Bounds-check before advancing: with
        // `overflow-checks = true` (see Cargo.toml) an unchecked `+= 4` on a
        // truncated response is a panic on the DoH path, not a silent wrap.
        if pos + 4 > resp.len() {
            return Err(DpiGuardError::Resolution(
                "truncated DNS question section".into(),
            ));
        }
        pos += 4;
    }

    let mut out = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(resp, pos)?;
        if pos + 10 > resp.len() {
            break;
        }
        let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10;
        if rtype == 1 && rdlen == 4 && pos + 4 <= resp.len() {
            let ip = Ipv4Addr::new(resp[pos], resp[pos + 1], resp[pos + 2], resp[pos + 3]);
            // Refuse loopback/link-local/multicast/metadata answers: a DoH
            // response that points the relay at a forbidden destination is
            // an SSRF risk. RFC1918 is allowed (internal relay target).
            if crate::netguard::is_forbidden_dest(IpAddr::V4(ip)) {
                return Err(DpiGuardError::Resolution(format!(
                    "DoH returned a forbidden address {ip}"
                )));
            }
            out.push(IpAddr::V4(ip));
        }
        pos = match pos.checked_add(rdlen) {
            Some(next) if next >= pos => next,
            _ => return Err(DpiGuardError::Resolution("DNS rdlen overflow".into())),
        };
        if pos > resp.len() {
            return Err(DpiGuardError::Resolution("DNS answer runs past response".into()));
        }
    }
    Ok(out)
}

/// Resolve `host` to IPv4 addresses over DoH. An IP literal is validated
/// and returned unchanged (no network). Returns all A records in order.
///
/// There is **no** plaintext UDP/53 fallback. Only A (IPv4) queries are
/// issued — AAAA is never queried.
pub fn resolve_a_v4(host: &str, doh_url: &str) -> Result<Vec<IpAddr>, DpiGuardError> {
    resolve_a_v4_attempts(host, doh_url, DOH_MAX_ATTEMPTS)
}

/// Process-wide DoH answer cache, loaded from disk on first use so a
/// restart during an outage can still resolve the relay destination.
fn global_cache() -> std::sync::MutexGuard<'static, crate::dns_cache::DnsCache> {
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<crate::dns_cache::DnsCache>> = OnceLock::new();
    let m = CACHE.get_or_init(|| {
        Mutex::new(crate::dns_cache::DnsCache::load(&crate::dns_cache::cache_path()))
    });
    // A poisoned cache must not break name resolution.
    match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

fn persist_cache() {
    let cache = global_cache();
    let _ = cache.save(&crate::dns_cache::cache_path(), std::time::Instant::now());
}

/// [`resolve_a_v4`] with an explicit attempt budget.
///
/// Networks with frequent outages and heavy packet loss drop individual
/// requests routinely, so a single failed query must not cost the
/// operator their connection. Attempts are spaced by [`retry_backoff`].
/// When every attempt fails, a cached answer (fresh or stale) is returned
/// if one exists — that is what keeps the relay startable while the
/// network is down.
pub fn resolve_a_v4_attempts(
    host: &str,
    doh_url: &str,
    attempts: u32,
) -> Result<Vec<IpAddr>, DpiGuardError> {
    let host = host.trim();
    if let Ok(ip) = host.parse::<IpAddr>() {
        crate::netguard::validate_relay_ip(ip)?;
        return Ok(vec![ip]);
    }
    let doh_url = crate::netguard::validate_doh_url(doh_url)?;
    let query = build_a_query(host)?;
    let url = format!(
        "{}?dns={}",
        doh_url.trim_end_matches('/'),
        b64url_no_pad(&query)
    );

    let attempts = attempts.clamp(1, DOH_MAX_ATTEMPTS);
    let mut last_err: Option<DpiGuardError> = None;
    for attempt in 0..attempts {
        if attempt > 0 {
            let delay = retry_backoff(attempt - 1);
            log::debug!("DoH retry {}/{} for {host} after {delay:?}", attempt + 1, attempts);
            std::thread::sleep(delay);
        }
        match fetch_a_records(&url) {
            Ok(ips) if !ips.is_empty() => {
                global_cache().insert(host, ips.clone());
                persist_cache();
                return Ok(ips);
            }
            Ok(_) => {
                last_err = Some(DpiGuardError::Resolution(format!("no A records for {host}")));
            }
            Err(e) => {
                log::warn!("DoH attempt {}/{} for {host} failed: {e}", attempt + 1, attempts);
                last_err = Some(e);
            }
        }
    }

    // Every attempt failed. A cached answer for the operator's own relay
    // destination beats no answer at all — but say loudly that it is not
    // from the network.
    if let Some((ips, fresh)) = global_cache().lookup(host, std::time::Instant::now()) {
        // Cached destination IPs are identifying: log them salted-hash
        // redacted, never raw (audit gap: "raw IPs are never logged" was
        // false on this fallback path). The configured domain name itself
        // still appears in DoH diagnostic lines by design.
        log::warn!(
            "DoH failed for {host} after {attempts} attempt(s); falling back to a {} \
             cached answer (redacted: {})",
            if fresh { "fresh" } else { "STALE" },
            ips.iter()
                .map(|ip| crate::stealth::redact_endpoint(&ip.to_string()))
                .collect::<Vec<_>>()
                .join(", ")
        );
        return Ok(ips);
    }

    Err(last_err.unwrap_or_else(|| {
        DpiGuardError::Resolution(format!("DoH resolution failed for {host}"))
    }))
}

/// One DoH round trip: GET the query, bound the body, parse the A records.
fn fetch_a_records(url: &str) -> Result<Vec<IpAddr>, DpiGuardError> {
    let response = ureq::get(url)
        .timeout(DOH_TIMEOUT)
        // RFC 8484: a DoH client MUST send Accept: application/dns-message.
        .set("Accept", "application/dns-message")
        .call()
        .map_err(|e| DpiGuardError::Resolution(format!("DoH request failed: {e}")))?;
    let mut body = Vec::new();
    // Bound the read to MAX_DOH_BODY so a hostile endpoint can't stream an
    // unlimited response.
    response
        .into_reader()
        .take(MAX_DOH_BODY as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|e| DpiGuardError::Resolution(format!("DoH read failed: {e}")))?;
    if body.len() > MAX_DOH_BODY {
        return Err(DpiGuardError::Resolution(format!(
            "DoH response exceeds {MAX_DOH_BODY} byte cap"
        )));
    }
    // validate_dnssec is a *presence* check (RRSIG record type 46 in the
    // answer/authority/additional sections). It is NOT a cryptographic
    // chain validation — see the doc comment on stealth::validate_dnssec —
    // but logging the signal is free and tells the operator whether the
    // resolver is even returning DNSSEC material they might later verify.
    match crate::stealth::validate_dnssec(&body) {
        Ok(true) => log::debug!("DoH response carries an RRSIG (DNSSEC-signed answer)"),
        Ok(false) => log::debug!("DoH response carries no RRSIG (answer is unsigned)"),
        Err(_) => log::debug!("DoH response was too short to run the RRSIG heuristic"),
    }
    parse_a_records(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_matches_rfc_vectors() {
        assert_eq!(b64url_no_pad(b""), "");
        assert_eq!(b64url_no_pad(b"f"), "Zg");
        assert_eq!(b64url_no_pad(b"fo"), "Zm8");
        assert_eq!(b64url_no_pad(b"foo"), "Zm9v");
        assert_eq!(b64url_no_pad(b"foob"), "Zm9vYg");
        assert_eq!(b64url_no_pad(b"fooba"), "Zm9vYmE");
        assert_eq!(b64url_no_pad(b"foobar"), "Zm9vYmFy");
    }

    /// The retry schedule must be monotonic, start small, and stay capped
    /// so a dead network cannot make the caller wait forever.
    #[test]
    fn retry_backoff_grows_and_is_capped() {
        assert_eq!(retry_backoff(0), Duration::from_millis(250));
        assert_eq!(retry_backoff(1), Duration::from_millis(500));
        assert_eq!(retry_backoff(2), Duration::from_millis(1000));
        assert_eq!(retry_backoff(3), Duration::from_millis(2000));
        // Beyond the cap it must not keep growing (and must not overflow).
        assert_eq!(retry_backoff(4), Duration::from_millis(2000));
        assert_eq!(retry_backoff(u32::MAX), Duration::from_millis(2000));
        for a in 0..20 {
            assert!(retry_backoff(a) <= Duration::from_secs(2));
        }
    }

    /// The whole retry budget must stay bounded: 3 attempts x 5 s plus the
    /// backoff between them. This is what bounds how long a flapping
    /// network can stall the caller.
    #[test]
    fn total_retry_budget_is_bounded() {
        let attempts = DOH_MAX_ATTEMPTS;
        let mut total = Duration::from_secs(0);
        for a in 0..attempts {
            total += DOH_TIMEOUT;
            if a + 1 < attempts {
                total += retry_backoff(a);
            }
        }
        assert!(
            total <= Duration::from_secs(21),
            "worst-case DoH budget is {total:?}, too long for a watchdog thread"
        );
    }

    #[test]
    fn ip_literal_skips_the_network_and_the_cache() {
        // An IP literal must resolve without touching DoH at all, so it
        // works with the network completely down.
        let ips = resolve_a_v4("1.2.3.4", "https://1.1.1.1/dns-query").unwrap();
        assert_eq!(ips, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
        // A forbidden literal is still refused.
        assert!(resolve_a_v4("127.0.0.1", "https://1.1.1.1/dns-query").is_err());
    }

    #[test]
    fn query_has_header_question_and_qtype_a() {
        let q = build_a_query("example.com").unwrap();
        assert!(q.len() >= 12 + 13 + 4);
        assert_eq!(q[2], 0x01); // RD flag
        assert_eq!(&q[4..6], &[0x00, 0x01]); // QDCOUNT
        // QTYPE A + QCLASS IN at the tail
        let tail = &q[q.len() - 4..];
        assert_eq!(tail, &[0x00, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn parse_extracts_a_records_and_honours_rcode() {
        // Header: id, flags 0x8180 (QR|RD|RA, RCODE=0), QD=1, AN=1.
        let mut m = vec![0u8; 12];
        m[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
        m[2] = 0x81;
        m[3] = 0x80;
        m[5] = 1;
        m[7] = 1;
        // Question: example.com A IN
        m.extend_from_slice(b"\x07example\x03com\x00");
        m.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // Answer: name ptr 0xC00C, A, IN, TTL 60, RDLEN 4, 1.2.3.4
        m.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);
        m.extend_from_slice(&[0x00, 0x00, 0x00, 60]);
        m.extend_from_slice(&[0x00, 0x04]);
        m.extend_from_slice(&[1, 2, 3, 4]);

        let ips = parse_a_records(&m).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);

        // NXDOMAIN (RCODE=3) must be an error, not an empty list.
        let mut nx = m.clone();
        nx[3] = 0x83;
        assert!(parse_a_records(&nx).is_err());
    }

    #[test]
    fn ip_literal_skips_network() {
        let ips = resolve_a_v4("1.2.3.4", DEFAULT_DOH_URL).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
    }

    #[test]
    fn malformed_label_rejected() {
        let big = "a".repeat(64);
        assert!(build_a_query(&big).is_err());
    }

    /// Regression: a response whose question section is cut off right after
    /// the name must be an error, not an arithmetic overflow. The release
    /// profile sets `overflow-checks = true`, so the old unchecked
    /// `pos += 4` panicked inside the DoH path on a hostile/truncated
    /// answer instead of degrading to the DNS cache.
    #[test]
    fn truncated_question_section_is_an_error_not_a_panic() {
        // 12-byte header claiming one question, then a bare root label with
        // no room for the 4-byte QTYPE/QCLASS that must follow.
        let mut resp = vec![0u8; 12];
        resp[3] = 0x00; // RCODE 0
        resp[5] = 0x01; // QDCOUNT = 1
        resp[7] = 0x00; // ANCOUNT = 0
        resp.push(0x00); // root label terminates the name; buffer ends here
        let got = parse_a_records(&resp);
        assert!(got.is_err(), "expected an error, got {got:?}");
    }

    /// The same guard on a question whose QTYPE/QCLASS is only partly
    /// present (2 of the 4 bytes).
    #[test]
    fn partial_qtype_qclass_is_an_error() {
        let mut resp = vec![0u8; 12];
        resp[5] = 0x01; // QDCOUNT = 1
        resp.extend_from_slice(&[0x00, 0x00, 0x01]); // root + 2 of 4 bytes
        assert!(parse_a_records(&resp).is_err());
    }

    #[test]
    fn default_doh_url_is_ip_literal_cloudflare() {
        assert_eq!(DEFAULT_DOH_URL, "https://1.1.1.1/dns-query");
        assert!(crate::netguard::validate_doh_url(DEFAULT_DOH_URL).is_ok());
    }

    #[test]
    fn query_refuses_forbidden_hosts() {
        assert!(build_a_query("localhost").is_err());
        assert!(build_a_query("metadata.google.internal").is_err());
        assert!(build_a_query("printer.local").is_err());
        assert!(build_a_query("127.0.0.1").is_err());
        assert!(build_a_query("169.254.169.254").is_err());
    }

    #[test]
    fn loopback_answer_rejected() {
        let mut m = vec![0u8; 12];
        m[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
        m[2] = 0x81;
        m[3] = 0x80;
        m[5] = 1;
        m[7] = 1;
        m.extend_from_slice(b"\x07example\x03com\x00");
        m.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        m.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);
        m.extend_from_slice(&[0x00, 0x00, 0x00, 60]);
        m.extend_from_slice(&[0x00, 0x04]);
        m.extend_from_slice(&[127, 0, 0, 1]);
        assert!(parse_a_records(&m).is_err());
    }

    #[test]
    fn ip_literal_loopback_rejected() {
        assert!(resolve_a_v4("127.0.0.1", DEFAULT_DOH_URL).is_err());
        assert!(resolve_a_v4("localhost", DEFAULT_DOH_URL).is_err());
    }

    #[test]
    fn body_cap_is_64kib() {
        assert_eq!(MAX_DOH_BODY, 64 * 1024);
    }
}
