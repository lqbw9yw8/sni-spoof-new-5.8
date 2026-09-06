//! netguard — destination / hostname allow-deny guards (SSRF surface). [DONE]
//!
//! The relay connects to a single operator-configured destination and the
//! DoH client fetches from an operator-configured URL. Both are user input
//! that ultimately drives an outbound socket, so they are validated here
//! before any I/O. The rules are deliberately conservative:
//!
//! * loopback, unspecified, broadcast, multicast, link-local, and the cloud
//!   metadata endpoint `169.254.169.254` are refused as relay/DoH targets.
//! * IPv4-mapped IPv6 addresses are unwrapped and re-checked, so
//!   `::ffff:127.0.0.1` cannot smuggle a loopback target past an IPv6-only
//!   check.
//! * RFC1918 private space (10/8, 172.16/12, 192.168/16) is **allowed** —
//!   the relay is commonly pointed at an internal host. Only the categories
//!   above are refused.
//! * hostnames `localhost`, `metadata.google.internal`, `*.local`, and
//!   `*.internal` are refused (mDNS / cloud-metadata / loopback names).
//! * the DoH URL must be `https`, carry no userinfo, and parse cleanly.
//!
//! This module is pure logic (no network) so every branch is unit tested on
//! every OS, including the non-Windows CI target.

use crate::error::DpiGuardError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Cloud metadata services listen here. It sits inside the 169.254/16
/// link-local block but is called out by name because it is the canonical
/// SSRF target on every major cloud.
pub const METADATA_IP: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);

/// Unwrap an IPv4-mapped/compatible IPv6 address to its IPv4 form so a
/// single IPv4 rule set covers both representations. Returns the address
/// unchanged when it is a "real" IPv6 address.
pub fn unmapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// True when `ip` must never be used as a relay/DoH/connect target:
/// loopback, unspecified, broadcast, multicast, link-local, or the cloud
/// metadata address. IPv4-mapped IPv6 is unwrapped first.
///
/// RFC1918 private space is **not** forbidden here.
pub fn is_forbidden_dest(ip: IpAddr) -> bool {
    let ip = unmapped(ip);
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_link_local()
                || v4 == METADATA_IP
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || is_ipv6_link_local(&v6)
                // Unique-local addresses (fc00::/7) are the IPv6 analogue of
                // RFC1918 and are intentionally allowed.
        }
    }
}

fn is_ipv6_link_local(v6: &Ipv6Addr) -> bool {
    let segs = v6.segments();
    // fe80::/10
    (segs[0] & 0xffc0) == 0xfe80
}

/// True when `host` is a name the relay must not resolve/connect to.
/// Comparison is ASCII-case-insensitive and tolerates a trailing dot.
///
/// Refused: `localhost` (and any `*.localhost`), the GCP metadata name
/// `metadata.google.internal`, `*.local` (mDNS), and `*.internal`.
/// A bare IP literal is not evaluated here — callers parse it through
/// [`is_forbidden_dest`] instead.
pub fn is_forbidden_hostname(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        return false; // empty is handled elsewhere as "missing"
    }
    // If it parses as an IP literal, apply the IP rule instead of the name
    // rule (so 127.0.0.1 is caught even though it is not a DNS name).
    if let Ok(ip) = h.parse::<IpAddr>() {
        return is_forbidden_dest(ip);
    }
    if h == "localhost" || h.ends_with(".localhost") {
        return true;
    }
    if h == "metadata.google.internal"
        || h == "metadata.goog"
        || h == "metadata.azure.com"
        || h == "169.254.169.254.nip.io"
    {
        return true;
    }
    if h == "local" || h.ends_with(".local") {
        return true;
    }
    if h == "internal" || h.ends_with(".internal") {
        return true;
    }
    false
}

/// Validate a DoH endpoint URL. Must be `https`, have no username/password
/// userinfo, a non-empty host, and a scheme/host that parse. Returns the
/// normalized (trimmed) URL on success.
///
/// A host that is a forbidden IP literal is refused; a hostname that is on
/// the forbidden-name list is refused.
pub fn validate_doh_url(url: &str) -> Result<String, DpiGuardError> {
    let url = url.trim();
    if !url.starts_with("https://") {
        return Err(DpiGuardError::Config(
            "doh_server must be an https:// URL".into(),
        ));
    }
    // Strip scheme for manual parsing (no url crate dependency).
    let rest = &url["https://".len()..];
    // userinfo is "user:pass@host" — refuse any '@' before the first '/'
    // (and before any '?'), since a DoH endpoint never needs credentials.
    let authority_end = rest
        .find(['/', '?', '#'])
        .unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.contains('@') {
        return Err(DpiGuardError::Config(
            "doh_server must not contain userinfo (user:password@)".into(),
        ));
    }
    // Split host from port. Accept [v6]:port as well as host:port.
    let host = if let Some(open) = authority.strip_prefix('[') {
        // bracketed IPv6
        let close = open.find(']').ok_or_else(|| {
            DpiGuardError::Config("doh_server has malformed [IPv6] host".into())
        })?;
        &open[..close]
    } else {
        // host or host:port — a raw IPv6 without brackets would contain
        // multiple colons; reject that as ambiguous.
        match authority.rsplit_once(':') {
            Some((h, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => h,
            _ => authority,
        }
    };
    if host.is_empty() {
        return Err(DpiGuardError::Config("doh_server has an empty host".into()));
    }
    if is_forbidden_hostname(host) {
        return Err(DpiGuardError::Config(format!(
            "doh_server host {host:?} resolves to a forbidden/loopback/metadata target"
        )));
    }
    Ok(url.to_string())
}

/// Validate an IP literal intended as the relay connect target. Loopback,
/// link-local, multicast, broadcast, unspecified, and metadata addresses
/// are refused. RFC1918 is allowed.
pub fn validate_relay_ip(ip: IpAddr) -> Result<(), DpiGuardError> {
    if is_forbidden_dest(ip) {
        return Err(DpiGuardError::Config(format!(
            "relay_connect_host IP {ip} is forbidden (loopback/link-local/multicast/metadata)"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_is_forbidden() {
        assert!(is_forbidden_dest(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_forbidden_dest("127.0.0.1".parse().unwrap()));
        assert!(is_forbidden_dest("127.255.255.255".parse().unwrap()));
        assert!(is_forbidden_dest("::1".parse().unwrap()));
    }

    #[test]
    fn unspecified_and_broadcast_forbidden() {
        assert!(is_forbidden_dest(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(is_forbidden_dest(IpAddr::V4(Ipv4Addr::BROADCAST)));
        assert!(is_forbidden_dest("::".parse().unwrap()));
    }

    #[test]
    fn multicast_forbidden() {
        assert!(is_forbidden_dest("224.0.0.1".parse().unwrap()));
        assert!(is_forbidden_dest("239.255.255.250".parse().unwrap()));
        assert!(is_forbidden_dest("ff02::1".parse().unwrap()));
    }

    #[test]
    fn link_local_and_metadata_forbidden() {
        assert!(is_forbidden_dest("169.254.1.1".parse().unwrap()));
        assert!(is_forbidden_dest(METADATA_IP.into()));
        assert!(is_forbidden_dest("fe80::1".parse().unwrap()));
    }

    #[test]
    fn rfc1918_is_allowed() {
        // Private space is allowed per spec (relay may target an internal host).
        assert!(!is_forbidden_dest("10.0.0.1".parse().unwrap()));
        assert!(!is_forbidden_dest("172.16.5.5".parse().unwrap()));
        assert!(!is_forbidden_dest("192.168.1.1".parse().unwrap()));
        // Public addresses allowed.
        assert!(!is_forbidden_dest("1.1.1.1".parse().unwrap()));
        assert!(!is_forbidden_dest("8.8.8.8".parse().unwrap()));
        // IPv6 unique-local allowed.
        assert!(!is_forbidden_dest("fd00::1".parse().unwrap()));
    }

    #[test]
    fn mapped_ipv6_loopback_is_forbidden() {
        // ::ffff:127.0.0.1 must be caught.
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(is_forbidden_dest(mapped));
        assert_eq!(unmapped(mapped), IpAddr::V4(Ipv4Addr::LOCALHOST));
        // ::ffff:1.1.1.1 is allowed.
        let ok: IpAddr = "::ffff:1.1.1.1".parse().unwrap();
        assert!(!is_forbidden_dest(ok));
    }

    #[test]
    fn forbidden_hostnames() {
        assert!(is_forbidden_hostname("localhost"));
        assert!(is_forbidden_hostname("LocalHost."));
        assert!(is_forbidden_hostname("foo.localhost"));
        assert!(is_forbidden_hostname("metadata.google.internal"));
        assert!(is_forbidden_hostname("printer.local"));
        assert!(is_forbidden_hostname("corp.internal"));
        assert!(is_forbidden_hostname("127.0.0.1"));
    }

    #[test]
    fn ordinary_hostnames_allowed() {
        assert!(!is_forbidden_hostname("example.com"));
        assert!(!is_forbidden_hostname("speedtest.example.com"));
        assert!(!is_forbidden_hostname("cloudflare-dns.com"));
        assert!(!is_forbidden_hostname("1.1.1.1.nip.io"));
    }

    #[test]
    fn doh_url_must_be_https() {
        assert!(validate_doh_url("http://1.1.1.1/dns-query").is_err());
        assert!(validate_doh_url("ftp://1.1.1.1/").is_err());
        assert!(validate_doh_url("1.1.1.1/dns-query").is_err());
        assert!(validate_doh_url("").is_err());
    }

    #[test]
    fn doh_url_rejects_userinfo_and_forbidden_host() {
        assert!(validate_doh_url("https://user:pass@1.1.1.1/dns-query").is_err());
        assert!(validate_doh_url("https://127.0.0.1/dns-query").is_err());
        assert!(validate_doh_url("https://localhost/dns-query").is_err());
        assert!(validate_doh_url("https://metadata.google.internal/dns-query").is_err());
    }

    #[test]
    fn doh_url_accepts_valid() {
        assert_eq!(
            validate_doh_url("https://1.1.1.1/dns-query").unwrap(),
            "https://1.1.1.1/dns-query"
        );
        assert_eq!(
            validate_doh_url("  https://cloudflare-dns.com/dns-query  ").unwrap(),
            "https://cloudflare-dns.com/dns-query"
        );
        assert!(validate_doh_url("https://[2606:4700:4700::1111]/dns-query").is_ok());
    }

    #[test]
    fn relay_ip_rejects_loopback_allows_public() {
        assert!(validate_relay_ip("127.0.0.1".parse().unwrap()).is_err());
        assert!(validate_relay_ip("169.254.169.254".parse().unwrap()).is_err());
        assert!(validate_relay_ip("::1".parse().unwrap()).is_err());
        assert!(validate_relay_ip("10.0.0.5".parse().unwrap()).is_ok());
        assert!(validate_relay_ip("1.1.1.1".parse().unwrap()).is_ok());
    }
}
