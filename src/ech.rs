//! ech — Encrypted Client Hello (ECH) handling — [PARTIAL]
//! Based on draft-ietf-tls-esni and Cloudflare blog.
//! ECH encrypts the real SNI in an inner ClientHello, outer SNI is benign.
//! This module implements:
//! - GREASE ECH extension injection
//! - Outer SNI handling
//! - Real ECHConfigList wire-format parsing (draft-ietf-tls-esni), so a
//!   `public_name` fetched via DNS HTTPS/SVCB can actually be extracted
//!   instead of hard-coded. The DNS-over-HTTPS *fetch* itself lives in
//!   `doh.rs`; this module only decodes bytes it is given — no network
//!   I/O, so it stays a pure, OS-independent lib function.
//!
//! Real ECH *encryption* still needs HPKE crypto (RFC 9180: X25519 +
//! HKDF + AEAD sealing of the inner ClientHello) and is out of scope
//! here — this module covers config parsing plus the GREASE/outer-SNI
//! bypass techniques, which do not require decrypting anything.

use crate::error::DpiGuardError;
use rand::Rng;

/// ECH extension type (draft, value 0xFE0D)
pub const ECH_EXTENSION_TYPE: u16 = 0xFE0D;

/// GREASE values for ECH (RFC 8701 style)
pub const ECH_GREASE_TYPES: [u16; 6] = [0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0xFAFA];

#[derive(Debug, Clone)]
pub struct EchConfig {
    pub public_name: String,
    pub raw: Vec<u8>,
}

/// Read a big-endian u16 length prefix at `pos`, returning the value and
/// the offset just past it. `None` if there aren't 2 bytes left.
fn read_u16(buf: &[u8], pos: usize) -> Option<(u16, usize)> {
    let end = pos.checked_add(2)?;
    let bytes: [u8; 2] = buf.get(pos..end)?.try_into().ok()?;
    Some((u16::from_be_bytes(bytes), end))
}

/// Parse an `ECHConfigList` (draft-ietf-tls-esni §4) — the raw bytes of
/// the "ech" SvcParamValue from an HTTPS/SVCB record, as delivered by a
/// DNS-over-HTTPS response. The list is a back-to-back sequence of
/// `ECHConfig` entries (each self-delimiting via its own length field);
/// entries with an unrecognized `version` are skipped so a future/older
/// draft version in the same list doesn't break parsing.
///
/// Layout of one `ECHConfig` (version 0xfe0d, the deployed draft-13+
/// version used by Cloudflare/Chrome/Firefox in production today):
/// ```text
/// uint16 version;               // 0xfe0d
/// uint16 length;                // length of everything below, in bytes
/// -- HpkeKeyConfig --
/// uint8  config_id;
/// uint16 kem_id;
/// uint16 public_key_len; opaque public_key[public_key_len];
/// uint16 cipher_suites_len;     opaque cipher_suites[cipher_suites_len];
/// -- back in ECHConfigContents --
/// uint8  maximum_name_length;
/// uint8  public_name_len;       opaque public_name[public_name_len];
/// uint16 extensions_len;        opaque extensions[extensions_len];
/// ```
/// Returns the first `0xfe0d` config found. Malformed or truncated input
/// returns `Err` rather than panicking (fail-open friendly).
pub fn parse_ech_config_from_https_record(record: &[u8]) -> Result<EchConfig, DpiGuardError> {
    const ECH_CONFIG_VERSION: u16 = ECH_EXTENSION_TYPE; // 0xfe0d, same value

    let mut pos = 0usize;
    while pos < record.len() {
        let (version, after_version) =
            read_u16(record, pos).ok_or_else(|| trunc("ECHConfig version"))?;
        let (length, after_length) =
            read_u16(record, after_version).ok_or_else(|| trunc("ECHConfig length"))?;
        let length = length as usize;
        let contents_end = after_length
            .checked_add(length)
            .ok_or_else(|| DpiGuardError::OutOfRange("ECHConfig length overflow".into()))?;
        let contents = record
            .get(after_length..contents_end)
            .ok_or_else(|| trunc("ECHConfig contents"))?;

        if version == ECH_CONFIG_VERSION {
            let public_name = parse_ech_config_contents(contents)?;
            return Ok(EchConfig {
                public_name,
                raw: record[pos..contents_end].to_vec(),
            });
        }
        // Unknown version: skip this entry, keep scanning the list.
        pos = contents_end;
    }
    Err(DpiGuardError::OutOfRange(
        "no supported (0xfe0d) ECHConfig found in ECHConfigList".into(),
    ))
}

fn trunc(what: &str) -> DpiGuardError {
    DpiGuardError::OutOfRange(format!("ECHConfigList truncated (reading {what})"))
}

/// Parse the `ECHConfigContents` of a single version-0xfe0d entry and
/// return `public_name`. Walks past `HpkeKeyConfig` (config_id, kem_id,
/// public_key, cipher_suites) without needing to understand their
/// contents — only their lengths — since the wire format is fully
/// self-delimiting.
fn parse_ech_config_contents(c: &[u8]) -> Result<String, DpiGuardError> {
    // config_id (1 byte) + kem_id (2 bytes), then a u16-prefixed public key.
    let (pk_len, pos) = read_u16(c, 3).ok_or_else(|| trunc("public_key length"))?;
    let pk_len = pk_len as usize;
    let pos_after_pk = pos
        .checked_add(pk_len)
        .ok_or_else(|| DpiGuardError::OutOfRange("public_key length overflow".into()))?;
    if pos_after_pk > c.len() {
        return Err(trunc("public_key bytes"));
    }

    let (cs_len, pos) =
        read_u16(c, pos_after_pk).ok_or_else(|| trunc("cipher_suites length"))?;
    let cs_len = cs_len as usize;
    let pos_after_cs = pos
        .checked_add(cs_len)
        .ok_or_else(|| DpiGuardError::OutOfRange("cipher_suites length overflow".into()))?;
    if pos_after_cs > c.len() {
        return Err(trunc("cipher_suites bytes"));
    }

    // maximum_name_length (1 byte) — not needed by callers, skip.
    let max_name_pos = pos_after_cs;
    let public_name_len_pos = max_name_pos
        .checked_add(1)
        .ok_or_else(|| DpiGuardError::OutOfRange("offset overflow".into()))?;
    let public_name_len = *c
        .get(public_name_len_pos)
        .ok_or_else(|| trunc("public_name length"))? as usize;
    let name_start = public_name_len_pos + 1;
    let name_end = name_start
        .checked_add(public_name_len)
        .ok_or_else(|| DpiGuardError::OutOfRange("public_name length overflow".into()))?;
    let name_bytes = c
        .get(name_start..name_end)
        .ok_or_else(|| trunc("public_name bytes"))?;
    // public_name is DNS-name ASCII per spec; lossy-convert defensively
    // rather than reject a config over one bad byte (fail-open in spirit
    // with the rest of this fail-open codebase).
    let public_name = String::from_utf8_lossy(name_bytes).into_owned();
    if public_name.is_empty() {
        return Err(DpiGuardError::OutOfRange("empty ECHConfig public_name".into()));
    }
    Ok(public_name)
}

/// Inject GREASE ECH extension (fake) to confuse DPI that fingerprints ECH
/// This adds an extension with GREASE type and random payload
pub fn inject_ech_grease_ext(record: &[u8]) -> Result<Vec<u8>, DpiGuardError> {
    let mut rng = rand::thread_rng();
    let grease_type = ECH_GREASE_TYPES[rng.gen_range(0..ECH_GREASE_TYPES.len())];
    let payload_len = rng.gen_range(8..=32);
    let mut payload = Vec::with_capacity(payload_len);
    for _ in 0..payload_len {
        payload.push(rng.gen::<u8>());
    }
    crate::fragmentation::inject_hidden_sni_in_unknown_ext(record, &payload, grease_type)
        .map_err(|e| DpiGuardError::OutOfRange(format!("ECH GREASE inject failed: {e}")))
}

/// Build outer ClientHello with benign SNI for ECH
/// outer SNI = public name (e.g., cloudflare-ech.com), inner = real (encrypted in real ECH)
pub fn build_outer_sni_for_ech(real_record: &[u8], public_name: &str) -> Result<Vec<u8>, DpiGuardError> {
    crate::fragmentation::front_sni_with_benign(real_record, public_name.as_bytes())
}

/// Check if ClientHello already contains ECH extension
pub fn has_ech_extension(record: &[u8]) -> bool {
    // Scan for extension type 0xFE0D
    if record.len() < 50 { return false; }
    // Rough scan: look for FE0D in extension area
    record.windows(2).any(|w| u16::from_be_bytes([w[0], w[1]]) == ECH_EXTENSION_TYPE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fragmentation::encode_client_hello;

    #[test]
    fn ech_grease_injection_grows_record() {
        let record = encode_client_hello("example.com");
        let with_grease = inject_ech_grease_ext(&record).unwrap();
        assert!(with_grease.len() > record.len());
    }

    #[test]
    fn outer_sni_for_ech_replaces_sni() {
        let record = encode_client_hello("real.example.com");
        let outer = build_outer_sni_for_ech(&record, "public.example.com").unwrap();
        let (s,e) = crate::fragmentation::calculate_smart_split_points(&outer).unwrap();
        assert_eq!(&outer[s..e], b"public.example.com");
    }

    #[test]
    fn detects_ech_extension_presence() {
        let record = encode_client_hello("example.com");
        assert!(!has_ech_extension(&record));
        // Manually inject FE0D
        let mut fake = record.clone();
        fake.extend_from_slice(&[0xFE, 0x0D, 0x00, 0x00]);
        assert!(has_ech_extension(&fake));
    }

    /// Hand-encode one real ECHConfig (version 0xfe0d) so the parser can
    /// be checked against an actual wire-format record instead of a stub.
    fn encode_ech_config(public_name: &str) -> Vec<u8> {
        let public_key = [0xABu8; 32]; // X25519 public key length, content irrelevant here
        let cipher_suites = [0x00, 0x01, 0x00, 0x01]; // one (kdf_id, aead_id) pair
        let mut contents = Vec::new();
        contents.push(0x01); // config_id
        contents.extend_from_slice(&0x0020u16.to_be_bytes()); // kem_id (X25519, RFC 9180)
        contents.extend_from_slice(&(public_key.len() as u16).to_be_bytes());
        contents.extend_from_slice(&public_key);
        contents.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
        contents.extend_from_slice(&cipher_suites);
        contents.push(128); // maximum_name_length
        contents.push(public_name.len() as u8);
        contents.extend_from_slice(public_name.as_bytes());
        contents.extend_from_slice(&0u16.to_be_bytes()); // empty extensions

        let mut entry = Vec::new();
        entry.extend_from_slice(&ECH_EXTENSION_TYPE.to_be_bytes()); // version 0xfe0d
        entry.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        entry.extend_from_slice(&contents);
        entry
    }

    #[test]
    fn parses_real_ech_config_public_name() {
        let list = encode_ech_config("public-fronting.example.com");
        let cfg = parse_ech_config_from_https_record(&list).unwrap();
        assert_eq!(cfg.public_name, "public-fronting.example.com");
        assert_eq!(cfg.raw, list);
    }

    #[test]
    fn skips_unknown_version_entries_in_the_list() {
        // An old/future draft version (0xfe0a) the parser doesn't decode,
        // followed by a real 0xfe0d entry — the list scan must skip the
        // first and still find the second.
        let mut unknown = Vec::new();
        unknown.extend_from_slice(&0xFE0Au16.to_be_bytes());
        unknown.extend_from_slice(&4u16.to_be_bytes());
        unknown.extend_from_slice(&[0u8; 4]);

        let mut list = unknown;
        list.extend_from_slice(&encode_ech_config("cloudflare-ech.com"));

        let cfg = parse_ech_config_from_https_record(&list).unwrap();
        assert_eq!(cfg.public_name, "cloudflare-ech.com");
    }

    #[test]
    fn truncated_record_is_rejected_not_panicking() {
        let list = encode_ech_config("example.com");
        for cut in [0, 1, 2, 3, 4, 10] {
            let truncated = &list[..cut.min(list.len())];
            assert!(parse_ech_config_from_https_record(truncated).is_err());
        }
    }

    #[test]
    fn record_with_only_unsupported_versions_errs() {
        let mut unknown = Vec::new();
        unknown.extend_from_slice(&0xFE0Au16.to_be_bytes());
        unknown.extend_from_slice(&2u16.to_be_bytes());
        unknown.extend_from_slice(&[0u8; 2]);
        assert!(parse_ech_config_from_https_record(&unknown).is_err());
    }
}
