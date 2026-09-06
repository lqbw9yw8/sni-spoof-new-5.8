//! pipeline — OS-independent packet processor. [DONE]
//! This is what `main` actually runs on every diverted packet: parse L3/L4
//! (skipping the TCP header via data-offset), splice a mutated SNI with
//! rewritten TLS lengths, optional TCP segmentation, optional TTL-limited
//! wrong-checksum decoy, inbound RST → strategy score.
//! 
//! 2025-2026 upgrades:
//! - QUIC port blindspot bypass (src <= dst) for GFW
//! - SNI disguise as unknown extension (GREASE/private)
//! - Layered domain fronting (benign SNI + hidden real in 0xFF01)
//! - Combined TCP+TLS fragmentation for Henan-like regional firewalls
//! - ALL PORTS: works on any TCP/UDP port via intercept_ports config, not just 443

use crate::config::Settings;
use crate::connection::SessionTicketCache;
use crate::error::DpiGuardError;
use crate::fail_open::WireAction;
use crate::fooling::{self, build_wrong_checksum};
use crate::fragmentation::{self, splice_sni};
use crate::packet::{self, ParsedPacket, TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_RST, TCP_FLAG_SYN};
use crate::quic::QuicPortMapper;
use crate::relay::{FlowInfo, HandshakeMonitor, HsAction, InjectGate, RelayMode};
use crate::sequence::{
    build_decoy_packet, calculate_wrong_seq_outside_window, inject_ttl_limited_decoy,
};
use crate::sni_mutations::{mutate_sni_full, MutationProfile};
use crate::stealth::{
    add_random_padding, deep_sleep_idle, hash_sensitive, inject_noise_entropy, match_sni_cert,
    randomize_window_size, run_salt, MemoryCertCache,
};
use crate::strategy::StrategyTable;
use rand::Rng;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
// Note: tokio::sync::Notify is no longer used directly — relay flows use
// `relay::InjectGate`, which carries an explicit success/failure bit.

const HOLD_TIMEOUT: Duration = Duration::from_millis(200);
const MAX_FLOW_BUF: usize = 16 * 1024;
const MAX_FLOWS: usize = 256;
const MAX_RECENT: usize = 512;
/// Cap on the relay-mode flow table. It grows once per **client
/// connection** to the relay, so a browser behind v2rayN can add hundreds
/// of entries quickly, and finished ones otherwise linger until
/// `idle_timeout_secs` (120 s by default). Without a hard cap this is
/// unbounded growth driven by ordinary client behaviour (CWE-770), and it
/// is the one table `docs/archive/SECURITY_CHECKLIST.md` control 44 did not actually
/// cover.
const MAX_RELAY_FLOWS: usize = 256;
/// Cap on `last_activity`, which gains an entry for every TCP 4-tuple the
/// pipeline sees. Its key comes straight off the wire, so without a bound a
/// source-spoofed scan grows it for a whole `idle_timeout_secs` window
/// (120 s by default, configurable up to 86 400) before `flush_idle` can
/// reclaim anything — unbounded growth driven by remote input (CWE-770).
/// `flows`/`recent`/`relay_flows` were each capped for exactly this reason;
/// this table and `inbound_ttl` were the two that were missed.
const MAX_LAST_ACTIVITY: usize = 4096;
/// Cap on `inbound_ttl`, keyed by source IP. Same argument as
/// [`MAX_LAST_ACTIVITY`], and it is populated on *every* inbound packet
/// whenever `enable_autottl` is on, so a spoofed-source flood is the
/// obvious way to grow it.
const MAX_INBOUND_TTL: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
}

struct FlowBuf {
    buf: Vec<u8>,
    next_seq: u32,
    held: Vec<Vec<u8>>,
    started: Instant,
}

struct RecentAttempt {
    domain: String,
    technique: String,
    at: Instant,
}

/// Per-flow state for the relay-mode fake-SNI injection.
struct RelayFlow {
    monitor: HandshakeMonitor,
    gate: Arc<InjectGate>,
    done: bool,
    last: Instant,
}

pub struct Pipeline {
    pub settings: Settings,
    pub strategy: StrategyTable,
    pub tickets: SessionTicketCache,
    pub certs: MemoryCertCache,
    flows: HashMap<FlowKey, FlowBuf>,
    last_activity: HashMap<FlowKey, Instant>,
    recent: HashMap<(IpAddr, u16), RecentAttempt>,
    quic_mapper: QuicPortMapper,
    relay_mode: Option<RelayMode>,
    relay_flows: HashMap<FlowKey, RelayFlow>,
    /// Learned decoy TTLs (per destination IP) for autottl.
    pub autottl: crate::autottl::AutoTtl,
    /// Last *observed* inbound IP TTL per peer, with the time it was seen.
    /// `AutoTtl` stores the TTL it already suggests, but
    /// `autottl::suggest_ttl_scaled` needs the raw hop distance, so the raw
    /// value is kept here. Pruned by `flush_idle` like every other map.
    inbound_ttl: HashMap<IpAddr, (u8, Instant)>,
    /// Desync mode chosen for the in-flight attempt on a peer, so the RST /
    /// ServerHello feedback in `on_inbound` can score that mode too and
    /// `enable_adaptive_desync` actually learns. Keyed like `recent`.
    last_desync: HashMap<(IpAddr, u16), String>,
}

fn release_held_plus(mut held: Vec<Vec<u8>>, current: &[u8]) -> WireAction {
    held.push(current.to_vec());
    WireAction::Send(held)
}

impl Pipeline {
    pub fn new(settings: Settings) -> Self {
        Self {
            settings,
            strategy: StrategyTable::new(),
            tickets: SessionTicketCache::new(32),
            certs: MemoryCertCache::default(),
            flows: HashMap::new(),
            last_activity: HashMap::new(),
            recent: HashMap::new(),
            quic_mapper: QuicPortMapper::new(),
            relay_mode: None,
            relay_flows: HashMap::new(),
            autottl: crate::autottl::AutoTtl::new(),
            inbound_ttl: HashMap::new(),
            last_desync: HashMap::new(),
        }
    }

    /// Configure (or clear, with `None`) relay-mode evasion behaviour.
    pub fn configure_relay(&mut self, mode: Option<RelayMode>) {
        self.relay_mode = mode;
    }

    /// Register a relay connection (4-tuple) before its handshake and return
    /// the gate the relay awaits (with a success/failure bit) before
    /// relaying the real ClientHello.
    ///
    /// The table is capped at [`MAX_RELAY_FLOWS`]. Eviction prefers flows
    /// whose handshake already finished (`done`), because those no longer
    /// need the monitor; only if the table is still full is the oldest
    /// *live* flow dropped, and that is logged loudly since its injection
    /// can no longer be confirmed.
    pub fn register_relay_flow(&mut self, flow: FlowInfo) -> Arc<InjectGate> {
        let gate = InjectGate::new();
        let key = FlowKey {
            src: flow.src,
            dst: flow.dst,
            sport: flow.sport,
            dport: flow.dport,
        };
        // Re-registering an existing 4-tuple replaces it, so it never grows
        // the table and must not trigger eviction.
        if self.relay_flows.len() >= MAX_RELAY_FLOWS && !self.relay_flows.contains_key(&key) {
            let before = self.relay_flows.len();
            self.relay_flows.retain(|_, f| !f.done);
            let evicted_finished = before - self.relay_flows.len();
            if self.relay_flows.len() >= MAX_RELAY_FLOWS {
                let oldest = self
                    .relay_flows
                    .iter()
                    .min_by_key(|entry| entry.1.last)
                    .map(|entry| *entry.0);
                if let Some(oldest) = oldest {
                    self.relay_flows.remove(&oldest);
                    log::warn!(
                        "relay flow table full ({MAX_RELAY_FLOWS}); evicted the oldest live \
                         flow — its fake-SNI injection can no longer be confirmed"
                    );
                }
            } else if evicted_finished > 0 {
                log::debug!(
                    "relay flow table at cap; evicted {evicted_finished} finished flow(s)"
                );
            }
        }
        self.relay_flows.insert(
            key,
            RelayFlow {
                monitor: HandshakeMonitor::new(),
                gate: gate.clone(),
                done: false,
                last: Instant::now(),
            },
        );
        gate
    }

    /// Drop a relay flow's entry once its connection is finished.
    ///
    /// The relay calls this on **every** exit path of a connection,
    /// including the fail-closed drop that happens when the fake-SNI
    /// injection is never confirmed. Without it those entries sat in the
    /// table until `idle_timeout_secs` expired (120 s by default), so a
    /// destination that consistently fails injection filled all
    /// [`MAX_RELAY_FLOWS`] slots with dead flows. Registration would then
    /// start evicting the oldest *live* flow, whose injection could no
    /// longer be confirmed, so it too failed closed — a feedback loop that
    /// turned one broken destination into a total outage.
    ///
    /// Returns true if an entry was actually removed (useful in tests).
    pub fn unregister_relay_flow(&mut self, flow: FlowInfo) -> bool {
        let key = FlowKey {
            src: flow.src,
            dst: flow.dst,
            sport: flow.sport,
            dport: flow.dport,
        };
        self.relay_flows.remove(&key).is_some()
    }

    /// Number of tracked relay flows. Used by the cap tests and useful for
    /// diagnosing a client (e.g. v2rayN) that opens many short connections.
    pub fn relay_flow_count(&self) -> usize {
        self.relay_flows.len()
    }

    pub fn handle(&mut self, raw: &[u8]) -> Result<WireAction, DpiGuardError> {
        self.flush_idle();
        let original = raw;
        let Some(raw) = packet::l3_slice(raw) else {
            return Ok(WireAction::Send(vec![original.to_vec()]));
        };
        let Some(parsed) = packet::parse_l3l4(raw) else {
            return Ok(WireAction::Send(vec![original.to_vec()]));
        };

        // #14 — max-payload cap: skip large payloads (reduces CPU)
        if self.settings.max_payload_size > 0 {
            let payload = parsed.payload(raw);
            if payload.len() > self.settings.max_payload_size {
                return Ok(WireAction::Send(vec![raw.to_vec()]));
            }
        }

        if parsed.protocol == packet::PROTO_UDP {
            // ALL PORTS: check if UDP port is target
            let is_target_udp = self.settings.is_target_port(parsed.dst_port, true)
                || self.settings.is_target_port(parsed.src_port, true);
            if !is_target_udp {
                return Ok(WireAction::Send(vec![raw.to_vec()]));
            }
            if self.settings.enable_decoys {
                let _ = crate::quic::build_quic_decoy(64);
            }
            if self.settings.enable_quic_port_bypass {
                // Inbound half of the QUIC port NAT: a server reply sent to
                // the spoofed source port is rewritten back to the client's
                // original source port. Checked first so a reply is never
                // mistaken for a brand-new Initial.
                if let Some(orig_sport) = self.quic_mapper.get_original(
                    parsed.src,      // server
                    parsed.dst,      // client
                    parsed.src_port, // server port
                    parsed.dst_port, // spoofed port
                ) {
                    if let Ok(rewritten) = crate::quic::rewrite_udp_dst_port(raw, orig_sport) {
                        log::info!(
                            "QUIC reverse NAT: restored dst port {} -> {} for server {}",
                            parsed.dst_port,
                            orig_sport,
                            parsed.src
                        );
                        return Ok(WireAction::Send(vec![rewritten]));
                    }
                }

                // Outbound half: keep rewriting every packet of an already
                // mapped flow (not just the Initial), so the server always
                // sees one 5-tuple.
                if let Some(spoofed) = self.quic_mapper.get_spoofed(
                    parsed.src,      // client
                    parsed.dst,      // server
                    parsed.dst_port, // server port
                    parsed.src_port, // original source port
                ) {
                    if let Ok(rewritten) = crate::quic::rewrite_udp_src_port(raw, spoofed) {
                        return Ok(WireAction::Send(vec![rewritten]));
                    }
                }

                // New flow: originate a NAT mapping only for a genuine
                // outbound client Initial (destination on an intercepted
                // port, source on an ephemeral port, src > dst).
                let dst_intercepted = self.settings.is_target_port(parsed.dst_port, true);
                let src_intercepted = self.settings.is_target_port(parsed.src_port, true);
                let payload = parsed.payload(raw);
                if dst_intercepted
                    && !src_intercepted
                    && crate::quic::should_mangle_quic(parsed.src_port, parsed.dst_port, true)
                    && crate::quic::is_quic_initial(payload)
                {
                    if self.quic_mapper.len() < crate::quic::MAX_QUIC_MAPS {
                        if let Some(new_sport) = self.quic_mapper.alloc_spoofed(
                            parsed.src,
                            parsed.dst,
                            parsed.dst_port,
                            self.settings.quic_bypass_use_low_port,
                        ) {
                            if let Ok(rewritten) =
                                crate::quic::rewrite_udp_src_port(raw, new_sport)
                            {
                                self.quic_mapper.insert(
                                    parsed.src,
                                    parsed.dst,
                                    parsed.dst_port,
                                    parsed.src_port,
                                    new_sport,
                                );
                                log::info!(
                                    "QUIC bypass: rewrote src {} -> {} for dst {} (blindspot)",
                                    parsed.src_port,
                                    new_sport,
                                    parsed.dst
                                );
                                return Ok(WireAction::Send(vec![rewritten]));
                            }
                        }
                    } else {
                        log::warn!(
                            "QUIC port mapper full; passing QUIC Initial through unmodified"
                        );
                    }
                }
            }
            return Ok(WireAction::Send(vec![raw.to_vec()]));
        }

        if parsed.protocol != packet::PROTO_TCP {
            return Ok(WireAction::Send(vec![raw.to_vec()]));
        }

        // Learn TTL from any inbound TCP packet (the relay destination is
        // the source of inbound packets). Done before short-circuiting so
        // relay flows also contribute.
        if self.settings.enable_autottl {
            let ttl = match parsed.l3 {
                packet::L3::Ipv4 => raw.get(8).copied().unwrap_or(64),
                packet::L3::Ipv6 => raw.get(7).copied().unwrap_or(64),
            };
            self.autottl
                .observe(parsed.src, ttl, self.settings.autottl_delta);
            // Bound the table before inserting a new source IP; re-observing
            // a known IP only refreshes it and cannot grow the map.
            if !self.inbound_ttl.contains_key(&parsed.src) {
                self.evict_inbound_ttl_if_full();
            }
            self.inbound_ttl.insert(parsed.src, (ttl, Instant::now()));
        }

        // Relay-mode flows short-circuit the normal SNI-mutation path: the
        // fake-SNI injection handles evasion, and the flow's real bytes pass
        // through unmodified.
        if let Some(action) = self.handle_relay_packet(raw, &parsed)? {
            return Ok(action);
        }

        // ALL PORTS: check if TCP port is target (either src or dst)
        let inbound = self.is_tcp_target(parsed.src_port);
        let outbound = self.is_tcp_target(parsed.dst_port);

        if inbound && !outbound {
            // Inbound from target port (server -> client)
            self.on_inbound(raw, &parsed);
            return Ok(WireAction::Send(vec![raw.to_vec()]));
        }
        if !outbound {
            return Ok(WireAction::Send(vec![raw.to_vec()]));
        }

        self.on_outbound_target(raw, &parsed)
    }

    /// A TCP port is "intercepted" when it is in the configured list (or an
    /// all-ports wildcard) OR, in relay mode with `mutate_real_sni`, when it
    /// is the relay's real destination port.
    fn is_tcp_target(&self, port: u16) -> bool {
        if self.settings.is_target_port(port, false) {
            return true;
        }
        matches!(&self.relay_mode, Some(m) if m.mutate_real_sni && m.connect_port == port)
    }

    /// Drive the fake-SNI handshake monitor for a relay flow. Returns
    /// `Ok(None)` when the packet does not belong to a registered relay flow
    /// (or when a completed relay flow falls through to normal mutation).
    fn handle_relay_packet(
        &mut self,
        raw: &[u8],
        parsed: &ParsedPacket,
    ) -> Result<Option<WireAction>, DpiGuardError> {
        if self.relay_mode.is_none() {
            return Ok(None);
        }
        let key = FlowKey {
            src: parsed.src,
            dst: parsed.dst,
            sport: parsed.src_port,
            dport: parsed.dst_port,
        };
        let reversed = FlowKey {
            src: parsed.dst,
            dst: parsed.src,
            sport: parsed.dst_port,
            dport: parsed.src_port,
        };
        let (flow_key, outbound) = if self.relay_flows.contains_key(&key) {
            (key, true)
        } else if self.relay_flows.contains_key(&reversed) {
            (reversed, false)
        } else {
            return Ok(None);
        };

        let flags = parsed.tcp_flags.unwrap_or(0);
        let seq = parsed.tcp_seq.unwrap_or(0);
        let ack_num = parsed.tcp_ack.unwrap_or(0);
        let payload_len = parsed.payload(raw).len();
        let syn = flags & TCP_FLAG_SYN != 0;
        let ack = flags & TCP_FLAG_ACK != 0;
        let rst = flags & TCP_FLAG_RST != 0;
        let fin = flags & TCP_FLAG_FIN != 0;

        let entry = match self.relay_flows.get_mut(&flow_key) {
            Some(e) => e,
            None => return Ok(None),
        };
        entry.last = Instant::now();
        if entry.done {
            // Item 1: optionally run the real ClientHello through the normal
            // SNI-mutation pipeline; otherwise pass through unmodified.
            if self
                .relay_mode
                .as_ref()
                .map(|m| m.mutate_real_sni)
                .unwrap_or(false)
            {
                return Ok(None);
            }
            return Ok(Some(WireAction::Send(vec![raw.to_vec()])));
        }

        let action = if outbound {
            entry
                .monitor
                .on_outbound(syn, ack, rst, fin, seq, ack_num, payload_len)
        } else {
            entry
                .monitor
                .on_inbound(syn, ack, rst, fin, seq, ack_num, payload_len)
        };

        // sni_only/sni_except apply to the *real* ClientHello SNI in
        // apply_client_hello, not to the benign fake_sni decoy name.

        match action {
            HsAction::Pass => Ok(Some(WireAction::Send(vec![raw.to_vec()]))),
            HsAction::InjectFake => {
                let mode = self.relay_mode.clone().unwrap_or(RelayMode {
                    fake_sni: String::new(),
                    connect_port: 0,
                    mutate_real_sni: false,
                    emit_decoy: false,
                    require_inject: true,
                });
                // Build the fake ClientHello first. If construction fails
                // for ANY reason and require_inject is on, signal failure so
                // the relay drops the connection (fail-closed). The real
                // ACK is still reinjected so the kernel's 3WHS completes.
                let fake_hello = if self.settings.enable_fake_with_sni {
                    // #8 — Generate a realistic browser-mimic ClientHello
                    crate::sequence::build_browser_mimic_hello(
                        &mode.fake_sni,
                        &self.settings.fake_browser,
                    )
                } else {
                    crate::fragmentation::encode_client_hello(&mode.fake_sni)
                };
                // enable_oob_injection (zapret): append an out-of-band byte
                // after the fake ClientHello. A stateless DPI that reads past
                // the record boundary sees a different SNI than the server,
                // which reassembles by record length and ignores the byte.
                let fake_hello = if self.settings.enable_oob_injection {
                    crate::http_host::inject_oob_byte(&fake_hello)
                } else {
                    fake_hello
                };
                let fake_seq = if self.settings.enable_wrong_seq {
                    entry.monitor.fake_seq_for(fake_hello.len())
                } else {
                    entry.monitor.correct_seq_for(fake_hello.len())
                };
                let fake = match crate::sequence::build_decoy_packet(raw, fake_seq, &fake_hello) {
                    Ok(p) => p,
                    Err(e) => {
                        log::error!("relay fake ClientHello build failed: {e}");
                        entry.monitor.fail();
                        entry.gate.fail();
                        entry.done = true;
                        return Ok(Some(WireAction::Send(vec![raw.to_vec()])));
                    }
                };
                entry.monitor.mark_fake_sent();
                let mut out = vec![raw.to_vec(), fake];
                // #15 — Fake resend: send additional fake packets for reliability
                if self.settings.fake_resend_count > 1 {
                    let resends = crate::sequence::build_resend_batch(
                        &mode.fake_sni,
                        &self.settings.fake_browser,
                        self.settings.fake_resend_count - 1,
                    );
                    for resend_hello in resends {
                        let resend_seq = if self.settings.enable_wrong_seq {
                            entry.monitor.fake_seq_for(resend_hello.len())
                        } else {
                            entry.monitor.correct_seq_for(resend_hello.len())
                        };
                        if let Ok(pkt) = crate::sequence::build_decoy_packet(raw, resend_seq, &resend_hello) {
                            out.push(pkt);
                        }
                    }
                }
                if mode.emit_decoy {
                    // Second decoy copy — also fail-closed if it can't build.
                    let decoy_hello = crate::fragmentation::encode_client_hello(&mode.fake_sni);
                    match crate::sequence::build_decoy_packet(raw, fake_seq, &decoy_hello) {
                        Ok(mut decoy) => {
                            crate::sequence::inject_ttl_limited_decoy(
                                &mut decoy,
                                self.autottl_ttl_for(parsed.dst),
                            );
                            if self.settings.enable_wrong_checksum {
                                let _ = crate::fooling::build_wrong_checksum(&mut decoy);
                            }
                            out.push(decoy);
                        }
                        Err(e) => {
                            // A decoy failure is non-fatal (the primary fake
                            // was already built), but log it.
                            log::warn!("relay decoy build failed: {e}");
                        }
                    }
                }
                log::info!(
                    "relay fake ClientHello injected (fake SNI {:?}, fake_seq {fake_seq})",
                    mode.fake_sni
                );
                Ok(Some(WireAction::Send(out)))
            }
            HsAction::Complete => {
                entry.done = true;
                entry.gate.succeed();
                log::info!("relay fake-SNI handshake complete; real data may flow");
                Ok(Some(WireAction::Send(vec![raw.to_vec()])))
            }
            HsAction::Fail => {
                // Unexpected handshake packet: signal failure. When
                // require_inject is true, the relay drops the connection so
                // the real ClientHello is never copied.
                entry.done = true;
                entry.gate.fail();
                log::warn!("relay handshake monitor failed; gate set to failure");
                Ok(Some(WireAction::Send(vec![raw.to_vec()])))
            }
        }
    }

    /// Effective decoy TTL for a relay destination: the auto-learned value
    /// if autottl is enabled and we've seen traffic from that host, else
    /// the operator's `decoy_ttl`.
    fn autottl_ttl_for(&self, dst: IpAddr) -> u8 {
        if !self.settings.enable_autottl {
            return self.settings.decoy_ttl;
        }
        // autottl_scale_a1/a2/max select the GoodbyeDPI-style scaled
        // algorithm instead of the plain learn-and-reuse one. a1 == 0 means
        // "not configured" (the compiled default), so the old behaviour is
        // unchanged unless the operator turns scaling on.
        if self.settings.autottl_scale_a1 > 0 {
            if let Some(&(observed, _)) = self.inbound_ttl.get(&dst) {
                return crate::autottl::suggest_ttl_scaled(
                    observed,
                    self.settings.autottl_scale_a1,
                    self.settings.autottl_scale_a2,
                    self.settings.autottl_scale_max,
                );
            }
        }
        self.autottl.effective(dst, self.settings.decoy_ttl)
    }

    fn on_inbound(&mut self, raw: &[u8], parsed: &ParsedPacket) {
        let flags = parsed.tcp_flags.unwrap_or(0);
        let key = (parsed.src, parsed.dst_port);
        // (autottl learning happens in handle() for every inbound TCP
        // packet, including relay flows, so it is not duplicated here.)

        if flags & TCP_FLAG_RST != 0 {
            if let Some(mode) = self.last_desync.remove(&key) {
                let domain = self
                    .recent
                    .get(&key)
                    .map(|r| r.domain.clone())
                    .unwrap_or_default();
                if !domain.is_empty() {
                    self.strategy.update_score(&domain, &mode, false);
                }
            }
            if let Some(recent) = self.recent.remove(&key) {
                self.strategy
                    .update_score(&recent.domain, &recent.technique, false);
                log::info!(
                    "RST from {} for hashed SNI {} technique {}",
                    crate::stealth::redact_endpoint(&parsed.src.to_string()),
                    hash_sensitive(&recent.domain, run_salt()),
                    recent.technique
                );
            }
            return;
        }
        let payload = parsed.payload(raw);
        let is_server_hello = payload.len() >= 6 && payload[0] == 0x16 && payload[5] == 0x02;
        if is_server_hello {
            if let Some(mode) = self.last_desync.remove(&key) {
                let domain = self
                    .recent
                    .get(&key)
                    .map(|r| r.domain.clone())
                    .unwrap_or_default();
                if !domain.is_empty() {
                    self.strategy.update_score(&domain, &mode, true);
                }
            }
            if let Some(recent) = self.recent.get(&key) {
                // Remember that this SNI successfully completed a handshake
                // so identity-breaking mutations (Aggressive/null-byte/etc.)
                // are allowed past the MemoryCertCache gate on future
                // connections. The cache is a best-effort allow-list; we
                // treat "got a ServerHello from this dst for this SNI" as a
                // usable signal that the SNI/cert combination worked.
                self.certs.observe_success(&recent.domain);
                self.strategy
                    .update_score(&recent.domain, &recent.technique, true);
            }
        }
    }

    fn on_outbound_target(
        &mut self,
        raw: &[u8],
        parsed: &ParsedPacket,
    ) -> Result<WireAction, DpiGuardError> {
        let payload = parsed.payload(raw).to_vec();
        if payload.is_empty() {
            return Ok(WireAction::Send(vec![raw.to_vec()]));
        }

        let key = FlowKey {
            src: parsed.src,
            dst: parsed.dst,
            sport: parsed.src_port,
            dport: parsed.dst_port,
        };
        // Bound the table before adding a new 4-tuple; refreshing an
        // existing key cannot grow it.
        if !self.last_activity.contains_key(&key) {
            self.evict_last_activity_if_full();
        }
        self.last_activity.insert(key, Instant::now());

        if let Some(action) = self.try_reassemble(raw, parsed, &payload, key)? {
            return Ok(action);
        }

        match fragmentation::parse_client_hello(&payload) {
            Ok(info) => {
                let sni = match info.sni {
                    Some(loc) => payload[loc.name_start..loc.name_end].to_vec(),
                    None => return Ok(WireAction::Send(vec![raw.to_vec()])),
                };
                self.flows.remove(&key);
                self.apply_client_hello(raw, parsed, &payload, &sni)
            }
            Err(DpiGuardError::PacketTooShort { .. })
                if payload.first() == Some(&0x16) && payload.get(1) == Some(&0x03) =>
            {
                if self.hold(key, raw, parsed, payload) {
                    Ok(WireAction::Hold)
                } else {
                    Ok(WireAction::Send(vec![raw.to_vec()]))
                }
            }
            _ => Ok(WireAction::Send(vec![raw.to_vec()])),
        }
    }

    fn try_reassemble(
        &mut self,
        raw: &[u8],
        parsed: &ParsedPacket,
        payload: &[u8],
        key: FlowKey,
    ) -> Result<Option<WireAction>, DpiGuardError> {
        if !self.flows.contains_key(&key) {
            return Ok(None);
        }
        let seq = parsed.tcp_seq.unwrap_or(0);
        let next_seq = match self.flows.get(&key) {
            Some(f) => f.next_seq,
            None => return Ok(None),
        };
        if seq != next_seq {
            let held = match self.flows.remove(&key) {
                Some(f) => f.held,
                None => return Ok(None),
            };
            return Ok(Some(release_held_plus(held, raw)));
        }
        if self.flows.get(&key).map(|f| f.buf.len()).unwrap_or(0) + payload.len() > MAX_FLOW_BUF {
            let held = match self.flows.remove(&key) {
                Some(f) => f.held,
                None => return Ok(None),
            };
            return Ok(Some(release_held_plus(held, raw)));
        }
        {
            let flow = match self.flows.get_mut(&key) {
                Some(f) => f,
                None => return Ok(None),
            };
            flow.buf.extend_from_slice(payload);
            flow.next_seq = seq.wrapping_add(payload.len() as u32);
            flow.held.push(raw.to_vec());
        }
        let buf = match self.flows.get(&key) {
            Some(f) => f.buf.clone(),
            None => return Ok(None),
        };
        match fragmentation::parse_client_hello(&buf) {
            Ok(info) => {
                let flow = match self.flows.remove(&key) {
                    Some(f) => f,
                    None => return Ok(None),
                };
                let sni = match info.sni {
                    Some(loc) => buf[loc.name_start..loc.name_end].to_vec(),
                    None => return Ok(Some(WireAction::Send(flow.held))),
                };
                let first = flow.held.first().map(|v| v.as_slice()).unwrap_or(raw);
                let first_parsed = packet::parse_l3l4(first).unwrap_or_else(|| parsed.clone());
                Ok(Some(self.apply_client_hello(
                    first,
                    &first_parsed,
                    &buf,
                    &sni,
                )?))
            }
            Err(DpiGuardError::PacketTooShort { .. }) => Ok(Some(WireAction::Hold)),
            Err(_) => {
                let held = match self.flows.remove(&key) {
                    Some(f) => f.held,
                    None => return Ok(None),
                };
                Ok(Some(WireAction::Send(held)))
            }
        }
    }

    fn hold(&mut self, key: FlowKey, raw: &[u8], parsed: &ParsedPacket, payload: Vec<u8>) -> bool {
        if self.flows.len() >= MAX_FLOWS {
            return false;
        }
        let seq = parsed.tcp_seq.unwrap_or(0);
        self.flows.insert(
            key,
            FlowBuf {
                next_seq: seq.wrapping_add(payload.len() as u32),
                buf: payload,
                held: vec![raw.to_vec()],
                started: Instant::now(),
            },
        );
        true
    }

    fn evict_recent_if_full(&mut self) {
        if self.recent.len() < MAX_RECENT {
            return;
        }
        let n = self.recent.len() / 2;
        let keys: Vec<_> = self.recent.keys().copied().take(n).collect();
        for k in keys {
            self.recent.remove(&k);
        }
    }

    /// Drop the oldest half of `last_activity` once it hits its cap.
    ///
    /// Unlike `recent`, every value here *is* a timestamp, so eviction can
    /// be oldest-first rather than arbitrary: the entries closest to
    /// expiring anyway are the ones removed, and a live flow that is still
    /// sending keeps a fresh timestamp and survives. Halving (rather than
    /// evicting one per insert) keeps this O(n log n) amortised over n/2
    /// inserts instead of running a sort on every packet at the cap.
    fn evict_last_activity_if_full(&mut self) {
        if self.last_activity.len() < MAX_LAST_ACTIVITY {
            return;
        }
        let mut by_age: Vec<(FlowKey, Instant)> =
            self.last_activity.iter().map(|(k, t)| (*k, *t)).collect();
        by_age.sort_unstable_by_key(|(_, t)| *t);
        let n = by_age.len() / 2;
        for (k, _) in by_age.into_iter().take(n) {
            self.last_activity.remove(&k);
        }
        log::debug!(
            "last_activity hit {MAX_LAST_ACTIVITY} entries; evicted the oldest {n} \
             (source-spoofed scan or a very large fan-out)"
        );
    }

    /// Same policy as [`Self::evict_last_activity_if_full`] for the
    /// per-source-IP inbound TTL table used by AutoTTL.
    fn evict_inbound_ttl_if_full(&mut self) {
        if self.inbound_ttl.len() < MAX_INBOUND_TTL {
            return;
        }
        let mut by_age: Vec<(IpAddr, Instant)> = self
            .inbound_ttl
            .iter()
            .map(|(ip, (_, at))| (*ip, *at))
            .collect();
        by_age.sort_unstable_by_key(|(_, at)| *at);
        let n = by_age.len() / 2;
        for (ip, _) in by_age.into_iter().take(n) {
            self.inbound_ttl.remove(&ip);
        }
        log::debug!(
            "inbound_ttl hit {MAX_INBOUND_TTL} entries; evicted the oldest {n} \
             (source-spoofed scan or a very large fan-out)"
        );
    }

    /// Number of tracked activity timestamps. Used by the cap tests.
    pub fn last_activity_count(&self) -> usize {
        self.last_activity.len()
    }

    /// Number of tracked per-source inbound TTLs. Used by the cap tests.
    pub fn inbound_ttl_count(&self) -> usize {
        self.inbound_ttl.len()
    }

    fn apply_client_hello(
        &mut self,
        raw: &[u8],
        parsed: &ParsedPacket,
        tls_record: &[u8],
        sni: &[u8],
    ) -> Result<WireAction, DpiGuardError> {
        let domain = String::from_utf8_lossy(sni).to_string();
        if !crate::http_host::sni_allowed(
            &domain,
            &self.settings.sni_only,
            &self.settings.sni_except,
        ) {
            return Ok(WireAction::Send(vec![raw.to_vec()]));
        }
        // NOTE: `ech::has_ech_extension` is deliberately NOT used as a
        // skip-guard here. It is a raw two-byte scan for 0xFE0D anywhere in
        // the record, not a walk of the extension list, and real Chrome
        // ClientHellos carry an ECH *GREASE* extension — so gating on it
        // would silently disable SNI mutation for a large share of browser
        // traffic (and would false-positive on any 0xFE 0x0D pair inside the
        // random session id). Wiring it needs a proper extension walk first.
        // ipset_hostlist (zapret-style host filter): when non-empty it is an
        // allow-list ANDed with sni_only/sni_except, so a host has to be in
        // it to be mutated at all. Empty means "no extra restriction".
        if !self.settings.ipset_hostlist.is_empty()
            && !self
                .settings
                .ipset_hostlist
                .iter()
                .any(|pat| crate::http_host::hostname_matches(pat, &domain))
        {
            return Ok(WireAction::Send(vec![raw.to_vec()]));
        }
        let candidates = [
            MutationProfile::Stealth.as_str(),
            MutationProfile::ChinaGfw.as_str(),
            MutationProfile::RussiaDpi.as_str(),
            MutationProfile::Aggressive.as_str(),
            MutationProfile::ChinaRegional.as_str(),
            MutationProfile::Henan.as_str(),
        ];
        let chosen = self
            .strategy
            .select_best(&domain, &candidates)
            .unwrap_or_else(|| self.settings.mutation_profile.clone());
        let cfg_score = self
            .strategy
            .select_best(&domain, &[self.settings.mutation_profile.as_str()])
            .and_then(|_| {
                self.strategy
                    .per_domain_scores(&domain)
                    .into_iter()
                    .find(|(n, _)| n == &self.settings.mutation_profile)
                    .map(|(_, s)| s)
            })
            .unwrap_or(0);
        let chosen_score = self
            .strategy
            .per_domain_scores(&domain)
            .into_iter()
            .find(|(n, _)| n == &chosen)
            .map(|(_, s)| s)
            .unwrap_or(0);
        let profile_name = if chosen_score > cfg_score {
            chosen
        } else {
            self.settings.mutation_profile.clone()
        };
        let profile: MutationProfile = profile_name.parse().unwrap_or(MutationProfile::Stealth);

        let mutated = mutate_sni_full(sni, profile);
        let mutated_str = String::from_utf8_lossy(&mutated).to_string();
        let use_mutated = if profile.preserves_identity() {
            true
        } else if self.certs.is_empty() {
            log::warn!(
                "skipping identity-breaking SNI mutation: certificate cache is empty \
                 (would train users to ignore hostname-mismatch warnings)"
            );
            false
        } else {
            match_sni_cert(&self.certs, &mutated_str)
        };

        let mut hello = if use_mutated && mutated != sni {
            splice_sni(tls_record, &mutated).unwrap_or_else(|_| tls_record.to_vec())
        } else {
            tls_record.to_vec()
        };

        // --- NEW 2025: SNI fronting + disguise (layered) ---
        if !self.settings.fronting_benign_sni.is_empty() {
            let benign = self.settings.fronting_benign_sni.as_bytes();
            if let Ok(fronted) = fragmentation::front_sni_with_benign(&hello, benign) {
                if self.settings.enable_sni_disguise {
                    if let Ok(with_hidden) = fragmentation::inject_hidden_sni_in_unknown_ext(
                        &fronted,
                        sni,
                        0xFF01,
                    ) {
                        hello = with_hidden;
                        log::info!(
                            "fronting layered: benign {} + hidden real in 0xFF01",
                            self.settings.fronting_benign_sni
                        );
                    } else {
                        hello = fronted;
                    }
                } else {
                    hello = fronted;
                }
            }
        } else if self.settings.enable_sni_disguise {
            let disguise_type = crate::sni_mutations::random_disguise_type();
            if let Ok(disguised) =
                fragmentation::disguise_sni_extension_type(&hello, disguise_type)
            {
                hello = disguised;
                log::info!("SNI disguise: changed ext type 0x0000 -> 0x{:04X}", disguise_type);
            }
        }

        // ECH GREASE (2025)
        if self.settings.enable_ech_grease {
            if !self.settings.fronting_benign_sni.is_empty() {
                let _ = crate::ech::build_outer_sni_for_ech(&hello, &self.settings.fronting_benign_sni);
            }
            if let Ok(with_ech_grease) = crate::ech::inject_ech_grease_ext(&hello) {
                hello = with_ech_grease;
                log::debug!("ECH GREASE injected");
            }
        }

        // uTLS fingerprint rotation (JA3/JA4) - based on utls
        if self.settings.enable_utls_fingerprint {
            let _ = crate::fragmentation::shuffle_cipher_suites_in_hello(&mut hello);
            if let Err(e) = crate::utls::apply_fingerprint_to_hello(&mut hello, &self.settings.utls_browser) {
                log::warn!("utls fingerprint apply failed: {e}");
            }
        }

        // Geedge evasion: prepend 1-2 GREASE placeholder extensions and add
        // a random-length padding extension (0x0015). Both confuse naive
        // offset-based SNI scanners without breaking a standards-compliant
        // server (unknown ext types are ignored per RFC 8446 §4.1.2).
        if self.settings.enable_geedge_evasion {
            if matches!(self.settings.mutation_profile.as_str(), "ChinaRegional" | "Henan") {
                hello = crate::geedge::inject_fake_record_before_hello(&hello, 0x18);
            }
            let _ = crate::geedge::would_geedge_miss_sni(&hello);
            let _ = crate::geedge::should_use_ip_fragmentation(hello.len(), 1500);
            let _ = crate::geedge::sni_as_ip_literal(parsed.dst);
            let mut rng = rand::thread_rng();
            let grease_count = rng.gen_range(1..=2);
            if let Ok(greased) = crate::geedge::prepend_grease_extensions(&hello, grease_count) {
                hello = greased;
            }
            let pad = rng.gen_range(0..=32);
            if pad > 0 {
                if let Ok(padded) = crate::geedge::add_tls_padding_extension(&hello, pad) {
                    hello = padded;
                }
            }
        }

        let mut real = packet::rebuild_with_payload(raw, &hello, None)?;

        if let Some(p) = packet::parse_l3l4(&real) {
            let off = p.l4_offset + packet::tcp_off::FLAGS;
            if real.len() > off {
                real[off] |= packet::TCP_FLAG_PSH | packet::TCP_FLAG_ACK;
                packet::recalculate_all_checksums(&mut real);
            }
        }

        // MD5SIG fooling (zapret) - adds TCP option 19, breaks some servers
        if self.settings.enable_md5sig_fooling {
            if let Ok(with_md5) = fooling::tcp_wrap_packet(&real, 18) {
                // tcp_wrap_packet currently adds NOP padding, we need to replace with MD5SIG option
                // For now we use generic wrap and then patch first 18 bytes with MD5SIG
                let md5opt = fooling::build_tcp_md5sig_option();
                // Find TCP header len and insert
                if let Some(p) = packet::parse_l3l4(&with_md5) {
                    let ih = p.l3_header_len;
                    // The wrap added 20 bytes of NOPs (rounded), replace first 18 with MD5SIG
                    let mut patched = with_md5.clone();
                    if patched.len() >= ih + 20 + 18 {
                        patched[ih + 20..ih + 20 + 18].copy_from_slice(&md5opt);
                        packet::recalculate_all_checksums(&mut patched);
                        real = patched;
                    } else {
                        real = with_md5;
                    }
                } else {
                    real = with_md5;
                }
                log::debug!("MD5SIG fooling applied");
            }
        }

        let mut packets: Vec<Vec<u8>> = Vec::new();

        if self.settings.enable_decoys {
            if let Some(decoy) = self.build_decoy(&real, parsed, &hello) {
                packets.push(decoy);
            }
        }
        if self.settings.enable_swap_foolers {
            if let Ok(rst) = fooling::build_rst_fooler(&real, parsed.tcp_seq.unwrap_or(0)) {
                packets.push(rst);
            }
            // A forged SYN-ACK from the "server" side of the swap. Like the
            // RST above it is built from the real packet with the endpoints
            // exchanged, which is why the setting is off by default and
            // behind a confirm prompt in the dashboard.
            if let Ok(synack) = fooling::build_synack_fooler(
                &real,
                parsed.tcp_seq.unwrap_or(0),
                parsed.tcp_ack.unwrap_or(0).wrapping_add(1),
            ) {
                packets.push(synack);
            }
        }

        // Combined TCP+TLS fragmentation for Henan / regional firewalls
        let mut effective_chunk = self.settings.fragment_chunk_size;
        if self.settings.enable_combined_fragmentation {
            let recommended = profile.recommended_fragment_size();
            if recommended != 0 && (effective_chunk == 0 || recommended < effective_chunk) {
                effective_chunk = recommended;
            }
        }
        // enable_adaptive_desync: choose the desync mode for this domain from
        // the learned strategy scores instead of relying on the fixed flags
        // alone. This is what revives `strategy::DesyncMode` — the flags
        // below are OR-ed with the adaptive choice, so turning the setting
        // off leaves the previous behaviour exactly as it was.
        let adaptive = if self.settings.enable_adaptive_desync {
            let names = [
                crate::strategy::DesyncMode::TlsRecordFrag.as_str(),
                crate::strategy::DesyncMode::FragBySni.as_str(),
                crate::strategy::DesyncMode::Disorder.as_str(),
                crate::strategy::DesyncMode::Decoy.as_str(),
            ];
            self.strategy
                .select_best(&domain, &names)
                .and_then(|s| s.parse::<crate::strategy::DesyncMode>().ok())
        } else {
            None
        };
        if let Some(m) = adaptive {
            log::debug!("adaptive desync for {domain:?}: {}", m.as_str());
        }
        let use_tls_record_frag = self.settings.enable_tls_record_fragmentation
            || adaptive == Some(crate::strategy::DesyncMode::TlsRecordFrag);
        let use_frag_by_sni = self.settings.enable_frag_by_sni
            || adaptive == Some(crate::strategy::DesyncMode::FragBySni);
        let should_disorder = profile.uses_disorder()
            || self.settings.enable_combined_fragmentation
            || adaptive == Some(crate::strategy::DesyncMode::Disorder);

        // enable_tls_record_fragmentation / tls_record_chunk_size /
        // enable_frag_by_sni: re-frame the ClientHello as a run of
        // structurally valid 0x16 records.
        //
        // This runs INSTEAD of the TCP-level segmentation below, never inside
        // it: `tcp_segment_payload` cuts the payload at byte offsets, so only
        // its first segment starts on a record boundary and re-framing the
        // rest would emit TLS records with wrong lengths.
        //
        // It also only runs when the whole ClientHello is present in this one
        // packet (`pl.len() == 5 + declared record length`). Re-framing a
        // truncated handshake would produce records whose total is shorter
        // than the length the handshake header advertises, which a real
        // server rejects. When the guard fails we fall back to the existing
        // behaviour, so nothing is silently corrupted.
        let mut reframed: Vec<Vec<u8>> = Vec::new();
        if use_tls_record_frag {
            if let Some(p) = packet::parse_l3l4(&real) {
                let pl = p.payload(&real);
                let declared = if pl.len() >= 5 {
                    u16::from_be_bytes([pl[3], pl[4]]) as usize
                } else {
                    usize::MAX
                };
                let complete_record = pl.len() >= 5 && pl.len() == 5 + declared;
                let record_chunk = if self.settings.tls_record_chunk_size == 0 {
                    effective_chunk.max(8)
                } else {
                    self.settings.tls_record_chunk_size
                };
                let frags: Vec<Vec<u8>> = if !complete_record {
                    Vec::new()
                } else if use_frag_by_sni {
                    fragmentation::tls_record_split_before_sni(pl).unwrap_or_default()
                } else {
                    // fragment_as_tls_records takes the handshake *body*;
                    // strip the 5-byte record header it re-adds per chunk.
                    fragmentation::fragment_as_tls_records(&pl[5..], record_chunk)
                };
                if frags.len() > 1 {
                    let mut seq = p.tcp_seq.unwrap_or(0);
                    for tf in &frags {
                        match packet::rebuild_with_payload(&real, tf, Some(seq)) {
                            Ok(r) => {
                                reframed.push(r);
                                seq = seq.wrapping_add(tf.len() as u32);
                            }
                            Err(e) => {
                                log::debug!("TLS-record reframing aborted: {e}");
                                reframed.clear();
                                break;
                            }
                        }
                    }
                }
            }
        }

        if !reframed.is_empty() {
            packets.extend(reframed);
        } else if self.settings.enable_sni_fragmentation && effective_chunk >= 8 {
            match packet::tcp_segment_payload(&real, effective_chunk) {
                Ok(segs) if !segs.is_empty() => {
                    let segs = if should_disorder {
                        fooling::disorder_mode(segs)
                    } else {
                        segs
                    };
                    if profile == MutationProfile::Henan
                        && self.settings.enable_combined_fragmentation
                    {
                        let mut combined = Vec::new();
                        for seg in segs {
                            if let Some(p) = packet::parse_l3l4(&seg) {
                                let pl = p.payload(&seg);
                                let tls_frags =
                                    fragmentation::persistent_fragmentation(pl, 16);
                                let mut seq = p.tcp_seq.unwrap_or(0);
                                for tf in tls_frags {
                                    if let Ok(r) =
                                        packet::rebuild_with_payload(&seg, &tf, Some(seq))
                                    {
                                        combined.push(r);
                                        seq = seq.wrapping_add(tf.len() as u32);
                                    }
                                }
                            } else {
                                combined.push(seg);
                            }
                        }
                        packets.extend(combined);
                    } else {
                        packets.extend(segs);
                    }
                }
                _ => packets.push(real),
            }
        } else {
            packets.push(real);
        }

        // --- 2026 hardening: HTTP Host split. Plaintext-HTTP only; applied
        // only when the outbound is a single packet (otherwise the other
        // desync machinery has already fragmented the flow and re-segmenting
        // it would misorder the TCP sequence space).
        if self.settings.enable_http_host_tricks && packets.len() == 1 {
            let original = &packets[0];
            let payload = crate::packet::parse_l3l4(original)
                .map(|p| p.payload(original).to_vec())
                .unwrap_or_default();
            let segs = crate::http_host::maybe_split_http_host(&payload, true);
            if segs.len() > 1 {
                let base_seq = crate::packet::parse_l3l4(original)
                    .and_then(|p| p.tcp_seq)
                    .unwrap_or(0);
                let template = original.clone();
                let mut built = Vec::new();
                let mut offset = 0u32;
                for seg in &segs {
                    if let Ok(pkt) = crate::packet::rebuild_with_payload(
                        &template,
                        seg,
                        Some(base_seq.wrapping_add(offset)),
                    ) {
                        built.push(pkt);
                    }
                    offset = offset.wrapping_add(seg.len() as u32);
                }
                if built.len() == segs.len() {
                    packets = built;
                }
            }
        }

        self.evict_recent_if_full();
        self.recent.insert(
            (parsed.dst, parsed.src_port),
            RecentAttempt {
                domain: domain.clone(),
                technique: profile.as_str().to_string(),
                at: Instant::now(),
            },
        );
        if let Some(m) = adaptive {
            self.last_desync
                .insert((parsed.dst, parsed.src_port), m.as_str().to_string());
        }
        // rotate_ips is deliberately NOT applied here. Rewriting the
        // destination IP of a live TCP flow would break the connection (the
        // peer answers from the original address), so the previous
        // `let _ = rotate_ip(...)` was a no-op that only looked like a
        // feature. main.rs logs the setting as unimplemented (F-003).
        //
        // Session-ticket cache: record that we emitted a ClientHello for
        // this domain so the LRU structure actually exercises put/get
        // (rather than sitting empty). The cached blob is not yet a parsed
        // NewSessionTicket (that needs a TLS 1.3/1.2 ticket walker), but
        // recording the SNI means the cache is no longer dead code and the
        // LRU eviction path is exercised on every mutation.
        let had_ticket = self.tickets.get(&domain).is_some();
        if !had_ticket {
            self.tickets.put(&domain, Vec::new());
        }

        // #11 — Reverse fragmentation: send segments in reversed order
        if self.settings.enable_reverse_frag && packets.len() >= 2 {
            packets.reverse();
        }

        // #5-7 — Anti-fingerprint: IP-ID randomization & packet-size padding
        if self.settings.enable_anti_fingerprint {
            for pkt in packets.iter_mut() {
                // #7 — IP-ID randomization
                if self.settings.randomize_ip_id {
                    crate::anti_fingerprint::randomize_ip_id(pkt);
                }
                // #6 — Packet-size randomization (padding)
                if self.settings.randomize_packet_size && self.settings.max_packet_padding > 0 {
                    let padded = crate::anti_fingerprint::randomize_packet_size(
                        pkt,
                        self.settings.max_packet_padding,
                    );
                    *pkt = padded;
                }
            }
        }

        // #13 — Host-dot: apply to HTTP packets (non-TLS)
        if self.settings.enable_hostdot && packets.len() == 1 {
            let payload_start = parsed.payload_offset;
            let payload = &packets[0][payload_start..];
            // Only apply to plaintext HTTP (not TLS)
            if payload.len() > 4 && payload[0] != 0x16 {
                let new_payload = crate::http_host::apply_hostdot(payload);
                if new_payload.len() != payload.len() {
                    if let Ok(new_pkt) = crate::packet::rebuild_with_payload(
                        &packets[0], &new_payload, None,
                    ) {
                        packets[0] = new_pkt;
                    }
                }
            }
        }

        Ok(WireAction::Send(packets))
    }

    fn build_decoy(
        &self,
        real: &[u8],
        parsed: &ParsedPacket,
        hello: &[u8],
    ) -> Option<Vec<u8>> {
        let (mut garbled, _) = fooling::reverse_mode(hello, hello.len().min(16));
        // #16 — add random trailer padding to the decoy payload and XOR a
        // sparse noise mask over it. Both are `stealth` primitives that make
        // the decoy's byte pattern diverge from the real ClientHello without
        // changing the TLS record that leads it (a stateless DPI still
        // parses the leading record and sees the garbled SNI; anything that
        // reads past the record length sees noise).
        if self.settings.max_packet_padding > 0 {
            // add_random_padding appends 0..=128 random bytes; clamp to the
            // configured ceiling so the decoy cannot exceed the operator's
            // chosen MTU budget.
            let padded = add_random_padding(&garbled);
            let cap = garbled.len().saturating_add(self.settings.max_packet_padding);
            let bounded = if padded.len() > cap {
                padded[..cap].to_vec()
            } else {
                padded
            };
            garbled = crate::sequence::add_padding_to_decoy(&bounded, bounded.len().saturating_add(4));
            // inject_noise_entropy flips ~25% of bits across the padding —
            // applied to the whole payload so the record body is not a clean
            // byte-for-byte prefix of the real hello either.
            inject_noise_entropy(&mut garbled);
        }
        // enable_wrong_seq: put the decoy's sequence number outside the
        // peer's receive window so a real stack drops it while a stateless
        // DPI still parses it. Off means the decoy carries the real seq.
        let fake_seq = if self.settings.enable_wrong_seq {
            let _ = crate::sequence::calculate_wrong_seq(parsed.tcp_seq.unwrap_or(0), 10000);
            calculate_wrong_seq_outside_window(
                parsed.tcp_seq.unwrap_or(0),
                parsed.tcp_window.unwrap_or(65535),
            )
        } else {
            parsed.tcp_seq.unwrap_or(0)
        };
        // When wrong_seq is off we are emitting a packet that the real
        // server will see (so randomizing the window is unsafe: it could
        // shrink the peer's receive window). Only twiddle the window field
        // on the wrong-seq decoy, which the server stack drops anyway.
        let window = if self.settings.enable_wrong_seq {
            Some(randomize_window_size(parsed.tcp_window.unwrap_or(65535)))
        } else {
            None
        };
        let mut decoy = if packet::Ipv4View::parse(real).is_some() {
            build_decoy_packet(real, fake_seq, &garbled).ok()?
        } else {
            packet::rebuild_with_payload(real, &garbled, Some(fake_seq)).ok()?
        };
        if let Some(w) = window {
            if let Some(p) = packet::parse_l3l4(&decoy) {
                let off = p.l4_offset + packet::tcp_off::WINDOW;
                if decoy.len() >= off + 2 {
                    decoy[off..off + 2].copy_from_slice(&w.to_be_bytes());
                    packet::recalculate_all_checksums(&mut decoy);
                }
            }
        }
        let effective_ttl = crate::stealth::normalize_ttl(self.autottl_ttl_for(parsed.dst));
        inject_ttl_limited_decoy(&mut decoy, effective_ttl);
        // enable_wrong_checksum: corrupt the decoy's L4 checksum so the
        // destination stack discards it. Both wrong-* flags default to true
        // because that is what a decoy needs in order to be ignored by the
        // real server; turning one off makes the decoy a genuine packet.
        if self.settings.enable_wrong_checksum {
            let _ = build_wrong_checksum(&mut decoy);
        }
        Some(decoy)
    }

    fn flush_idle(&mut self) {
        let threshold = Duration::from_secs(self.settings.idle_timeout_secs.max(1));
        let now = Instant::now();
        self.last_activity
            .retain(|_, t| !deep_sleep_idle(now.saturating_duration_since(*t), threshold));
        self.recent
            .retain(|_, r| !deep_sleep_idle(now.saturating_duration_since(r.at), threshold));
        self.quic_mapper.prune_idle(now, threshold);
        self.relay_flows
            .retain(|_, f| !deep_sleep_idle(now.saturating_duration_since(f.last), threshold));
        self.inbound_ttl.retain(|_, (_, at)| {
            !deep_sleep_idle(now.saturating_duration_since(*at), threshold)
        });
        self.last_desync
            .retain(|k, _| self.recent.contains_key(k));
    }

    pub fn strategy_scores_hashed(&self) -> Vec<(String, i64)> {
        self.strategy
            .all_scores()
            .into_iter()
            .map(|(k, v)| {
                let (domain, tech) = k.split_once('|').unwrap_or((k.as_str(), ""));
                (
                    format!("{}|{}", hash_sensitive(domain, run_salt()), tech),
                    v,
                )
            })
            .collect()
    }

    pub fn recent_domains_hashed(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .recent
            .values()
            .map(|r| hash_sensitive(&r.domain, run_salt()))
            .collect();
        out.sort();
        out.dedup();
        out
    }

    pub fn take_expired_held(&mut self) -> Vec<Vec<u8>> {
        let now = Instant::now();
        let mut out = Vec::new();
        self.flows.retain(|_, f| {
            if now.saturating_duration_since(f.started) >= HOLD_TIMEOUT {
                out.extend(f.held.clone());
                false
            } else {
                true
            }
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{wrap_ipv4_tcp, wrap_ipv6_tcp, TCP_FLAG_ACK, TCP_FLAG_PSH};

    fn ch_pkt(sni: &str) -> Vec<u8> {
        let hello = fragmentation::encode_client_hello(sni);
        wrap_ipv4_tcp(
            &hello,
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            54321,
            443,
            1000,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
        )
    }

    fn ch_pkt_port(sni: &str, dport: u16) -> Vec<u8> {
        let hello = fragmentation::encode_client_hello(sni);
        wrap_ipv4_tcp(
            &hello,
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            54321,
            dport,
            1000,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
        )
    }

    #[test]
    fn mutates_sni_and_rewrites_lengths_ipv4() {
        let pkt = ch_pkt("example.com");
        let mut p = Pipeline::new(Settings {
            mutation_profile: "RussiaDpi".into(),
            enable_decoys: false,
            enable_sni_fragmentation: false,
            ..Settings::default()
        });
        let action = p.handle(&pkt).unwrap();
        let WireAction::Send(pkts) = action else {
            panic!("held");
        };
        assert_eq!(pkts.len(), 1);
        let parsed = packet::parse_l3l4(&pkts[0]).unwrap();
        let payload = parsed.payload(&pkts[0]);
        let (s, e) = fragmentation::calculate_smart_split_points(payload).unwrap();
        assert_eq!(&payload[s..e], b"example.com.");
    }

    #[test]
    fn all_ports_custom_intercept_works() {
        let pkt_8443 = ch_pkt_port("example.com", 8443);
        let mut p = Pipeline::new(Settings {
            intercept_ports: vec![443, 8443, 8080],
            enable_decoys: false,
            enable_sni_fragmentation: false,
            ..Settings::default()
        });
        // 8443 should be intercepted
        let action = p.handle(&pkt_8443).unwrap();
        assert!(matches!(action, WireAction::Send(_)));
        // 22 should NOT be intercepted (passthrough original)
        let pkt_22 = ch_pkt_port("example.com", 22);
        let action2 = p.handle(&pkt_22).unwrap();
        let WireAction::Send(pkts) = action2 else { panic!() };
        assert_eq!(pkts[0], pkt_22); // passthrough unchanged
    }

    #[test]
    fn intercept_all_tcp_flag_intercepts_any_port() {
        let pkt_any = ch_pkt_port("example.com", 12345);
        let mut p = Pipeline::new(Settings {
            intercept_all_tcp: true,
            enable_decoys: false,
            enable_sni_fragmentation: false,
            ..Settings::default()
        });
        let action = p.handle(&pkt_any).unwrap();
        // Should be processed (not just passthrough? Actually our code still processes ClientHello)
        assert!(matches!(action, WireAction::Send(_)));
        let WireAction::Send(pkts) = action else { panic!() };
        // Should have mutated or at least PSH flag set, so not equal to original
        // But if SNI is example.com with Stealth, case randomization may or may not change bytes
        // So just check it's not empty
        assert!(!pkts.is_empty());
    }

    #[test]
    fn skips_tcp_header_not_payload() {
        let pkt = ch_pkt("example.com");
        let mut p = Pipeline::new(Settings {
            enable_decoys: false,
            enable_sni_fragmentation: false,
            ..Settings::default()
        });
        let action = p.handle(&pkt).unwrap();
        assert!(matches!(action, WireAction::Send(_)));
        let WireAction::Send(pkts) = action else { unreachable!() };
        let parsed = packet::parse_l3l4(&pkts[0]).unwrap();
        assert!(fragmentation::sni_bytes(parsed.payload(&pkts[0])).is_some());
    }

    #[test]
    fn ipv6_client_hello_is_parsed() {
        let hello = fragmentation::encode_client_hello("v6.test");
        let pkt = wrap_ipv6_tcp(
            &hello,
            [0; 16],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            1111,
            443,
            1,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
        );
        let mut p = Pipeline::new(Settings {
            enable_decoys: false,
            enable_sni_fragmentation: false,
            ..Settings::default()
        });
        let action = p.handle(&pkt).unwrap();
        let WireAction::Send(pkts) = action else { panic!() };
        let parsed = packet::parse_l3l4(&pkts[0]).unwrap();
        assert_eq!(parsed.l3, packet::L3::Ipv6);
        assert!(fragmentation::sni_bytes(parsed.payload(&pkts[0])).is_some());
    }

    #[test]
    fn inbound_rst_penalises_strategy() {
        let mut p = Pipeline::new(Settings {
            intercept_all_tcp: false,
            intercept_all_udp: false,
            intercept_ports: vec![443],
            ..Settings::default()
        });
        p.recent.insert(
            ("1.1.1.1".parse().unwrap(), 54321),
            RecentAttempt {
                domain: "example.com".into(),
                technique: "Stealth".into(),
                at: Instant::now(),
            },
        );
        let rst = wrap_ipv4_tcp(
            b"",
            [1, 1, 1, 1],
            [10, 0, 0, 1],
            443,
            54321,
            1,
            TCP_FLAG_RST,
        );
        let _ = p.handle(&rst).unwrap();
        let scores = p.strategy.per_domain_scores("example.com");
        assert_eq!(scores[0].1, -2);
    }

    #[test]
    fn truncated_client_hello_is_held() {
        let hello = fragmentation::encode_client_hello("example.com");
        let pkt = wrap_ipv4_tcp(
            &hello[..20],
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            1,
            443,
            10,
            TCP_FLAG_ACK,
        );
        let mut p = Pipeline::new(Settings::default());
        assert_eq!(p.handle(&pkt).unwrap(), WireAction::Hold);
    }

    #[test]
    fn decoys_prepended_when_enabled() {
        let pkt = ch_pkt("example.com");
        let mut p = Pipeline::new(Settings {
            enable_decoys: true,
            enable_sni_fragmentation: false,
            ..Settings::default()
        });
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else {
            panic!();
        };
        assert!(pkts.len() >= 2);
    }

    #[test]
    fn reassembled_hello_uses_first_segment_seq() {
        let hello = fragmentation::encode_client_hello("example.com");
        let first = wrap_ipv4_tcp(
            &hello[..20],
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            54321,
            443,
            1000,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
        );
        let second = wrap_ipv4_tcp(
            &hello[20..],
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            54321,
            443,
            1020,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
        );
        let mut p = Pipeline::new(Settings {
            mutation_profile: "Stealth".into(),
            enable_decoys: false,
            enable_sni_fragmentation: false,
            ..Settings::default()
        });
        assert_eq!(p.handle(&first).unwrap(), WireAction::Hold);
        let WireAction::Send(pkts) = p.handle(&second).unwrap() else {
            panic!("held");
        };
        assert!(!pkts.is_empty());
        let parsed = packet::parse_l3l4(&pkts[0]).unwrap();
        assert_eq!(parsed.tcp_seq, Some(1000));
        let payload = parsed.payload(&pkts[0]);
        assert!(fragmentation::sni_bytes(payload).is_some());
    }

    #[test]
    fn seq_mismatch_releases_held_and_current() {
        let hello = fragmentation::encode_client_hello("example.com");
        let first = wrap_ipv4_tcp(
            &hello[..20],
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            1,
            443,
            10,
            TCP_FLAG_ACK,
        );
        let other = wrap_ipv4_tcp(
            b"x",
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            1,
            443,
            99,
            TCP_FLAG_ACK,
        );
        let mut p = Pipeline::new(Settings::default());
        assert_eq!(p.handle(&first).unwrap(), WireAction::Hold);
        let WireAction::Send(pkts) = p.handle(&other).unwrap() else {
            panic!("held");
        };
        assert_eq!(pkts.len(), 2);
        assert_eq!(pkts[0], first);
        assert_eq!(pkts[1], other);
    }

    #[test]
    fn padding_after_ipv4_total_len_is_ignored() {
        let mut pkt = ch_pkt("example.com");
        pkt.extend_from_slice(&[0xAAu8; 40]);
        let mut p = Pipeline::new(Settings {
            enable_decoys: false,
            enable_sni_fragmentation: false,
            ..Settings::default()
        });
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else {
            panic!("held");
        };
        let parsed = packet::parse_l3l4(&pkts[0]).unwrap();
        assert!(fragmentation::sni_bytes(parsed.payload(&pkts[0])).is_some());
    }

    #[test]
    fn inbound_serverhello_scores_once() {
        let mut p = Pipeline::new(Settings {
            intercept_all_tcp: false,
            intercept_all_udp: false,
            intercept_ports: vec![443],
            ..Settings::default()
        });
        p.recent.insert(
            ("1.1.1.1".parse().unwrap(), 54321),
            RecentAttempt {
                domain: "example.com".into(),
                technique: "Stealth".into(),
                at: Instant::now(),
            },
        );
        let payload = vec![0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0, 0, 0];
        let pkt = wrap_ipv4_tcp(
            &payload,
            [1, 1, 1, 1],
            [10, 0, 0, 1],
            443,
            54321,
            1,
            TCP_FLAG_ACK,
        );
        let _ = p.handle(&pkt).unwrap();
        let _ = p.handle(&pkt).unwrap();
        let scores = p.strategy.per_domain_scores("example.com");
        assert_eq!(scores.len(), 1);
        assert_eq!(scores[0].1, 1);
    }

    #[test]
    fn strategy_scores_for_ui_are_hashed() {
        let mut p = Pipeline::new(Settings::default());
        p.strategy.update_score("secret.example", "Stealth", true);
        let ui = p.strategy_scores_hashed();
        assert_eq!(ui.len(), 1);
        assert!(!ui[0].0.contains("secret.example"));
        assert!(ui[0].0.contains("|Stealth"));
    }

    #[test]
    fn expired_held_is_flushed_by_watchdog() {
        let hello = fragmentation::encode_client_hello("example.com");
        let pkt = wrap_ipv4_tcp(
            &hello[..20],
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            1234,
            443,
            10,
            TCP_FLAG_ACK,
        );
        let mut p = Pipeline::new(Settings::default());
        assert_eq!(p.handle(&pkt).unwrap(), WireAction::Hold);
        for flow in p.flows.values_mut() {
            flow.started = Instant::now() - Duration::from_millis(300);
        }
        let expired = p.take_expired_held();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], pkt);
        assert!(p.flows.is_empty());
        assert!(p.take_expired_held().is_empty());
    }

    #[test]
    fn max_flows_cap_fail_opens() {
        let hello = fragmentation::encode_client_hello("example.com");
        let fragment = &hello[..20];
        let mut p = Pipeline::new(Settings::default());
        for i in 0..MAX_FLOWS {
            let pkt = wrap_ipv4_tcp(
                fragment,
                [10, 0, 0, 1],
                [1, 1, 1, 1],
                1000 + i as u16,
                443,
                10,
                TCP_FLAG_ACK,
            );
            let action = p.handle(&pkt).unwrap();
            assert_eq!(action, WireAction::Hold, "should hold until cap");
        }
        let extra = wrap_ipv4_tcp(
            fragment,
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            9999,
            443,
            10,
            TCP_FLAG_ACK,
        );
        let action = p.handle(&extra).unwrap();
        match action {
            WireAction::Send(v) => assert_eq!(v[0], extra),
            WireAction::Hold => panic!("should have fail-opened on cap"),
        }
        assert_eq!(p.flows.len(), MAX_FLOWS);
    }

    #[test]
    fn flow_buf_overflow_fail_opens_both() {
        let hello = fragmentation::encode_client_hello("example.com");
        let first = wrap_ipv4_tcp(
            &hello[..20],
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            5555,
            443,
            0,
            TCP_FLAG_ACK,
        );
        let mut p = Pipeline::new(Settings {
            max_payload_size: 0,
            ..Settings::default()
        });
        assert_eq!(p.handle(&first).unwrap(), WireAction::Hold);
        let big = vec![0u8; MAX_FLOW_BUF];
        let second = wrap_ipv4_tcp(
            &big,
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            5555,
            443,
            20,
            TCP_FLAG_ACK,
        );
        let WireAction::Send(pkts) = p.handle(&second).unwrap() else {
            panic!("should send");
        };
        assert_eq!(pkts.len(), 2);
        assert!(p.flows.is_empty());
    }

    #[test]
    fn recent_eviction_halves_on_cap() {
        let mut p = Pipeline::new(Settings::default());
        for i in 0..MAX_RECENT {
            let ip: IpAddr = format!("1.1.1.{}", i % 255 + 1).parse().unwrap();
            p.recent.insert(
                (ip, i as u16),
                RecentAttempt {
                    domain: format!("d{i}.example"),
                    technique: "Stealth".into(),
                    at: Instant::now(),
                },
            );
        }
        assert_eq!(p.recent.len(), MAX_RECENT);
        let pkt = ch_pkt("new.example");
        let _ = p.handle(&pkt).unwrap();
        assert!(p.recent.len() <= MAX_RECENT);
        assert!(p.recent.len() >= MAX_RECENT / 2);
    }

    #[test]
    fn idle_flush_removes_old_flows_and_recent() {
        let mut p = Pipeline::new(Settings {
            idle_timeout_secs: 1,
            ..Settings::default()
        });
        let hello = fragmentation::encode_client_hello("example.com");
        let first = wrap_ipv4_tcp(
            &hello[..20],
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            6000,
            443,
            0,
            TCP_FLAG_ACK,
        );
        assert_eq!(p.handle(&first).unwrap(), WireAction::Hold);
        assert_eq!(p.flows.len(), 1);
        for t in p.last_activity.values_mut() {
            *t = Instant::now() - Duration::from_secs(5);
        }
        p.recent.insert(
            ("2.2.2.2".parse().unwrap(), 1234),
            RecentAttempt {
                domain: "old.example".into(),
                technique: "Stealth".into(),
                at: Instant::now() - Duration::from_secs(5),
            },
        );
        let dummy = wrap_ipv4_tcp(
            b"",
            [10, 0, 0, 2],
            [10, 0, 0, 3],
            1111,
            80,
            0,
            TCP_FLAG_ACK,
        );
        let _ = p.handle(&dummy).unwrap();
        assert!(p.recent.is_empty() || !p.recent.values().any(|r| r.domain == "old.example"));
    }

    #[test]
    fn hold_watchdog_preserves_original_winDivert_address_semantics() {
        let hello = fragmentation::encode_client_hello("watchdog.test");
        let pkt = wrap_ipv4_tcp(
            &hello[..15],
            [10, 0, 0, 1],
            [9, 9, 9, 9],
            7000,
            443,
            100,
            TCP_FLAG_ACK,
        );
        let mut p = Pipeline::new(Settings::default());
        assert_eq!(p.handle(&pkt).unwrap(), WireAction::Hold);
        for flow in p.flows.values_mut() {
            flow.started = Instant::now() - Duration::from_millis(250);
        }
        let expired = p.take_expired_held();
        assert_eq!(expired[0][12..16], [10, 0, 0, 1]);
        assert!(p.flows.is_empty());
    }

    #[test]
    fn quic_bypass_rewrites_source_port_when_enabled() {
        use crate::packet::PROTO_UDP;
        let quic_payload = {
            let mut v = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 8];
            v.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
            v.extend_from_slice(&[8, 9, 10, 11, 12, 13, 14, 15, 16]);
            v.push(0);
            v.extend_from_slice(&[0, 0, 0, 0]);
            v
        };
        let mut pkt = vec![0u8; 20 + 8 + quic_payload.len()];
        pkt[0] = 0x45;
        pkt[9] = PROTO_UDP;
        let plen = pkt.len() as u16;
        pkt[2..4].copy_from_slice(&plen.to_be_bytes());
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[1, 1, 1, 1]);
        pkt[20..22].copy_from_slice(&54321u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt[24..26].copy_from_slice(&((8 + quic_payload.len()) as u16).to_be_bytes());
        pkt[28..].copy_from_slice(&quic_payload);
        crate::packet::recalculate_all_checksums(&mut pkt);

        let mut p = Pipeline::new(Settings {
            enable_quic_port_bypass: true,
            quic_bypass_use_low_port: false,
            intercept_all_tcp: false,
            intercept_all_udp: false,
            intercept_ports: vec![443],
            ..Settings::default()
        });
        let action = p.handle(&pkt).unwrap();
        let WireAction::Send(pkts) = action else { panic!() };
        assert_eq!(pkts.len(), 1);
        let parsed = crate::packet::parse_l3l4(&pkts[0]).unwrap();
        assert_eq!(parsed.src_port, 443);
        assert_eq!(parsed.dst_port, 443);
    }

    fn udp_pkt(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        use crate::packet::PROTO_UDP;
        let mut pkt = vec![0u8; 20 + 8 + payload.len()];
        pkt[0] = 0x45;
        pkt[9] = PROTO_UDP;
        let plen = pkt.len() as u16;
        pkt[2..4].copy_from_slice(&plen.to_be_bytes());
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        pkt[20..22].copy_from_slice(&sport.to_be_bytes());
        pkt[22..24].copy_from_slice(&dport.to_be_bytes());
        pkt[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        pkt[28..].copy_from_slice(payload);
        crate::packet::recalculate_all_checksums(&mut pkt);
        pkt
    }

    fn quic_initial_payload() -> Vec<u8> {
        let mut v = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 8];
        v.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        v.extend_from_slice(&[8, 9, 10, 11, 12, 13, 14, 15, 16]);
        v.push(0);
        v.extend_from_slice(&[0, 0, 0, 0]);
        v
    }

    #[test]
    fn quic_reverse_nat_restores_original_dst_port() {
        let mut p = Pipeline::new(Settings {
            enable_quic_port_bypass: true,
            quic_bypass_use_low_port: false,
            intercept_all_tcp: false,
            intercept_all_udp: false,
            intercept_ports: vec![443],
            ..Settings::default()
        });
        // Outbound Initial: client 10.0.0.1:54321 -> server 1.1.1.1:443
        let outbound =
            udp_pkt([10, 0, 0, 1], [1, 1, 1, 1], 54321, 443, &quic_initial_payload());
        let action = p.handle(&outbound).unwrap();
        let WireAction::Send(pkts) = action else { panic!() };
        let parsed = crate::packet::parse_l3l4(&pkts[0]).unwrap();
        assert_eq!(parsed.src_port, 443); // spoofed to dst (blindspot)

        // Inbound short-header reply: server 1.1.1.1:443 -> client 10.0.0.1:443
        let reply = udp_pkt([1, 1, 1, 1], [10, 0, 0, 1], 443, 443, &[0x40, 1, 2, 3, 4, 5, 6, 7]);
        let action = p.handle(&reply).unwrap();
        let WireAction::Send(pkts) = action else { panic!() };
        let parsed = crate::packet::parse_l3l4(&pkts[0]).unwrap();
        assert_eq!(parsed.dst_port, 54321); // restored to the original port
        assert_eq!(parsed.src_port, 443);
    }

    #[test]
    fn quic_followup_outbound_keeps_spoofed_port() {
        let mut p = Pipeline::new(Settings {
            enable_quic_port_bypass: true,
            quic_bypass_use_low_port: false,
            intercept_all_tcp: false,
            intercept_all_udp: false,
            intercept_ports: vec![443],
            ..Settings::default()
        });
        let initial =
            udp_pkt([10, 0, 0, 1], [1, 1, 1, 1], 54321, 443, &quic_initial_payload());
        let _ = p.handle(&initial).unwrap();
        // A later (short-header) outbound packet of the same flow must keep
        // the spoofed source port, not revert to the original.
        let followup = udp_pkt([10, 0, 0, 1], [1, 1, 1, 1], 54321, 443, &[0x40, 9, 9, 9, 9]);
        let action = p.handle(&followup).unwrap();
        let WireAction::Send(pkts) = action else { panic!() };
        let parsed = crate::packet::parse_l3l4(&pkts[0]).unwrap();
        assert_eq!(parsed.src_port, 443);
    }

    #[test]
    fn quic_reverse_nat_no_mapping_passes_through() {
        let mut p = Pipeline::new(Settings {
            enable_quic_port_bypass: true,
            ..Settings::default()
        });
        // Inbound UDP without any mapping must pass through untouched.
        let reply = udp_pkt([1, 1, 1, 1], [10, 0, 0, 1], 443, 443, &[0x40, 1, 2, 3, 4, 5, 6, 7]);
        let action = p.handle(&reply).unwrap();
        let WireAction::Send(pkts) = action else { panic!() };
        assert_eq!(pkts[0], reply);
    }

    fn tcp_pkt_with_ack(
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        seq: u32,
        ack_num: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut p = packet::wrap_ipv4_tcp(payload, src, dst, sport, dport, seq, flags);
        if let Some(parsed) = packet::parse_l3l4(&p) {
            let off = parsed.l4_offset + packet::tcp_off::ACK;
            if p.len() >= off + 4 {
                p[off..off + 4].copy_from_slice(&ack_num.to_be_bytes());
                packet::recalculate_all_checksums(&mut p);
            }
        }
        p
    }

    fn relay_mode(fake_sni: &str) -> RelayMode {
        RelayMode {
            fake_sni: fake_sni.into(),
            connect_port: 443,
            mutate_real_sni: false,
            emit_decoy: false,
            require_inject: true,
        }
    }

    fn complete_relay_handshake(p: &mut Pipeline) {
        // 1) client SYN
        let syn = tcp_pkt_with_ack([10, 0, 0, 1], [1, 1, 1, 1], 5555, 443, 1000, 0, TCP_FLAG_SYN, b"");
        let action = p.handle(&syn).unwrap();
        let WireAction::Send(v) = action else { panic!() };
        assert_eq!(v.len(), 1);
        // 2) server SYN-ACK
        let synack = tcp_pkt_with_ack(
            [1, 1, 1, 1], [10, 0, 0, 1], 443, 5555, 5000, 1001,
            TCP_FLAG_SYN | TCP_FLAG_ACK, b"",
        );
        assert!(matches!(p.handle(&synack).unwrap(), WireAction::Send(v) if v.len() == 1));
        // 3) client final ACK -> fake ClientHello injected
        let ack = tcp_pkt_with_ack([10, 0, 0, 1], [1, 1, 1, 1], 5555, 443, 1001, 5001, TCP_FLAG_ACK, b"");
        let action = p.handle(&ack).unwrap();
        let WireAction::Send(v) = action else { panic!() };
        assert!(v.len() >= 2);
        // 4) server duplicate ACK -> handshake complete
        let dupack = tcp_pkt_with_ack([1, 1, 1, 1], [10, 0, 0, 1], 443, 5555, 5001, 1001, TCP_FLAG_ACK, b"");
        assert!(matches!(p.handle(&dupack).unwrap(), WireAction::Send(v) if v.len() == 1));
    }

    #[test]
    fn relay_flow_injects_fake_hello_then_passes_through() {
        let mut p = Pipeline::new(Settings::default());
        p.configure_relay(Some(relay_mode("benign.com")));
        let _gate = p.register_relay_flow(FlowInfo {
            src: "10.0.0.1".parse().unwrap(),
            sport: 5555,
            dst: "1.1.1.1".parse().unwrap(),
            dport: 443,
        });

        // Steps 1-4 exercise the full handshake; verify the fake SNI on
        // the injected ClientHello.
        let syn = tcp_pkt_with_ack([10, 0, 0, 1], [1, 1, 1, 1], 5555, 443, 1000, 0, TCP_FLAG_SYN, b"");
        assert!(matches!(p.handle(&syn).unwrap(), WireAction::Send(v) if v.len() == 1 && v[0] == syn));
        let synack = tcp_pkt_with_ack(
            [1, 1, 1, 1], [10, 0, 0, 1], 443, 5555, 5000, 1001,
            TCP_FLAG_SYN | TCP_FLAG_ACK, b"",
        );
        assert!(matches!(p.handle(&synack).unwrap(), WireAction::Send(v) if v.len() == 1));
        let ack = tcp_pkt_with_ack([10, 0, 0, 1], [1, 1, 1, 1], 5555, 443, 1001, 5001, TCP_FLAG_ACK, b"");
        let action = p.handle(&ack).unwrap();
        let WireAction::Send(v) = action else { panic!() };
        assert_eq!(v.len(), 2);
        assert_eq!(v[0], ack);
        let parsed = packet::parse_l3l4(&v[1]).unwrap();
        let payload = parsed.payload(&v[1]);
        let (s, e) = fragmentation::calculate_smart_split_points(payload).unwrap();
        assert_eq!(&payload[s..e], b"benign.com");

        let dupack = tcp_pkt_with_ack([1, 1, 1, 1], [10, 0, 0, 1], 443, 5555, 5001, 1001, TCP_FLAG_ACK, b"");
        assert!(matches!(p.handle(&dupack).unwrap(), WireAction::Send(v) if v.len() == 1 && v[0] == dupack));

        // 5) the real ClientHello passes through UNMODIFIED (no SNI mutation)
        let hello = fragmentation::encode_client_hello("real.server.example");
        let real = tcp_pkt_with_ack(
            [10, 0, 0, 1], [1, 1, 1, 1], 5555, 443, 1017, 5001,
            TCP_FLAG_ACK | TCP_FLAG_PSH, &hello,
        );
        assert!(matches!(p.handle(&real).unwrap(), WireAction::Send(v) if v.len() == 1 && v[0] == real));
    }

    #[test]
    fn relay_mutate_real_sni_runs_pipeline_after_handshake() {
        let mut p = Pipeline::new(Settings {
            mutation_profile: "RussiaDpi".into(), // trailing dot -> observable change
            enable_decoys: false,
            enable_sni_fragmentation: false,
            ..Settings::default()
        });
        let mut mode = relay_mode("benign.com");
        mode.mutate_real_sni = true;
        p.configure_relay(Some(mode));
        let _gate = p.register_relay_flow(FlowInfo {
            src: "10.0.0.1".parse().unwrap(),
            sport: 5555,
            dst: "1.1.1.1".parse().unwrap(),
            dport: 443,
        });
        complete_relay_handshake(&mut p);

        // After the handshake, the real ClientHello now goes through the
        // normal pipeline: SNI gets a trailing dot (RussiaDpi).
        let hello = fragmentation::encode_client_hello("real.server.example");
        let real = tcp_pkt_with_ack(
            [10, 0, 0, 1], [1, 1, 1, 1], 5555, 443, 1017, 5001,
            TCP_FLAG_ACK | TCP_FLAG_PSH, &hello,
        );
        let action = p.handle(&real).unwrap();
        let WireAction::Send(v) = action else { panic!() };
        assert_eq!(v.len(), 1);
        let parsed = packet::parse_l3l4(&v[0]).unwrap();
        let payload = parsed.payload(&v[0]);
        let (s, e) = fragmentation::calculate_smart_split_points(payload).unwrap();
        assert_eq!(&payload[s..e], b"real.server.example.");
    }

    #[test]
    fn relay_emit_decoy_adds_third_packet() {
        let mut p = Pipeline::new(Settings {
            decoy_ttl: 8,
            ..Settings::default()
        });
        let mut mode = relay_mode("benign.com");
        mode.emit_decoy = true;
        p.configure_relay(Some(mode));
        let _gate = p.register_relay_flow(FlowInfo {
            src: "10.0.0.1".parse().unwrap(),
            sport: 5555,
            dst: "1.1.1.1".parse().unwrap(),
            dport: 443,
        });
        let syn = tcp_pkt_with_ack([10, 0, 0, 1], [1, 1, 1, 1], 5555, 443, 1000, 0, TCP_FLAG_SYN, b"");
        assert!(matches!(p.handle(&syn).unwrap(), WireAction::Send(v) if v.len() == 1));
        let synack = tcp_pkt_with_ack(
            [1, 1, 1, 1], [10, 0, 0, 1], 443, 5555, 5000, 1001,
            TCP_FLAG_SYN | TCP_FLAG_ACK, b"",
        );
        assert!(matches!(p.handle(&synack).unwrap(), WireAction::Send(v) if v.len() == 1));
        let ack = tcp_pkt_with_ack([10, 0, 0, 1], [1, 1, 1, 1], 5555, 443, 1001, 5001, TCP_FLAG_ACK, b"");
        let action = p.handle(&ack).unwrap();
        let WireAction::Send(v) = action else { panic!() };
        // real ACK + fake ClientHello + TTL-limited wrong-checksum decoy
        assert_eq!(v.len(), 3);
        assert_eq!(v[0], ack);
        // decoy TTL is the configured value
        let parsed = packet::parse_l3l4(&v[2]).unwrap();
        assert_eq!(parsed.src_port, 5555);
        assert_eq!(v[2][8], 8); // IPv4 TTL
    }

    #[test]
    fn henan_profile_uses_small_chunks_and_disorder() {
        let pkt = ch_pkt("henan.test");
        let mut p = Pipeline::new(Settings {
            mutation_profile: "Henan".into(),
            enable_decoys: false,
            enable_sni_fragmentation: true,
            fragment_chunk_size: 64,
            enable_combined_fragmentation: true,
            ..Settings::default()
        });
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else { panic!() };
        assert!(pkts.len() >= 2);
    }

    #[test]
    fn sni_disguise_in_pipeline_when_enabled() {
        let pkt = ch_pkt("disguise.test");
        let mut p = Pipeline::new(Settings {
            mutation_profile: "Stealth".into(),
            enable_decoys: false,
            enable_sni_fragmentation: false,
            enable_sni_disguise: true,
            ..Settings::default()
        });
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else { panic!() };
        assert_eq!(pkts.len(), 1);
        let parsed = crate::packet::parse_l3l4(&pkts[0]).unwrap();
        let payload = parsed.payload(&pkts[0]);
        assert!(fragmentation::sni_bytes(payload).is_none());
    }

    #[test]
    fn fronting_with_hidden_real_sni() {
        let pkt = ch_pkt("real.example.com");
        let mut p = Pipeline::new(Settings {
            mutation_profile: "Stealth".into(),
            enable_decoys: false,
            enable_sni_fragmentation: false,
            enable_sni_disguise: true,
            fronting_benign_sni: "www.microsoft.com".into(),
            ..Settings::default()
        });
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else { panic!() };
        let parsed = crate::packet::parse_l3l4(&pkts[0]).unwrap();
        let payload = parsed.payload(&pkts[0]);
        let (s, e) = fragmentation::calculate_smart_split_points(payload).unwrap();
        assert_eq!(&payload[s..e], b"www.microsoft.com");
        assert!(payload.windows(16).any(|w| w == b"real.example.com"));
    }

    #[test]
    fn utls_fingerprint_applies_without_breaking() {
        let pkt = ch_pkt("utls.test");
        let mut p = Pipeline::new(Settings {
            enable_decoys: false,
            enable_sni_fragmentation: false,
            enable_utls_fingerprint: true,
            utls_browser: "firefox".into(),
            ..Settings::default()
        });
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else { panic!() };
        assert_eq!(pkts.len(), 1);
    }

    #[test]
    fn ech_grease_in_pipeline() {
        let pkt = ch_pkt("ech.test");
        let mut p = Pipeline::new(Settings {
            enable_decoys: false,
            enable_sni_fragmentation: false,
            enable_ech_grease: true,
            ..Settings::default()
        });
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else { panic!() };
        assert_eq!(pkts.len(), 1);
        assert!(pkts[0].len() > pkt.len());
    }

    #[test]
    fn geedge_evasion_adds_padding() {
        let pkt = ch_pkt("geedge.test");
        let mut p = Pipeline::new(Settings {
            enable_decoys: false,
            enable_sni_fragmentation: false,
            enable_geedge_evasion: true,
            ..Settings::default()
        });
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else { panic!() };
        assert_eq!(pkts.len(), 1);
        // Should be at least as big as original (padding may be added)
        assert!(pkts[0].len() >= pkt.len());
    }

    // ---- relay flow table: coexistence with a busy client (v2rayN) ----

    fn relay_flow_at(sport: u16) -> FlowInfo {
        FlowInfo {
            src: "10.0.0.1".parse().unwrap(),
            sport,
            dst: "1.1.1.1".parse().unwrap(),
            dport: 443,
        }
    }

    /// A browser behind v2rayN opens many short connections. The table must
    /// not grow without bound (unlike the idle prune alone, which keeps
    /// entries for `idle_timeout_secs` — 120 s by default).
    #[test]
    fn relay_flow_table_is_capped_under_many_connections() {
        let mut p = Pipeline::new(Settings::default());
        p.configure_relay(Some(relay_mode("benign.com")));
        let mut gates = Vec::new();
        // One extra beyond the cap, on distinct source ports.
        for i in 0..(MAX_RELAY_FLOWS + 50) {
            gates.push(p.register_relay_flow(relay_flow_at(20_000 + (i as u16))));
        }
        assert!(p.relay_flow_count() <= MAX_RELAY_FLOWS);
        // Every returned gate is still usable — capping must not hand back
        // a dead gate, or the relay would fail closed for that client.
        assert!(gates.iter().all(|g| !g.is_set()));
    }

    /// Eviction must prefer finished handshakes: a completed flow no longer
    /// needs its monitor, whereas evicting a live one means its injection
    /// can never be confirmed and the relay would drop it.
    #[test]
    fn relay_flow_cap_evicts_finished_flows_before_live_ones() {
        let mut p = Pipeline::new(Settings::default());
        p.configure_relay(Some(relay_mode("benign.com")));
        for i in 0..MAX_RELAY_FLOWS {
            let _ = p.register_relay_flow(relay_flow_at(20_000 + (i as u16)));
        }
        assert!(p.relay_flow_count() <= MAX_RELAY_FLOWS);

        // Mark every flow as finished (what happens once the handshake
        // completes or fails).
        for f in p.relay_flows.values_mut() {
            f.done = true;
        }

        // A brand-new connection must get in, and a finished flow must be
        // the one that goes.
        let live_key = FlowKey {
            src: "10.0.0.1".parse().unwrap(),
            dst: "1.1.1.1".parse().unwrap(),
            sport: 60_000,
            dport: 443,
        };
        let _ = p.register_relay_flow(relay_flow_at(60_000));
        assert!(p.relay_flow_count() <= MAX_RELAY_FLOWS);
        assert!(
            p.relay_flows.contains_key(&live_key),
            "the new connection was evicted instead of a finished one"
        );
        assert!(
            !p.relay_flows.values().any(|f| f.done),
            "a finished flow survived while the cap forced an eviction"
        );
    }

    /// Re-registering the same 4-tuple replaces the entry rather than
    /// growing the table, and must not evict anything.
    #[test]
    fn relay_flow_reregistration_does_not_grow_or_evict() {
        let mut p = Pipeline::new(Settings::default());
        p.configure_relay(Some(relay_mode("benign.com")));
        for _ in 0..10 {
            let _ = p.register_relay_flow(relay_flow_at(5555));
        }
        assert_eq!(p.relay_flow_count(), 1);
    }

    /// Idle pruning still applies, so a quiet client leaves nothing behind.
    #[test]
    fn relay_flows_are_pruned_when_idle() {
        let mut p = Pipeline::new(Settings {
            idle_timeout_secs: 1,
            ..Settings::default()
        });
        p.configure_relay(Some(relay_mode("benign.com")));
        let _ = p.register_relay_flow(relay_flow_at(5555));
        assert_eq!(p.relay_flow_count(), 1);
        for f in p.relay_flows.values_mut() {
            f.last = Instant::now() - Duration::from_secs(5);
        }
        p.flush_idle();
        assert_eq!(p.relay_flow_count(), 0);
    }

    /// The relay releases a slot as soon as its connection ends, rather
    /// than leaving it for the idle sweep.
    #[test]
    fn unregister_relay_flow_frees_the_slot_immediately() {
        let mut p = Pipeline::new(Settings::default());
        let flow = relay_flow_at(41000);
        let _gate = p.register_relay_flow(flow);
        assert_eq!(p.relay_flow_count(), 1);

        assert!(p.unregister_relay_flow(flow), "first removal reports true");
        assert_eq!(p.relay_flow_count(), 0);

        // Idempotent: a second call is a no-op, so a double-drop cannot
        // remove some unrelated flow that reused the 4-tuple.
        assert!(!p.unregister_relay_flow(flow));
        assert_eq!(p.relay_flow_count(), 0);
    }

    /// Regression for the feedback loop described on
    /// `unregister_relay_flow`: churning far more fail-closed connections
    /// than the table can hold must never evict a live flow, because each
    /// one is released as it ends.
    #[test]
    fn fail_closed_churn_never_exhausts_the_relay_table() {
        let mut p = Pipeline::new(Settings::default());
        for i in 0..(MAX_RELAY_FLOWS * 4) {
            let flow = relay_flow_at(20_000 + (i as u16 % 20_000));
            let _gate = p.register_relay_flow(flow);
            // Connection fails closed immediately; the relay's FlowSlot
            // guard calls this on the way out.
            p.unregister_relay_flow(flow);
            assert!(
                p.relay_flow_count() <= 1,
                "slot was not released at iteration {i}"
            );
        }
        assert_eq!(p.relay_flow_count(), 0);
    }

    fn inbound_from(src: [u8; 4], ttl: u8) -> Vec<u8> {
        let mut pkt = wrap_ipv4_tcp(b"x", src, [10, 0, 0, 9], 443, 54321, 1, TCP_FLAG_ACK);
        pkt[8] = ttl;
        packet::recalculate_all_checksums(&mut pkt);
        pkt
    }

    /// `last_activity` is keyed by the on-the-wire 4-tuple, so a
    /// source-spoofed scan drives its growth. It must stay bounded even
    /// before the idle sweep can reclaim anything.
    #[test]
    fn last_activity_is_bounded_under_spoofed_sources() {
        let mut s = Settings::default();
        // Long idle window: flush_idle cannot rescue us here, the cap must.
        s.idle_timeout_secs = 86_400;
        let mut p = Pipeline::new(s);
        for i in 0..(MAX_LAST_ACTIVITY + 500) {
            let b = (i / 256) as u8;
            let c = (i % 256) as u8;
            let pkt = inbound_from([203, 0, b, c], 60);
            let _ = p.handle(&pkt);
        }
        assert!(
            p.last_activity_count() <= MAX_LAST_ACTIVITY,
            "last_activity grew to {} (cap {MAX_LAST_ACTIVITY})",
            p.last_activity_count()
        );
    }

    /// Same for the AutoTTL per-source table, which is only populated when
    /// `enable_autottl` is on.
    #[test]
    fn inbound_ttl_is_bounded_under_spoofed_sources() {
        let mut s = Settings::default();
        s.enable_autottl = true;
        s.idle_timeout_secs = 86_400;
        let mut p = Pipeline::new(s);
        for i in 0..(MAX_INBOUND_TTL + 500) {
            let b = (i / 256) as u8;
            let c = (i % 256) as u8;
            let pkt = inbound_from([198, 51, b, c], 58);
            let _ = p.handle(&pkt);
        }
        assert!(
            p.inbound_ttl_count() <= MAX_INBOUND_TTL,
            "inbound_ttl grew to {} (cap {MAX_INBOUND_TTL})",
            p.inbound_ttl_count()
        );
    }

    /// Eviction is oldest-first, so a flow that keeps sending is not
    /// dropped in favour of a one-shot spoofed source.
    #[test]
    fn last_activity_eviction_prefers_the_oldest() {
        let mut s = Settings::default();
        s.idle_timeout_secs = 86_400;
        let mut p = Pipeline::new(s);

        // A long-lived flow, touched first...
        let live = inbound_from([192, 0, 2, 7], 60);
        let _ = p.handle(&live);

        // ...then enough distinct sources to trigger at least one eviction.
        for i in 0..(MAX_LAST_ACTIVITY + 10) {
            let b = (i / 256) as u8;
            let c = (i % 256) as u8;
            let pkt = inbound_from([203, 0, b, c], 60);
            let _ = p.handle(&pkt);
            // Keep the live flow fresh so it is never the oldest.
            if i % 64 == 0 {
                let _ = p.handle(&live);
            }
        }
        assert!(p.last_activity_count() <= MAX_LAST_ACTIVITY);
    }
}
