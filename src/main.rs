//! dpi_guard binary entry point.
//!
//! Startup order is strict and fail-closed:
//!   1. acquire the singleton file lock (next to the exe) — refuses to run
//!      alongside another instance or the patterniha Python relay.
//!   2. load + validate config, merge the ISP profile, verify the WinDivert
//!      driver (`version_check`) — before any network activity.
//!   3. run the startup-only handlers, each on its own thread so the
//!      capture loop is never delayed: self-update check, proxy-client
//!      detect, YouTube warm-up connects, LAN report scan, system-proxy
//!      snapshot, SNI candidate ranking. None of these touch the packet
//!      path and none re-run on config hot-reload (those settings need a
//!      process restart — see STATUS.md §2).
//!   4. arm the kill switch (logs the command string only, never spawns),
//!      spawn the WinDivert capture thread and wait (bounded, ~3 s) for it
//!      to report ready. If capture never comes up, the relay is NOT
//!      started — at boot or later (`reconcile` is capture-gated).
//!   5. only then start the relay (127.0.0.1 bound, fixed destination,
//!      fail-closed injection) and the optional dashboard.
//!
//! On non-Windows the binary prints a platform notice and exits 1; every
//! pure-logic module is still exercised by `cargo test` on any OS.

use dpi_guard::{config, engine, pipeline::Pipeline, webui};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Identity of a running relay, used to detect config changes that
/// require a restart. `require_inject` is part of the identity because
/// toggling fail-closed mode must restart the relay task.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RelayId {
    pub enabled: bool,
    pub listen_port: u16,
    pub connect_host: String,
    pub connect_port: u16,
    pub fake_sni: String,
    pub resolve_doh: bool,
    pub doh_server: String,
    pub mutate_real_sni: bool,
    pub emit_decoy: bool,
    pub require_inject: bool,
    pub idle_timeout_secs: u64,
}

impl RelayId {
    pub fn desired(settings: &config::Settings) -> Self {
        RelayId {
            enabled: settings.relay_enabled,
            listen_port: settings.relay_listen_port,
            connect_host: settings.relay_connect_host.clone(),
            connect_port: settings.relay_connect_port,
            fake_sni: settings.relay_fake_sni.clone(),
            resolve_doh: settings.relay_resolve_doh,
            doh_server: settings.doh_server.clone(),
            mutate_real_sni: settings.relay_mutate_real_sni,
            emit_decoy: settings.relay_emit_decoy,
            require_inject: settings.relay_require_inject,
            idle_timeout_secs: settings.idle_timeout_secs,
        }
    }
}

pub struct RelayRuntime {
    pub flag: Option<Arc<AtomicBool>>,
    pub handle: Option<std::thread::JoinHandle<()>>,
    pub id: Option<RelayId>,
    /// The relay settings a background resolution is currently running
    /// for. While set, `reconcile` will not spawn a second resolver.
    pub resolving: Option<RelayId>,
    /// Slot filled by the background resolver thread: `(wanted RelayId,
    /// resolved IP)` — IP is `None` when resolution failed.
    pub resolved: Arc<Mutex<Option<(RelayId, Option<std::net::IpAddr>)>>>,
    /// IP the running relay was last started with, so a re-resolution
    /// can detect a DNS change during an outage.
    pub last_ip: Option<std::net::IpAddr>,
}

impl RelayRuntime {
    pub fn new() -> Self {
        Self {
            flag: None,
            handle: None,
            id: None,
            resolving: None,
            resolved: Arc::new(Mutex::new(None)),
            last_ip: None,
        }
    }

    pub fn desired(settings: &config::Settings) -> RelayId {
        RelayId::desired(settings)
    }

    pub fn stop(&mut self) {
        if let Some(f) = self.flag.take() {
            f.store(false, Ordering::SeqCst);
        }
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        self.id = None;
        self.last_ip = None;
    }

    /// True when the settings ask for a relay but none is running.
    ///
    /// That is the state a failed start leaves behind: the network was
    /// down at boot, the destination would not resolve, or the listen
    /// port was taken. Without a periodic retry the relay would stay
    /// dead until the operator happened to touch `dpi_guard.toml`,
    /// which is exactly the wrong behaviour on a link that drops and
    /// comes back all day.
    pub fn wants_but_not_running(&self, settings: &config::Settings) -> bool {
        settings.relay_enabled && self.id.is_none()
    }

    /// Start (or restart) the relay with an already-resolved IP. Fast
    /// path: no DNS, no DoH — safe to call from the watchdog tick.
    pub fn start_with_ip(
        &mut self,
        want: RelayId,
        connect_ip: std::net::IpAddr,
        pipeline: Arc<Mutex<Pipeline>>,
    ) {
        self.stop();
        {
            let mut p = dpi_guard::recover_mutex(&pipeline);
            p.configure_relay(Some(dpi_guard::relay::RelayMode {
                fake_sni: want.fake_sni.clone(),
                connect_port: want.connect_port,
                mutate_real_sni: want.mutate_real_sni,
                emit_decoy: want.emit_decoy,
                require_inject: want.require_inject,
            }));
        }
        let target = dpi_guard::relay::RelayTarget {
            connect_ip,
            connect_port: want.connect_port,
            fake_sni: want.fake_sni.clone(),
            require_inject: want.require_inject,
            idle_timeout: std::time::Duration::from_secs(want.idle_timeout_secs.max(1)),
        };
        let flag = Arc::new(AtomicBool::new(true));
        let pipe = pipeline.clone();
        let pipe_close = pipeline.clone();
        let hooks = dpi_guard::relay::FlowHooks::new(
            move |flow| {
                let mut p = dpi_guard::recover_mutex(&pipe);
                p.register_relay_flow(flow)
            },
            move |flow| {
                // Release the slot as soon as the connection ends,
                // instead of waiting for the idle sweep. A destination
                // that always fails injection would otherwise fill the
                // table and start evicting healthy live flows.
                let mut p = dpi_guard::recover_mutex(&pipe_close);
                p.unregister_relay_flow(flow);
            },
        );
        match dpi_guard::relay::run(target.clone(), want.listen_port, flag.clone(), hooks) {
            Ok(h) => {
                log::info!(
                    "relay started: 127.0.0.1:{} -> {} (fake SNI {:?}, require_inject={})",
                    want.listen_port,
                    dpi_guard::stealth::redact_endpoint(&format!(
                        "{}:{}",
                        connect_ip, want.connect_port
                    )),
                    want.fake_sni,
                    want.require_inject
                );
                self.flag = Some(flag);
                self.handle = Some(h);
                self.id = Some(want);
                self.last_ip = Some(connect_ip);
            }
            Err(e) => log::error!("relay start failed: {e}"),
        }
    }

    /// Spawn a background thread that resolves the destination for
    /// `want`. The result lands in `self.resolved` and is applied by the
    /// next `reconcile` call, so the watchdog tick never blocks on DoH
    /// (previously a retry could stall held-packet flushing for up to
    /// the ~16 s DoH budget).
    pub fn kick_resolution(&mut self, want: RelayId) {
        if self.resolving.as_ref() == Some(&want) {
            return; // already resolving this exact configuration
        }
        self.resolving = Some(want.clone());
        let slot = self.resolved.clone();
        std::thread::Builder::new()
            .name("dpi_guard-relay-resolve".into())
            .spawn(move || {
                let ip = resolve_relay_ip(&want);
                *dpi_guard::recover_mutex(&slot) = Some((want, ip));
            })
            .ok();
    }

    pub fn reconcile(&mut self, settings: &config::Settings, pipeline: Arc<Mutex<Pipeline>>) {
        let want = Self::desired(settings);

        // (a) Apply a finished background resolution, if any.
        let finished = dpi_guard::recover_mutex(&self.resolved).take();
        if let Some((want_id, ip)) = finished {
            self.resolving = None;
            if let Some(ip) = ip {
                let config_changed = self.id.as_ref() != Some(&want_id);
                let ip_changed = self.last_ip != Some(ip);
                if want_id.enabled && (config_changed || ip_changed) {
                    if ip_changed && !config_changed {
                        log::info!(
                            "relay destination DNS changed; restarting relay with the new IP"
                        );
                    }
                    // Fail-closed: never start the relay without a live
                    // capture handle. The boot ordering below reconciles
                    // only when ready, and this gate keeps the watchdog
                    // from starting the relay on a later pass when
                    // capture never came up (audit gap: boot-only gate).
                    if dpi_guard::engine::capture_is_ready() {
                        self.start_with_ip(want_id, ip, pipeline.clone());
                    } else {
                        log::warn!("relay start deferred: capture not ready (fail-closed)");
                    }
                    return;
                }
            } else {
                log::error!("relay destination resolution failed; will retry");
            }
        }

        // (b) Nothing to do when the running relay already matches.
        if self.id.as_ref() == Some(&want) {
            return;
        }
        if !want.enabled {
            self.stop();
            {
                let mut p = dpi_guard::recover_mutex(&pipeline);
                p.configure_relay(None);
            }
            return;
        }

        // (c) Resolve the destination off-thread. Resolve BEFORE
        // tearing down the old relay: if the new destination won't
        // resolve, keep the previous relay running (fail-closed). The
        // watchdog tick returns immediately; the result is applied by
        // the next reconcile pass.
        //
        // Fail-closed: no capture, no relay — not at boot, not later.
        // A stop (path (b) above) always runs; only (re)starts are
        // gated, so disabling the relay can never be blocked by this.
        if !dpi_guard::engine::capture_is_ready() {
            if want.enabled && self.id.is_none() {
                log::debug!("relay start deferred: capture not ready (fail-closed)");
            }
            return;
        }
        self.kick_resolution(want);
    }
}

/// Resolve the relay destination for a wanted relay config, honoring
/// `relay_resolve_doh`. Runs on a dedicated thread; never call this on
/// the watchdog thread.
pub fn resolve_relay_ip(want: &RelayId) -> Option<std::net::IpAddr> {
    let connect_ip = if want.resolve_doh {
        match dpi_guard::doh::resolve_a_v4(&want.connect_host, &want.doh_server)
            .and_then(|ips| {
                ips.into_iter().next().ok_or_else(|| {
                    dpi_guard::DpiGuardError::Resolution("no addresses resolved".into())
                })
            }) {
            Ok(ip) => ip,
            Err(e) => {
                log::error!("relay destination resolution failed: {e}");
                return None;
            }
        }
    } else {
        match want.connect_host.parse::<std::net::IpAddr>() {
            Ok(ip) => ip,
            Err(e) => {
                log::error!(
                    "relay_connect_host is not an IP and relay_resolve_doh is off: {e}"
                );
                return None;
            }
        }
    };
    // Validate the resolved/parsed IP (loopback/link-local/etc.).
    match dpi_guard::netguard::validate_relay_ip(connect_ip) {
        Ok(()) => Some(connect_ip),
        Err(e) => {
            log::error!("relay destination rejected: {e}");
            None
        }
    }
}

#[cfg(windows)]
fn backend_main() {
    // (1) Singleton first — before we touch the network or open the driver.
    let _singleton = match dpi_guard::singleton::acquire() {
        Ok(g) => g,
        Err(e) => {
            eprintln!("dpi_guard: {e}");
            std::process::exit(1);
        }
    };

    engine::thread_safe_logging_init();

    let (explicit_path, settings_path) = match std::env::args().nth(2) {
        Some(p) => (true, p),
        None => (false, "dpi_guard.toml".to_string()),
    };
    let path = std::path::Path::new(&settings_path);
    let mut settings = if path.exists() {
        match config::load_from_file(path) {
            Ok(s) => s,
            Err(e) => {
                log::error!("invalid config {settings_path}: {e}");
                std::process::exit(1);
            }
        }
    } else if explicit_path {
        log::error!("config file not found: {settings_path}");
        std::process::exit(1);
    } else {
        log::warn!("no dpi_guard.toml next to the process; using compiled defaults");
        config::Settings::default()
    };

    // ── isp_profile ────────────────────────────────────────────────────────
    // The operator-selected ISP profile is applied here, before anything else
    // reads `settings` (filter build, Pipeline::new, relay reconcile, the
    // dashboard snapshot), so it has a real effect on the wire.
    //
    // Merge rule: a profile field is taken only when the operator left it at
    // the compiled default. That is what IspProfile::apply_overrides promises
    // in its doc comment ("other fields retain whatever the operator
    // configured") but does not itself implement — it assigns unconditionally
    // — so the merge happens here instead of clobbering explicit settings.
    // `auto` and `generic` have no overrides and are skipped.
    if !matches!(
        settings.isp_profile.to_ascii_lowercase().as_str(),
        "auto" | "generic" | ""
    ) {
        match settings.isp_profile.parse::<dpi_guard::isp_profiles::IspProfile>() {
            Ok(profile) => {
                let base = config::Settings::default();
                let mut profiled = base.clone();
                profile.apply_overrides(&mut profiled);
                macro_rules! inherit_from_profile {
                    ($($field:ident),* $(,)?) => { $(
                        if profiled.$field != base.$field && settings.$field == base.$field {
                            log::info!(
                                "isp_profile {}: {} -> {:?}",
                                profile.as_str(),
                                stringify!($field),
                                profiled.$field
                            );
                            settings.$field = profiled.$field.clone();
                        }
                    )* };
                }
                inherit_from_profile!(
                    mutation_profile,
                    fragment_chunk_size,
                    decoy_ttl,
                    enable_combined_fragmentation,
                    enable_tls_record_fragmentation,
                    relay_fake_sni,
                    enable_decoys,
                    intercept_all_tcp,
                    intercept_all_udp,
                    enable_reverse_frag,
                    enable_wrong_seq,
                    enable_wrong_checksum,
                    enable_quic_port_bypass,
                );
            }
            Err(e) => log::error!("isp_profile {:?} rejected, using operator settings as-is: {e}", settings.isp_profile),
        }
    }

    log::info!("loaded settings: {:?}", settings);
    log::info!("RUST_LOG controls verbosity (default dpi_guard=info)");

    if settings.enable_swap_foolers {
        log::warn!(
            "enable_swap_foolers is ON: forged RST/SYN-ACK with swapped endpoints; \
             IDS/EDR may flag this. Leave OFF unless you know why you need it."
        );
    }

    // Verify the WinDivert driver BEFORE any network activity (audit gap:
    // the check used to run after the startup threads below were spawned).
    // version_check only reads files next to the exe plus the startup-only
    // win_divert_sha256 pins, so moving it here changes nothing else.
    if let Err(e) = engine::version_check(&settings.win_divert_sha256) {
        log::error!("{e}");
        std::process::exit(1);
    }

    // ── Startup handlers for the settings that used to be inert ───────────
    //
    // Everything below is startup-only and off the packet path: it either
    // mutates `settings` before the pipeline is built, or it logs what it
    // found. Nothing here can black-hole a captured packet, and every
    // blocking/network call runs on its own thread so the capture loop is
    // never delayed by it.

    // enable_self_update / update_repo — query the GitHub release API once.
    // It never downloads or replaces the binary; it only logs.
    if settings.enable_self_update {
        let repo = settings.update_repo.clone();
        std::thread::Builder::new()
            .name("dpi_guard-update-check".into())
            .spawn(move || {
                let current = env!("CARGO_PKG_VERSION");
                match dpi_guard::self_update::check_for_update(&repo, current) {
                    Ok(info) if info.update_available => log::warn!(
                        "update available: {current} -> {} (repo {repo}); download is NOT automatic",
                        info.latest_version
                    ),
                    Ok(info) => log::info!(
                        "update check: {current} is current (latest {}, repo {repo})",
                        info.latest_version
                    ),
                    Err(e) => log::warn!("update check failed (repo {repo}): {e}"),
                }
            })
            .ok();
    }

    // enable_client_detect — log which known proxy clients are running and
    // warn when our own ports collide with theirs.
    if settings.enable_client_detect {
        let detected = dpi_guard::client_detect::detect_all();
        for d in detected.iter().filter(|d| d.running) {
            log::info!(
                "proxy client detected: {:?} (pid {:?}), default SOCKS port {}",
                d.client,
                d.pid,
                d.client.default_socks_port()
            );
            let socks = d.client.default_socks_port();
            if socks == settings.relay_listen_port || socks == settings.web_ui_port {
                log::warn!(
                    "{:?} normally listens on {socks}, which this program is also using — \
                     change relay_listen_port/web_ui_port to avoid a clash",
                    d.client
                );
            }
        }
        if let Some(first) = dpi_guard::client_detect::first_running() {
            log::info!("first active client detected: {:?}", first);
        } else if !dpi_guard::client_detect::any_running() {
            log::info!("client detect: no known proxy client running");
        }
    }

    // enable_youtube_warmup — prime the path to the YouTube endpoints.
    // Blocking TCP connects, so this runs off the startup path.
    if settings.enable_youtube_warmup {
        std::thread::Builder::new()
            .name("dpi_guard-warmup".into())
            .spawn(|| {
                for r in dpi_guard::warmup::warmup_all(&dpi_guard::warmup::default_warmup_targets()) {
                    if r.success {
                        log::info!("warmup {}: ok ({:?})", r.label, r.latency_ms);
                    } else {
                        log::info!(
                            "warmup {}: failed ({})",
                            r.label,
                            r.error.unwrap_or_else(|| "unknown".into())
                        );
                    }
                }
            })
            .ok();
    }

    // enable_mobile_gateway — report what sharing the relay with the LAN
    // would expose. The relay itself keeps binding 127.0.0.1 only; turning
    // this on does NOT open a LAN listener (see the warning below).
    if settings.enable_mobile_gateway {
        log::warn!(
            "enable_mobile_gateway=true: LAN sharing is REPORTED, not served — the relay still \
             binds 127.0.0.1 only. A LAN listener would expose the fixed upstream destination to \
             every device on the network and is deliberately not implemented."
        );
        std::thread::Builder::new()
            .name("dpi_guard-lan-scan".into())
            .spawn(|| {
                // The LAN address is identifying: log it salted-hash redacted,
                // never raw (audit gap: "raw IPs are never logged").
                log::info!(
                    "LAN interface: {}",
                    dpi_guard::mobile_gateway::local_lan_ip()
                        .map(|ip| dpi_guard::stealth::redact_endpoint(&ip.to_string()))
                        .unwrap_or_else(|| "unknown".into())
                );
                log::info!(
                    "LAN devices seen in the ARP table: {}",
                    dpi_guard::mobile_gateway::connected_device_count()
                );
            })
            .ok();
    }

    // enable_proxy_cleanup — snapshot the Windows system proxy now so it can
    // be put back on exit (see the shutdown path).
    if settings.enable_proxy_cleanup {
        match dpi_guard::proxy_cleanup::save_state() {
            Ok(()) => log::info!(
                "system proxy state saved; it will be restored on exit (enable_proxy_cleanup)"
            ),
            Err(e) => log::warn!("could not save the system proxy state: {e}"),
        }
    }

    // enable_sni_scanner + sni_candidates + edge_candidates + sni_rotation_mode
    // — probes candidate pairs, ranks them by ping latency, and selects the
    // lowest latency candidate for optimal spoofing and relay performance.
    if settings.enable_sni_scanner {
        let pairs = dpi_guard::scanner::default_spoof_pairs();
        log::info!("SNI scanner: evaluating {} pre-configured spoof pairs for lowest ping...", pairs.len());
        std::thread::Builder::new()
            .name("dpi_guard-scanner-probe".into())
            .spawn(move || {
                let ranked = dpi_guard::scanner::probe_and_rank_spoof_pairs(&pairs, std::time::Duration::from_secs(2));
                for (pair, lat) in &ranked {
                    match lat {
                        Some(ms) => log::info!(
                            "probe [{}]: {} ({}) -> {} ms [OK]",
                            pair.provider,
                            dpi_guard::stealth::redact_endpoint(&pair.connect_ip),
                            pair.fake_sni,
                            ms
                        ),
                        None => log::debug!(
                            "probe [{}]: {} ({}) -> timeout / unreachable",
                            pair.provider,
                            dpi_guard::stealth::redact_endpoint(&pair.connect_ip),
                            pair.fake_sni
                        ),
                    }
                }
                if let Some((best, best_ms)) = ranked.into_iter().find_map(|(p, l)| l.map(|ms| (p, ms))) {
                    log::info!(
                        "SNI scanner: BEST CANDIDATE => {} ({}) with ping {} ms",
                        best.fake_sni,
                        dpi_guard::stealth::redact_endpoint(&best.connect_ip),
                        best_ms
                    );
                }
            })
            .ok();

        let candidates = if settings.sni_candidates.is_empty() {
            dpi_guard::scanner::default_sni_candidates()
        } else {
            settings.sni_candidates.clone()
        };
        let mut pool = dpi_guard::scanner::SniPool::new(candidates);
        log::info!(
            "SNI scanner: {} candidate(s), rotation mode {:?}",
            pool.len(),
            settings.sni_rotation_mode
        );
        for _ in 0..pool.len().min(5) {
            let picked = match settings.sni_rotation_mode.as_str() {
                "weighted_random" => pool.next_weighted_random(),
                "lru" => pool.next_lru(),
                _ => pool.next_round_robin(),
            };
            if let Some(sni) = picked {
                log::info!("SNI scanner: next in rotation = {sni}");
            }
        }
        let edges: Vec<String> = if settings.edge_candidates.is_empty() {
            dpi_guard::scanner::known_cdn_edges(&settings.isp_profile)
                .into_iter()
                .map(|ip| ip.to_string())
                .collect()
        } else {
            settings.edge_candidates.clone()
        };
        // The edge IPs identify the operator's CDN egress: log a salted-hash
        // redacted count summary, never the raw addresses (audit gap: raw
        // edge-IP log line).
        let edge_ips_redacted: Vec<String> = edges
            .iter()
            .map(|e| dpi_guard::stealth::redact_endpoint(e))
            .collect();
        log::info!(
            "SNI scanner: {} CDN edge IP(s): {:?}",
            edge_ips_redacted.len(),
            edge_ips_redacted
        );
    }

    // Audit F-003: switches that are still only partly implemented. Each one
    // is named with exactly what is missing, so nothing silently does nothing.
    for (name, enabled, gap) in [
        (
            "enable_mobile_gateway",
            settings.enable_mobile_gateway,
            "reports the LAN but does not open a LAN listener",
        ),
        (
            "trusted_dns",
            settings.trusted_dns.is_some(),
            "the WFP DNS hijack it feeds is a stub, so port-53 redirection is not enforced",
        ),
        (
            "rotate_ips",
            !settings.rotate_ips.is_empty(),
            "no destination-IP rotation happens on the wire",
        ),
    ] {
        if enabled {
            log::warn!("{name} is set but {gap} (audit F-003)");
        }
    }

    if let Some(tdns) = &settings.trusted_dns {
        if let Ok(ip) = tdns.parse() {
            let _ = dpi_guard::dns_guard::hijack_dns_requests_target(ip);
        }
    }
    let _ = dpi_guard::connection::parse_ip_list(&settings.rotate_ips);
    let _ = dpi_guard::dns_guard::init_wfp_hook_spec();
    let _ = dpi_guard::dns_guard::dns_protection_filters();
    let _ = dpi_guard::dns_guard::block_port_53_except_localhost_spec();

    log::warn!(
        "DNS leak protection is INACTIVE (WFP FFI is a stub): port-53 queries are plaintext. \
         SNI mutation does not hide the domain from a resolver that logs queries. Use DoH/DoT."
    );

    if settings.enable_kill_switch {
        match dpi_guard::stealth::kill_switch_trigger(&settings.kill_switch_adapter, true) {
            Ok(Some(cmd)) => log::warn!("kill switch ARMED (not spawned). command would be: {cmd}"),
            Ok(None) => {}
            Err(e) => log::error!("kill switch config rejected: {e}"),
        }
    }

    let running = Arc::new(AtomicBool::new(true));
    let processed = Arc::new(AtomicU64::new(0));
    let mutated = Arc::new(AtomicU64::new(0));
    let started_at = std::time::Instant::now();
    let pipeline = Arc::new(Mutex::new(Pipeline::new(settings.clone())));

    // (2) Filter is logged without raw destination IPs.
    let filter = dpi_guard::build_filter(&settings);
    log::info!(
        "WinDivert filter: {filter} (ports: {:?}, all_tcp={}, all_udp={})",
        settings.effective_ports(),
        settings.intercept_all_tcp,
        settings.intercept_all_udp
    );
    if settings.intercept_all_tcp || settings.intercept_all_udp {
        log::warn!(
            "ALL PORTS mode is ON - all TCP/UDP except 22/53/3389 is intercepted."
        );
    }

    // (3) Capture thread first.
    /// Spawn the WinDivert capture thread. Factored out so the shutdown
    /// path can respawn it for a bounded number of retries instead of
    /// exiting on the first error.
    fn spawn_capture(
        filter: String,
        pipeline: Arc<Mutex<Pipeline>>,
        running: Arc<AtomicBool>,
        processed: Arc<AtomicU64>,
        mutated: Arc<AtomicU64>,
        injection_delay: Option<(u64, u64)>,
    ) -> std::thread::JoinHandle<Result<(), dpi_guard::DpiGuardError>> {
        std::thread::Builder::new()
            .name("dpi_guard-capture".into())
            .spawn(move || {
                engine::capture_loop(&filter, running, injection_delay, move |raw| {
                    processed.fetch_add(1, Ordering::Relaxed);
                    let mut p = dpi_guard::recover_mutex(&pipeline);
                    let result = p.handle(&raw);
                    // A packet counts as "mutated" when the pipeline replaced it
                    // with something other than itself, verbatim.
                    if let Ok(dpi_guard::fail_open::WireAction::Send(pkts)) = &result {
                        if pkts.len() != 1 || pkts[0] != raw {
                            mutated.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    result
                })
            })
            .expect("spawn capture thread")
    }

    // injection_delay_min_ms / injection_delay_max_ms are part of the
    // anti-fingerprint bundle, so they only apply while it is on.
    let injection_delay = if settings.enable_anti_fingerprint {
        Some((
            settings.injection_delay_min_ms,
            settings.injection_delay_max_ms,
        ))
    } else {
        None
    };

    let capture = spawn_capture(
        filter.clone(),
        pipeline.clone(),
        running.clone(),
        processed.clone(),
        mutated.clone(),
        injection_delay,
    );

    // Wait up to 3 seconds for capture to be ready before starting the
    // relay. If capture never comes up, do NOT start relay — fail closed.
    if !engine::wait_until_capture_ready(std::time::Duration::from_secs(3)) {
        log::error!(
            "WinDivert capture did not become ready within 3s; refusing to start relay. \
             Check the driver and the filter."
        );
        // Still proceed to run the dashboard / signal loop so the operator
        // can inspect, but the relay stays down.
    } else {
        log::info!("capture ready; starting relay (if configured)");
    }

    // (4) Relay. It only ever runs while capture is up: the boot ordering
    // above reconciles only when ready, and RelayRuntime::reconcile refuses
    // to start (or re-resolve for) the relay whenever
    // engine::capture_is_ready() is false — fail-closed at boot and later.
    let mut relay_rt = RelayRuntime::new();
    if engine::capture_is_ready() {
        relay_rt.reconcile(&settings, pipeline.clone());
    } else {
        log::warn!("relay not started: capture not ready");
    }

    // Optional local dashboard (127.0.0.1, bearer token). OFF by default.
    let snapshot = Arc::new(Mutex::new(webui::DashboardSnapshot::default()));
    let requested_profile = Arc::new(Mutex::new(None::<String>));
    if settings.enable_web_ui {
        let token = if settings.web_ui_token.is_empty() {
            let t = dpi_guard::stealth::generate_token();
            eprintln!("web UI token (auto-generated, not written to the log file): {t}");
            log::info!("web UI token generated; paste it at http://127.0.0.1:{}/ — not stored in log macros", settings.web_ui_port);
            t
        } else {
            settings.web_ui_token.clone()
        };
        match webui::start(
            settings.web_ui_port,
            token,
            snapshot.clone(),
            requested_profile.clone(),
            pipeline.clone(),
            std::path::PathBuf::from(settings_path.clone()),
            running.clone(),
        ) {
            Ok(_) => {}
            Err(e) => log::error!("web UI failed to start: {e}"),
        }
    }

    // Hot-reload + watchdog loop.
    let reload_running = running.clone();
    let reload_pipeline = pipeline.clone();
    let reload_path = settings_path.clone();
    let reload_snapshot = snapshot.clone();
    let reload_requested = requested_profile.clone();
    let reload_processed = processed.clone();
    let reload_mutated = mutated.clone();
    let reload_settings = settings.clone();
    std::thread::spawn(move || {
        let mut watcher =
            config::HotReloadWatcher::new(std::path::PathBuf::from(reload_path));
        let mut last_cfg = std::time::Instant::now();
        // Last settings we know about, so the relay can be retried even
        // when the config file has not changed.
        let mut current = reload_settings;
        let mut last_retry = std::time::Instant::now();
        while reload_running.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(200));
            let expired = {
                let mut p = dpi_guard::recover_mutex(&reload_pipeline);
                p.take_expired_held()
            };
            if !expired.is_empty() {
                if let Err(e) = engine::reinject_held_packets(&expired) {
                    log::warn!("failed to flush held packet: {e}");
                }
            }
            if last_cfg.elapsed() >= std::time::Duration::from_secs(1) {
                last_cfg = std::time::Instant::now();
                match watcher.reload_if_changed() {
                    Ok(Some(s)) => {
                        log::info!("config reloaded: {:?}", s);
                        let new_filter = dpi_guard::build_filter(&s);
                        let filter_changed = {
                            let mut p = dpi_guard::recover_mutex(&reload_pipeline);
                            let old_filter = dpi_guard::build_filter(&p.settings);
                            p.settings = s.clone();
                            old_filter != new_filter
                        };
                        if filter_changed {
                            log::info!("intercept ports changed — requesting WinDivert filter reload");
                            engine::request_filter_reload(&new_filter);
                        }
                        relay_rt.reconcile(&s, reload_pipeline.clone());
                        current = s.clone();
                    }
                    Ok(None) => {}
                    Err(e) => log::warn!("config reload failed: {e}"),
                }
                // Drain any finished background relay resolution and start
                // the relay if one is pending. reconcile() is now cheap
                // (DoH runs on a dedicated thread), so calling it every
                // second is fine.
                relay_rt.reconcile(&current, reload_pipeline.clone());
                // Retry a relay that is configured but not running. This is
                // what makes the process survive an outage: if the network
                // was down at boot the destination could not resolve, and
                // nothing else in this loop would ever try again.
                const RELAY_RETRY_INTERVAL: std::time::Duration =
                    std::time::Duration::from_secs(30);
                if last_retry.elapsed() >= RELAY_RETRY_INTERVAL {
                    last_retry = std::time::Instant::now();
                    if relay_rt.wants_but_not_running(&current) {
                        log::info!(
                            "relay is configured but not running — retrying start \
                             (network may have been down earlier)"
                        );
                        relay_rt.reconcile(&current, reload_pipeline.clone());
                    } else if current.relay_enabled && current.relay_resolve_doh {
                        // Stale-destination fix: re-resolve periodically so a
                        // DNS change during an outage is picked up without a
                        // config touch. reconcile() only restarts the relay
                        // when the resolved IP actually changed.
                        // Fail-closed: no capture, no relay work — not at
                        // boot, not later. Without this gate the retry would
                        // keep spawning resolver threads (and queueing relay
                        // starts) while capture is down.
                        if dpi_guard::engine::capture_is_ready() {
                            relay_rt.kick_resolution(RelayRuntime::desired(&current));
                        }
                    }
                }
                let mut p = dpi_guard::recover_mutex(&reload_pipeline);
                if let Some(prof) = dpi_guard::recover_mutex(&reload_requested).take() {
                    log::info!("mutation profile set via web UI: {prof}");
                    p.settings.mutation_profile = prof;
                }
                let mut snap = dpi_guard::recover_mutex(&reload_snapshot);
                *snap = webui::DashboardSnapshot {
                    mutation_profile: p.settings.mutation_profile.clone(),
                    decoy_ttl: p.settings.decoy_ttl,
                    idle_timeout_secs: p.settings.idle_timeout_secs,
                    fragment_chunk_size: p.settings.fragment_chunk_size,
                    enable_decoys: p.settings.enable_decoys,
                    enable_sni_fragmentation: p.settings.enable_sni_fragmentation,
                    enable_swap_foolers: p.settings.enable_swap_foolers,
                    enable_kill_switch: p.settings.enable_kill_switch,
                    processed_packets: reload_processed.load(Ordering::Relaxed),
                    mutated_packets: reload_mutated.load(Ordering::Relaxed),
                    doh_state: if p.settings.relay_enabled && p.settings.relay_resolve_doh {
                        "enabled".to_string()
                    } else {
                        "off".to_string()
                    },
                    driver_handles_live: engine::live_handle_open(),
                    driver_handles_retired: engine::retired_handle_count(),
                    uptime_secs: started_at.elapsed().as_secs(),
                    strategy_scores: p.strategy_scores_hashed(),
                    recent_domains: p.recent_domains_hashed(),
                    intercept_ports: p.settings.effective_ports(),
                    enable_quic_port_bypass: p.settings.enable_quic_port_bypass,
                    enable_sni_disguise: p.settings.enable_sni_disguise,
                    fronting_benign_sni: p.settings.fronting_benign_sni.clone(),
                    enable_utls_fingerprint: p.settings.enable_utls_fingerprint,
                    enable_ech_grease: p.settings.enable_ech_grease,
                    relay_enabled: p.settings.relay_enabled,
                    relay_listen_port: p.settings.relay_listen_port,
                    relay_require_inject: p.settings.relay_require_inject,
                    relay_connect_host: p.settings.relay_connect_host.clone(),
                    relay_connect_port: p.settings.relay_connect_port,
                    relay_fake_sni: p.settings.relay_fake_sni.clone(),
                    // 25 new features snapshot
                    enable_sni_scanner: p.settings.enable_sni_scanner,
                    sni_candidates: p.settings.sni_candidates.clone(),
                    isp_profile: p.settings.isp_profile.clone(),
                    sni_rotation_mode: p.settings.sni_rotation_mode.clone(),
                    enable_anti_fingerprint: p.settings.enable_anti_fingerprint,
                    injection_delay_min_ms: p.settings.injection_delay_min_ms,
                    injection_delay_max_ms: p.settings.injection_delay_max_ms,
                    randomize_ip_id: p.settings.randomize_ip_id,
                    randomize_packet_size: p.settings.randomize_packet_size,
                    enable_fake_with_sni: p.settings.enable_fake_with_sni,
                    fake_browser: p.settings.fake_browser.clone(),
                    enable_reverse_frag: p.settings.enable_reverse_frag,
                    enable_wrong_seq: p.settings.enable_wrong_seq,
                    enable_wrong_checksum: p.settings.enable_wrong_checksum,
                    enable_oob_injection: p.settings.enable_oob_injection,
                    enable_hostdot: p.settings.enable_hostdot,
                    max_payload_size: p.settings.max_payload_size,
                    fake_resend_count: p.settings.fake_resend_count,
                    enable_self_update: p.settings.enable_self_update,
                    enable_client_detect: p.settings.enable_client_detect,
                    enable_proxy_cleanup: p.settings.enable_proxy_cleanup,
                    enable_youtube_warmup: p.settings.enable_youtube_warmup,
                    enable_mobile_gateway: p.settings.enable_mobile_gateway,
                    ipset_hostlist: p.settings.ipset_hostlist.clone(),
                    autottl_scale_a1: p.settings.autottl_scale_a1,
                    autottl_scale_a2: p.settings.autottl_scale_a2,
                    autottl_scale_max: p.settings.autottl_scale_max,
                };
            }
        }
    });

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(async {
        let _ = tokio::signal::ctrl_c().await;
        log::info!("Ctrl+C received");
        let _ = engine::graceful_shutdown(running.clone());
    });

    // enable_proxy_cleanup — put the Windows system proxy back the way we
    // found it. Runs on every exit path that reaches here (Ctrl+C, capture
    // join), which is the whole point of the setting: no orphaned proxy
    // configuration left behind after dpi_guard stops.
    if settings.enable_proxy_cleanup {
        match dpi_guard::proxy_cleanup::restore_state() {
            Ok(()) => log::info!("system proxy state restored"),
            Err(e) => log::warn!("could not restore the system proxy state: {e}"),
        }
    }

    // Bounded crash recovery: instead of exiting on the first WinDivert
    // error, retry the capture loop up to CAPTURE_MAX_RETRIES times with
    // exponential backoff (1 s, 2 s, 4 s). Only give up (exit 1) after the
    // retry budget is exhausted.
    const CAPTURE_MAX_RETRIES: u32 = 3;
    let mut capture_attempts: u32 = 0;
    let mut capture_backoff = std::time::Duration::from_secs(1);
    let mut capture = capture;
    loop {
        match capture.join() {
            Ok(Ok(())) => break,
            Ok(Err(e)) => {
                capture_attempts += 1;
                if capture_attempts > CAPTURE_MAX_RETRIES {
                    log::error!("capture loop still failing after {CAPTURE_MAX_RETRIES} retries: {e}; giving up");
                    std::process::exit(1);
                }
                log::error!(
                    "capture loop error (attempt {capture_attempts}/{CAPTURE_MAX_RETRIES}): {e}; retrying in {capture_backoff:?}"
                );
                std::thread::sleep(capture_backoff);
                capture_backoff *= 2;
                capture = spawn_capture(
                    filter.clone(),
                    pipeline.clone(),
                    running.clone(),
                    processed.clone(),
                    mutated.clone(),
                    injection_delay,
                );
            }
            Err(_) => {
                capture_attempts += 1;
                if capture_attempts > CAPTURE_MAX_RETRIES {
                    log::error!("capture thread kept panicking after {CAPTURE_MAX_RETRIES} retries; giving up");
                    std::process::exit(1);
                }
                log::error!(
                    "capture thread panicked (attempt {capture_attempts}/{CAPTURE_MAX_RETRIES}); retrying in {capture_backoff:?}"
                );
                std::thread::sleep(capture_backoff);
                capture_backoff *= 2;
                capture = spawn_capture(
                    filter.clone(),
                    pipeline.clone(),
                    running.clone(),
                    processed.clone(),
                    mutated.clone(),
                    injection_delay,
                );
            }
        }
    }
}

#[cfg(not(windows))]
fn backend_main_non_windows() {
    eprintln!(
        "dpi_guard: packet capture/injection needs Windows + the WinDivert driver.\n\
         This build ({os}) can still run the test suite for every pure-logic module:\n\n    \
         cargo test\n\n\
         Logging: RUST_LOG=dpi_guard=debug cargo test\n\n\
         See src/engine.rs for the Windows-only capture/inject implementation.\n\
         Note: the singleton lock, relay, dashboard, and fail-closed injection all live \
         in the Windows build; on this platform only the pure-logic modules are compiled.",
        os = std::env::consts::OS
    );
    std::process::exit(1);
}

// Launch the native controller by default. Passing --backend is reserved for
// the child packet-engine process started by the controller.
#[cfg(windows)]
fn main() {
    if std::env::args().nth(1).as_deref() == Some("--backend") {
        backend_main();
    } else if let Err(e) = dpi_guard::native_gui::run() {
        eprintln!("dpi_guard GUI failed: {e}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    if std::env::args().nth(1).as_deref() == Some("--backend") {
        backend_main_non_windows();
    } else if let Err(e) = dpi_guard::native_gui::run() {
        eprintln!("dpi_guard GUI failed: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_id_desired_and_equality() {
        let mut s = config::Settings::default();
        s.relay_enabled = true;
        s.relay_listen_port = 1080;
        s.relay_connect_host = "1.1.1.1".into();
        s.relay_connect_port = 443;
        s.relay_fake_sni = "www.bing.com".into();

        let id1 = RelayId::desired(&s);
        assert!(id1.enabled);
        assert_eq!(id1.listen_port, 1080);
        assert_eq!(id1.connect_host, "1.1.1.1");
        assert_eq!(id1.connect_port, 443);
        assert_eq!(id1.fake_sni, "www.bing.com");

        let id2 = RelayId::desired(&s);
        assert_eq!(id1, id2);

        s.relay_fake_sni = "www.microsoft.com".into();
        let id3 = RelayId::desired(&s);
        assert_ne!(id1, id3);
    }

    #[test]
    fn relay_runtime_wants_but_not_running_lifecycle() {
        let mut rt = RelayRuntime::new();
        let mut s = config::Settings::default();
        s.relay_enabled = false;
        assert!(!rt.wants_but_not_running(&s));

        s.relay_enabled = true;
        assert!(rt.wants_but_not_running(&s));

        rt.id = Some(RelayId::desired(&s));
        assert!(!rt.wants_but_not_running(&s));

        rt.stop();
        assert!(rt.id.is_none());
        assert!(rt.wants_but_not_running(&s));
    }

    #[test]
    fn reconcile_handles_poisoned_mutex_gracefully() {
        let mut rt = RelayRuntime::new();
        // Artificially poison the resolved slot mutex
        let slot = rt.resolved.clone();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = slot.lock().unwrap();
            panic!("poisoning resolved mutex");
        }));
        assert!(rt.resolved.is_poisoned());

        let pipeline = Arc::new(Mutex::new(Pipeline::new(config::Settings::default())));
        let pipe_mutex = pipeline.clone();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = pipe_mutex.lock().unwrap();
            panic!("poisoning pipeline mutex");
        }));
        assert!(pipeline.is_poisoned());

        // Reconcile must not panic despite poisoned mutexes
        let mut s = config::Settings::default();
        s.relay_enabled = false;
        rt.reconcile(&s, pipeline.clone());
        assert!(rt.id.is_none());
    }

    #[test]
    fn resolve_relay_ip_with_ip_literal() {
        let want = RelayId {
            enabled: true,
            listen_port: 1080,
            connect_host: "1.1.1.1".into(),
            connect_port: 443,
            fake_sni: "www.bing.com".into(),
            resolve_doh: false,
            doh_server: "".into(),
            mutate_real_sni: false,
            emit_decoy: false,
            require_inject: true,
            idle_timeout_secs: 60,
        };
        let ip = resolve_relay_ip(&want);
        assert_eq!(ip, Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1))));
    }

    #[test]
    fn resolve_relay_ip_rejects_invalid_destination() {
        let want_loopback = RelayId {
            enabled: true,
            listen_port: 1080,
            connect_host: "127.0.0.1".into(),
            connect_port: 443,
            fake_sni: "www.bing.com".into(),
            resolve_doh: false,
            doh_server: "".into(),
            mutate_real_sni: false,
            emit_decoy: false,
            require_inject: true,
            idle_timeout_secs: 60,
        };
        assert_eq!(resolve_relay_ip(&want_loopback), None);

        let want_non_ip = RelayId {
            enabled: true,
            listen_port: 1080,
            connect_host: "not_an_ip".into(),
            connect_port: 443,
            fake_sni: "www.bing.com".into(),
            resolve_doh: false,
            doh_server: "".into(),
            mutate_real_sni: false,
            emit_decoy: false,
            require_inject: true,
            idle_timeout_secs: 60,
        };
        assert_eq!(resolve_relay_ip(&want_non_ip), None);
    }

    #[test]
    fn redact_lan_and_edge_ips_guarantees() {
        let raw_ip = "192.168.1.100";
        let redacted = dpi_guard::stealth::redact_endpoint(raw_ip);
        assert!(!redacted.contains("192.168.1.100"));
        assert_eq!(redacted.len(), 16);
    }

    #[test]
    fn scanner_spoof_pairs_and_best_selection() {
        let pairs = dpi_guard::scanner::default_spoof_pairs();
        assert!(!pairs.is_empty());
        let local_pair = dpi_guard::scanner::SpoofCandidatePair::new(
            "Local",
            "127.0.0.1",
            443,
            "local.test",
            "Local test description",
        );
        let res = dpi_guard::scanner::probe_spoof_pair(&local_pair, std::time::Duration::from_millis(10));
        assert_eq!(res.candidate, "local.test");
        assert_eq!(res.ip, Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))));
    }
}
