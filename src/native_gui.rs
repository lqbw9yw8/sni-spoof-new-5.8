//! Native desktop controller for dpi_guard. A real window (not the HTTP
//! dashboard) with a v2rayN-style categorized settings panel plus an
//! advanced raw-TOML editor. English UI, top-level tab strip: each
//! section (Overview, Proxy & SNI, Traffic, Connection, Advanced, Raw
//! TOML) is its own tab — no nested side panel — so switching sections
//! can't cause the content area to resize/reflow underneath a scrollbar.

use eframe::egui;
use crate::config::Settings;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn run() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 720.0])
            .with_min_inner_size([820.0, 560.0])
            .with_title("dpi_guard — Desktop Control Panel"),
        ..Default::default()
    };
    eframe::run_native(
        "dpi_guard",
        options,
        Box::new(|cc| {
            apply_theme(&cc.egui_ctx);
            Ok(Box::new(DpiGuardApp::new(cc)))
        }),
    )
}

/// v2rayN-like dark blue-gray palette.
fn apply_theme(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();
    v.panel_fill = egui::Color32::from_rgb(30, 34, 45);
    v.window_fill = egui::Color32::from_rgb(34, 39, 52);
    v.faint_bg_color = egui::Color32::from_rgb(40, 46, 61);
    v.extreme_bg_color = egui::Color32::from_rgb(23, 26, 34);
    v.selection.bg_fill = egui::Color32::from_rgb(62, 118, 194);
    v.widgets.inactive.bg_fill = egui::Color32::from_rgb(43, 49, 66);
    v.widgets.hovered.bg_fill = egui::Color32::from_rgb(52, 60, 80);
    v.widgets.active.bg_fill = egui::Color32::from_rgb(58, 68, 92);
    ctx.set_visuals(v);
}

/// Text buffers for the Vec<String>/Vec<u16> settings fields (one entry
/// per line / comma-separated for ports, empty string = None).
#[derive(Default)]
struct ListBuffers {
    win_divert_sha256: String,
    intercept_ports: String,
    sni_only: String,
    sni_except: String,
    sni_candidates: String,
    edge_candidates: String,
    ipset_hostlist: String,
}

impl ListBuffers {
    fn from_settings(s: &Settings) -> Self {
        Self {
            win_divert_sha256: s.win_divert_sha256.join("\n"),
            intercept_ports: s
                .intercept_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            sni_only: s.sni_only.join("\n"),
            sni_except: s.sni_except.join("\n"),
            sni_candidates: s.sni_candidates.join("\n"),
            edge_candidates: s.edge_candidates.join("\n"),
            ipset_hostlist: s.ipset_hostlist.join("\n"),
        }
    }
}

struct DpiGuardApp {
    config_path: PathBuf,
    settings: Settings,
    lists: ListBuffers,
    raw_toml: String,
    tab: usize,
    message: String,
    log: Vec<String>,
    child: Option<Child>,
    /// True when the operator asked for the backend to stop — a subsequent
    /// child exit is expected and must not trigger an auto-restart.
    user_stopped: bool,
    /// How many times the backend was auto-restarted after an unexpected
    /// exit. Bounded so a crash-looping backend cannot spin forever.
    auto_restarts: u32,
}

/// Top-level tabs. Each one is a fully separate page — switching tabs
/// never resizes or re-parents a panel, it just swaps which function
/// draws into the single CentralPanel, so the window/scrollbar geometry
/// stays stable between tabs.
const TABS: [&str; 6] = [
    "Overview",
    "Proxy & SNI",
    "Traffic",
    "Connection",
    "Advanced",
    "Raw TOML",
];

impl DpiGuardApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let config_path = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("dpi_guard.toml");
        let (settings, message) = match crate::config::load_from_file(&config_path) {
            Ok(s) => (s, format!("Loaded: {}", config_path.display())),
            Err(_) => (
                Settings::default(),
                "No config file found; defaults loaded. Click Save to create it.".into(),
            ),
        };
        let raw_toml = toml::to_string_pretty(&settings).unwrap_or_default();
        let lists = ListBuffers::from_settings(&settings);
        let _ = cc;
        let mut app = Self {
            config_path,
            settings,
            lists,
            raw_toml,
            tab: 0,
            message,
            log: Vec::new(),
            child: None,
            user_stopped: false,
            auto_restarts: 0,
        };
        app.logln("Desktop control panel started");
        app
    }

    fn logln(&mut self, msg: &str) {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let (h, m, s) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60);
        self.log.push(format!("[{h:02}:{m:02}:{s:02}] {msg}"));
        if self.log.len() > 500 {
            self.log.drain(..self.log.len() - 500);
        }
    }

    /// Copy the text buffers into the Settings struct. Returns Err with a
    /// human-readable message when a port entry is not a number.
    fn sync_lists(&mut self) -> Result<(), String> {
        let l = &self.lists;
        self.settings.win_divert_sha256 = lines(&l.win_divert_sha256);
        self.settings.sni_only = lines(&l.sni_only);
        self.settings.sni_except = lines(&l.sni_except);
        self.settings.sni_candidates = lines(&l.sni_candidates);
        self.settings.edge_candidates = lines(&l.edge_candidates);
        self.settings.ipset_hostlist = lines(&l.ipset_hostlist);
        let mut ports = Vec::new();
        for tok in l.intercept_ports.split(&[',', ' ', ';'][..]) {
            let tok = tok.trim();
            if tok.is_empty() {
                continue;
            }
            match tok.parse::<u16>() {
                Ok(p) => ports.push(p),
                Err(_) => return Err(format!("Invalid port in the port list: {tok:?}")),
            }
        }
        self.settings.intercept_ports = ports;
        Ok(())
    }

    fn sync_from_settings(&mut self) {
        self.lists = ListBuffers::from_settings(&self.settings);
        self.raw_toml = toml::to_string_pretty(&self.settings).unwrap_or_default();
    }

    fn save(&mut self) {
        if let Err(e) = self.sync_lists() {
            self.message = e;
            return;
        }
        match self.settings.validate() {
            Ok(()) => {
                self.sync_from_settings();
                match toml::to_string_pretty(&self.settings)
                    .map_err(|e| e.to_string())
                    .and_then(|text| {
                        std::fs::write(&self.config_path, &text).map_err(|e| e.to_string())
                    }) {
                    Ok(()) => {
                        self.message = format!("Saved: {}", self.config_path.display());
                        self.logln("Settings saved");
                    }
                    Err(e) => self.message = format!("Save failed: {e}"),
                }
            }
            Err(e) => self.message = format!("Validation failed: {e}"),
        }
    }

    fn reload(&mut self) {
        match crate::config::load_from_file(&self.config_path) {
            Ok(s) => {
                self.settings = s;
                self.sync_from_settings();
                self.message = "Settings reloaded from file".into();
                self.logln("Settings reloaded from file");
            }
            Err(e) => self.message = format!("Reload failed: {e}"),
        }
    }

    /// Parse the raw-TOML editor into the structured settings.
    fn apply_raw_toml(&mut self) {
        match toml::from_str::<Settings>(&self.raw_toml) {
            Ok(mut s) => match s.validate() {
                Ok(()) => {
                    self.settings = s;
                    self.sync_from_settings();
                    self.message = "TOML applied".into();
                    self.logln("Settings applied from raw TOML");
                }
                Err(e) => self.message = format!("Validation failed: {e}"),
            },
            Err(e) => self.message = format!("TOML error: {e}"),
        }
    }

    fn start(&mut self) {
        self.save();
        if self.message.starts_with("Saved") {
            if self.child.is_some() {
                self.message = "Already running".into();
                return;
            }
            match std::env::current_exe().and_then(|exe| {
                let mut command = Command::new(exe);
                command.arg("--backend").arg(&self.config_path);
                #[cfg(windows)]
                {
                    use std::os::windows::process::CommandExt;
                    command.creation_flags(0x08000000); // CREATE_NO_WINDOW
                }
                command.spawn()
            }) {
                Ok(child) => {
                    self.child = Some(child);
                    self.user_stopped = false;
                    self.message = "Started. WinDivert requires administrator access.".into();
                    self.logln("Backend engine started");
                }
                Err(e) => self.message = format!("Start failed: {e}"),
            }
        }
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            self.user_stopped = true;
            let _ = child.kill();
            let _ = child.wait();
            self.message = "Stopped".into();
            self.logln("Backend engine stopped");
        } else {
            self.message = "Not running".into();
        }
    }

    // ── Overview tab ────────────────────────────────────────────────

    fn overview_tab(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("dpi_guard");
        ui.label("Desktop control panel — no browser needed");
        ui.add_space(10.0);

        let running = self.child.is_some();
        let (status, color) = if running {
            ("Running", egui::Color32::from_rgb(96, 220, 130))
        } else {
            ("Stopped", egui::Color32::from_rgb(235, 95, 95))
        };

        // Status card. Fixed inner layout (no widgets whose height changes
        // with content) so this card never grows/shrinks between frames.
        egui::Frame::none()
            .fill(ui.visuals().faint_bg_color)
            .rounding(8.0)
            .inner_margin(egui::Margin::same(14.0))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(
                    egui::RichText::new(format!("● {status}"))
                        .color(color)
                        .size(20.0)
                        .strong(),
                );
                ui.add_space(6.0);
                let ports = if self.settings.intercept_all_tcp || self.settings.intercept_all_udp {
                    "All ports (except 22/53/3389)".to_string()
                } else if self.settings.intercept_ports.is_empty() {
                    "443 (default)".to_string()
                } else {
                    self.settings
                        .intercept_ports
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                let kv = [
                    ("Config file", self.config_path.display().to_string()),
                    ("Mutation profile", self.settings.mutation_profile.clone()),
                    ("Covered ports", ports),
                    (
                        "Relay mode",
                        if self.settings.relay_enabled {
                            format!(
                                "Enabled — 127.0.0.1:{} → {}:{}",
                                self.settings.relay_listen_port,
                                self.settings.relay_connect_host,
                                self.settings.relay_connect_port
                            )
                        } else {
                            "Disabled".to_string()
                        },
                    ),
                ];
                for (k, v) in kv {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(k).strong());
                        ui.label(v);
                    });
                }
            });

        ui.add_space(10.0);
        ui.horizontal(|ui| {
            let start_btn =
                egui::Button::new(egui::RichText::new("▶ Start").size(16.0)).min_size(egui::vec2(110.0, 32.0));
            if ui.add_enabled(!running, start_btn).clicked() {
                self.start();
            }
            let stop_btn =
                egui::Button::new(egui::RichText::new("■ Stop").size(16.0)).min_size(egui::vec2(110.0, 32.0));
            if ui.add_enabled(running, stop_btn).clicked() {
                self.stop();
            }
            ui.add_space(10.0);
            if ui.button("↻ Reload").clicked() {
                self.reload();
            }
            if ui.button("💾 Save").clicked() {
                self.save();
            }
        });

        ui.add_space(8.0);
        // Fixed-height message row (reserved even when empty) so this
        // section never changes height depending on whether there is a
        // message — that height change was the main cause of the log
        // panel (and everything below it) visibly jumping up/down.
        ui.horizontal(|ui| {
            ui.set_min_height(18.0);
            if !self.message.is_empty() {
                ui.label(&self.message);
            }
        });
        ui.add_space(6.0);
        ui.separator();
        ui.label(egui::RichText::new("Event log").strong());
        egui::ScrollArea::vertical()
            .id_salt("overview_log_scroll")
            .max_height(180.0)
            .min_scrolled_height(180.0)
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                egui::Frame::none()
                    .fill(ui.visuals().extreme_bg_color)
                    .rounding(6.0)
                    .inner_margin(egui::Margin::same(8.0))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        if self.log.is_empty() {
                            ui.label("—");
                        } else {
                            for line in &self.log {
                                ui.label(
                                    egui::RichText::new(line)
                                        .monospace()
                                        .color(egui::Color32::from_rgb(180, 190, 205)),
                                );
                            }
                        }
                    });
            });
        ui.add_space(4.0);
        ui.label("Edit every option in the other tabs, then click Save.");
    }

    fn section_sni(&mut self, ui: &mut egui::Ui) {
        ui.heading("Proxy & SNI");
        ui.add_space(8.0);
        let s = &mut self.settings;

        combo_row(ui, "SNI mutation profile:", "profile", &mut s.mutation_profile, &[
            "Stealth", "ChinaGfw", "RussiaDpi", "Aggressive", "ChinaRegional", "Henan",
        ]);

        check_row(ui, "Enable decoys", &mut s.enable_decoys);
        drag_row(ui, "Decoy TTL (decoy_ttl):", &mut s.decoy_ttl, 1..=64, "hop");
        check_row(ui, "SNI fragmentation", &mut s.enable_sni_fragmentation);
        drag_row(ui, "Fragment chunk size:", &mut s.fragment_chunk_size, 0..=16384, "bytes — 0 = off");
        check_row(ui, "Combined fragmentation", &mut s.enable_combined_fragmentation);
        check_row(ui, "Reverse fragmentation (zapret)", &mut s.enable_reverse_frag);
        check_row(ui, "Wrong SEQ", &mut s.enable_wrong_seq);
        check_row(ui, "Wrong checksum", &mut s.enable_wrong_checksum);
        check_row(ui, "OOB injection (zapret)", &mut s.enable_oob_injection);
        check_row(ui, "Dotted-host trick", &mut s.enable_hostdot);
        check_row(ui, "Swap foolers", &mut s.enable_swap_foolers);

        check_row(ui, "SNI disguise", &mut s.enable_sni_disguise);
        text_row(ui, "Benign fronting domain:", &mut s.fronting_benign_sni, "e.g. www.microsoft.com");
        check_row(ui, "Fake-with-SNI mode (browser emulation)", &mut s.enable_fake_with_sni);
        combo_row(ui, "Emulated browser:", "fake_browser", &mut s.fake_browser, &[
            "firefox", "chrome", "safari", "edge", "random",
        ]);
        check_row(ui, "uTLS fingerprint mutation (JA3/JA4)", &mut s.enable_utls_fingerprint);
        combo_row(ui, "uTLS browser:", "utls_browser", &mut s.utls_browser, &[
            "chrome", "firefox", "safari", "edge", "random",
        ]);
        check_row(ui, "ECH GREASE", &mut s.enable_ech_grease);
        check_row(ui, "MD5SIG fooling (may break connectivity)", &mut s.enable_md5sig_fooling);
        check_row(ui, "Geedge evasion", &mut s.enable_geedge_evasion);

        list_row(ui, "Allowed SNI list (sni_only):", &mut self.lists.sni_only, "one pattern per line — empty = all");
        list_row(ui, "Excluded SNI list (sni_except):", &mut self.lists.sni_except, "one pattern per line");
    }

    fn section_traffic(&mut self, ui: &mut egui::Ui) {
        ui.heading("Traffic Behavior");
        ui.add_space(8.0);
        let s = &mut self.settings;

        check_row(ui, "Cover all TCP ports", &mut s.intercept_all_tcp);
        check_row(ui, "Cover all UDP ports", &mut s.intercept_all_udp);
        text_row(ui, "Specific ports (intercept_ports):", &mut self.lists.intercept_ports, "e.g. 443, 8443, 2053");
        check_row(ui, "QUIC port bypass", &mut s.enable_quic_port_bypass);
        check_row(ui, "Use low port for QUIC", &mut s.quic_bypass_use_low_port);

        drag_row(ui, "Idle timeout (idle_timeout_secs):", &mut s.idle_timeout_secs, 1..=86_400, "sec");
        check_row(ui, "HTTP Host tricks", &mut s.enable_http_host_tricks);

        check_row(ui, "AutoTTL (learn TTL from hop count)", &mut s.enable_autottl);
        drag_row(ui, "AutoTTL delta:", &mut s.autottl_delta, 0..=32, "hop");

        drag_row(ui, "Max packet size (max_payload_size):", &mut s.max_payload_size, 0..=65_535, "bytes");
        drag_row(ui, "Max packet padding:", &mut s.max_packet_padding, 0..=1024, "bytes");
        check_row(ui, "Anti-fingerprint (random delay/padding)", &mut s.enable_anti_fingerprint);
        drag_row(ui, "Min injection delay:", &mut s.injection_delay_min_ms, 0..=10_000, "ms");
        drag_row(ui, "Max injection delay:", &mut s.injection_delay_max_ms, 0..=10_000, "ms");
        check_row(ui, "Randomize IP ID", &mut s.randomize_ip_id);
        check_row(ui, "Randomize packet size", &mut s.randomize_packet_size);
        drag_row(ui, "Fake resend count:", &mut s.fake_resend_count, 0..=10, "");

        check_row(ui, "Kill switch", &mut s.enable_kill_switch);
        text_row(ui, "Kill switch adapter name:", &mut s.kill_switch_adapter, "exact network adapter name");
    }

    fn section_connection(&mut self, ui: &mut egui::Ui) {
        ui.heading("Connection");
        ui.add_space(8.0);
        let s = &mut self.settings;

        ui.label(egui::RichText::new("Relay mode (v2rayN connects to dpi_guard)").strong());
        ui.separator();
        check_row(ui, "Enable relay", &mut s.relay_enabled);
        drag_row(ui, "Relay listen port:", &mut s.relay_listen_port, 1..=65_535, "v2rayN connects here");
        text_row(ui, "Real destination (IP or domain):", &mut s.relay_connect_host, "e.g. 1.1.1.1");
        drag_row(ui, "Real destination port:", &mut s.relay_connect_port, 1..=65_535, "");
        text_row(ui, "Injected fake SNI:", &mut s.relay_fake_sni, "e.g. www.microsoft.com");
        check_row(ui, "Resolve destination via DoH", &mut s.relay_resolve_doh);
        check_row(ui, "Mutate real SNI in relay stream", &mut s.relay_mutate_real_sni);
        check_row(ui, "Emit decoy on injection", &mut s.relay_emit_decoy);
        check_row(ui, "Fail-closed (relay only with confirmed injection)", &mut s.relay_require_inject);

        ui.add_space(8.0);
        ui.label(egui::RichText::new("DNS").strong());
        ui.separator();
        text_row(ui, "DoH server:", &mut s.doh_server, "https://…/dns-query");

        ui.add_space(8.0);
        ui.label(egui::RichText::new("Web interface").strong());
        ui.separator();
        check_row(ui, "Enable web dashboard", &mut s.enable_web_ui);
        drag_row(ui, "Web UI port:", &mut s.web_ui_port, 1..=65_535, "");
        text_row(ui, "Web UI token:", &mut s.web_ui_token, "16+ ASCII chars — empty = no token");
    }

    fn section_advanced(&mut self, ui: &mut egui::Ui) {
        ui.heading("Advanced & Tools");
        ui.add_space(8.0);
        let s = &mut self.settings;

        combo_row(ui, "ISP profile:", "isp", &mut s.isp_profile, &[
            "auto", "mci", "irancell", "russia", "china", "generic",
        ]);
        combo_row(ui, "SNI rotation mode:", "rot", &mut s.sni_rotation_mode, &[
            "round_robin", "weighted_random", "lru",
        ]);
        list_row(ui, "SNI candidates:", &mut self.lists.sni_candidates, "one domain per line");
        list_row(ui, "Edge candidates:", &mut self.lists.edge_candidates, "one IP/domain per line");
        list_row(ui, "ipset host list:", &mut self.lists.ipset_hostlist, "one host per line");

        check_row(ui, "Smart proxy cleanup on exit", &mut s.enable_proxy_cleanup);

        ui.add_space(8.0);
        ui.label(egui::RichText::new("Security").strong());
        ui.separator();
        list_row(ui, "WinDivert driver SHA-256 pins:", &mut self.lists.win_divert_sha256, "one 64-char hex hash per line");
    }

    fn section_raw_toml(&mut self, ui: &mut egui::Ui) {
        ui.heading("Raw TOML Editor (advanced)");
        ui.label("Edit the whole settings file directly. Click \"Apply TOML\" after changing it.");
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if ui.button("Apply TOML").clicked() {
                self.apply_raw_toml();
            }
            if ui.button("Reset from current settings").clicked() {
                self.sync_from_settings();
                self.message = "Editor reset from current settings".into();
            }
        });
        ui.add_space(4.0);
        // Fixed height (not ui.available_size()) — sizing a widget off
        // available_size() inside a scroll area can feed back into the
        // scroll area's own content-height calculation and make the box
        // (and everything after it) twitch by a few pixels every frame.
        ui.add_sized(
            [ui.available_width(), 480.0],
            egui::TextEdit::multiline(&mut self.raw_toml)
                .code_editor()
                .desired_rows(24),
        );
    }
}

fn lines(s: &str) -> Vec<String> {
    s.lines()
        .map(|l| l.trim().to_owned())
        .filter(|l| !l.is_empty())
        .collect()
}

/// A left-to-right settings row: label on the left, widget to its right.
fn row(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    ui.horizontal(|ui| {
        add(ui);
    });
    ui.add_space(4.0);
}

fn check_row(ui: &mut egui::Ui, label: &str, value: &mut bool) {
    row(ui, |ui| {
        ui.checkbox(value, label);
    });
}

fn text_row(ui: &mut egui::Ui, label: &str, value: &mut String, hint: &str) {
    row(ui, |ui| {
        ui.label(label);
        ui.add(
            egui::TextEdit::singleline(value)
                .desired_width(260.0)
                .hint_text(hint),
        );
    });
}

fn drag_row<N>(ui: &mut egui::Ui, label: &str, value: &mut N, range: std::ops::RangeInclusive<N>, suffix: &str)
where
    N: egui::emath::Numeric + Copy + std::fmt::Display,
{
    row(ui, |ui| {
        ui.label(label);
        let mut dv = egui::DragValue::new(value).range(range).speed(0.2);
        if !suffix.is_empty() {
            dv = dv.suffix(format!(" {suffix}"));
        }
        ui.add(dv);
    });
}

fn combo_row(ui: &mut egui::Ui, label: &str, id: &str, value: &mut String, options: &[&str]) {
    row(ui, |ui| {
        ui.label(label);
        egui::ComboBox::from_id_salt(id)
            .selected_text(value.clone())
            .width(180.0)
            .show_ui(ui, |ui| {
                for opt in options {
                    ui.selectable_value(value, opt.to_string(), *opt);
                }
            });
    });
}

fn list_row(ui: &mut egui::Ui, label: &str, value: &mut String, hint: &str) {
    row(ui, |ui| {
        ui.label(label);
        ui.add(
            egui::TextEdit::multiline(value)
                .desired_width(320.0)
                .desired_rows(3)
                .hint_text(hint),
        );
    });
}

impl eframe::App for DpiGuardApp {
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.stop();
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                for (i, name) in TABS.iter().enumerate() {
                    if ui.selectable_label(self.tab == i, *name).clicked() {
                        self.tab = i;
                    }
                }
            });
            ui.add_space(2.0);
        });
        egui::CentralPanel::default()
            .frame(egui::Frame::none().inner_margin(egui::Margin::same(12.0)))
            .show(ctx, |ui| {
                // One ScrollArea shared by every tab, keyed by tab index so
                // each tab keeps its own scroll position instead of all
                // tabs fighting over one. This also means switching tabs
                // never destroys/recreates a differently-sized panel tree
                // (that mismatch was the other likely source of the
                // window content visibly jumping up and down).
                egui::ScrollArea::vertical()
                    .id_salt(("tab_scroll", self.tab))
                    .auto_shrink([false, false])
                    .show(ui, |ui| match self.tab {
                        0 => self.overview_tab(ui),
                        1 => self.section_sni(ui),
                        2 => self.section_traffic(ui),
                        3 => self.section_connection(ui),
                        4 => self.section_advanced(ui),
                        _ => self.section_raw_toml(ui),
                    });
            });
        // Backend-child supervision: poll the child every frame (and ask
        // egui to keep ticking once a second even when idle) so an
        // unexpected backend death is noticed quickly. An unexpected exit
        // (i.e. one the operator did not request) triggers a single
        // automatic restart; after that we surface the error and let the
        // operator decide, so a crash-looping backend cannot spin forever.
        if self.child.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_secs(1));
        }
        if self
            .child
            .as_mut()
            .is_some_and(|c| c.try_wait().ok().flatten().is_some())
        {
            self.child = None;
            self.logln("Backend engine exited");
            if self.user_stopped {
                self.user_stopped = false;
                self.message = "Backend engine stopped; check its console output.".into();
            } else if self.auto_restarts < 1 {
                self.auto_restarts += 1;
                self.logln("Unexpected exit — restarting automatically (once)");
                self.message =
                    "Backend engine closed unexpectedly; restarting automatically once…".into();
                self.start();
            } else {
                self.message =
                    "Error: backend engine closed again (after one automatic restart). Check the log and click Start again."
                        .into();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_helper_trims_and_filters_empty() {
        let input = "  line1  \n\n  line2\r\n   \nline3\n";
        let parsed = lines(input);
        assert_eq!(parsed, vec!["line1", "line2", "line3"]);
    }

    #[test]
    fn list_buffers_from_settings_roundtrips() {
        let mut s = Settings::default();
        s.intercept_ports = vec![443, 8443];
        s.sni_only = vec!["example.com".into(), "test.org".into()];
        s.sni_candidates = vec!["www.microsoft.com".into()];
        let bufs = ListBuffers::from_settings(&s);
        assert!(bufs.intercept_ports.contains("443"));
        assert!(bufs.intercept_ports.contains("8443"));
        assert_eq!(bufs.sni_only, "example.com\ntest.org");
        assert_eq!(bufs.sni_candidates, "www.microsoft.com");
    }

    #[test]
    fn sync_lists_parses_valid_ports() {
        let mut app = DpiGuardApp {
            config_path: PathBuf::from("dpi_guard.toml"),
            settings: Settings::default(),
            lists: ListBuffers {
                win_divert_sha256: "".into(),
                intercept_ports: "443, 8443, 2053".into(),
                sni_only: "a.com\nb.com".into(),
                sni_except: "c.com".into(),
                sni_candidates: "d.com".into(),
                edge_candidates: "1.1.1.1".into(),
                ipset_hostlist: "e.com".into(),
            },
            raw_toml: String::new(),
            tab: 0,
            message: String::new(),
            log: Vec::new(),
            child: None,
            user_stopped: false,
            auto_restarts: 0,
        };
        assert!(app.sync_lists().is_ok());
        assert_eq!(app.settings.intercept_ports, vec![443, 8443, 2053]);
        assert_eq!(app.settings.sni_only, vec!["a.com", "b.com"]);
        assert_eq!(app.settings.sni_except, vec!["c.com"]);
        assert_eq!(app.settings.edge_candidates, vec!["1.1.1.1"]);
    }

    #[test]
    fn sync_lists_rejects_invalid_port() {
        let mut app = DpiGuardApp {
            config_path: PathBuf::from("dpi_guard.toml"),
            settings: Settings::default(),
            lists: ListBuffers {
                intercept_ports: "443, not_a_port, 8443".into(),
                ..Default::default()
            },
            raw_toml: String::new(),
            tab: 0,
            message: String::new(),
            log: Vec::new(),
            child: None,
            user_stopped: false,
            auto_restarts: 0,
        };
        let res = app.sync_lists();
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Invalid port"));
    }

    #[test]
    fn apply_raw_toml_applies_valid_toml() {
        let mut app = DpiGuardApp {
            config_path: PathBuf::from("dpi_guard.toml"),
            settings: Settings::default(),
            lists: ListBuffers::default(),
            raw_toml: "mutation_profile = \"Henan\"\ndecoy_ttl = 15\n".into(),
            tab: 0,
            message: String::new(),
            log: Vec::new(),
            child: None,
            user_stopped: false,
            auto_restarts: 0,
        };
        app.apply_raw_toml();
        assert_eq!(app.settings.mutation_profile, "Henan");
        assert_eq!(app.settings.decoy_ttl, 15);
        assert_eq!(app.message, "TOML applied");
    }

    #[test]
    fn apply_raw_toml_rejects_invalid_toml() {
        let mut app = DpiGuardApp {
            config_path: PathBuf::from("dpi_guard.toml"),
            settings: Settings::default(),
            lists: ListBuffers::default(),
            raw_toml: "this is not valid toml {[[".into(),
            tab: 0,
            message: String::new(),
            log: Vec::new(),
            child: None,
            user_stopped: false,
            auto_restarts: 0,
        };
        app.apply_raw_toml();
        assert!(app.message.starts_with("TOML error:"));
    }

    #[test]
    fn logln_maintains_cap() {
        let mut app = DpiGuardApp {
            config_path: PathBuf::from("dpi_guard.toml"),
            settings: Settings::default(),
            lists: ListBuffers::default(),
            raw_toml: String::new(),
            tab: 0,
            message: String::new(),
            log: Vec::new(),
            child: None,
            user_stopped: false,
            auto_restarts: 0,
        };
        for i in 0..600 {
            app.logln(&format!("entry {i}"));
        }
        assert!(app.log.len() <= 500);
    }

    #[test]
    fn tabs_metadata_complete() {
        assert_eq!(TABS.len(), 6);
        assert_eq!(TABS[0], "Overview");
        assert_eq!(TABS[1], "Proxy & SNI");
        assert_eq!(TABS[2], "Traffic");
        assert_eq!(TABS[3], "Connection");
        assert_eq!(TABS[4], "Advanced");
        assert_eq!(TABS[5], "Raw TOML");
    }
}
