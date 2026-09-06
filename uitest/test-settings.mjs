/*
 * Settings-UI tests: quick-access toolbar, restart-required hints,
 * feature counter, and dirty-tracking of bulk toggles.
 *
 * Drives the REAL src/webui/index.html in jsdom against the mock API:
 *   node uitest/test-settings.mjs
 */
import { JSDOM, VirtualConsole } from "jsdom";
import fs from "node:fs";
import path from "node:path";
import { createServer, resetForTests, getSettings, DEFAULTS } from "./mock-server.mjs";

const REPO = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const HTML_PATH = path.join(REPO, "src/webui/index.html");
const TOKEN = "dev-token-dev-token";

let pass = 0;
const failures = [];
function ok(name, cond, extra) {
  if (cond) { pass++; console.log("  ok   " + name); }
  else { failures.push(name + (extra ? " — " + extra : "")); console.log("  FAIL " + name + (extra ? " — " + extra : "")); }
}
function eq(name, a, b) { ok(name + ` (got ${JSON.stringify(a)}, want ${JSON.stringify(b)})`, JSON.stringify(a) === JSON.stringify(b)); }

const server = createServer();
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const PORT = server.address().port;
const BASE = `http://127.0.0.1:${PORT}`;

const captured = [];

async function makeDom() {
  resetForTests();
  captured.length = 0;
  const vc = new VirtualConsole();
  vc.on("jsdomError", (e) => { throw e; });
  const dom = new JSDOM(fs.readFileSync(HTML_PATH, "utf8"), {
    url: BASE + "/",
    runScripts: "dangerously",
    pretendToBeVisual: true,
    virtualConsole: vc,
    beforeParse(window) {
      window.confirm = () => true;
      window.fetch = async (input, init) => {
        const p = String(input);
        const url = p.startsWith("http") ? p : BASE + p;
        if (init && init.method && init.method !== "GET") {
          captured.push({ path: p, body: String(init.body || "") });
        }
        return fetch(url, Object.assign({}, init, {
          headers: Object.assign({}, init && init.headers),
        }));
      };
      window.localStorage.setItem("dpi_guard_token", TOKEN);
    },
  });
  return dom;
}

const settle = (ms = 120) => new Promise((r) => setTimeout(r, ms));
const click = (doc, id) => doc.getElementById(id).dispatchEvent(
  new doc.defaultView.Event("click", { bubbles: true }));
function setBool(doc, key, value) {
  const el = doc.getElementById("f_" + key);
  el.checked = !!value;
  el.dispatchEvent(new el.ownerDocument.defaultView.Event("change", { bubbles: true }));
}

console.log("\n[S1] quick-access toolbar toggles mark rows dirty");
{
  const dom = await makeDom();
  const doc = dom.window.document;
  await settle(250);

  const features = ["enable_anti_fingerprint", "randomize_ip_id", "randomize_packet_size",
    "enable_reverse_frag", "enable_wrong_seq", "enable_wrong_checksum",
    "enable_oob_injection", "enable_hostdot", "enable_fake_with_sni"];
  // enable_wrong_seq / enable_wrong_checksum default to TRUE: a decoy that
  // carries a valid checksum and an in-window sequence number is a real
  // packet, not a decoy (see the doc comment in src/config.rs). Everything
  // else in the bundle starts off.
  const startsOn = new Set(["enable_wrong_seq", "enable_wrong_checksum"]);
  for (const f of features)
    eq("starts at its documented default: " + f,
       doc.getElementById("f_" + f).checked, startsOn.has(f));

  click(doc, "qa_all_on");
  await settle(30);
  for (const f of features) eq("qa_all_on enables " + f, doc.getElementById("f_" + f).checked, true);
  ok("Save enabled after bulk toggle", doc.getElementById("btn_save").disabled === false);
  // The two that were already on cannot become dirty.
  ok("dirty rows counted",
    doc.querySelectorAll(".row.dirty").length >= features.length - startsOn.size,
    "n=" + doc.querySelectorAll(".row.dirty").length);

  click(doc, "btn_save");
  await settle(250);
  const save = captured.find((c) => c.path === "/api/config");
  ok("bulk toggle POSTed a partial TOML", !!save);
  for (const f of features) ok("server applied " + f, getSettings()[f] === true);
  // This set does NOT include restart-flagged fields: the message must
  // stay the plain hot-reload one (no restart warning).
  ok("no restart warning for hot-reloadable keys", doc.getElementById("msg").className === "ok",
    JSON.stringify(doc.getElementById("msg").textContent));

  click(doc, "qa_all_off");
  await settle(30);
  click(doc, "btn_save");
  await settle(250);
  for (const f of features) ok("qa_all_off applied " + f, getSettings()[f] === false);
  dom.window.close();
}

console.log("\n[S2] profile shortcuts set the mutation profile + technique set");
{
  const dom = await makeDom();
  const doc = dom.window.document;
  await settle(250);

  click(doc, "qa_stealth");
  await settle(30);
  eq("stealth preset selects the Stealth profile", doc.getElementById("f_mutation_profile").value, "Stealth");
  eq("stealth keeps decoys on", doc.getElementById("f_enable_decoys").checked, true);
  eq("stealth keeps SNI fragmentation on", doc.getElementById("f_enable_sni_fragmentation").checked, true);
  eq("stealth turns reverse-frag off", doc.getElementById("f_enable_reverse_frag").checked, false);

  click(doc, "btn_save");
  await settle(250);
  eq("server profile saved", getSettings().mutation_profile, "Stealth");

  click(doc, "qa_aggressive");
  await settle(30);
  eq("aggressive preset selects the Aggressive profile", doc.getElementById("f_mutation_profile").value, "Aggressive");
  click(doc, "btn_save");
  await settle(250);
  eq("server profile saved (Aggressive)", getSettings().mutation_profile, "Aggressive");
  dom.window.close();
}

console.log("\n[S3] restart-required settings are tagged and warned");
{
  const dom = await makeDom();
  const doc = dom.window.document;
  await settle(250);

  // The schema flags exactly the startup-only settings (audit gap C110:
  // hot-reload cannot apply these; they are read once at boot). Sorted to
  // match Array.prototype.sort() order used above.
  const tagged = [...doc.querySelectorAll('.row[data-k]')]
    .filter((r) => r.textContent.includes("نیاز به ری‌استارت"))
    .map((r) => r.dataset.k).sort();
  eq("restart-tagged fields are exactly the startup-only ones",
    tagged, ["enable_client_detect", "enable_kill_switch", "enable_mobile_gateway",
      "enable_proxy_cleanup", "enable_self_update", "enable_web_ui",
      "enable_youtube_warmup", "injection_delay_max_ms", "injection_delay_min_ms",
      "isp_profile", "kill_switch_adapter", "update_repo", "web_ui_port",
      "web_ui_token", "win_divert_sha256"]);

  // Saving a restart-flagged key shows the restart hint...
  setBool(doc, "enable_web_ui", !DEFAULTS.enable_web_ui);
  await settle(20);
  click(doc, "btn_save");
  await settle(250);
  ok("restart hint shown for enable_web_ui",
    /اجرای مجدد/.test(doc.getElementById("msg").textContent),
    JSON.stringify(doc.getElementById("msg").textContent));
  eq("server applied enable_web_ui", getSettings().enable_web_ui, !DEFAULTS.enable_web_ui);

  // ...but a plain hot-reloadable key never does.
  const el = doc.getElementById("f_decoy_ttl");
  el.value = String(DEFAULTS.decoy_ttl + 3);
  el.dispatchEvent(new dom.window.Event("input", { bubbles: true }));
  await settle(20);
  click(doc, "btn_save");
  await settle(250);
  ok("no restart warning for decoy_ttl",
    doc.getElementById("msg").className === "ok",
    JSON.stringify(doc.getElementById("msg").textContent));
  dom.window.close();
}

console.log("\n[S4] feature counter reflects the live state");
{
  const dom = await makeDom();
  const doc = dom.window.document;
  await settle(250);
  const before = doc.getElementById("feature_count").textContent;
  ok("counter renders at boot", /\d+ از \d+ قابلیت فعال/.test(before), before);

  click(doc, "qa_all_on");
  await settle(30);
  const after = doc.getElementById("feature_count").textContent;
  const nBefore = parseInt(before, 10);
  const nAfter = parseInt(after, 10);
  ok("counter increases after enabling techniques", nAfter > nBefore,
    `${before} -> ${after}`);
  dom.window.close();
}

console.log("\n[S5] revert also clears bulk quick-access changes");
{
  const dom = await makeDom();
  const doc = dom.window.document;
  await settle(250);
  click(doc, "qa_all_on");
  await settle(30);
  ok("dirty rows exist before revert", doc.querySelectorAll(".row.dirty").length > 0);
  click(doc, "btn_revert");
  await settle(50);
  eq("all bulk changes reverted", doc.querySelectorAll(".row.dirty").length, 0);
  eq("reverse-frag back to server value",
    doc.getElementById("f_enable_reverse_frag").checked,
    !!DEFAULTS.enable_reverse_frag);
  dom.window.close();
}

server.close();
console.log("\n========================================================");
if (failures.length) {
  console.log(`${pass} passed, ${failures.length} FAILED`);
  process.exit(1);
} else {
  console.log(`${pass} passed, 0 failed`);
  console.log("ALL SETTINGS-UI TESTS PASSED");
}
