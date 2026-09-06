/*
 * Live-overview + UX-safety tests for the 2026 GUI upgrade:
 *   - overview cards render the new /api/status fields
 *     (mutated packets, uptime, DoH state, driver handle count)
 *   - profile switch asks for confirmation before the immediate apply,
 *     and a cancelled confirmation sends nothing
 *   - beforeunload only fires when there are unsaved changes
 *   - accessibility: aria-label / aria-describedby / aria-invalid wiring,
 *     live-region message element
 *
 * Drives the REAL src/webui/index.html in jsdom against the mock API:
 *   node uitest/test-status.mjs
 */
import { JSDOM, VirtualConsole } from "jsdom";
import fs from "node:fs";
import path from "node:path";
import { createServer, resetForTests } from "./mock-server.mjs";

const REPO = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const HTML_PATH = path.join(REPO, "src/webui/index.html");
const TOKEN = "dev-token-dev-token";

let pass = 0;
const failures = [];
function ok(name, cond, extra) {
  if (cond) { pass++; console.log("  ok   " + name); }
  else { failures.push(name + (extra ? " — " + extra : "")); console.log("  FAIL " + name + (extra ? " — " + extra : "")); }
}

const server = createServer();
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const PORT = server.address().port;
const BASE = `http://127.0.0.1:${PORT}`;

const captured = [];
let confirmAnswer = true;
let lastConfirmText = "";

async function makeDom() {
  resetForTests();
  captured.length = 0;
  confirmAnswer = true;
  lastConfirmText = "";
  const vc = new VirtualConsole();
  vc.on("jsdomError", (e) => { throw e; });
  const dom = new JSDOM(fs.readFileSync(HTML_PATH, "utf8"), {
    url: BASE + "/",
    runScripts: "dangerously",
    pretendToBeVisual: true,
    virtualConsole: vc,
    beforeParse(window) {
      window.confirm = (text) => { lastConfirmText = String(text); return confirmAnswer; };
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

console.log("\n[O1] overview cards render the new status fields");
{
  const dom = await makeDom();
  const doc = dom.window.document;
  await settle(250);
  const cards = doc.getElementById("cards").textContent;
  ok("mutated-packets card present", cards.includes("پکت جهش‌یافته"));
  ok("uptime card present", cards.includes("مدت کارکرد"));
  ok("uptime formatted (3725s = 1 ساعت)", cards.includes("۱".length && "1 ساعت") || cards.includes("1 ساعت"),
    "cards text: " + cards.slice(0, 200));
  ok("DoH state card present", cards.includes("DoH رله"));
  ok("DoH state value rendered (off by default)",
    doc.getElementById("cardv_doh").textContent === "off",
    JSON.stringify(doc.getElementById("cardv_doh").textContent));
  ok("driver handle card present", cards.includes("هندل درایور"));
  ok("driver handle live+retired rendered", cards.includes("1 فعال + 2 بازنشسته"),
    "expected '1 فعال + 2 بازنشسته'");
  ok("intercepted-packets card still present", cards.includes("پکت رهگیری‌شده"));
  dom.window.close();
}

console.log("\n[O2] profile switch asks for confirmation before applying");
{
  const dom = await makeDom();
  const doc = dom.window.document;
  await settle(250);

  // Accepted confirmation -> POST /api/profile fires.
  click(doc, "profiles");
  const btn = doc.querySelector('button[data-p="Henan"]');
  ok("profile button exists", !!btn);
  btn.dispatchEvent(new doc.defaultView.Event("click", { bubbles: true }));
  await settle(250);
  ok("confirmation dialog shown", lastConfirmText.includes("Henan"),
    "confirm text: " + JSON.stringify(lastConfirmText));
  const post = captured.find((c) => c.path === "/api/profile");
  ok("POST /api/profile sent after confirm", !!post);
  ok("POST body carries the profile", post && post.body.includes("Henan"));

  // Cancelled confirmation -> nothing sent.
  captured.length = 0;
  confirmAnswer = false;
  const btn2 = doc.querySelector('button[data-p="Aggressive"]');
  btn2.dispatchEvent(new doc.defaultView.Event("click", { bubbles: true }));
  await settle(200);
  ok("cancel still shows the dialog", lastConfirmText.includes("Aggressive"));
  ok("cancelled confirm sends nothing", captured.length === 0,
    "captured: " + JSON.stringify(captured));
  dom.window.close();
}

console.log("\n[O3] beforeunload only warns with unsaved changes");
{
  const dom = await makeDom();
  const win = dom.window, doc = win.document;
  await settle(250);

  let warned = false;
  const handler = (e) => { if (e.defaultPrevented || e.returnValue === "") warned = true; };
  win.addEventListener("beforeunload", handler);
  const ev = new win.Event("beforeunload", { bubbles: true, cancelable: true });
  win.dispatchEvent(ev);
  ok("clean form does not warn", !warned);

  // dirty the form
  const el = doc.getElementById("f_decoy_ttl");
  el.value = "12";
  el.dispatchEvent(new win.Event("input", { bubbles: true }));
  await settle(50);
  warned = false;
  const ev2 = new win.Event("beforeunload", { bubbles: true, cancelable: true });
  win.dispatchEvent(ev2);
  ok("dirty form warns on unload", warned);
  win.removeEventListener("beforeunload", handler);
  dom.window.close();
}

console.log("\n[O4] accessibility wiring on form controls");
{
  const dom = await makeDom();
  const doc = dom.window.document;
  await settle(250);

  const inp = doc.getElementById("f_decoy_ttl");
  ok("aria-label on input", !!(inp && inp.getAttribute("aria-label")));
  ok("aria-describedby points at the error node",
    inp && inp.getAttribute("aria-describedby") === "e_decoy_ttl");
  ok("aria-invalid=false while valid",
    inp && inp.getAttribute("aria-invalid") === "false");

  // Make the field invalid -> aria-invalid flips to true.
  inp.value = "0";
  inp.dispatchEvent(new doc.defaultView.Event("input", { bubbles: true }));
  await settle(50);
  ok("aria-invalid=true on validation error",
    inp.getAttribute("aria-invalid") === "true");

  // Checkbox + select also labelled.
  const cb = doc.getElementById("f_enable_decoys");
  ok("checkbox has aria-label", !!(cb && cb.getAttribute("aria-label")));
  const sel = doc.getElementById("f_mutation_profile");
  ok("select has aria-label", !!(sel && sel.getAttribute("aria-label")));

  // Live regions for status messages.
  ok("#msg is a polite live region",
    doc.getElementById("msg").getAttribute("aria-live") === "polite");
  ok("#dirtypill is a polite live region",
    doc.getElementById("dirtypill").getAttribute("aria-live") === "polite");
  dom.window.close();
}

console.log("\n[O5] responsive layout hooks exist in the stylesheet");
{
  const html = fs.readFileSync(HTML_PATH, "utf8");
  ok("360px-class breakpoint present", html.includes("max-width: 430px"));
  ok("focus-visible ring present", html.includes(":focus-visible"));
}

console.log(`\n${pass} passed, ${failures.length} failed`);
if (failures.length) {
  console.log("FAILURES:\n  " + failures.join("\n  "));
  process.exit(1);
}
console.log("ALL STATUS-UI TESTS PASSED");
process.exit(0);
