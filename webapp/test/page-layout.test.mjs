// The page's layout, read from index.html and style.css as text: the folder
// tabs, the wallet button, the Vanish amount box, the Network and About
// panels, Claim kept in a hidden container, the light brand colors as
// CSS variables in one light theme, and the CSP. No browser and no module
// build are needed.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
const css = readFileSync(new URL("../style.css", import.meta.url), "utf8");

// The opening tag of the element with `id`.
function tag(id) {
  const m = new RegExp(`<[a-z]+\\b[^>]*\\bid="${id}"[^>]*>`, "i").exec(html);
  assert.ok(m, `index.html has an element with id ${id}`);
  return m[0];
}

// The markup of the element with `id`, its closing tag included, found by
// counting the nesting of its own tag name.
function element(id) {
  const open = tag(id);
  const name = /^<([a-z]+)/i.exec(open)[1];
  const start = html.indexOf(open);
  const re = new RegExp(`<(/?)${name}\\b[^>]*>`, "gi");
  re.lastIndex = start;
  let depth = 0;
  for (let m = re.exec(html); m; m = re.exec(html)) {
    depth += m[1] ? -1 : 1;
    if (depth === 0) return html.slice(start, m.index + m[0].length);
  }
  assert.fail(`the element with id ${id} is closed`);
}

const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1]);

test("every id the app's wiring uses is in the page, once", () => {
  const source = readFileSync(new URL("../src/app.mjs", import.meta.url), "utf8");
  const used = new Set([...source.matchAll(/\$\("([\w-]+)"\)/g)].map((m) => m[1]));
  for (const part of ["key", "key-text", "check", "check-groups", "show", "digits", "copy", "copy-note", "saved"]) {
    used.add(`claim-${part}`);
  }
  for (const part of ["key", "words", "check", "check-groups", "copy", "copy-note", "saved", "back", "done-button"]) {
    used.add(`vanish-${part}`);
  }
  for (const t of ["vanish", "summon"]) used.add(`tab-${t}`).add(`panel-${t}`);
  assert.ok(used.size > 40);
  for (const id of used) assert.ok(ids.includes(id), `index.html has id ${id}`);
  const seen = new Set();
  for (const id of ids) {
    assert.ok(!seen.has(id), `id ${id} is used once`);
    seen.add(id);
  }
});

test("the stable ids of the new layout are in the page", () => {
  for (const id of [
    "tab-vanish",
    "tab-summon",
    "panel-vanish",
    "panel-summon",
    "wallet-button",
    "wallet-panel",
    "network-panel",
    "about-panel",
    "vanish-amount",
    "vanish-balance",
    "vanish-max",
  ]) {
    tag(id);
  }
});

test("the tabs are Vanish and Summon, a tab list with Vanish selected", () => {
  const list = /<[a-z]+\b[^>]*role="tablist"[^>]*>/i.exec(html);
  assert.ok(list, "a tab list");
  const tabs = [...html.matchAll(/<button\b[^>]*role="tab"[^>]*>([^<]*)</gi)];
  assert.deepEqual(
    tabs.map((m) => m[1].trim()),
    ["Vanish", "Summon"],
  );
  assert.equal(tabs.filter((m) => /aria-selected="true"/.test(m[0])).length, 1);
  assert.match(tag("tab-vanish"), /aria-selected="true"/);
  assert.match(tag("tab-vanish"), /aria-controls="panel-vanish"/);
  assert.match(tag("tab-summon"), /aria-selected="false"/);
  assert.match(tag("tab-summon"), /aria-controls="panel-summon"/);
  assert.match(tag("panel-vanish"), /role="tabpanel"/);
  assert.doesNotMatch(tag("panel-vanish"), /\bhidden\b/);
  assert.match(tag("panel-summon"), /role="tabpanel"/);
  assert.match(tag("panel-summon"), /\bhidden\b/);
  // Claim has no tab of its own.
  assert.doesNotMatch(html, /id="tab-claim"/);
});

test("the Vanish panel holds the amount box, the balance line and the main button", () => {
  const panel = element("panel-vanish");
  const amount = tag("vanish-amount");
  assert.ok(panel.includes(amount));
  assert.match(amount, /placeholder="0\.00"/);
  assert.match(amount, /inputmode="decimal"/);
  const box = /<label class="amount-box">[\s\S]*?<\/label>/.exec(panel);
  assert.ok(box, "an amount box");
  assert.ok(box[0].includes(amount), "the input is inside the box");
  assert.match(box[0], /<use href="#icon-ghost">/, "the ghost icon is inside the box");
  assert.match(box[0], /GHOST\s*<\/span>/);
  assert.match(panel, /Balance: <span id="vanish-balance">—<\/span>/);
  assert.ok(panel.indexOf('id="vanish-balance"') < panel.indexOf('id="vanish-max"'));
  assert.match(element("vanish-max"), />Max</);
  assert.match(element("vanish-submit"), /type="submit"[^>]*>Connect wallet</);
  for (const id of ["vanish-key", "vanish-check", "vanish-status", "vanish-recheck"]) assert.ok(panel.includes(`id="${id}"`), id);
});

test("the Summon panel holds the paste box, the amount box, the confirm, waiting and Done screens", () => {
  const panel = element("panel-summon");
  for (const id of [
    "summon-form",
    "summon-key",
    "summon-amount",
    "summon-in-key",
    "summon-max",
    "summon-submit",
    "summon-confirm",
    "summon-confirm-text",
    "summon-confirm-button",
    "summon-cancel",
    "summon-waiting",
    "summon-done",
    "summon-done-button",
    "summon-error",
  ]) {
    assert.ok(panel.includes(`id="${id}"`), id);
  }
  assert.match(element("summon-submit"), /type="submit"[^>]*>Paste a key</);
  // The confirm screen starts hidden, between the form and the waiting
  // screen, with one primary button.
  assert.match(tag("summon-confirm"), /\bhidden\b/);
  assert.ok(panel.indexOf('id="summon-form"') < panel.indexOf('id="summon-confirm"'));
  assert.ok(panel.indexOf('id="summon-confirm"') < panel.indexOf('id="summon-waiting"'));
  assert.equal(element("summon-confirm").match(/class="primary/g).length, 1);
  assert.match(css, /\.confirm\s*\{/);
  // No payout address field and no reveal form of their own.
  assert.doesNotMatch(panel, /id="reveal-/);
});

test("the Connect wallet button top right opens a dialog listing the quantum-safe wallets", () => {
  assert.match(element("wallet-button"), /Connect wallet/);
  assert.match(element("wallet-button"), /<use href="#icon-wallet">/);
  assert.match(tag("wallet-button"), /aria-controls="wallet-panel"/);
  assert.match(tag("wallet-panel"), /\bhidden\b/);
  assert.match(tag("wallet-panel"), /role="dialog"/);
  const panel = element("wallet-panel");
  assert.match(element("wallet-title"), />Connect a wallet</);
  // One wallet listed, as a button in a list: the Ghost pop-up wallet.
  const list = element("wallet-connect");
  const options = [...list.matchAll(/<button\b[^>]*class="wallet-option"[^>]*>/g)];
  assert.deepEqual(
    options.map((m) => /id="([^"]+)"/.exec(m[0])[1]),
    ["wallet-option-popup"],
  );
  assert.match(element("wallet-option-popup"), /<span id="wallet-option-popup-name"[^>]*>Ghost wallet<\/span>/);
  assert.match(element("wallet-option-popup"), /its own window/);
  assert.doesNotMatch(html, /metamask|snap/i, "no MetaMask option is left on the page");
  assert.match(list, /<ul class="wallet-list"/);
  assert.match(list, /quantum-safe/);
  assert.match(list, /never sees a seed or a key/);
  // Connected: the full address, the balance, Refresh and Disconnect.
  for (const id of ["wallet-open", "wallet-address", "wallet-balance", "wallet-refresh", "wallet-disconnect", "wallet-error"]) {
    assert.ok(panel.includes(`id="${id}"`), id);
  }
  assert.match(tag("wallet-open"), /\bhidden\b/);
  assert.match(element("wallet-refresh"), />Refresh</);
  assert.match(element("wallet-disconnect"), />Disconnect</);
  // The brand top left, the wallet button after it.
  const top = /<header class="top">[\s\S]*?<\/header>/.exec(html);
  assert.ok(top, "a top bar");
  assert.ok(top[0].indexOf("Ghost</span>") < top[0].indexOf('id="wallet-button"'));
  assert.ok(top[0].includes('id="wallet-panel"'));
  assert.match(css, /\.wallet-option\s*\{/);
});

test("the page has no create or restore wallet flow and holds no seed", () => {
  const source = readFileSync(new URL("../src/app.mjs", import.meta.url), "utf8");
  const flow = readFileSync(new URL("../src/flow.mjs", import.meta.url), "utf8");
  const panel = element("wallet-panel");
  // No text box in the wallet dialog: nothing to type words into.
  assert.doesNotMatch(panel, /<(textarea|input|form)\b/);
  assert.doesNotMatch(panel, /24 words|seed words|save check|restore/i);
  for (const id of ["wallet-closed", "wallet-words", "wallet-check", "wallet-show", "wallet-saved", "wallet-close"]) {
    assert.ok(!ids.includes(id), `no element ${id}`);
  }
  // The worker's wallet requests are not used by the page.
  for (const op of ["walletNew", "walletAccount", "walletSign"]) {
    assert.ok(!flow.includes(`"${op}"`), `flow.mjs asks the worker for ${op}`);
    assert.ok(!source.includes(op), `app.mjs names ${op}`);
  }
  assert.equal(source.match(/flow\.walletConnect\(/g).length, 1, "the pop-up wallet is the only one connected");
  assert.match(source, /flow\.walletConnect\(popupConnector\(\)\)/);
  assert.doesNotMatch(source, /metamask|ethereum|snaps?\b/i);
  assert.match(source, /flow\.walletDisconnect\(\)/);
  // The connection is not remembered: no browser storage and no cookie.
  const stores = [["local", "Storage"].join(""), ["session", "Storage"].join(""), "document.cookie", "indexedDB"];
  const connectors = ["wallet-connect", "popup-wallet"].map((name) => readFileSync(new URL(`../src/${name}.mjs`, import.meta.url), "utf8"));
  for (const text of [source, flow, ...connectors]) {
    for (const store of stores) assert.ok(!text.includes(store), store);
  }
});

test("the network settings and privacy wording sit in Network and About panels from the footer", () => {
  const network = element("network-panel");
  assert.match(tag("network-panel"), /\bhidden\b/);
  for (const id of ["network-form", "endpoint", "commit-entry", "chain-status"]) assert.ok(network.includes(`id="${id}"`), id);
  const about = element("about-panel");
  assert.match(tag("about-panel"), /\bhidden\b/);
  assert.match(about, /No key or wallet seed is stored/);
  const footer = /<footer\b[\s\S]*?<\/footer>/.exec(html)[0];
  assert.match(footer, /aria-controls="network-panel"/);
  assert.match(footer, /aria-controls="about-panel"/);
  // One short warning line.
  const warn = [...footer.matchAll(/<p class="warn">([^<]*)<\/p>/g)];
  assert.equal(warn.length, 1);
  assert.match(warn[0][1], /Experimental/);
  assert.ok(warn[0][1].length <= 80);
  assert.doesNotMatch(footer, /No key or wallet seed is stored/);
});

test("Claim stays in the page inside a hidden container", () => {
  const container = element("claim-container");
  assert.match(tag("claim-container"), /\bhidden\b/);
  for (const id of ["claim", "claim-start", "claim-key", "claim-check", "claim-status"]) {
    assert.ok(container.includes(`id="${id}"`), id);
  }
  assert.equal(html.split('id="claim-start"').length, 2);
});

test("the icons are inline SVG with no namespace attribute", () => {
  assert.match(html, /<symbol id="icon-ghost"/);
  assert.match(html, /<symbol id="icon-wallet"/);
  assert.doesNotMatch(html, /xmlns/);
  assert.doesNotMatch(html, /<img\b/i);
});

test("the CSP stays default-src 'none' and adds font-src 'self'", () => {
  const csp = /http-equiv="Content-Security-Policy"\s+content="([^"]+)"/i.exec(html);
  assert.ok(csp);
  const parts = csp[1].split(";").map((p) => p.trim());
  assert.equal(parts[0], "default-src 'none'");
  assert.ok(parts.includes("font-src 'self'"));
  assert.ok(parts.includes("style-src 'self'"));
  assert.ok(parts.includes("script-src 'self' 'wasm-unsafe-eval'"));
});

test("neither the page nor the style names an external URL", () => {
  for (const [name, text] of [
    ["index.html", html],
    ["style.css", css],
  ]) {
    assert.doesNotMatch(text, /https?:\/\//i, name);
    assert.doesNotMatch(text, /url\(\s*["']?(?!#)[^)"']*\/\//i, name);
    assert.doesNotMatch(text, /@import/i, name);
  }
  assert.doesNotMatch(html, /<script\b(?![^>]*\bsrc=)/i, "no inline script");
  assert.doesNotMatch(html, /\sstyle="/i, "no inline style");
});

test("the light brand colors are CSS variables of one light theme", () => {
  const root = /:root\s*\{([^}]*)\}/.exec(css);
  assert.ok(root, "a :root block");
  const vars = Object.fromEntries([...root[1].matchAll(/(--[\w-]+):\s*([^;]+);/g)].map((m) => [m[1], m[2].trim()]));
  assert.equal(vars["--bg"].toUpperCase(), "#F5F5F8");
  for (const name of ["--surface", "--surface-behind", "--violet", "--text", "--muted", "--shadow", "--font", "--mono", "--ease"]) {
    assert.ok(vars[name], `${name} is set`);
  }
  assert.match(vars["--font"], /^"Instrument Sans", system-ui/);
  assert.match(vars["--mono"], /^"IBM Plex Mono", ui-monospace/);
  assert.match(root[1], /color-scheme:\s*light;/);
  assert.equal(css.match(/:root\b/g).length, 1, "one theme");
  assert.doesNotMatch(css, /color-scheme:\s*[^;]*dark/);
  // No second theme behind a color-scheme media query.
  assert.doesNotMatch(css, /prefers-color-[s]cheme/);
  // The inactive tab is darker than the card it sits behind.
  const shade = (hex) => parseInt(hex.slice(1, 3), 16) + parseInt(hex.slice(3, 5), 16) + parseInt(hex.slice(5, 7), 16);
  assert.ok(shade(vars["--surface-behind"]) < shade(vars["--surface"]));
  assert.match(css, /\.tab\s*\{[^}]*background:\s*var\(--surface-behind\)/);
  assert.match(css, /\.tab\[aria-selected="true"\]\s*\{[^}]*background:\s*var\(--surface\)/);
  assert.match(css, /\.card\s*\{[^}]*background:\s*var\(--surface\)/);
});

test("motion turns off under reduced motion; the card's soft shadow stays", () => {
  const at = css.indexOf("@media (prefers-reduced-motion: no-preference)");
  assert.notEqual(at, -1);
  const outside = css.slice(0, at);
  assert.doesNotMatch(outside, /\b(transition|animation)\s*:/);
  assert.doesNotMatch(css, /var\(--glow\)/);
  assert.match(outside, /\.card\s*\{[^}]*box-shadow:\s*var\(--shadow\)/);
  assert.match(css.slice(at), /transition/);
});

test("the page fits a phone's width", () => {
  assert.match(html, /<meta name="viewport" content="width=device-width, initial-scale=1">/);
  assert.match(css, /--card-width:\s*420px/);
  assert.match(css, /\.folder\s*\{[^}]*max-width:\s*var\(--card-width\);[^}]*width:\s*100%/);
  assert.match(css, /box-sizing:\s*border-box/);
  assert.match(css, /overflow-x:\s*hidden/);
  assert.match(css, /@media \(max-width: 480px\)/);
});
