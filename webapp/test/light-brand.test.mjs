// The Specter look, read from style.css, index.html, favicon.svg and
// vercel/config.json as text: the palette as CSS variables and the rules
// that use them, WCAG AA (4.5:1) for every text color on the background it
// sits on, one light theme with no dark variant, the foil used sparingly,
// the Specter logo's exact geometry in the header and the favicon, and
// motion only inside `prefers-reduced-motion: no-preference`. No browser is
// needed.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const read = (path) => readFileSync(new URL(path, import.meta.url), "utf8");
const css = read("../style.css").replace(/\/\*[\s\S]*?\*\//g, "");
const html = read("../index.html");
const favicon = read("../favicon.svg");
const build = read("../build.sh");
const config = JSON.parse(read("../vercel/config.json"));

const MOTION = "@media (prefers-reduced-motion: no-preference)";

// The text of the block opened by the `{` after `at`, braces matched.
function block(text, at) {
  const open = text.indexOf("{", at);
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === "{") depth++;
    if (text[i] === "}" && --depth === 0) return text.slice(open + 1, i);
  }
  assert.fail("the block is closed");
}

const motionAt = css.indexOf(MOTION);
const motion = motionAt === -1 ? "" : block(css, motionAt);
const outsideMotion = motionAt === -1 ? css : css.slice(0, motionAt) + css.slice(motionAt + MOTION.length + motion.length + 2);

const root = /:root\s*\{([^}]*)\}/.exec(css);
const vars = root ? Object.fromEntries([...root[1].matchAll(/(--[\w-]+):\s*([^;]+);/g)].map((m) => [m[1], m[2].trim()])) : {};

// A value with its var() references replaced by the :root values.
function resolve(value) {
  let out = value;
  for (let i = 0; i < 5 && /var\(--[\w-]+\)/.test(out); i++) {
    out = out.replace(/var\((--[\w-]+)\)/g, (_, name) => {
      assert.ok(name in vars, `${name} is set in :root`);
      return vars[name];
    });
  }
  return out;
}

// The declarations of every rule in `text` whose selector list names
// `selector`, later rules winning, values resolved.
function rule(selector, text = css) {
  const out = {};
  let found = false;
  for (const m of text.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    const selectors = m[1].split(",").map((s) => s.trim());
    if (!selectors.includes(selector)) continue;
    found = true;
    for (const d of m[2].matchAll(/([\w-]+)\s*:\s*([^;]+);?/g)) out[d[1]] = resolve(d[2].trim());
  }
  assert.ok(found, `style.css has a rule for ${selector}`);
  return out;
}

// WCAG 2 relative luminance and contrast ratio of two opaque #RRGGBB colors.
function rgb(color) {
  const hex = /^#([0-9a-f]{6})$/i.exec(color.trim());
  assert.ok(hex, `an opaque color: ${color}`);
  return [0, 2, 4].map((i) => parseInt(hex[1].slice(i, i + 2), 16));
}

function luminance(color) {
  const [r, g, b] = rgb(color).map((c) => {
    const s = c / 255;
    return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a, b) {
  const [x, y] = [luminance(a), luminance(b)];
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
}

const upper = (s) => s.trim().toUpperCase();

const CARD_INK = "#101013";
const FOIL = ["#FF7AD9", "#B58CFF", "#7FB8FF", "#8CFFE0", "#FFF3A0", "#FF9A8C", "#FF7AD9"];

// The foil gradient's stop colors, in order, and its id.
function foil(svg) {
  const g = /<linearGradient id="([^"]+)" x1="-0\.33" y1="0\.35" x2="1\.33" y2="0\.65">([\s\S]*?)<\/linearGradient>/.exec(svg);
  assert.ok(g, "a foil gradient");
  return { id: g[1], stops: [...g[2].matchAll(/stop-color="([^"]+)"/g)].map((m) => m[1].toUpperCase()) };
}

// The rules outside the media queries: the base look, before a phone's
// sizes or the motion block change anything.
const base = css.replace(/@media[^{]*\{(?:[^{}]*\{[^{}]*\})*[^{}]*\}/g, "");

test("the Specter palette sits in :root variables", () => {
  assert.ok(root, "a :root block");
  const roles = {
    "--wall": "#EDEBE6",
    "--paper": "#FFFFFF",
    "--ink": "#101013",
    "--body": "#4A4A52",
    "--quiet": "#6A6973",
    "--line": "#D6D3CC",
    "--on-ink": "#FFFFFF",
    "--card-black": "#131316",
    "--go": "#0B7A4B",
    "--go-bg": "#E0F2E9",
    "--wait": "#8A5A00",
    "--wait-bg": "#F6ECD4",
    "--wait-text": "#4A3A12",
    "--danger": "#B3261E",
  };
  for (const [name, hex] of Object.entries(roles)) assert.equal(upper(vars[name] ?? ""), hex, name);
  // The foil, the only colour, in its seven stops.
  const stops = [...vars["--foil"].matchAll(/#[0-9A-F]{6}/gi)].map((m) => m[0].toUpperCase());
  assert.deepEqual(stops, FOIL);
  assert.match(vars["--foil"], /^linear-gradient\(100deg,/);
});

test("the rules use the palette: page, tile, switch, wells, buttons, wallet, warnings", () => {
  assert.equal(upper(rule(":root", base).background), "#EDEBE6");
  assert.equal(upper(rule("body", base).background), "#EDEBE6");

  // The tile: white, 26px corners, no border and no shadow.
  const tile = rule(".folder", base);
  assert.equal(upper(tile.background), "#FFFFFF");
  assert.equal(tile["border-radius"], "26px");
  assert.equal(tile.border, undefined);
  assert.equal(tile["box-shadow"], undefined);

  // The switch: the selected side ink with white text, the other quiet.
  assert.equal(upper(rule(".tabs", base).background), "#EDEBE6");
  const front = rule('.tab[aria-selected="true"]', base);
  assert.equal(upper(front.background), "#101013");
  assert.equal(upper(front.color), "#FFFFFF");
  assert.equal(upper(rule(".tab", base).color), "#6A6973");

  assert.equal(upper(rule(".well", base).background), "#EDEBE6");
  assert.equal(upper(rule("input", base).background), "#EDEBE6");
  assert.equal(upper(rule("input::placeholder", base).color), "#6A6973");
  assert.equal(rule("input::placeholder", base).opacity, "1");

  // The main button is solid ink with white text, 14px corners.
  const primary = rule("button.primary", base);
  assert.equal(upper(primary.background), "#101013");
  assert.equal(upper(primary.color), "#FFFFFF");
  assert.equal(rule("button", base)["border-radius"], "14px");

  // The wallet button: ink until a wallet is connected, then a white pill.
  assert.equal(upper(rule(".wallet-button", base).background), "#101013");
  assert.equal(upper(rule('body[data-wallet="on"] .wallet-button', base).background), "#FFFFFF");
  assert.equal(upper(rule(".wallet-dot", base).background), "#0B7A4B");

  for (const sel of [".error-line", "#error"]) assert.equal(upper(rule(sel, base).color), "#B3261E", sel);
  assert.equal(upper(rule(".warn-box", base).background), "#F6ECD4");
  assert.equal(upper(rule(".warn-box p:not(.box-head)", base).color), "#4A3A12");
  assert.equal(upper(rule(".box-head", base).color), "#8A5A00");
  assert.equal(upper(rule(".bottom .warn", base).color), "#6A6973");
  assert.equal(upper(rule(".bottom .warn::before", base).background), "#8A5A00");
  assert.equal(upper(rule(".ok", base).color), "#0B7A4B");
});

test("the foil is used sparingly, and the only shadows are under the card", () => {
  // The foil: the card's glints, small dots, the progress bar, the mini card.
  const uses = [...css.matchAll(/([^{}]+)\{[^{}]*var\(--foil\)[^{}]*\}/g)].map((m) => m[1].trim());
  assert.ok(uses.length > 0 && uses.length <= 6, uses.join(" | "));
  for (const sel of uses) {
    assert.match(sel, /::before|::after|\.bar span|now/, `foil only on small marks: ${sel}`);
  }
  // No tile, panel or button has a drop shadow; insets (outlines) only.
  for (const m of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    const shadow = /box-shadow:\s*([^;]+);/.exec(m[2]);
    if (!shadow) continue;
    const sel = m[1].trim();
    if (sel === ".face") {
      assert.match(shadow[1], /var\(--card-shadow\)/);
      continue;
    }
    assert.ok(/^none$/.test(shadow[1]) || shadow[1].split(/,(?![^(]*\))/).every((s) => /\binset\b/.test(s)), `${sel}: ${shadow[1]}`);
  }
});

test("every text color meets WCAG AA (4.5:1) on the background it sits on", () => {
  const AA = 4.5;
  const v = (name) => vars[name];
  const pairs = [
    ["ink on the page", "--ink", "--wall"],
    ["ink on the tile", "--ink", "--paper"],
    ["body on the page", "--body", "--wall"],
    ["body on the tile", "--body", "--paper"],
    ["quiet on the tile", "--quiet", "--paper"],
    ["quiet on the page and the wells", "--quiet", "--wall"],
    ["quiet on a warning box", "--quiet", "--wait-bg"],
    ["white on ink (buttons, the switch)", "--on-ink", "--ink"],
    ["green on the tile", "--go", "--paper"],
    ["green on the page", "--go", "--wall"],
    ["green on its fill", "--go", "--go-bg"],
    ["amber on the page", "--wait", "--wall"],
    ["amber on a warning box", "--wait", "--wait-bg"],
    ["warning text on a warning box", "--wait-text", "--wait-bg"],
    ["red on the tile", "--danger", "--paper"],
    ["red on the page", "--danger", "--wall"],
  ];
  for (const [what, fg, bg] of pairs) {
    const ratio = contrast(v(fg), v(bg));
    assert.ok(ratio >= AA, `${what}: ${ratio.toFixed(2)}:1`);
  }
});

test("one light theme only: no dark variant and no color-scheme media query", () => {
  assert.match(root[1], /color-scheme:\s*light;/);
  assert.equal(css.match(/:root\b/g).length, 1);
  assert.doesNotMatch(css, /\bdark\b/i);
  assert.doesNotMatch(css, new RegExp("prefers-color-" + "scheme"));
  assert.doesNotMatch(css, /\[data-theme/);
  assert.match(html, /<meta name="color-scheme" content="light">/);
  assert.match(html, /<meta name="theme-color" content="#EDEBE6">/);
  assert.equal(html.match(/name="theme-color"/g).length, 1);
  assert.doesNotMatch(html, /\bdark\b/i);
});

// The logo: the Specter mark (the Ring: a black square tile with a foil ring) and the
// "specter" wordmark, as the website draws them (its logo.svg and
// favicon.svg).

test("the header shows the full Specter logo inline: the tile, the foil ring and the wordmark", () => {
  const top = /<header class="top">[\s\S]*?<\/header>/.exec(html);
  assert.ok(top, "a top bar");
  const logo = /<svg class="brand-logo" viewBox="0 0 118\.02 26" role="img" aria-label="Specter" focusable="false">([\s\S]*?)<\/svg>/.exec(top[0]);
  assert.ok(logo, "the brand is the logo as inline SVG named Specter");
  const ring = foil(logo[1]);
  assert.deepEqual(ring.stops, FOIL);
  assert.equal(html.split(`id="${ring.id}"`).length, 2, "the gradient id is used once in the page");
  assert.match(logo[1], new RegExp(`<rect x="0" y="0" width="26" height="26" rx="5\\.89" fill="${CARD_INK}"/>`));
  assert.match(logo[1], new RegExp(`<circle cx="13" cy="13" r="6\\.6" fill="none" stroke="url\\(#${ring.id}\\)" stroke-width="2\\.44"/>`));
  assert.match(logo[1], new RegExp(`<path fill="${CARD_INK}" d="M41\\.96 21\\.43[^"]+Z"/>`), "the wordmark");
  const brand = rule(".brand-logo", base);
  assert.equal(brand.height, "1.6rem");
  assert.equal(brand.width, "7.26rem", "the logo's own ratio, 118.02 by 26");
  // The old pixel-ghost mark and its full-logo switches are gone.
  assert.doesNotMatch(html, /icon-brand|logo-cells|#C9BCFF/i);
  assert.doesNotMatch(css, /icon-brand|--logo-cells|--logo-body|C9BCFF/i);
});

test("the small mark of the wallet list is the Specter Ring: a black square tile with a foil ring", () => {
  assert.match(html, /<span class="mini-card" aria-hidden="true"><\/span>/);
  const mini = rule(".mini-card", base);
  assert.equal(mini.background, "#131316");
  assert.equal(mini["aspect-ratio"], "1");
  assert.match(rule(".mini-card::after", base).background, /^linear-gradient\(100deg/);
});

test("the favicon is the Specter Ring: the black tile and the foil ring, linked and built", () => {
  assert.match(favicon, /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg" viewBox="0 0 32 32">/);
  const ring = foil(favicon);
  assert.deepEqual(ring.stops, FOIL);
  assert.match(favicon, new RegExp(`<rect x="0" y="0" width="32" height="32" rx="7\\.25" fill="${CARD_INK}"/>`));
  assert.match(favicon, new RegExp(`<circle cx="16" cy="16" r="8\\.12" fill="none" stroke="url\\(#${ring.id}\\)" stroke-width="3\\.6"/>`));
  assert.equal([...favicon.matchAll(/<(rect|circle|path)\b/g)].length, 2, "the tile and the ring, nothing else");
  assert.match(html, /<link rel="icon" href="favicon\.svg" type="image\/svg\+xml">/);
  assert.match(build, /^files=\([^)]*\bfavicon\.svg\b[^)]*\)$/m);
});

test("motion stays inside prefers-reduced-motion: no-preference", () => {
  assert.notEqual(motionAt, -1, "a no-preference motion block");
  assert.doesNotMatch(outsideMotion, /\b(animation|transition)(-[\w]+)?\s*:/);
  assert.doesNotMatch(outsideMotion, /@keyframes/);
  // The card turns and tilts, the glint runs on a vanished card, the bar
  // runs while waiting: all only with motion allowed.
  assert.match(rule(".bearer", motion).transition, /\btransform\b/);
  assert.match(rule('body[data-screen="vanished"] .glint', motion).animation, /\bglint\b/);
  assert.match(rule(".bar span", motion).animation, /\brun\b/);
  // The tilt follows the pointer only without reduced motion and not on touch.
  const card = read("../src/bearer-card.mjs");
  assert.match(card, /matchMedia\("\(prefers-reduced-motion: reduce\)"\)/);
  assert.match(card, /if \(calm\.matches \|\| touch\.matches \|\| e\.pointerType === "touch"\) return;/);
});

test("the served CSP is the page's CSP plus frame-ancestors 'none', with font-src 'self' in both", () => {
  const page = /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/.exec(html);
  assert.ok(page, "index.html carries a CSP");
  const headers = config.routes.find((r) => r.src === "/(.*)").headers;
  const served = headers["Content-Security-Policy"];
  assert.equal(served, `${page[1]}; frame-ancestors 'none'`);
  for (const policy of [page[1], served]) {
    const parts = policy.split(";").map((p) => p.trim());
    assert.ok(parts.includes("font-src 'self'"), policy);
    assert.ok(parts.includes("img-src 'self' blob:"), policy);
    assert.equal(parts[0], "default-src 'none'");
  }
});
