// The light brand look, read from style.css, index.html, favicon.svg and
// vercel/config.json as text: the light palette as CSS variables and the
// rules that use them, WCAG AA (4.5:1) for every text color on the
// background it sits on, one light theme with no dark variant, the
// Specter logo's exact geometry in the header, its mark as the small icon
// and the favicon, and motion only inside
// `prefers-reduced-motion: no-preference`. No browser is needed.

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

test("the light palette sits in :root variables with the roles of the ticket's table", () => {
  assert.ok(root, "a :root block");
  const roles = {
    "--bg": "#F5F5F8",
    "--header": "#FFFFFF",
    "--header-line": "#E4E3EC",
    "--surface": "#FFFFFF",
    "--border": "#E4E3EC",
    "--surface-behind": "#ECEBF2",
    "--text-behind": "#5F5D73",
    "--input": "#F5F5F8",
    "--input-border": "#E4E3EC",
    "--placeholder": "#6E6C82",
    "--text": "#0E0D1A",
    "--muted": "#4A4860",
    "--quiet": "#6E6C82",
    "--accent": "#6B4CFF",
    "--tint": "#EEEAFF",
    "--token": "#EEEAFF",
    "--violet": "#6B4CFF",
    "--violet-hover": "#5A3BEE",
    "--on-violet": "#FFFFFF",
    "--wallet-bg": "#FFFFFF",
    "--wallet-border": "#E4E3EC",
    "--wallet-text": "#0E0D1A",
    "--danger": "#C8264B",
    "--caution": "#A15C00",
    "--mint": "#4FF0C8",
  };
  for (const [name, hex] of Object.entries(roles)) assert.equal(upper(vars[name] ?? ""), hex, name);
  assert.match(vars["--shadow"], /^0 12px 32px rgba\(14,\s*13,\s*26,\s*0?\.06\)$/);
});

test("the rules use the palette: page, header, card, tabs, inputs, token, buttons, wallet, warnings", () => {
  assert.equal(upper(rule(":root").background), "#F5F5F8");
  assert.equal(upper(rule("body").background), "#F5F5F8");

  const top = rule(".top");
  assert.equal(upper(top.background), "#FFFFFF");
  assert.equal(upper(top["border-bottom"]), "1PX SOLID #E4E3EC");

  const card = rule(".card");
  assert.equal(upper(card.background), "#FFFFFF");
  assert.equal(upper(card.border), "1PX SOLID #E4E3EC");
  assert.match(card["box-shadow"], /^0 12px 32px rgba\(14,\s*13,\s*26,\s*0?\.06\)$/);
  assert.equal(card["border-radius"], "18px");

  const behind = rule(".tab");
  assert.equal(upper(behind.background), "#ECEBF2");
  assert.equal(upper(behind.color), "#5F5D73");
  const front = rule('.tab[aria-selected="true"]');
  assert.equal(upper(front.background), "#FFFFFF");
  assert.equal(upper(front.color), "#0E0D1A");
  // The tab in front sits over the card, the one behind under it.
  assert.ok(Number(front["z-index"]) > Number(card["z-index"]));
  assert.ok(Number(behind["z-index"]) < Number(card["z-index"]));

  for (const sel of ["input", ".amount-box"]) {
    assert.equal(upper(rule(sel).background), "#F5F5F8", sel);
    assert.equal(upper(rule(sel).border), "1PX SOLID #E4E3EC", sel);
  }
  assert.equal(upper(rule("input::placeholder").color), "#6E6C82");
  assert.equal(rule("input::placeholder").opacity, "1");

  // The token chip: violet tint with ink text, never violet text on the tint.
  const token = rule(".token");
  assert.equal(upper(token.background), "#EEEAFF");
  assert.equal(upper(token.color), "#0E0D1A");

  for (const sel of ["button.link", "#progress"]) assert.equal(upper(rule(sel).color), "#6B4CFF", sel);
  assert.equal(upper(rule("input:focus")["border-color"]), "#6B4CFF");
  assert.match(rule("input:focus")["box-shadow"], /rgba\(107,\s*76,\s*255/);

  // The main button is solid violet, darker on hover, with no gradient.
  const primary = rule("button.primary");
  assert.equal(upper(primary.background), "#6B4CFF");
  assert.equal(upper(primary.color), "#FFFFFF");
  assert.equal(upper(rule("button.primary:hover:not(:disabled)").background), "#5A3BEE");
  assert.doesNotMatch(css, /gradient\(/);

  const wallet = rule(".wallet-button");
  assert.equal(upper(wallet.background), "#FFFFFF");
  assert.equal(upper(wallet.border), "1PX SOLID #E4E3EC");
  assert.equal(upper(wallet.color), "#0E0D1A");

  for (const sel of [".error-line", "#error"]) assert.equal(upper(rule(sel).color), "#C8264B", sel);
  assert.equal(upper(rule(".bottom .warn").color), "#A15C00");

  // Summon's success moment: mint as a fill with ink on it.
  const success = rule("#summon-done .icon-done");
  assert.equal(upper(success.background), "#4FF0C8");
  assert.equal(upper(success.color), "#0E0D1A");
  // Mint is used nowhere else, so never as text on white.
  assert.equal(css.split("var(--mint)").length, 2);
  assert.equal(css.toUpperCase().split("#4FF0C8").length, 2);
});

test("the dark glow circles and the cyan are gone; at most one soft tint behind the card", () => {
  assert.doesNotMatch(css, /2EC5FF/i);
  assert.doesNotMatch(css, /--glow\b|--glow-(violet|cyan)/);
  assert.ok(!/body::after/.test(css), "no second glow circle");
  const tints = css.match(/body::before\s*\{/g) ?? [];
  assert.ok(tints.length <= 1);
  if (tints.length) assert.match(rule("body::before").background, /EEEAFF|238,\s*234,\s*255/i);
});

test("every text color meets WCAG AA (4.5:1) on the background it sits on", () => {
  const AA = 4.5;
  const v = (name) => vars[name];
  const pairs = [
    ["ink on the page", "--text", "--bg"],
    ["ink on the header", "--text", "--header"],
    ["ink on the card", "--text", "--surface"],
    ["ink in an input", "--text", "--input"],
    ["ink on the token chip", "--text", "--token"],
    ["ink on the install line", "--text", "--surface-behind"],
    ["ink on mint", "--text", "--mint"],
    ["muted on the page", "--muted", "--bg"],
    ["muted on the card", "--muted", "--surface"],
    ["muted in an input", "--muted", "--input"],
    ["muted on the tab behind (hover)", "--muted", "--surface-behind"],
    ["quiet on the card", "--quiet", "--surface"],
    ["quiet on the page", "--quiet", "--bg"],
    ["placeholder in an input", "--placeholder", "--input"],
    ["tab text behind the card", "--text-behind", "--surface-behind"],
    ["accent on the page", "--accent", "--bg"],
    ["accent on the card", "--accent", "--surface"],
    ["accent in an input", "--accent", "--input"],
    ["button text on violet", "--on-violet", "--violet"],
    ["button text on the hover violet", "--on-violet", "--violet-hover"],
    ["wallet text on the wallet button", "--wallet-text", "--wallet-bg"],
    ["danger on the card", "--danger", "--surface"],
    ["danger on the page", "--danger", "--bg"],
    ["caution on the card", "--caution", "--surface"],
    ["caution on the page", "--caution", "--bg"],
  ];
  for (const [what, fg, bg] of pairs) {
    const ratio = contrast(v(fg), v(bg));
    assert.ok(ratio >= AA, `${what}: ${ratio.toFixed(2)}:1`);
  }
  // The two the ticket rules out really fail, which is why they are not used.
  assert.ok(contrast("#6E6C82", v("--surface-behind")) < AA);
  assert.ok(contrast(v("--accent"), v("--tint")) < AA);
});

test("one light theme only: no dark variant and no color-scheme media query", () => {
  assert.match(root[1], /color-scheme:\s*light;/);
  assert.equal(css.match(/:root\b/g).length, 1);
  assert.doesNotMatch(css, /\bdark\b/i);
  assert.doesNotMatch(css, new RegExp("prefers-color-" + "scheme"));
  assert.doesNotMatch(css, /\[data-theme/);
  assert.match(html, /<meta name="color-scheme" content="light">/);
  assert.match(html, /<meta name="theme-color" content="#FFFFFF">/);
  assert.equal(html.match(/name="theme-color"/g).length, 1);
  assert.doesNotMatch(html, /\bdark\b/i);
});

// The logo: the Specter mark (a dark card with a foil ring) and the
// "specter" wordmark, as the website draws them (its logo.svg and
// favicon.svg).

const CARD_INK = "#101013";
const FOIL = ["#FF7AD9", "#B58CFF", "#7FB8FF", "#8CFFE0", "#FFF3A0", "#FF9A8C", "#FF7AD9"];

// The foil gradient's stop colors, in order, and its id.
function foil(svg) {
  const g = /<linearGradient id="([^"]+)" x1="0" y1="0\.41" x2="1" y2="0\.59">([\s\S]*?)<\/linearGradient>/.exec(svg);
  assert.ok(g, "a foil gradient");
  return { id: g[1], stops: [...g[2].matchAll(/stop-color="([^"]+)"/g)].map((m) => m[1].toUpperCase()) };
}

test("the header shows the full Specter logo inline: the card, the foil ring and the wordmark", () => {
  const top = /<header class="top">[\s\S]*?<\/header>/.exec(html);
  assert.ok(top, "a top bar");
  const logo = /<svg class="brand-logo" viewBox="0 0 122\.02 22\.39" role="img" aria-label="Specter" focusable="false">([\s\S]*?)<\/svg>/.exec(top[0]);
  assert.ok(logo, "the brand is the logo as inline SVG named Specter");
  const ring = foil(logo[1]);
  assert.deepEqual(ring.stops, FOIL);
  assert.equal(html.split(`id="${ring.id}"`).length, 2, "the gradient id is used once in the page");
  assert.match(logo[1], new RegExp(`<rect x="0" y="0" width="30" height="19" rx="5" fill="${CARD_INK}"/>`));
  assert.match(logo[1], new RegExp(`<circle cx="21" cy="9\\.5" r="5\\.25" fill="none" stroke="url\\(#${ring.id}\\)" stroke-width="1\\.6"/>`));
  assert.match(logo[1], new RegExp(`<path fill="${CARD_INK}" d="M45\\.96 17\\.93[^"]+Z"/>`), "the wordmark");
  const brand = rule(".brand-logo");
  assert.equal(brand.height, "1.4rem");
  assert.equal(brand.width, "7.63rem", "the logo's own ratio, 122.02 by 22.39");
  // The old pixel-ghost mark and its full-logo switches are gone.
  assert.doesNotMatch(html, /icon-brand|logo-cells|#C9BCFF/i);
  assert.doesNotMatch(css, /icon-brand|--logo-cells|--logo-body|C9BCFF/i);
});

test("the small icon symbol is the Specter mark in one color, its ring a hole", () => {
  const symbol = /<symbol id="icon-ghost" viewBox="([^"]+)">([\s\S]*?)<\/symbol>/.exec(html);
  assert.ok(symbol, "#icon-ghost is a symbol with a viewBox");
  assert.equal(symbol[1], "0 0 32 32");
  const paths = [...symbol[2].matchAll(/<path\b[^>]*>/g)].map((m) => m[0]);
  assert.equal(paths.length, 1);
  assert.doesNotMatch(symbol[2], /<(rect|circle|g)\b/);
  assert.match(paths[0], /^<path class="logo-body" fill-rule="evenodd" d="[^"]+"\/>$/);
  const d = /d="([^"]+)"/.exec(paths[0])[1];
  // The card of the favicon (0, 5.9, 32 by 20.2, radius 4.6), then the
  // ring's outer and inner edges around (22.4, 16): radius 6.2 with its
  // 2.8 stroke, so 7.6 and 4.8.
  assert.match(d, /^M4\.6 5\.9H27\.4A4\.6 4\.6 0 0 1 32 10\.5V21\.5A4\.6 4\.6 0 0 1 27\.4 26\.1H4\.6A4\.6 4\.6 0 0 1 0 21\.5V10\.5A4\.6 4\.6 0 0 1 4\.6 5\.9Z/);
  assert.match(d, / M30 16A7\.6 7\.6 0 1 1 14\.8 16A7\.6 7\.6 0 1 1 30 16Z/);
  assert.match(d, / M27\.2 16A4\.8 4\.8 0 1 1 17\.6 16A4\.8 4\.8 0 1 1 27\.2 16Z$/);
  assert.equal(rule(".logo-body").fill, "currentColor");
});

test("the favicon is the Specter mark: the dark card and the foil ring, linked and built", () => {
  assert.match(favicon, /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg" viewBox="0 0 32 32">/);
  const ring = foil(favicon);
  assert.deepEqual(ring.stops, FOIL);
  assert.match(favicon, new RegExp(`<rect x="0" y="5\\.9" width="32" height="20\\.2" rx="4\\.6" fill="${CARD_INK}"/>`));
  assert.match(favicon, new RegExp(`<circle cx="22\\.4" cy="16" r="6\\.2" fill="none" stroke="url\\(#${ring.id}\\)" stroke-width="2\\.8"/>`));
  assert.equal([...favicon.matchAll(/<(rect|circle|path)\b/g)].length, 2, "the card and the ring, nothing else");
  assert.match(html, /<link rel="icon" href="favicon\.svg" type="image\/svg\+xml">/);
  assert.match(build, /^files=\([^)]*\bfavicon\.svg\b[^)]*\)$/m);
});

test("motion stays inside prefers-reduced-motion: no-preference", () => {
  assert.notEqual(motionAt, -1, "a no-preference motion block");
  assert.doesNotMatch(outsideMotion, /\b(animation|transition)(-[\w]+)?\s*:/);
  assert.doesNotMatch(outsideMotion, /@keyframes/);
  assert.match(rule(".tab", motion).transition, /\btransform\b/);
  assert.match(rule("#vanish-done:not([hidden]) .icon-done", motion).animation, /\bcoin-out\b/);
  assert.match(rule("#summon-done:not([hidden]) .icon-done", motion).animation, /\bcoin-in\b/);
  assert.doesNotMatch(motion, /\bdrift\b/);
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
