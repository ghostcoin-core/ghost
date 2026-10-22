// The Midnight violet look, read from style.css, index.html and
// vercel/config.json as text: the founder's palette as CSS variables and the
// rules that use them, the 18px card, the two glow circles and their slow
// drift, the tab slide and the coin fades (all motion inside
// `prefers-reduced-motion: no-preference`), WCAG AA contrast for the text
// colors, the served CSP and one dark theme. No browser is needed.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const read = (path) => readFileSync(new URL(path, import.meta.url), "utf8");
const css = read("../style.css").replace(/\/\*[\s\S]*?\*\//g, "");
const html = read("../index.html");
const config = JSON.parse(read("../vercel/config.json"));

const PALETTE = [
  "#0A0A12",
  "#6B4CFF",
  "#2EC5FF",
  "#15142A",
  "#2A2850",
  "#0E0D1C",
  "#1E1C38",
  "#6E6A99",
  "#23214A",
  "#4E4A7A",
  "#1F1D3D",
  "#A78BFF",
  "#ECEBFF",
  "#8C88B8",
  "#A64CFF",
  "#CFC3FF",
  "#FF7A9A",
];

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
  for (let i = 0; i < 5 && /var\(/.test(out); i++) {
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

// Seconds in a CSS time.
function seconds(value) {
  const m = /([\d.]+)(ms|s)\b/.exec(value);
  assert.ok(m, `a time in ${value}`);
  return m[2] === "ms" ? Number(m[1]) / 1000 : Number(m[1]);
}

// WCAG 2 relative luminance and contrast ratio.
function rgb(color) {
  const hex = /^#([0-9a-f]{6})$/i.exec(color.trim());
  if (hex) return [0, 2, 4].map((i) => parseInt(hex[1].slice(i, i + 2), 16));
  const fn = /^rgba?\(\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)/i.exec(color.trim());
  assert.ok(fn, `a color: ${color}`);
  return fn.slice(1, 4).map(Number);
}

function alpha(color) {
  const m = /^rgba\([^)]*,\s*([\d.]+)\s*\)$/i.exec(color.trim());
  return m ? Number(m[1]) : 1;
}

// `top` painted over the opaque `under`.
function over(top, under) {
  const a = alpha(top);
  const [t, u] = [rgb(top), rgb(under)];
  return t.map((c, i) => c * a + u[i] * (1 - a));
}

function luminance(channels) {
  const [r, g, b] = channels.map((c) => {
    const s = c / 255;
    return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a, b) {
  const [x, y] = [luminance(Array.isArray(a) ? a : rgb(a)), luminance(Array.isArray(b) ? b : rgb(b))];
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
}

const upper = (s) => s.trim().toUpperCase();

test("every color of the Midnight violet table is in style.css", () => {
  const text = css.toUpperCase();
  for (const hex of PALETTE) assert.ok(text.includes(hex), `style.css has ${hex}`);
});

test("the palette sits in :root variables with the roles of the table", () => {
  assert.ok(root, "a :root block");
  const roles = {
    "--bg": "#0A0A12",
    "--glow-violet": "#6B4CFF",
    "--glow-cyan": "#2EC5FF",
    "--surface": "#15142A",
    "--border": "#2A2850",
    "--surface-behind": "#0E0D1C",
    "--border-behind": "#1E1C38",
    "--text-behind": "#6E6A99",
    "--input": "#0E0D1C",
    "--input-border": "#23214A",
    "--placeholder": "#4E4A7A",
    "--token": "#1F1D3D",
    "--text": "#ECEBFF",
    "--muted": "#8C88B8",
    "--accent": "#A78BFF",
    "--violet": "#6B4CFF",
    "--violet-end": "#A64CFF",
    "--wallet-text": "#CFC3FF",
    "--danger": "#FF7A9A",
  };
  for (const [name, hex] of Object.entries(roles)) assert.equal(upper(vars[name] ?? ""), hex, name);
  assert.match(vars["--wallet-tint"], /^rgba\(167,\s*139,\s*255,\s*0?\.12\)$/);
  assert.match(vars["--wallet-border"], /^rgba\(167,\s*139,\s*255,\s*0?\.3\)$/);
});

test("the rules use the palette: page, card, tabs, inputs, token, button, wallet, errors", () => {
  assert.equal(upper(rule(":root").background), "#0A0A12");
  assert.equal(upper(rule("body").background), "#0A0A12");

  const card = rule(".card");
  assert.equal(upper(card.background), "#15142A");
  assert.equal(card.border, "1px solid #2A2850");
  assert.equal(card["border-radius"], "18px");

  const behind = rule(".tab");
  assert.equal(upper(behind.background), "#0E0D1C");
  assert.equal(behind.border, "1px solid #1E1C38");
  assert.equal(upper(behind.color), "#6E6A99");
  const front = rule('.tab[aria-selected="true"]');
  assert.equal(upper(front.background), "#15142A");
  assert.equal(upper(front["border-color"]), "#2A2850");
  assert.equal(upper(front.color), "#ECEBFF");
  // The tab in front sits over the card, the one behind under it.
  assert.ok(Number(front["z-index"]) > Number(card["z-index"]));
  assert.ok(Number(behind["z-index"]) < Number(card["z-index"]));
  assert.match(behind.transform, /translateY\(\d+px\)/);
  assert.equal(front.transform, "none");

  for (const sel of ["input", ".amount-box"]) {
    assert.equal(upper(rule(sel).background), "#0E0D1C", sel);
    assert.equal(rule(sel).border, "1px solid #23214A", sel);
  }
  assert.equal(upper(rule("input::placeholder").color), "#4E4A7A");
  assert.equal(rule("input::placeholder").opacity, "1");
  assert.equal(upper(rule(".token").background), "#1F1D3D");
  assert.equal(upper(rule(".token .icon").color), "#A78BFF");

  for (const sel of ["button.link", ".icon-brand"]) assert.equal(upper(rule(sel).color), "#A78BFF", sel);
  assert.equal(upper(rule("input:focus")["border-color"]), "#A78BFF");
  assert.match(rule("input:focus")["box-shadow"], /rgba\(167,\s*139,\s*255/);

  const primary = rule("button.primary");
  assert.match(primary.background, /linear-gradient\([^,]*,\s*#6B4CFF,\s*#A64CFF\)/i);
  assert.equal(upper(primary.color), "#FFFFFF");
  assert.match(rule("button.primary:hover:not(:disabled)").filter, /brightness\(1\.\d+\)/);

  const wallet = rule(".wallet-button");
  assert.equal(wallet.background, vars["--wallet-tint"]);
  assert.equal(wallet.border, `1px solid ${vars["--wallet-border"]}`);
  assert.equal(upper(wallet.color), "#CFC3FF");

  for (const sel of [".error-line", "#error"]) assert.equal(upper(rule(sel).color), "#FF7A9A", sel);
});

test("two large blurred glow circles sit behind the page: violet at 35%, cyan at 18%", () => {
  const circles = [
    ["body::before", "#6B4CFF", 0.35],
    ["body::after", "#2EC5FF", 0.18],
  ];
  const shared = rule("body::before");
  for (const [sel, hex, opacity] of circles) {
    const r = { ...shared, ...rule(sel) };
    assert.equal(upper(r.background), hex, sel);
    assert.equal(Number(r.opacity), opacity, sel);
    assert.equal(r["border-radius"], "50%", sel);
    assert.equal(r.position, "fixed", sel);
    assert.equal(r["pointer-events"], "none", sel);
    assert.ok(Number(r["z-index"]) < 0, `${sel} sits behind the page`);
    const blur = /blur\((\d+)px\)/.exec(r.filter);
    assert.ok(blur && Number(blur[1]) >= 60, `${sel} is blurred`);
    assert.ok(parseInt(r.width, 10) >= 300 && r.width === r.height, `${sel} is a large circle`);
  }
  assert.equal(rule("body").isolation, "isolate");
});

test("the glow drifts in a loop of about 20s, only without reduced motion", () => {
  assert.notEqual(motionAt, -1, "a no-preference motion block");
  for (const sel of ["body::before", "body::after"]) {
    const animation = rule(sel, motion).animation;
    assert.match(animation, /\bdrift\b/, sel);
    assert.match(animation, /\binfinite\b/, sel);
    const s = seconds(animation);
    assert.ok(s >= 15 && s <= 25, `${sel} drifts in about 20s, not ${s}s`);
  }
  assert.match(motion, /@keyframes drift\s*\{[\s\S]*?transform/);
  // Nothing moves outside the no-preference block.
  assert.doesNotMatch(outsideMotion, /\b(animation|transition)(-[\w]+)?\s*:/);
  assert.doesNotMatch(outsideMotion, /@keyframes/);
});

test("the tab slides forward in about 200ms", () => {
  const transition = rule(".tab", motion).transition;
  const slide = transition.split(",").find((t) => /\btransform\b/.test(t));
  assert.ok(slide, "the tab's transform is animated");
  const s = seconds(slide);
  assert.ok(s >= 0.15 && s <= 0.25, `the tab slides in about 200ms, not ${s * 1000}ms`);
});

test("the coin fades out on Vanish's Done screen and in on Summon's", () => {
  const out = rule("#vanish-done:not([hidden]) .icon-done", motion).animation;
  const into = rule("#summon-done:not([hidden]) .icon-done", motion).animation;
  const name = (a) => /^([\w-]+)/.exec(a)[1];
  const frames = (n) => {
    const at = motion.indexOf(`@keyframes ${n}`);
    assert.notEqual(at, -1, `@keyframes ${n}`);
    return block(motion, at);
  };
  // Fading out ends lower than it starts; fading in starts from nothing.
  const outFrames = frames(name(out));
  const opacities = [...outFrames.matchAll(/opacity:\s*([\d.]+)/g)].map((m) => Number(m[1]));
  assert.ok(opacities.length === 2 && opacities[1] < opacities[0], "the vanished coin fades out");
  assert.match(out, /\bforwards\b/);
  assert.match(frames(name(into)), /from\s*\{[^}]*opacity:\s*0;/);
});

test("text colors meet WCAG AA on their backgrounds", () => {
  const AA = 4.5;
  const pairs = [
    ["main text on the page", vars["--text"], vars["--bg"]],
    ["main text on the card", vars["--text"], vars["--surface"]],
    ["main text in an input", vars["--text"], vars["--input"]],
    ["secondary text on the page", vars["--muted"], vars["--bg"]],
    ["secondary text on the card", vars["--muted"], vars["--surface"]],
    ["secondary text in an input", vars["--muted"], vars["--input"]],
    ["accent on the page", vars["--accent"], vars["--bg"]],
    ["accent on the card", vars["--accent"], vars["--surface"]],
    ["error text on the card", vars["--danger"], vars["--surface"]],
    ["button text on the gradient's start", vars["--on-violet"], vars["--violet"]],
    ["wallet text on its tint", rgb(vars["--wallet-text"]), over(vars["--wallet-tint"], vars["--bg"])],
  ];
  for (const [what, fg, bg] of pairs) {
    const ratio = contrast(fg, bg);
    assert.ok(ratio >= AA, `${what}: ${ratio.toFixed(2)}:1`);
  }
  // The button's text sits in the middle of the gradient.
  const middle = rgb(vars["--violet"]).map((c, i) => (c + rgb(vars["--violet-end"])[i]) / 2);
  assert.ok(contrast(vars["--on-violet"], middle) >= AA, "button text on the gradient's middle");
  // The light end is 4.1:1, so the button's text is WCAG large text
  // (18.66px bold or more), whose AA ratio is 3:1.
  assert.ok(contrast(vars["--on-violet"], vars["--violet-end"]) >= 3);
  const primary = rule("button.primary");
  assert.ok(parseFloat(primary["font-size"]) * 16 >= 18.66, "large text");
  assert.ok(Number(primary["font-weight"]) >= 700, "bold");
  assert.ok(!("font-size" in rule("button.big")), "the big button keeps the large text");
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
    assert.equal(parts[0], "default-src 'none'");
  }
});

test("style.css has one dark theme only, with Inter first in the font stack", () => {
  assert.match(root[1], /color-scheme:\s*dark;/);
  assert.equal(css.match(/:root\b/g).length, 1);
  assert.doesNotMatch(css, /\blight\b/i);
  assert.doesNotMatch(css, new RegExp("prefers-color-" + "scheme"));
  assert.doesNotMatch(css, /\[data-theme/);
  assert.match(html, /<meta name="color-scheme" content="dark">/);
  assert.match(vars["--font"], /^"Inter", system-ui/);
  assert.doesNotMatch(css, new RegExp("@font-" + "face"));
});
