// The light brand look: style.css's palette tokens, WCAG AA contrast for
// every text color on the background it sits on, the pixel-ghost logo (in
// the page, and its small cut as the favicon) drawn to its exact geometry, the
// self-hosted fonts, and one light theme. Files are read as text.

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";
import { BODY_FILL, CELLS, glyphProblems, showsGlyph, smallProblems, viewBox } from "../../scripts/check-pixel-ghost-logo.mjs";

const read = (path) => readFileSync(new URL(path, import.meta.url), "utf8");
const css = read("../style.css");
const page = read("../index.html");
const favicon = read("../favicon.svg");
const config = JSON.parse(read("../vercel/config.json"));

const PALETTE = {
  "--bg": "#ffffff",
  "--panel": "#f5f5f8",
  "--line": "#e4e3ec",
  "--text": "#0e0d1a",
  "--muted": "#4a4860",
  "--quiet": "#6e6c82",
  "--accent": "#6b4cff",
  "--on-accent": "#ffffff",
  "--highlight": "#eeeaff",
  "--code-bg": "#0e0d1a",
  "--code-text": "#4ff0c8",
};

// The CSS as a list of rules: selector and its declarations.
function rules(text) {
  const body = text.replace(/\/\*[\s\S]*?\*\//g, "");
  return [...body.matchAll(/([^{}]+)\{([^{}]*)\}/g)].map((m) => ({
    selector: m[1].trim(),
    decls: Object.fromEntries(
      m[2]
        .split(";")
        .map((d) => d.trim())
        .filter(Boolean)
        .map((d) => [d.slice(0, d.indexOf(":")).trim(), d.slice(d.indexOf(":") + 1).trim()]),
    ),
  }));
}

const RULES = rules(css);
const root = RULES.find((r) => r.selector === ":root").decls;
const rule = (selector) => RULES.find((r) => r.selector === selector)?.decls ?? {};

// A var(--x) to its hex value from :root.
function token(value) {
  const m = /^var\((--[\w-]+)\)$/.exec(value);
  assert.ok(m, `${value} is not a palette token`);
  assert.ok(m[1] in root, `${m[1]} is not in :root`);
  return root[m[1]].toLowerCase();
}

function luminance(hex) {
  const [r, g, b] = [1, 3, 5].map((i) => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a, b) {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

test("contrast is the WCAG ratio", () => {
  assert.equal(contrast("#000000", "#ffffff"), 21);
  assert.equal(contrast("#777777", "#777777"), 1);
  assert.ok(Math.abs(contrast("#767676", "#ffffff") - 4.54) < 0.01);
});

test("style.css's palette is the brand's light palette, with one light theme only", () => {
  for (const [name, value] of Object.entries(PALETTE)) {
    assert.equal(root[name]?.toLowerCase(), value, name);
  }
  assert.equal(root["color-scheme"], "light");
  assert.doesNotMatch(css, /prefers-color-scheme/);
  assert.doesNotMatch(page, /prefers-color-scheme/);
  assert.match(page, /<meta name="theme-color" content="#FFFFFF">/);
  assert.equal(page.match(/name="theme-color"/g).length, 1, "one theme-color, no media variants");
  assert.equal(token(rule("body").background), PALETTE["--bg"]);
  assert.equal(token(rule("body").color), PALETTE["--text"]);
  assert.equal(token(rule(".primary").background), PALETTE["--panel"]);
  assert.match(rule(".primary").border, /var\(--line\)$/);
});

test("every color outside :root comes from the palette tokens", () => {
  for (const { selector, decls } of RULES) {
    if (selector === ":root") continue;
    for (const [prop, value] of Object.entries(decls)) {
      assert.doesNotMatch(value, /#[0-9a-f]{3,8}\b|rgb|hsl/i, `${selector} ${prop}: ${value}`);
    }
  }
});

test("the install command is a dark code box, the buttons violet with white text, links violet", () => {
  assert.equal(token(rule("code").background), PALETTE["--code-bg"]);
  assert.equal(token(rule("code").color), PALETTE["--code-text"]);
  assert.equal(token(rule("button").background), PALETTE["--accent"]);
  assert.equal(token(rule("button").color), PALETTE["--on-accent"]);
  assert.equal(token(rule("a").color), PALETTE["--accent"]);
  assert.equal(token(rule("::selection").background), PALETTE["--highlight"]);
});

// The backgrounds a color-only rule's text can sit on: the page and the
// panel of the primary section.
const SURFACES = ["--bg", "--panel"];

test("every text color meets WCAG AA (4.5:1) on its background", () => {
  let checked = 0;
  for (const { selector, decls } of RULES) {
    if (!decls.color) continue;
    const fg = token(decls.color);
    const bgs = decls.background ? [token(decls.background)] : SURFACES.map((s) => root[s].toLowerCase());
    for (const bg of bgs) {
      const ratio = contrast(fg, bg);
      assert.ok(ratio >= 4.5, `${selector}: ${fg} on ${bg} is ${ratio.toFixed(2)}:1`);
      checked++;
    }
  }
  assert.ok(checked >= 10, `only ${checked} pairs checked`);
  // The pairs the brand names, whether or not a rule uses them today.
  const pairs = [
    ["--text", "--bg"],
    ["--text", "--panel"],
    ["--text", "--highlight"],
    ["--muted", "--bg"],
    ["--muted", "--panel"],
    ["--quiet", "--bg"],
    ["--quiet", "--panel"],
    ["--accent", "--bg"],
    ["--accent", "--panel"],
    ["--on-accent", "--accent"],
    ["--code-text", "--code-bg"],
  ];
  for (const [fg, bg] of pairs) {
    const ratio = contrast(PALETTE[fg], PALETTE[bg]);
    assert.ok(ratio >= 4.5, `${fg} on ${bg} is ${ratio.toFixed(2)}:1`);
  }
});

// The pixel ghost: a 124-unit glyph of 19 outlined cells on a lavender body
// that overflows it by 3, the eyes left empty; and its small cut for 16 to
// 32 px. The geometry is the brand kit's, from scripts/check-pixel-ghost-logo.mjs.
test("the cells sit on a pitch of 26 with the eyes left empty", () => {
  assert.equal(CELLS.length, 19);
  const at = CELLS.map(([x, y]) => `${x},${y}`);
  assert.ok(!at.includes("26,26") && !at.includes("78,26"), "the eyes");
  for (const [x, y] of CELLS) assert.ok(x % 26 === 0 && y % 26 === 0 && x <= 104 && y <= 104);
  assert.equal(BODY_FILL, "#C9BCFF");
});

test("favicon.svg is the logo's small cut, with no outlines", () => {
  assert.deepEqual(smallProblems(favicon, "favicon.svg"), []);
  assert.match(favicon, /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg"/);
  assert.doesNotMatch(favicon, /<rect\b/);
  assert.match(page, /<link rel="icon" href="\/favicon\.svg" type="image\/svg\+xml">/);
});

test("the page shows the full pixel-ghost logo, body overflow in view", () => {
  const svgs = page.match(/<svg\b[\s\S]*?<\/svg>/g);
  assert.equal(svgs.length, 1);
  assert.deepEqual(glyphProblems(svgs[0], "index.html"), []);
  assert.ok(showsGlyph(viewBox(svgs[0])), "the viewBox shows the body's overflow");
  assert.match(svgs[0], /role="img" aria-label="Ghost"/);
  assert.equal([...svgs[0].matchAll(/<rect\b/g)].length, 38, "19 cells and their outlines");
});

test("the logo check rejects a moved cell, a wrong fill and a missing outline", () => {
  const svg = page.match(/<svg\b[\s\S]*?<\/svg>/)[0];
  assert.notDeepEqual(glyphProblems(svg.replace('<rect x="26" y="0"', '<rect x="26" y="26"'), "moved"), []);
  assert.notDeepEqual(glyphProblems(svg.replace('rx="2" fill="#EEEAFF"', 'rx="2" fill="#0E0D1A"'), "fill"), []);
  assert.notDeepEqual(glyphProblems(svg.replace('stroke-width="4"', 'stroke-width="2"'), "outline"), []);
  assert.notDeepEqual(glyphProblems(svg.replace('fill-rule="evenodd" ', ""), "eyes filled"), []);
});

test("the fonts are Instrument Sans and IBM Plex Mono, self-hosted, with their OFL notices", () => {
  const faces = RULES.filter((r) => r.selector === "@font-face").map((r) => r.decls);
  assert.deepEqual([...new Set(faces.map((f) => f["font-family"]))].toSorted(), ['"IBM Plex Mono"', '"Instrument Sans"']);
  for (const face of faces) {
    const m = /^url\("\/fonts\/([\w.-]+\.woff2)"\) format\("woff2"\)$/.exec(face.src);
    assert.ok(m, face.src);
    const file = new URL(`../fonts/${m[1]}`, import.meta.url);
    assert.ok(existsSync(file), `fonts/${m[1]} is there`);
    assert.equal(readFileSync(file).subarray(0, 4).toString("latin1"), "wOF2", `fonts/${m[1]} is woff2`);
  }
  assert.match(rule("body").font, /^16px\/1\.5 "Instrument Sans", /);
  assert.match(rule("code").font, / "IBM Plex Mono", /);

  const licence = read("../fonts/LICENSE.txt");
  assert.match(licence, /Copyright 2022 The Instrument Sans Project Authors/);
  assert.match(licence, /Copyright © 2017 IBM Corp\. with Reserved Font Name "Plex"/);
  assert.match(licence, /SIL OPEN FONT LICENSE Version 1\.1/);
});

test("the Content-Security-Policy lets the page load its own fonts and nothing else's", () => {
  const meta = page.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)">/)[1];
  assert.ok(meta.split(";").map((d) => d.trim()).includes("font-src 'self'"));
  assert.equal(config.routes[0].headers["Content-Security-Policy"], `${meta}; frame-ancestors 'none'`);
});
