// The light brand look: style.css's palette tokens, WCAG AA contrast for
// every text color on the background it sits on, the nine-square logo (in
// the page and as the favicon) drawn to its exact geometry, the
// self-hosted fonts, and one light theme. Files are read as text.

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";

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

// The nine-square block: a 100-unit box, squares of side 26 at 0, 37 and
// 74 (a gap of 11), the center cell holding the ghost.
const GHOST = "M37 50a13 13 0 0 1 26 0v13l-6.5-5.2-6.5 5.2-6.5-5.2-6.5 5.2z";
const SQUARES = [0, 37, 74]
  .flatMap((y) => [0, 37, 74].map((x) => `${x},${y}`))
  .filter((p) => p !== "37,37")
  .toSorted();

const attrs = (tag) => Object.fromEntries([...tag.matchAll(/([\w:-]+)="([^"]*)"/g)].map((m) => [m[1], m[2]]));

function assertLogo(svg, where) {
  const open = attrs(svg.match(/<svg\b[^>]*>/)[0]);
  assert.equal(open.viewBox, "0 0 100 100", where);
  assert.doesNotMatch(svg, /stroke/i, `${where}: no strokes`);
  assert.doesNotMatch(svg, /<(?:circle|ellipse|line|polyline|polygon|image|text|use|style)\b/, where);

  const rects = [...svg.matchAll(/<rect\b[^>]*>/g)].map((m) => attrs(m[0]));
  assert.equal(rects.length, 8, `${where}: eight squares`);
  for (const r of rects) {
    assert.equal(r.width, "26", where);
    assert.equal(r.height, "26", where);
    assert.ok(!("rx" in r) && !("ry" in r) && !("transform" in r), where);
  }
  assert.deepEqual(rects.map((r) => `${r.x},${r.y}`).toSorted(), SQUARES, where);
  // The squares are ink, by their own fill or their group's.
  const group = svg.match(/<g\b[^>]*>([\s\S]*?)<\/g>/);
  assert.ok(group, `${where}: the squares are grouped`);
  assert.equal(attrs(group[0].match(/<g\b[^>]*>/)[0]).fill, "#0E0D1A", where);
  assert.equal([...group[1].matchAll(/<rect\b/g)].length, 8, where);

  const paths = [...svg.matchAll(/<path\b[^>]*>/g)].map((m) => attrs(m[0]));
  assert.equal(paths.length, 1, `${where}: one ghost`);
  assert.equal(paths[0].d, GHOST, where);
  assert.equal(paths[0].fill, "#6B4CFF", where);
  assert.ok(!("transform" in paths[0]), where);
}

test("the squares of the block are side 26 at 0, 37 and 74, with the center cell left for the ghost", () => {
  assert.equal(SQUARES.length, 8);
  assert.ok(!SQUARES.includes("37,37"));
  assert.equal(37 - 26, 11);
  assert.equal(74 + 26, 100);
});

test("favicon.svg is the nine-square logo", () => {
  assertLogo(favicon, "favicon.svg");
  assert.match(favicon, /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg"/);
  assert.match(page, /<link rel="icon" href="\/favicon\.svg" type="image\/svg\+xml">/);
});

test("the page shows the nine-square logo", () => {
  const svgs = page.match(/<svg\b[\s\S]*?<\/svg>/g);
  assert.equal(svgs.length, 1);
  assertLogo(svgs[0], "index.html");
  assert.match(svgs[0], /role="img" aria-label="Ghost"/);
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
