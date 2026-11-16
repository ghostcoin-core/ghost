// Red Hat Display (UI, headings, amounts) and Red Hat Mono (labels, keys,
// addresses) are served from the page's own origin: the woff2 files and their licence sit in
// webapp/fonts, style.css points at them with @font-face rules, build.sh
// copies them into dist (so they are in SHA256SUMS), and the CSP keeps
// font-src 'self'. No browser is needed.

import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { test } from "node:test";

const url = (path) => new URL(path, import.meta.url);
const read = (path) => readFileSync(url(path), "utf8");
const css = read("../style.css").replace(/\/\*[\s\S]*?\*\//g, "");
const build = read("../build.sh");
const html = read("../index.html");
const config = JSON.parse(read("../vercel/config.json"));

// Each family, its files and the weight each file covers.
const FONTS = [
  ["Red Hat Display", "fonts/red-hat-display-latin-500-normal.woff2", "500"],
  ["Red Hat Display", "fonts/red-hat-display-latin-700-normal.woff2", "700"],
  ["Red Hat Display", "fonts/red-hat-display-latin-800-normal.woff2", "800"],
  ["Red Hat Display", "fonts/red-hat-display-latin-900-normal.woff2", "900"],
  ["Red Hat Mono", "fonts/red-hat-mono-latin-400-normal.woff2", "400"],
  ["Red Hat Mono", "fonts/red-hat-mono-latin-500-normal.woff2", "500"],
];

test("the font files are woff2 and each family carries its OFL licence", () => {
  for (const [, file] of FONTS) {
    const font = readFileSync(url(`../${file}`));
    assert.equal(font.subarray(0, 4).toString("latin1"), "wOF2", file);
  }
  for (const family of ["display", "mono"]) {
    const licence = read(`../fonts/LICENSE-red-hat-${family}.txt`);
    assert.match(licence, /SIL Open Font License, Version 1\.1/);
    assert.match(licence, /Copyright 2024 The Red Hat Project Authors/);
  }
  // Only these fonts and their licences ship.
  const files = readdirSync(url("../fonts/")).sort();
  assert.deepEqual(files, [...FONTS.map(([, f]) => f.slice("fonts/".length)), "LICENSE-red-hat-display.txt", "LICENSE-red-hat-mono.txt"].sort());
});

test("style.css loads both families from this origin with font-display: swap", () => {
  const faces = css.match(/@font-face\s*{[^}]*}/g) ?? [];
  assert.equal(faces.length, FONTS.length);
  for (const [i, [family, file, weight]] of FONTS.entries()) {
    const face = faces[i];
    assert.match(face, new RegExp(`font-family:\\s*"${family}"`));
    assert.match(face, new RegExp(`font-weight:\\s*${weight};`));
    assert.match(face, /font-display:\s*swap/);
    const src = face.match(/url\("([^"]+)"\)/);
    assert.ok(src, "the @font-face has a url()");
    assert.equal(src[1], file);
    assert.ok(existsSync(url(`../${src[1]}`)), file);
  }
  assert.doesNotMatch(css, /https?:\/\//, "no external font host");
  assert.doesNotMatch(css, /Instrument Sans|IBM Plex/);
  assert.match(css, /--font:\s*"Red Hat Display",\s*system-ui/);
  assert.match(css, /--mono:\s*"Red Hat Mono",\s*ui-monospace/);
});

test("amounts are in the display face; keys, words and addresses in the mono font", () => {
  for (const sel of [".balance-big", ".secret", ".word-grid li", "code,\n.address", ".key-box textarea", ".payout-box input"]) {
    const at = css.indexOf(`${sel} {`);
    assert.notEqual(at, -1, sel);
    assert.match(css.slice(at, css.indexOf("}", at)), /font-family:\s*var\(--mono\)/, sel);
  }
  const amount = css.indexOf(".amount-box input {");
  assert.match(css.slice(amount, css.indexOf("}", amount)), /font-family:\s*var\(--font\);[\s\S]*font-weight:\s*900/);
  // The card draws its words and amounts in the same self-hosted faces.
  const card = read("../src/bearer-card.mjs");
  assert.match(card, /font-family="Red Hat Mono"/);
  assert.match(card, /font-family="Red Hat Display"/);
});

test("build.sh copies the fonts folder into dist before SHA256SUMS", () => {
  const copy = build.indexOf('cp -R "$here/fonts" "$dist/fonts"');
  assert.ok(copy > 0);
  assert.ok(copy < build.indexOf("> SHA256SUMS"));
});

test("the CSP keeps font-src 'self'", () => {
  assert.match(html, /font-src 'self';/);
  assert.match(config.routes[0].headers["Content-Security-Policy"], /font-src 'self';/);
});
