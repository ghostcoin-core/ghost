// Instrument Sans (UI) and IBM Plex Mono (amounts, keys, addresses) are
// served from the page's own origin: the woff2 files and their licence sit in
// webapp/fonts, style.css points at them with @font-face rules, build.sh
// copies them into dist (so they are in SHA256SUMS), and the CSP keeps
// font-src 'self'. No browser is needed.

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";

const url = (path) => new URL(path, import.meta.url);
const read = (path) => readFileSync(url(path), "utf8");
const css = read("../style.css").replace(/\/\*[\s\S]*?\*\//g, "");
const build = read("../build.sh");
const html = read("../index.html");
const config = JSON.parse(read("../vercel/config.json"));

// Each family, its files and the weights each file covers.
const FONTS = [
  ["Instrument Sans", "fonts/instrument-sans-latin-wght-normal.woff2", "400 700"],
  ["IBM Plex Mono", "fonts/ibm-plex-mono-latin-400-normal.woff2", "400"],
  ["IBM Plex Mono", "fonts/ibm-plex-mono-latin-600-normal.woff2", "600"],
];

test("the font files are woff2 and the licence carries both OFL notices", () => {
  for (const [, file] of FONTS) {
    const font = readFileSync(url(`../${file}`));
    assert.equal(font.subarray(0, 4).toString("latin1"), "wOF2", file);
  }
  const licence = read("../fonts/LICENSE.txt");
  assert.match(licence, /SIL OPEN FONT LICENSE Version 1\.1/);
  assert.match(licence, /Copyright 2022 The Instrument Sans Project Authors/);
  assert.match(licence, /Copyright 2017 IBM Corp\./);
  assert.doesNotMatch(licence, /Inter Project/);
  assert.ok(!existsSync(url("../fonts/InterVariable-latin.woff2")), "Inter is gone");
});

test("style.css loads both families from this origin with font-display: swap", () => {
  const faces = css.match(/@font-face\s*{[^}]*}/g) ?? [];
  assert.equal(faces.length, FONTS.length);
  for (const [i, [family, file, weight]] of FONTS.entries()) {
    const face = faces[i];
    assert.match(face, new RegExp(`font-family:\\s*"${family}"`));
    assert.match(face, new RegExp(`font-weight:\\s*${weight};`));
    assert.match(face, /font-display:\s*swap/);
    assert.match(face, /unicode-range:\s*U\+0000-00FF/, "the latin subset");
    const src = face.match(/url\("([^"]+)"\)/);
    assert.ok(src, "the @font-face has a url()");
    assert.equal(src[1], file);
    assert.ok(existsSync(url(`../${src[1]}`)), file);
  }
  assert.doesNotMatch(css, /https?:\/\//, "no external font host");
  assert.doesNotMatch(css, /"Inter"/);
  assert.match(css, /--font:\s*"Instrument Sans",\s*system-ui/);
  assert.match(css, /--mono:\s*"IBM Plex Mono",\s*ui-monospace/);
});

test("amounts, keys and addresses use the mono font", () => {
  for (const sel of [".amount-box input", ".balance-big", ".secret", ".word-grid li", "code,\n.address"]) {
    const at = css.indexOf(`${sel} {`);
    assert.notEqual(at, -1, sel);
    assert.match(css.slice(at, css.indexOf("}", at)), /font-family:\s*var\(--mono\)/, sel);
  }
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
