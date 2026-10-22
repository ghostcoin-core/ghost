// Inter is served from the page's own origin: the woff2 and its licence sit in
// webapp/fonts, style.css points at them with an @font-face rule, build.sh
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

test("the font file is a woff2 and the OFL licence ships with it", () => {
  const font = readFileSync(url("../fonts/InterVariable-latin.woff2"));
  assert.equal(font.subarray(0, 4).toString("latin1"), "wOF2");
  assert.match(read("../fonts/LICENSE.txt"), /SIL OPEN FONT LICENSE Version 1\.1/);
});

test("style.css loads Inter from this origin with font-display: swap", () => {
  const faces = css.match(/@font-face\s*{[^}]*}/g) ?? [];
  assert.equal(faces.length, 1);
  const face = faces[0];
  assert.match(face, /font-family:\s*"Inter"/);
  assert.match(face, /font-display:\s*swap/);
  const src = face.match(/url\("([^"]+)"\)/);
  assert.ok(src, "the @font-face has a url()");
  assert.equal(src[1], "fonts/InterVariable-latin.woff2");
  assert.ok(existsSync(url(`../${src[1]}`)));
  assert.doesNotMatch(css, /https?:\/\//, "no external font host");
  assert.match(css, /--font:\s*"Inter",\s*system-ui/);
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
