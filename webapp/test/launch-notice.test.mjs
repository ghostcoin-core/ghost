// The launch notice: its text without and with a ticker, the page's line
// as the page serves it, and the module the page loads it from. No browser
// and no module build are needed.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { NASDAQ_TICKER, launchNotice } from "../src/launch-notice.mjs";

const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
const app = readFileSync(new URL("../src/app.mjs", import.meta.url), "utf8");
const source = readFileSync(new URL("../src/launch-notice.mjs", import.meta.url), "utf8");

const PLAIN = "Specter is expected to begin trading on Nasdaq on Thursday, November 19.";

test("with no ticker the notice names no ticker", () => {
  assert.equal(launchNotice(""), PLAIN);
  assert.equal(launchNotice("  "), PLAIN);
  assert.equal(launchNotice(null), PLAIN);
});

test("with a ticker the notice names it before the date", () => {
  assert.equal(
    launchNotice("ABCD"),
    "Specter is expected to begin trading on Nasdaq under the ticker ABCD on Thursday, November 19.",
  );
  assert.equal(launchNotice(" ABCD "), launchNotice("ABCD"));
});

test("the ticker is one string constant, the default of launchNotice", () => {
  assert.equal(typeof NASDAQ_TICKER, "string");
  assert.equal(launchNotice(), launchNotice(NASDAQ_TICKER));
  assert.equal(source.match(/export const NASDAQ_TICKER = /g).length, 1);
  assert.doesNotMatch(source, /\bfetch\b|XMLHttpRequest|import\(/, "no network request");
});

test("the page serves the plain line under the header, and the app sets it from the module", () => {
  const line = /<p id="launch-notice" class="launch-notice">([^<]*)<\/p>/.exec(html);
  assert.ok(line, "index.html has the launch notice as a plain paragraph");
  assert.equal(line[1], PLAIN);
  assert.ok(html.indexOf("</header>") < line.index && line.index < html.indexOf("<main>"), "between the header and main");
  assert.doesNotMatch(line[0], /\bstyle=/);
  assert.match(app, /import \{ launchNotice \} from "\.\/launch-notice\.mjs";/);
  assert.match(app, /\$\("launch-notice"\)\.textContent = launchNotice\(\);/);
});
