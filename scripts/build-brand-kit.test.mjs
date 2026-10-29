// Runs scripts/build-brand-kit.sh into a temporary folder and checks what it
// renders: every PNG the kit ships, at the size its name gives, the favicons
// pixel for pixel from the small cut, and favicon.ico with 16, 32 and 48.
// Skipped where rsvg-convert or ImageMagick's convert is not installed.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { expectedSize, icoSizes, pngSize, smallPngProblems } from "./check-pixel-ghost-logo.mjs";

const script = fileURLToPath(new URL("./build-brand-kit.sh", import.meta.url));
const kit = fileURLToPath(new URL("../design/brand-kit-v1", import.meta.url));
const tools = ["/usr/bin/rsvg-convert", "/usr/bin/convert"].every((t) => existsSync(t));

const pngs = (dir) =>
  readdirSync(dir, { recursive: true })
    .map(String)
    .filter((f) => f.endsWith(".png"))
    .toSorted();

test("the build renders every PNG of the kit, the favicons from the small cut", { skip: !tools && "no rsvg-convert or convert" }, (t) => {
  const out = mkdtempSync(join(tmpdir(), "brand-kit-"));
  t.after(() => rmSync(out, { recursive: true, force: true }));
  execFileSync(script, [out], { stdio: "pipe" });

  assert.deepEqual(pngs(out), pngs(kit), "the same PNGs as the kit ships");
  for (const file of pngs(out)) {
    const [w, h] = pngSize(readFileSync(join(out, file)));
    const want = expectedSize(file);
    assert.ok(want, `${file} has a size in its name`);
    assert.equal(w, want[0], file);
    if (want[1] !== null) assert.equal(h, want[1], file);
  }
  for (const size of [16, 32, 48]) {
    const file = join(out, `favicon/favicon-${size}.png`);
    assert.deepEqual(smallPngProblems(readFileSync(file), size, relative(out, file)), []);
  }
  assert.deepEqual(icoSizes(readFileSync(join(out, "favicon/favicon.ico")))?.toSorted((a, b) => a - b), [16, 32, 48]);
});

test("the small-cut pixel check rejects the outlined logo scaled down to 16 px", { skip: !tools && "no rsvg-convert" }, () => {
  const png = execFileSync("/usr/bin/rsvg-convert", ["--width", "16", join(kit, "svg/ghost-logo-primary.svg")]);
  assert.notDeepEqual(smallPngProblems(png, 16, "primary at 16"), []);
});
