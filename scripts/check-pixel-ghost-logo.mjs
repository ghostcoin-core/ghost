// Checks the pixel-ghost logo across the repo, with plain node and no
// dependencies:
//
//   - design/brand-kit-v1/svg/ghost-logo-primary.svg is the 124-unit glyph:
//     the lavender body (evenodd, the eyes left as holes) behind 19 cells of
//     20 x 20 (rx 2) on a pitch of 26, in order, each with its fill and an
//     ink outline inside it (x+2 y+2, 16 x 16, stroke 4, no fill);
//   - the small cut (svg/ghost-logo-small.svg) and the X profile image
//     (social/ghost-x-profile.svg and .png) are there;
//   - the favicons come from the small cut: the SVGs carry its path and no
//     outline, and favicon-16.png and favicon-32.png are its pixels exactly,
//     so they are not the outlined master scaled down; favicon.ico holds
//     16, 32 and 48;
//   - every PNG of the kit is the width (and height) its name gives;
//   - no git-tracked text file still carries the old logo's signatures.
//
// Usage: node scripts/check-pixel-ghost-logo.mjs   (exit 1 on any problem)

import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { inflateSync } from "node:zlib";

const self = fileURLToPath(import.meta.url);
const root = join(dirname(self), "..");
const KIT = "design/brand-kit-v1";

export const INK = "#0E0D1A";
export const BODY_FILL = "#C9BCFF";
export const BODY = "M23 -3H101V23H127V127H101V101H75V127H49V101H23V127H-3V23H23Z M23 23H49V49H23Z M75 23H101V49H75Z";
// The cells, top row to bottom, left to right: x, y and fill.
export const CELLS = [
  [26, 0, "#EEEAFF"],
  [52, 0, "#6B4CFF"],
  [78, 0, "#FFFFFF"],
  [0, 26, "#6B4CFF"],
  [52, 26, "#FFFFFF"],
  [104, 26, "#EEEAFF"],
  [0, 52, "#FFFFFF"],
  [26, 52, "#6B4CFF"],
  [52, 52, "#EEEAFF"],
  [78, 52, "#6B4CFF"],
  [104, 52, "#FFFFFF"],
  [0, 78, "#EEEAFF"],
  [26, 78, "#FFFFFF"],
  [52, 78, "#6B4CFF"],
  [78, 78, "#EEEAFF"],
  [104, 78, "#FFFFFF"],
  [0, 104, "#6B4CFF"],
  [52, 104, "#EEEAFF"],
  [104, 104, "#FFFFFF"],
];

// The small cut for 16 to 32 px: the body on a 16-unit pixel grid (columns
// and rows of 3, 3, 4, 3, 3), one violet, the eyes as holes, no outlines.
export const SMALL = "M3 0H13V3H16V16H13V13H10V16H6V13H3V16H0V3H3Z M3 3H6V6H3Z M10 3H13V6H10Z";
export const SMALL_FILL = "#6B4CFF";
const SMALL_EDGES = [0, 3, 6, 10, 13, 16];
const SMALL_ROWS = ["01110", "10101", "11111", "11111", "10101"];

// The old logo's signatures, built from parts so this file does not hold them.
const OLD = [
  new RegExp(["ni", "ne"].join("") + "[\\s-]*" + ["squ", "are"].join(""), "i"),
  new RegExp("M\\s*37[\\s,]+50(?:\\.\\d+)?\\s*" + "a\\s*13"),
];

export const attrs = (tag) => Object.fromEntries([...tag.matchAll(/([\w:-]+)="([^"]*)"/g)].map((m) => [m[1], m[2]]));
const same = (a, b) => String(a ?? "").toUpperCase() === String(b).toUpperCase();

// The problems with `svg` (a document or the inside of a symbol) as the
// glyph: the body path first, then the 19 cells, each followed by its
// outline. Other shapes are not allowed among them.
export function glyphProblems(svg, where) {
  const out = [];
  const shapes = [...svg.matchAll(/<(rect|path|circle|ellipse|polygon|polyline|line|use|image|text)\b[^>]*>/g)]
    .map((m) => ({ tag: m[1], a: attrs(m[0]) }))
    .filter((s) => !(s.tag === "rect" && s.a.width !== "20" && s.a.width !== "16") && s.tag !== "circle");
  const [body, ...rest] = shapes;
  if (!body || body.tag !== "path") return [`${where}: the body path is not drawn first`];
  if (body.a.d !== BODY) out.push(`${where}: the body path is ${JSON.stringify(body.a.d)}`);
  if (body.a["fill-rule"] !== "evenodd") out.push(`${where}: the body is not fill-rule evenodd`);
  if (rest.length !== CELLS.length * 2) out.push(`${where}: ${rest.length} shapes after the body, not ${CELLS.length} cells and their outlines`);
  const cells = rest.filter((s) => s.tag === "rect" && s.a.width === "20");
  if (cells.length !== CELLS.length) out.push(`${where}: ${cells.length} cell rects, not ${CELLS.length}`);
  CELLS.forEach(([x, y, fill], i) => {
    const cell = rest[2 * i];
    const line = rest[2 * i + 1];
    const at = `${where}: cell ${i + 1} (${x},${y})`;
    if (!cell || cell.tag !== "rect") return out.push(`${at} is missing`);
    const c = cell.a;
    if (c.x !== String(x) || c.y !== String(y)) out.push(`${at} is at ${c.x},${c.y}`);
    if (c.width !== "20" || c.height !== "20" || c.rx !== "2") out.push(`${at} is not 20 x 20 with rx 2`);
    if (!same(c.fill, fill)) out.push(`${at} is filled ${c.fill}, not ${fill}`);
    if ("stroke" in c || "transform" in c) out.push(`${at} has a stroke or a transform`);
    if (!line || line.tag !== "rect") return out.push(`${at} has no outline`);
    const l = line.a;
    if (l.x !== String(x + 2) || l.y !== String(y + 2) || l.width !== "16" || l.height !== "16")
      out.push(`${at}: the outline is not x+2 y+2, 16 x 16`);
    if (l.fill !== "none" || !same(l.stroke, INK) || l["stroke-width"] !== "4" || "transform" in l)
      out.push(`${at}: the outline is not an ink stroke of 4 with no fill`);
  });
  if (!same(body.a.fill, BODY_FILL)) out.push(`${where}: the body is ${body.a.fill}, not ${BODY_FILL}`);
  return out;
}

// The viewBox of the first <svg> or <symbol> as numbers.
export function viewBox(svg) {
  const m = /<(?:svg|symbol)\b[^>]*\bviewBox="([^"]+)"/.exec(svg);
  return m ? m[1].trim().split(/[\s,]+/).map(Number) : null;
}

// A viewBox that shows the whole glyph, the body's 3-unit overflow included.
export const showsGlyph = (box) => !!box && box[0] <= -3 && box[1] <= -3 && box[0] + box[2] >= 127 && box[1] + box[3] >= 127;

// The problems with `svg` as the small cut: its one path, no outline.
export function smallProblems(svg, where) {
  const out = [];
  const paths = [...svg.matchAll(/<path\b[^>]*>/g)].map((m) => attrs(m[0]));
  if (paths.length !== 1 || paths[0].d !== SMALL) out.push(`${where}: not the small cut's one path`);
  else {
    if (paths[0]["fill-rule"] !== "evenodd") out.push(`${where}: the small cut is not fill-rule evenodd`);
    if (!same(paths[0].fill, SMALL_FILL)) out.push(`${where}: the small cut is not ${SMALL_FILL}`);
  }
  if (/stroke|<rect\b/.test(svg)) out.push(`${where}: has outlines or cells; the small cut has neither`);
  if (viewBox(svg)?.join(" ") !== "0 0 16 16") out.push(`${where}: viewBox is not 0 0 16 16`);
  return out;
}

// Width and height from a PNG's IHDR.
export function pngSize(buf) {
  if (buf.length < 24 || buf.toString("latin1", 1, 4) !== "PNG" || buf.toString("latin1", 12, 16) !== "IHDR") return null;
  return [buf.readUInt32BE(16), buf.readUInt32BE(20)];
}

// The RGBA pixels of an 8-bit RGBA, non-interlaced PNG.
export function pngPixels(buf) {
  const [w, h] = pngSize(buf);
  if (buf[24] !== 8 || buf[25] !== 6 || buf[28] !== 0) throw new Error("not an 8-bit RGBA PNG");
  const chunks = [];
  for (let at = 8; at < buf.length; ) {
    const len = buf.readUInt32BE(at);
    if (buf.toString("latin1", at + 4, at + 8) === "IDAT") chunks.push(buf.subarray(at + 8, at + 8 + len));
    at += len + 12;
  }
  const raw = inflateSync(Buffer.concat(chunks));
  const stride = w * 4;
  const px = Buffer.alloc(stride * h);
  for (let y = 0; y < h; y++) {
    const filter = raw[y * (stride + 1)];
    for (let x = 0; x < stride; x++) {
      const v = raw[y * (stride + 1) + 1 + x];
      const a = x >= 4 ? px[y * stride + x - 4] : 0;
      const b = y > 0 ? px[(y - 1) * stride + x] : 0;
      const c = x >= 4 && y > 0 ? px[(y - 1) * stride + x - 4] : 0;
      const p = a + b - c;
      const pr = [Math.abs(p - a), Math.abs(p - b), Math.abs(p - c)];
      const paeth = pr[0] <= pr[1] && pr[0] <= pr[2] ? a : pr[1] <= pr[2] ? b : c;
      const add = [0, a, b, (a + b) >> 1, paeth][filter];
      if (add === undefined) throw new Error(`PNG filter ${filter}`);
      px[y * stride + x] = (v + add) & 0xff;
    }
  }
  return { w, h, px };
}

// Is the small cut's pixel grid filled at (u, v), in its 16 units?
const smallFilled = (u, v) => {
  const col = SMALL_EDGES.findIndex((e, i) => u >= e && u < SMALL_EDGES[i + 1]);
  const row = SMALL_EDGES.findIndex((e, i) => v >= e && v < SMALL_EDGES[i + 1]);
  return SMALL_ROWS[row]?.[col] === "1";
};

// The problems with a PNG as the small cut at its size: every pixel either
// solid violet or clear, as the grid says. The outlined master scaled down
// has ink, lavender and blurred edges, so it cannot pass.
export function smallPngProblems(buf, size, where) {
  const { w, h, px } = pngPixels(buf);
  if (w !== size || h !== size) return [`${where}: ${w} x ${h}, not ${size} x ${size}`];
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(SMALL_FILL.slice(i, i + 2), 16));
  const out = [];
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const at = (y * size + x) * 4;
      const filled = smallFilled(((x + 0.5) * 16) / size, ((y + 0.5) * 16) / size);
      const ok = filled
        ? px[at + 3] >= 250 && Math.abs(px[at] - r) <= 3 && Math.abs(px[at + 1] - g) <= 3 && Math.abs(px[at + 2] - b) <= 3
        : px[at + 3] <= 5;
      if (!ok) out.push(`${where}: pixel ${x},${y} is not ${filled ? "solid violet" : "clear"}`);
    }
  }
  return out.slice(0, 5);
}

// The sizes an .ico holds (0 in the directory means 256).
export function icoSizes(buf) {
  if (buf.length < 6 || buf.readUInt16LE(0) !== 0 || buf.readUInt16LE(2) !== 1) return null;
  const n = buf.readUInt16LE(4);
  return Array.from({ length: n }, (_, i) => buf[6 + 16 * i] || 256);
}

// The size a kit PNG's name gives it: -WxH, -N (square, or N wide for a
// lockup), or one of the two named ones.
export function expectedSize(file) {
  const name = file.split("/").pop();
  const named = { "apple-touch-icon.png": [180, 180], "ghost-x-profile.png": [400, 400] };
  if (named[name]) return named[name];
  let m = /-(\d+)x(\d+)\.png$/.exec(name);
  if (m) return [Number(m[1]), Number(m[2])];
  m = /-(\d+)\.png$/.exec(name);
  if (m) return name.startsWith("ghost-lockup-") ? [Number(m[1]), null] : [Number(m[1]), Number(m[1])];
  return null;
}

function walk(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)],
  );
}

export function check() {
  const problems = [];
  const read = (path) => readFileSync(join(root, path), "utf8");
  const need = (path) => {
    const ok = existsSync(join(root, path));
    if (!ok) problems.push(`${path} is missing`);
    return ok;
  };

  const primary = `${KIT}/svg/ghost-logo-primary.svg`;
  if (need(primary)) {
    const svg = read(primary);
    problems.push(...glyphProblems(svg, primary));
    if (!showsGlyph(viewBox(svg))) problems.push(`${primary}: the viewBox cuts off the body`);
  }

  const small = `${KIT}/svg/ghost-logo-small.svg`;
  if (need(small)) problems.push(...smallProblems(read(small), small));

  const x = `${KIT}/social/ghost-x-profile.svg`;
  if (need(x)) {
    const svg = read(x);
    const circle = /<circle\b[^>]*>/.exec(svg);
    if (!circle || !same(attrs(circle[0]).fill, "#FFFFFF")) problems.push(`${x}: no white circle`);
    problems.push(...glyphProblems(svg, x));
  }
  need(`${KIT}/social/ghost-x-profile.png`);

  for (const path of [`${KIT}/favicon/favicon.svg`, "get/favicon.svg", "webapp/favicon.svg"]) {
    if (need(path)) problems.push(...smallProblems(read(path), path));
  }
  for (const size of [16, 32]) {
    const path = `${KIT}/favicon/favicon-${size}.png`;
    if (!need(path)) continue;
    try {
      problems.push(...smallPngProblems(readFileSync(join(root, path)), size, path));
    } catch (e) {
      problems.push(`${path}: ${e.message}`);
    }
  }
  const ico = `${KIT}/favicon/favicon.ico`;
  if (need(ico)) {
    const sizes = icoSizes(readFileSync(join(root, ico)));
    if (!sizes || ![16, 32, 48].every((s) => sizes.includes(s))) problems.push(`${ico}: does not hold 16, 32 and 48`);
  }

  for (const file of walk(join(root, KIT)).filter((f) => f.endsWith(".png"))) {
    const path = relative(root, file);
    const want = expectedSize(path);
    const got = pngSize(readFileSync(file));
    if (!want) problems.push(`${path}: its name gives no size`);
    else if (!got) problems.push(`${path}: not a PNG`);
    else if (got[0] !== want[0] || (want[1] !== null && got[1] !== want[1]))
      problems.push(`${path}: ${got.join(" x ")}, not ${want[0]}${want[1] === null ? " wide" : ` x ${want[1]}`}`);
  }

  const tracked = execFileSync("git", ["ls-files", "-z"], { cwd: root, encoding: "utf8" }).split("\0").filter(Boolean);
  for (const path of tracked) {
    const file = join(root, path);
    if (file === self || !existsSync(file)) continue;
    const buf = readFileSync(file);
    if (buf.subarray(0, 8000).includes(0)) continue;
    const text = buf.toString("utf8");
    if (OLD.some((re) => re.test(text))) problems.push(`${path}: still carries the old logo`);
  }
  return problems;
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const problems = check();
  for (const p of problems) console.error(p);
  if (problems.length) {
    console.error(`${problems.length} problem(s) with the pixel-ghost logo`);
    process.exit(1);
  }
  console.log("the pixel-ghost logo checks out");
}
