// The Run a node page: the system is found from the user agent, only that
// system's line is shown with the one copy button, and the other systems'
// lines are listed below. src/page.mjs runs against a small stand-in for
// the DOM; index.html is read as text.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { detectSystem, LINES, parseReady, plan, render, SYSTEMS } from "../src/page.mjs";

const read = (path) => readFileSync(new URL(path, import.meta.url), "utf8");
const page = read("../index.html");

const AGENTS = {
  macos: [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.6; rv:131.0) Gecko/20100101 Firefox/131.0",
  ],
  linux: [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (X11; Fedora; Linux aarch64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
    "",
  ],
  windows: [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
  ],
};

test("detectSystem finds macOS, Linux and Windows from the user agent", () => {
  for (const [system, agents] of Object.entries(AGENTS)) {
    for (const ua of agents) assert.equal(detectSystem(ua), system, ua);
  }
  assert.equal(detectSystem(undefined), "linux");
});

test("the lines are the site's one-line installs", () => {
  assert.equal(LINES.sh, "curl -fsSL https://get.ghostcoin.com | sh");
  assert.equal(LINES.win, "irm https://get.ghostcoin.com/win | iex");
  assert.match(LINES.cmd, /^curl -fsSL https:\/\/get\.ghostcoin\.com\/cmd -o (\S+\.cmd) && \1 && del \1$/);
  assert.deepEqual(
    SYSTEMS.map((s) => [s.id, LINES[s.script]]),
    [
      ["macos", LINES.sh],
      ["linux", LINES.sh],
      ["windows", LINES.win],
      ["windows-cmd", LINES.cmd],
    ],
  );
});

test("parseReady keeps only the known scripts", () => {
  assert.deepEqual([...parseReady("sh win cmd")], ["sh", "win", "cmd"]);
  assert.deepEqual([...parseReady(" sh  toString constructor ")], ["sh"]);
  assert.deepEqual([...parseReady(undefined)], []);
});

// A small stand-in for the DOM: elements with children, text, hidden,
// click listeners and lookup by id.
class FakeElement {
  constructor(doc, tag, id) {
    Object.assign(this, { doc, tagName: tag.toUpperCase(), id, children: [], parent: null, hidden: false, className: "" });
    this.ownText = "";
    this.listeners = {};
  }
  get textContent() {
    return this.ownText + this.children.map((c) => c.textContent).join("");
  }
  set textContent(text) {
    this.children = [];
    this.ownText = String(text);
  }
  append(...nodes) {
    for (const n of nodes) {
      n.parent = this;
      this.children.push(n);
    }
  }
  replaceChildren(...nodes) {
    this.children = [];
    this.append(...nodes);
  }
  remove() {
    if (this.parent) this.parent.children = this.parent.children.filter((c) => c !== this);
    this.parent = null;
  }
  addEventListener(type, fn) {
    (this.listeners[type] ??= []).push(fn);
  }
  async click() {
    await Promise.all((this.listeners.click ?? []).map((fn) => fn()));
  }
  *walk() {
    yield this;
    for (const c of this.children) yield* c.walk();
  }
}

// The page's elements, as index.html lays them out.
function fakePage() {
  const doc = {
    createElement: (tag) => new FakeElement(doc, tag),
    getElementById: (id) => [...doc.body.walk()].find((e) => e.id === id) ?? null,
  };
  const el = (tag, id, ...kids) => {
    const e = new FakeElement(doc, tag, id);
    e.append(...kids);
    return e;
  };
  const copy = el("button", "copy");
  copy.hidden = true;
  copy.textContent = "Copy";
  const soon = el("p", "primary-soon");
  soon.hidden = true;
  doc.body = el(
    "main",
    undefined,
    el("section", undefined, el("h2", "primary-label"), el("div", "primary-command", el("code", "primary-line"), copy), soon),
    el("section", undefined, el("h2", "others-label"), el("ul", "others")),
  );
  return doc;
}

const visible = (e) => {
  for (let n = e; n; n = n.parent) if (n.hidden) return false;
  return true;
};
const all = (doc, tag) => [...doc.body.walk()].filter((e) => e.tagName === tag.toUpperCase() && visible(e));

function show(ua, ready = "sh win cmd") {
  const doc = fakePage();
  const copied = [];
  render(doc, plan(detectSystem(ua), parseReady(ready)), { writeText: async (t) => copied.push(t) });
  const others = doc.getElementById("others").children.map((li) => ({
    label: li.children[0].textContent,
    line: li.children.find((c) => c.tagName === "CODE")?.textContent ?? null,
    soon: li.children.some((c) => c.className === "soon"),
  }));
  return { doc, copied, others };
}

const expected = {
  macos: { label: "macOS", line: LINES.sh, others: ["Linux", "Windows (PowerShell)", "Windows (CMD)"] },
  linux: { label: "Linux", line: LINES.sh, others: ["macOS", "Windows (PowerShell)", "Windows (CMD)"] },
  windows: { label: "Windows (PowerShell)", line: LINES.win, others: ["macOS", "Linux", "Windows (CMD)"] },
};

for (const [system, want] of Object.entries(expected)) {
  test(`a ${system} visitor sees only the ${system} line, with the one copy button, and the others below`, async () => {
    const { doc, copied, others } = show(AGENTS[system][0]);
    assert.equal(doc.getElementById("primary-label").textContent, want.label);
    assert.equal(doc.getElementById("primary-line").textContent, want.line);
    assert.ok(visible(doc.getElementById("primary-line")));
    assert.equal(doc.getElementById("primary-soon").hidden, true);

    const buttons = all(doc, "button");
    assert.equal(buttons.length, 1, "one copy button");
    assert.equal(buttons[0].id, "copy");
    await buttons[0].click();
    assert.deepEqual(copied, [want.line]);
    assert.equal(buttons[0].textContent, "Copied");

    // The visitor's own line appears once, at the top; the others are listed.
    assert.deepEqual(others.map((o) => o.label), want.others);
    for (const o of others) {
      const s = SYSTEMS.find((x) => x.label === o.label);
      assert.equal(o.line, LINES[s.script], o.label);
      assert.equal(o.soon, false);
    }
    const codes = all(doc, "code").map((c) => c.textContent);
    assert.equal(codes[0], want.line);
    assert.equal(codes.length, 4);
  });
}

test("a failed copy says to select the line instead", async () => {
  const doc = fakePage();
  render(doc, plan("linux", parseReady("sh")), {
    writeText: async () => {
      throw new Error("denied");
    },
  });
  const copy = doc.getElementById("copy");
  await copy.click();
  assert.equal(copy.textContent, "Select the line to copy");
});

test("with the Windows scripts not published, a Windows visitor sees coming soon and no copy button", () => {
  const { doc, others } = show(AGENTS.windows[0], "sh");
  assert.equal(doc.getElementById("primary-label").textContent, "Windows (PowerShell)");
  assert.equal(doc.getElementById("copy"), null, "the copy button is gone");
  assert.equal(all(doc, "button").length, 0);
  assert.equal(doc.getElementById("primary-command").hidden, true);
  assert.equal(doc.getElementById("primary-soon").hidden, false);
  assert.ok(!all(doc, "code").some((c) => c.textContent === LINES.win || c.textContent === LINES.cmd));
  assert.deepEqual(others, [
    { label: "macOS", line: LINES.sh, soon: false },
    { label: "Linux", line: LINES.sh, soon: false },
    { label: "Windows (CMD)", line: null, soon: true },
  ]);
});

test("with the Windows scripts not published, a Mac visitor sees both Windows entries as coming soon", () => {
  const { doc, others } = show(AGENTS.macos[0], "sh");
  assert.equal(all(doc, "button").length, 1);
  assert.equal(doc.getElementById("primary-line").textContent, LINES.sh);
  assert.deepEqual(others, [
    { label: "Linux", line: LINES.sh, soon: false },
    { label: "Windows (PowerShell)", line: null, soon: true },
    { label: "Windows (CMD)", line: null, soon: true },
  ]);
});

test("index.html has the page's elements, one module script and no inline script or style", () => {
  for (const id of ["primary-label", "primary-command", "primary-line", "copy", "primary-soon", "others"]) {
    assert.match(page, new RegExp(`id="${id}"`), id);
  }
  const scripts = [...page.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)];
  assert.equal(scripts.length, 1);
  assert.match(scripts[0][1], /^ type="module" src="\/src\/page\.mjs"$/);
  assert.equal(scripts[0][2], "");
  assert.doesNotMatch(page, /\son\w+=/i, "no inline event handler");
  assert.doesNotMatch(page, /\sstyle=/i, "no inline style");
  assert.doesNotMatch(page, /<style/i);
  assert.doesNotMatch(page, /javascript:/i);
  assert.equal(page.match(/<button/g).length, 1, "one button");
  assert.match(page, /<html lang="en" data-ready="sh">/);
});

test("the page loads nothing from another origin", () => {
  const refs = [...page.matchAll(/\s(?:src|href)="([^"]+)"/g)].map((m) => m[1]);
  for (const ref of refs) {
    if (ref.startsWith("/")) continue;
    // Only plain links out to the release; nothing is loaded from them.
    assert.equal(ref, "https://github.com/ghostcoin-core/ghost-node/releases/latest");
  }
  const sources = read("../src/page.mjs");
  for (const word of ["fetch(", "XMLHttpRequest", "cookie", "sendBeacon", "import("]) {
    assert.ok(!sources.includes(word), `page.mjs uses ${word}`);
  }
});
