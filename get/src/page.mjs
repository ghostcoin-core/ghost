// The Run a node page: finds the visitor's system from the user agent,
// shows that system's one line with the one copy button, and lists the
// other systems' lines below it. The build writes which scripts the signed
// release carries into <html data-ready>; a system whose script is not
// published shows as coming soon, with no line to copy.

export const SITE = "https://get.ghostcoin.com";

// The one line per script, as the site serves it (vercel/config.json).
export const LINES = {
  sh: `curl -fsSL ${SITE} | sh`,
  win: `irm ${SITE}/win | iex`,
  cmd: `curl -fsSL ${SITE}/cmd -o ghost-install.cmd && ghost-install.cmd && del ghost-install.cmd`,
};

export const SYSTEMS = [
  { id: "macos", label: "macOS", script: "sh" },
  { id: "linux", label: "Linux", script: "sh" },
  { id: "windows", label: "Windows (PowerShell)", script: "win" },
  { id: "windows-cmd", label: "Windows (CMD)", script: "cmd" },
];

// Windows, macOS, otherwise Linux. iPhones and iPads say "like Mac OS X"
// but do not run the node, so only a Macintosh counts as macOS.
export function detectSystem(userAgent) {
  const ua = String(userAgent ?? "");
  if (/Windows/i.test(ua)) return "windows";
  if (/Macintosh/i.test(ua)) return "macos";
  return "linux";
}

// The scripts named in data-ready ("sh win cmd"); unknown words are dropped.
export function parseReady(text) {
  return new Set(
    String(text ?? "")
      .split(/\s+/)
      .filter((word) => Object.hasOwn(LINES, word)),
  );
}

// What the page shows: the visitor's system first, then the others. A
// system's line is null when its script is not published.
export function plan(system, ready) {
  const entry = (s) => ({
    id: s.id,
    label: s.label,
    line: ready.has(s.script) ? LINES[s.script] : null,
  });
  const primary = SYSTEMS.find((s) => s.id === system) ?? SYSTEMS.find((s) => s.id === "linux");
  return {
    primary: entry(primary),
    others: SYSTEMS.filter((s) => s !== primary).map(entry),
  };
}

function otherItem(doc, other) {
  const item = doc.createElement("li");
  const label = doc.createElement("span");
  label.className = "label";
  label.textContent = other.label;
  item.append(label);
  if (other.line) {
    const code = doc.createElement("code");
    code.textContent = other.line;
    item.append(code);
  } else {
    const soon = doc.createElement("span");
    soon.className = "soon";
    soon.textContent = "Coming soon";
    item.append(soon);
  }
  return item;
}

// Fills the page in from a plan. Only the visitor's line has a copy button.
export function render(doc, view, clipboard) {
  const { primary, others } = view;
  doc.getElementById("primary-label").textContent = primary.label;
  const command = doc.getElementById("primary-command");
  const copy = doc.getElementById("copy");
  const soon = doc.getElementById("primary-soon");
  if (primary.line) {
    doc.getElementById("primary-line").textContent = primary.line;
    command.hidden = false;
    soon.hidden = true;
    copy.hidden = false;
    copy.addEventListener("click", async () => {
      try {
        await clipboard.writeText(primary.line);
        copy.textContent = "Copied";
      } catch {
        copy.textContent = "Select the line to copy";
      }
    });
  } else {
    copy.remove();
    command.hidden = true;
    soon.hidden = false;
  }
  doc.getElementById("others").replaceChildren(...others.map((o) => otherItem(doc, o)));
}

if (typeof document !== "undefined" && typeof navigator !== "undefined") {
  const view = plan(detectSystem(navigator.userAgent), parseReady(document.documentElement.dataset.ready));
  render(document, view, navigator.clipboard);
}
