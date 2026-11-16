// The bearer card above the app's tile: a black card in foil that shows what
// the current step is about. It only reads the page: which screen of the
// tile shows, the amounts app.mjs filled in and, while the Phantom Key is on
// screen, its words from the word list. It changes nothing app.mjs uses.
//
// The card is hidden from screen readers (the stage is aria-hidden), which
// read the word list itself, so the words are read once. The words are drawn
// on the card only while the list holds them: when app.mjs empties the list
// the card is redrawn without them, and on pagehide the face is emptied.
//
// Faces: the amount face (Vanish, the coin a pasted key holds, Summoning),
// the Phantom Key face with the 24 words (blank where the check asks for a
// word), and the burned back, face-down once a Vanish is done and while
// Summon has no key yet. The card tilts toward the pointer and slides its
// foil with the tilt, except on touch screens and under reduced motion,
// where it rests.

const STOPS = ["#FF7AD9", "#B58CFF", "#7FB8FF", "#8CFFE0", "#FFF3A0", "#FF9A8C", "#FF7AD9", "#B58CFF", "#7FB8FF"];
const MICRO = "PAYABLE TO THE BEARER · NO NAME · NO NUMBER · NO LEDGER · ".repeat(7);

// One foil gradient per face; sliding its ends is what makes the foil shimmer.
const defs = (id) => `<defs>
  <linearGradient id="${id}" gradientUnits="userSpaceOnUse" x1="0" y1="0" x2="1300" y2="520" class="hg">
    ${STOPS.map((c, i) => `<stop offset="${i / (STOPS.length - 1)}" stop-color="${c}"/>`).join("")}
  </linearGradient>
  <path id="${id}p" d="M52 26H804a26 26 0 0 1 26 26V488a26 26 0 0 1-26 26H52a26 26 0 0 1-26-26V52a26 26 0 0 1 26-26Z"/>
</defs>`;

const microtext = (id) =>
  `<text font-family="Red Hat Mono" font-size="10.5" letter-spacing="2.2" fill="url(#${id})"><textPath href="#${id}p">${MICRO}</textPath></text>`;

function rings(cx, cy, n, op = 1) {
  let s = "";
  for (let i = 0; i < n; i++) {
    const o = ((0.05 + 0.02 * (i % 3)) * op).toFixed(3);
    s += `<ellipse cx="${cx}" cy="${cy}" rx="${40 + i * 17}" ry="${40 + i * 17 * 0.92}" fill="none" stroke="#fff" stroke-opacity="${o}" transform="rotate(${i * 7} ${cx} ${cy})"/>`;
  }
  return s;
}

const waves = (id) =>
  `<g fill="none" stroke="url(#${id})" stroke-width="4" stroke-linecap="round"><path d="M748 82a22 22 0 0 1 0 34"/><path d="M762 70a40 40 0 0 1 0 58"/><path d="M776 58a58 58 0 0 1 0 82"/></g>`;

// The text of the slot named `name` in `svg`. Everything the page supplies
// (amounts, words) goes in as text, never as markup.
function put(svg, name, value) {
  const slot = svg.querySelector(`[data-slot="${name}"]`);
  if (slot) slot.textContent = value;
}

// Face-up, with an amount: `label` over `amount` SPECTER.
function amountFace(svg, label, amount, quiet) {
  const id = "bearer-fa";
  // A long amount gets a smaller size so it stays on the card.
  const size = Math.round(Math.min(112, (112 * 6) / Math.max(amount.length, 1)));
  svg.innerHTML = `${defs(id)}<rect width="856" height="540" fill="#131316"/>${rings(640, 250, 26)}${microtext(id)}
<circle cx="640" cy="250" r="118" fill="none" stroke="url(#${id})" stroke-width="5"/>
<circle cx="640" cy="250" r="100" fill="none" stroke="url(#${id})" stroke-width="1.5" stroke-dasharray="2 7"/>
<text x="640" y="257" text-anchor="middle" font-family="Red Hat Mono" font-size="14" letter-spacing="5" fill="#fff" fill-opacity=".55">NOTHING ON CHAIN</text>
<text x="70" y="112" font-family="Red Hat Display" font-weight="900" font-size="50" letter-spacing="-2" fill="url(#${id})">specter</text>
${waves(id)}
<text x="70" y="376" font-family="Red Hat Mono" font-size="19" letter-spacing="3.5" fill="#fff" fill-opacity=".45" data-slot="label"></text>
<text x="66" y="468" font-family="Red Hat Display" font-weight="900" font-size="${size}" letter-spacing="-4" fill="#fff" fill-opacity="${quiet ? 0.3 : 0.96}"><tspan data-slot="amount"></tspan><tspan dx="16" font-family="Red Hat Mono" font-weight="500" font-size="26" letter-spacing="3" fill="url(#${id})" fill-opacity="1">SPECTER</tspan></text>`;
  put(svg, "label", label);
  put(svg, "amount", amount);
}

// The Phantom Key printed on the card: foil numbers, white words, read down
// each of four columns of six. `blanks` are the positions (1 to 24) the
// check asks for: an empty box there, and the other words dimmed.
function wordsFace(svg, words, blanks, amount) {
  const id = "bearer-fw";
  let grid = "";
  for (let i = 0; i < 24; i++) {
    const c = Math.floor(i / 6);
    const r = i % 6;
    const x = 70 + c * 186;
    const y = 168 + r * 52;
    grid += `<text x="${x}" y="${y}" font-family="Red Hat Mono" font-weight="500" font-size="17" fill="url(#${id})">${String(i + 1).padStart(2, "0")}</text>`;
    grid += blanks.includes(i + 1)
      ? `<rect x="${x + 34}" y="${y - 25}" width="118" height="34" rx="8" fill="#fff" fill-opacity=".05" stroke="url(#${id})" stroke-width="2"/>`
      : `<text x="${x + 34}" y="${y}" font-family="Red Hat Mono" font-weight="500" font-size="27" fill="#fff" fill-opacity="${blanks.length ? 0.32 : 0.96}" data-slot="w${i}"></text>`;
  }
  const foot = blanks.length ? "TYPE THE THREE MISSING WORDS" : "BEARER · ANYONE WITH THESE 24 WORDS CAN SUMMON IT";
  svg.innerHTML = `${defs(id)}<rect width="856" height="540" fill="#131316"/>${rings(700, 120, 22, 0.55)}${microtext(id)}
<text x="70" y="96" font-family="Red Hat Display" font-weight="900" font-size="36" letter-spacing="-1.4" fill="url(#${id})">specter</text>
<text x="786" y="92" text-anchor="end" font-family="Red Hat Mono" font-size="15" letter-spacing="3" fill="#fff" fill-opacity=".55" data-slot="head"></text>
<line x1="70" y1="120" x2="786" y2="120" stroke="url(#${id})" stroke-opacity=".5" stroke-width="1"/>
${grid}
<text x="70" y="482" font-family="Red Hat Mono" font-size="13" letter-spacing="2.5" fill="#fff" fill-opacity=".42">${foot}</text>`;
  put(svg, "head", amount ? `PHANTOM KEY · ${amount} SPECTER` : "PHANTOM KEY");
  words.forEach((w, i) => put(svg, `w${i}`, w));
}

// Face-down: nothing to read, only the foil.
function backFace(svg) {
  const id = "bearer-fb";
  let lines = "";
  for (let i = 0; i < 34; i++) {
    const o = (0.07 + 0.05 * (i % 3)).toFixed(2);
    lines += `<ellipse cx="428" cy="270" rx="${30 + i * 13}" ry="${30 + i * 13 * 0.62}" fill="none" stroke="url(#${id})" stroke-opacity="${o}" transform="rotate(${i * 5.3} 428 270)"/>`;
  }
  svg.innerHTML = `${defs(id)}<rect width="856" height="540" fill="#131316"/>${lines}${microtext(id)}
<circle cx="428" cy="254" r="96" fill="#131316" stroke="url(#${id})" stroke-width="5"/>
<circle cx="428" cy="254" r="80" fill="none" stroke="url(#${id})" stroke-width="1.5" stroke-dasharray="2 7"/>
<text x="428" y="266" text-anchor="middle" font-family="Red Hat Display" font-weight="900" font-size="38" letter-spacing="-1.4" fill="#fff">specter</text>
<text x="428" y="420" text-anchor="middle" font-family="Red Hat Mono" font-size="15" letter-spacing="5" fill="#fff" fill-opacity=".6">BURNED · NOTHING ON CHAIN</text>
<text x="428" y="452" text-anchor="middle" font-family="Red Hat Mono" font-size="12" letter-spacing="3" fill="url(#${id})">ONLY THE 24 WORDS CAN MINT IT AGAIN</text>`;
}

// --- Reading the page ---

const $ = (id) => document.getElementById(id);
const shown = (id) => Boolean($(id)) && !$(id).hidden;
const text = (id) => ($(id) ? $(id).textContent.trim() : "");

// The number at the start of `raw` ("2.5 SPECTER", "2.5"), or "".
function amountOf(raw) {
  const m = /^\d[\d,]*(\.\d*)?/.exec(String(raw).trim());
  return m ? m[0].slice(0, 16) : "";
}

// The words in the list, in order, while app.mjs shows them.
function listWords() {
  const list = $("vanish-words");
  if (!list) return [];
  return [...list.children].map((item) => (item.lastElementChild || item).textContent.trim());
}

// The positions the check asks for, from its inputs.
function checkPositions() {
  const groups = $("vanish-check-groups");
  if (!groups) return [];
  return [...groups.querySelectorAll("input")].map((input) => Number(input.dataset.position)).filter(Boolean);
}

// What the card shows for the screen on the tile: the screen's name, the
// card's size (s, m or l), and the face (amount, words) or down.
function current() {
  if (shown("panel-vanish")) {
    if (shown("vanish-key")) return { screen: "key", size: "l", face: "words", blanks: [] };
    if (shown("vanish-check")) return { screen: "check", size: "l", face: "words", blanks: checkPositions() };
    const sending = amountOf(text("vanish-send-amount"));
    if (shown("vanish-waiting")) return { screen: "vanishing", size: "s", face: "amount", label: "VANISHING", amount: sending };
    if (shown("vanish-done")) return { screen: "vanished", size: "m", down: true };
    if (shown("vanish-after")) {
      const dropped = /^Commit dropped/.test(text("vanish-status"));
      return { screen: "after", size: "s", face: "amount", label: dropped ? "NOT VANISHED" : "SENT", amount: sending };
    }
    const typed = $("vanish-amount") ? amountOf($("vanish-amount").value) : "";
    return { screen: "vanish", size: "s", face: "amount", label: "TO VANISH", amount: typed || "0.00", quiet: !typed };
  }
  if (shown("summon-confirm")) {
    const typed = $("summon-amount") ? amountOf($("summon-amount").value) : "";
    return { screen: "confirm", size: "s", face: "amount", label: "TO SUMMON", amount: typed || "0.00" };
  }
  if (shown("summon-waiting")) {
    return { screen: "summoning", size: "s", face: "amount", label: "SUMMONING", amount: amountOf(text("summon-waiting-amount")) || "0.00" };
  }
  if (shown("summon-done")) {
    return { screen: "summoned", size: "s", face: "amount", label: "SUMMONED", amount: amountOf(text("summon-done-amount")) || "0.00" };
  }
  if (shown("summon-form") && shown("summon-amount-area")) {
    return { screen: "summon-coin", size: "s", face: "amount", label: "IN THIS KEY", amount: amountOf(text("summon-in-key")) || "0.00" };
  }
  return { screen: "summon", size: "s", down: true };
}

// --- The card ---

const bearer = typeof document === "undefined" ? null : $("bearer");
if (bearer) wire(bearer);

function wire(card) {
  const body = document.body;
  const front = $("bearer-front");
  backFace($("bearer-back"));

  const calm = matchMedia("(prefers-reduced-motion: reduce)");
  const touch = matchMedia("(hover: none)");

  let flip = 0; // degrees; odd multiples of 180 lie face-down
  let drawn = null; // what the front shows: the state's signature
  let shownScreen = null;
  let swapTimer = 0;
  let rest = { rx: 5, ry: -10 };
  let amp = 1;

  const down = () => (flip / 180) % 2 === 1;

  function foil(rx, ry) {
    const o = ry * 26 + rx * 14;
    card.querySelectorAll(".hg").forEach((g) => {
      g.setAttribute("x1", String(-500 + o));
      g.setAttribute("x2", String(800 + o));
    });
  }

  function pose(rx, ry, live) {
    card.classList.toggle("live", live);
    card.style.setProperty("--rx", rx.toFixed(2));
    card.style.setProperty("--ry", ry.toFixed(2));
    card.parentElement.style.setProperty("--ry", ry.toFixed(1));
    foil(rx, ry);
  }

  // Hides whichever face points away from the viewer. backface-visibility
  // does the same where the browser supports it; this covers the browsers
  // that draw the back face through the front.
  function sync() {
    const m = new DOMMatrix(getComputedStyle(card).transform);
    card.classList.toggle("turned", m.m33 < 0);
  }

  // Follows the turn frame by frame until the transition has finished.
  function follow(until) {
    sync();
    if (performance.now() < until) requestAnimationFrame(() => follow(until));
  }

  function turn() {
    flip += 180;
    card.classList.remove("live");
    card.style.setProperty("--flip", `${flip}deg`);
    follow(performance.now() + 1000);
  }

  function draw(s) {
    if (s.face === "words") wordsFace(front, listWords(), s.blanks, amountOf(text("vanish-key-amount")));
    else amountFace(front, s.label, s.amount, Boolean(s.quiet));
    foil(rest.rx, rest.ry);
  }

  function signature(s) {
    if (s.down) return "down";
    if (s.face === "words") return `words:${listWords().length}:${s.blanks.join(",")}:${text("vanish-key-amount")}`;
    return `amount:${s.label}:${s.amount}:${s.quiet ? 1 : 0}`;
  }

  function update() {
    const s = current();
    const sign = signature(s);
    body.dataset.screen = s.screen;
    body.dataset.size = s.size;
    body.dataset.wallet = shown("wallet-open") ? "on" : "off";
    if (s.screen !== shownScreen) {
      rest = s.size === "l" ? { rx: 2, ry: -3 } : { rx: 5, ry: -10 };
      amp = s.size === "l" ? 0.35 : 1;
      pose(rest.rx, rest.ry, false);
    }
    const first = shownScreen === null;
    shownScreen = s.screen;
    if (sign === drawn) return;
    clearTimeout(swapTimer);
    card.classList.remove("swap");
    const was = drawn;
    drawn = sign;

    if (s.down) {
      if (!down()) {
        if (first) still(turn);
        else turn();
      }
      return;
    }
    if (down()) {
      // The face turns up: drawn while it faces away, then turned.
      draw(s);
      if (first) still(turn);
      else turn();
      return;
    }
    // Leaving the words face, or the first paint: at once, so no word stays
    // on the card after the list is emptied.
    const leavingWords = Boolean(was && was.startsWith("words:")) && s.face !== "words";
    if (first || leavingWords || calm.matches) {
      draw(s);
      return;
    }
    // Same face, new content: a short fade.
    card.classList.add("swap");
    swapTimer = setTimeout(() => {
      draw(current());
      card.classList.remove("swap");
    }, 160);
  }

  // Runs `step` with transitions off, for the first paint of a face-down card.
  function still(step) {
    card.classList.add("still");
    step();
    requestAnimationFrame(() => requestAnimationFrame(() => card.classList.remove("still")));
  }

  // Coalesces the page's changes into one update per task.
  let queued = false;
  function soon() {
    if (queued) return;
    queued = true;
    queueMicrotask(() => {
      queued = false;
      update();
    });
  }

  const watch = new MutationObserver(soon);
  const tile = $("card");
  if (tile) watch.observe(tile, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ["hidden"] });
  const walletOpen = $("wallet-open");
  if (walletOpen) watch.observe(walletOpen, { attributes: true, attributeFilter: ["hidden"] });
  for (const id of ["vanish-amount", "summon-amount"]) {
    if ($(id)) $(id).addEventListener("input", soon);
  }
  // Max fills the amount without an input event.
  for (const id of ["vanish-max", "summon-max"]) {
    if ($(id)) $(id).addEventListener("click", () => setTimeout(soon));
  }

  // The panels (wallet, Network, About): the scrim shows behind an open one,
  // and a click on it closes it through the panel's own button.
  const panels = ["wallet-panel", "network-panel", "about-panel"].map($).filter(Boolean);
  const scrim = $("scrim");
  function panelsChanged() {
    const open = panels.find((p) => !p.hidden);
    if (scrim) scrim.hidden = !open;
    body.dataset.panel = open ? open.id : "";
  }
  const panelWatch = new MutationObserver(panelsChanged);
  for (const p of panels) panelWatch.observe(p, { attributes: true, attributeFilter: ["hidden"] });
  if (scrim) {
    scrim.addEventListener("click", () => {
      const open = panels.find((p) => !p.hidden);
      const button = open && document.querySelector(`[aria-controls="${open.id}"]`);
      if (button) button.click();
    });
  }
  panelsChanged();

  // Tilt toward the pointer, except on touch and under reduced motion.
  const main = card.closest("main") || document;
  main.addEventListener("pointermove", (e) => {
    if (calm.matches || touch.matches || e.pointerType === "touch") return;
    const r = card.getBoundingClientRect();
    const x = (e.clientX - (r.left + r.width / 2)) / innerWidth;
    const y = (e.clientY - (r.top + r.height / 2)) / innerHeight;
    card.style.setProperty("--gx", `${50 + x * 130}%`);
    card.style.setProperty("--gy", `${50 + y * 160}%`);
    pose(rest.rx - y * 24 * amp, rest.ry + x * 34 * amp, true);
  });
  main.addEventListener("pointerleave", () => pose(rest.rx, rest.ry, false));

  // The words leave the card with the page.
  window.addEventListener("pagehide", () => {
    front.replaceChildren();
    drawn = null;
  });

  update();
}
