// The launch notice under the header: one fixed line, no network request.
// The Nasdaq ticker is set here, in this one constant, once it is known;
// while it is empty the line leaves the ticker out. index.html loads this
// module on its own and serves the line without a ticker until it runs.
export const NASDAQ_TICKER = "";

// The notice's text, with `ticker` when one is given.
export function launchNotice(ticker = NASDAQ_TICKER) {
  const t = String(ticker ?? "").trim();
  return t
    ? `Specter is expected to begin trading on Nasdaq under the ticker ${t} on Thursday, November 19.`
    : "Specter is expected to begin trading on Nasdaq on Thursday, November 19.";
}

// On the page: the line under the header takes the text above.
const line = typeof document === "undefined" ? null : document.getElementById("launch-notice");
if (line) line.textContent = launchNotice();
