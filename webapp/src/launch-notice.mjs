// The launch notice under the header: one fixed line, no network request.
// The Nasdaq ticker is set here, in this one constant, once it is known;
// while it is empty the line leaves the ticker out.
export const NASDAQ_TICKER = "";

// The notice's text, with `ticker` when one is given.
export function launchNotice(ticker = NASDAQ_TICKER) {
  const t = String(ticker ?? "").trim();
  return t
    ? `Specter is expected to begin trading on Nasdaq under the ticker ${t} on Thursday, November 19.`
    : "Specter is expected to begin trading on Nasdaq on Thursday, November 19.";
}
