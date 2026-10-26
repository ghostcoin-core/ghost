// A Ghost node on this computer: one look on page load, and the one-line
// install for the visitor's system when none answers. The look is a single
// JSON-RPC rpc_modules request with no parameters: it names no key, no
// coin and no address, sends no cookie and is not cached. A Ghost node
// registers the ghost namespace, so its answer has a ghost key; anything
// else, an error or no answer in time is no node.

// How long the look waits for an answer, in milliseconds.
export const PROBE_TIMEOUT_MS = 1500;

// The request's whole body: the JSON-RPC envelope and nothing else.
export const PROBE_BODY = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "rpc_modules", params: [] });

// The install site, linked from the Run a node block.
export const INSTALL_SITE = "https://get.ghostcoin.com";

// The one pasted line for each system, shown as fixed text.
export const INSTALL_LINES = {
  macOS: "curl -fsSL https://get.ghostcoin.com/install.sh | bash",
  Linux: "curl -fsSL https://get.ghostcoin.com/install.sh | bash",
  Windows: "irm https://get.ghostcoin.com/install.ps1 | iex",
};

// The visitor's system from the browser's user agent: "macOS", "Windows" or
// "Linux", Linux when it is neither of the others.
export function systemOf(userAgent) {
  const ua = String(userAgent || "");
  if (/Windows/i.test(ua)) return "Windows";
  if (/Macintosh|Mac OS X/i.test(ua) && !/iPhone|iPad|iPod/i.test(ua)) return "macOS";
  return "Linux";
}

// Whether a Ghost node answers at `endpoint`, asked once with `fetch`.
// Never throws: an HTTP error, a JSON-RPC error, a network or CORS failure,
// any answer without a ghost module, or no answer within PROBE_TIMEOUT_MS is
// false.
export async function probeLocalNode(fetch, endpoint) {
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: PROBE_BODY,
      credentials: "omit",
      cache: "no-store",
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    });
    if (!response || !response.ok) return false;
    const reply = await response.json();
    if (!reply || typeof reply !== "object" || reply.error != null) return false;
    const modules = reply.result;
    return Boolean(modules) && typeof modules === "object" && !Array.isArray(modules) && Object.hasOwn(modules, "ghost");
  } catch {
    return false;
  }
}
