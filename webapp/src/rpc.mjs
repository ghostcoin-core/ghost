// JSON-RPC over HTTP to the chosen node endpoint. Every request goes to one
// URL at a time; the app talks to nothing else. With no endpoint typed, that
// URL is a Ghost node on this computer when one answers (local-node.mjs),
// otherwise the first of the public test nodes that answers for the public
// test network.

// The local internal network, the built-in default.
export const DEFAULT_ENDPOINT = "http://127.0.0.1:8545";

// The public test network's nodes, in the order they are tried when no Ghost
// node on this computer answers. The Ghost Wallet app lists the same two.
// Each serves the eth, net, web3 and ghost modules and allows requests from
// the hosted page. Nothing a public node says is taken on its word: the
// header chain's seal and difficulty checks and the receipt checks apply to
// it as to any endpoint.
export const PUBLIC_ENDPOINTS = Object.freeze([
  "https://spark-2912.tail11407b.ts.net/ghost-rpc",
  "https://kipp-vm.tail11407b.ts.net/ghost-rpc",
]);

// The chain a public node must name (eth_chainId) to be used: the public
// test network, whose start this build pins (header.mjs, NETWORKS).
export const PUBLIC_CHAIN_ID = 6777972n;

// How long a public node has to answer eth_chainId, in milliseconds, before
// the next one is tried.
export const NODE_CHECK_MS = 4000;

// How long any request waits for its answer, in milliseconds. A request that
// hangs (a node gone quiet, or a browser holding it behind a permission
// prompt) fails after this instead of holding the page.
export const REQUEST_TIMEOUT_MS = 30000;

// geth's code for an error a method returned (its rpc package, errcodeDefault).
export const SERVER_ERROR = -32000;

export class RpcError extends Error {
  constructor(message, code, data) {
    super(message);
    this.name = "RpcError";
    this.code = code;
    if (data !== undefined) this.data = data;
  }
}

// A typed endpoint: an http or https URL with no credentials in it.
export function validateEndpoint(text) {
  let url;
  try {
    url = new URL(String(text).trim());
  } catch {
    throw new Error("enter the endpoint as a URL, for example the default");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("the endpoint must be an http or https URL");
  }
  if (url.username || url.password) throw new Error("the endpoint must not carry a user name or password");
  return url.href;
}

// The eth_chainId request's whole body.
export const CHAIN_ID_BODY = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] });

// Whether the node at `endpoint` names `chainId` as its chain, asked once
// with `fetch`. Never throws: an HTTP error, a JSON-RPC error, a network or
// CORS failure, another chain or no answer within `timeoutMs` is false.
export async function answersChain(fetch, endpoint, { chainId = PUBLIC_CHAIN_ID, timeoutMs = NODE_CHECK_MS } = {}) {
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: CHAIN_ID_BODY,
      credentials: "omit",
      cache: "no-store",
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!response || !response.ok) return false;
    const reply = await response.json();
    if (!reply || typeof reply !== "object" || reply.error != null) return false;
    if (typeof reply.result !== "string" || !/^0x[0-9a-f]{1,16}$/i.test(reply.result)) return false;
    return BigInt(reply.result) === BigInt(chainId);
  } catch {
    return false;
  }
}

// The first of `endpoints` that answers for `chainId`, asked one after the
// other, or null when none does.
export async function pickNode(fetch, endpoints, options = {}) {
  for (const endpoint of endpoints) {
    if (await answersChain(fetch, endpoint, options)) return endpoint;
  }
  return null;
}

// The JSON-RPC client of `endpoint`. Every request gives up after
// `timeoutMs`. `fallbacks` are the nodes to move to, in order, when the one
// in use stops answering: a request that gets no answer (a network failure,
// an HTTP error or no answer in time; a JSON-RPC error is an answer) still
// fails, and the client moves to the next fallback that answers for
// `chainId`, telling `onMove` its URL. Each fallback is tried at most once
// (one pass, no polling). A typed endpoint has none and is never replaced.
export function createRpc(
  endpoint,
  {
    fetch = globalThis.fetch,
    fallbacks = [],
    chainId = PUBLIC_CHAIN_ID,
    timeoutMs = REQUEST_TIMEOUT_MS,
    checkMs = NODE_CHECK_MS,
    onMove = () => {},
  } = {},
) {
  let url = validateEndpoint(endpoint);
  const ahead = fallbacks.map(validateEndpoint);
  let moving = null;
  let id = 0;

  // After `failed` gave no answer: the next fallback that answers, once per
  // failure of the node in use. A failure of a node already left behind, or
  // one while the move is under way, waits for that move only.
  function moveOn(failed) {
    if (!moving && failed === url && ahead.length > 0) {
      moving = (async () => {
        while (ahead.length > 0) {
          const next = ahead.shift();
          if (await answersChain(fetch, next, { chainId, timeoutMs: checkMs })) {
            url = next;
            onMove(url);
            return;
          }
        }
      })().finally(() => {
        moving = null;
      });
    }
    return moving ?? Promise.resolve();
  }

  return {
    get url() {
      return url;
    },
    async call(method, params = []) {
      id += 1;
      const at = url;
      let body;
      try {
        const response = await fetch(at, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
          credentials: "omit",
          cache: "no-store",
          signal: AbortSignal.timeout(timeoutMs),
        });
        if (!response.ok) throw new RpcError(`the endpoint answered HTTP ${response.status}`, response.status);
        body = await response.json();
      } catch (err) {
        await moveOn(at);
        throw err;
      }
      if (body.error) {
        const { message, code, data } = body.error;
        throw new RpcError(String(message ?? "") || "the endpoint returned an error", Number(code), data);
      }
      return body.result;
    },
  };
}
