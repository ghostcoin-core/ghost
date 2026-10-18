// JSON-RPC over HTTP to the chosen node endpoint. Every request goes to that
// one URL; the app talks to nothing else.

// The local internal network, the built-in default.
export const DEFAULT_ENDPOINT = "http://127.0.0.1:8545";

export class RpcError extends Error {
  constructor(message, code) {
    super(message);
    this.code = code;
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

export function createRpc(endpoint, { fetch = globalThis.fetch } = {}) {
  const url = validateEndpoint(endpoint);
  let id = 0;
  return {
    url,
    async call(method, params = []) {
      id += 1;
      const response = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
        credentials: "omit",
        cache: "no-store",
      });
      if (!response.ok) throw new RpcError(`the endpoint answered HTTP ${response.status}`, response.status);
      const body = await response.json();
      if (body.error) throw new RpcError(body.error.message || "the endpoint returned an error", body.error.code);
      return body.result;
    },
  };
}
