# Ghost pop-up wallet

A small static wallet site, served from its own origin, that the web app
opens as a pop-up for **Connect wallet**. It holds the Ghost account's
quantum-safe key (ML-DSA-44); the web app never sees a seed, the words or
the key. It is a reference wallet: anyone can build another against the
same two requests.

**Experimental and unaudited.** Do not use it for anything of value.

## What it does

- **Two requests, over `postMessage`.** `ghost_getAccount` answers the
  address and public key of account 0; `ghost_signTransaction` takes the
  fields of an account transaction (type 0x52) as 0x hex and answers the
  signed envelope, its hash and sender. Turned down or closed, the answer is
  code 4001 and nothing is signed.
- **Origin checks both ways.** The wallet reads a message only from its
  opener on one of the web app origins in `src/config.mjs` (the hosted web
  app, `https://ghost-webapp-alpha.vercel.app`), and answers that origin
  only; the web app (`webapp/src/popup-wallet.mjs`) reads a reply only from
  the wallet's origin (`https://ghost-wallet-nine.vercel.app`) and the
  window it opened. Anything else is ignored.
- **Strict refusal, before any screen.** An unknown method, a chain id not
  in `CHAIN_IDS` (the test network, 7777001), a missing, extra or malformed
  field, a `to` that is not 20 bytes (no contract creation), or a priority
  fee above the fee cap is refused with an error naming the field.
- **The key is never stored in the clear.** Create takes 32 bytes from
  `crypto.getRandomValues` and makes them the wallet's 24 words with the
  module's `ghost_wallet_new`. The words are encrypted with AES-256-GCM
  under a key from a passkey's PRF output (HKDF-SHA-256) or a password
  (PBKDF2-SHA-256, 600,000 iterations, random 16-byte salt), and only the
  ciphertext, salt, IV and parameters are stored, in IndexedDB on the
  wallet's origin. The vault is written once and never replaced. For each
  request the words are decrypted into a byte array that is overwritten
  with zeros once used, and handed to the module as bytes. The passkey's own
  signature is never used, only its PRF output.
- **Mandatory backup.** On create the 24 words are shown once, and three
  of them chosen at random must be typed back before anything is stored.
  Restore from the 24 words is in the wallet, never in the web app.
- **Approval in the pop-up.** Every request shows who asks; a signature
  shows the amount, the maximum fee (gas limit × max fee per gas), the full
  destination address and the chain id. Each needs Approve and the unlock.
- **Locked-down page.** Every script is a local file with an SRI hash; the
  CSP is `default-src 'none'`, `script-src 'self' 'wasm-unsafe-eval'`,
  `connect-src 'none'`, and `frame-ancestors 'none'` in the served headers.
  The wallet makes no network request: the module is carried in a
  JavaScript file, and the web app sends what the wallet signs. It sets no
  opener policy, which would cut it off from the page that opened it.

To start again (another wallet), clear the wallet origin's site data in the
browser; keep the 24 words first.

## Files

| File | What it does |
| --- | --- |
| `index.html` | The page: its CSP and referrer policy, the module preloads, the one script tag, and the screens (start, words, backup check, restore, protect, approve). |
| `style.css` | The page's few styles. |
| `headers.json` | The headers the host serves for every file: the page's CSP plus `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`. |
| `src/config.mjs` | The two settings: the web app origins and the chain ids. |
| `src/wallet.mjs` | The wallet's logic: the request checks, the vault (AES-GCM, PBKDF2, HKDF, passkey PRF, IndexedDB), the backup check, the approval and the signing. No DOM. |
| `src/main.mjs` | The page's script: loads the module and gives `wallet.mjs` its screens and the browser's objects. |
| `build.mjs` | Writes the release (below). |
| `test/wallet.test.mjs` | The logic on the built module with stand-ins for IndexedDB, the screens, passkeys and the opener. |
| `test/build.test.mjs` | Two builds compared, RELEASE.json, the CSP, the SRI hashes and the absence of network code. |
| `test/fakes.mjs` | The tests' stand-ins. |

From the web app the release also carries `webapp/src/wasm.mjs` (the
module's plain exports) and `webapp/src/bytes.mjs` (hex and byte helpers),
unchanged.

## Build and check a release

Build the module, then the release:

```sh
cargo build --release --locked --target wasm32-unknown-unknown --manifest-path webapp/wasm/Cargo.toml
node wallet/build.mjs            # or: node wallet/build.mjs <folder>
```

`wallet/dist` then holds `index.html` at its root, the files under their
repository paths (so no import is rewritten), `wallet/src/ghost-wasm.mjs`
(the module in base64; `GHOST_WEBAPP_WASM` names another module file), and
`RELEASE.json`, the SHA-256 of every file. `index.html` carries the sha384
SRI hash of every script, preload and stylesheet. Nothing depends on the
time or the machine, so the same commit gives the same bytes: compare a
deployed wallet's files with `RELEASE.json` from your own build.

## Test it

```sh
node --test wallet/test/wallet.test.mjs wallet/test/build.test.mjs webapp/test/popup-wallet.test.mjs
```
