# Ghost pop-up wallet

A small static wallet site, served from its own origin, that the web app
opens as a pop-up for **Connect wallet**. It holds the Ghost account's
quantum-safe keys (ML-DSA-44, and an SLH-DSA rescue key); the web app never
sees a seed, the words or a key. It is a reference wallet: anyone can build
another against the same four requests.

**Experimental and unaudited.** Do not use it for anything of value.

## What it does

- **Four requests, over `postMessage`.** `ghost_getAccount` answers
  `{ address, publicKey, scheme, rescueKey }` of account 0.
  `ghost_newReceiveAddress` (`{ id, method }`, no params) answers the same
  fields for the next account
  never handed out (1, then 2, and so on), so an app can be paid to an
  address that was never used. `ghost_signTransaction` takes the fields of
  an account transaction (type 0x52) as 0x hex and answers the signed
  envelope, its hash, sender and `scheme`. Its optional `from` (20 bytes of
  0x hex) picks the address that signs: left out, account 0; otherwise it
  must be account 0 or an address `ghost_newReceiveAddress` issued, or the
  answer is code -32602 naming `from`. `ghost_rescue` (below) moves an
  account's whole balance with its rescue key. Turned down or closed, the
  answer is code 4001, nothing is signed and no address is issued.
- **Rescue-key accounts by default.** Every new account is a rescue-key
  account (spec 09, section 5, scheme `0x0003`): its 1,344-byte public key
  is an ML-DSA-44 key and an SLH-DSA-SHAKE-128s key, and it signs ordinary
  transactions with ML-DSA-44 (the module's `ghost_wallet_rescue_account`
  and `ghost_wallet_sign_rescue_key`). Replies say `scheme: "0x0003"` and
  `rescueKey: true`. Which scheme an account has is stored, not guessed: the
  record `accounts` beside the vault holds `{ rescueFrom }`, and accounts
  below that index are scheme `0x0001` (`rescueKey: false`), from it up
  `0x0003`. A wallet created or restored stores `{ rescueFrom: 0 }` with its
  vault. A vault stored before rescue keys gets the issued count plus one
  as `rescueFrom` on its first request: its existing accounts keep working as
  `0x0001`, and every account it issues after is `0x0003`. Restoring the 24
  words on a new device derives `0x0003` accounts only: an old `0x0001`
  address is not derived again there, and can be spent only from the device
  that holds it.
- **The rescue action.** `ghost_rescue` takes the fields of
  `ghost_signTransaction` without `to`, `value` and `data`, plus `balance`
  (the account's balance in wei, a 0x quantity the app reads from the node;
  the wallet reads no node), and `from` optional (account 0). The
  destination is typed by the user on the wallet's approval screen, never
  taken from the request, so an app cannot redirect a rescue. The wallet
  signs a scheme `0x0004` transaction with the account's SLH-DSA key alone
  (`ghost_wallet_sign_rescue`; nothing of ML-DSA signs) that sends
  `balance - gasLimit × maxFeePerGas` to that destination with empty data,
  and answers `{ sender, txHash, envelope, scheme: "0x0004" }`. Refused
  before any screen: a `from` known to be a `0x0001` account ("this account
  has no rescue key"), a `to`, `value` or `data` in the request ("unknown
  field"), a balance that does not cover `gasLimit × maxFeePerGas` with
  something left to move. After the approval, a destination that is not 20
  bytes of 0x hex, or is the account itself, is refused and nothing is
  signed.
- **Issued addresses are counted, as public data.** Beside the vault, in
  the same IndexedDB store, the record `issued` holds `{ count }`: accounts
  1 to `count` have been handed out. It is written once the user approved
  and before the answer, so an address is never handed out twice, also after
  a reload. It holds no words or key. The addresses themselves are derived
  again from the words when needed and kept only in the window's memory; a
  `from` that is none of them is refused before any screen, or, in a window
  that has not unlocked yet, once unlocked and before anything is signed.
- **Origin checks both ways.** The wallet reads a message only from its
  opener on one of the web app origins in `src/config.mjs` (the hosted web
  app, `https://ghost-webapp-alpha.vercel.app`), and answers that origin
  only; the web app (`webapp/src/popup-wallet.mjs`) reads a reply only from
  the wallet's origin (`https://ghost-wallet-nine.vercel.app`) and the
  window it opened. Anything else is ignored.
- **Strict refusal, before any screen.** An unknown method, a chain id not
  in `CHAIN_IDS` (the test network, 7777001), a missing, extra or malformed
  field (params on `ghost_getAccount` or `ghost_newReceiveAddress`
  included), a `to` or `from` that is not 20 bytes (no contract creation),
  a `from` this wallet never issued, or a priority fee above the fee cap is
  refused with an error naming the field.
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
- **Approval in the pop-up.** Every request shows who asks; a new receive
  address says the app sees a new address and public key; a signature
  shows the address that signs, its scheme and "Rescue key: yes" or "no",
  the amount, the maximum fee (gas limit × max fee per gas), the full
  destination address and the chain id; a rescue shows the account, the
  balance, the amount moved and the maximum fee, and asks for the
  destination. Each needs Approve and the unlock.
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
| `src/wallet.mjs` | The wallet's logic: the request checks, the vault (AES-GCM, PBKDF2, HKDF, passkey PRF, IndexedDB), the issued-address count, the backup check, the approval and the signing. No DOM. |
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
