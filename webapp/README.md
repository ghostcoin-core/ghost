# Ghost web app

A web app for committing and revealing GHOST with the link between the two hidden on chain (amounts, timing and network address can still give it away, and one block holding a transaction is neither final settlement nor privacy; see [privacy under attack](../docs/research/privacy-under-attack.md)): open its quantum-safe wallet, **Vanish**
GHOST into a new Phantom Key, **Summon** any amount of a key's coin to the
open wallet, and **Claim** a received key's coin to a new key. It is plain ES
modules with no framework and no npm dependencies, on top of the client
library, which runs in a background worker as WebAssembly.

A new Phantom Key is 24 words (it can also be shown as 21 groups of digits),
and every coin's commit carries its own random salt, so the key keeps about
128 bits of strength even against a quantum search. Keys issued earlier as
twelve groups of digits still open, reveal and claim; they hold a smaller,
unsalted secret and are not called quantum-safe. You type a key as its words
(any case, spaces or hyphens between them) or as its digits; a key whose
check fails is refused before anything is derived from it, and a wrong word
is named by its position, never corrected.

**Experimental.** Nothing here has been audited. Do not use it for anything
of value.

The design, the node methods it calls and its limits are in
[docs/webapp.md](../docs/webapp.md).

## What it never does

- It stores no key or secret: not in the browser, not in a file, not in a
  cookie, not on a server. A key exists only in the page's memory for the
  step that needs it, and the wallet's 24 words only while the wallet is
  open. The key image is drawn in the page and saved only when you press the
  button. Copying a key or saving its image is a convenience, never the only
  backup: a new key is sent only after you type three of its words back.
- It uses no elliptic-curve key. The wallet's account key is ML-DSA-44,
  derived from the wallet's seed, and every commit is a quantum-safe account
  transaction signed in the background worker.
- It downloads no proving key. The prover needs none: the statement is
  built into the WebAssembly module, which proves in a background worker.
- It talks to one thing only: the node endpoint you choose (JSON-RPC). No
  request names your key, your seed, your commitment, its position or its
  marker.
- It takes no confirmation on the endpoint's word. The background worker
  keeps a header chain for the page and checks every header's difficulty
  and RandomX seal from the start this build pins for the network, keeping
  the chain with the most work; a chain that fails the check shows no
  confirmations. This build pins no network yet (`webapp/src/header.mjs`),
  so it shows none on any network until one is added.

## Build it yourself

You need `rustup` and `sha256sum`. The build pins Rust 1.99.1, the version
CI uses, for the single-thread module, and the nightly
`nightly-2026-10-15` with its `rust-src` component for the threaded module
(build.sh installs that one when it is missing):

```sh
rustup toolchain install 1.99.1 --profile minimal --target wasm32-unknown-unknown
rustup toolchain install nightly-2026-10-15 --profile minimal --component rust-src --target wasm32-unknown-unknown
webapp/build.sh
```

The script fetches only the crates `webapp/wasm/Cargo.lock` pins, builds the
two WebAssembly modules offline with `--locked` and with every local path
remapped (`--remap-path-prefix`), copies the page into `webapp/dist`, and
writes `webapp/dist/SHA256SUMS` with one line per file.

- `ghost_webapp_wasm.wasm`, the single-thread module, with SIMD.
- `ghost_webapp_wasm_threads.wasm`, the threaded module: the same crate with
  its `threads` feature (the proofs crate's `parallel` prover), built with
  SIMD, threads and atomics on a shared memory, and the standard library
  rebuilt for them (`-Z build-std`). The background worker loads it when the
  page is cross-origin isolated and the device has more than one core, and
  runs up to 8 prover threads, itself and one Web Worker for each of the
  others (`src/threads.mjs`, `src/thread.mjs`); otherwise, or when it does
  not start, it loads the single-thread module. Both prove the same
  statements with the same configuration.

The hosted site makes the page cross-origin isolated with
`Cross-Origin-Opener-Policy: same-origin` and
`Cross-Origin-Embedder-Policy: require-corp` (`vercel/config.json`). A plain
static server without those headers gets the single-thread module.

## Check a build

A build is verifiable when anyone gets the same bytes from the same commit.
To check one that was published with its `SHA256SUMS`:

1. Check out the commit it names.
2. Run `webapp/build.sh` with the toolchain above.
3. Compare: `diff published/SHA256SUMS webapp/dist/SHA256SUMS`. No output
   means every file is byte for byte the same. To check the files you were
   served, run `sha256sum -c SHA256SUMS` in the folder that holds them.

The module's bytes depend on the toolchain version, the locked crates and
the build flags in `build.sh`, not on the machine's paths. A difference in
any line means the files differ from what the commit builds; do not use them.

## Check the hosted site

The hosted site is deployed from `main` by
`.github/workflows/deploy-webapp.yml`. It serves exactly the files
`build.sh` makes, nothing added, with the checksum list at `/SHA256SUMS`.
To check it, fetch the list and each file it names into an empty folder,
then check them (`SITE` is the site's address):

```sh
mkdir site && cd site
curl -fsSO "$SITE/SHA256SUMS"
awk '{print $2}' SHA256SUMS | while read -r f; do
  curl -fsS --create-dirs -o "$f" "$SITE/$f"
done
sha256sum -c SHA256SUMS
```

Every line must say `OK`. Then compare the list with your own build of the
same commit, as above: `diff SHA256SUMS ../webapp/dist/SHA256SUMS`.

## Run it

Serve `webapp/dist` over HTTP from any static file server (a module worker
does not start from a `file:` page), for example:

```sh
python3 -m http.server --directory webapp/dist 8080
```

and open `http://localhost:8080`. The page has the wallet button top right
("Open wallet", then the wallet's short address once it is open: it holds
the create and restore flows) and one card with two tabs, **Vanish** (an
amount box, the open wallet's balance and Max, and the Vanish button) and
**Summon** (a box to paste a key, then an amount box and the Summon button).
Vanish then steps through three
screens in the card: **Save your Phantom Key** (the 24 words in a numbered
grid, Copy, Download and "I saved it"), **Check your key** (three of the
words typed back; a wrong one sends nothing, and "Vanish *amount* GHOST"
sends the commit with a thin waiting bar) and **Done** ("*amount* GHOST
vanished"; Done drops the key). The key also leaves memory when you switch
to Summon or close the page. Summon opens the pasted key once it holds 24
words (or the digit form), or when you leave the box, shows what the key
holds with Max, and pays only the open wallet's address ("Open wallet"
with none open). While the reveal goes out the card shows three steps that
tick off as the app reaches them (Making your proof, Sending to the network,
Confirming), then **Done** ("*amount* GHOST summoned", what is still in the
key, or "This key is now empty."). Done, a tab switch or closing the page
drops the key. Claim has no visible control in
this layout; its code stays. The footer holds the experimental warning and
two small panels: **About**, on what the app keeps and sends, and
**Network**. Under **Network**, the endpoint defaults to
the local internal network at `http://127.0.0.1:8545`; type another JSON-RPC
URL to use another node. The node must allow requests from the page's origin
(its CORS setting). The commit entry address is a setting next to it; it
defaults to the internal network's, `0x67686f7374000000000000000000000000000005`.

## Test it

```sh
cargo build --release --locked --target wasm32-unknown-unknown --manifest-path webapp/wasm/Cargo.toml
node --test --test-timeout=1200000 webapp/test/
node --test --test-timeout=1200000 webapp/test/words-key.test.mjs webapp/test/salted-coin.test.mjs webapp/test/words-flow.test.mjs
```

The last three cover the words key (new keys, typed keys, a swapped word
refused, an old 12-group key restoring) and the salted coin (the 206-byte
commit of version 2, the salt read back beside the leaf, a salted coin
revealed and claimed, a version 1 coin still revealing).

`webapp/test/header-chain.test.mjs` checks the page's header chain: chains
with seals that are not valid or with a wrong difficulty refused with no
confirmation, and a lighter competing chain refused with the heavier one
kept. `webapp/test/flow.test.mjs` drives the flow controller through Vanish (a
wrong save check of three words that sends nothing, then a right one), a partial Summon and a
Claim, with the real prover in a `worker_threads` worker speaking the browser
worker's messages, against a scripted stand-in for the node's JSON-RPC that
verifies every proof and records every request. Set `GHOST_WEBAPP_WASM` to
test another build of the module, for example
`webapp/dist/ghost_webapp_wasm.wasm`.

`webapp/test/vanish-screens.test.mjs` needs no build: it reads the page and
`app.mjs` as text and runs the Vanish screens against a stand-in page and
flow (the wording, a wrong check word that sends nothing, the right words
that send, and Done or a tab switch that drops the key).
`webapp/test/summon-screens.test.mjs` does the same for Summon: the paste
box and its plain errors, the amount checks, the reveal paid to the open
wallet's address, the three steps, Done with the rest or an empty key, and
Done or a tab switch that drops the key.

To run the same flow against a real node, build ghost-node's `geth` at the
pinned commit and point the real-node test at it:

```sh
GHOST_NODE_GETH="$(webapp/scripts/build-node.sh)" \
  node --test --test-timeout=3600000 webapp/test/e2e/real-node.test.mjs
```

It needs `git`, Go and a C compiler for the node, and prints
`SKIP: GHOST_NODE_GETH is not set` when the variable is unset. The pinned
commit (`webapp/test/e2e/NODE_COMMIT`) takes the salted 206-byte commit and
serves each leaf's salt back.

To prove recovery with every project-run host blocked (an independent node
synced from peers only, a clean device given only digits, a reorganisation
during recovery), run `scripts/recovery-blackout.sh`; see
[docs/recovery-test.md](../docs/recovery-test.md).
