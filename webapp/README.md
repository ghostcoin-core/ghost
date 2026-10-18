# Ghost web app

A web app for using GHOST privately: connect a browser wallet, **Vanish**
GHOST into a new Phantom Key, **Summon** any amount of a key's coin to any
address, and **Claim** a received key's coin to a new key. It is plain ES
modules with no framework and no npm dependencies, on top of the client
library, which runs in a background worker as WebAssembly.

**Experimental.** Nothing here has been audited. Do not use it for anything
of value.

The design, the node methods it calls and its limits are in
[docs/webapp.md](../docs/webapp.md).

## What it never does

- It stores no key or secret: not in the browser, not in a file, not in a
  cookie, not on a server. A key exists only in the page's memory for the
  step that needs it. The key image is drawn in the page and saved only when
  you press the button.
- It downloads no proving key. The prover needs none: the statement is
  built into the WebAssembly module, which proves in a background worker.
- It talks to two things only: the node endpoint you choose (JSON-RPC) and
  the wallet your browser injects (`window.ethereum`). No request names your
  key, your commitment, its position or its marker.

## Build it yourself

You need `rustup` and `sha256sum`. The build pins Rust 1.99.1, the version
CI uses:

```sh
rustup toolchain install 1.99.1 --profile minimal --target wasm32-unknown-unknown
webapp/build.sh
```

The script fetches only the crates `webapp/wasm/Cargo.lock` pins, builds the
WebAssembly module offline with `--locked` and with every local path
remapped (`--remap-path-prefix`), copies the page into `webapp/dist`, and
writes `webapp/dist/SHA256SUMS` with one line per file.

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

## Run it

Serve `webapp/dist` over HTTP from any static file server (a module worker
does not start from a `file:` page), for example:

```sh
python3 -m http.server --directory webapp/dist 8080
```

and open `http://localhost:8080`. Under **Network**, the endpoint defaults to
the local internal network at `http://127.0.0.1:8545`; type another JSON-RPC
URL to use another node. The node must allow requests from the page's origin
(its CORS setting). The commit entry address is a setting next to it.

## Test it

```sh
cargo build --release --locked --target wasm32-unknown-unknown --manifest-path webapp/wasm/Cargo.toml
node --test --test-timeout=1200000 webapp/test/
```

`webapp/test/flow.test.mjs` drives the flow controller through Vanish (a
wrong save check that sends nothing, then a right one), a partial Summon and a
Claim, with the real prover in a `worker_threads` worker speaking the browser
worker's messages, against a scripted stand-in for the node's JSON-RPC that
verifies every proof and records every request. Set `GHOST_WEBAPP_WASM` to
test another build of the module, for example
`webapp/dist/ghost_webapp_wasm.wasm`.
