# Recovery with every project-run service blocked

Status: first version, 2026-10-21. Experimental and unaudited.

"Ghost works if its team disappears" has to be shown, not claimed. This test
shows it for the coin lifecycle: a holder who has only a key's digits, a node
built from the published source and a wallet they built themselves restores
the key and spends it while every project-run website, endpoint, indexer and
download location is blocked, and the run fails if one of them is reachable
or used.

```sh
scripts/recovery-blackout.sh                # skipped cases are reported, not failed
scripts/recovery-blackout.sh --require-all  # the release condition: no case may be skipped
```

It needs git, Go, a C compiler, Node.js, rustup with the toolchain of
`webapp/build.sh`, `nft`, `ip`, `setpriv` and `sudo`. Sudo is used only to
make, configure and delete the test's own network namespace; the builds and
the test run as the calling user, and no rule outside the namespace is
touched.

## What the script does

1. **Build from the published source, before anything is blocked.** It
   builds ghost-node at the commit in `webapp/test/e2e/NODE_COMMIT` from its
   public repository (`GHOST_NODE_REPO` selects any mirror) as the test
   node of its `ghosttreetest14` build tag (coin trees of 14 levels and
   16,384 leaves instead of the release's 2^32; the release build refuses
   any other depth, and the tag does not compile with the release tag),
   through `webapp/scripts/build-node.sh` with `GHOST_NODE_BUILD_TAGS`,
   twice in two directories, and fails unless the two
   binaries are byte for byte the same. It builds the wallet with
   `webapp/build.sh` and checks `webapp/dist` against its `SHA256SUMS`.
   For a node of trees below 32 levels it also builds the wallet's module
   with the `test-tree-depth` feature of `webapp/wasm`, into a target
   directory of its own (`ghost-test-depth` in the work directory), and the
   test run uses that module (`GHOST_WEBAPP_WASM`); `webapp/dist` stays as
   built and checked ([web app](webapp.md), Coin trees).
2. **Block every project-run host.** It resolves the project-run hosts (the
   project's website, its code and release downloads, its container
   registry, and any in `GHOST_RECOVERY_HOSTS`), then makes a network
   namespace whose only way out is a dummy interface behind an nftables
   table that rejects every packet not on loopback. One counter counts
   packets to the project-run addresses, another every other packet out, and
   DNS inside the namespace points behind the same rule. A self-check
   connects to a project-run address and fails unless the rule refused and
   counted it; then every project-run host is tried by name and by address
   from inside, and the run fails if any answers. The counters are then
   reset.
3. **Recover inside the namespace.** `webapp/test/e2e/recovery.test.mjs`
   runs the internal network as three nodes of that build on the namespace's
   loopback, with discovery off, no bootstrap nodes and peers only on
   `127.0.0.0/8`: two miners (A and C) and an independent node (B), with no
   miner, started from the genesis file and synced from A and C over the
   peer protocol alone. An original device makes the commitments through A.
   A clean device, with an empty header chain and no wallet, is given only
   the keys' digit views and talks to B and nothing else: its requests to
   any other address are refused and fail the test, and so is any request
   of the test process that leaves loopback. Both devices are the web app's
   flow controller and the WebAssembly module the wallet build made (its
   test-depth build for a node of smaller trees), in a
   worker that speaks the browser worker's messages; every header the clean
   device counts is one its worker checked, seal and difficulty included.
4. **Verdict.** The run fails if a counter moved (a project-run host was
   used, or anything tried to leave the internal network), if any case
   failed or did not run, or, with `--require-all`, if any case was skipped.
   Each case is printed as PASS, SKIP (with its reason) or FAIL. A skip is
   never a pass.
5. **Tear down.** It stops what is left in the namespace, deletes the
   namespace and its `resolv.conf`, and removes the work directory
   (`GHOST_RECOVERY_KEEP=1` keeps it).

## Cases

| Case | What it shows | Today |
|---|---|---|
| `partial-reveal-then-claim` | Key K1 commits 1 GHOST and the original device reveals 0.25 of it. The clean device restores K1 from its digits, finds coin 0 spent and the remainder unspent, and claims the remainder to a new key; K1 then shows claimed and the new key holds the remainder | Runs |
| `reorganisation-during-recovery` | C is cut off. A mines a few blocks, one with key K4's commit, and the clean device sees K4's coin through B. C mines a longer branch without it and rejoins while the clean device is scanning another key: the scan is held at its first tree page, after it adopted A's tip, until B has switched to C's branch, and then goes on. B and the clean device follow the heavier branch: the device's tip is C's head, the block after the fork is C's, and K4's coin is gone from its view. A scan the reorganisation cut short is started again, as a holder would | Runs |
| `older-tree-state` | Key K2, committed before everything above and more than 34 blocks (the scan's header window and the settle depth) below the tip, on the branch that won the reorganisation, is restored from its digits and 0.2 GHOST of it is revealed | Runs |
| `rollover` | Keys KB and KA commit in coin tree 0, strangers' commits fill it, the next commit starts tree index 1 at position 0, and KA's remainder of a partial reveal lands in tree 1; the clean device reads both trees and restores KA's spent coin and its remainder | Runs: the script builds the `ghosttreetest14` node and sets `GHOST_RECOVERY_TREE_LEAVES` to its 16,384 leaves ([spec 05](spec/05-trees-and-headers.md), RT-1 Part B), and KA's reveal against the 14-level tree carries the test node's stub proof (below). The test still skips it when run without `GHOST_RECOVERY_TREE_LEAVES`, since the release's node holds 2^32 leaves per coin tree |
| `commitment-in-full-tree` | KB's coin, left unspent in the full tree 0, is restored by the clean device and revealed in part | The same as `rollover` (spec 05, RT-2 Part B) |

The script no longer skips any case: every case runs on every run, and
`--require-all` would fail if one were skipped.

**Running the two tree cases.** The script builds the node with the
`ghosttreetest14` tag and sets `GHOST_RECOVERY_TREE_LEAVES` to 16384 by
default (an override must match the node built): the script hands
it to the test, the devices are told it (createFlow's `treeLeaves`), and the
rollover case sends enough strangers' commits of 1 wei to fill coin tree 0.
The node refuses a send over its per-connection budget of 80 signature
verifications a second ([spec 09](spec/09-quantum-safe-accounts.md), RPC
budget), so the test sends these filler commits at most 60 at a time,
starting each batch at least 1.1 s after the last (`webapp/test/e2e/fillers.mjs`,
checked without a node by `webapp/test/filler-pacing.test.mjs`). A send the
node answers with "already known" counts as sent; any other refusal fails
the case with the index of the send and the node's message.
The node takes no commitment in the block in which a coin tree fills (the
next tree starts in a later block, [spec 05](spec/05-trees-and-headers.md)),
so after the filler the test waits until the head is past the block of the
last filler's receipt before the next commit (`waitPastBlock` in
`webapp/test/e2e/fillers.mjs`, checked without a node by
`webapp/test/next-block-wait.test.mjs`); it gives up after 120 s.
The web app reads every coin tree index from 0 up to the tip's, each full
earlier tree checked against its final root in a header and the last
against the tip's root, checks every tree's leaves, notes and salts and the
spent markers against the block receipts, restores a key's coins across
trees, and proves a coin of a full earlier tree against that tree's final
root ([web app](webapp.md), Coin trees). The trees' depth is
`GHOST_RECOVERY_TREE_DEPTH` (by default the depth whose 2^depth is the leaf
count, so 14 for spec 05's 16,384), and the devices check that depth's roots.
The page's module proves a coin only against a 32-level root, which no header
of such a node carries, and the STARK is made for 32 levels only; Part B's
node takes a reveal with a stub verifier instead (spec 05, RT-8 Part B). So
the devices run the module built with the `test-tree-depth` feature, which
reveals a coin of a 14-level tree as a real reveal is built, with
`K("ghost/test-proof/v1", binding digest)` in the first 32 bytes of the proof
field and zeros after; the test refuses to start at a depth below 32 with any
other module. Every reveal of the run, the two tree cases' included, is made
that way.

## Release condition

This test is a release condition. The base-client plan's phase 4 gate
requires clean-device recovery without project data, and spec 05's recovery
test (RT-1 to RT-12) is the full procedure; this script is the repeatable
part of it that runs today. `scripts/recovery-blackout.sh --require-all` is
the command the launch-readiness gate runs once that gate exists, and the
launch does not go ahead unless it passes on the frozen release: the node
and wallet built from the published release source, with every case run and
none skipped. The script now skips no case: it builds the test node of the
`ghosttreetest14` tag, so the rollover and commitment-in-full-tree cases
run, and their reveals carry the test node's stub proof from the wallet's
test-depth module (above), so `--require-all` can pass with every case run.
That full run needs the network namespace, Go and sudo, and is made on a
host that has them.

## What it assumes, and what no wallet can do

- **An independent network keeps running.** The test proves that nothing
  the project runs is needed: no website, endpoint, indexer or download.
  It does not and cannot prove that someone keeps a network running. It
  assumes that miners and full nodes independent of the project go on
  producing blocks and serving the coin tree, the spent markers and the
  block receipts from genesis.
- **No wallet can exit a stalled or fully censoring chain.** A coin moves
  only by a transaction in a block. If no one mines, or if every miner
  refuses the holder's reveal or claim, the digits still prove ownership,
  but no wallet, this one included, can spend the coin until a miner
  includes the transaction. There is no way out of the chain that does not
  go through its blocks.
- **The published source is still available to the holder.** The build step
  runs before the blackout and fetches the node's source and its pinned
  dependencies, and the wallet's crates, from where they are published.
  The project's code is meant to be mirrored in more than one place (the
  outline, Maintenance); `GHOST_NODE_REPO` builds from any mirror.
- **The internal network stands in for the real one.** The nodes are built
  from the published source with the test-only coin tree depth of the
  `ghosttreetest14` tag rather than the release build's, the chain is the
  internal test network with its test consensus values, and all its nodes
  run on one machine.
