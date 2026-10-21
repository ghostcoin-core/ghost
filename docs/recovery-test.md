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
   public repository (`GHOST_NODE_REPO` selects any mirror) with the
   release build, twice in two directories, and fails unless the two
   binaries are byte for byte the same. It builds the wallet with
   `webapp/build.sh` and checks `webapp/dist` against its `SHA256SUMS`.
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
   runs the internal network as three release nodes on the namespace's
   loopback, with discovery off, no bootstrap nodes and peers only on
   `127.0.0.0/8`: two miners (A and C) and an independent node (B), with no
   miner, started from the genesis file and synced from A and C over the
   peer protocol alone. An original device makes the commitments through A.
   A clean device, with an empty header chain and no wallet, is given only
   the keys' digit views and talks to B and nothing else: its requests to
   any other address are refused and fail the test, and so is any request
   of the test process that leaves loopback. Both devices are the web app's
   flow controller and the WebAssembly module the wallet build made, in a
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
| `rollover` | A coin tree fills and the next commit starts tree index 1; the clean device restores across both | Skipped: ghost-node fixes the tree depth at 32 (`core/ghosttree`, `Release = Params{Depth: 32}`, and `Params.Check` refuses any other depth) with no test build of a smaller depth, so a rollover needs 2^32 commits; the web app reads only coin tree 0. It needs the test-build depth of [spec 05](spec/05-trees-and-headers.md), RT-1 Part B |
| `commitment-in-full-tree` | A commitment left unspent in a full earlier tree is restored and revealed against that tree's final root | Skipped for the same reason (spec 05, RT-2 Part B) |

The two skipped cases are part of the test on purpose: the script lists them
on every run, and `--require-all` fails until they run.

## Release condition

This test is a release condition. The base-client plan's phase 4 gate
requires clean-device recovery without project data, and spec 05's recovery
test (RT-1 to RT-12) is the full procedure; this script is the repeatable
part of it that runs today. No launch-readiness gate script exists in this
repository yet. When it is written, it runs
`scripts/recovery-blackout.sh --require-all`, and the launch does not go
ahead unless that passes on the frozen release: the node and wallet built
from the published release source, with every case run and none skipped.

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
- **The internal network stands in for the real one.** The nodes are the
  release build, but the chain is the internal test network with its test
  consensus values, and all its nodes run on one machine.
