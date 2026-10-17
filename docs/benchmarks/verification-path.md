# Verification path for the node

The node is a Go program (decision [0001](../decisions/0001-base-client.md)),
and it must verify every reveal proof itself. The proof system is the one the
[benchmark](results.md) chose and this note does not change: Plonky3 at
revision `f98331687e47`, a STARK over BabyBear with a degree-5 extension, FRI
with the hiding commitment scheme (zero-knowledge mode), Keccak-256 for the
commitments and the transcript, blowup 2^2 or 2^3, 128 conjectured bits.

Verification path: Rust over cgo. The node calls the pinned Plonky3 verifier,
the same Rust code the prover is checked against, through a small C interface
linked into the Go binary. No reviewed Go verifier for this proof system
exists, a Go rewrite would be a second consensus implementation that has to
agree with the prover bit for bit, and the node already needs cgo for RandomX,
so cgo adds a Rust toolchain to the build, not a new kind of build problem.

**No measurement in this note was taken by this work.** The sandbox it was
written in has no Rust toolchain (no `cargo` or `rustc`) and does not allow
building or running programs. The prototype and its measuring program are
committed, unbuilt and unrun, and every figure below is either quoted from an
earlier measured report, with its source, or marked "not measured" with the
exact command that takes it.

## What was looked for

| Option | Found | Judgement |
|---|---|---|
| A reviewed Go verifier for Plonky3 | None. A web search on 2026-10-17 found Plonky3 only in Rust. The nearest Go code is `gnark-plonky2-verifier`, which verifies Plonky2 proofs (Goldilocks field, Poseidon) inside a gnark circuit, and the FRI package of Consensys `loom`, which is internal to that project and verifies its own proof format. Neither reads this proof's encoding. | Not available. |
| Write a Go verifier | Not attempted. It would need, in Go and matching the Rust code exactly: postcard decoding of Plonky3's proof type, the Keccak transcript (`SerializingChallenger32`), the hiding Merkle commitments with salts, FRI folding and query checks, and the constraint evaluation of the Keccak-f circuit. | Rejected as the consensus path. Any difference from the prover's library is a chain split, and it needs its own review. It could later serve as a second implementation for cross-checks, as the pure-Go RandomX library does. |
| Rust over cgo | Prototyped here (below). | **Chosen.** One implementation, the one the prover is tested against. |
| Other: the WebAssembly build inside a pure-Go WebAssembly runtime | Not prototyped. The browser build already verifies (median about 7 ms on the Mac Studio, [results](results.md#hash-choice)). | Fallback only if cgo is ruled out. It avoids cgo but adds a WebAssembly runtime to the node as a new Go dependency, and its speed in such a runtime is unmeasured. |
| Other: a proof system with a Go verifier | Not considered. | Out of scope: the proof system and hash are fixed. |

## The prototype

Everything is under `benchmarks/` and adds no external dependency: the only
new entry in `benchmarks/Cargo.lock` is the workspace's own crate, and the Go
module imports the standard library only.

| Path | What it is |
|---|---|
| `benchmarks/prover/src/bin/ghost-bench-verify.rs` | Measures verification time and peak heap for a valid proof and for worst-case invalid proofs, and prints the table below. It can write the honest proof and public inputs as a fixture for the Go side. |
| `benchmarks/verify-ffi/` | Package `ghost-verify-ffi`: a static library with one C function, `ghost_verify`, and its header `ghost_verify.h`. |
| `benchmarks/verify-ffi/go/` | A Go program that calls `ghost_verify` through cgo, as the node would, and times each call. |

`ghost_verify(candidate, log_blowup, public_inputs, len, proof, len)` returns
a status code: accepted, rejected, malformed proof, malformed public inputs,
bad configuration, bad argument, or panicked. It never lets a Rust panic
unwind into Go. It computes the security plan of a configuration once and
keeps it, so the gate does not run on every call. Memory is allocated and
freed inside the call; only the plan cache stays, outside the Go heap.

The cases the measuring program runs, all from one honest proof:

- **valid**: the honest proof and public inputs;
- **wrong public input**: the lowest bit of the first binding digest limb
  flipped; it stays in range, so it passes the range check and reaches the
  full verifier;
- **truncated by one byte**, **truncated to half**, **empty**;
- **one byte appended**: the honest proof with a trailing zero byte;
- **altered at the end** (the last query): one bit flipped in each of the last
  64 bytes in turn, which in postcard order are the last query's openings and
  the few fields after them; the slowest rejection is measured;
- **altered anywhere**: one bit flipped at 256 offsets spread over the whole
  proof; the slowest rejection is measured.

The program exits with status 1 if the valid proof is rejected, if any other
case except the appended byte is accepted, or if the verifier panics on any
input. Memory is the peak heap allocated during the call above what was live
before it, counted by a wrapper around the system allocator on every thread.

## Measurements

| Case | Blowup | Verification median (ms) | Verification largest (ms) | Peak heap during verification (KiB) | Outcome |
|---|---|---|---|---|---|
| valid | 2^2 | 8.51, quoted | 9.23, quoted | not measured | accepted, quoted |
| valid | 2^3 | 7.56, quoted | 8.30, quoted | not measured | accepted, quoted |
| wrong public input | 2^2 and 2^3 | not measured | not measured | not measured | not measured |
| truncated by one byte | 2^2 and 2^3 | not measured | not measured | not measured | not measured |
| truncated to half | 2^2 and 2^3 | not measured | not measured | not measured | not measured |
| empty | 2^2 and 2^3 | not measured | not measured | not measured | not measured |
| one byte appended | 2^2 and 2^3 | not measured | not measured | not measured | not measured |
| altered at the end (worst case of the last 64 bytes) | 2^2 and 2^3 | not measured | not measured | not measured | not measured |
| altered anywhere (worst case of 256 offsets) | 2^2 and 2^3 | not measured | not measured | not measured | not measured |
| any case, called from Go through cgo | 2^3 | not measured | not measured | not measured | not measured |

The quoted rows are from [native verification on the chain](results.md#native-verification-on-the-chain):
`ghost-bench-native`, threads on, a Linux aarch64 virtual machine on the Mac
Studio, 10 warm runs per configuration. That run did not record memory.

The commands that fill the table, from `benchmarks/`:

```sh
# Rust verifier, threads on (as in the quoted rows), then off.
cargo build --locked --release -p ghost-bench --features parallel --bin ghost-bench-verify
target/release/ghost-bench-verify --runs 10 --tail 64 --sweep 256 --fixture /tmp/ghost-verify-fixture
cargo build --locked --release -p ghost-bench --bin ghost-bench-verify
target/release/ghost-bench-verify --runs 10 --tail 64 --sweep 256

# The C interface's own tests, then the library and the Go caller.
cargo test --locked --release -p ghost-verify-ffi
cargo build --locked --release -p ghost-verify-ffi --features parallel
cd verify-ffi/go && CGO_ENABLED=1 go run . -fixture /tmp/ghost-verify-fixture -blowup 3 -runs 10
```

The fixture holds the last configuration run, blowup 2^3; the Go program
takes `-blowup 3` to match. The Go program reports peak resident memory of the
whole process, Rust heap included, because the Go runtime cannot see memory
the Rust library allocates.

What to expect, from reading the code, not measured: rejection of a proof
altered in its last query should cost about as much as a valid proof, because
the verifier does all the earlier work first, so the worst case should be
close to the valid row. Truncated and empty proofs should be rejected while
decoding, quickly. `postcard::from_bytes` does not check that the whole input
was used, so the appended-byte proof is expected to be **accepted**; see the
blockers.

## Does cgo break reproducible, signed or cross-platform builds

Short answer: not by itself, on the evidence so far, but it has only been
shown on one platform and not yet for a Rust library.

**Evidence already measured in this repository** (the
[RandomX survey](../surveys/randomx.md#what-cgo-does-to-builds), Go 1.26.6,
gcc 13.3.0, linux/arm64, a C++ static library linked through cgo):

- The static library was byte-identical across three directories.
- The Go binary differed by directory with `-trimpath` alone, because the
  build ID hashes the absolute `${SRCDIR}` in the cgo linker flags. With
  `-trimpath -ldflags=-buildid=` the two builds were byte-identical.
- The binary was still linked dynamically to the C++ runtime; fully static
  linking was not tested.
- An empty cgo call took 16 ns, against about 8 ms per verification.

The node needs cgo for RandomX whatever is chosen here, so these costs are
already accepted. The verifier adds the following, none of it tested:

- **Reproducible.** The Rust library must be built with a pinned compiler
  (the benchmark recorded rustc 1.99.1), `--locked`, and
  `--remap-path-prefix` for the source and cargo directories, because Rust
  embeds absolute paths in panic messages and debug data. The release profile
  already sets `codegen-units = 1`. Unlike the C++ runtime, Rust's standard
  library goes into the static library itself; only system C libraries are
  linked from the host.
- **Signed.** Signing is applied to the finished binary, so cgo does not
  change it. The verifier generates no machine code at run time, so unlike
  RandomX it needs no JIT entitlement on macOS.
- **Cross-platform.** Each release platform needs a Rust target beside the C
  compiler RandomX already needs. On Windows cgo uses a MinGW compiler, so the
  library must be built for the `x86_64-pc-windows-gnu` target, not the MSVC
  one. Core-Geth builds its releases on native runners per platform, which
  avoids cross-compiling cgo. The extra system libraries the Rust library needs
  are printed by `cargo rustc --release -p ghost-verify-ffi --lib -- --print native-static-libs`,
  and the Go program's cgo flags must match them on each platform.

The commands that take the reproducibility check, from the repository root,
on Linux:

```sh
git clone . /tmp/repro-a && git clone . /tmp/repro-b
for d in /tmp/repro-a /tmp/repro-b; do
  (cd "$d/benchmarks" && RUSTFLAGS="--remap-path-prefix=$d=/src --remap-path-prefix=$HOME/.cargo=/cargo" \
    cargo build --locked --release -p ghost-verify-ffi)
  (cd "$d/benchmarks/verify-ffi/go" && CGO_ENABLED=1 go build -trimpath -ldflags=-buildid= -o verifyffi .)
done
sha256sum /tmp/repro-{a,b}/benchmarks/target/release/libghost_verify_ffi.a
sha256sum /tmp/repro-{a,b}/benchmarks/verify-ffi/go/verifyffi
```

The same commands on macOS arm64, and on Windows with MinGW after
`rustup target add x86_64-pc-windows-gnu` and `--target x86_64-pc-windows-gnu`
on the cargo build, take the second and third platforms.

## Blockers for the founder

These are open. None stops the choice of path, but each must be closed before
node phase 0 ends.

1. **No verification time or memory has been measured for invalid proofs, and
   no memory at all.** The only measured figures are the valid rows quoted
   above. Command: the measurement block above, on the reference machine and
   on the intended minimum node.
2. **Rust over cgo is not shown to build reproducibly, or on a second
   platform.** The RandomX evidence covers one C++ library on linux/arm64. The
   prototype has not been compiled. Command: the reproducibility block above,
   on Linux, macOS and Windows.
3. **Proof encoding is expected to be malleable.** If the appended-byte case
   is accepted, as the decoder suggests, the same proof has many encodings. The
   node must accept only the fixed proof length the
   [identical-size rule](results.md#cost-of-identical-size-and-shape) sets and
   reject any input not wholly consumed by the decoder. Confirm with the
   measuring program's "one byte appended" row.
4. **A panic in the verifier would crash a node.** The prototype turns a panic
   into a status code, but whether Plonky3's verifier can panic on a
   malformed proof is unknown until the "altered anywhere" sweep runs. A panic
   there is a denial-of-service bug to fix before any public node.
5. **The verifier the chain depends on has no review that is known to cover
   it.** A published audit of Plonky3 exists (Least Authority, for Polygon);
   whether it covers revision `f98331687e47` and the hiding commitment code
   was not checked.
