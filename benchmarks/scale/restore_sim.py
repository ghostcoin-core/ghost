"""Wallet restore and catch-up of an old key against a simulated mature chain.

A tested model, not a benchmark. It builds a chain of N leaves, each a 32-byte
leaf with its 156-byte note (spec 05, section 8), with one wallet's notes at
known positions and one canonical spent marker per leaf, and restores that
wallet under three candidate designs:

- baseline: spec 05, section 8 as written. Every page from page 0, every note
  trial-decrypted, every marker from the scan start read in bulk.
- buckets: a 4-byte tag in the note's nonce, bound to the leaf (the note tag of
  docs/research/recovery-cost.md, design C). The wallet reads the leaf and tag
  of every leaf, then fetches the rest of the notes only for whole pages: the
  pages of its hits, each with a fixed set of decoy pages derived from the key,
  padded to a fixed least number of pages.
- checkpoint: a coarse birth epoch carried with the key (design F of the same
  page). The wallet scans whole pages from the start of the key's epoch.

None of them is chosen here; they are candidates for a later verdict.

Every design reports download bytes, trial decryptions, elapsed time, peak
memory and storage on the reference phone, and a privacy measure: the smallest
set of commitments an endpoint can narrow the wallet's coins to. Every figure
is modeled: counts come from the simulation or from the analytic mode, and
times from the inputs below, none of which is measured on a phone.

The simulation's hashes (SHA-256 and HMAC-SHA-256) are stand-ins that make
notes, tags and markers deterministic. They are not the wallet's primitives and
no figure here is evidence about any hash.

Usage: python3 benchmarks/scale/restore_sim.py [--leaves N] [--seed S]
"""

import argparse
import hashlib
import hmac
import math
import random
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import budget  # noqa: E402

# Wallet tree data (spec 05, section 8).
LEAF_BYTES = 32
NOTE_BYTES = 156
LEAF_AND_NOTE_BYTES = LEAF_BYTES + NOTE_BYTES
PAGE_LEAVES = 4096
PAGE_ROOT_BYTES = 32
MARKER_BYTES = 32
# The note tag of the buckets design: the first 4 bytes of the note's nonce.
TAG_BYTES = 4
NOTE_REST_BYTES = NOTE_BYTES - TAG_BYTES

# The target (docs/scale/workload.md, Workload; the inputs of budget.py).
NEW_LEAVES_PER_DAY = budget.INPUTS["new_leaves_per_day"]
SPENDS_PER_DAY = budget.INPUTS["private_per_day"]
DAYS_PER_YEAR = budget.INPUTS["days_per_year"]
BLOCKS_PER_DAY = budget.blocks_per_day()
DAYS_PER_MONTH = 30

# Reference phone ceilings (docs/scale/workload.md, Reference phone). Each is a
# proposal there, not yet established.
PHONE_MEMORY_CEILING_BYTES = 1 << 30
PHONE_RESTORE_DOWNLOAD_CEILING_BYTES = 500_000_000
PHONE_CATCH_UP_CEILING_BYTES_PER_MONTH = 50_000_000
PHONE_RESTORE_TIME_CEILING_SECONDS = 10 * 60
PHONE_STORAGE_CEILING_BYTES = 200_000_000

# Phone link and processor inputs. workload.md states no link speed for the
# phone, so the link is the assumption of docs/research/recovery-cost.md: a
# 50 Mbit/s link at 80 percent use. The per-leaf costs are that page's
# measurements on the build machine (the client crate's real restore_coins, the
# slowest of three runs, and the page-root hashing), times the same page's
# assumed phone slowdown of 4. None is established on a phone.
PHONE_LINK_BYTES_PER_SECOND = 5_000_000
TRIAL_DECRYPT_NS_BUILD_MACHINE = 287
LEAF_HASH_NS_BUILD_MACHINE = 170
PHONE_SLOWDOWN = 4
TRIAL_DECRYPT_NS_PHONE = TRIAL_DECRYPT_NS_BUILD_MACHINE * PHONE_SLOWDOWN
# One keyed hash per leaf for a tag check, taken at the cost of one page-root
# node hash.
TAG_CHECK_NS_PHONE = LEAF_HASH_NS_BUILD_MACHINE * PHONE_SLOWDOWN
LEAF_HASH_NS_PHONE = LEAF_HASH_NS_BUILD_MACHINE * PHONE_SLOWDOWN

# A header (vector header-block-one-example, spec 05, section 11). A clean
# device checks every header from genesis whatever the design, so headers are
# reported beside the designs, not in them.
HEADER_BYTES = 582

# What the wallet holds while it streams: one page of leaves and notes and one
# page of markers.
STREAM_BUFFER_BYTES = PAGE_LEAVES * LEAF_AND_NOTE_BYTES + PAGE_LEAVES * MARKER_BYTES

# The simulated chain the tests use.
TEST_LEAVES = 100_000
SEED = 20261024
TEST_KEY = hashlib.sha256(b"synthetic test wallet key").digest()
OTHER_KEY = hashlib.sha256(b"synthetic other wallet key").digest()
TEST_KEY_BIRTH = 50_000
TEST_OWNED = (50_001, 53_248, 61_440, 70_000, 77_777, 86_016, 93_000, 99_998)
TEST_SPENT = (50_001, 70_000)
# Spent only in a block that a reorganisation disconnected: unspent on the
# canonical chain (designs.md, rule 2).
TEST_SPENT_DISCONNECTED = (77_777,)
TEST_EPOCH_LEAVES = 16_384

MODELED = "modeled"


@dataclass(frozen=True)
class Design:
    key: str
    name: str
    decoys_per_hit: int = 0
    min_pages: int = 0
    epoch_leaves: int = 0


BASELINE = Design("baseline", "baseline: every page from page 0, every note trial-decrypted")
BUCKETS = Design("buckets", "note tags, then whole pages with fixed decoy pages", decoys_per_hit=15, min_pages=64)
CHECKPOINT = Design("checkpoint", "scan from the start of the key's birth epoch", epoch_leaves=DAYS_PER_MONTH * NEW_LEAVES_PER_DAY)
DESIGNS = (BASELINE, BUCKETS, CHECKPOINT)

SPENT_CHECKS = ("canonical", "hints", "skip")


# Stand-in primitives of the simulation.

def _hash(*parts):
    return hashlib.sha256(b"".join(parts)).digest()


def _prf(key, *parts):
    return hmac.new(key, b"".join(parts), hashlib.sha256).digest()


def commitment(key, blind, amount):
    return _hash(b"sim/leaf", key, blind, amount.to_bytes(8, "big"))


def note_tag(key, leaf):
    return _prf(key, b"sim/tag", leaf)[:TAG_BYTES]


def _note_mac(key, leaf, body):
    return _prf(key, b"sim/mac", leaf, body)[:16]


def _keystream(key, leaf, length):
    out = b""
    counter = 0
    while len(out) < length:
        out += _hash(b"sim/stream", key, leaf, counter.to_bytes(4, "big"))
        counter += 1
    return out[:length]


def marker(key, leaf):
    return _hash(b"sim/marker", key, leaf)


def make_note(key, leaf, blind, amount):
    """A 156-byte note: tag, MAC, then the encrypted blinding and amount."""
    body_len = NOTE_BYTES - TAG_BYTES - 16
    payload = (blind + amount.to_bytes(8, "big")).ljust(body_len, b"\0")
    body = bytes(a ^ b for a, b in zip(payload, _keystream(key, leaf, body_len)))
    return note_tag(key, leaf) + _note_mac(key, leaf, body) + body


def trial_decrypt(key, leaf, note):
    """The amount of a note that opens this leaf under the key, else None."""
    body = note[TAG_BYTES + 16:]
    if not hmac.compare_digest(note[TAG_BYTES:TAG_BYTES + 16], _note_mac(key, leaf, body)):
        return None
    payload = bytes(a ^ b for a, b in zip(body, _keystream(key, leaf, len(body))))
    blind, amount = payload[:32], int.from_bytes(payload[32:40], "big")
    return amount if commitment(key, blind, amount) == leaf else None


# The simulated chain.

@dataclass
class Chain:
    count: int
    leaves: bytes
    notes: bytes
    # Canonical spent markers, marker j included when the chain held j + 1
    # leaves (one marker per leaf, as at the target).
    markers: bytes
    # Markers only in blocks a reorganisation disconnected.
    disconnected_markers: list
    owned: dict
    spent: frozenset
    spent_disconnected: frozenset

    def leaf(self, i):
        return self.leaves[i * LEAF_BYTES:(i + 1) * LEAF_BYTES]

    def note(self, i):
        return self.notes[i * NOTE_BYTES:(i + 1) * NOTE_BYTES]

    def marker_at(self, j):
        return self.markers[j * MARKER_BYTES:(j + 1) * MARKER_BYTES]

    @property
    def pages(self):
        return pages_for(self.count)


def pages_for(leaves):
    return -(-leaves // PAGE_LEAVES)


def generate_chain(leaves=TEST_LEAVES, key=TEST_KEY, owned=TEST_OWNED, spent=TEST_SPENT,
                   spent_disconnected=TEST_SPENT_DISCONNECTED, seed=SEED):
    """A chain of `leaves` leaves with the key's notes at the `owned` positions.

    Every other leaf and note is random. A coin in `spent` has its marker in a
    canonical block after it; a coin in `spent_disconnected` only in a block
    off the canonical chain.
    """
    owned = tuple(sorted(set(owned)))
    if any(not 0 <= p < leaves - 1 for p in owned):
        raise ValueError("owned positions must lie in the chain, before its last leaf")
    if not set(spent) <= set(owned) or not set(spent_disconnected) <= set(owned):
        raise ValueError("only owned coins can be spent")
    if set(spent) & set(spent_disconnected):
        raise ValueError("a coin is spent on the canonical chain or only off it, not both")
    rng = random.Random(seed)
    leaf_bytes = bytearray(rng.randbytes(leaves * LEAF_BYTES))
    note_bytes = bytearray(rng.randbytes(leaves * NOTE_BYTES))
    marker_bytes = bytearray(rng.randbytes(leaves * MARKER_BYTES))
    amounts = {}
    disconnected = []
    for p in owned:
        amount = rng.randrange(1, 10 ** 9)
        blind = rng.randbytes(32)
        leaf = commitment(key, blind, amount)
        leaf_bytes[p * LEAF_BYTES:(p + 1) * LEAF_BYTES] = leaf
        note_bytes[p * NOTE_BYTES:(p + 1) * NOTE_BYTES] = make_note(key, leaf, blind, amount)
        amounts[p] = amount
        if p in spent:
            j = rng.randrange(p + 1, leaves)
            marker_bytes[j * MARKER_BYTES:(j + 1) * MARKER_BYTES] = marker(key, leaf)
        if p in spent_disconnected:
            disconnected.append(marker(key, leaf))
    disconnected.append(rng.randbytes(MARKER_BYTES))
    return Chain(
        count=leaves,
        leaves=bytes(leaf_bytes),
        notes=bytes(note_bytes),
        markers=bytes(marker_bytes),
        disconnected_markers=disconnected,
        owned=amounts,
        spent=frozenset(spent),
        spent_disconnected=frozenset(spent_disconnected),
    )


# What a restore downloads and does.

@dataclass
class Counts:
    total_leaves: int
    scan_start: int
    leaf_and_note_bytes: int
    page_root_bytes: int
    marker_bytes: int
    trial_decryptions: int
    tag_checks: int
    leaf_hashes: int
    owned_pages: int
    anonymity_set: int


def costs(counts):
    """Download, time, memory, storage and privacy of a restore, all modeled."""
    download = counts.leaf_and_note_bytes + counts.page_root_bytes + counts.marker_bytes
    download_seconds = download / PHONE_LINK_BYTES_PER_SECOND
    cpu_seconds = (
        counts.trial_decryptions * TRIAL_DECRYPT_NS_PHONE
        + counts.tag_checks * TAG_CHECK_NS_PHONE
        + counts.leaf_hashes * LEAF_HASH_NS_PHONE
    ) / 1e9
    own_pages_bytes = counts.owned_pages * PAGE_LEAVES * LEAF_BYTES
    return {
        "label": MODELED,
        "leaves": counts.total_leaves,
        "scan_start": counts.scan_start,
        "leaf_and_note_bytes": counts.leaf_and_note_bytes,
        "page_root_bytes": counts.page_root_bytes,
        "marker_bytes": counts.marker_bytes,
        "download_bytes": download,
        "trial_decryptions": counts.trial_decryptions,
        "tag_checks": counts.tag_checks,
        "download_seconds": download_seconds,
        "cpu_seconds": cpu_seconds,
        # Download and processing taken one after the other: an upper bound.
        "elapsed_seconds": download_seconds + cpu_seconds,
        "peak_memory_bytes": counts.page_root_bytes + STREAM_BUFFER_BYTES + own_pages_bytes,
        "storage_bytes": counts.page_root_bytes + own_pages_bytes,
        "anonymity_set": counts.anonymity_set,
        "excluded_fraction": 1 - counts.anonymity_set / counts.total_leaves,
    }


@dataclass
class Restore:
    design: Design
    coins: dict
    status: dict
    spent_check: str
    counts: Counts
    requests: list = field(default_factory=list)

    @property
    def costs(self):
        return costs(self.counts)


def checkpoint_start(design, key_birth, leaves):
    """Scan start of the checkpoint design: the key's epoch, down to a whole page.

    Never past the chain's last partly filled page, which is always read whole.
    """
    start = key_birth // design.epoch_leaves * design.epoch_leaves
    return min(start, leaves - 1 if leaves else 0) // PAGE_LEAVES * PAGE_LEAVES


def _decoy_pages(key, page, wanted, total_pages):
    """The fixed decoy pages of one page: derived from the key and the page only."""
    wanted = min(wanted, total_pages - 1)
    out = []
    i = 0
    while len(out) < wanted:
        d = int.from_bytes(_prf(key, b"sim/decoy", page.to_bytes(8, "big"), i.to_bytes(4, "big"))[:8], "big") % total_pages
        if d != page and d not in out:
            out.append(d)
        i += 1
    return out


def _padding_pages(key, have, wanted, total_pages):
    """Pages added until the request holds the least number of pages."""
    wanted = min(wanted, total_pages)
    have = set(have)
    i = 0
    while len(have) < wanted:
        have.add(int.from_bytes(_prf(key, b"sim/pad", i.to_bytes(4, "big"))[:8], "big") % total_pages)
        i += 1
    return have


def _filled(page, leaves):
    return max(0, min(PAGE_LEAVES, leaves - page * PAGE_LEAVES))


def _spent_status(chain, key, coins, scan_start, spent_check):
    """Status of each found coin and the marker bytes read for it."""
    if spent_check == "skip":
        return {p: "unknown" for p in coins}, 0
    own = {marker(key, chain.leaf(p)): p for p in coins}
    status = {p: "unspent" for p in coins}
    for j in range(scan_start, chain.count):
        p = own.get(chain.marker_at(j))
        if p is not None:
            status[p] = "spent"
    if spent_check == "hints":
        # Marker pages from a peer, unchecked against receipts: they can carry
        # markers of blocks that are not on the canonical chain.
        for m in chain.disconnected_markers:
            if m in own:
                status[own[m]] = "spent"
    return status, (chain.count - scan_start) * MARKER_BYTES


def restore(chain, key, design=BASELINE, key_birth=0, spent_check="canonical"):
    """Restore the key's coins from the chain under one design."""
    if spent_check not in SPENT_CHECKS:
        raise ValueError(f"spent_check must be one of {SPENT_CHECKS}")
    n = chain.count
    total_pages = chain.pages
    coins = {}
    requests = [("page-root-list",)]
    if design.key in ("baseline", "checkpoint"):
        start = 0 if design.key == "baseline" else checkpoint_start(design, key_birth, n)
        first_page = start // PAGE_LEAVES
        requests += [("page", p) for p in range(first_page, total_pages)]
        for i in range(start, n):
            amount = trial_decrypt(key, chain.leaf(i), chain.note(i))
            if amount is not None:
                coins[i] = amount
        scanned = n - start
        own_pages = {p // PAGE_LEAVES for p in coins}
        counts = dict(
            scan_start=start,
            leaf_and_note_bytes=scanned * LEAF_AND_NOTE_BYTES,
            trial_decryptions=scanned,
            tag_checks=0,
            leaf_hashes=scanned,
            anonymity_set=scanned,
        )
    elif design.key == "buckets":
        start = 0
        requests.append(("leaf-and-tag-columns", 0))
        hits = [i for i in range(n) if chain.note(i)[:TAG_BYTES] == note_tag(key, chain.leaf(i))]
        hit_pages = sorted({i // PAGE_LEAVES for i in hits})
        wanted = set(hit_pages)
        for page in hit_pages:
            wanted.update(_decoy_pages(key, page, design.decoys_per_hit, total_pages))
        wanted = _padding_pages(key, wanted, design.min_pages, total_pages)
        # Sent as one request, in page order, so the order shows nothing.
        requests += [("note-rest", p) for p in sorted(wanted)]
        for i in hits:
            amount = trial_decrypt(key, chain.leaf(i), chain.note(i))
            if amount is not None:
                coins[i] = amount
        own_pages = {p // PAGE_LEAVES for p in coins}
        fetched = sum(_filled(p, n) for p in wanted)
        counts = dict(
            scan_start=0,
            leaf_and_note_bytes=n * (LEAF_BYTES + TAG_BYTES) + fetched * NOTE_REST_BYTES,
            trial_decryptions=len(hits),
            tag_checks=n,
            leaf_hashes=n,
            anonymity_set=fetched,
        )
    else:
        raise ValueError(f"unknown design {design.key}")
    status, marker_bytes = _spent_status(chain, key, coins, start, spent_check)
    if spent_check != "skip":
        requests.append(("markers-from", start))
    return Restore(
        design=design,
        coins=coins,
        status=status,
        spent_check=spent_check,
        counts=Counts(
            total_leaves=n,
            page_root_bytes=total_pages * PAGE_ROOT_BYTES,
            marker_bytes=marker_bytes,
            owned_pages=len(own_pages),
            **counts,
        ),
        requests=requests,
    )


def audit(result):
    """What is wrong with a restore's result; empty when nothing is.

    Spent status must come from the canonical chain (designs.md, rule 2):
    a restore that skipped the check, or took it from unchecked marker hints,
    is flagged, and so is any coin whose status is unknown.
    """
    problems = []
    if result.spent_check != "canonical":
        problems.append(f"spent status not checked against the canonical chain ({result.spent_check})")
    if any(s == "unknown" for s in result.status.values()):
        problems.append("a found coin has an unknown spent status")
    return problems


# Analytic mode: the same counts without building the chain.

def analytic(design, leaves, owned_pages, key_birth=0):
    """Modeled costs of a restore over `leaves` leaves, the key's coins on `owned_pages` pages.

    For the buckets design every expected false tag hit (one in 2^32 leaves,
    rounded up) is counted as one more hit page, so its figures are an upper
    bound on the simulation's.
    """
    total_pages = pages_for(leaves)
    if design.key in ("baseline", "checkpoint"):
        start = 0 if design.key == "baseline" else checkpoint_start(design, key_birth, leaves)
        scanned = leaves - start
        counts = dict(
            scan_start=start,
            leaf_and_note_bytes=scanned * LEAF_AND_NOTE_BYTES,
            trial_decryptions=scanned,
            tag_checks=0,
            leaf_hashes=scanned,
            anonymity_set=scanned,
        )
    elif design.key == "buckets":
        start = 0
        hit_pages = owned_pages + math.ceil(leaves / 2 ** (8 * TAG_BYTES))
        pages = min(total_pages, max(design.min_pages, hit_pages * (1 + design.decoys_per_hit)))
        fetched = min(leaves, pages * PAGE_LEAVES)
        counts = dict(
            scan_start=0,
            leaf_and_note_bytes=leaves * (LEAF_BYTES + TAG_BYTES) + fetched * NOTE_REST_BYTES,
            trial_decryptions=hit_pages,
            tag_checks=leaves,
            leaf_hashes=leaves,
            anonymity_set=fetched,
        )
    else:
        raise ValueError(f"unknown design {design.key}")
    markers = (leaves - start) * SPENDS_PER_DAY // NEW_LEAVES_PER_DAY
    return costs(Counts(
        total_leaves=leaves,
        page_root_bytes=total_pages * PAGE_ROOT_BYTES,
        marker_bytes=markers * MARKER_BYTES,
        owned_pages=owned_pages,
        **counts,
    ))


def leaves_after(days):
    return days * NEW_LEAVES_PER_DAY


def header_bytes(days):
    """Headers a clean device downloads from genesis over that many days."""
    return days * BLOCKS_PER_DAY * HEADER_BYTES


def catch_up_bytes(design, days, owned_pages):
    """Leaf-and-note bytes and marker bytes to keep up for `days` days, modeled."""
    leaves = leaves_after(days)
    if design.key == "buckets":
        pages = max(design.min_pages, owned_pages * (1 + design.decoys_per_hit))
        tree = leaves * (LEAF_BYTES + TAG_BYTES) + min(leaves, pages * PAGE_LEAVES) * NOTE_REST_BYTES
    else:
        tree = leaves * LEAF_AND_NOTE_BYTES
    return {"label": MODELED, "leaf_and_note_bytes": tree,
            "marker_bytes": leaves * SPENDS_PER_DAY // NEW_LEAVES_PER_DAY * MARKER_BYTES}


def ceilings(result):
    """Which reference phone ceilings a full restore meets (True) or misses (False)."""
    return {
        "restore download": result["download_bytes"] <= PHONE_RESTORE_DOWNLOAD_CEILING_BYTES,
        "restore time": result["elapsed_seconds"] <= PHONE_RESTORE_TIME_CEILING_SECONDS,
        "memory": result["peak_memory_bytes"] <= PHONE_MEMORY_CEILING_BYTES,
        "storage": result["storage_bytes"] <= PHONE_STORAGE_CEILING_BYTES,
    }


# The scenarios of docs/scale/phone-results.md: a key one year old with 52
# notes a year on 52 pages (one a week, the assumption of recovery-cost.md).
NOTES_PER_YEAR = 52


def scenarios():
    """(name, design, modeled costs) for the simulated size, one year and five years."""
    out = []
    sim_checkpoint = replace(CHECKPOINT, epoch_leaves=TEST_EPOCH_LEAVES)
    for design in (BASELINE, BUCKETS, sim_checkpoint):
        out.append(("simulated chain", design, analytic(design, TEST_LEAVES, len(TEST_OWNED), TEST_KEY_BIRTH)))
    for years in (1, 5):
        leaves = leaves_after(years * DAYS_PER_YEAR)
        birth = leaves_after((years - 1) * DAYS_PER_YEAR)
        for design in DESIGNS:
            out.append((f"{years} year(s) at the target", design, analytic(design, leaves, NOTES_PER_YEAR, birth)))
    return out


def report(leaves, seed):
    lines = ["Modeled from the inputs at the top of benchmarks/scale/restore_sim.py"]
    for name, design, c in scenarios():
        met = ", ".join(f"{k} {'met' if v else 'missed'}" for k, v in ceilings(c).items())
        lines.append(
            f"{name:28} {design.key:10} download {c['download_bytes']:,} B, "
            f"trial decryptions {c['trial_decryptions']:,}, elapsed {c['elapsed_seconds']:,.1f} s, "
            f"peak memory {c['peak_memory_bytes']:,} B, anonymity set {c['anonymity_set']:,}; {met}"
        )
    chain = generate_chain(leaves, seed=seed, owned=[p for p in TEST_OWNED if p < leaves - 1],
                           spent=[p for p in TEST_SPENT if p < leaves - 1],
                           spent_disconnected=[p for p in TEST_SPENT_DISCONNECTED if p < leaves - 1])
    for design in (BASELINE, BUCKETS, replace(CHECKPOINT, epoch_leaves=TEST_EPOCH_LEAVES)):
        r = restore(chain, TEST_KEY, design, key_birth=TEST_KEY_BIRTH)
        c = r.costs
        lines.append(
            f"simulated {leaves:,} leaves {design.key:10} found {len(r.coins)} of {len(chain.owned)}, "
            f"download {c['download_bytes']:,} B, trial decryptions {c['trial_decryptions']:,}, "
            f"problems {audit(r) or 'none'}"
        )
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--leaves", type=int, default=TEST_LEAVES)
    ap.add_argument("--seed", type=int, default=SEED)
    args = ap.parse_args(argv)
    print(report(args.leaves, args.seed))
    return 0


if __name__ == "__main__":
    sys.exit(main())
