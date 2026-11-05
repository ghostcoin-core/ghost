"""Which statements are proven with the batch STARK, what each one's witness is, and whether
its cross-AIR LogUp terminals need hiding.

At the pinned Plonky3 revision, ``p3-batch-stark`` publishes every AIR's LogUp terminal in the
proof unmasked, even under the hiding PCS. An AIR's share of a lookup across several AIRs is a
partial sum over its own trace, so a statement may prove cross-AIR lookups under the hiding
configuration at this revision only if everything its trace is computed from is public. This
module checks, against the repository:

1. The page (docs/scale/stage2-design.md, "Proof library for the layers") has a table with one
   row for each statement of ``STATEMENTS``, whose last column is exactly ``PUBLIC`` (its
   witness is public, the terminals need no hiding) or ``RELIES`` (it relies on hiding them),
   and the open item on the terminals is gone.
2. Each statement's prover takes exactly the inputs listed here: the public ones of
   ``PUBLIC_INPUTS`` and the statement's witness. A new input to a prover fails the check until
   it is listed here and the page says whether it is public. The signed transaction a chunk
   reads has exactly the fields listed here.
3. The batch STARK is proven only from the files of ``PROVERS``; lookups across AIRs are sent
   only from the files of ``GLOBAL_SENDERS``; the library's own lookup check is test-only and
   local; and only the proofs crate depends on ``p3-batch-stark`` or ``p3-lookup``.
4. Every Plonky3 crate of the repository names one revision. If any row relies on hiding, that
   revision is not ``UNMASKED_REVISION`` and a test under proofs/tests reads a masked terminal.

Usage: python3 benchmarks/scale/layer_witness.py
Exits 1 and prints each problem when the repository fails.
"""

import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
DOC = Path("docs/scale/stage2-design.md")
SECTION = "### Proof library for the layers"

# The revision whose p3-batch-stark publishes LogUp terminals unmasked under a hiding PCS.
UNMASKED_REVISION = "0d803737b681774186cd283b1fd2d8e493655c82"

PUBLIC = "public witness, no hiding needed"
RELIES = "relies on hiding"
VERDICTS = (PUBLIC, RELIES)
TABLE_HEADER = "| Statement | Prover | Its witness | Cross-AIR terminals |"

# Prover inputs that are public by construction: the key, the binding and position the node
# rebuilds, the starting digest, the tag, the child AIR and key (fixed by the verifier key),
# the prover's own zero-knowledge seed and the flag of the refusal tests.
PUBLIC_INPUTS = {
    "key": "&LayerKey",
    "air": "&A",
    "binding_slots": "&[usize; BINDING_ELEMS]",
    "binding": "&Binding",
    "index": "u32",
    "tag": "&LayerTag",
    "start": "&NativeDigest",
    "child": "&LayerKey",
    "zk_seed": "[u8; 32]",
    "unchecked": "bool",
}

# Every statement proven with the batch STARK: its row on the page, the function that proves
# it, and the inputs that make its witness, with their exact types.
STATEMENTS = (
    {
        "row": "Batch over reveal proofs",
        "file": "proofs/src/layers/keys.rs",
        "function": "prove_batch_of",
        "public": ("key", "air", "binding_slots", "tag", "start", "zk_seed", "unchecked"),
        "witness": {"children": "&[(Vec<u8>, Vec<F>)]"},
    },
    {
        "row": "Batch over chunk proofs",
        "file": "proofs/src/layers/keys.rs",
        "function": "prove_layer_of",
        "public": ("key", "child", "tag", "zk_seed", "unchecked"),
        "witness": {"children": "&[(Vec<u8>, Claim)]"},
    },
    {
        "row": "Root",
        "file": "proofs/src/layers/keys.rs",
        "function": "prove_layer_of",
        "public": ("key", "child", "tag", "zk_seed", "unchecked"),
        "witness": {"children": "&[(Vec<u8>, Claim)]"},
    },
    {
        "row": "Shrink",
        "file": "proofs/src/layers/keys.rs",
        "function": "prove_layer_of",
        "public": ("key", "child", "tag", "zk_seed", "unchecked"),
        "witness": {"children": "&[(Vec<u8>, Claim)]"},
    },
    {
        "row": "ML-DSA-44 chunk",
        "file": "proofs/src/mldsa/mod.rs",
        "function": "prove_chunk_of",
        "public": ("key", "binding", "index", "start", "zk_seed", "unchecked"),
        "witness": {"txs": "&[SignedTx]"},
        "public_types": {"key": "&ChunkKey", "start": "&Digest"},
    },
)

# The fields of the signed transaction a chunk reads, all carried by the pooled transaction.
SIGNED_TX = ("proofs/src/mldsa/mod.rs", "SignedTx", {
    "account": "[u8; ACCOUNT_BYTES]",
    "key_id": "[u8; KEY_ID_BYTES]",
    "message": "Vec<u8>",
    "public_key": "Vec<u8>",
    "signature": "Vec<u8>",
})

# The only Rust files of a shipped crate that call a batch-STARK prover, and why.
PROVERS = {
    "proofs/src/layers/tables.rs": "the prover of a circuit's tables, called only from the files below",
    "proofs/src/layers/keys.rs": "batch, root and shrink (finish)",
    "proofs/src/mldsa/mod.rs": "the ML-DSA-44 chunk",
    "proofs/src/layers/mod.rs": "table_roundtrip_check, a fixed synthetic circuit",
    "proofs/src/lookup_check.rs": "the test-only lookup check, local lookups only",
}

# The only Rust files that send a lookup across AIRs (a named bus).
GLOBAL_SENDERS = ("proofs/src/layers/tables.rs", "proofs/src/mldsa/tables.rs")
LOOKUP_CHECK = "proofs/src/lookup_check.rs"
LIB = "proofs/src/lib.rs"
LOOKUP_CRATES = ("p3-batch-stark", "p3-lookup")
LOOKUP_MANIFEST = "proofs/Cargo.toml"

# Calls of a batch-STARK prover: the library's own, and the tables' prover of a circuit.
# (The layers' own `layers::prove_batch` is the batch statement above, not a new one.)
PROVE_CALL = re.compile(r"(?<!layers::)(?<![\w.])prove_batch\s*\(|\btables::prove\s*\(")
# A send on a named bus: `push_interaction(bus, ..)` (or a global variant of it).
GLOBAL_SEND = re.compile(r"\bpush_(?:global_)?interaction\s*\(")
SKIP_DIRS = {"target", "node_modules", ".git"}
REV = re.compile(r'Plonky3[^\n]*\brev\s*=\s*"([0-9a-f]+)"')
MASK_TEST = re.compile(r"lookup_terminals[\s\S]*masked|masked[\s\S]*lookup_terminals")


def section(text, heading=SECTION):
    """The lines under ``heading`` up to the next heading of its level or above."""
    lines = text.splitlines()
    if heading not in lines:
        return None
    level = len(heading) - len(heading.lstrip("#"))
    out = []
    for line in lines[lines.index(heading) + 1:]:
        stripped = line.lstrip("#")
        if line.startswith("#") and len(line) - len(stripped) <= level and stripped.startswith(" "):
            break
        out.append(line)
    return out


def cells(line):
    """The cells of a table row, the label check's markers left out."""
    line = re.sub(r"\s*<!--.*?-->", "", line).strip()
    return [c.strip() for c in line.strip("|").split("|")]


def doc_rows(text):
    """The table of the section, as {statement: [cells]}, and the problems found reading it."""
    body = section(text)
    if body is None:
        return {}, [f"missing section {SECTION}"]
    problems = []
    if TABLE_HEADER not in [re.sub(r"\s+", " ", b.strip()) for b in body]:
        return {}, [f"{SECTION} has no table headed {TABLE_HEADER}"]
    start = [re.sub(r"\s+", " ", b.strip()) for b in body].index(TABLE_HEADER)
    rows = {}
    for line in body[start + 2:]:
        if not line.startswith("|"):
            break
        row = cells(line)
        if len(row) != 4:
            problems.append(f"row with {len(row)} cells, not 4: {line.strip()}")
            continue
        if row[0] in rows:
            problems.append(f"two rows for {row[0]}")
        rows[row[0]] = row
    return rows, problems


def check_doc(text):
    """Problems of the page: the table and the open item."""
    rows, problems = doc_rows(text)
    if problems and not rows:
        return problems, {}
    names = {s["row"] for s in STATEMENTS}
    verdicts = {}
    for s in STATEMENTS:
        row = rows.get(s["row"])
        if row is None:
            problems.append(f"no row for {s['row']}")
            continue
        if f"`{s['function']}`" not in row[1]:
            problems.append(f"{s['row']}: the prover column does not name `{s['function']}`")
        if not row[2]:
            problems.append(f"{s['row']}: the witness column is empty")
        if row[3] not in VERDICTS:
            problems.append(f"{s['row']}: cross-AIR terminals must be '{PUBLIC}' or '{RELIES}', not '{row[3]}'")
            continue
        verdicts[s["row"]] = row[3]
    for name in rows:
        if name not in names:
            problems.append(f"row for a statement this check does not know: {name}")
    for line in section(text) or []:
        if re.match(r"^\s*[-*]\s+\*\*Open:", line) and "terminal" in line.lower():
            problems.append("the open item on the lookup terminals is still on the page")
    return problems, verdicts


def split_top(text):
    """Split at commas outside brackets."""
    out, depth, cur = [], 0, ""
    for ch in text:
        if ch in "([<{":
            depth += 1
        elif ch in ")]>}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return [p.strip() for p in out if p.strip()]


def params(source, function):
    """{name: type} of a Rust function's parameters, or None when it is not there."""
    match = re.search(r"\bfn\s+" + re.escape(function) + r"\b\s*(?:<[^>]*>)?\s*\(", source)
    if match is None:
        return None
    depth, i = 1, match.end()
    while i < len(source) and depth:
        depth += {"(": 1, ")": -1}.get(source[i], 0)
        i += 1
    out = {}
    for p in split_top(source[match.end():i - 1]):
        name, _, ty = p.partition(":")
        out[name.strip()] = re.sub(r"\s+", " ", ty.strip())
    return out


def struct_fields(source, name):
    match = re.search(r"\bstruct\s+" + re.escape(name) + r"\s*\{([^}]*)\}", source)
    if match is None:
        return None
    out = {}
    for p in split_top(match.group(1)):
        p = re.sub(r"^\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?", "", p)
        name_, _, ty = p.partition(":")
        out[name_.strip()] = re.sub(r"\s+", " ", ty.strip())
    return out


def check_provers(sources):
    """Problems of the provers' inputs. ``sources`` maps repository paths to file text."""
    problems = []
    for s in STATEMENTS:
        got = params(sources.get(s["file"], ""), s["function"])
        if got is None:
            problems.append(f"{s['row']}: no fn {s['function']} in {s['file']}")
            continue
        types = dict(PUBLIC_INPUTS, **s.get("public_types", {}))
        want = {name: types[name] for name in s["public"]}
        want.update(s["witness"])
        for name, ty in got.items():
            if name not in want:
                problems.append(f"{s['row']}: {s['function']} takes {name}: {ty}, which this check does not "
                                "list; say on the page whether it is public")
            elif ty != want[name]:
                problems.append(f"{s['row']}: {s['function']} takes {name}: {ty}, not {want[name]}")
        for name in want:
            if name not in got:
                problems.append(f"{s['row']}: {s['function']} no longer takes {name}")
    path, struct, want = SIGNED_TX
    got = struct_fields(sources.get(path, ""), struct)
    if got is None:
        problems.append(f"no struct {struct} in {path}")
    elif got != want:
        problems.append(f"{struct} has fields {got}, not {want}: say on the page whether each is public")
    return problems


def check_sources(sources, manifests):
    """Problems of who proves the batch STARK and who sends lookups across AIRs."""
    problems = []
    for path, text in sorted(sources.items()):
        code = "\n".join(line.split("//", 1)[0] for line in text.splitlines())
        if PROVE_CALL.search(code) and path not in PROVERS:
            problems.append(f"{path} proves with the batch STARK; list the statement and its witness first")
        if GLOBAL_SEND.search(code) and path not in GLOBAL_SENDERS:
            problems.append(f"{path} sends a lookup across AIRs; list the statement and its witness first")
    check = sources.get(LOOKUP_CHECK)
    if check is not None:
        if GLOBAL_SEND.search(check):
            problems.append(f"{LOOKUP_CHECK} must use local lookups only")
        if not re.search(r"#\[cfg\(test\)\]\s*mod\s+lookup_check\s*;", sources.get(LIB, "")):
            problems.append(f"{LOOKUP_CHECK} must stay a test-only module of {LIB}")
    for path, text in sorted(manifests.items()):
        for crate in LOOKUP_CRATES:
            if re.search(r"^\s*" + re.escape(crate) + r"\s*=", text, re.MULTILINE) and path != LOOKUP_MANIFEST:
                problems.append(f"{path} depends on {crate}; only {LOOKUP_MANIFEST} may")
    return problems


def check_pin(verdicts, manifests, tests):
    """Problems of the pinned revision, given the page's verdicts. ``tests`` maps the paths of
    proofs/tests to their text."""
    problems = []
    revisions = sorted({rev for text in manifests.values() for rev in REV.findall(text)})
    if len(revisions) != 1:
        problems.append(f"the Plonky3 crates name {len(revisions)} revisions, not one: {revisions}")
    relying = sorted(name for name, v in verdicts.items() if v == RELIES)
    if relying:
        if UNMASKED_REVISION in revisions:
            problems.append(f"{', '.join(relying)} relies on hiding the terminals, but the pin publishes them "
                            "unmasked; move it to a revision with the masking on main")
        if not any(MASK_TEST.search(text) for text in tests.values()):
            problems.append("no test under proofs/tests shows a cross-AIR terminal masked")
    return problems


def walk(root, keep):
    """{repository path: text} of every file under ``root`` that ``keep`` accepts, outside
    build output, packages and git."""
    out = {}
    for top, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            rel = (Path(top) / name).relative_to(root).as_posix()
            if keep(rel):
                out[rel] = (Path(top) / name).read_text(encoding="utf-8")
    return out


def rust_sources(root):
    """The Rust sources of every crate's library and binaries (its src/ directory)."""
    return walk(root, lambda rel: rel.endswith(".rs") and "/src/" in f"/{rel}")


def manifests(root):
    return walk(root, lambda rel: rel.endswith("Cargo.toml"))


def proof_tests(root):
    return {p.relative_to(root).as_posix(): p.read_text(encoding="utf-8")
            for p in sorted((root / "proofs" / "tests").glob("*.rs"))}


def check(root=REPO):
    """Every problem of the repository at ``root``, as text."""
    doc = (root / DOC).read_text(encoding="utf-8") if (root / DOC).exists() else ""
    problems, verdicts = check_doc(doc)
    sources = rust_sources(root)
    found = manifests(root)
    problems += check_provers(sources)
    problems += check_sources(sources, found)
    problems += check_pin(verdicts, found, proof_tests(root))
    return problems


def main(argv=None):
    problems = check()
    for p in problems:
        print(p, file=sys.stderr)
    if problems:
        return 1
    print(f"{len(STATEMENTS)} statements proven with the batch STARK; every one's witness is stated")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
