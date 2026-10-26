#!/usr/bin/env python3
"""Checks the structure of docs/spec/02-proof-statements.md.

Python standard library only. It checks that:

  1. the required sections are present;
  2. every statement section (`## N. Statement Sk: ...`) lists its public
     inputs, with a reason for each that it does not link to the commit, its
     private inputs and its constraints, that no name is in both tables, and
     that the secrets and the salt are private inputs and never public ones;
  3. each statement's public inputs are exactly the fields of its binding
     layout plus the digest itself, at the same widths;
  4. every binding layout is contiguous, sums to its stated total, gives the
     right size with its tag and the right number of Keccak permutations, and
     holds every field its statement must bind: the data reveal and hold
     bindings bind the 32-byte content fingerprint `cf`, the coin reveal
     binding does not;
  5. every hash tag the document names is in the tag table of spec 01 (so the
     removed unsalted fingerprint and marker tags, such as
     `ghost/coin-marker/v1`, are gaps), and the four salted fingerprint and
     marker tags are named;
  6. the properties are numbered PS-1 upwards without gaps or repeats, each
     names its check, and every PS-n cited anywhere exists;
  7. every named adversarial vector has exactly one entry, the entries are
     numbered AV-1 upwards, and each states the expected result and cites a
     property;
  8. the amount and conservation vectors are right;
  9. the data statements S2 and S3 open the data leaf with the fee reserve,
     `K("ghost/data-commitment/v1", DATA, DATA_RESERVE, F_d)`, and no data
     leaf hash anywhere in the document leaves the reserve out.

Usage:
    python3 scripts/check_proof_statements.py [SPEC_MD]

Exit status is non-zero on any gap.
"""

import re
import sys
from pathlib import Path

DEFAULT_SPEC = Path(__file__).resolve().parent.parent / "docs" / "spec" / "02-proof-statements.md"
TAG_TABLE_SPEC = "01-commitments-and-keys.md"

REQUIRED_SECTIONS = ("One-time reveal", "Proof of holding", "Purpose binding", "Shared tree state",
                     "Conservation", "Range", "Properties", "Adversarial vectors")

REQUIRED_VECTORS = ("recipient substitution", "fee substitution", "cross-chain replay",
                    "cross-version replay", "coin/data type confusion", "marker double use",
                    "overflow")

KECCAK_RATE = 136
V_MAX = 2**96 - 1
LIMBS = 6
LIMB_BITS = 16

CHAIN_FIELDS = ("chain_id", "version", "domain", "statement", "statement_version", "type",
                "purpose", "root")
BINDINGS = {
    "ghost/coin-reveal-binding/v1": CHAIN_FIELDS + (
        "marker", "remainder", "remainder_note", "recipient", "out", "fee", "rule"),
    "ghost/data-reveal-binding/v1": CHAIN_FIELDS + ("marker", "party", "fee", "rule", "cf"),
    "ghost/hold-binding/v1": CHAIN_FIELDS + ("marker_set_root", "verifier", "challenge", "cf"),
}
# The content fingerprint: public in the data statements, so revealed bytes
# can be checked against it, and never bound by the coin reveal, where it is
# the constant zero.
CONTENT_FINGERPRINT = "cf"
DIGEST = "binding"
# Secrets every statement must take privately and never publicly. The salt of
# a version 2 commitment is public on the commit, which is exactly why a
# statement must not publish it again (spec 01, section 3).
PRIVATE_SECRETS = ("s", "r", "b", "salt", "position", "path")
# The salted (commitment format version 2) tags every statement opens with.
SALTED_TAGS = ("ghost/coin-fingerprint/v2", "ghost/data-fingerprint/v2",
               "ghost/coin-marker/v2", "ghost/data-marker/v2")

# The data leaf with its fee reserve (spec 04, section 3, "The fee reserve"):
# a constant of the data statements, not an input and not a binding field.
DATA_RESERVE = "DATA_RESERVE"
DATA_LEAF = 'K("ghost/data-commitment/v1", DATA, DATA_RESERVE, F_d)'
DATA_STATEMENTS = (2, 3)
DATA_LEAF_RE = re.compile(r'K\("ghost/data-commitment/v1",([^)]*)\)')

REQUIRED_AMOUNT_VECTORS =("amount-v-max", "amount-two-to-96")
REQUIRED_CONSERVATION_VECTORS = ("conservation-full-reveal", "conservation-field-wrap",
                                 "conservation-wrap-at-two-to-96")

STATEMENT_RE = re.compile(r"^## \d+\. Statement S(\d+): (.+)$")
TAG_RE = re.compile(r"ghost/[a-z0-9-]+/v\d+")
PROPERTY_RE = re.compile(r"^- \*\*PS-(\d+)\. (.+?)\*\*")
VECTOR_RE = re.compile(r"^- \*\*AV-(\d+)\. (.+?)\.\*\*")
PS_REF_RE = re.compile(r"\bPS-(\d+)\b")
TOTAL_RE = re.compile(r"^Total: (\d+) bytes after the tag; (\d+) bytes with the tag; "
                      r"(\d+) Keccak permutations?\.$")


def sections(text):
    """Map each '## ' heading to the lines under it, up to the next one."""
    out, name = {}, None
    for line in text.splitlines():
        if line.startswith("## "):
            name = line[3:].strip()
            out[name] = []
        elif name is not None:
            out[name].append(line)
    return out


def subsections(lines):
    """Map each '### ' heading inside a section to its lines."""
    out, name = {}, None
    for line in lines:
        if line.startswith("### "):
            name = line[4:].strip()
            out[name] = []
        elif name is not None:
            out[name].append(line)
    return out


def table_after(lines, label):
    """The first Markdown table after the line that starts with `label`, as
    (header, rows); None if the label or the table is missing."""
    start = next((i for i, line in enumerate(lines) if line.startswith(label)), None)
    if start is None:
        return None
    block = []
    for line in lines[start + 1:]:
        if line.startswith("|"):
            block.append([c.strip() for c in line.strip().strip("|").split("|")])
        elif block or line.startswith("**") or line.startswith("#"):
            break
    if len(block) < 3:
        return None
    header = block[0]
    return header, [dict(zip(header, cells)) for cells in block[2:]]


def name_of(cell):
    return cell.strip().strip("`").strip()


def find_section(secs, word):
    return [name for name in secs if word in name]


def entries(lines, item_re):
    """List items matching item_re, each with its full text (to the next item)."""
    found, current = [], None
    for line in lines:
        m = item_re.match(line)
        if m:
            current = [int(m.group(1)), m.group(2), [line]]
            found.append(current)
        elif line.startswith("- ") or line.startswith("#"):
            current = None
        elif current is not None:
            current[2].append(line)
    return [(n, title, " ".join(" ".join(text).split())) for n, title, text in found]


def vector_blocks(lines):
    """Every `[name]` block inside fenced code blocks, as name -> fields."""
    blocks, fenced, current = {}, False, None
    for line in lines:
        if line.startswith("```"):
            fenced, current = not fenced, None
            continue
        if not fenced:
            continue
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            current = {}
            blocks[line[1:-1]] = current
        elif current is not None and " = " in line:
            key, value = line.split(" = ", 1)
            current[key.strip()] = value.strip()
        elif current is not None and line.endswith(" ="):
            current[line[:-2].strip()] = ""
    return blocks


def amount_word(value):
    return value.to_bytes(32, "big").hex() if 0 <= value < 2**256 else None


def limbs_of(value):
    """The six 16-bit limbs of the low 12 bytes, least significant first."""
    return [(value >> (LIMB_BITS * j)) & 0xFFFF for j in range(LIMBS)]


def limb_conservation(v, out, rem, fee):
    """The limb rule of section 10: high bytes zero, limb equations with carries
    in {0, 1, 2}, final carry 0."""
    if any(not 0 <= x <= V_MAX for x in (v, out, rem, fee)):
        return False
    lv, lo, lr, lf = (limbs_of(x) for x in (v, out, rem, fee))
    carry = 0
    for j in range(LIMBS):
        total = lo[j] + lr[j] + lf[j] + carry
        if total % 2**LIMB_BITS != lv[j]:
            return False
        carry = total // 2**LIMB_BITS
        if carry not in (0, 1, 2):
            return False
    return carry == 0


def integer_conservation(v, out, rem, fee):
    return all(0 <= x <= V_MAX for x in (v, out, rem, fee)) and v == out + rem + fee


class Checker:
    def __init__(self, text, tag_table_text):
        self.text = text
        self.lines = text.splitlines()
        self.secs = sections(text)
        self.tag_table_text = tag_table_text
        self.errors = []
        self.layouts = {}

    def fail(self, message):
        self.errors.append(message)

    def run(self):
        self.check_sections()
        self.check_layouts()
        self.check_statements()
        self.check_data_reserve()
        self.check_tags()
        self.check_properties()
        self.check_vectors()
        self.check_amounts()
        self.check_conservation()
        return self.errors

    def check_sections(self):
        for word in REQUIRED_SECTIONS:
            if not find_section(self.secs, word):
                self.fail(f"no '## ' section whose title contains '{word}'")

    def check_layouts(self):
        names = find_section(self.secs, "Purpose binding")
        if not names:
            return
        lines = self.secs[names[0]]
        for tag, required in BINDINGS.items():
            sub = [body for body in subsections(lines).values()
                   if any(f'K("{tag}"' in line for line in body)]
            if len(sub) != 1:
                self.fail(f"binding {tag}: expected one layout subsection, found {len(sub)}")
                continue
            body = sub[0]
            table = table_after(body, "`binding = K(")
            if table is None or not {"Offset", "Width", "Field"} <= set(table[0]):
                self.fail(f"binding {tag}: no Offset/Width/Field table")
                continue
            fields, offset = {}, 0
            for row in table[1]:
                field = name_of(row.get("Field", ""))
                try:
                    at, width = int(row["Offset"]), int(row["Width"])
                except (KeyError, ValueError):
                    self.fail(f"binding {tag}: row '{field}' has a non-numeric offset or width")
                    continue
                if at != offset:
                    self.fail(f"binding {tag}: field '{field}' at offset {at}, expected {offset}")
                if width <= 0:
                    self.fail(f"binding {tag}: field '{field}' has width {width}")
                if field in fields:
                    self.fail(f"binding {tag}: field '{field}' appears twice")
                fields[field] = width
                offset = at + width
            missing = [f for f in required if f not in fields]
            if missing:
                self.fail(f"binding {tag}: does not bind {missing}")
            if CONTENT_FINGERPRINT in fields and CONTENT_FINGERPRINT not in required:
                self.fail(f"binding {tag}: binds '{CONTENT_FINGERPRINT}', which only the "
                          f"data statements make public")
            if CONTENT_FINGERPRINT in fields and fields[CONTENT_FINGERPRINT] != 32:
                self.fail(f"binding {tag}: '{CONTENT_FINGERPRINT}' is "
                          f"{fields[CONTENT_FINGERPRINT]} bytes, expected 32")
            self.layouts[tag] = fields
            totals = [TOTAL_RE.match(line) for line in body if line.startswith("Total:")]
            totals = [m for m in totals if m]
            if len(totals) != 1:
                self.fail(f"binding {tag}: expected one 'Total: ...' line")
                continue
            after, with_tag, perms = (int(g) for g in totals[0].groups())
            expect_with = 1 + len(tag) + offset
            expect_perms = expect_with // KECCAK_RATE + 1
            if after != offset:
                self.fail(f"binding {tag}: total says {after} bytes, fields sum to {offset}")
            if with_tag != expect_with:
                self.fail(f"binding {tag}: says {with_tag} bytes with the tag, "
                          f"recomputed {expect_with}")
            if perms != expect_perms:
                self.fail(f"binding {tag}: says {perms} permutations, recomputed {expect_perms}")

    def check_statements(self):
        found = []
        for name, lines in self.secs.items():
            m = STATEMENT_RE.match("## " + name)
            if m:
                found.append((int(m.group(1)), name, lines))
        numbers = [n for n, _, _ in found]
        if len(found) < 3:
            self.fail(f"expected at least three statement sections, found {len(found)}")
        if numbers != list(range(1, len(numbers) + 1)):
            self.fail(f"statements are numbered {numbers}, expected S1 upwards in order")
        for n, name, lines in found:
            where = f"statement S{n}"
            public = table_after(lines, "**Public inputs.**")
            private = table_after(lines, "**Private inputs.**")
            if public is None:
                self.fail(f"{where}: no public inputs table after '**Public inputs.**'")
            if private is None:
                self.fail(f"{where}: no private inputs table after '**Private inputs.**'")
            if not any(line.startswith("**Constraints.**") for line in lines):
                self.fail(f"{where}: no '**Constraints.**'")
            if public is None or private is None:
                continue
            header, rows = public
            why = next((h for h in header if h.startswith("Why it does not link")), None)
            if "Input" not in header or "Width" not in header or why is None:
                self.fail(f"{where}: public inputs table needs Input, Width and "
                          f"'Why it does not link' columns")
                continue
            pub = {}
            for row in rows:
                field = name_of(row["Input"])
                if not row.get(why, "").strip():
                    self.fail(f"{where}: public input '{field}' gives no reason it does not link")
                pub[field] = row["Width"]
            priv = {name_of(row.get("Input", "")) for row in private[1]}
            both = sorted(set(pub) & priv)
            if both:
                self.fail(f"{where}: {both} are both public and private")
            for secret in PRIVATE_SECRETS:
                if secret not in priv:
                    self.fail(f"{where}: '{secret}' is not a private input")
                if secret in pub:
                    self.fail(f"{where}: '{secret}' is a public input")
            if DIGEST not in pub:
                self.fail(f"{where}: the binding digest is not a public input")
            text = "\n".join(lines)
            tags = [tag for tag in BINDINGS if tag in text]
            if len(tags) != 1:
                self.fail(f"{where}: names {len(tags)} binding tags, expected one")
                continue
            layout = self.layouts.get(tags[0])
            if layout is None:
                continue
            expected = set(layout) | {DIGEST}
            if set(pub) != expected:
                self.fail(f"{where}: public inputs not in {tags[0]}: "
                          f"{sorted(set(pub) - expected)}; bound but not listed: "
                          f"{sorted(expected - set(pub))}")
            for field, width in layout.items():
                if field in pub and pub[field] != str(width):
                    self.fail(f"{where}: '{field}' is {pub[field]} bytes in the public inputs "
                              f"and {width} in {tags[0]}")

    def check_data_reserve(self):
        for name, lines in self.secs.items():
            m = STATEMENT_RE.match("## " + name)
            if not m or int(m.group(1)) not in DATA_STATEMENTS:
                continue
            body = " ".join(" ".join(lines).split())
            if DATA_RESERVE not in body or DATA_LEAF not in body:
                self.fail(f"S{m.group(1)} does not open the data leaf with {DATA_RESERVE}")
        flat = " ".join(self.text.split())
        for args in DATA_LEAF_RE.findall(flat):
            if DATA_RESERVE not in args:
                self.fail(f"data leaf hash without {DATA_RESERVE}: "
                          f'K("ghost/data-commitment/v1",{args})')

    def check_tags(self):
        known = set()
        for line in self.tag_table_text.splitlines():
            if line.startswith("| `ghost/"):
                known.add(name_of(line.strip("|").split("|")[0]))
        if not known:
            self.fail("no tag table found in spec 01")
            return
        for tag in BINDINGS:
            if tag not in known:
                self.fail(f"binding tag {tag} is not in the tag table of spec 01")
        for tag in sorted(set(TAG_RE.findall(self.text))):
            if tag not in known:
                self.fail(f"tag {tag} is not in the tag table of spec 01")
        for tag in SALTED_TAGS:
            if tag not in self.text:
                self.fail(f"salted tag {tag} is not named; no statement opens version 2")

    def check_properties(self):
        names = find_section(self.secs, "Properties")
        if not names:
            return
        props = entries(self.secs[names[0]], PROPERTY_RE)
        numbers = [n for n, _, _ in props]
        if not props:
            self.fail("no numbered properties (- **PS-n. ...**)")
        if numbers != list(range(1, len(numbers) + 1)):
            self.fail(f"properties are numbered {numbers}, expected PS-1 upwards without gaps")
        for n, _, body in props:
            if "Check:" not in body:
                self.fail(f"PS-{n} does not say how a test checks it ('Check:')")
        defined = set(numbers)
        for ref in sorted({int(x) for x in PS_REF_RE.findall(self.text)}):
            if ref not in defined:
                self.fail(f"PS-{ref} is cited but not defined")

    def check_vectors(self):
        names = find_section(self.secs, "Adversarial vectors")
        if not names:
            return
        vecs = entries(self.secs[names[0]], VECTOR_RE)
        numbers = [n for n, _, _ in vecs]
        if numbers != list(range(1, len(numbers) + 1)):
            self.fail(f"adversarial vectors are numbered {numbers}, expected AV-1 upwards")
        for required in REQUIRED_VECTORS:
            hits = [n for n, title, _ in vecs if required in title.lower()]
            if len(hits) != 1:
                self.fail(f"adversarial vector '{required}': expected one entry, found {len(hits)}")
        for n, _, body in vecs:
            if "Expected:" not in body:
                self.fail(f"AV-{n} states no expected result ('Expected:')")
            if not PS_REF_RE.search(body):
                self.fail(f"AV-{n} cites no property")

    def blocks_in(self, word, kind):
        names = find_section(self.secs, word)
        if not names:
            return {}
        blocks = vector_blocks(self.secs[names[0]])
        for name, fields in blocks.items():
            if fields.get("kind") != kind:
                self.fail(f"vector {name}: kind '{fields.get('kind')}' in the {word} section")
        return {n: f for n, f in blocks.items() if f.get("kind") == kind}

    def integer(self, name, fields, key):
        try:
            return int(fields[key])
        except (KeyError, ValueError):
            self.fail(f"vector {name}: '{key}' is missing or not an integer")
            return None

    def valid_flag(self, name, fields):
        flag = fields.get("valid")
        if flag not in ("yes", "no"):
            self.fail(f"vector {name}: 'valid' must be yes or no")
            return None
        return flag == "yes"

    def check_amounts(self):
        blocks = self.blocks_in("Range", "amount")
        for required in REQUIRED_AMOUNT_VECTORS:
            if required not in blocks:
                self.fail(f"amount vector {required} is missing")
        for name, fields in blocks.items():
            value = self.integer(name, fields, "value")
            valid = self.valid_flag(name, fields)
            if value is None or valid is None:
                continue
            word = amount_word(value)
            if word is None or fields.get("word") != word:
                self.fail(f"vector {name}: word is {fields.get('word')}, recomputed {word}")
            limbs = " ".join(f"{x:04x}" for x in reversed(limbs_of(value)))
            if fields.get("limbs") != limbs:
                self.fail(f"vector {name}: limbs are {fields.get('limbs')}, recomputed {limbs}")
            if valid != (0 <= value <= V_MAX):
                self.fail(f"vector {name}: valid = {fields['valid']}, but the value is "
                          f"{'in' if value <= V_MAX else 'out of'} range")

    def check_conservation(self):
        blocks = self.blocks_in("Conservation", "conservation")
        for required in REQUIRED_CONSERVATION_VECTORS:
            if required not in blocks:
                self.fail(f"conservation vector {required} is missing")
        outcomes = set()
        for name, fields in blocks.items():
            values = [self.integer(name, fields, k) for k in ("v", "out", "remainder", "fee")]
            valid = self.valid_flag(name, fields)
            if None in values or valid is None:
                continue
            by_integer = integer_conservation(*values)
            by_limbs = limb_conservation(*values)
            if by_integer != by_limbs:
                self.fail(f"vector {name}: the limb rule gives {by_limbs}, "
                          f"the integer rule {by_integer}")
            if valid != by_integer:
                self.fail(f"vector {name}: valid = {fields['valid']}, recomputed "
                          f"{'yes' if by_integer else 'no'}")
            outcomes.add(valid)
        if blocks and outcomes != {True, False}:
            self.fail("conservation vectors need both valid and invalid cases")


def check_text(text, tag_table_text):
    """All gaps found in the text of the specification (empty when complete)."""
    return Checker(text, tag_table_text).run()


def run(path):
    path = Path(path)
    tag_path = path.parent / TAG_TABLE_SPEC
    tag_text = tag_path.read_text(encoding="utf-8") if tag_path.exists() else ""
    return check_text(path.read_text(encoding="utf-8"), tag_text)


def main(argv):
    path = Path(argv[1]) if len(argv) > 1 else DEFAULT_SPEC
    if not path.exists():
        print(f"MISSING: {path}")
        return 1
    errors = run(path)
    for e in errors:
        print("GAP: " + e)
    if errors:
        print(f"{len(errors)} gap(s) in {path}")
        return 1
    print(f"Proof statements complete: {path.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
