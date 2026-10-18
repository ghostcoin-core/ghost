#!/usr/bin/env python3
"""Checks the structure of docs/spec/07-private-transaction.md.

Python standard library only. It checks that:

  1. the required sections are present, each as a numbered `## N. ...`
     heading, and the sections are numbered 1 upwards without gaps;
  2. the parameter table holds every named constant, the type byte is outside
     Ethereum's types, the proof field is the version 1 width, and every
     derived constant (payload and envelope size,
     `G_PRIV`, the pool's byte cap) equals its recomputed value;
  3. the payload table lists exactly the fields of the private transaction, in
     order, contiguous, at their stated widths, with no sender, signature,
     nonce or gas field, and its widths add up to the stated fixed size;
  4. the binding table maps every field of the coin reveal binding of spec 02
     to a payload field or to the node, and every payload field except the
     proof is bound;
  5. every worked example's arithmetic is right: the window fee, the
     worst-case base-fee growth inside a window, a lapsed fee, each boundary
     case and the two competing reveals;
  6. the properties are numbered PT-1 upwards without gaps or repeats, each
     names its check, and every PT-n cited anywhere exists;
  7. the conflicts section names spec 02, spec 03 and spec 04.

Usage:
    python3 scripts/check_private_transaction.py [SPEC_MD]

Exit status is non-zero on any gap.
"""

import re
import sys
from pathlib import Path

DEFAULT_SPEC = Path(__file__).resolve().parent.parent / "docs" / "spec" / "07-private-transaction.md"

REQUIRED_SECTIONS = ("Encoding and hashing", "Fee formula", "Fee is current", "Transaction pool",
                     "Boundary cases", "Properties", "Conflicts")

# Ethereum's own transaction types, and the deposit type of the OP Stack.
TAKEN_TYPES = set(range(0x00, 0x05)) | {0x7E}

# The payload fields, in order, as the front desk fixed them. `None` is the
# width of the proof, which the parameter table gives.
PAYLOAD = (("version", 2), ("chain_id", 8), ("marker", 32), ("root", 32), ("remainder", 32),
           ("recipient", 20), ("out", 32), ("fee", 32), ("proof", None), ("note", 156))
FORBIDDEN_FIELDS = ("signature", "sig", "v", "r", "s", "y_parity", "nonce", "gas_price",
                    "gas_limit", "gas", "max_fee_per_gas", "max_priority_fee_per_gas", "tip",
                    "sender", "from", "access_list", "value", "type", "rule", "binding")

# The coin reveal binding of spec 02, section 7.
COIN_BINDING = ("chain_id", "version", "domain", "statement", "statement_version", "type",
                "purpose", "root", "marker", "remainder", "recipient", "out", "fee", "rule",
                "remainder_note")
# Binding fields whose payload field has another name.
BINDING_ALIAS = {"remainder_note": "note"}

PARAMETERS = ("TYPE_BYTE", "TX_VERSION", "PROOF_BYTES", "NOTE_BYTES", "PAYLOAD_BYTES",
              "ENVELOPE_BYTES", "BYTE_GAS", "BASE_TX_GAS", "VERIFY_GAS", "G_PRIV", "FEE_WINDOW",
              "TIP_DIVISOR", "MIN_GAS_LIMIT", "POOL_MAX_COUNT", "POOL_MAX_BYTES")

V_MAX = 2**96 - 1
# The proof field of version 1 for every reveal kind (section 3, "Proof
# field"); a change of width is a new version, never an edit of this one.
PROOF_FIELD_BYTES = 1_310_720
# The base client's smallest gas limit; the ceiling step's 1/20000 term is
# 1 / (8 * MIN_GAS_LIMIT / 2).
MIN_GAS_LIMIT = 5000

REQUIRED_EXAMPLES = {
    "full-reveal": "reveal",
    "zero-amount-claim": "reveal",
    "fee-uses-whole-balance": "reveal",
    "fee-above-balance": "reveal",
    "competing-reveals": "competing",
}

HEADING_RE = re.compile(r"^## (\d+)\. (.+)$")
PROPERTY_RE = re.compile(r"^- \*\*PT-(\d+)\. (.+?)\*\*")
PT_REF_RE = re.compile(r"\bPT-(\d+)\b")
TOTAL_RE = re.compile(r"^Total: ([\d,]+) bytes of payload; ([\d,]+) bytes with the type byte\.$")


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


def find_section(secs, word):
    return [name for name in secs if word.lower() in name.lower()]


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


def to_int(text):
    """An integer written in decimal with optional commas, or in hex as 0x..."""
    text = name_of(text).split()[0] if text.strip() else ""
    text = text.replace(",", "")
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


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
    return blocks


def ceil_div(a, b):
    return -(-a // b)


def ceiling_step(u):
    """One block of the most the base fee can grow (section 4)."""
    return u + u // 8 + u // 20000 + 1


def window_price(b_ref, window):
    u = b_ref
    for _ in range(window - 1):
        u = ceiling_step(u)
    return u


RATIO_BASE = 10**9


def ratio_text(value, base):
    """value / base to three decimals, rounded half up."""
    milli = (value * 1000 * 2 + base) // (2 * base)
    return f"{milli // 1000}.{milli % 1000:03d}"


def next_base_fee(base_fee, gas_limit, gas_used):
    """The base client's EIP-1559 rule for the next block's base fee, for a
    parent with this base fee, gas limit and gas used (elasticity 2,
    change denominator 8)."""
    target = gas_limit // 2
    if gas_used == target:
        return base_fee
    if gas_used > target:
        delta = (gas_used - target) * base_fee // target // 8
        return base_fee + max(1, delta)
    delta = (target - gas_used) * base_fee // target // 8
    return max(0, base_fee - delta)


def conserves(v, out, rem, fee):
    return all(0 <= x <= V_MAX for x in (v, out, rem, fee)) and v == out + rem + fee


class Checker:
    def __init__(self, text):
        self.text = text
        self.secs = sections(text)
        self.errors = []
        self.params = {}
        self.payload = {}
        self.windows = {}

    def fail(self, message):
        self.errors.append(message)

    def run(self):
        self.check_sections()
        self.check_parameters()
        self.check_payload()
        self.check_binding()
        self.check_examples()
        self.check_properties()
        self.check_conflicts()
        return self.errors

    def section(self, word):
        names = find_section(self.secs, word)
        return self.secs[names[0]] if names else None

    def check_sections(self):
        numbers = []
        for line in self.text.splitlines():
            if line.startswith("## "):
                m = HEADING_RE.match(line)
                if not m:
                    self.fail(f"heading '{line}' is not numbered as '## N. ...'")
                    continue
                numbers.append(int(m.group(1)))
        if numbers != list(range(1, len(numbers) + 1)):
            self.fail(f"sections are numbered {numbers}, expected 1 upwards without gaps")
        for word in REQUIRED_SECTIONS:
            if not find_section(self.secs, word):
                self.fail(f"no '## N.' section whose title contains '{word}'")

    def check_parameters(self):
        found = None
        for lines in self.secs.values():
            found = table_after(lines, "**Parameters.**")
            if found:
                break
        if found is None:
            self.fail("no parameter table after '**Parameters.**'")
            return
        for row in found[1]:
            name = name_of(row.get("Name", ""))
            value = to_int(row.get("Value", ""))
            if value is None:
                self.fail(f"parameter {name}: value '{row.get('Value')}' is not an integer")
                continue
            self.params[name] = value
        missing = [p for p in PARAMETERS if p not in self.params]
        if missing:
            self.fail(f"parameter table lacks {missing}")
            return
        p = self.params
        if p["TYPE_BYTE"] in TAKEN_TYPES or not 0 < p["TYPE_BYTE"] < 0x7F:
            self.fail(f"TYPE_BYTE {p['TYPE_BYTE']:#04x} is taken or outside EIP-2718's range")
        if p["NOTE_BYTES"] != 156:
            self.fail(f"NOTE_BYTES is {p['NOTE_BYTES']}, spec 01 fixes 156")
        if p["PROOF_BYTES"] != PROOF_FIELD_BYTES:
            self.fail(f"PROOF_BYTES is {p['PROOF_BYTES']}, version 1 fixes {PROOF_FIELD_BYTES}; "
                      f"a change of width is a new version")
        if p["MIN_GAS_LIMIT"] != MIN_GAS_LIMIT:
            self.fail(f"MIN_GAS_LIMIT is {p['MIN_GAS_LIMIT']}; the ceiling step of section 5 "
                      f"assumes {MIN_GAS_LIMIT}")
        widths = [p["PROOF_BYTES"] if w is None else w for _, w in PAYLOAD]
        derived = {
            "PAYLOAD_BYTES": sum(widths),
            "ENVELOPE_BYTES": 1 + p["PAYLOAD_BYTES"],
            "G_PRIV": p["BYTE_GAS"] * p["ENVELOPE_BYTES"] + p["BASE_TX_GAS"] + p["VERIFY_GAS"],
            "POOL_MAX_BYTES": p["POOL_MAX_COUNT"] * p["ENVELOPE_BYTES"],
        }
        for name, value in derived.items():
            if p[name] != value:
                self.fail(f"parameter {name} is {p[name]}, recomputed {value}")
        if p["FEE_WINDOW"] < 1:
            self.fail("FEE_WINDOW must be at least one block")
        if p["TIP_DIVISOR"] < 1:
            self.fail("TIP_DIVISOR must be at least 1")

    def check_payload(self):
        lines = self.section("Encoding and hashing")
        if lines is None:
            return
        table = table_after(lines, "**Payload.**")
        if table is None or not {"Offset", "Width", "Field"} <= set(table[0]):
            self.fail("no Offset/Width/Field payload table after '**Payload.**'")
            return
        offset, order = 0, []
        for row in table[1]:
            field = name_of(row.get("Field", ""))
            at, width = to_int(row.get("Offset", "")), to_int(row.get("Width", ""))
            if at is None or width is None:
                self.fail(f"payload field '{field}' has a non-numeric offset or width")
                continue
            if at != offset:
                self.fail(f"payload field '{field}' at offset {at}, expected {offset}")
            if width <= 0:
                self.fail(f"payload field '{field}' has width {width}")
            if field in self.payload:
                self.fail(f"payload field '{field}' appears twice")
            if field.lower() in FORBIDDEN_FIELDS:
                self.fail(f"payload field '{field}' is not allowed in a private transaction")
            self.payload[field] = width
            order.append(field)
            offset = at + width
        expected = [name for name, _ in PAYLOAD]
        if order != expected:
            self.fail(f"payload fields are {order}, expected {expected}")
        for name, width in PAYLOAD:
            if width is None:
                width = self.params.get("PROOF_BYTES")
            if name in self.payload and width is not None and self.payload[name] != width:
                self.fail(f"payload field '{name}' is {self.payload[name]} bytes, expected {width}")
        totals = [TOTAL_RE.match(line) for line in lines if line.startswith("Total:")]
        totals = [m for m in totals if m]
        if len(totals) != 1:
            self.fail("expected one 'Total: N bytes of payload; M bytes with the type byte.' line")
            return
        payload, envelope = (int(g.replace(",", "")) for g in totals[0].groups())
        if payload != offset:
            self.fail(f"total says {payload} bytes of payload, fields sum to {offset}")
        if envelope != offset + 1:
            self.fail(f"total says {envelope} bytes with the type byte, recomputed {offset + 1}")
        if self.params.get("PAYLOAD_BYTES") not in (None, offset):
            self.fail(f"PAYLOAD_BYTES is {self.params['PAYLOAD_BYTES']}, fields sum to {offset}")

    def check_binding(self):
        lines = self.section("Encoding and hashing")
        if lines is None:
            return
        table = table_after(lines, "**Binding.**")
        if table is None or not {"Binding field", "Source"} <= set(table[0]):
            self.fail("no 'Binding field'/'Source' table after '**Binding.**'")
            return
        sources = {}
        for row in table[1]:
            sources[name_of(row["Binding field"])] = name_of(row["Source"])
        missing = [f for f in COIN_BINDING if f not in sources]
        extra = [f for f in sources if f not in COIN_BINDING]
        if missing:
            self.fail(f"binding table does not map {missing}")
        if extra:
            self.fail(f"binding table maps fields not in the coin reveal binding: {extra}")
        bound = set()
        for field, source in sources.items():
            if source.lower().startswith("node"):
                continue
            if source not in self.payload:
                self.fail(f"binding field '{field}' comes from '{source}', not a payload field")
                continue
            if source != BINDING_ALIAS.get(field, field):
                self.fail(f"binding field '{field}' comes from payload field '{source}'")
            bound.add(source)
        unbound = [f for f in self.payload if f != "proof" and f not in bound]
        if unbound:
            self.fail(f"payload fields not bound by the proof: {unbound}")

    def integer(self, name, fields, key):
        value = to_int(fields.get(key, ""))
        if value is None:
            self.fail(f"example {name}: '{key}' is missing or not an integer")
        return value

    def flag(self, name, fields):
        value = fields.get("valid")
        if value not in ("yes", "no"):
            self.fail(f"example {name}: 'valid' must be yes or no")
            return None
        return value == "yes"

    def check_examples(self):
        blocks = {}
        for word in ("Fee formula", "Fee is current", "Boundary cases"):
            lines = self.section(word)
            if lines is not None:
                blocks.update(vector_blocks(lines))
        kinds = {"window": self.check_window, "growth": self.check_growth,
                 "lapse": self.check_lapse, "reveal": self.check_reveal,
                 "competing": self.check_competing}
        # Windows first: the other examples refer to them.
        for name, fields in sorted(blocks.items(), key=lambda kv: kv[1].get("kind") != "window"):
            kind = fields.get("kind")
            if kind not in kinds:
                self.fail(f"example {name}: unknown kind '{kind}'")
                continue
            kinds[kind](name, fields)
        if not any(f.get("kind") == "window" for f in blocks.values()):
            self.fail("no window fee example (kind = window)")
        if not any(f.get("kind") == "growth" for f in blocks.values()):
            self.fail("no worst-case growth example (kind = growth)")
        if not any(f.get("kind") == "lapse" for f in blocks.values()):
            self.fail("no lapsed fee example (kind = lapse)")
        self.check_window_lengths()
        boundary = self.section("Boundary cases") or []
        in_boundary = vector_blocks(boundary)
        for name, kind in REQUIRED_EXAMPLES.items():
            if in_boundary.get(name, {}).get("kind") != kind:
                self.fail(f"boundary case example {name} (kind = {kind}) is missing")

    def check_window_lengths(self):
        lines = self.section("Fee is current")
        if lines is None:
            return
        table = table_after(lines, "**Window length.**")
        if table is None or not {"Window (blocks)", "Ceiling over b_ref"} <= set(table[0]):
            self.fail("no 'Window (blocks)'/'Ceiling over b_ref' table after '**Window length.**'")
            return
        lengths = []
        for row in table[1]:
            window = to_int(row["Window (blocks)"])
            if window is None or window < 1:
                self.fail(f"window length '{row['Window (blocks)']}' is not a positive integer")
                continue
            lengths.append(window)
            want = ratio_text(window_price(RATIO_BASE, window), RATIO_BASE)
            if row["Ceiling over b_ref"] != want:
                self.fail(f"window length {window}: ceiling is {row['Ceiling over b_ref']}, "
                          f"recomputed {want}")
        if self.params.get("FEE_WINDOW") not in lengths:
            self.fail("the window length table has no row for FEE_WINDOW")

    def check_window(self, name, fields):
        b_ref, g_priv = self.integer(name, fields, "b_ref"), self.integer(name, fields, "g_priv")
        price, base = self.integer(name, fields, "price"), self.integer(name, fields, "base_part")
        tip, fee = self.integer(name, fields, "tip"), self.integer(name, fields, "fee")
        if None in (b_ref, g_priv, price, base, tip, fee) or any(p not in self.params
                                                                 for p in PARAMETERS):
            return
        if g_priv != self.params.get("G_PRIV"):
            self.fail(f"example {name}: g_priv is {g_priv}, G_PRIV is {self.params.get('G_PRIV')}")
        want_price = window_price(b_ref, self.params["FEE_WINDOW"])
        want_base = g_priv * want_price
        want_tip = ceil_div(want_base, self.params["TIP_DIVISOR"])
        for key, got, want in (("price", price, want_price), ("base_part", base, want_base),
                               ("tip", tip, want_tip), ("fee", fee, want_base + want_tip)):
            if got != want:
                self.fail(f"example {name}: {key} is {got}, recomputed {want}")
        if fee > V_MAX:
            self.fail(f"example {name}: fee {fee} is above V_MAX")
        # The other examples are checked against the recomputed values, so a
        # wrong ceiling shows up in them too.
        self.windows[name] = {"price": want_price, "base_part": want_base, "tip": want_tip,
                              "fee": want_base + want_tip, "b_ref": b_ref}

    def check_growth(self, name, fields):
        gas_limit = self.integer(name, fields, "gas_limit")
        window = self.windows.get(fields.get("window"))
        if window is None:
            self.fail(f"example {name}: names no window example")
            return
        try:
            fees = [int(x.replace(",", "")) for x in fields.get("base_fees", "").split()]
        except ValueError:
            fees = []
        if gas_limit is None or len(fees) != self.params.get("FEE_WINDOW"):
            self.fail(f"example {name}: needs gas_limit and one base fee per block of the window")
            return
        if fees[0] != window["b_ref"]:
            self.fail(f"example {name}: the first base fee is {fees[0]}, b_ref is {window['b_ref']}")
        for j in range(1, len(fees)):
            want = next_base_fee(fees[j - 1], gas_limit, gas_limit)
            if fees[j] != want:
                self.fail(f"example {name}: base fee {j} is {fees[j]}, recomputed {want}")
        for j, fee in enumerate(fees):
            if self.params.get("G_PRIV", 0) * fee > window["base_part"]:
                self.fail(f"example {name}: block {j} charges more than the window's base part")

    def check_lapse(self, name, fields):
        proved = self.integer(name, fields, "fee_proved")
        in_force = self.integer(name, fields, "fee_in_force")
        valid = self.flag(name, fields)
        if None in (proved, in_force, valid):
            return
        if valid != (proved == in_force):
            self.fail(f"example {name}: valid = {fields['valid']}, but the fees "
                      f"{'are' if proved == in_force else 'are not'} equal")
        for key, value in (("fee_proved", proved), ("fee_in_force", in_force)):
            if not any(w["fee"] == value for w in self.windows.values()):
                self.fail(f"example {name}: {key} {value} is no window example's fee")

    def reveal_values(self, name, fields, suffix=""):
        keys = ("out" + suffix, "remainder" + suffix)
        return [self.integer(name, fields, k) for k in keys]

    def check_reveal(self, name, fields):
        v, fee = self.integer(name, fields, "v"), self.integer(name, fields, "fee")
        out, rem = self.reveal_values(name, fields)
        burned, tip = self.integer(name, fields, "burned"), self.integer(name, fields, "tip")
        minted, valid = self.integer(name, fields, "minted"), self.flag(name, fields)
        window = self.windows.get(fields.get("window"))
        if window is None:
            self.fail(f"example {name}: names no window example")
        if None in (v, fee, out, rem, burned, tip, minted, valid):
            return
        ok = conserves(v, out, rem, fee)
        if valid != ok:
            self.fail(f"example {name}: valid = {fields['valid']}, recomputed "
                      f"{'yes' if ok else 'no'}")
        if window is not None and fee != window["fee"]:
            self.fail(f"example {name}: fee {fee} is not the window fee {window['fee']}")
        want = (window["base_part"], window["tip"], out) if ok and window else (0, 0, 0)
        for key, got, expect in zip(("burned", "tip", "minted"), (burned, tip, minted), want):
            if got != expect:
                self.fail(f"example {name}: {key} is {got}, recomputed {expect}")
        shape = {
            "full-reveal": rem == 0 and out == v - fee and out > 0,
            "zero-amount-claim": out == 0 and rem == v - fee and rem > 0,
            "fee-uses-whole-balance": out == 0 and rem == 0 and v == fee,
            "fee-above-balance": v < fee and not ok,
        }
        if not shape.get(name, True):
            self.fail(f"example {name}: the amounts do not have the shape of this case")

    def check_competing(self, name, fields):
        v, fee = self.integer(name, fields, "v"), self.integer(name, fields, "fee")
        out_a, rem_a = self.reveal_values(name, fields, "_a")
        out_b, rem_b = self.reveal_values(name, fields, "_b")
        minted = self.integer(name, fields, "minted")
        change = self.integer(name, fields, "total_out_change")
        window = self.windows.get(fields.get("window"))
        if window is None:
            self.fail(f"example {name}: names no window example")
        if None in (v, fee, out_a, rem_a, out_b, rem_b, minted, change):
            return
        if window is not None and fee != window["fee"]:
            self.fail(f"example {name}: fee {fee} is not the window fee {window['fee']}")
        if fields.get("marker_a") != fields.get("marker_b") or not fields.get("marker_a"):
            self.fail(f"example {name}: the two reveals must carry the same marker")
        for side, out, rem in (("a", out_a, rem_a), ("b", out_b, rem_b)):
            if not conserves(v, out, rem, fee):
                self.fail(f"example {name}: reveal {side} does not conserve value on its own")
        first, included = fields.get("first"), fields.get("included")
        rejected = fields.get("rejected")
        if first not in ("a", "b") or included != first or rejected != ("b" if first == "a" else "a"):
            self.fail(f"example {name}: the first reveal must be included and the other rejected")
            return
        out = out_a if included == "a" else out_b
        if minted != out:
            self.fail(f"example {name}: minted is {minted}, recomputed {out}")
        if change != out + fee:
            self.fail(f"example {name}: total_out_change is {change}, recomputed {out + fee}")

    def check_properties(self):
        lines = self.section("Properties")
        if lines is None:
            return
        found, current = [], None
        for line in lines:
            m = PROPERTY_RE.match(line)
            if m:
                current = [int(m.group(1)), [line]]
                found.append(current)
            elif line.startswith("- ") or line.startswith("#"):
                current = None
            elif current is not None:
                current[1].append(line)
        numbers = [n for n, _ in found]
        if not found:
            self.fail("no numbered properties (- **PT-n. ...**)")
        if numbers != list(range(1, len(numbers) + 1)):
            self.fail(f"properties are numbered {numbers}, expected PT-1 upwards without gaps")
        for n, body in found:
            if "Check:" not in " ".join(body):
                self.fail(f"PT-{n} does not say how a test checks it ('Check:')")
        defined = set(numbers)
        for ref in sorted({int(x) for x in PT_REF_RE.findall(self.text)}):
            if ref not in defined:
                self.fail(f"PT-{ref} is cited but not defined")

    def check_conflicts(self):
        lines = self.section("Conflicts")
        if lines is None:
            return
        body = " ".join(lines).lower()
        for spec in ("spec 02", "spec 03", "spec 04"):
            if spec not in body:
                self.fail(f"the conflicts section does not name {spec}")


def check_text(text):
    """All gaps found in the text of the specification (empty when complete)."""
    return Checker(text).run()


def main(argv):
    path = Path(argv[1]) if len(argv) > 1 else DEFAULT_SPEC
    if not path.exists():
        print(f"MISSING: {path}")
        return 1
    errors = check_text(path.read_text(encoding="utf-8"))
    for e in errors:
        print("GAP: " + e)
    if errors:
        print(f"{len(errors)} gap(s) in {path}")
        return 1
    print(f"Private transaction complete: {path.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
