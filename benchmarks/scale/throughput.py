"""Throughput and transaction-to-inclusion delay of an aggregator fleet folding private reveals.

A discrete-event model, not a benchmark. Private reveals arrive over time and each is picked
up by one of several independent aggregators, in proportion to a stated share. An aggregator
checks every proof it receives, converts each valid reveal into the first recursive layer as
soon as it arrives, and at every block folds the reveals it holds into one bundle with a
binary two-to-one merge tree (an odd proof is carried up unmerged). A bundle whose root proof
is done is included in the next block found. Tasks run on the aggregator's machines, one task
a machine, oldest work first. Blocks are found at random intervals of the stated mean.

What it reports, apart from one another: the sustained reveals included per block, the
backlog at every block, the p50 and p99 transaction-to-inclusion delay, the time to drain
after an overload, the machine-seconds spent (honest, wasted by failures and spent on invalid
proofs), the cost per reveal at a stated machine price, and the public transactions included
per block under the public encoding's message-cap capacity. Scenarios add bursts, machines
that fail, the largest aggregator disappearing, and a stream of invalid proofs, some of which
fail only late, after they were converted and merged.

Merge and conversion seconds come from docs/scale/recursion-proxy.jsonl through
recursion_costs.py when its records are present: they are modeled from measured (proxy)
records, a lower bound on a real recursive layer. Without records the 0.3 s ceiling of
workload.md stands in, an illustrative input whose figure for Ghost is not yet established.

Every figure is modeled. The random generator is seeded; one seed gives one result.

Usage: python3 benchmarks/scale/throughput.py
"""

import heapq
import math
import random
import sys
from collections import deque
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import budget  # noqa: E402
import public_encoding  # noqa: E402
import recursion_costs  # noqa: E402

ARCHITECTURE = "keccak-leaves-keccak-aggregation"
ILLUSTRATIVE = "not yet established (illustrative input)"

INPUTS = {
    # The target per block (workload.md); never changed by the model.
    "reveals_per_block": budget.INPUTS["private_per_block"],
    "public_per_block": budget.INPUTS["public_per_block"],
    # The public mix of workload.md, a proposal for the founder.
    "public_mix": {"plain transfer": 0.7, "commit": 0.2, "contract call": 0.1},
    # Public transactions a block can carry: "raw" or "proof" (public_encoding.py).
    "public_encoding": "raw",
    "block_seconds": budget.INPUTS["block_seconds"],
    # Exponential block intervals around the mean, as proof-of-work finds them.
    "random_block_times": True,
    # Blocks of arrivals, and the most blocks run after them to drain.
    "blocks": 60,
    "drain_limit_blocks": 600,
    # Seconds of each block over which its arrivals spread; None: the whole block.
    "arrival_window_seconds": None,
    # Seconds of one proof on one aggregator machine. None: from the recursion records.
    "conversion_seconds": None,
    "merge_seconds": None,
    # Checking one incoming reveal proof on one machine: the slowest native verification,
    # 9.23 ms on one thread (spec 07, section 4), spread over the machine's 32 cores.
    "check_seconds": 0.00923 / recursion_costs.INPUTS["cores_per_machine"],
    "machines": budget.INPUTS["machines"],
    # Independent aggregators and the share of reveals and machines each holds.
    "aggregator_shares": (0.4, 0.35, 0.25),
    # US dollars per machine-hour: no price is stated anywhere in the repository.
    "price_per_machine_hour": 2.0,
    # Arrivals multiplied by burst_factor for burst_blocks blocks from burst_start_block.
    "burst_factor": 1.0,
    "burst_start_block": 0,
    "burst_blocks": 0,
    # Machines that fail: (seconds, aggregator index, machines lost). Their tasks restart.
    "machine_failures": (),
    # An aggregator that disappears: (seconds, aggregator index), or None. The reveals it
    # held are picked up by the others failover_seconds later, from public data.
    "disappear": None,
    "failover_seconds": 30,
    # Invalid recursive proofs a block, from many identities, and the fraction of them that
    # pass the check and fail only late, after conversion and merging (a marker spent by
    # another transaction first); such a bundle's affected paths are merged again.
    "invalid_per_block": 0,
    "late_failure_fraction": 0.0,
    # Most reveals and proofs an aggregator holds unchecked or unconverted; past it new
    # ones are dropped and counted. None: no bound.
    "queue_limit": None,
    # The private delay ceiling of workload.md: 5 minutes at the 99th percentile.
    "delay_ceiling_seconds": 300,
    "seed": 1,
}


def layer_costs(records_path=None, architecture=ARCHITECTURE):
    """Seconds of a conversion and a merge on one aggregator machine, with their label.

    From the recursion records when present and valid; otherwise the 0.3 s ceiling as an
    illustrative input.
    """
    path = recursion_costs.RECORDS if records_path is None else Path(records_path)
    try:
        records = recursion_costs.load(path)
    except (OSError, ValueError):
        records = []
    figures = recursion_costs.fleet(records)[architecture]
    out = {}
    for layer in ("conversion", "merge"):
        f = figures[layer]
        if f is None:
            out[layer] = {"seconds": float(budget.INPUTS["merge_seconds"]), "label": ILLUSTRATIVE, "source": None}
        else:
            out[layer] = {
                "seconds": f["single_proof_seconds"],
                "label": f"modeled from a {f['label']} record, a lower bound",
                "source": str(path),
            }
    return out


def resolved(inputs=None):
    """The inputs with conversion and merge seconds filled in, and their labels."""
    inputs = dict(INPUTS if inputs is None else inputs)
    labels = {}
    costs = None
    for layer in ("conversion", "merge"):
        key = f"{layer}_seconds"
        if inputs.get(key) is None:
            costs = costs or layer_costs()
            inputs[key] = costs[layer]["seconds"]
            labels[layer] = costs[layer]["label"]
        else:
            labels[layer] = "input"
    inputs["cost_labels"] = labels
    return inputs


# Arithmetic of one batch.

def batch_machine_seconds(merges, merge_seconds):
    return budget.machine_seconds(merges, merge_seconds)


def batch_min_wall_seconds(merges, merge_seconds, machines):
    """No schedule on that many machines folds a batch that arrives at once sooner."""
    return budget.min_wall_seconds(merges, merge_seconds, machines)


def tree_levels(proofs):
    return budget.merge_tree_levels(proofs)


def bundle_floor_seconds(proofs, machines, conversion_seconds, merge_seconds, check_seconds=0.0):
    """Least wall time from a bundle's reveals all arriving at once to its root proof: the larger
    of the work bound and the critical path (a conversion and one merge a level)."""
    if proofs <= 0:
        return 0.0
    first = check_seconds + conversion_seconds
    work = (proofs * first + (proofs - 1) * merge_seconds) / machines
    path = first + tree_levels(proofs) * merge_seconds
    return max(work, path)


def fold_batch(proofs, machines, merge_seconds, conversion_seconds=0.0):
    """Fold a batch that arrives at once on idle machines with the binary merge tree, oldest
    task first: (wall seconds to the root proof, machine-seconds spent)."""
    if proofs <= 0:
        return 0.0, 0.0
    merge_seconds, conversion_seconds = float(merge_seconds), float(conversion_seconds)
    tree = _Bundle([_Reveal(0.0, True, False) for _ in range(proofs)], None)
    ready = list(range(proofs))
    events = []
    free, now, busy = machines, 0.0, 0.0
    while ready or events:
        while ready and free:
            node = heapq.heappop(ready)
            seconds = conversion_seconds if node < proofs else merge_seconds
            free -= 1
            busy += seconds
            heapq.heappush(events, (now + seconds, node))
        now, node = heapq.heappop(events)
        free += 1
        if node == tree.root:
            break
        parent = tree.parent[node]
        tree.need[parent] -= 1
        if tree.need[parent] == 0:
            heapq.heappush(ready, parent)
    return now, busy


def machine_seconds_per_reveal(inputs):
    """Fleet time one reveal costs in a large bundle: a check, a conversion and a merge."""
    return inputs["check_seconds"] + inputs["conversion_seconds"] + inputs["merge_seconds"]


def work_bound_machines(inputs, per_block=None):
    """Fewest machines whose time a block covers the work of one block's reveals."""
    per_block = inputs["reveals_per_block"] if per_block is None else per_block
    work = per_block * (inputs["check_seconds"] + inputs["conversion_seconds"]) + max(per_block - 1, 0) * inputs["merge_seconds"]
    return math.ceil(work / inputs["block_seconds"])


def split_machines(machines, shares):
    """Machines of each aggregator by its share; the remainder goes to the largest."""
    total = sum(shares)
    out = [int(machines * s / total) for s in shares]
    out[max(range(len(shares)), key=lambda i: shares[i])] += machines - sum(out)
    return out


def percentile(values, p):
    """Nearest-rank percentile of a sorted list."""
    if not values:
        return None
    rank = max(math.ceil(p / 100 * len(values)), 1)
    return values[rank - 1]


# The discrete-event model.

class _Reveal:
    __slots__ = ("arrival", "honest", "late", "converted", "leaf", "agg")

    def __init__(self, arrival, honest, late):
        self.arrival = arrival
        self.honest = honest
        self.late = late
        self.converted = False
        self.leaf = None
        self.agg = None


class _Bundle:
    __slots__ = ("reveals", "parent", "need", "root", "level_merges", "key", "late", "stages", "left", "agg")

    def __init__(self, reveals, agg):
        self.reveals = reveals
        self.agg = agg
        self.key = min(r.arrival for r in reveals)
        self.late = sum(1 for r in reveals if r.late)
        self.stages = None
        self.left = 0
        n = len(reveals)
        self.parent = [None] * n
        self.need = [0] * n
        self.level_merges = []
        level = list(range(n))
        while len(level) > 1:
            nxt = []
            for i in range(0, len(level) - 1, 2):
                node = len(self.parent)
                self.parent.append(None)
                self.need.append(2)
                self.parent[level[i]] = node
                self.parent[level[i + 1]] = node
                nxt.append(node)
            if len(level) % 2:
                nxt.append(level[-1])
            self.level_merges.append(len(level) // 2)
            level = nxt
        self.root = level[0]


class _Aggregator:
    def __init__(self, index, machines, share):
        self.index = index
        self.share = share
        self.alive = True
        self.machines = machines
        self.running = {}
        self.ready = []
        self.pending = []
        self.bundles = []
        self.done = []
        self.queued = 0
        self.included = 0


class Simulation:
    def __init__(self, inputs=None):
        self.p = resolved(inputs)
        self.rng = random.Random(self.p["seed"])
        self.events = []
        self.seq = 0
        self.now = 0.0
        shares = self.p["aggregator_shares"]
        self.aggs = [_Aggregator(i, m, s) for i, (m, s) in enumerate(zip(split_machines(self.p["machines"], shares), shares))]
        self.delays = []
        self.blocks = []
        self.backlog = []
        self.honest_arrived = 0
        self.honest_included = 0
        self.late_dropped = 0
        self.queue_dropped = {"honest": 0, "invalid": 0}
        self.work = {"honest": 0.0, "invalid": 0.0, "late": 0.0, "wasted": 0.0}
        self.public = {"arrivals": [], "index": 0, "queue": deque(), "delays": [], "included": [], "backlog": []}
        self.public_capacity = public_encoding.public_capacity(self.p["public_encoding"])

    # Events.

    def push(self, time, kind, data=None):
        self.seq += 1
        heapq.heappush(self.events, (time, self.seq, kind, data))

    def factor(self, slot):
        p = self.p
        if p["burst_blocks"] and p["burst_start_block"] <= slot < p["burst_start_block"] + p["burst_blocks"]:
            return p["burst_factor"]
        return 1.0

    def arrivals(self):
        p = self.p
        span = p["block_seconds"]
        # Arrivals of a block spread over its first `window` seconds; 0 sends them at once.
        window = span if p["arrival_window_seconds"] is None else p["arrival_window_seconds"]
        public = []
        for slot in range(p["blocks"]):
            f = self.factor(slot)
            start = slot * span
            for _ in range(round(p["reveals_per_block"] * f)):
                self.push(start + self.rng.random() * window, "arrive", _Reveal(0.0, True, False))
            invalid = round(p["invalid_per_block"] * f)
            for _ in range(invalid):
                late = self.rng.random() < p["late_failure_fraction"]
                self.push(start + self.rng.random() * window, "arrive", _Reveal(0.0, False, late))
            public.extend(start + self.rng.random() * window for _ in range(round(p["public_per_block"] * f)))
        public.sort()
        self.public["arrivals"] = public

    def next_block_interval(self):
        if self.p["random_block_times"]:
            return self.rng.expovariate(1.0 / self.p["block_seconds"])
        return float(self.p["block_seconds"])

    # Routing and tasks.

    def choose(self):
        live = [a for a in self.aggs if a.alive and a.machines > 0]
        if not live:
            return None
        return self.rng.choices(live, weights=[a.share for a in live])[0]

    def admit(self, reveal, agg):
        p = self.p
        if agg is None:
            self.queue_dropped["honest" if reveal.honest else "invalid"] += 1
            return
        if p["queue_limit"] is not None and agg.queued >= p["queue_limit"]:
            self.queue_dropped["honest" if reveal.honest else "invalid"] += 1
            return
        reveal.agg = agg
        agg.queued += 1
        if reveal.honest or reveal.late:
            agg.pending.append(reveal)
            self.enqueue(agg, reveal.arrival, ("conv", p["check_seconds"] + p["conversion_seconds"], reveal, None))
        else:
            self.enqueue(agg, reveal.arrival, ("check", p["check_seconds"], reveal, None))

    def enqueue(self, agg, key, task):
        self.seq += 1
        heapq.heappush(agg.ready, (key, self.seq, task))
        self.dispatch(agg)

    def dispatch(self, agg):
        while agg.alive and agg.ready and len(agg.running) < agg.machines:
            _, token, task = heapq.heappop(agg.ready)
            agg.running[token] = (task, self.now)
            self.push(self.now + task[1], "done", (agg, token))

    def category(self, task):
        kind, _, a, _ = task
        if kind == "check":
            return "invalid"
        if kind == "conv":
            return "honest" if a.honest else "late"
        if kind == "rebuild":
            return "late"
        return "honest"

    def finish(self, agg, token):
        entry = agg.running.pop(token, None)
        if entry is None:
            return
        task, _ = entry
        kind, seconds, a, b = task
        self.work[self.category(task)] += seconds
        if kind == "check":
            agg.queued -= 1
        elif kind == "conv":
            agg.queued -= 1
            a.converted = True
            if a.leaf is not None:
                self.complete(*a.leaf)
        elif kind == "merge":
            self.complete(a, b)
        elif kind == "rebuild":
            self.rebuild_step(a)
        self.dispatch(agg)

    def complete(self, bundle, node):
        if node == bundle.root:
            self.root_done(bundle)
            return
        parent = bundle.parent[node]
        bundle.need[parent] -= 1
        if bundle.need[parent] == 0:
            self.enqueue(bundle.agg, bundle.key, ("merge", self.p["merge_seconds"], bundle, parent))

    def root_done(self, bundle):
        if bundle.late and bundle.stages is None:
            # The late failures are found when the bundle meets executed state: every merge on
            # their paths to the root is done again without them.
            bundle.stages = [min(bundle.late, m) for m in bundle.level_merges if m]
            if bundle.stages:
                self.start_stage(bundle)
                return
        self.ready_bundle(bundle)

    def start_stage(self, bundle):
        count = bundle.stages.pop(0)
        bundle.left = count
        for _ in range(count):
            self.enqueue(bundle.agg, bundle.key, ("rebuild", self.p["merge_seconds"], bundle, None))

    def rebuild_step(self, bundle):
        bundle.left -= 1
        if bundle.left == 0:
            if bundle.stages:
                self.start_stage(bundle)
            else:
                self.ready_bundle(bundle)

    def ready_bundle(self, bundle):
        agg = bundle.agg
        if bundle in agg.bundles:
            agg.bundles.remove(bundle)
            agg.done.append(bundle)

    # Blocks and failures.

    def waiting(self):
        """Honest reveals arrived and neither included nor dropped: the backlog."""
        return self.honest_arrived - self.honest_included - self.queue_dropped["honest"]

    def block(self, index):
        t = self.now
        included = 0
        for agg in self.aggs:
            for bundle in agg.done:
                for r in bundle.reveals:
                    if r.honest:
                        self.delays.append(t - r.arrival)
                        included += 1
                    else:
                        self.late_dropped += 1
                agg.included += sum(1 for r in bundle.reveals if r.honest)
            agg.done = []
        self.honest_included += included
        self.blocks.append((index, t, included))
        self.backlog.append((index, t, self.waiting()))
        self.public_block(t)
        for agg in self.aggs:
            if agg.alive and agg.pending:
                bundle = _Bundle(agg.pending, agg)
                agg.pending = []
                agg.bundles.append(bundle)
                for node, r in enumerate(bundle.reveals):
                    r.leaf = (bundle, node)
                for node, r in enumerate(bundle.reveals):
                    if r.converted:
                        self.complete(bundle, node)

    def public_block(self, t):
        pub = self.public
        arrivals = pub["arrivals"]
        while pub["index"] < len(arrivals) and arrivals[pub["index"]] <= t:
            pub["queue"].append(arrivals[pub["index"]])
            pub["index"] += 1
        take = min(len(pub["queue"]), self.public_capacity)
        for _ in range(take):
            pub["delays"].append(t - pub["queue"].popleft())
        pub["included"].append(take)
        pub["backlog"].append(len(pub["queue"]))

    def fail(self, agg, lost):
        lost = min(lost, agg.machines)
        agg.machines -= lost
        # The failed machines are busy ones: their tasks restart elsewhere in the aggregator.
        tokens = sorted(agg.running, reverse=True)[:lost]
        for token in tokens:
            task, start = agg.running.pop(token)
            self.work["wasted"] += self.now - start
            key = task[2].arrival if task[0] in ("check", "conv") else task[2].key
            self.enqueue(agg, key, task)
        self.dispatch(agg)

    def disappear(self, agg):
        agg.alive = False
        for task, start in agg.running.values():
            self.work["wasted"] += self.now - start
        agg.running = {}
        agg.ready = []
        stranded = list(agg.pending)
        for bundle in agg.bundles + agg.done:
            stranded.extend(bundle.reveals)
        agg.pending, agg.bundles, agg.done, agg.queued = [], [], [], 0
        agg.machines = 0
        for r in stranded:
            r.converted = False
            r.leaf = None
        self.push(self.now + self.p["failover_seconds"], "reroute", stranded)

    def run(self):
        p = self.p
        self.arrivals()
        for time, index, lost in p["machine_failures"]:
            self.push(time, "fail", (index, lost))
        if p["disappear"] is not None:
            self.push(p["disappear"][0], "disappear", p["disappear"][1])
        arrival_end = p["blocks"] * p["block_seconds"]
        block_index = 0
        self.push(self.next_block_interval(), "block", 0)
        while self.events:
            time, _, kind, data = heapq.heappop(self.events)
            self.now = time
            if kind == "arrive":
                data.arrival = time
                if data.honest:
                    self.honest_arrived += 1
                self.admit(data, self.choose())
            elif kind == "done":
                self.finish(*data)
            elif kind == "block":
                self.block(data)
                block_index = data + 1
                over = time >= arrival_end
                if over and (self.waiting() == 0 or block_index * p["block_seconds"] > arrival_end + p["drain_limit_blocks"] * p["block_seconds"]):
                    break
                self.push(time + self.next_block_interval(), "block", block_index)
            elif kind == "fail":
                self.fail(self.aggs[data[0]], data[1])
            elif kind == "disappear":
                self.disappear(self.aggs[data])
            elif kind == "reroute":
                for r in data:
                    self.admit(r, self.choose())
        return self.result(arrival_end)

    # Results.

    def drain_seconds(self, arrival_end):
        p = self.p
        span = p["block_seconds"]
        if p["burst_blocks"] and p["burst_factor"] > 1:
            start = p["burst_start_block"] * span
            end = (p["burst_start_block"] + p["burst_blocks"]) * span
            normal = max((b for _, t, b in self.backlog if t < start), default=0)
        else:
            end, normal = arrival_end, 0
        for _, t, b in self.backlog:
            if t >= end and b <= normal:
                return t - end
        return None

    def result(self, arrival_end):
        p = self.p
        delays = sorted(self.delays)
        window = [n for _, t, n in self.blocks if t <= arrival_end]
        # Sustained throughput: the last two thirds of the arrivals, past the pipeline's start.
        steady = arrival_end / 3
        pub = self.public
        pub_delays = sorted(pub["delays"])
        elapsed = self.blocks[-1][1] if self.blocks else 0.0
        machine_hours = p["machines"] * elapsed / 3600
        cost = p["price_per_machine_hour"] * machine_hours / self.honest_included if self.honest_included else None
        return {
            "inputs": p,
            "blocks": len(self.blocks),
            "blocks_in_window": len(window),
            "sustained_per_block": sum(n for _, t, n in self.blocks if steady <= t < arrival_end) / (arrival_end - steady) * p["block_seconds"],
            "offered_per_block": p["reveals_per_block"],
            "arrived": self.honest_arrived,
            "included": self.honest_included,
            "not_included": self.waiting(),
            "p50_delay": percentile(delays, 50),
            "p99_delay": percentile(delays, 99),
            "min_delay": delays[0] if delays else None,
            "max_delay": delays[-1] if delays else None,
            "backlog": self.backlog,
            "max_backlog": max((b for _, _, b in self.backlog), default=0),
            "backlog_at_window_end": next((b for _, t, b in reversed(self.backlog) if t <= arrival_end), 0),
            "drain_seconds": self.drain_seconds(arrival_end),
            "elapsed_seconds": elapsed,
            "work": dict(self.work),
            "late_dropped": self.late_dropped,
            "queue_dropped": dict(self.queue_dropped),
            "cost_per_reveal": cost,
            "per_aggregator": [a.included for a in self.aggs],
            "included_by_block": self.blocks,
            "public_capacity": self.public_capacity,
            "public_per_block_mix": {k: round(p["public_per_block"] * v) for k, v in p["public_mix"].items()},
            "public_sustained_per_block": sum(pub["included"][: len(window)]) / len(window) if window else 0.0,
            "public_p50_delay": percentile(pub_delays, 50),
            "public_p99_delay": percentile(pub_delays, 99),
            "public_backlog_at_window_end": pub["backlog"][len(window) - 1] if window else 0,
        }


def simulate(inputs=None, **changes):
    """Run the model on INPUTS (or the given inputs) with any changes, and return its result."""
    base = dict(INPUTS if inputs is None else inputs)
    base.update(changes)
    return Simulation(base).run()


def included_rate(result, start, end):
    """Honest reveals included a second in blocks found between start and end."""
    n = sum(k for _, t, k in result["included_by_block"] if start <= t < end)
    return n / (end - start)


STEPS = (1.0, 1.1, 1.25, 1.5, 2.0, 3.0, 5.0, 10.0)


def keeps_up(result):
    """Everything included, sustained throughput within 10 percent of the arrivals (random block
    times move it by about that much over a short run), and a backlog at the end of the arrivals
    no larger than the delay ceiling's worth of arrivals."""
    p = result["inputs"]
    allowed = p["reveals_per_block"] * p["delay_ceiling_seconds"] / p["block_seconds"]
    return (result["not_included"] == 0
            and result["sustained_per_block"] >= 0.9 * p["reveals_per_block"]
            and result["backlog_at_window_end"] <= allowed)


def holds_delay(result):
    return (keeps_up(result) and result["p99_delay"] is not None
            and result["p99_delay"] <= result["inputs"]["delay_ceiling_seconds"])


def fleet_needed(inputs=None, steps=STEPS, **changes):
    """Fleets of the work bound times each step: the fewest that keeps up with the arrivals and
    the fewest whose p99 delay holds the ceiling, each None when no step does, and every run."""
    base = resolved(dict(INPUTS if inputs is None else inputs, **changes))
    floor = work_bound_machines(base)
    out = {"work_bound": floor, "throughput": None, "delay": None, "tried": []}
    for step in steps:
        machines = math.ceil(floor * step)
        r = simulate(base, machines=machines)
        out["tried"].append((machines, r))
        if out["throughput"] is None and keeps_up(r):
            out["throughput"] = machines
        if holds_delay(r):
            out["delay"] = machines
            break
    return out


# The aggregation cost ceiling of workload.md, a proposal: 0.1 US cents a private reveal.
CEILING_CENTS = 0.1


def break_even_price(inputs, ceiling_cents=CEILING_CENTS):
    """Machine-hour price, in US dollars, at which a fully used fleet meets the cost ceiling."""
    return ceiling_cents / 100 * 3600 / machine_seconds_per_reveal(inputs)


def delay_floor_seconds(inputs, share=None):
    """Least delay of the last reveal of the largest aggregator's bundle with unlimited machines:
    a check, a conversion and one merge a level of its tree, before the waits for blocks."""
    share = max(inputs["aggregator_shares"]) / sum(inputs["aggregator_shares"]) if share is None else share
    proofs = math.ceil(inputs["reveals_per_block"] * share)
    return inputs["check_seconds"] + inputs["conversion_seconds"] + tree_levels(proofs) * inputs["merge_seconds"]


# Command line.

def _s(value):
    return "none" if value is None else f"{value:,.1f} s"


def scenario_row(name, r):
    cost = _cents(r)
    return (
        f"| {name} | {r['inputs']['machines']:,} | {r['offered_per_block']:,} | {r['sustained_per_block']:,.1f} (modeled) "
        f"| {r['backlog_at_window_end']:,} (modeled) | {_s(r['p50_delay'])} (modeled) | {_s(r['p99_delay'])} (modeled) "
        f"| {_s(r['drain_seconds'])} (modeled) | {cost} (modeled) |"
    )


HEADER = [
    "| Scenario | Machines | Offered a block | Sustained a block | Backlog at the end of arrivals | p50 delay, modeled | p99 delay, modeled | Drain after overload | Cost a reveal |",
    "|---|---|---|---|---|---|---|---|---|",
]


def report(quick=False):
    base = resolved()
    costs = base["cost_labels"]
    lines = [
        f"Conversion {base['conversion_seconds']:.4f} s a machine ({costs['conversion']})",
        f"Merge {base['merge_seconds']:.4f} s a machine ({costs['merge']})",
        f"Check {base['check_seconds']:.6f} s a machine (modeled from spec 07)",
        "",
    ]
    blocks = 30 if quick else 80
    span = base["block_seconds"]
    end = blocks * span
    price = base["price_per_machine_hour"]
    rows, notes = [], []
    for per_block in (500, 3_500):
        common = dict(reveals_per_block=per_block, blocks=blocks)
        sized = dict(base, **common)
        fleet = fleet_needed(base, **common)
        floor = fleet["work_bound"]
        lines += [
            f"At {per_block:,} a block:",
            f"- work bound: {floor:,} machines (modeled)",
            f"- delay floor with unlimited machines, before the waits for blocks: {delay_floor_seconds(sized):,.1f} s (modeled)",
            f"- machine-seconds a reveal: {machine_seconds_per_reveal(sized):,.4f}, at full use "
            f"{machine_seconds_per_reveal(sized) * price / 3600 * 100:,.4f} US cents a reveal (modeled)",
            f"- highest machine-hour price at which full use meets {CEILING_CENTS} US cents a reveal: "
            f"{break_even_price(sized):,.4f} US dollars (modeled)",
            f"- fewest machines tried that keep up: {fleet['throughput'] or 'none'} (modeled)",
            f"- fewest machines tried that hold the {base['delay_ceiling_seconds']} s p99 ceiling: {fleet['delay'] or 'none'} (modeled)",
            "",
            "| Machines | Multiple of the work bound | Sustained a block | Backlog at the end of arrivals | p50 delay, modeled | p99 delay, modeled | Keeps up | Holds the p99 ceiling | Cost a reveal |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
        for machines, r in fleet["tried"]:
            lines.append(
                f"| {machines:,} | {machines / floor:,.2f} | {r['sustained_per_block']:,.1f} (modeled) "
                f"| {r['backlog_at_window_end']:,} (modeled) | {_s(r['p50_delay'])} (modeled) | {_s(r['p99_delay'])} (modeled) "
                f"| {'yes' if keeps_up(r) else 'no'} (modeled) | {'yes' if holds_delay(r) else 'no'} (modeled) "
                f"| {_cents(r)} (modeled) |"
            )
        lines.append("")
        held = fleet["throughput"] or fleet["tried"][-1][0]
        at = dict(common, machines=held)
        largest = split_machines(held, base["aggregator_shares"])[0]
        rows.append((f"{per_block:,}: the 40 machines of workload.md", simulate(base, **common, drain_limit_blocks=20)))
        rows.append((f"{per_block:,}: steady, {held:,} machines", dict(fleet["tried"])[held]))
        rows.append((f"{per_block:,}: twice the target for 10 blocks", simulate(base, **dict(at, blocks=blocks + 20, burst_factor=2.0, burst_start_block=10, burst_blocks=10))))
        rows.append((f"{per_block:,}: half the largest aggregator's machines fail at 600 s", simulate(base, **dict(at, machine_failures=((600.0, 0, largest // 2),)))))
        rows.append((f"{per_block:,}: the largest aggregator disappears at 600 s", simulate(base, **dict(at, disappear=(600.0, 0)))))
        rows.append((f"{per_block:,}: invalid proofs at ten times the target", simulate(base, **dict(at, invalid_per_block=10 * per_block))))
        rows.append((f"{per_block:,}: late failures at a tenth of the target", simulate(base, **dict(at, invalid_per_block=per_block // 10, late_failure_fraction=1.0))))
    lines += HEADER
    lines += [scenario_row(name, r) for name, r in rows]
    for name, r in rows:
        w = r["work"]
        if "disappears" in name:
            before = included_rate(r, 300, 600) * span
            after = included_rate(r, 900, end) * span
            notes.append(f"{name}: {before:,.1f} included a block before, {after:,.1f} after failover (modeled)")
        if "invalid" in name or "late" in name:
            notes.append(
                f"{name}: {w['invalid']:,.1f} machine-seconds on invalid checks, {w['late']:,.1f} on late failures, "
                f"{w['honest']:,.1f} honest (modeled)"
            )
        if "fail at" in name:
            notes.append(f"{name}: {w['wasted']:,.1f} machine-seconds lost to the failure (modeled)")
    r = rows[1][1]
    notes.append(
        f"Public transactions a block under the {base['public_encoding']} encoding: capacity {r['public_capacity']:,}, "
        f"offered {base['public_per_block']:,}, included {r['public_sustained_per_block']:,.1f} a block, "
        f"backlog {r['public_backlog_at_window_end']:,} at the end of arrivals, p99 delay {_s(r['public_p99_delay'])} (modeled)"
    )
    lines.append("")
    lines += notes
    return "\n".join(lines)


def _cents(r):
    return "none" if r["cost_per_reveal"] is None else f"{r['cost_per_reveal'] * 100:,.4f} US cents"


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    print("Modeled from the inputs at the top of benchmarks/scale/throughput.py and docs/scale/recursion-proxy.jsonl")
    print(report(quick="--quick" in args))
    return 0


if __name__ == "__main__":
    sys.exit(main())
