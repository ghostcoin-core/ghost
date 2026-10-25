# Throughput and inclusion delay of the aggregator fleet

This page models how many private reveals an aggregator fleet folds into bundles per block, and how long a reveal waits from arrival to inclusion, at 500 and then 3,500 private reveals per block beside the public stream, with bursts, machine failures, the largest aggregator disappearing and streams of invalid proofs (all modeled). It is part of the first stage (feasibility and security) of the scale work, follows the rules of designs.md (rules 4, 5 and 6 above all) and judges against the ceilings of workload.md, which do not change here. The target stays 3,500 private reveals and 3,500 public transactions per block, 10 million of each a day (modeled: the founder's target); the 500 runs are a step toward it, not a substitute for it.

Every figure carries one of the labels of workload.md: measured, modeled or not yet established. Nothing on this page is measured. Every modeled figure is printed by benchmarks/scale/throughput.py, a discrete-event model whose inputs are the `INPUTS` dict at the top of the file, tested by benchmarks/tests/test_scale_throughput.py. The model's generator is seeded (seed 1, modeled: an input), so the commands below reproduce every table of this page exactly:

```sh
python3 benchmarks/scale/throughput.py
python3 benchmarks/tests/test_scale_throughput.py
```

**Result.** With the conversion and merge seconds of architecture (a)'s recursion proxy, which are lower bounds on a real recursive layer (modeled in recursion.md), the 40 machines of workload.md include about 43 of 500 reveals a block and none of 3,500 (modeled). Keeping up with 3,500 a block takes about 2,780 machines (modeled), each of which would also need more than the 128 GiB of memory workload.md proposes (modeled in recursion.md). No fleet size tried, up to ten times the work bound, holds the 5-minute p99 delay ceiling (modeled): one conversion and a merge for each of the 11 levels of the largest aggregator's tree take 166.0 s before the waits for two proof-of-work blocks (modeled). At full use a reveal costs 21.6585 machine-seconds (modeled), which meets the 0.1 US cent ceiling of workload.md only below 0.1662 US dollars a machine-hour (modeled). Private reveals keep being included when the largest aggregator disappears, at the remaining aggregators' capacity (modeled).

## Model

What the model does (benchmarks/scale/throughput.py, every step modeled):

- **Arrivals.** Each 30 s slot brings the stated reveals per block at uniformly random times inside it (modeled: an input), multiplied by the burst factor during a burst. The public stream arrives the same way.
- **Independent aggregators.** Three aggregators, with 40, 35 and 25 percent of the reveals and of the machines (modeled: a stated share; no real market share is established). Each reveal goes to one aggregator by share. Reveals are public, so when an aggregator disappears the others pick up what it held after a failover delay of 30 s (modeled: an input), from public data and with no key or permission of the aggregator that left.
- **Check and conversion.** An aggregator checks every incoming proof, 0.000288 s a machine (modeled: the slowest native verification of 9.23 ms on one thread, spec 07, section 4, spread over the 32 cores of an aggregator machine), and converts each valid reveal into the first recursive layer as soon as it arrives: 7.2194 s a machine (modeled).
- **Merge tree.** At every block an aggregator folds the reveals it holds into one bundle with a binary two-to-one merge tree, an odd proof carried up unmerged: 14.4388 s a merge a machine (modeled). A bundle whose root proof is done before a block is found is included in that block.
- **Where the seconds come from.** The 7.2194 s and 14.4388 s are read from docs/scale/recursion-proxy.jsonl through benchmarks/scale/recursion_costs.py: architecture (a)'s conversion and merge at the counted size, 231.020419 s and 462.040838 s on one thread, divided by 32 cores at perfect speedup (modeled: those records are themselves modeled from measured (proxy) runs, and a proxy is a lower bound). Without those records the model falls back to the 0.3 s ceiling of workload.md, labelled an illustrative input whose figure for Ghost is not yet established; the tests use that 0.3 s only as such an input (modeled).
- **Machines.** One task a machine at a time, oldest work first. A failed machine is a busy one: its task restarts on another machine of the same aggregator and the work done is lost (modeled).
- **Blocks.** Found at exponential intervals with a 30 s mean, as proof of work finds them (modeled). A 30 s block time is an average, not a proving window: a reveal waits for the block after its arrival to be bundled and for the block after its root proof to be included (modeled).
- **One bundle per aggregator per block.** Smaller bundles would cut the tree's depth and so the delay, but every bundle publishes a root proof in the block, and public-encoding.md already counts three root proofs of 1,310,720 bytes against the message cap (modeled there), so more bundles spend block bytes the public stream needs.
- **Invalid proofs.** A stream of invalid recursive proofs at a stated rate, from many identities: each costs a check. A stated fraction fail late: they pass the check (a valid proof whose marker another transaction spends first), are converted and merged, and when the bundle meets executed state every merge on their paths to the root is done again without them. Neither kind is ever included (modeled, tested).
- **Public stream.** In the raw encoding public transactions need no fleet; a block carries at most the 1,429 public transactions that fit beside the private parts under the message cap (modeled in public-encoding.md), first come first served. The proof encoding would put the proving of 3,500 ML-DSA-44 verifications a block on a fleet, but its seconds are not yet established, so the model leaves them out. The public mix (2,450 transfers, 700 commits and 350 contract calls a block, modeled from the proposed shares of workload.md, which are not yet established) changes no fleet figure for that reason (modeled).

What it reports, each apart from the others (modeled):

- sustained reveals included per block, over the last two thirds of the arrival window, past the pipeline's start;
- the backlog at every block: reveals arrived and not yet included, in flight included;
- p50 and p99 transaction-to-inclusion delay (modeled: nearest rank, every included reveal), reported apart from throughput;
- time to drain after an overload: from the end of a burst until the backlog is back to its highest level before the burst (modeled);
- machine-seconds spent on honest work, invalid checks, late failures and work lost to failures;
- cost per reveal: machines times the price a machine-hour times the hours run, over the reveals included, idle time included (modeled);
- the fleet search: the work bound (machine-seconds of one block's reveals over 30 s), then the work bound times 1, 1.1, 1.25, 1.5, 2, 3, 5 and 10 (modeled), with whether each keeps up (everything included, sustained within 10 percent of the arrivals, a backlog at the end of the arrivals no larger than 10 blocks of arrivals) and whether it holds the p99 ceiling.

The arithmetic of rule 4, checked by the tests: 3,499 merges at 0.3 s are 1,049.7 machine-seconds and need at least 26.2425 s on 40 machines for a batch that arrives at once (modeled, with 0.3 s an illustrative input not yet established for Ghost); the model's schedule folds that batch in at most 28.2 s and never under 26.2425 s, and no reveal's delay is below that minimum wall time (modeled, tested).

Each run: 80 blocks of arrivals, run on until the backlog is empty or 600 more blocks pass (modeled: inputs).

## Results at 500 and 3,500 per block

The 40 machines of workload.md (modeled):

| Scenario | Machines | Offered a block | Sustained a block | Backlog at the end of arrivals | p50 delay, modeled | p99 delay, modeled | Drain after overload | Cost a reveal |
|---|---|---|---|---|---|---|---|---|
| 500: the 40 machines of workload.md | 40 | 500 | 42.9 (modeled) | 36,479 (modeled) | 1,414.5 s (modeled) | 2,764.1 s (modeled) | none (modeled) | 1.3374 US cents (modeled) |
| 3,500: the 40 machines of workload.md | 40 | 3,500 | 0.0 (modeled) | 275,136 (modeled) | none (modeled) | none (modeled) | none (modeled) | none (modeled) |

At 3,500 a block the 40 machines include nothing within the run: the backlog grows by the whole arrival rate and the delay has no bound (modeled). At 500 a block they sustain about 43 a block and the backlog grows without bound (modeled).

At 500 a block (modeled):

- work bound: 361 machines (modeled)
- delay floor with unlimited machines, before the waits for blocks: 122.7 s (modeled: a check, a conversion and 8 merges for the largest aggregator's 200 reveals)
- fewest machines tried that keep up: 361 (modeled)
- fewest machines tried that hold the 300 s p99 ceiling: none (modeled)

| Machines | Multiple of the work bound | Sustained a block | Backlog at the end of arrivals | p50 delay, modeled | p99 delay, modeled | Keeps up | Holds the p99 ceiling | Cost a reveal |
|---|---|---|---|---|---|---|---|---|
| 361 | 1.00 | 499.9 (modeled) | 3,308 (modeled) | 230.0 s (modeled) | 317.5 s (modeled) | yes (modeled) | no (modeled) | 1.3158 US cents (modeled) |
| 398 | 1.10 | 477.5 (modeled) | 3,029 (modeled) | 197.1 s (modeled) | 306.4 s (modeled) | yes (modeled) | no (modeled) | 1.4234 US cents (modeled) |
| 452 | 1.25 | 481.4 (modeled) | 2,825 (modeled) | 189.4 s (modeled) | 306.4 s (modeled) | yes (modeled) | no (modeled) | 1.6165 US cents (modeled) |
| 542 | 1.50 | 481.4 (modeled) | 2,825 (modeled) | 186.0 s (modeled) | 306.4 s (modeled) | yes (modeled) | no (modeled) | 1.9384 US cents (modeled) |
| 722 | 2.00 | 481.4 (modeled) | 2,825 (modeled) | 181.6 s (modeled) | 304.3 s (modeled) | yes (modeled) | no (modeled) | 2.5822 US cents (modeled) |
| 1,083 | 3.00 | 481.4 (modeled) | 2,825 (modeled) | 180.8 s (modeled) | 302.0 s (modeled) | yes (modeled) | no (modeled) | 3.8733 US cents (modeled) |
| 1,805 | 5.00 | 481.4 (modeled) | 2,825 (modeled) | 180.8 s (modeled) | 302.0 s (modeled) | yes (modeled) | no (modeled) | 6.4554 US cents (modeled) |
| 3,610 | 10.00 | 481.4 (modeled) | 2,825 (modeled) | 180.8 s (modeled) | 302.0 s (modeled) | yes (modeled) | no (modeled) | 12.9109 US cents (modeled) |

At 3,500 a block (modeled):

- work bound: 2,527 machines (modeled)
- delay floor with unlimited machines, before the waits for blocks: 166.0 s (modeled: a check, a conversion and 11 merges for the largest aggregator's 1,400 reveals)
- fewest machines tried that keep up: 2,780 (modeled)
- fewest machines tried that hold the 300 s p99 ceiling: none (modeled)

| Machines | Multiple of the work bound | Sustained a block | Backlog at the end of arrivals | p50 delay, modeled | p99 delay, modeled | Keeps up | Holds the p99 ceiling | Cost a reveal |
|---|---|---|---|---|---|---|---|---|
| 2,527 | 1.00 | 3,193.3 (modeled) | 40,309 (modeled) | 288.1 s (modeled) | 417.1 s (modeled) | no (modeled) | no (modeled) | 1.3335 US cents (modeled) |
| 2,780 | 1.10 | 3,330.6 (modeled) | 30,008 (modeled) | 250.2 s (modeled) | 392.8 s (modeled) | yes (modeled) | no (modeled) | 1.4244 US cents (modeled) |
| 3,159 | 1.25 | 3,434.9 (modeled) | 22,431 (modeled) | 238.6 s (modeled) | 392.8 s (modeled) | yes (modeled) | no (modeled) | 1.6186 US cents (modeled) |
| 3,791 | 1.50 | 3,434.9 (modeled) | 22,431 (modeled) | 232.1 s (modeled) | 356.2 s (modeled) | yes (modeled) | no (modeled) | 1.9425 US cents (modeled) |
| 5,054 | 2.00 | 3,434.9 (modeled) | 22,431 (modeled) | 228.3 s (modeled) | 356.2 s (modeled) | yes (modeled) | no (modeled) | 2.5896 US cents (modeled) |
| 7,581 | 3.00 | 3,434.9 (modeled) | 22,431 (modeled) | 226.8 s (modeled) | 356.2 s (modeled) | yes (modeled) | no (modeled) | 3.8844 US cents (modeled) |
| 12,635 | 5.00 | 3,434.9 (modeled) | 22,431 (modeled) | 226.8 s (modeled) | 356.2 s (modeled) | yes (modeled) | no (modeled) | 6.4741 US cents (modeled) |
| 25,270 | 10.00 | 3,434.9 (modeled) | 22,431 (modeled) | 226.8 s (modeled) | 356.2 s (modeled) | yes (modeled) | no (modeled) | 12.9481 US cents (modeled) |

Throughput and delay part ways (modeled): past about twice the work bound more machines change neither the sustained figure nor the p99, because the delay is then set by the critical path of the tree and the waits for blocks, not by machines. The sustained figures sit within 10 percent of the arrivals because random block times move the count of included reveals in a window (modeled); the backlog at the end of the arrivals, about 6 to 9 blocks of arrivals at the fleets that keep up, is the reveals in flight (modeled). Against the private delay ceiling of 5 minutes at the 99th percentile (a proposal of workload.md, not yet established): missed at every fleet tried, by 2.0 s at 500 a block and 56.2 s at 3,500 (modeled).

Public stream at 2,780 machines and 3,500 a block, raw encoding (modeled): a capacity of 1,429 a block against the 3,500 offered, 1,429.0 included a block, a backlog of 168,855 at the end of the arrivals and a p99 delay of 1,659.4 s against the 2-minute public ceiling of workload.md (modeled). The public backlog grows without bound in the raw encoding (modeled); public-encoding.md gives the encoding that fits.

## Bursts and failures

At the fewest machines that keep up (361 and 2,780, modeled):

| Scenario | Machines | Offered a block | Sustained a block | Backlog at the end of arrivals | p50 delay, modeled | p99 delay, modeled | Drain after overload | Cost a reveal |
|---|---|---|---|---|---|---|---|---|
| 500: steady, 361 machines | 361 | 500 | 499.9 (modeled) | 3,308 (modeled) | 230.0 s (modeled) | 317.5 s (modeled) | 224.2 s (modeled) | 1.3158 US cents (modeled) |
| 500: twice the target for 10 blocks | 361 | 500 | 511.4 (modeled) | 7,337 (modeled) | 467.1 s (modeled) | 606.9 s (modeled) | 2,703.6 s (modeled) | 1.2605 US cents (modeled) |
| 500: half the largest aggregator's machines fail at 600 s | 361 | 500 | 398.5 (modeled) | 8,726 (modeled) | 255.1 s (modeled) | 1,982.9 s (modeled) | 2,028.6 s (modeled) | 2.2204 US cents (modeled) |
| 500: the largest aggregator disappears at 600 s | 361 | 500 | 320.5 (modeled) | 15,943 (modeled) | 912.9 s (modeled) | 1,620.5 s (modeled) | 1,596.4 s (modeled) | 2.0038 US cents (modeled) |
| 3,500: steady, 2,780 machines | 2,780 | 3,500 | 3,330.6 (modeled) | 30,008 (modeled) | 250.2 s (modeled) | 392.8 s (modeled) | 182.4 s (modeled) | 1.4244 US cents (modeled) |
| 3,500: twice the target for 10 blocks | 2,780 | 3,500 | 3,810.5 (modeled) | 33,596 (modeled) | 385.1 s (modeled) | 621.4 s (modeled) | 2,458.7 s (modeled) | 1.3043 US cents (modeled) |
| 3,500: half the largest aggregator's machines fail at 600 s | 2,780 | 3,500 | 2,755.8 (modeled) | 60,663 (modeled) | 275.0 s (modeled) | 1,691.0 s (modeled) | 1,713.0 s (modeled) | 2.2687 US cents (modeled) |
| 3,500: the largest aggregator disappears at 600 s | 2,780 | 3,500 | 2,387.0 (modeled) | 92,392 (modeled) | 686.2 s (modeled) | 1,314.5 s (modeled) | 1,256.7 s (modeled) | 2.0170 US cents (modeled) |

The steady rows' drain is the time to empty the pipeline after the arrivals stop; the burst rows' drain is the time from the end of the burst until the backlog is back to its level before it (modeled).

- **Bursts.** Twice the arrivals for 10 blocks (5 minutes) at the fleet that just keeps up take 2,458.7 s to drain at 3,500 a block, and the p99 rises from 392.8 s to 621.4 s while the p50 rises from 250.2 s to 385.1 s (modeled). The recovery ceiling of workload.md (back to the normal delay within an hour after twice the target for an hour, a proposal, not yet established) is not run here: an hour of twice the target needs about twice the fleet that keeps up, by the work bound (modeled), and the run is `burst_blocks` set to 120 at that fleet (not yet established: not run).
- **Machine failures.** Half the largest aggregator's machines failing at 600 s loses 1,668.1 machine-seconds of work in flight at 3,500 a block and 465.5 at 500 (modeled); the larger cost is the capacity gone for the rest of the run: the p99 rises to 1,691.0 s at 3,500 a block (modeled).
- **The largest aggregator disappears (independent operation, rule 6).** At 3,500 a block, 4,399.9 reveals were included a block in the 5 minutes before it left (catching up included) and 2,435.0 a block from 5 minutes after it left to the end of the arrivals (modeled): inclusion goes on, picked up by the two other aggregators from public data after the 30 s failover, at their capacity of about 2,310 a block (modeled: their 1,668 machines over 21.6585 machine-seconds a reveal, times 30 s), which is below the arrivals, so the backlog then grows (modeled). At 500 a block the same figures are 486.2 before and 324.3 after (modeled). The tests check that every 5-minute window after the failover still includes reveals and that the rate after it is the remaining aggregators' capacity (modeled, tested). What the model does not show: that the remaining aggregators would take the work (their payment is not yet established, designs.md private bundle requirement 6), and censorship by an aggregator that stays (not yet established; in the model a censored reveal is like a stranded one only if it is resubmitted to another aggregator).

## Adversarial traffic

At the fewest machines that keep up (modeled):

| Scenario | Machines | Offered a block | Sustained a block | Backlog at the end of arrivals | p50 delay, modeled | p99 delay, modeled | Drain after overload | Cost a reveal |
|---|---|---|---|---|---|---|---|---|
| 500: invalid proofs at ten times the target | 361 | 500 | 523.6 (modeled) | 3,112 (modeled) | 242.6 s (modeled) | 355.2 s (modeled) | 205.8 s (modeled) | 1.3065 US cents (modeled) |
| 500: late failures at a tenth of the target | 361 | 500 | 332.2 (modeled) | 14,600 (modeled) | 759.7 s (modeled) | 1,326.0 s (modeled) | 1,256.0 s (modeled) | 1.8331 US cents (modeled) |
| 3,500: invalid proofs at ten times the target | 2,780 | 3,500 | 3,597.2 (modeled) | 23,695 (modeled) | 239.2 s (modeled) | 342.6 s (modeled) | 197.5 s (modeled) | 1.4327 US cents (modeled) |
| 3,500: late failures at a tenth of the target | 2,780 | 3,500 | 2,935.0 (modeled) | 85,225 (modeled) | 687.6 s (modeled) | 1,046.7 s (modeled) | 1,008.6 s (modeled) | 1.8801 US cents (modeled) |

- **Invalid proofs that fail the check.** 35,000 invalid proofs a block, ten times the target, cost 807.6 machine-seconds of checks over the run against 6,061,031.4 of honest work at 3,500 a block (modeled), about 0.013 percent: at 0.000288 s a check they are cheap to refuse, and the change in delay against the steady row is within what the random block times move it (modeled). The tests show the mechanism with a dearer check: invalid proofs then take fleet capacity and raise the p99 (modeled, tested). Their bound is the check's cost times their rate, a total a fleet can provision for (modeled).
- **Late failures.** 350 late failures a block, a tenth of the target, cost 1,968,403.1 machine-seconds against 6,464,927.3 honest at 3,500 a block (modeled), about 70.3 machine-seconds each (modeled: over 28,000 late failures), and raise the p99 from 392.8 s to 1,046.7 s with a growing backlog (modeled). One late failure costs at most a check, a conversion, its own merge and a merge again on each of the 11 levels above it, 180.49 machine-seconds (modeled). This is the denial-of-service bound that matters: a correctly sized reveal with a plausible marker and fee that fails only at execution costs the fleet as much as an honest one, and more.
- **What bounds the attacker** (rule 5): each late failure needs a valid reveal proof, 13.15 s warm on the emulated mid-range phone (measured, emulated, not a real device, workload.md) or far less on a server (not yet established), and a marker another transaction spends first, which takes a coin the attacker spends; whether a reveal that fails late pays any fee is not yet established, so neither is the attacker's cost per late failure. Queue growth: the model has a per-aggregator bound on reveals held unchecked or unconverted, past which new ones are dropped and counted (modeled, tested), with no bound set by default; per-peer budgets, memory and the node's own verification work for bundles that fail late are not yet established (designs.md, private bundle requirement 10).

## Fleet size and cost

| Figure | At 500 a block (modeled) | At 3,500 a block (modeled) | Label |
|---|---|---|---|
| Machine-seconds a reveal: a check, a conversion and a merge | 21.6585 | 21.6585 | modeled, from the proxy: a lower bound |
| Work bound | 361 machines | 2,527 machines | modeled |
| Fewest machines tried that keep up | 361 | 2,780 | modeled |
| Against the 40 machines of workload.md | 9 times as many | 69.5 times as many | modeled |
| Fewest machines tried that hold the 5-minute p99 | none up to 3,610 | none up to 25,270 | modeled |
| Delay floor with unlimited machines, before the waits for blocks | 122.7 s | 166.0 s | modeled |
| Cost a reveal at full use, at 2 US dollars a machine-hour | 1.2032 US cents | 1.2032 US cents | modeled; the price is an illustrative input, not yet established |
| Cost a reveal at the fleet that keeps up, idle time included | 1.3158 US cents | 1.4244 US cents | modeled, at the same illustrative price |
| Highest machine-hour price that meets 0.1 US cents a reveal at full use | 0.1662 US dollars | 0.1662 US dollars | modeled |
| Memory a merge needs on one machine | more than 164.875 GiB | more than 164.875 GiB | modeled in recursion.md, against 128 GiB |

What these figures rest on (modeled): architecture (a)'s proxy, which proves only a verifier's Keccak-f\[1600\] permutations, so every fleet size and cost above is a lower bound for (a); a real recursive layer costs more, which only raises them. The fleet runs on machines with enough memory for a merge, which the 128 GiB of workload.md is not (modeled in recursion.md). No price for a 32-core machine of that memory is stated anywhere in the repository, so the 2 US dollars a machine-hour is an illustrative input (not yet established); the break-even price of 0.1662 US dollars a machine-hour does not depend on it (modeled). Architectures (b) and (c) have no recursion seconds (not yet established in recursion.md), so no fleet for them can be modeled.

What is not yet established, and what would establish it:

- The seconds of a real recursive conversion and merge of any architecture, on named hardware (recursion.md lists the commands); the model reads them from docs/scale/recursion-proxy.jsonl as soon as a measured record is there.
- Multi-threaded proving at the per-machine figures above (not yet established: recursion.md, item 4).
- The price of an aggregator machine-hour, from a named cloud offer of a machine with the memory a merge needs.
- An hour-long burst at twice the target, the input change named under Bursts and failures.
- The proving seconds of the public signature proof (public-encoding.md), which would add its fleet to this one.
- Block propagation time and the node's verification of each bundle's root inside the 3,000 ms budget of spec 07, section 4 (not yet established: stage 3).
