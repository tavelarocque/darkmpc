# Threat model and leakage

This document says who darkmpc protects, from whom, and exactly what each party can learn. It is the contract the security argument and the leakage audit are checked against. Where a choice is still open it says so.

## Who is involved

There are three kinds of party. **Traders** (clients) submit orders and receive their own fills. **Three servers**, run by three independent organisations, hold secret shares and run the matching; the intended deployment is something like the venue, a second market participant and a regulator or auditor, so that no two of them have a reason to collude. **The public** supplies two things everyone sees: the auction schedule (when each batch closes) and the reference midpoint from the lit market, at which every Stage 1 trade executes.

## What the adversary can do

The adversary corrupts at most one server, chosen before the protocol starts (static corruption), and may also control any number of traders, including colluding with them. This is the honest-majority assumption: if two servers pool their shares, they see every order, and nothing in darkmpc prevents that. That limit belongs in the first paragraph of the README, not in a footnote.

In **Phase 1 (semi-honest)**, the corrupt server follows the protocol exactly and tries to learn from everything it sees: its shares, every message it receives, and the timing of both. The requirement is that its view can be produced by a simulator that knows only the public leakage listed below. In **Phase 2 (malicious with abort)**, the corrupt server may deviate arbitrarily: send wrong values, send nothing, or send different things to different parties. The requirement is that any deviation that would change an output is detected before any fill is revealed, and that no honest server ever outputs a wrong value. darkmpc does not promise fairness or guaranteed output delivery: a corrupt server can always force an abort, so it can always deny service for an auction. Abort is also not guaranteed to be unanimous. In the verdict round a corrupt server can tell one honest server "pass" and the other "fail"; the first then waits for messages that never come. It outputs nothing wrong, and a trader who requires both copies of each share rejects the incomplete output, but the guarantee is security with selective abort. These are accepted limitations, not bugs.

**Corrupt traders** can submit anything at all, so every input check has to be done inside the MPC, on shares, without trusting the client. There are two separate attacks to stop.

The first is out-of-range values. A trader can share a size of 2^63 or a minimum fill larger than the size. Beyond producing nonsense, an out-of-range size breaks the soundness of comparison by sign (see decisions.md), which could corrupt other traders' fills. The servers must therefore check every bound the reference's `validate` checks (size in 1..2^40 − 1, minimum fill in 1..size, side a single bit, symbol in the public universe) on shares, and turn an invalid order into a dummy that matches nothing. The submitting trader may be told that its order was rejected. That reveals nothing about anyone else.

The second is inconsistent shares. In replicated sharing each additive share goes to two servers. A malicious trader could give those two servers different values, so the three servers hold pieces that do not describe any single order, and different servers end up computing on different secrets. The fix is cheap: each pair of servers that should hold the same share compares what it received (full copies today; a hash would be cheaper), and any mismatch rejects that order. In Phase 2 this check is mandatory. In Phase 1 traders are still untrusted, so it should be on from the start. Implemented in Milestone 4a step 2, with one honest limitation: a corrupt server can falsely report a mismatch and so get an honest order rejected (censorship). It learns nothing by doing this, and equivocation, telling the two other servers different things, is detected and aborts.

## Outputs, and how a trader reads them

Each trader receives, for each of its orders, the filled quantity. In Stage 2 a filled order also receives its symbol's clearing price, since a fill cannot settle without one; an unfilled order receives 0 in its place, so the output has the same shape either way. Because every share is held by two servers, the trader receives each of the three shares of its fill twice. It checks that both copies agree and rejects the output if not. This stops a single corrupt server from feeding a trader a wrong fill at the last step.

Nothing else is published by default. In particular, per-symbol matched volume is not revealed: it would tell everyone where interest is resting, which is exactly what a dark pool exists to hide. A real venue would later report executed trades to a public tape under regulation. That is outside this prototype and is noted as such.

## What leaks by design

| Leaks | To whom | Why it is acceptable, or how it is limited |
|---|---|---|
| Each trader's own fills | That trader | The purpose of the venue |
| Number of orders in a batch | Servers | Could be hidden by padding every batch to a public size with dummy orders (cost linear in the padding). Not implemented: darkmpc reveals the batch size |
| Which traders submitted, and when | Servers (network metadata) | Inherent to clients connecting. Batching per auction limits timing detail to "submitted before the cutoff" |
| Message sizes | Servers, network observers | Every order has the same fixed-size encoding, so sizes reveal only the order count |
| That an auction aborted | Everyone | An abort in Phase 2 means a server cheated or failed. It is visible by design |
| Rejection of an invalid order | Its submitter | Concerns only that trader's own input |

## What must not leak

To any single server, possibly together with corrupt traders: the symbol, side, size, minimum fill or even existence (beyond the public count) of any honest trader's order; whether any order was eliminated for its minimum fill; whether a symbol hit the pass-cap fail-safe; per-symbol totals; and any unmatched interest. The number of elimination passes is not a leak, because it is always the public cap k.

## Leakage the functionality itself causes

Some leakage survives even a perfect implementation, because the ideal functionality hands each trader its fills, and fills carry information about others. A trader who submits a one-share buy in a symbol learns from a non-zero fill that sell interest exists there. Repeated across symbols and auctions, this is "pinging", a known way of gaming real dark pools, and MPC does nothing about it. The defences are market rules, not cryptography: minimum order sizes, fees, limits on how many orders each trader can send, and minimum fills on large resting orders (which make a one-share probe fail to fill). Stage 2 adds one more: the clearing price is always the limit of some order on the symbol, so a filled trader whose own limit differs learns that another order has exactly that limit. The write-up must say this plainly. darkmpc hides orders from the operator; it does not make a dark pool immune to its own participants.

## Hiding symbol and side

Symbols and sides are secret, as decided on 4 November 2026. That changes the computation. With public symbols, the servers could split the batch into one small auction per symbol. With secret symbols they cannot, so grouping orders by symbol has to happen inside the MPC. There are two families of approaches, and the choice between them is the largest cost decision in Stage 1.

The first fixes a public universe of U symbols and has each trader share its symbol as a one-hot vector of U bits, so per-symbol totals become sums over all orders weighted by those bits. It is simple and has a fixed number of rounds, but its work grows with n × U, which is prohibitive for thousands of symbols and large batches.

The second sorts the batch by symbol obliviously, computes per-symbol totals with segmented prefix sums over the sorted order, matches, and routes each fill back to its original position. Done naively with a sorting network, the work grows with n·log²n comparisons. Shuffle-then-sort techniques first randomly permute the batch so that comparison results can be opened safely, bringing it down towards n·log n. The sort must be stable so that arrival order, and therefore time priority, survives within a symbol.

darkmpc uses the second family: the stable radix sort of Asharov et al. (CCS 2022), which shuffles and then opens only uniformly random permutations, followed by segmented scans. Side is a sort key too, so "volume ahead on the same side" is a segmented prefix sum after sorting. Costs as measured are in `docs/benchmarks.md`.

## What this document does not claim

It does not claim security against two colluding servers, against an adversary that corrupts servers adaptively during an auction, against denial of service, against manipulation of the lit-market midpoint that Stage 1 trades at, or against traffic analysis beyond message counts and sizes. The code is a research prototype and has not been audited. The empirical leakage tests (`crates/auction/tests/audit.rs`, `crates/mpc/tests/leakage.rs`) are checks that catch implementation bugs, as the planted leaks show. They are not evidence of indistinguishability. The security argument is the simulation proof in `leakage-audit.md`, and for malicious servers the proofs in `ring-proofs.md`, which have not been reviewed by an expert.
