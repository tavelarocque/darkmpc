# Stage 2 in MPC: design

Stage 2 adds limit prices. The mechanism, and the reasons for each choice, are in `crates/reference/src/stage2.rs`: maximum executable volume, then minimum surplus (Cboe Europe Periodic Auctions' first two criteria), then the lowest price, with price-then-time priority. This document is the plan for computing it on secret shares without revealing any order's symbol, side, size or limit.

## The key fact

Per symbol, over increasing candidate prices, demand $D$ falls and supply $S$ rises, so $[S \ge D]$ flips from 0 to 1 at most once. The clearing price is then one of exactly two candidates:

- the first price at or after the flip, and
- the first price of the flat stretch of unchanged $(D, S)$ that ends just before the flip.

No search over all prices is needed. The plain implementation of this, `clearing_price_by_crossing`, must equal the brute-force `clearing_price`, and a property test checks that on 200,000 random batches.

The second candidate was not in my first version. The property test produced a two-order counterexample (buy 13 @ 101, sell 1 @ 95: $D$ and $S$ do not change between the two prices, so they tie and the lower one wins). Building the plain version first, and testing it against an oracle, caught a mechanism-level mistake before any cryptography existed.

## Pipeline (as built, `crates/auction/src/stage2.rs`)

1. **Validate** as in Stage 1. The trader shares its limit as 20 bits, like the symbol, so "every bit is 0 or 1" already bounds the limit below $2^{20}$, and the opened validity bit becomes $[0 < \text{size}]\,[0 < \ell]$. A rejected order becomes a dummy of size 0 with limit 1. Limit 1 is the lowest price, where supply consists only of real sells at 1, so the extra candidate price can never win unless price 1 is already a real candidate.
2. **Sort** stably by (symbol, limit): 20 + 13 = 33 key bits, against 14 in Stage 1. The MAC-verified shuffle carries over unchanged.
3. **Runs and symbols.** One batch of comparisons with each predecessor gives both "symbol changed" and "(symbol, limit) changed".
4. **Demand and supply at every order's own limit.** In sorted order, the buys with limit at least $\ell_t$ are the buys from $t$'s run to the end of the symbol, and the sells with limit at most $\ell_t$ are the sells from the start of the symbol to the end of $t$'s run. Each is a symbol sum corrected by a run sum:
   $D_t = (\text{symbol suffix from } t) + (\text{run part before } t)$ and $S_t = (\text{symbol prefix to } t) + (\text{run part after } t)$.
   Every order in a run gets the same $(D, S)$, so no spreading step is needed.
5. **Candidate A** is the first position with $c_t = [S_t \ge D_t] = 1$. Because $c$ is monotone along a symbol, that is $c_t - (1 - \text{start}_t)\,c_{t-1}$: one multiplication, no search.
6. **Candidate B** is the first position of the block of unchanged $(D, S)$ that contains the last position with $S < D$. Along a symbol $D$ falls and $S$ rises, so $(D_{t-1} - D_t) + (S_t - S_{t-1}) \ge 0$, with equality exactly when nothing changed. One comparison with 0 therefore detects a change. Blocks start at a new symbol or a change; a segmented total over blocks marks the block holding the last $S < D$ position, and multiplying by the block-start flag keeps its first position.
7. **Pick.** Both candidates' (exists, volume, surplus, price) are masked and summed over the symbol, so every position holds both. B wins if A does not exist, or B has more volume, or equal volume and no more surplus (B is the lower price, so it wins a full tie). Then $p^*$ and $V^*$ are selected by one multiplication each.
8. **Eligibility** at $p^*$: buys with $\ell \ge p^*$, sells with $\ell \le p^*$, one batch of comparisons.
9. **Allocation without a second sort.** The draft planned a second sort for price priority. It is not needed. Sells are already in priority order: ascending limit, then arrival. For a buy, the eligible volume ahead is the buys at higher limits (the later runs of its symbol) plus those earlier in its own run. That is again symbol sums minus run sums, from one scan. Then fill = $\min(\text{size}, \max(0, V^* - \text{ahead}))$, as in Stage 1.
10. **Deliver.** Each order's outputs are its fill and $[\text{fill} > 0] \cdot p^*$, routed back to arrival order with the Stage 1 unsort.

**Scans in one go.** Steps 4 and 9 each need forward and backward scans under two segmentations (symbols and runs). `segmented_prefix_and_total_multi` lays all four end to end in one sequence. Each piece begins with a start flag, so no segment crosses into the next piece, and the cost is $\lceil \log_2 4n \rceil$ rounds instead of $4 \lceil \log_2 n \rceil$. Stage 1 uses the same routine for its forward and backward pair, which cut its rounds from 316 to 280 at 1,024 orders (566 from 595 in malicious mode) for 2.6% to 4% more data.

## Measured cost

In-process, three server threads on a 2-core cloud workspace, simulated networks, every result checked against the reference. LAN is 0.47 ms round trip and 10 Gbit/s; WAN is 40 ms and 1 Gbit/s. Costs do not depend on the data, by construction, so the random workload does not matter.

| Orders | Mode | Stage 1 rounds | Stage 2 rounds | Stage 1 data/server | Stage 2 data/server | Stage 1 time | Stage 2 time |
|---|---|---|---|---|---|---|---|
| 1,024 | semi-honest, LAN | 280 | 297 | 7.2 MB | 18.1 MB | 0.12 s | 0.16 s |
| 1,024 | semi-honest, WAN | 280 | 297 | 7.2 MB | 18.1 MB | 5.8 s | 6.3 s |
| 10,000 | semi-honest, LAN | 296 | 313 | 76 MB | 189 MB | 0.35 s | 0.85 s |
| 10,000 | semi-honest, WAN | 296 | 313 | 76 MB | 189 MB | 6.9 s | 8.9 s |
| 1,024 | malicious, LAN | 566 | 855 | 165 MB | 269 MB | 1.38 s | 2.01 s |

The draft estimated "a few times Stage 1". Measured, Stage 2 sends about 2.5 times the data in semi-honest mode (1.6 times in malicious mode), but takes only 1.1 to 1.3 times as long on the WAN, because time there is set by rounds. Stage 2 has nearly the same round count as Stage 1: its sort is longer, but it has no elimination passes. In malicious mode every one of the 33 sort bits ends in a verified opening, which is where the extra rounds come from. Security from the run's own accounting is at least 44.6 bits at 1,024 orders.

Command: `cargo run --release -p darkmpc-auction --example stages -- 1024 wan [malicious]`.

## Testing

- **Differential tests** (`crates/auction/tests/stage2.rs`): the MPC fills and delivered prices must equal `match_stage2` on random batches. Limits are drawn mostly from 11 neighbouring ticks, so runs, ties and flat stretches are common, with some at 1 and at the maximum. There is one property for four symbols, one for a single deep book, and one in malicious mode. All three passed 3,000 cases each.
- **Hand-worked cases**: the flat-stretch counterexample, a sell at exactly the clearing price, price beating time, no cross, a single order, an empty batch, and maximum sizes and prices.
- **Malicious traders**: seven bad limit orders (an inconsistent limit bit, a limit bit of 2, limit 0, size 0, size above $2^{40} - 1$, side 2, symbol bit 2). Each is rejected, and only it, and the honest orders still get the reference's fills and prices. The four validation plants from Stage 1 also break this test.
- **Planted bugs**: `plant-stage2-mpc-drop-flat-stretch` (B is the last $S < D$ price itself), `plant-stage2-mpc-strict-sell` (sells need $\ell < p^*$), and `plant-stage2-mpc-buy-time-only` (buys allocated by arrival, ignoring price). Each fails the suite.

## Leakage

Each trader learns its own fill and, if filled, the clearing price; nobody learns anything else, as in the threat model. Two consequences of the mechanism itself, which no cryptography can remove, belong in the write-up:

- **The price is always some order's limit.** A filled trader whose own limit differs from $p^*$ therefore learns that another order on the symbol has exactly that limit. That is inherent to a uniform-price auction over submitted limits.
- **Publishing the price** to everyone, as lit venues publish trades, would also reveal that the symbol traded. The default here is to send $p^*$ only to filled orders. Whether to publish is an open decision.
