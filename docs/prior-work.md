# Prior work: MPC dark pools

Every number below was checked against the paper's own text or tables (November 2026). Section and table references are to the versions linked at the end.

## Why a dark pool needs this

In January 2016 Barclays and Credit Suisse agreed to pay a combined $154.3 million to settle investigations by the SEC and the New York Attorney General over their dark pools: Barclays paid $70 million and admitted misleading investors, and Credit Suisse paid $84.3 million ($60 million in penalties plus $24.3 million for other violations). The 2020 paper below lists further SEC settlements with dark pool operators through 2019. The common thread is that the operator sees every order. Remove the operator's view and that whole class of misconduct becomes impossible rather than merely prohibited.

## What has been built

**Cartlidge, Smart and Talibi Alaoui, "MPC Joins The Dark Side" (AsiaCCS 2019; ePrint 2018/1045).** The first serious implementation. The authors build three mechanisms in the SCALE-MAMBA framework, all actively secure with abort, over a 128-bit prime field with 64-bit integers and 40-bit statistical security: a continuous double auction, a periodic auction, and a volume match. The two-party setting uses SPDZ (dishonest majority); the three-party setting uses Shamir sharing (the abstract calls it honest majority; Section 3 calls it "dishonest majority", which cannot be right for Shamir with three parties). They conclude the continuous double auction is not viable in MPC and that volume matching is. Their volume match is single-instrument, volume-only and first-come-first-served: total buys B and sells S, matched volume T = min(B, S), then walk each side in arrival order capping fills at what is left of T. There are no minimum fills. It costs 2(N+M)+1 comparisons and 9(max(N,M)+1) communication rounds (Sec. 4.3).

**Cartlidge, Smart and Talibi Alaoui, Turquoise Plato Uncross (ePrint 2020/662).** The same group scales the idea to the London Stock Exchange's Turquoise Plato Uncross venue: orders carry an instrument, side, size and minimum execution size (MES); the book is prioritised "by size and then time of order entry"; trades execute at the reference mid-price; and buy/sell pairs are matched sequentially, each pair checked against both MES constraints. That costs about 2NM comparisons per uncross (quadratic). Instruments are spread over L engines of R instruments each, so the system leaks which group of R instruments an order belongs to (they call this R-anonymity). Orders enter through distributed Paillier decryption. The design target is real: 4,500 instruments, an uncross every 5 seconds, about 2,000 orders per 5 seconds.

## Their numbers

All benchmarks are LAN only: i7-7700K machines, 32 GB RAM, 10 Gbit switch, 0.47 ms ping.

| Result | Two parties | Three parties | Source |
|---|---|---|---|
| Volume match, N = M = 500 (1,000 orders): online time | 0.500 s | 0.900 s | 2018/1045, Table 8 |
| same: offline (preprocessing) time | 225.656 s | 4.136 s | Table 8 |
| same: online throughput (orders/s) | 2,000 | 1,111 | Table 8 |
| same: rounds | 4,509 | | Table 8 |
| Volume match, N = M = 10: online / offline | 0.010 / 4.623 s | 0.018 / 0.100 s | Table 8 |
| Headline in text | "800 orders per second" | | Sec. 5 |
| Plato uncross, R = 16, T(14,14) | about 2.5 s | about 3.6 s | 2020/662, Sec. 5 |
| Plato order insertion, R = 16 | about 1.1 s | about 1.9 s | Sec. 5 |
| Plato order input (Paillier), 2,000 orders on 64 cores | about 3.687 s | | Sec. 5 |
| Machines per organisation for 4,500 instruments, R = 16 | 282 | | Sec. 5 |

Two cautions. The 2018 paper's text ("800 orders per second") does not match its own Table 8 (1,000 to 2,200 online). And its "throughput" is online only: in the three-party case the 1,000-order batch also spends 4.136 s in preprocessing, so end to end it is closer to 200 orders per second.

## Where there is room to go further

This part is my analysis, not a result from the papers.

**Rounds, and therefore WAN.** The 2018 volume match needs 9(max(N,M)+1) rounds because it walks the book sequentially. Neither paper benchmarks a WAN, and on a WAN, rounds dominate: 4,509 rounds at a 20 ms round trip is at least 90 seconds of waiting alone. The same first-come-first-served rule can be written as $\mathit{fill}_i = \min(\mathit{size}_i,\ \max(0,\ T - P_i))$, where $P_{i}$ is the volume ahead of order i on its side. Prefix sums of secret-shared values are free local additions, so every fill can be computed in parallel in a constant number of rounds. The reference matcher already checks that this formula and the sequential walk agree.

**Minimum fills without quadratic cost.** Plato handles MES with about 2NM pairwise comparisons. With time priority, only the one marginal order on the longer side can violate its minimum in any pass, so elimination costs O(n) comparisons per pass and a small public number of passes. This is a different mechanism from Plato (time priority rather than size priority), so the honest comparison for minimum fills is a cost-and-leakage comparison, not a like-for-like benchmark.

**What leaks.** The 2018 system is single-instrument; the 2020 system leaks instrument groups by design. Hiding the symbol and side of every order, leaking only batch size and each trader's own fill, is open.

**Protocol choice and scale.** Both papers run a general-purpose framework over a 128-bit prime field with a separate preprocessing phase. Replicated three-party sharing over a 64-bit ring makes semi-honest multiplication need no preprocessing and native machine arithmetic, and batches of 100 to 100,000 orders go well past their largest (1,000).

**The fair comparison.** The 2018 three-party volume match with every minimum fill set to 1 is exactly darkmpc's Stage 1 mechanism. Run with malicious security on a comparable LAN, it gives an apples-to-apples comparison against Table 8, as long as both online and end-to-end time are reported. darkmpc's semi-honest numbers must never be quoted against their actively secure ones.

## Sources

- Cartlidge, Smart, Talibi Alaoui. MPC Joins The Dark Side. AsiaCCS 2019, pp. 148-159, doi:10.1145/3321705.3329809. ePrint: https://eprint.iacr.org/2018/1045 ; author manuscript read: https://core.ac.uk/download/226774922.pdf
- Cartlidge, Smart, Talibi Alaoui. Multi-Party Computation Mechanism for Anonymous Equity Block Trading: A Secure Implementation of Turquoise Plato Uncross. https://eprint.iacr.org/2020/662
- Settlement: CBS News / AP, "Banks reach $154.3 million settlement on dark pool fraud", 1 Feb 2016. https://www.cbsnews.com/news/banks-reach-154-3-million-settlement-on-dark-pool-fraud
