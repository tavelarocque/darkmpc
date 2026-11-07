# Stage 1 in MPC: design (draft for approval)

> **Planning record.** This document was written before the code, to choose a design, and is kept as written for the record. Where it differs from what was built, `docs/design-report.md` describes the system as built.

The servers must run the reference mechanism without knowing any order's symbol or side. The reference groups orders by symbol and then by side, keeping arrival order inside each group. The MPC version has to do the same grouping obliviously. This document recommends how, with costs taken from the source paper, and lays out the pipeline that Milestone 3 will build.

## Recommendation: a stable oblivious radix sort on (symbol, side)

**Decision.** Sort the batch by the key (symbol, side) with the three-party radix sort of Asharov, Hamada, Ikarashi, Kikuchi, Nof, Pinkas, Takahashi and Tomida, "Efficient Secure Three-Party Sorting with Applications to Data Analysis and Heavy Hitters" (ACM CCS 2022; ePrint 2022/1595).

**Why this paper fits.** Five facts from the paper settle it. First, it is a three-party protocol in exactly our setting, with security against passive and active adversaries with an honest majority. Second, it uses the same share layout as our core: party $P_i$ holds $(x_i, x_{i+1})$. Third, the sort is stable, which is the property that matters most: after sorting by (symbol, side), orders with the same key stay in arrival order, so time priority survives with no extra work and without encoding arrival times into the key. Fourth, its cost grows with the key length, and our key is short: a symbol from a public universe of up to $2^{13} = 8{,}192$ symbols plus one side bit is a 14-bit key. Fifth, it permutes the full payload (size, minimum fill, and so on) only once, not once per key bit.

**How it works, in brief.** The sort never compares two orders. For a single key bit, each element's destination is computable with prefix sums, which are free, plus one multiplication. The zeros go first in their original order and the ones after them, so with $f^{(0)} = 1 - k$ and $f^{(1)} = k$, element $i$ goes to

$$s^{(0)}_i + k_i\,\big(s^{(1)}_i - s^{(0)}_i\big),$$

where $s^{(0)}$ is the running count of zeros and $s^{(1)}$ the running count of ones offset by the total number of zeros (GenBitPerm, Protocol 4.1). Doing this bit by bit, least significant first, and composing the resulting permutations gives a stable sort; this is the classical radix sort. The cryptographic work is applying a secret permutation to secret data. The parties first shuffle with a random permutation $\pi = \pi_3 \circ \pi_2 \circ \pi_1$, where each $\pi_i$ is known to exactly two parties (Protocol 3.2). Then they open the composition $\rho \circ \pi^{-1}$, which is a uniformly random permutation from any single party's point of view, and apply that publicly (ApplyPerm, Protocol 4.2). Composition uses the matching unshuffle (Protocols 3.3 and 4.3).

**Cost.** The paper gives per-party communication of $11 m \lVert R\rVert \ell_k + 3m\lVert R\rVert + 2m\lVert R'\rVert$ bits for $m$ items with $\ell_k$-bit keys, where $R$ is the ring for keys and $R'$ the payload ring. It says an appendix optimisation reduces this further. Its implementation sorted one million items with 32-bit keys in 2.261 s semi-honest and 5.585 s malicious (Table 7.1, three AWS c5.18xlarge servers, links limited to 10 Gb, shares in $\mathbb{Z}_p$ with $p = 2^{61} - 1$). The abstract's rounder figures ("less than 2 seconds", "about 3.5 seconds") do not match Table 7.1; the table is what we cite. Our key is 14 bits rather than 32, and our batches are at most $2^{17}$ items rather than $2^{20}$.

**Alternative rejected: one-hot symbols.** Each trader would share its symbol as a vector of $U$ bits over a public universe of $U$ symbols, and per-symbol totals would be sums weighted by those bits. That is simple and has constant rounds, but it needs on the order of $n \times U$ multiplications. With $n = 100{,}000$ and $U$ in the thousands, that is hundreds of millions of multiplications per pass, against the sort's cost, which grows with $14 \cdot n \log n$. One-hot only wins for a universe of a few dozen symbols, so it is not the general design.

**What changes for our ring.** The paper works over a prime field. The semi-honest construction only needs the values involved (positions below $n \le 2^{17}$) not to wrap, so it carries over to $\mathbb{Z}_{2^{64}}$ unchanged. The malicious version (Section 5) needs a MAC-based verification before every opening of a shuffled permutation, because an active adversary can tamper during a shuffle and learn from whether the opened vector is still a permutation. Its bound ($2/|F|$, Lemma 5.5) is a field argument, so Milestone 4 will need the same ring lifting as everything else. That is the hardest part of Milestone 4 and should be planned as such.

## The Stage 1 pipeline

Each order arrives as arithmetic shares of its symbol bits, its side bit (1 = sell), its size and its minimum fill. Its slot in the batch is public, because the servers know which client sent which slot. Then:

1. **Validate on shares.** Range-check size and minimum fill, check that every key bit is 0 or 1, and replace invalid orders with zero-size dummies. Pad the batch to its public size with dummies.
2. **Sort.** Compute the stable sorting permutation $\sigma$ from the 14 key bits, and apply it once to the payload.
3. **Find group boundaries.** For each sorted position, compute a secret flag for "starts a new symbol" and one for "starts a new (symbol, side) group", using equality tests between neighbouring keys. This costs $n$ equality tests on 14-bit keys.
4. **Elimination passes, k of them.** Each pass computes:
   - with segmented prefix sums inside each (symbol, side) group, $P_i$, the eligible volume ahead of order $i$ on its side;
   - with segmented sums inside each symbol, the symbol's eligible buy total $B$ and sell total $S$, made available at every position. Segmented scans take $\log_2 n$ rounds, with two multiplications per element per round;
   - the matched volume $T = \min(B, S)$, with one comparison per element;
   - each fill, $\min(\mathit{size}_i, \max(0, T - P_i))$, which is two comparisons per element;
   - the violation flag $[0 < \mathit{fill}_i < \mathit{min}_i]$, which is two comparisons per element. A violator's eligible size becomes 0 for the next pass.

   After pass k, any symbol that still has a violator is zeroed (the fail-safe), using a segmented OR of the violation flags.
5. **Unsort.** Apply $\sigma^{-1}$ to the fills, so each fill is back in its order's original slot.
6. **Deliver.** Send each trader both copies of each share of its own fills, and nothing else is ever opened.

Every step is data-oblivious: the sequence of operations depends only on the public batch size and the public pass count $k$.

**Testing.** The pipeline must produce exactly the reference matcher's fills (with `Passes::Fixed(k)`) on random batches. Those batches are drawn from the same generator as the reference property tests, plus the hand-worked cases. The sort, scans and equality tests get their own property tests first. Planted bugs for this milestone: an unstable sort (time priority broken inside a group), a segmented scan that leaks across a group boundary, and an unsort with the wrong permutation.

## Open questions for Tave

1. **Is a public symbol universe of up to 8,192 symbols acceptable?** That is a 13-bit symbol field, enough for US equities in a single venue. Each extra bit costs about 1/14 more sort work.
2. **Batch padding.** I recommend a few public batch sizes, for example powers of two from $2^{7}$ to $2^{17}$. A batch is padded to the next size, so the servers learn only which bucket the order count fell in.
