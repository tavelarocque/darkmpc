# Leakage audit

This document states exactly what one server learns from running either auction, proves that statement for the semi-honest protocol, and describes the tests that go with the proof. The tests are sanity checks: they catch specific implementation mistakes, and two planted leaks show that they do. The proof is the actual argument.

## 1. What is claimed

**Setting.** Three servers $P_0, P_1, P_2$, indices modulo 3. At most one server, $P_i$, is corrupt. In this section it follows the protocol and tries to learn from what it sees (semi-honest). Traders are honest here; malicious traders are handled by validation (Section 5).

**Public parameters.** $\mathsf{pub} = (n, \text{symbol bits}, \text{passes}, \text{stage}, \text{mode})$: the batch size and the configuration. Nothing about any order.

**The view of $P_i$.** Everything it holds at the end of a run:

1. its shares of every input,
2. every message it receives, in order,
3. every value it learns from an opening.

Servers receive no output. Fills and prices go to traders as shares, so no server sends anything that depends on them back to another server.

**Theorem.** Assume $F$ (AES-128 in counter mode, `crates/mpc/src/prf.rs`) is a pseudorandom function and the traders' share randomness is uniform. For each $i$ there is a simulator $\mathcal{S}_i$ which, given only $\mathsf{pub}$, outputs a view whose distribution no efficient distinguisher can tell from the real view of $P_i$, on any batch of $n$ valid orders, for either stage. The distinguishing advantage is at most
$$\mathrm{Adv}^{\mathrm{prf}}_F.$$
(An earlier version had an extra term $S \cdot n^2/2^{65}$ for the modulo bias of the permutation sampler. The sampler now uses rejection sampling and is exactly uniform given uniform words; see ring-proofs.md, Section 2.3.)

## 2. Notation

A value $x$ in $\mathbb{Z}_{2^{64}}$ is split as $x = x_0 + x_1 + x_2$, and $P_j$ holds the pair $(x_j, x_{j+1})$. So $P_i$ is missing exactly $x_{i+2}$. Boolean sharing is the same with XOR.

Each pair of servers shares one PRF key. Key $k_j$ is held by $P_j$ and $P_{j-1}$, so $P_i$ holds $k_i$ and $k_{i+1}$, and the one key it does not hold is
$$k_{i+2}, \quad \text{shared by } P_{i+1} \text{ and } P_{i+2}.$$
Each key drives one stream of words, and the code consumes every stream sequentially: no word is ever used twice.

## 3. The proof, step by step

**Hybrid $H_0$** is the real view of $P_i$.

**Hybrid $H_1$** replaces the stream of $k_{i+2}$ by truly uniform words.
$$|\Pr[D(H_0)=1] - \Pr[D(H_1)=1]| \le \mathrm{Adv}^{\mathrm{prf}}_F.$$
The reduction plays $P_{i+1}$ and $P_{i+2}$ honestly, using its oracle wherever they would evaluate $F(k_{i+2}, \cdot)$, and plays $P_i$ with $P_i$'s own keys. With the real PRF it produces $H_0$, and with a random function it produces $H_1$.

Everything below is in $H_1$.

**Step 1: input shares.** A trader shares $x$ by drawing $x_0, x_1$ uniformly and setting
$$x_2 = x - x_0 - x_1 .$$
For $P_0$ the pair $(x_0, x_1)$ is uniform. For $P_1$ the pair $(x_1, x_2)$ is uniform, because $x_0$ is uniform and appears only in $x_2$. The same holds for $P_2$ with $(x_2, x_0)$. In every case $P_i$'s two shares are uniform on $\mathbb{Z}_{2^{64}}^2$ and independent of $x$. Shares of different values are independent. The simulator draws them uniformly.

**Step 2: what the protocol does between messages.** Every operation of both auctions is built from four interactive primitives: multiplication, AND, the reshare step of the shuffle, and opening. That covers comparison, the scans and validation. Everything else is local arithmetic on $P_i$'s own shares and on values it has already received. So $P_i$'s view is determined by its input shares, its keys, and the sequence of received messages. It is enough to show that each received message has, given everything $P_i$ saw before it, a distribution the simulator can sample from $\mathsf{pub}$ and the simulated view so far.

The lengths of all messages, and which primitive runs when, depend only on $\mathsf{pub}$. The code branches on the party index, the mode, the batch size and opened public values, never on a secret. The shape test (Section 4) checks this on every run.

**Step 3: multiplication messages.** $P_{i+1}$ sends $P_i$, for each product,
$$z_{i+1} = x_{i+1} y_{i+1} + x_{i+1} y_{i+2} + x_{i+2} y_{i+1} + \alpha_{i+1},$$
with the zero-sharing mask
$$\alpha_{i+1} = F(k_{i+1})[w] - F(k_{i+2})[w'] .$$
In $H_1$ the word $F(k_{i+2})[w']$ is uniform and used nowhere else, so
$$z_{i+1} \text{ is uniform and independent of everything } P_i \text{ has seen.}$$
The AND gate is the same over $\mathbb{Z}_2^{64}$ with XOR in place of $+$ and $-$. The simulator answers every multiplication and AND message with fresh uniform words.

**Step 4: the shuffle.** A shuffle applies $\pi = \pi_2 \circ \pi_1 \circ \pi_0$ in three reshare steps. In step $c$, the pair $P_{c+1}, P_{c+2}$ permutes by $\pi_c$ and reshares to the excluded server $P_c$. With $r, m$ drawn from the pair's stream (key $k_{c+2}$), the new summands are
$$y_{c+2} = r, \qquad y_{c+1} = a' - r + m, \qquad y_c = b' - m .$$
$P_i$ receives messages only in its own step, $c = i$, whose stream is that of $k_{i+2}$. It receives the pair
$$(y_{i+1},\, y_i) = (a' - r + m,\; b' - m).$$
In $H_1$, $m$ is fresh and uniform, so $y_i$ is uniform. Given $y_i$, the fresh uniform $r$ makes $y_{i+1}$ uniform. So
$$(y_{i+1}, y_i) \text{ is uniform on } \mathbb{Z}_{2^{64}}^2 \text{ and independent of everything } P_i \text{ has seen.}$$
In the other two steps $P_i$ only sends. The simulator answers its own step with fresh uniform words.

This also shows something needed next. The piece $\pi_i$ is drawn from the stream of $k_{i+2}$, and the only messages $P_i$ receives that depend on it are masked by fresh $r, m$. Every message after the shuffle is masked afresh (Steps 3 and 4). So
$$\pi_i \text{ is uniform on } S_n \text{ and independent of } P_i\text{'s view up to the next opening,}$$
exactly, because Fisher-Yates draws each index by rejection sampling.

**Step 5: permutation openings.** To apply a secret permutation $\rho$, the servers shuffle $\rho$ by a fresh $\pi$ and open the result. The opened value is
$$\sigma = \rho \circ \pi^{-1} = \rho \circ \pi_0^{-1} \circ \pi_1^{-1} \circ \pi_2^{-1}.$$
Fix every value other than $\pi_i$. Writing the product as $A \circ \pi_i^{-1} \circ B$, the map
$$\tau \mapsto A \circ \tau^{-1} \circ B$$
is a bijection of $S_n$. A uniform $\pi_i$, independent of $A$, $B$ and the view (Step 4), therefore gives
$$\sigma \text{ uniform on } S_n \text{ and independent of } P_i\text{'s view before the opening.}$$
The opening message is the missing summand, which is fixed by $\sigma$ and $P_i$'s own shares:
$$x_{i+2} = \sigma - x_i - x_{i+1} \quad \text{(coordinatewise).}$$
Each shuffle draws a fresh $\pi$, so the next opening has its own fresh $\pi_i$, and the argument repeats. The simulator draws $\sigma$ uniformly from $S_n$ and sends the summand that matches it.

**Step 6: the remaining messages.**

- *Validation* (when switched on) first sends each server its predecessor's copy of the summand it also holds, which for an honest trader equals its own $s_0$. It then exchanges per-order flags, all 0, and opens values that are public constants for a valid order: $b - b^2 = 0$, high bits $= 0$, validity $= 1$. The simulator writes those constants.
- *Every other opening* in a semi-honest run is a permutation opening. In particular no fill, price, volume or comparison result is ever opened to a server.
- *The exit barrier* in the server binary sends empty messages.

**Step 7: the simulator.** $\mathcal{S}_i$ draws uniform input shares (Step 1) and runs $P_i$'s own code. It answers each multiplication, AND and reshare message with fresh uniform words (Steps 3 and 4). It answers each permutation opening with the summand for a fresh uniform $\sigma \in S_n$ (Step 5), and each validation message with its public constant (Step 6). It outputs the resulting view.

**Step 8: conclusion.** In $H_1$, every item $P_i$ receives has, given the view before it, exactly the conditional distribution $\mathcal{S}_i$ uses. $P_i$'s own computation is the same function in both. By the chain rule the two joint distributions are equal. Adding the $H_0 \to H_1$ step gives the bound in the theorem. $\blacksquare$

## 4. The tests (`crates/auction/tests/audit.rs`)

They check the two facts the proof relies on, on the actual code.

**Shape, exact.** Two batches of four orders are run: one where everything crosses on one symbol, one spread over symbols with different sides, sizes, minimums and limits. For each, every server's received message lengths and opening lengths are recorded. They must be identical, for Stage 1 and Stage 2, semi-honest and malicious. This is Step 2's "depends only on $\mathsf{pub}$", checked directly.

**Openings, statistical.** Each batch is run 300 times with fresh randomness, and every opened value is recorded. For each opening, the two batches' distributions must be the same: a two-sample chi-squared test on a 16-bucket hash of the opened vector, at $p = 10^{-9}$. Every permutation opening must also be uniform over the 24 permutations of four elements. This is Step 5, checked directly, and Step 6's "constants stay constant", since a constant opening that changed with the data would split the buckets. Malicious mode is included: its extra openings (masked differences, zero checks, joint coins, the MAC check) must also not depend on the orders.

**Planted leaks.** Both keep every fill and price correct, so the differential tests cannot see them. Only the audit can.

- `plant-open-unshuffled` opens $\rho$ without shuffling it first, so the sorting permutation, which is the order of the data, becomes public. Caught in Stage 1, Stage 2 and malicious mode, with a statistic of 600, the maximum for 300 runs per batch.
- `plant-stage2-debug-open` leaves a stray opening of the clearing prices in Stage 2, the kind of thing a debugging session leaves behind. Caught in both modes, with a statistic of 600.

With them, `check_planted.sh` runs 27 planted bugs.

**What the tests cannot show.** A chi-squared test on a hash bucket detects gross dependence, not a subtle bias. Four orders is a small batch. Passing is evidence that the implementation follows the protocol the proof is about, not a proof in itself.

## 5. Scope: what this does not cover

- **Malicious servers.** In an honest run of malicious mode, every extra opening is a value masked by a fresh random triple, a check that is 0, a joint coin, a validation constant, or the MAC check, which is 0. So the view argument above extends to a server that follows the protocol, and the tests cover it. Against a server that deviates, the proof must also show that any deviation is caught before an opening it could influence. That is the job of the FLNW product checks and the MAC-checked shuffle (`docs/design/malicious.md`). The full simulation proof, including the two ring extensions, is Milestone 6 work.
- **Malicious traders.** Validation opens, for an invalid order, a value that depends on that order (for example $b - b^2$ for a bad bit). That reveals something about the cheating trader's own input, to every server, and nothing about anyone else.
- **Side channels.** Message sizes and counts are fixed by $\mathsf{pub}$, which the shape test checks. CPU timing and memory access patterns have not been audited. Local work on secrets uses fixed-time integer arithmetic in Rust, but nothing here proves constant time.
- **Key setup.** The theorem assumes each PRF key is known to exactly its two servers. The keys are agreed over mutually authenticated TLS at setup, which is assumed correct.
- **What traders learn.** The proof is about servers. Traders learn what the auction itself reveals: their fills and, in Stage 2, the clearing price. That includes the inherent leaks in `threat-model.md`: probing ("pinging"), and the fact that the price is always some order's limit.
