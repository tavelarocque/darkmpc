# Milestone 4: malicious security with abort (design)

> **Planning record.** This document was written before the code, to choose a design, and is kept as written for the record. Where it differs from what was built, `docs/design-report.md` describes the system as built.

The goal: if the one corrupt server deviates from the protocol in any way that could change an output or leak an input, every honest server aborts before any fill is revealed. Corrupt traders must also be unable to break the computation with malformed or inconsistent input. Facts below are cited. Where an argument is my own extension of a published one, it says so.

## The plan in one paragraph

Compute exactly as now (semi-honest, "optimistically"), but record every multiplication and every AND gate. Before anything is opened, prove all of them correct in one batch, each against a multiplication triple $(a, b, c = ab)$ that has itself been proven correct by cut-and-choose and bucketing. Every opening sends each missing share from both servers that hold it, and the receiver compares the two copies. Traders' inputs get a consistency check and a range check, run on shares. That is Milestone 4a. Milestone 4b is the oblivious shuffle inside the sort, which needs a separate verification and is the hardest part.

## 4a.1 Verified AND gates (the comparison circuits)

This is Furukawa, Lindell, Nof and Weinstein, "High-Throughput Secure Three-Party Computation for Malicious Adversaries and an Honest Majority" (Eurocrypt 2017; ePrint 2016/944), used as published. Their protocol is stated for Boolean circuits. Our AND gates are exactly that: each 64-bit word is 64 independent Boolean gates.

- **What a cheater can do.** Their Lemma 2.4: a malicious party in the semi-honest AND protocol can at most flip the output bit; the sharing stays consistent.
- **Checking a gate against a triple.** Protocol 2.24 checks a gate $(x, y, z)$ against a correct triple $(a, b, c)$. Open $\rho = x \oplus a$ and $\sigma = y \oplus b$, compute $z \oplus c \oplus \sigma a \oplus \rho b \oplus \rho\sigma$ locally, and check that it is a sharing of 0 (Lemma 2.25).
- **Producing correct triples.** Protocol 3.2 generates $NB + C$ random triples with the semi-honest AND, shuffles them with jointly tossed coins, opens and checks $C$ of them, splits the rest into $N$ buckets of size $B$, and uses the first triple in each bucket to check the others.
- **The bound.** Theorem 5.3: if $C \ge B$, the probability that a bad triple survives is at most $N / \binom{NB+C}{B}$. Their Table 1 example: $N = 2^{20}$ and statistical security $\sigma = 40$ give $B = C = 3$.
- **When views are compared.** Gates are checked in parallel at the end (Protocol 4.2, step 3). The neighbouring servers compare hashes of their views before outputs are released.

## 4a.2 Verified multiplications over $\mathbb{Z}_{2^{64}}$

The same structure in the ring. The check of a product $(x, y, z)$ against a triple $(a, b, c)$ opens $\rho = x - a$ and $\sigma = y - b$ and computes

$$t = z - c - \sigma a - \rho b - \rho\sigma.$$

Since $x = \rho + a$ and $y = \sigma + b$, we have $xy = \rho\sigma + \rho b + \sigma a + ab$. So if both products are correct, $t = 0$ exactly. No division or inverse appears, so the algebra holds in any commutative ring.

**Soundness argument (mine, extending FLNW; ABY3 Section 5.2 builds its malicious multiplication on "a natural extension of protocol 2.24" of FLNW without, in the part I could read, giving a ring analysis).**

1. A corrupt server's messages in a multiplication are functions of its own view. Its view is independent of the secrets, because every message it receives is masked, as shown in chapter 1. So any deviation changes the product by an additive error $\delta$ that is independent of the secret inputs: $z = xy + \delta$.
2. With $z = xy + \delta_z$ and $c = ab + \delta_c$, the check gives $t = \delta_z - \delta_c$. It passes exactly when the two errors are equal.
3. In the bucketing game, a bucket passes only if every triple in it has the same error. The adversary's best strategy is the Boolean one: corrupt a set of triples with a common error and hope they land together in a bucket while avoiding the opened ones. That makes the FLNW combinatorial bound carry over unchanged.
4. A wider ring gives the adversary more error values to choose from, but no extra way to pass a check, since passing requires equality.

This argument goes into the write-up with its proof written out, not as a citation.

**Openings.** Every opening, whether of the masks $\rho$ and $\sigma$, of $t$, or of anything else, is a verified opening. Each server is missing one summand, and that summand is held by both other servers. Both send it, and the receiver aborts if the two copies differ. With at most one corrupt server, at least one copy is honest, so a wrong value is always caught. This is the replicated-sharing reveal described by Eerikson et al. ("Use your Brain!", ITC 2020; ePrint 2019/164, Section 2.4), whose servers "check that the two copies agree". The same comparison catches a server that keeps one value as its own copy of a product summand and sends a different one: the two holders of that summand then compute different shares of $t$.

**Coins.** The random permutation that assigns triples to buckets is derived from a jointly opened random sharing. That sharing is created after the triples are fixed, and its opening is verified, so no single server can predict or bias it.

## 4a.3 Inputs from traders

**Consistency.** Each summand of a trader's sharing goes to two servers, which compare their copies. If they disagree, the order is rejected for everyone (turned into a zero-size dummy). Honest limitation: a corrupt server can falsely report a mismatch and so censor an order. It cannot learn anything by doing so, but it can deny service to a trader. This is recorded in the threat model rather than hidden.

**Ranges.** A trader could share a size of $2^{63}$, which would break comparison by sign. The servers check, on shares:

- every key bit is 0 or 1, by opening $b(1 - b)$, which must be 0;
- size and minimum fill are below $2^{40}$, using the full bit decomposition the carry circuit already computes ($s + c = p \oplus (G \ll 1)$, so every bit of the sum is available at no extra cost) followed by an OR over bits 40 to 63;
- $1 \le \text{min fill} \le \text{size}$, by comparisons that are sound once the bounds above hold.

Only each order's single valid or invalid bit is opened. Invalid orders become zero-size dummies.

## 4a.4 Outputs

Each trader receives both copies of each summand of its fills from the two servers holding it and rejects on any mismatch. That is already in the threat model, and now it is implemented.

## 4b. The shuffle (the hard part)

Applying a secret permutation opens a shuffled vector. Asharov et al. (CCS 2022, Section 5) show that in the malicious setting a corrupt server can tamper during the shuffle and learn from whether the opened vector is still a permutation. That is a selective-failure leak, and it is not an additive error. Verified multiplications do not cover this, because a shuffle has no multiplications. Their fix is to authenticate shuffled data with MACs and verify them before every reveal (their Protocol 5.4, Lemma 5.5, bound $2/|F|$). Their bound is a field argument. In $\mathbb{Z}_{2^{64}}$, a MAC key can be a zero divisor, so the check must be done in a lifted ring such as $\mathbb{Z}_{2^{128}}$ (the SPDZ2k idea). The MACed copies of the shuffled columns would then be carried at 128 bits.

**Status: implemented** (crates/mpc/src/mac.rs). The design matches what is described above: a fresh key $\alpha$ per shuffle, MACs computed mod $2^{128}$, values and MACs shuffled together, and public coefficients drawn after the shuffle. The batch check uses SPDZ2k's bound (CRYPTO 2018, Theorem 1: $2^{-s+\log(s+1)}$ with $s = 64$). The values are lifted to $\mathbb{Z}_{2^{128}}$ for free and reduced back afterwards. Combining SPDZ2k's check with the honest-majority replicated shuffle is the author's construction and needs a written proof; see docs/learning/07-verified-shuffle.md.

## Order of work

1. Verified opening. Optimistic recording of every multiplication and AND. Triple generation with cut-and-choose and bucketing. A batch check before any opening. One planted cheating server for each check: a wrong product share, a flipped AND output, a bad triple, inconsistent copies, and a wrong opened copy. Each must be caught.
2. Input consistency and range checks, with planted malicious clients: inconsistent shares, a size above $2^{40}$, a key bit equal to 2, and a minimum fill above the size.
3. 4b: MAC-verified shuffle in $\mathbb{Z}_{2^{128}}$, with a planted tampering shuffle.
4. Benchmarks of the malicious version against the 2018 paper's actively secure numbers, on real machines.
