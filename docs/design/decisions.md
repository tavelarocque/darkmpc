# Protocol decisions

> **Planning record.** This document was written before the code, to choose a design, and is kept as written for the record. Where it differs from what was built, `docs/design-report.md` describes the system as built.

This records the three core choices for darkmpc and the reasons, so each can be defended. Facts carry citations to sources that were opened and checked. Everything else is my judgement, labelled as such.

## 1. The ring: $\mathbb{Z}_{2^{64}}$ for data, $\mathbb{Z}_{2^{128}}$ for malicious checks

**Decision.** Secret values live in $\mathbb{Z}_{2^{64}}$, which is a Rust `u64` with wrapping arithmetic. In Milestone 4, the values used only for checking honesty are lifted to $\mathbb{Z}_{2^{128}}$ (a `u128`), giving 64 bits of slack above the data.

**Why a ring and not a prime field.** Three reasons, in order of importance.

The first is the workload. A dark pool matcher is comparison-heavy and multiplication-light. Each Stage 1 auction needs a few comparisons per order (a minimum and a clamp for each fill, a check against each minimum fill) and almost no other arithmetic. The cheapest known way to compare in three-party replicated sharing is local share conversion: each of the three additive summands of a ring element is held in the clear by two parties, so each summand can be turned into a Boolean sharing with no communication, and a binary adder circuit then recovers the bits of the sum. That trick depends on the sharing being plain additive sharing over a power-of-two ring. The MP-SPDZ documentation says local conversion "requires additive secret sharing over a ring without any MACs" and that "where available, local share conversion is likely the most efficient variant" (MP-SPDZ README, checked at commit f32f2f97). Over a prime field, addition of the summands wraps modulo p rather than modulo a power of two, so the bits of the sum are not the bits a binary adder produces, and you need a different, more expensive bit decomposition.

The second is speed and simplicity of the arithmetic itself: wrapping 64-bit integer arithmetic is what the CPU does natively, with no modular reduction.

The third is that it differs from prior work for a reason. Both MPC dark pool papers ran on a 128-bit prime field with a separate preprocessing phase (see prior-work.md). A ring-based design is a real point of comparison, not a cosmetic change.

**What the ring costs.** In $\mathbb{Z}_{2^{64}}$ most elements have no multiplicative inverse (every even number is a zero divisor). Two consequences follow. Division is awkward, which is one reason Stage 1 uses time priority rather than pro-rata allocation (pro rata needs a secret divisor). And the standard malicious-security checks over fields rely on a random challenge being invertible, which fails in a ring, so those checks have to be done in a bigger ring $\mathbb{Z}_{2^{k+s}}$ where the extra s bits absorb the problem. This is the SPDZ2k idea, and MP-SPDZ's malicious replicated ring protocols do exactly this: their check values have type `MaliciousRep3Share<Z2<K + S>>`, with S = 40 by default (Protocols/config.h). I choose s = 64 rather than 40 because k + s = 128 is a native `u128`; it costs a few extra bytes per checked value and gives more statistical slack. The precise soundness bound will be taken from the paper when Milestone 4 is implemented, not asserted now.

**What makes comparison by sign sound.** Comparing a and b by taking the top bit of a − b in $\mathbb{Z}_{2^{64}}$ is only correct if a − b cannot wrap around. The reference matcher enforces sizes of at most 2^40 − 1 and batches of at most 2^17 orders, so every sum and difference the matcher computes stays strictly inside (−2^63, 2^63). The MPC matcher will enforce the same bounds (Milestone 4 must also check them for malicious clients, since a client can share anything).

## 2. Comparison: local conversion plus a log-depth carry circuit

**Decision.** To compute whether a < b, take d = a − b (free), convert d's three summands into Boolean replicated sharings locally, reduce three addends to two with one layer of full adders (a carry-save adder: one round of AND gates), then compute only the carry into the top bit with a parallel-prefix (log-depth) carry circuit. The sign bit is the answer. To use the result arithmetically (for example $\min(a,b) = b + [a<b]\cdot(a-b)$), convert the bit back into the ring with one more step (bit injection).

**Why.** It needs no preprocessing and no trusted dealer, its cost is a fixed number of AND gates and about log2(64) = 6 rounds of carry propagation plus a constant, and every piece is a small Boolean circuit that can be tested exhaustively at small bit widths. This is the approach ABY3 uses (its code computes the sum of two of the summands, then a two-input MSB extraction), and MP-SPDZ implements it for replicated rings (compiler option `-Z 3`), so MP-SPDZ can serve as an independent cross-check of results and of AND and round counts.

**Alternatives considered.** edaBits (Escudero et al., CRYPTO 2020) precompute random values shared both arithmetically and in binary, then compare by revealing a masked value. Their Table 8 reports, for a 63-bit comparison in honest-majority malicious $\mathbb{Z}_{2^k}$, 5.4 kbit with edaBits against 27.8 with daBits and 63.4 with plain arithmetic. That is attractive, but in the malicious setting it relies on large batches for the cut-and-choose to be efficient (MP-SPDZ notes bucket size 3 needs about a million edaBits per batch), and it adds a preprocessing phase to build and to prove correct. Rabbit (Makri, Rotaru, Vercauteren, Wagh, FC 2021) is a refinement of mask-and-reveal comparison with roughly 1.5× better throughput reported in most adversarial settings. Both are good upgrade paths once the simple version is measured; neither is the right first build.

**Cost numbers.** I am not quoting AND-gate or round counts for this circuit yet, because I could not verify them from a primary source. Milestone 2 will count them in our own implementation and cross-check against MP-SPDZ.

## 3. Malicious security with abort: optimistic multiply, then verify

**Decision.** Milestone 4 adds a verification layer on top of the unchanged semi-honest protocol. For ring multiplications, use the "multiply optimistically, then sacrifice-check" approach of Lindell and Nof (CCS 2017), with check values lifted to $\mathbb{Z}_{2^{128}}$. *(As built: ring multiplications use the same FLNW cut-and-choose triple check as the AND gates, in $\mathbb{Z}_{2^{64}}$, proved in `ring-proofs.md`; $\mathbb{Z}_{2^{128}}$ is used for the MAC-checked shuffle.)* For the Boolean AND gates inside comparisons, use the triple-verification of Furukawa, Lindell, Nof and Weinstein (Eurocrypt 2017) as optimised by Araki et al. (IEEE S&P 2017). Inputs from clients get their own consistency check (see the threat model, still in draft). Any failed check makes every honest server abort before anything is opened.

**Why this one.** Three reasons. Its security argument is the simplest of the options: a cheating server that tampers with a product creates a triple that fails a randomised check except with small probability, and the check can be batched over all multiplications in an auction. It matches MP-SPDZ's `ps-rep-ring` protocol (which MP-SPDZ credits to Eerikson et al., ITC 2020, building on this line of work), giving a bit-for-bit cross-check. And it keeps local share conversion available, which the more communication-efficient SPDZ-wise approach does not, because SPDZ-wise attaches a MAC to every value.

**The lineage, verified.** Araki et al. (CCS 2016) gave the semi-honest protocol: one bit per AND gate per party. Furukawa et al. (Eurocrypt 2017) made it malicious with cut-and-choose verification of triples, about 10 bits per AND gate (as described in the S&P 2017 paper). Araki et al. (S&P 2017) reduced that to 7 bits per AND and reported about 1.15 billion AND gates per second on three 20-core Xeon servers over 10 Gbps. Lindell and Nof (CCS 2017) generalised to arithmetic circuits over fields, 4 field elements per multiplication per party in the replicated three-party case. Chida et al. (CRYPTO 2018) brought that to 2 field elements per multiplication for large fields with a single randomised check for the whole circuit. Abspoel, Dalskov, Escudero and Nof (ACNS 2021) carried that "SPDZ-wise" approach to $\mathbb{Z}_{2^k}$ at about twice the semi-honest cost. Boyle, Gilboa, Ishai and Nof (CCS 2019 and Asiacrypt 2020) replaced per-gate checks with sublinear distributed zero-knowledge proofs, getting to about one ring element per multiplication per party, matching semi-honest, with $\mathbb{Z}_{2^k}$ handled through an extension ring. Li et al. (CCS 2024) give sublinear checks for replicated sharing over $\mathbb{Z}_{2^\ell}$ without extension rings and report checking 10 million gates in 2.82 seconds.

**What the current best practical approach is.** On communication, the distributed zero-knowledge proofs win: verification becomes nearly free asymptotically, and the Li et al. CCS 2024 version is built for exactly our setting (replicated sharing over a power-of-two ring). That is the state of the art. It is also substantially harder to implement and to argue correct, so it is the stretch upgrade for Milestone 4 if the optimistic-multiply version is working with time to spare, and an honest line in the write-up if it is not.

## What I am deliberately not deciding yet

Pseudorandom generation and channels will use audited libraries (a standard AES or ChaCha implementation for the PRF, rustls for TLS between servers and from clients), chosen in Milestone 2 after checking their APIs and audit status rather than from memory.

## Sources

- MP-SPDZ, README and source at commit f32f2f97 (3 Nov 2026). https://github.com/data61/MP-SPDZ
- Araki et al. CCS 2016. https://eprint.iacr.org/2016/768
- Furukawa, Lindell, Nof, Weinstein. Eurocrypt 2017. https://eprint.iacr.org/2016/944
- Araki et al. Optimized Honest-Majority MPC for Malicious Adversaries. IEEE S&P 2017. https://www.ieee-security.org/TC/SP2017/papers/96.pdf
- Lindell, Nof. CCS 2017. https://acmccs.github.io/papers/p259-lindellA.pdf
- Chida et al. CRYPTO 2018; Journal of Cryptology 36:15 (2023). https://eprint.iacr.org/2018/570
- Abspoel, Dalskov, Escudero, Nof. ACNS 2021. https://eprint.iacr.org/2019/1298
- Boyle, Gilboa, Ishai, Nof. CCS 2019 (https://eprint.iacr.org/2019/1390) and Asiacrypt 2020 (https://eprint.iacr.org/2020/1451)
- Li, Escudero, Duan, Huang, Hong, Zhang, Song. CCS 2024. https://eprint.iacr.org/2024/700
- Eerikson et al. ITC 2020. https://eprint.iacr.org/2019/164
- Escudero, Ghosh, Keller, Rachuri, Scholl. edaBits. CRYPTO 2020. https://iacr.org/archive/crypto2020/12171394/12171394.pdf
- Makri, Rotaru, Vercauteren, Wagh. Rabbit. FC 2021. https://eprint.iacr.org/2021/119
- Mohassel, Rindal. ABY3. CCS 2018. https://eprint.iacr.org/2018/403 ; code https://github.com/ladnir/aby3
