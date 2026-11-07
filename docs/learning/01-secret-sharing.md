# Secret sharing and three-party multiplication

## The problem

Three servers must compute the matching of a set of orders that none of them is allowed to see. The trick that makes this possible is older and simpler than most of cryptography: split each number into pieces that are individually meaningless, give each server some pieces, and find ways to compute on the pieces directly. Splitting a number this way is called secret sharing, and the pieces are shares.

All arithmetic here happens in the ring $\mathbb{Z}_{2^{64}}$, the integers modulo 2^64. That is exactly what a 64-bit unsigned integer does when you let it wrap around, so a Rust `u64` with `wrapping_add` and `wrapping_mul` is the ring, with no extra code. To keep the worked example readable it uses $\mathbb{Z}_{256}$ (8-bit wrapping arithmetic) instead. Nothing in the reasoning depends on the size.

## Additive sharing

To share a secret x among three parties, pick x1 and x2 uniformly at random and set x3 = x − x1 − x2. Then x1 + x2 + x3 = x, so anyone holding all three shares recovers x by adding them.

Why are the shares meaningless on their own? Look at any two of them, say x1 and x2. They were chosen uniformly at random without looking at x, so they are uniform and tell you nothing. Now look at x2 and x3. Since x3 = x − x1 − x2 and x1 is a uniform value nobody has seen, x3 is uniform too, whatever x is: adding a uniform random value to anything in a ring gives a uniform result. This "one-time pad" argument is the whole security of secret sharing, and it is not computational. No amount of computing power helps someone who holds two of the three shares, because every value of x is exactly equally consistent with what they see.

Addition is free. If x is shared as (x1, x2, x3) and y as (y1, y2, y3), then each party adding its own two pieces produces (x1 + y1, x2 + y2, x3 + y3), which is a valid sharing of x + y. Multiplying by a public constant and adding a public constant are equally local. Nobody sends anything. This is why the matcher's prefix sums cost nothing: a running total of secret sizes is just each server adding up its own shares.

Multiplication is not free. The product is xy = (x1 + x2 + x3)(y1 + y2 + y3), which expands into nine cross terms $x_{i}$·$y_{j}$. In plain additive sharing, if each party holds just one share, no party holds both x1 and y2, so no one can compute that cross term without someone sending something. Every non-linear step in the matcher (comparisons, minimums, choosing between values) is built from multiplications, so the cost of multiplication is the cost of the whole system.

## Replicated sharing

Replicated sharing is additive sharing where each party gets two of the three shares. Number the parties 1, 2, 3 and treat indices cyclically, so after 3 comes 1 again. Party i holds the pair ($x_{i}$, $x_{i+1}$): party 1 holds (x1, x2), party 2 holds (x2, x3), party 3 holds (x3, x1). Each share is held by exactly two parties.

Privacy is the same argument as before. Any single party sees exactly two of the three additive shares, which are uniform and independent of x. This is the honest-majority assumption made concrete: if two parties pooled their views they would have all three shares and learn x. The design is only secure while at most one of the three servers is corrupt.

Opening a value (deliberately revealing it, such as a trader's fill to that trader) needs one message per party: each party is missing exactly one share, and one of its neighbours has it.

The payoff is in multiplication. Party i holds $x_{i}$, $x_{i+1}$, $y_{i}$ and $y_{i+1}$, so it can compute four of the nine cross terms itself. Give each party three of them:

$$z_i = x_i y_i + x_i y_{i+1} + x_{i+1} y_i$$

Party 1 covers x1y1, x1y2, x2y1. Party 2 covers x2y2, x2y3, x3y2. Party 3 covers x3y3, x3y1, x1y3. That is all nine terms, each exactly once, so z1 + z2 + z3 = xy. The product is now additively shared with one share per party, and nobody has communicated yet.

## Restoring the replicated form, and why it needs fresh randomness

Two problems remain. First, each party holds only one share of the product, but the next multiplication needs the replicated form with two shares each. The fix is one message: party i sends $z_{i}$ to party i − 1. Afterwards party i holds $z_{i}$ (its own) and $z_{i+1}$ (received from party i + 1), which is exactly the replicated pair. So a multiplication costs one round and one ring element sent by each party, which is what makes this protocol fast.

Second, and this is the subtle part, $z_{i}$ as written leaks. The party that receives $z_{i}$ is party i − 1, which already holds $x_{i−1}$, $x_{i}$, $y_{i−1}$ and $y_{i}$. Substitute $x_{i+1}$ = x − $x_{i−1}$ − $x_{i}$ and $y_{i+1}$ = y − $y_{i−1}$ − $y_{i}$ into the formula for $z_{i}$ and the terms rearrange into

$$z_i + x_i y_{i-1} + x_{i-1} y_i + x_i y_i = x_i\,y + y_i\,x.$$

Everything on the left is known to the receiver, so the receiver learns $x_{i}$·y + $y_{i}$·x: a linear equation in the two secrets with coefficients it knows. That is a real leak. For instance, if $x_{i}$ happens to be odd and $y_{i}$ even, the lowest bit of that quantity is the lowest bit of y, so the receiver learns whether y is odd.

The fix is to add a random sharing of zero before sending. The parties hold random values α1, α2, α3 with α1 + α2 + α3 = 0, each known only to its own party, and party i sends $z_{i}$ + $\alpha_{i}$ instead. The sum is unchanged, so the result is still a sharing of xy, but to the receiver $\alpha_{i}$ is a uniformly random mask, so the message is uniformly random and carries no information. Forgetting this step is one of the bugs this project will plant on purpose, and the leakage tests must catch it.

The zero sharing costs no communication. Once, at setup, each pair of neighbouring parties agrees on a secret key: party i holds keys $k_{i}$ and $k_{i+1}$, so each key is known to exactly two parties. For the c-th multiplication, party i computes $\alpha_{i}$ = F($k_{i}$, c) − F($k_{i+1}$, c), where F is a pseudorandom function (in practice a standard cipher such as AES, from an audited library). Summing over all three parties, every F term appears once with a plus sign and once with a minus sign, so the α's sum to exactly zero. And the $\alpha_{i}$ that masks the message party i − 1 receives contains F($k_{i+1}$, c), which party i − 1 does not hold the key for. This is the one place where the protocol's security is computational rather than information-theoretic: the masks are pseudorandom, not truly random.

## Worked example in $\mathbb{Z}_{256}$

Let x = 20 and y = 7, so xy = 140. All arithmetic is mod 256.

Share x: pick x1 = 200 and x2 = 91, then x3 = 20 − 200 − 91 = −271 ≡ 241. Check: 200 + 91 + 241 = 532 = 2·256 + 20.

Share y: pick y1 = 130 and y2 = 45, then y3 = 7 − 175 = −168 ≡ 88. Check: 130 + 45 + 88 = 263 = 256 + 7.

The replicated holdings are: party 1 has x = (200, 91) and y = (130, 45); party 2 has x = (91, 241) and y = (45, 88); party 3 has x = (241, 200) and y = (88, 130).

The zero sharing: α1 = 17, α2 = 250, α3 = 245. Check: 17 + 250 + 245 = 512 ≡ 0.

Each party computes its masked product share:

z1 = 200·130 + 200·45 + 91·130 + 17 = 26000 + 9000 + 11830 + 17 = 46847 ≡ 255

z2 = 91·45 + 91·88 + 241·45 + 250 = 4095 + 8008 + 10845 + 250 = 23198 ≡ 158

z3 = 241·88 + 241·130 + 200·88 + 245 = 21208 + 31330 + 17600 + 245 = 70383 ≡ 239

Sum: 255 + 158 + 239 = 652 = 2·256 + 140. The shares reconstruct to 140, as they should.

Then party 1 sends 255 to party 3, party 2 sends 158 to party 1, and party 3 sends 239 to party 2. Afterwards party 1 holds (255, 158), party 2 holds (158, 239) and party 3 holds (239, 255): a replicated sharing of 140.

Now watch the leak without the mask. Unmasked, z1 = 26000 + 9000 + 11830 = 46830 ≡ 238, and party 3 receives it. Party 3 knows x3, x1, y3, y1, so it computes x1·y3 + x3·y1 + x1·y1 = 17600 + 31330 + 26000 = 74930 ≡ 178, and adds: 238 + 178 = 416 ≡ 160. The true value of x1·y + y1·x is 200·7 + 130·20 = 4000 ≡ 160. Party 3 has learned a fact about the secrets it should never have learned. With the mask, it receives 255 instead, which is uniformly random from its point of view.

(These numbers, and the leakage identity on 10,000 random sharings, were checked by script.)

## What this does and does not protect against

Everything above assumes each server follows the protocol and only tries to learn from what it sees: the semi-honest model. A corrupt server could instead send a wrong $z_{i}$. Nothing in this protocol would notice, and the result would silently be wrong. Detecting that (malicious security with abort) is the subject of Milestone 4, and the protocol choice for it is in the design decisions document.

## Sources

- Araki, Furukawa, Lindell, Nof, Ohara. High-Throughput Semi-Honest Secure Three-Party Computation with an Honest Majority. CCS 2016. https://eprint.iacr.org/2016/768 . The protocol this chapter teaches. Their abstract: "each party sends only a single bit for every AND gate", over 1.3 million AES computations per second on three 20-core servers with 10 Gbps links. Their paper writes shares in an equivalent but differently indexed form (a pair of a share and a one-time-padded value); I have not yet read their ring construction in full text, so the exact notation here is mine.
- Lindell, Nof. A Framework for Constructing Fast MPC over Arithmetic Circuits with Malicious Adversaries and an Honest-Majority. CCS 2017, Sec. 6.2.1 (https://acmccs.github.io/papers/p259-lindellA.pdf): the same replicated structure, written "P1's share is (r1, r3), P2's share is (r2, r1) and P3's share is (r3, r2)". Only the indexing direction differs from this chapter.
