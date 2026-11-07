# The reference matcher

## What it is for

Before any cryptography exists, darkmpc needs a definition of the right answer. The reference matcher is that definition: a short, plain Rust function that takes a batch of orders and returns each order's fill, with no secret sharing and no attempt at speed. Every later milestone is judged against it. In Milestone 3 the MPC matcher must return exactly the reference's fills on millions of random batches, and if the two ever disagree the MPC matcher is wrong by definition. That only works if the reference is simple enough to trust by reading it, so it is written the obvious way and kept in its own crate with no dependencies.

## The mechanism it defines

An auction runs per symbol. Total the eligible buy sizes into B and the sell sizes into S; the matched volume is T = min(B, S), traded at the public midpoint, so no prices are involved. Each side then shares out T by time priority: the earliest order takes as much as it wants up to what is left, then the next, and so on. On the side with less volume everyone fills completely. On the side with more, a run of orders fills completely, then one order (the marginal order) gets a partial fill, then the rest get nothing.

Minimum fills complicate this. An order may say "fill me at least m shares or not at all". If the marginal order's partial fill falls below its minimum, it cannot trade, so it is removed and the allocation is redone. That can push the imbalance to the other side, whose marginal order may now be below its own minimum, so the process can bounce back and forth. Each round is a pass, and the process stops at the first pass with no violation.

Two facts make this cheap and well defined. Only the marginal order can ever violate its minimum, because full fills never violate (a minimum is at most the order's size) and everyone else gets zero, so each pass removes at most one order. And since each pass removes an order or stops, the process ends within n + 1 passes for n orders. The tests check both facts directly on random books rather than taking them on trust.

## Why there is a pass cap

An MPC evaluation cannot run "until stable", because the number of passes it ran would itself leak information about the orders. It has to run a fixed, public number of passes k. So the reference implements the capped rule too: run at most k passes, and if pass k still has a violator, that symbol matches nothing this auction. The fail-safe means a minimum is never broken, whatever k is. The tests prove that a cap of k gives exactly the uncapped answer on every symbol that settles within k passes and all zeros on every symbol that does not. Choosing k is a trade-off between cost (each pass is a few comparisons per order) and how often the fail-safe triggers, and it will be measured on realistic order-size distributions before it is fixed.

## Two formulas that must agree

Prior work allocates by walking down each side with a running remainder, which in MPC means one step after another: their volume match needs 9(max(N,M)+1) communication rounds. The same rule can be written as a closed formula. If $P_{i}$ is the total size of the orders ahead of order i on its side, then order i's fill is $\min(\mathit{size}_i,\ \max(0,\ T - P_i))$. Prefix sums of secret-shared values are free local additions, so every fill can be computed at once, in a constant number of rounds whatever the batch size. The reference contains both forms, `allocate_walk` and `allocate_prefix`, and a property test requires them to be identical on random books. The matcher itself uses the prefix form, because that is what the MPC version will compute.

## How the tests are built

There are 13 hand-worked examples, each with its expected answer worked out in a comment rather than copied from the code. The first is the worked example printed in "MPC Joins The Dark Side" (sells 3, 4, 5 against buys 5, 2, 11, 1), so the mechanism is pinned to the published one. The others cover an empty batch, an empty side, a perfectly balanced book, ties, a fill exactly at the minimum, removal of a marginal order, an all-or-none order that cannot trade, elimination bouncing between sides for three passes, the pass-cap fail-safe, two interleaved symbols, maximum sizes in a batch of 79,999 orders without overflow, and every kind of invalid input.

There are nine property tests, each run on 4,096 random batches by default (the run for this draft used 100,000): the walk and prefix formulas agree; bought volume equals sold volume on every symbol; every fill is zero or between the minimum and the size; time priority holds; at most one order per symbol is partially filled; without binding minimums, matched volume is exactly min(B, S); each pass has at most one violator and the uncapped rule never needs the fail-safe; capped runs equal uncapped runs or fail safe exactly when they should; and each symbol's fills ignore every other symbol's orders. The random batches mix tiny sizes (to force ties and binding minimums) with sizes at the maximum.

Finally, three bugs are planted in the code behind feature flags: a minimum check that is off by one at the boundary, an elimination step that is skipped, and a prefix sum that wrongly counts an order as ahead of itself. `scripts/check_planted.sh` builds each one and passes only if the test suite fails for every one of them, which shows the tests can actually fail.
