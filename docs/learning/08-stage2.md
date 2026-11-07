# Milestone 5a: an auction with prices

## What changes when orders carry limits

In Stage 1 every order traded at the public midpoint, so the only question per symbol was how much. Stage 2 lets each order name a limit: a buyer will pay at most its limit, a seller will take at least its limit. Now the auction must also choose a price, and different prices let different orders in. The rule used here is the one most periodic auctions use. For each possible price $p$, demand $D(p)$ is the total size of buys willing to pay $p$, and supply $S(p)$ is the total size of sells willing to accept it. The volume that can trade at $p$ is the smaller of the two. The auction picks the price with the most volume. If several tie, it picks the one where the leftover imbalance $|D - S|$ is smallest. If they still tie, it takes the lowest. Those first two steps are the first two criteria Cboe Europe publishes for its Periodic Auctions; the third is my simplification, because Cboe's later steps need a public reference price, which would have to be a secret lookup when the symbol is hidden.

The plain version of this rule is easy: try every limit price that appears, compute $D$ and $S$, keep the best. The MPC version cannot "try every price and keep the best" cheaply, because every comparison on shares costs rounds, and the servers must do the same work whatever the data. So the real design question was how to find the best price without a search.

## The shape of demand and supply

The answer comes from the shape of the two curves. As the price rises, buyers drop out, so demand can only fall; sellers join, so supply can only rise. Picture two staircases, one stepping down and one stepping up. They cross once. Before the crossing, supply is the short side, so the volume is $S$, which grows as you move right. After it, demand is the short side, so the volume is $D$, which shrinks. The best price must sit right at the crossing.

That leaves exactly two contenders: the first price at or after the crossing, and the best price just before it. The first is unambiguous. The second hides a trap, and I fell into it. I assumed the best price before the crossing was simply the last one, the price immediately to the left. The property test, which compares the shortcut with the brute-force search on random books, found a two-order counterexample within seconds: a buy of 13 at 101 and a sell of 1 at 95. At both prices demand is 13 and supply is 1, because nothing enters or leaves between them. A buy only drops out *above* its limit and a sell only joins *at* its limit. The two prices tie on everything, and the lowest-price rule picks 95, not 101. The fix is to take the first price of the flat stretch that ends just before the crossing. The lesson is the reason the reference exists: the mistake was in the mechanism, not the cryptography, and a plain program with an oracle caught it before a single share was involved.

## Doing it on shares

Sort the orders by symbol and then limit. Orders with the same symbol and the same limit form a *run*. Along a symbol, the runs appear in increasing price order, which is exactly the order in which to walk the two staircases.

Demand at an order's own limit is the buys from its run to the end of the symbol. Supply is the sells from the start of the symbol to the end of its run. Both are sums over the symbol corrected by sums over the run, and sums over segments are what the scans from Milestone 3 compute. So every order learns, on shares, the $(D, S)$ of its own price.

Finding the crossing is then local. Let $c = [S \ge D]$ at each position. It is 0 and then 1 along a symbol, never back, so the first 1 is where $c$ differs from its predecessor: one multiplication, no search. Finding the flat stretch uses the same shape. Because $D$ only falls and $S$ only rises, the quantity $(D_{\text{prev}} - D) + (S - S_{\text{prev}})$ is never negative, and it is zero exactly when nothing changed. One comparison with zero detects a change. Wherever a change happens a new block starts, and the block holding the last position before the crossing is the flat stretch; its first position is the second candidate.

Each symbol then sums its two candidates' volume, surplus and price into every position, compares them, and selects the clearing price. Every step has the same cost whatever the books look like, which is what makes it safe to run on secrets.

## Allocation without a second sort

The draft design planned a second sort, because allocation needs a different order: sells by lowest limit first, buys by highest limit first, then arrival. Writing the code showed that the first sort already gives both. For sells, ascending limit then arrival is the sorted order itself. For a buy, the eligible buys ahead of it are those at higher limits, which are the later runs of its symbol, plus those earlier in its own run. That is once more a symbol sum minus a run sum. So allocation needs scans, not a sort, and the clamp formula from Stage 1, fill $= \min(\text{size}, \max(0, V^* - \text{ahead}))$, finishes the job.

A related saving applies to both stages. A scan over $n$ positions takes about $\log_2 n$ rounds, and the auctions run several scans side by side: forward and backward, over symbols and over runs. Laying them end to end in one long sequence, with each piece starting a new segment so no sum leaks from one piece into the next, runs them all in one scan of a few more rounds. That cut Stage 1 from 316 to 280 rounds at 1,024 orders.

## What it costs, and what a trader learns

Measured on simulated networks, Stage 2 sends about two and a half times Stage 1's data, but on a 40 ms network it takes only 1.1 to 1.3 times as long, because there time is set by rounds, and Stage 2 has almost the same round count. Its sort is longer, but it has no elimination passes.

A filled trader must learn the price, or the trade cannot settle, so each order's output is its fill and, if filled, the price. That reveals something the cryptography cannot hide: the price is always some order's limit, so a filled trader whose limit differs learns that someone named exactly that price. This leak comes from how the auction is defined, not from the protocol, and the write-up says so.

Three planted bugs guard the new code: dropping the flat-stretch candidate, letting a sell trade only strictly below the price, and allocating buys by arrival alone. Each one breaks the differential tests, which is the evidence that the tests can see those mistakes.
