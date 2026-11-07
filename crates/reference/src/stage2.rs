//! Stage 2 mechanism: a uniform-price call auction with limit prices.
//!
//! Per symbol, per auction:
//!
//! 1. **Price.** For a candidate price p, demand D(p) is the total size of
//!    buys with limit >= p and supply S(p) the total size of sells with limit
//!    <= p; executable volume is V(p) = min(D(p), S(p)) and surplus
//!    |D(p) - S(p)|. The clearing price p* is chosen among the limit prices
//!    present on the symbol by, in order: maximum executable volume, then
//!    minimum surplus, then the lowest price. If the maximum volume is 0 the
//!    symbol does not trade.
//!
//!    The first two criteria are those of Cboe Europe Periodic Auctions
//!    ("1 Maximum executable volume, 2 Minimum surplus, 3 Market pressure,
//!    4 Reference price"). Their steps 3 and 4 need a public reference price
//!    per symbol; with symbols hidden that lookup would itself be secret, so
//!    darkmpc breaks remaining ties by the lowest price. That is a deliberate
//!    simplification, not a claim about best practice.
//!
//!    Restricting candidates to limit prices loses nothing: D and S only
//!    change at limit prices, so V attains its maximum at one of them (the
//!    tests check this against every integer price in range).
//!
//! 2. **Allocation.** At p*, buys with limit >= p* and sells with limit <= p*
//!    are eligible. Each side shares out V(p*) by price priority (buys: higher
//!    limit first; sells: lower limit first), then time priority (arrival
//!    order), each order taking min(size, what is left).
//!
//! Stage 2 has no minimum fills: removing an order for its minimum could move
//! the clearing price, and the interaction is left out of scope.

use std::collections::BTreeMap;

use crate::types::{MAX_BATCH, MAX_SIZE, Side};

/// Largest limit price, in ticks: 2^20 - 1.
pub const MAX_PRICE: u64 = (1 << 20) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LimitOrder {
    pub symbol: u32,
    pub side: Side,
    /// Shares, 1..=MAX_SIZE.
    pub size: u64,
    /// Limit price in ticks, 1..=MAX_PRICE.
    pub limit: u64,
}

impl LimitOrder {
    pub const fn buy(symbol: u32, size: u64, limit: u64) -> Self {
        LimitOrder { symbol, side: Side::Buy, size, limit }
    }
    pub const fn sell(symbol: u32, size: u64, limit: u64) -> Self {
        LimitOrder { symbol, side: Side::Sell, size, limit }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stage2Invalid {
    BatchTooLarge,
    SizeOutOfRange { index: usize },
    LimitOutOfRange { index: usize },
}

pub fn validate_stage2(orders: &[LimitOrder]) -> Result<(), Stage2Invalid> {
    if orders.len() > MAX_BATCH {
        return Err(Stage2Invalid::BatchTooLarge);
    }
    for (index, o) in orders.iter().enumerate() {
        if o.size == 0 || o.size > MAX_SIZE {
            return Err(Stage2Invalid::SizeOutOfRange { index });
        }
        if o.limit == 0 || o.limit > MAX_PRICE {
            return Err(Stage2Invalid::LimitOutOfRange { index });
        }
    }
    Ok(())
}

/// Demand and supply at price p over one symbol's orders.
pub fn demand_supply(book: &[&LimitOrder], p: u64) -> (u64, u64) {
    let d = book.iter().filter(|o| o.side == Side::Buy && o.limit >= p).map(|o| o.size).sum();
    let s = book.iter().filter(|o| o.side == Side::Sell && o.limit <= p).map(|o| o.size).sum();
    (d, s)
}

/// The clearing price of one symbol, or None if nothing can trade.
pub fn clearing_price(book: &[&LimitOrder]) -> Option<u64> {
    let mut best: Option<(u64, u64, u64)> = None; // (volume, surplus, price)
    let mut prices: Vec<u64> = book.iter().map(|o| o.limit).collect();
    prices.sort_unstable();
    prices.dedup();
    for p in prices {
        let (d, s) = demand_supply(book, p);
        let (v, surplus) = (d.min(s), d.abs_diff(s));
        let better = match best {
            None => true,
            Some((bv, bs, _)) => {
                if cfg!(feature = "plant-stage2-no-surplus") {
                    v > bv // PLANTED BUG: surplus tie-break missing
                } else {
                    v > bv || (v == bv && surplus < bs)
                }
            }
        };
        if better {
            best = Some((v, surplus, p));
        }
    }
    best.filter(|&(v, _, _)| v > 0).map(|(_, _, p)| p)
}

/// The same clearing price, found the way the MPC version will find it.
///
/// Over increasing candidate prices D falls and S rises, so [S >= D] flips
/// from 0 to 1 at most once.
///
/// Where S >= D the volume is D, which falls with p, and the surplus S - D
/// rises, so the *first* such price is best (and is also the lowest).
///
/// Where S < D the volume is S, which rises with p, and the surplus D - S
/// falls, so nothing beats the *last* such price, but earlier prices can tie
/// it exactly: D and S need not change between two candidate prices (a buy
/// leaves demand only above its limit, a sell joins supply only at its
/// limit). Example: buy 13 @ 101, sell 1 @ 95 gives D = 13, S = 1 at both 95
/// and 101. The lowest-price rule then picks the *first* price of that final
/// flat stretch. (An earlier version of this function took the last price
/// and the property test below found the counterexample above.)
///
/// So only two candidates need comparing: the first price of the flat
/// stretch that ends at the last S < D price, and the first S >= D price.
/// Tests require this to equal [`clearing_price`].
pub fn clearing_price_by_crossing(book: &[&LimitOrder]) -> Option<u64> {
    let mut prices: Vec<u64> = book.iter().map(|o| o.limit).collect();
    prices.sort_unstable();
    prices.dedup();
    let ds: Vec<(u64, u64)> = prices.iter().map(|&p| demand_supply(book, p)).collect();
    let flip = ds.iter().position(|&(d, s)| s >= d).unwrap_or(prices.len());
    let mut candidates = Vec::new();
    if flip > 0 {
        // Walk back over the flat stretch ending at the last S < D price.
        let mut start = flip - 1;
        while start > 0 && ds[start - 1] == ds[flip - 1] {
            start -= 1;
        }
        candidates.push(prices[start]);
    }
    if flip < prices.len() {
        candidates.push(prices[flip]);
    }
    let mut best: Option<(u64, u64, u64)> = None;
    for p in candidates {
        let (d, s) = demand_supply(book, p);
        let key = (d.min(s), d.abs_diff(s), p);
        let better = match best {
            None => true,
            Some((bv, bs, _)) => key.0 > bv || (key.0 == bv && key.1 < bs),
        };
        if better {
            best = Some(key);
        }
    }
    best.filter(|&(v, _, _)| v > 0).map(|(_, _, p)| p)
}

/// Run Stage 2 on a batch. Returns each order's fill and each symbol's
/// clearing price (symbols that do not trade are absent).
pub fn match_stage2(orders: &[LimitOrder]) -> Result<(Vec<u64>, BTreeMap<u32, u64>), Stage2Invalid> {
    validate_stage2(orders)?;
    let mut groups: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    for (i, o) in orders.iter().enumerate() {
        groups.entry(o.symbol).or_default().push(i);
    }
    let mut fills = vec![0u64; orders.len()];
    let mut prices = BTreeMap::new();
    for (symbol, members) in groups {
        let book: Vec<&LimitOrder> = members.iter().map(|&i| &orders[i]).collect();
        let Some(p) = clearing_price(&book) else { continue };
        prices.insert(symbol, p);
        let (d, s) = demand_supply(&book, p);
        let volume = d.min(s);
        // Buys: limit >= p, highest limit first, then arrival.
        let mut buys: Vec<usize> =
            members.iter().copied().filter(|&i| orders[i].side == Side::Buy && orders[i].limit >= p).collect();
        if cfg!(feature = "plant-stage2-time-before-price") {
            buys.sort_unstable(); // PLANTED BUG: arrival order only, price priority ignored
        } else {
            buys.sort_by_key(|&i| (std::cmp::Reverse(orders[i].limit), i));
        }
        // Sells: limit <= p, lowest limit first, then arrival.
        let mut sells: Vec<usize> =
            members.iter().copied().filter(|&i| orders[i].side == Side::Sell && orders[i].limit <= p).collect();
        sells.sort_by_key(|&i| (orders[i].limit, i));
        for side in [buys, sells] {
            let mut left = volume;
            for i in side {
                let f = orders[i].size.min(left);
                fills[i] = f;
                left -= f;
            }
        }
    }
    Ok((fills, prices))
}
