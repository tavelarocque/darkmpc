//! Stage 2 reference: hand-worked cases and invariants, plus two independent
//! cross-checks (brute-force maximality over every integer price, and
//! equality with Stage 1 when all limits coincide).

use std::collections::{BTreeMap, BTreeSet};

use darkmpc_reference::*;
use proptest::prelude::*;

/// Buys 100@105, 50@103; sells 80@101, 60@104.
/// p=101: D=150, S=80, V=80.  p=103: D=150, S=80, V=80.
/// p=104: D=100, S=140, V=100, surplus 40.  p=105: same.
/// Max volume 100 at 104 and 105, equal surplus: lowest price, 104.
/// Buys >= 104: only 100@105, filled 100. Sells <= 104: 80@101 then 60@104
/// by price priority: 80 and 20.
#[test]
fn simple_cross() {
    let o = [
        LimitOrder::buy(0, 100, 105),
        LimitOrder::buy(0, 50, 103),
        LimitOrder::sell(0, 80, 101),
        LimitOrder::sell(0, 60, 104),
    ];
    let (f, p) = match_stage2(&o).unwrap();
    assert_eq!(p[&0], 104);
    assert_eq!(f, vec![100, 0, 80, 20]);
}

/// Bid below ask: nothing trades and no price is set.
#[test]
fn no_cross() {
    let o = [LimitOrder::buy(0, 10, 100), LimitOrder::sell(0, 10, 101)];
    let (f, p) = match_stage2(&o).unwrap();
    assert_eq!(f, vec![0, 0]);
    assert!(p.is_empty());
}

/// Buys 10@102, 10@100; sells 10@99, 5@101. V = 10 at every candidate;
/// surplus 10 at 99 and 100, 5 at 101 and 102: price 101 (lowest of those).
/// Buys >= 101: 10@102 -> 10. Sells <= 101: 99 first -> 10, then 101 -> 0.
#[test]
fn surplus_breaks_volume_ties() {
    let o = [
        LimitOrder::buy(0, 10, 102),
        LimitOrder::buy(0, 10, 100),
        LimitOrder::sell(0, 10, 99),
        LimitOrder::sell(0, 5, 101),
    ];
    let (f, p) = match_stage2(&o).unwrap();
    assert_eq!(p[&0], 101);
    assert_eq!(f, vec![10, 0, 10, 0]);
}

/// Buys 5@100 (first), 5@101 (second); sell 8@99.
/// p=99 and p=100: D=10, S=8, V=8, surplus 2. p=101: V=5. Price 99.
/// Both buys eligible; price priority puts the later 101 buy first: 5, then 3.
#[test]
fn price_priority_beats_time() {
    let o = [LimitOrder::buy(0, 5, 100), LimitOrder::buy(0, 5, 101), LimitOrder::sell(0, 8, 99)];
    let (f, p) = match_stage2(&o).unwrap();
    assert_eq!(p[&0], 99);
    assert_eq!(f, vec![3, 5, 8]);
}

/// Found by the property test: buy 13 @ 101, sell 1 @ 95. D = 13 and S = 1
/// at both candidate prices (nothing enters or leaves between them), so
/// volume and surplus tie and the lowest price, 95, wins. A shortcut that
/// takes the last price below the crossing would wrongly say 101.
#[test]
fn flat_stretch_takes_its_lowest_price() {
    let o = [LimitOrder::buy(1, 13, 101), LimitOrder::sell(1, 1, 95)];
    let book: Vec<&LimitOrder> = o.iter().collect();
    assert_eq!(clearing_price(&book), Some(95));
    assert_eq!(clearing_price_by_crossing(&book), Some(95));
    let (f, _) = match_stage2(&o).unwrap();
    assert_eq!(f, vec![1, 1]);
}

#[test]
fn rejects_bad_limits() {
    assert!(match_stage2(&[LimitOrder::buy(0, 1, 0)]).is_err());
    assert!(match_stage2(&[LimitOrder::buy(0, 1, MAX_PRICE + 1)]).is_err());
}

fn order() -> impl Strategy<Value = LimitOrder> {
    (0u32..3, any::<bool>(), 1u64..=20, 95u64..=105).prop_map(|(symbol, buy, size, limit)| LimitOrder {
        symbol,
        side: if buy { Side::Buy } else { Side::Sell },
        size,
        limit,
    })
}

fn cases() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(4096);
    ProptestConfig::with_cases(cases)
}

fn by_symbol(o: &[LimitOrder]) -> BTreeMap<u32, Vec<&LimitOrder>> {
    let mut m: BTreeMap<u32, Vec<&LimitOrder>> = BTreeMap::new();
    for x in o {
        m.entry(x.symbol).or_default().push(x);
    }
    m
}

proptest! {
    #![proptest_config(cases())]

    /// Bought = sold per symbol; fills within size; only eligible orders fill.
    #[test]
    fn conservation_and_eligibility(o in prop::collection::vec(order(), 0..40)) {
        let (f, prices) = match_stage2(&o).unwrap();
        for s in o.iter().map(|x| x.symbol).collect::<BTreeSet<_>>() {
            let bought: u64 = o.iter().zip(&f).filter(|(x, _)| x.symbol == s && x.side == Side::Buy).map(|(_, q)| q).sum();
            let sold: u64 = o.iter().zip(&f).filter(|(x, _)| x.symbol == s && x.side == Side::Sell).map(|(_, q)| q).sum();
            prop_assert_eq!(bought, sold);
        }
        for (x, &q) in o.iter().zip(&f) {
            prop_assert!(q <= x.size);
            if q > 0 {
                let p = prices[&x.symbol];
                match x.side {
                    Side::Buy => prop_assert!(x.limit >= p),
                    Side::Sell => prop_assert!(x.limit <= p),
                }
            }
        }
    }

    /// Independent oracle: no integer price anywhere in range executes more
    /// volume than was traded.
    #[test]
    fn traded_volume_is_maximal_over_all_prices(o in prop::collection::vec(order(), 0..40)) {
        let (f, _) = match_stage2(&o).unwrap();
        for (s, book) in by_symbol(&o) {
            let traded: u64 = o.iter().zip(&f).filter(|(x, _)| x.symbol == s && x.side == Side::Buy).map(|(_, q)| q).sum();
            for p in 1..=200u64 {
                let (d, sup) = demand_supply(&book, p);
                prop_assert!(d.min(sup) <= traded, "price {} beats the chosen price", p);
            }
        }
    }

    /// Price then time priority: if an eligible order on a side got anything,
    /// every eligible order with strictly better priority got all of its size.
    #[test]
    fn price_time_priority(o in prop::collection::vec(order(), 0..40)) {
        let (f, prices) = match_stage2(&o).unwrap();
        for j in 0..o.len() {
            if f[j] == 0 { continue; }
            for i in 0..o.len() {
                if i == j || o[i].symbol != o[j].symbol || o[i].side != o[j].side { continue; }
                let p = prices[&o[j].symbol];
                let (better, eligible) = match o[i].side {
                    Side::Buy => (o[i].limit > o[j].limit || (o[i].limit == o[j].limit && i < j), o[i].limit >= p),
                    Side::Sell => (o[i].limit < o[j].limit || (o[i].limit == o[j].limit && i < j), o[i].limit <= p),
                };
                if better && eligible { prop_assert_eq!(f[i], o[i].size); }
            }
        }
    }

    /// The lemma the MPC design relies on: over increasing candidate prices,
    /// [S(p) >= D(p)] switches from 0 to 1 at most once (D falls, S rises).
    #[test]
    fn crossing_indicator_is_monotone(o in prop::collection::vec(order(), 0..40)) {
        for (_, book) in by_symbol(&o) {
            let mut prices: Vec<u64> = book.iter().map(|x| x.limit).collect();
            prices.sort_unstable();
            prices.dedup();
            let c: Vec<bool> = prices.iter().map(|&p| { let (d, s) = demand_supply(&book, p); s >= d }).collect();
            prop_assert!(c.windows(2).all(|w| w[0] <= w[1]), "{:?}", c);
        }
    }

    /// The two-candidate shortcut the MPC version uses finds exactly the
    /// brute-force clearing price.
    #[test]
    fn crossing_shortcut_equals_brute_force(o in prop::collection::vec(order(), 0..40)) {
        for (_, book) in by_symbol(&o) {
            prop_assert_eq!(clearing_price_by_crossing(&book), clearing_price(&book));
        }
    }

    /// Cross-check against Stage 1: with every limit equal, Stage 2 is the
    /// Stage 1 volume match with no minimum fills.
    #[test]
    fn equal_limits_reduce_to_stage1(o in prop::collection::vec(order(), 0..40)) {
        let flat: Vec<LimitOrder> = o.iter().map(|x| LimitOrder { limit: 100, ..*x }).collect();
        let (f2, _) = match_stage2(&flat).unwrap();
        let s1: Vec<Order> = o.iter().map(|x| Order { symbol: x.symbol, side: x.side, size: x.size, min_fill: 1 }).collect();
        let f1 = match_batch(&s1, Params::default()).unwrap();
        prop_assert_eq!(f2, f1);
    }
}
