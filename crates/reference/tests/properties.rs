//! Property tests: invariants every correct Stage 1 matcher satisfies.
//! Set PROPTEST_CASES to raise the case count (default here: 4096 per property).

use std::collections::{BTreeMap, BTreeSet};

use darkmpc_reference::*;
use proptest::prelude::*;

/// Sizes mix tiny values (lots of ties, minimum fills that bind) with
/// occasional values near MAX_SIZE.
fn size() -> impl Strategy<Value = u64> {
    prop_oneof![8 => 1u64..=12, 1 => 1u64..=MAX_SIZE, 1 => (MAX_SIZE - 3)..=MAX_SIZE]
}

/// Minimum fills: often none, often all-or-none, otherwise anything legal.
fn order() -> impl Strategy<Value = Order> {
    (0u32..4, any::<bool>(), size(), 0u8..3, any::<u64>()).prop_map(|(symbol, buy, size, kind, r)| {
        let min_fill = match kind {
            0 => 1,
            1 => size,
            _ => 1 + r % size,
        };
        let side = if buy { Side::Buy } else { Side::Sell };
        Order { symbol, side, size, min_fill }
    })
}

fn batch() -> impl Strategy<Value = Vec<Order>> {
    prop::collection::vec(order(), 0..48)
}

fn book() -> impl Strategy<Value = Vec<(Side, u64)>> {
    prop::collection::vec((prop_oneof![Just(Side::Buy), Just(Side::Sell)], size()), 0..48)
}

fn symbols(o: &[Order]) -> BTreeSet<u32> {
    o.iter().map(|x| x.symbol).collect()
}

fn side_total(o: &[Order], fills: &[u64], symbol: u32, side: Side) -> u64 {
    o.iter().zip(fills).filter(|(x, _)| x.symbol == symbol && x.side == side).map(|(_, f)| f).sum()
}

fn config() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(4096);
    ProptestConfig::with_cases(cases)
}

proptest! {
    #![proptest_config(config())]

    /// The sequential walk (prior work) and the prefix formula (what MPC will
    /// evaluate) are two independent statements of time priority. They agree.
    #[test]
    fn walk_equals_prefix(b in book()) {
        prop_assert_eq!(allocate_walk(&b), allocate_prefix(&b));
    }

    /// Bought volume equals sold volume on every symbol.
    #[test]
    fn conservation(o in batch()) {
        let f = match_batch(&o, Params::default()).unwrap();
        for s in symbols(&o) {
            prop_assert_eq!(side_total(&o, &f, s, Side::Buy), side_total(&o, &f, s, Side::Sell));
        }
    }

    /// Every fill is 0 or between the order's minimum and its size, under
    /// any pass cap.
    #[test]
    fn fills_respect_size_and_minimum(o in batch(), k in 1u32..6) {
        for passes in [Passes::UntilStable, Passes::Fixed(k)] {
            let f = match_batch(&o, Params { passes }).unwrap();
            for (x, &q) in o.iter().zip(&f) {
                prop_assert!(q <= x.size);
                prop_assert!(q == 0 || q >= x.min_fill, "fill {} below minimum {}", q, x.min_fill);
            }
        }
    }

    /// Time priority: if an order on a side gets anything, every earlier
    /// order on that side got all of its size or nothing (was eliminated).
    #[test]
    fn time_priority(o in batch()) {
        let f = match_batch(&o, Params::default()).unwrap();
        for j in 0..o.len() {
            if f[j] == 0 { continue; }
            for i in 0..j {
                if o[i].symbol == o[j].symbol && o[i].side == o[j].side {
                    prop_assert!(f[i] == 0 || f[i] == o[i].size, "earlier order {} partially filled before {}", i, j);
                }
            }
        }
    }

    /// At most one order per symbol is partially filled (the marginal order).
    #[test]
    fn at_most_one_partial_per_symbol(o in batch()) {
        let f = match_batch(&o, Params::default()).unwrap();
        let mut partial: BTreeMap<u32, usize> = BTreeMap::new();
        for (x, &q) in o.iter().zip(&f) {
            if q > 0 && q < x.size { *partial.entry(x.symbol).or_default() += 1; }
        }
        prop_assert!(partial.values().all(|&c| c <= 1));
    }

    /// With no binding minimums, one pass suffices and matched volume is
    /// exactly min(B, S): nothing that could trade is left on the table.
    #[test]
    fn maximal_without_minimums(mut o in batch()) {
        for x in o.iter_mut() { x.min_fill = 1; }
        let (f, traces) = match_batch_traced(&o, Params::default()).unwrap();
        for t in &traces { prop_assert_eq!(&t.violators_per_pass, &vec![0]); }
        for s in symbols(&o) {
            let b: u64 = o.iter().filter(|x| x.symbol == s && x.side == Side::Buy).map(|x| x.size).sum();
            let v: u64 = o.iter().filter(|x| x.symbol == s && x.side == Side::Sell).map(|x| x.size).sum();
            prop_assert_eq!(side_total(&o, &f, s, Side::Buy), b.min(v));
        }
    }

    /// The lemma in matcher.rs: each pass finds at most one violator, and the
    /// uncapped rule never needs the fail-safe.
    #[test]
    fn at_most_one_violator_per_pass(o in batch()) {
        let (_, traces) = match_batch_traced(&o, Params::default()).unwrap();
        for t in traces {
            prop_assert!(t.violators_per_pass.iter().all(|&v| v <= 1), "{:?}", t);
            prop_assert!(!t.fail_safe);
            prop_assert_eq!(*t.violators_per_pass.last().unwrap(), 0);
        }
    }

    /// A cap of k passes gives the uncapped answer on every symbol that
    /// stabilises within k passes, and the all-zero fail-safe on the rest.
    #[test]
    fn capped_matches_uncapped_or_fails_safe(o in batch(), k in 1u32..5) {
        let (full, full_t) = match_batch_traced(&o, Params::default()).unwrap();
        let (cap, cap_t) = match_batch_traced(&o, Params { passes: Passes::Fixed(k) }).unwrap();
        for (ft, ct) in full_t.iter().zip(&cap_t) {
            let needed = ft.violators_per_pass.len() as u32;
            prop_assert_eq!(ct.fail_safe, needed > k);
            for (i, x) in o.iter().enumerate() {
                if x.symbol != ft.symbol { continue; }
                if needed <= k { prop_assert_eq!(cap[i], full[i]); } else { prop_assert_eq!(cap[i], 0); }
            }
        }
    }

    /// A symbol's fills do not depend on any other symbol's orders.
    #[test]
    fn symbol_independence(o in batch()) {
        let f = match_batch(&o, Params::default()).unwrap();
        for s in symbols(&o) {
            let idx: Vec<usize> = (0..o.len()).filter(|&i| o[i].symbol == s).collect();
            let alone: Vec<Order> = idx.iter().map(|&i| o[i]).collect();
            let g = match_batch(&alone, Params::default()).unwrap();
            for (k, &i) in idx.iter().enumerate() { prop_assert_eq!(f[i], g[k]); }
        }
    }
}
