//! Stage 2 differential tests: the MPC auction must produce exactly the
//! reference's fills, and the reference's clearing price for every filled
//! order (0 for unfilled ones), on every batch.

use std::collections::BTreeMap;

use darkmpc_auction::{SharedLimitOrder, Stage2Params, run_stage2, share_limit_orders, validate_stage2_inputs};
use darkmpc_mpc::{A, run3, share_a};
use darkmpc_reference::{LimitOrder, MAX_PRICE, MAX_SIZE, Side, match_stage2};
use proptest::prelude::*;

fn splitmix(seed: u64) -> impl FnMut() -> u64 {
    let mut s = seed;
    move || {
        s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = s;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

fn open_both(p: &mut darkmpc_mpc::Party, views: &[SharedLimitOrder], params: Stage2Params) -> (Vec<u64>, Vec<u64>) {
    let out = run_stage2(p, views, params).expect("honest run must not abort");
    let f = p.open_a_safe(&out.fill).expect("honest run must not abort");
    let q = p.open_a_safe(&out.price).expect("honest run must not abort");
    (f, q)
}

fn mpc(orders: &[LimitOrder], symbol_bits: usize, malicious: bool, seed: u64) -> (Vec<u64>, Vec<u64>) {
    let views = share_limit_orders(orders, symbol_bits, splitmix(seed));
    let params = Stage2Params { symbol_bits, malicious, validate: malicious };
    let out = run3(false, |p| open_both(p, &views[p.id], params));
    assert_eq!(out[0], out[1]);
    assert_eq!(out[1], out[2]);
    out[0].clone()
}

/// What the reference says each order should receive.
fn want(orders: &[LimitOrder]) -> (Vec<u64>, Vec<u64>) {
    let (fills, prices): (Vec<u64>, BTreeMap<u32, u64>) = match_stage2(orders).unwrap();
    let price = orders.iter().zip(&fills).map(|(o, &f)| if f > 0 { prices[&o.symbol] } else { 0 }).collect();
    (fills, price)
}

fn check(orders: &[LimitOrder], symbol_bits: usize, malicious: bool, seed: u64) {
    assert_eq!(mpc(orders, symbol_bits, malicious, seed), want(orders), "orders: {orders:?}");
}

#[test]
fn simple_cross() {
    let o = vec![
        LimitOrder::buy(0, 100, 105),
        LimitOrder::buy(0, 50, 100),
        LimitOrder::sell(0, 80, 98),
        LimitOrder::sell(0, 70, 104),
    ];
    check(&o, 1, false, 1);
}

#[test]
fn flat_stretch_takes_its_lowest_price() {
    // D = 13, S = 1 at both 95 and 101: the lower price wins the full tie.
    let o = vec![LimitOrder::buy(0, 13, 101), LimitOrder::sell(0, 1, 95)];
    assert_eq!(want(&o), (vec![1, 1], vec![95, 95]));
    check(&o, 1, false, 2);
}

#[test]
fn sell_at_exactly_the_clearing_price_trades() {
    let o = vec![LimitOrder::buy(0, 5, 100), LimitOrder::sell(0, 5, 100)];
    assert_eq!(want(&o), (vec![5, 5], vec![100, 100]));
    check(&o, 1, false, 3);
}

#[test]
fn price_priority_beats_time() {
    let o = vec![LimitOrder::buy(0, 5, 100), LimitOrder::buy(0, 5, 102), LimitOrder::sell(0, 5, 99)];
    assert_eq!(want(&o).0, vec![0, 5, 5]);
    check(&o, 1, false, 4);
}

#[test]
fn no_cross_and_single_order() {
    check(&[LimitOrder::buy(0, 5, 99), LimitOrder::sell(0, 5, 100)], 1, false, 5);
    check(&[LimitOrder::sell(3, 5, 1)], 2, false, 6);
    check(&[], 2, false, 7);
}

#[test]
fn extreme_values() {
    let o = vec![
        LimitOrder::buy(1, MAX_SIZE, MAX_PRICE),
        LimitOrder::sell(1, MAX_SIZE, 1),
        LimitOrder::sell(1, MAX_SIZE, MAX_PRICE),
        LimitOrder::buy(1, 1, 1),
    ];
    check(&o, 1, false, 8);
}

fn size() -> impl Strategy<Value = u64> {
    prop_oneof![8 => 1u64..=12, 1 => 1u64..=MAX_SIZE]
}

/// Few distinct prices so ties, runs and flat stretches are common.
fn limit() -> impl Strategy<Value = u64> {
    prop_oneof![8 => 95u64..=105, 1 => 1u64..=MAX_PRICE, 1 => Just(1), 1 => Just(MAX_PRICE)]
}

fn order(max_symbol: u32) -> impl Strategy<Value = LimitOrder> {
    (0..max_symbol, any::<bool>(), size(), limit()).prop_map(|(symbol, buy, size, limit)| LimitOrder {
        symbol,
        side: if buy { Side::Buy } else { Side::Sell },
        size,
        limit,
    })
}

fn cases() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(128);
    ProptestConfig::with_cases(cases)
}

proptest! {
    #![proptest_config(cases())]

    #[test]
    fn mpc_equals_reference(o in prop::collection::vec(order(4), 0..40), seed in any::<u64>()) {
        prop_assert_eq!(mpc(&o, 2, false, seed), want(&o));
    }

    /// One symbol, many orders: long runs and deep books.
    #[test]
    fn mpc_equals_reference_one_symbol(o in prop::collection::vec(order(1), 1..60), seed in any::<u64>()) {
        prop_assert_eq!(mpc(&o, 1, false, seed), want(&o));
    }

    #[test]
    fn malicious_mode_equals_reference(o in prop::collection::vec(order(3), 0..24), seed in any::<u64>()) {
        prop_assert_eq!(mpc(&o, 2, true, seed), want(&o));
    }
}

// ----- malicious traders -----

fn share_raw(
    sym: &[u64],
    side: u64,
    size: u64,
    limit_bits: &[u64],
    r: &mut impl FnMut() -> u64,
) -> [SharedLimitOrder; 3] {
    let s: Vec<[A; 3]> = sym.iter().map(|&b| share_a(b, &mut *r)).collect();
    let l: Vec<[A; 3]> = limit_bits.iter().map(|&b| share_a(b, &mut *r)).collect();
    let (sd, sz) = (share_a(side, &mut *r), share_a(size, &mut *r));
    [0, 1, 2].map(|i| SharedLimitOrder {
        symbol_bits: s.iter().map(|b| b[i]).collect(),
        side: sd[i],
        size: sz[i],
        limit_bits: l.iter().map(|b| b[i]).collect(),
    })
}

fn bits_of(v: u64) -> Vec<u64> {
    (0..20).map(|b| (v >> b) & 1).collect()
}

fn bad_orders(r: &mut impl FnMut() -> u64) -> Vec<(&'static str, [SharedLimitOrder; 3])> {
    let mut two = bits_of(100);
    two[3] = 2;
    let mut inconsistent = share_raw(&[1], 0, 5, &bits_of(100), r);
    inconsistent[2].limit_bits[4].s1 ^= 1;
    vec![
        ("inconsistent limit bit", inconsistent),
        ("limit bit 2", share_raw(&[1], 0, 5, &two, r)),
        ("limit 0", share_raw(&[1], 1, 5, &bits_of(0), r)),
        ("size 0", share_raw(&[1], 1, 0, &bits_of(100), r)),
        ("size too big", share_raw(&[1], 0, MAX_SIZE + 1, &bits_of(100), r)),
        ("side 2", share_raw(&[1], 2, 5, &bits_of(100), r)),
        ("symbol bit 2", share_raw(&[2], 0, 5, &bits_of(100), r)),
    ]
}

/// Each bad order, placed among honest ones, is rejected (and only it), and
/// the honest orders still get exactly the reference's fills and prices.
#[test]
fn bad_orders_are_rejected_and_honest_ones_still_match() {
    let honest = vec![
        LimitOrder::buy(1, 10, 101),
        LimitOrder::sell(1, 6, 99),
        LimitOrder::sell(0, 4, 50),
        LimitOrder::buy(0, 4, 60),
    ];
    let (mut wf, mut wp) = want(&honest);
    wf.insert(2, 0);
    wp.insert(2, 0);
    let mut r = splitmix(11);
    for (name, bad) in bad_orders(&mut r) {
        let mut views = share_limit_orders(&honest, 1, &mut r);
        for i in 0..3 {
            views[i].insert(2, bad[i].clone());
        }
        let rejected = run3(false, |p| {
            p.malicious = true;
            let mut mine = views[p.id].clone();
            validate_stage2_inputs(p, &mut mine, 1)
        });
        for rej in rejected {
            let rej = rej.unwrap_or_else(|_| panic!("{name}: aborted"));
            assert_eq!(rej, (0..5).map(|k| k == 2).collect::<Vec<_>>(), "{name}");
        }
        let params = Stage2Params { symbol_bits: 1, malicious: true, validate: true };
        let out = run3(false, |p| open_both(p, &views[p.id], params));
        for o in out {
            assert_eq!(o, (wf.clone(), wp.clone()), "{name}");
        }
    }
}
