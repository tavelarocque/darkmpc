//! Differential tests: the MPC auction must produce exactly the reference
//! matcher's fills (with the same fixed pass count) on every batch.

use darkmpc_auction::{Params, run_auction, share_orders};
use darkmpc_mpc::run3;
use darkmpc_reference::{MAX_SIZE, Order, Passes, Side, match_batch};
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

/// Run the auction on three server threads and open every fill.
fn mpc_fills(orders: &[Order], params: Params, seed: u64) -> Vec<u64> {
    let views = share_orders(orders, params.symbol_bits, splitmix(seed));
    let out = run3(false, |p| {
        let f = run_auction(p, &views[p.id], params).expect("honest run must not abort");
        p.open_a_safe(&f).expect("honest run must not abort")
    });
    assert_eq!(out[0], out[1]);
    assert_eq!(out[1], out[2]);
    out[0].clone()
}

fn reference_fills(orders: &[Order], k: u32) -> Vec<u64> {
    match_batch(orders, darkmpc_reference::Params { passes: Passes::Fixed(k) }).unwrap()
}

fn size() -> impl Strategy<Value = u64> {
    prop_oneof![8 => 1u64..=12, 1 => 1u64..=MAX_SIZE, 1 => (MAX_SIZE - 3)..=MAX_SIZE]
}

fn order(max_symbol: u32) -> impl Strategy<Value = Order> {
    (0..max_symbol, any::<bool>(), size(), 0u8..3, any::<u64>()).prop_map(|(symbol, buy, size, kind, r)| {
        let min_fill = match kind {
            0 => 1,
            1 => size,
            _ => 1 + r % size,
        };
        Order { symbol, side: if buy { Side::Buy } else { Side::Sell }, size, min_fill }
    })
}

fn cases() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(128);
    ProptestConfig::with_cases(cases)
}

proptest! {
    #![proptest_config(cases())]

    /// Random batches over 8 symbols (3 symbol bits) with 1 to 4 passes.
    #[test]
    fn mpc_equals_reference(orders in prop::collection::vec(order(8), 1..40), k in 1u32..5, seed in any::<u64>()) {
        let params = Params { symbol_bits: 3, passes: k, malicious: false, validate: false };
        prop_assert_eq!(mpc_fills(&orders, params, seed), reference_fills(&orders, k));
    }

    /// Few symbols, so books are deep and minimum fills interact.
    #[test]
    fn mpc_equals_reference_deep_books(orders in prop::collection::vec(order(2), 1..48), k in 1u32..6, seed in any::<u64>()) {
        let params = Params { symbol_bits: 1, passes: k, malicious: false, validate: false };
        prop_assert_eq!(mpc_fills(&orders, params, seed), reference_fills(&orders, k));
    }
}

/// The worked example from "MPC Joins The Dark Side", Sec. 4.3.
#[test]
fn prior_work_example() {
    let o = [
        Order::sell(0, 3, 1),
        Order::sell(0, 4, 1),
        Order::sell(0, 5, 1),
        Order::buy(0, 5, 1),
        Order::buy(0, 2, 1),
        Order::buy(0, 11, 1),
        Order::buy(0, 1, 1),
    ];
    let p = Params { symbol_bits: 2, passes: 1, malicious: false, validate: false };
    assert_eq!(mpc_fills(&o, p, 1), vec![3, 4, 5, 5, 2, 5, 0]);
}

/// Elimination that alternates sides for three passes, and the fail-safe
/// at two (hand-worked in the reference crate's tests).
#[test]
fn three_pass_book_and_fail_safe() {
    let o = [
        Order::buy(0, 50, 1),
        Order::buy(0, 40, 40),
        Order::sell(0, 30, 1),
        Order::sell(0, 40, 35),
        Order::sell(0, 5, 1),
    ];
    assert_eq!(
        mpc_fills(&o, Params { symbol_bits: 1, passes: 3, malicious: false, validate: false }, 2),
        vec![35, 0, 30, 0, 5]
    );
    assert_eq!(mpc_fills(&o, Params { symbol_bits: 1, passes: 2, malicious: false, validate: false }, 3), vec![0; 5]);
}

/// Full 13-bit symbol field, symbols spread across the range, interleaved.
#[test]
fn full_symbol_width() {
    let mut r = splitmix(99);
    let syms = [0u32, 1, 4095, 4096, 8191, 777];
    let orders: Vec<Order> = (0..60)
        .map(|_| {
            let s = syms[(r() % syms.len() as u64) as usize];
            let size = 1 + r() % 20;
            let side = if r().is_multiple_of(2) { Side::Buy } else { Side::Sell };
            Order { symbol: s, side, size, min_fill: 1 + r() % size }
        })
        .collect();
    let p = Params { symbol_bits: 13, passes: 3, malicious: false, validate: false };
    assert_eq!(mpc_fills(&orders, p, 4), reference_fills(&orders, 3));
}

#[test]
fn single_order() {
    let p = Params { symbol_bits: 2, passes: 2, malicious: false, validate: false };
    assert_eq!(mpc_fills(&[Order::buy(3, 10, 5)], p, 5), vec![0]);
}
