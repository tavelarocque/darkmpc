//! The auction in malicious mode (Milestone 4a) must still equal the
//! reference, and must verify on honest runs.

use darkmpc_auction::{Params, run_auction, share_orders};
use darkmpc_mpc::run3;
use darkmpc_reference::{Order, Passes, Side, match_batch};
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

fn order() -> impl Strategy<Value = Order> {
    (0u32..4, any::<bool>(), 1u64..=12, 0u8..3, any::<u64>()).prop_map(|(symbol, buy, size, kind, r)| {
        let min_fill = match kind {
            0 => 1,
            1 => size,
            _ => 1 + r % size,
        };
        Order { symbol, side: if buy { Side::Buy } else { Side::Sell }, size, min_fill }
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(24)))]

    #[test]
    fn malicious_mode_equals_reference(orders in prop::collection::vec(order(), 1..24), k in 1u32..4, seed in any::<u64>()) {
        let params = Params { symbol_bits: 2, passes: k, malicious: true, validate: true };
        let views = share_orders(&orders, 2, splitmix(seed));
        let out = run3(false, |p| {
            let f = run_auction(p, &views[p.id], params)?;
            p.open_a_safe(&f)
        });
        let want = match_batch(&orders, darkmpc_reference::Params { passes: Passes::Fixed(k) }).unwrap();
        for r in out {
            prop_assert_eq!(r.expect("honest malicious-mode run aborted"), want.clone());
        }
    }
}
