//! Malicious traders (Milestone 4a step 2). Each bad order, placed among
//! honest ones, must be rejected (and only it), and the honest orders must
//! still get exactly the reference fills. Planted gaps in validation
//! (features plant-skip-*) must make these tests fail.

use darkmpc_auction::{Params, SharedOrder, run_auction, validate_inputs};
use darkmpc_mpc::{A, run3, share_a};
use darkmpc_reference::{MAX_SIZE, Order, Passes, match_batch};

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

const BITS: usize = 2;

/// Share raw field values exactly as a (possibly malicious) trader would.
fn share_raw(
    symbol_bits: &[u64],
    side: u64,
    size: u64,
    min_fill: u64,
    r: &mut impl FnMut() -> u64,
) -> [SharedOrder; 3] {
    let bits: Vec<[A; 3]> = symbol_bits.iter().map(|&b| share_a(b, &mut *r)).collect();
    let (sd, sz, mf) = (share_a(side, &mut *r), share_a(size, &mut *r), share_a(min_fill, &mut *r));
    [0, 1, 2].map(|i| SharedOrder {
        symbol_bits: bits.iter().map(|b| b[i]).collect(),
        side: sd[i],
        size: sz[i],
        min_fill: mf[i],
    })
}

fn honest(o: &Order, r: &mut impl FnMut() -> u64) -> [SharedOrder; 3] {
    let bits: Vec<u64> = (0..BITS).map(|b| (u64::from(o.symbol) >> b) & 1).collect();
    share_raw(&bits, matches!(o.side, darkmpc_reference::Side::Sell) as u64, o.size, o.min_fill, r)
}

fn honest_orders() -> Vec<Order> {
    vec![Order::buy(1, 10, 1), Order::sell(1, 6, 1), Order::buy(2, 7, 7), Order::sell(1, 3, 2), Order::sell(2, 9, 1)]
}

#[derive(Clone, Copy, Debug)]
enum Bad {
    Inconsistent,
    SizeHuge,
    SizeJustTooBig,
    SizeAllOnes,
    SideTwo,
    SymbolBitTwo,
    MinZero,
    MinAboveSize,
    SizeZero,
}

const ALL_BAD: [Bad; 9] = [
    Bad::Inconsistent,
    Bad::SizeHuge,
    Bad::SizeJustTooBig,
    Bad::SizeAllOnes,
    Bad::SideTwo,
    Bad::SymbolBitTwo,
    Bad::MinZero,
    Bad::MinAboveSize,
    Bad::SizeZero,
];

fn bad_order(kind: Bad, r: &mut impl FnMut() -> u64) -> [SharedOrder; 3] {
    match kind {
        Bad::Inconsistent => {
            let mut v = share_raw(&[1, 0], 0, 5, 1, r);
            v[1].size.s0 = v[1].size.s0.wrapping_add(1); // party 1's copy of summand 1 differs from party 0's
            v
        }
        Bad::SizeHuge => share_raw(&[1, 0], 0, 1 << 63, 1, r),
        Bad::SizeJustTooBig => share_raw(&[1, 0], 1, MAX_SIZE + 1, 1, r),
        Bad::SizeAllOnes => share_raw(&[1, 0], 1, u64::MAX, 1, r),
        Bad::SideTwo => share_raw(&[1, 0], 2, 5, 1, r),
        Bad::SymbolBitTwo => share_raw(&[2, 0], 0, 5, 1, r),
        Bad::MinZero => share_raw(&[1, 0], 0, 5, 0, r),
        Bad::MinAboveSize => share_raw(&[1, 0], 0, 5, 6, r),
        Bad::SizeZero => share_raw(&[1, 0], 0, 0, 1, r),
    }
}

/// Honest orders with one bad order inserted at index 2.
fn batch(kind: Bad, seed: u64) -> [Vec<SharedOrder>; 3] {
    let mut r = splitmix(seed);
    let mut views: [Vec<SharedOrder>; 3] = Default::default();
    for (k, o) in honest_orders().iter().enumerate() {
        if k == 2 {
            let b = bad_order(kind, &mut r);
            for i in 0..3 {
                views[i].push(b[i].clone());
            }
        }
        let h = honest(o, &mut r);
        for i in 0..3 {
            views[i].push(h[i].clone());
        }
    }
    views
}

#[test]
fn each_bad_order_is_rejected_and_only_it() {
    for (n, kind) in ALL_BAD.iter().enumerate() {
        let views = batch(*kind, 100 + n as u64);
        let out = run3(false, |p| {
            p.malicious = true;
            let mut mine = views[p.id].clone();
            validate_inputs(p, &mut mine, BITS)
        });
        for r in out {
            let rejected = r.unwrap_or_else(|_| panic!("{kind:?}: honest servers aborted"));
            let want: Vec<bool> = (0..6).map(|k| k == 2).collect();
            assert_eq!(rejected, want, "{kind:?}");
        }
    }
}

#[test]
fn honest_orders_still_match_with_a_bad_order_present() {
    let mut want = match_batch(&honest_orders(), darkmpc_reference::Params { passes: Passes::Fixed(3) }).unwrap();
    want.insert(2, 0);
    for (n, kind) in ALL_BAD.iter().enumerate() {
        let views = batch(*kind, 200 + n as u64);
        let params = Params { symbol_bits: BITS, passes: 3, malicious: true, validate: true };
        let out = run3(false, |p| {
            let f = run_auction(p, &views[p.id], params)?;
            p.open_a_safe(&f)
        });
        for r in out {
            assert_eq!(r.unwrap_or_else(|_| panic!("{kind:?}: aborted")), want, "{kind:?}");
        }
    }
}

/// With no bad order, nothing is rejected.
#[test]
fn honest_batch_rejects_nothing() {
    let mut r = splitmix(7);
    let mut views: [Vec<SharedOrder>; 3] = Default::default();
    for o in honest_orders() {
        let h = honest(&o, &mut r);
        for i in 0..3 {
            views[i].push(h[i].clone());
        }
    }
    let out = run3(false, |p| {
        p.malicious = true;
        let mut mine = views[p.id].clone();
        validate_inputs(p, &mut mine, BITS)
    });
    for r in out {
        assert_eq!(r.unwrap(), vec![false; 5]);
    }
}
