//! Property tests for the semi-honest core: every operation, run by three
//! real party threads, must open to the plaintext answer.

use darkmpc_mpc::*;
use proptest::prelude::*;

/// Test-only randomness for client-side sharing (real clients use the OS RNG).
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

/// Each party's view of fresh sharings of `xs`.
fn views_a(xs: &[u64], seed: u64) -> [Vec<A>; 3] {
    let mut r = splitmix(seed);
    let mut v: [Vec<A>; 3] = Default::default();
    for &x in xs {
        let s = share_a(x, &mut r);
        for i in 0..3 {
            v[i].push(s[i]);
        }
    }
    v
}

fn views_b(xs: &[u64], seed: u64) -> [Vec<B>; 3] {
    let mut r = splitmix(seed);
    let mut v: [Vec<B>; 3] = Default::default();
    for &x in xs {
        let s = share_b(x, &mut r);
        for i in 0..3 {
            v[i].push(s[i]);
        }
    }
    v
}

/// All three parties must open the same values; return them.
fn agree(r: [Vec<u64>; 3]) -> Vec<u64> {
    assert_eq!(r[0], r[1]);
    assert_eq!(r[1], r[2]);
    r[0].clone()
}

/// Values that stress wraparound and carries, mixed with random ones.
fn word() -> impl Strategy<Value = u64> {
    prop_oneof![
        4 => any::<u64>(),
        1 => Just(0u64),
        1 => Just(1u64),
        1 => Just(u64::MAX),
        1 => Just(1u64 << 63),
        1 => Just((1u64 << 63) - 1),
        1 => (0u32..64).prop_map(|k| 1u64 << k),
        1 => (0u32..64).prop_map(|k| (1u64 << k).wrapping_sub(1)),
    ]
}

/// Signed values whose pairwise differences cannot wrap: |v| < 2^62.
fn bounded() -> impl Strategy<Value = u64> {
    let lim = 1i64 << 62;
    prop_oneof![
        4 => (-lim + 1..lim).prop_map(|v| v as u64),
        1 => (-3i64..=3).prop_map(|v| v as u64),
        1 => Just((lim - 1) as u64),
        1 => Just((-lim + 1) as u64),
    ]
}

fn cases() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(256);
    ProptestConfig::with_cases(cases)
}

proptest! {
    #![proptest_config(cases())]

    #[test]
    fn share_reconstruct_roundtrip(x in word(), seed in any::<u64>()) {
        let mut r = splitmix(seed);
        prop_assert_eq!(reconstruct_a(share_a(x, &mut r)), Some(x));
        prop_assert_eq!(reconstruct_b(share_b(x, &mut r)), Some(x));
        let mut bad = share_a(x, &mut r);
        bad[1].s0 ^= 1; // party 1's copy of summand 1 no longer matches party 0's
        prop_assert_eq!(reconstruct_a(bad), None);
    }

    #[test]
    fn linear_ops_are_local_and_correct(xs in prop::collection::vec((word(), word(), word()), 1..32), seed in any::<u64>()) {
        let (x, y): (Vec<u64>, Vec<u64>) = xs.iter().map(|t| (t.0, t.1)).unzip();
        let c: Vec<u64> = xs.iter().map(|t| t.2).collect();
        let (vx, vy) = (views_a(&x, seed), views_a(&y, seed ^ 1));
        let out = run3(false, |p| {
            let (a, b) = (&vx[p.id], &vy[p.id]);
            let before = p.net.stats.clone();
            let lin: Vec<A> = (0..a.len())
                .flat_map(|k| [a[k] + b[k], a[k] - b[k], -a[k], a[k].scale(c[k]), a[k].add_public(c[k], p.id)])
                .collect();
            assert_eq!(p.net.stats, before, "linear operations must not communicate");
            p.open_a(&lin)
        });
        let got = agree(out);
        for k in 0..x.len() {
            let want = [
                x[k].wrapping_add(y[k]), x[k].wrapping_sub(y[k]), x[k].wrapping_neg(),
                x[k].wrapping_mul(c[k]), x[k].wrapping_add(c[k]),
            ];
            prop_assert_eq!(&got[5 * k..5 * k + 5], &want[..]);
        }
    }

    #[test]
    fn mul_is_correct(xs in prop::collection::vec((word(), word()), 1..64), seed in any::<u64>()) {
        let (x, y): (Vec<u64>, Vec<u64>) = xs.into_iter().unzip();
        let (vx, vy) = (views_a(&x, seed), views_a(&y, seed ^ 1));
        let got = agree(run3(false, |p| { let z = p.mul(&vx[p.id], &vy[p.id]); p.open_a(&z) }));
        for k in 0..x.len() { prop_assert_eq!(got[k], x[k].wrapping_mul(y[k])); }
    }

    /// A product's sharing is itself a valid replicated sharing (the two
    /// copies of every summand agree), so products can be chained.
    #[test]
    fn mul_output_is_consistent_and_chains(x in word(), y in word(), z in word(), seed in any::<u64>()) {
        let (vx, vy, vz) = (views_a(&[x], seed), views_a(&[y], seed ^ 1), views_a(&[z], seed ^ 2));
        let out = run3(false, |p| { let t = p.mul(&vx[p.id], &vy[p.id]); p.mul(&t, &vz[p.id])[0] });
        prop_assert_eq!(reconstruct_a(out), Some(x.wrapping_mul(y).wrapping_mul(z)));
    }

    #[test]
    fn and_is_correct(xs in prop::collection::vec((word(), word()), 1..64), seed in any::<u64>()) {
        let (x, y): (Vec<u64>, Vec<u64>) = xs.into_iter().unzip();
        let (vx, vy) = (views_b(&x, seed), views_b(&y, seed ^ 1));
        let got = agree(run3(false, |p| { let z = p.and(&vx[p.id], &vy[p.id]); p.open_b(&z) }));
        for k in 0..x.len() { prop_assert_eq!(got[k], x[k] & y[k]); }
    }

    #[test]
    fn msb_is_correct(x in prop::collection::vec(word(), 1..64), seed in any::<u64>()) {
        let vx = views_a(&x, seed);
        let got = agree(run3(false, |p| { let b = p.msb(&vx[p.id]); p.open_b(&b) }));
        for k in 0..x.len() { prop_assert_eq!(got[k], x[k] >> 63); }
    }

    #[test]
    fn lt_min_max_are_correct(xs in prop::collection::vec((bounded(), bounded()), 1..48), seed in any::<u64>()) {
        let (a, b): (Vec<u64>, Vec<u64>) = xs.into_iter().unzip();
        let (va, vb) = (views_a(&a, seed), views_a(&b, seed ^ 1));
        let got = agree(run3(false, |p| {
            let (x, y) = (&va[p.id], &vb[p.id]);
            let mut r = p.lt(x, y);
            r.extend(p.min(x, y));
            r.extend(p.max(x, y));
            p.open_a(&r)
        }));
        let n = a.len();
        for k in 0..n {
            let (sa, sb) = (a[k] as i64, b[k] as i64);
            prop_assert_eq!(got[k], (sa < sb) as u64, "lt({}, {})", sa, sb);
            prop_assert_eq!(got[n + k] as i64, sa.min(sb));
            prop_assert_eq!(got[2 * n + k] as i64, sa.max(sb));
        }
    }

    #[test]
    fn bit_inject_is_correct(bits in prop::collection::vec(0u64..2, 1..64), seed in any::<u64>()) {
        let vb = views_b(&bits, seed);
        let got = agree(run3(false, |p| { let a = p.bit_inject(&vb[p.id]); p.open_a(&a) }));
        prop_assert_eq!(got, bits);
    }
}

/// Comparison at its boundaries: equal values, neighbours, and the extremes
/// of the range darkmpc guarantees (|a - b| < 2^63).
#[test]
fn lt_boundaries() {
    let big = (1i64 << 62) - 1;
    let pairs: Vec<(i64, i64)> = vec![
        (0, 0),
        (5, 5),
        (-5, -5),
        (4, 5),
        (5, 4),
        (-1, 0),
        (0, -1),
        (big, big),
        (big - 1, big),
        (big, big - 1),
        (-big, big),
        (big, -big),
        (i64::MAX, i64::MAX),
        (i64::MIN + 1, i64::MIN + 1),
    ];
    let a: Vec<u64> = pairs.iter().map(|p| p.0 as u64).collect();
    let b: Vec<u64> = pairs.iter().map(|p| p.1 as u64).collect();
    for seed in 0..20 {
        let (va, vb) = (views_a(&a, seed), views_a(&b, seed + 1000));
        let got = agree(run3(false, |p| {
            let r = p.lt(&va[p.id], &vb[p.id]);
            p.open_a(&r)
        }));
        for (k, &(x, y)) in pairs.iter().enumerate() {
            assert_eq!(got[k], (x < y) as u64, "lt({x}, {y})");
        }
    }
}

/// The carry circuit on its own, on chosen (not random) inputs, forcing
/// carries across every distance from 1 to 63.
///
/// Carry-chain length is set by the secret value, not by the random shares.
/// The carry-save adder turns d0 + d1 + d2 into s + c with s + c = d + w 2^64
/// for some w. When d is small, non-negative and w > 0 (the usual case), the addition
/// wraps while every result bit above d's highest set bit is 0, which needs a
/// carry running through all of those positions and out of the top. Dark
/// pool values are small, so long chains
/// are the common case, and a carry circuit with too few levels fails on
/// almost every comparison of small numbers. Uniformly random 64-bit test
/// values would mostly miss this; this test and the 0, 1 and small values
/// in the property tests do not.
#[test]
fn carry_chains_of_every_length() {
    let mut s_vals = Vec::new();
    let mut c_vals = Vec::new();
    for k in 0..64u32 {
        // s = 2^k - 1 (k ones), c = 1: the carry ripples k positions.
        s_vals.push((1u64 << k).wrapping_sub(1));
        c_vals.push(1);
        // s = 0111...1 shifted, c = lowest set bit: carry into bit 63 or not.
        s_vals.push(u64::MAX >> 1 >> k << k);
        c_vals.push(1u64 << k);
    }
    s_vals.push(u64::MAX >> 1);
    c_vals.push(1);
    let want: Vec<u64> = s_vals.iter().zip(&c_vals).map(|(s, c)| s.wrapping_add(*c) >> 63).collect();
    let (vs, vc) = (views_b(&s_vals, 7), views_b(&c_vals, 8));
    let got = agree(run3(false, |p| {
        let m = p.msb_of_sum(&vs[p.id], &vc[p.id]);
        p.open_b(&m)
    }));
    assert_eq!(got, want);
}

/// Measured communication per operation per party (bytes and rounds).
#[test]
fn communication_cost() {
    let n = 100usize;
    let x: Vec<u64> = (0..n as u64).collect();
    let (vx, vy) = (views_a(&x, 1), views_a(&x, 2));
    let stats = run3(false, |p| {
        let mut costs = Vec::new();
        let mut step = |p: &mut Party, f: &dyn Fn(&mut Party)| {
            let before = p.net.stats.clone();
            f(p);
            costs.push((p.net.stats.bytes_sent - before.bytes_sent, p.net.stats.rounds - before.rounds));
        };
        step(p, &|p| {
            p.mul(&vx[p.id], &vy[p.id]);
        });
        step(p, &|p| {
            p.msb(&vx[p.id]);
        });
        step(p, &|p| {
            p.lt(&vx[p.id], &vy[p.id]);
        });
        step(p, &|p| {
            p.open_a(&vx[p.id]);
        });
        costs
    });
    for s in &stats {
        assert_eq!(s[0], (8 * n as u64, 1), "mul: one word, one round");
        assert_eq!(s[1], (13 * 8 * n as u64, 8), "msb: 13 words, 8 rounds");
        assert_eq!(s[2], (15 * 8 * n as u64, 10), "lt: 15 words, 10 rounds");
        assert_eq!(s[3], (8 * n as u64, 1), "open: one word, one round");
    }
}

/// The simulated network changes timing, never results: products over a
/// 20 ms round-trip link are still correct, and five sequential rounds take
/// at least five one-way latencies.
#[test]
fn simulated_network_delays_but_preserves_results() {
    let model = NetModel::new(std::time::Duration::from_millis(20), 1000.0);
    let x: Vec<u64> = (1..=8).collect();
    let (vx, vy) = (views_a(&x, 11), views_a(&x, 12));
    let start = std::time::Instant::now();
    let out = run3_model(Some(model), false, |p| {
        let mut z = vx[p.id].clone();
        for _ in 0..4 {
            z = p.mul(&z, &vy[p.id]);
        }
        p.open_a(&z)
    });
    let elapsed = start.elapsed();
    let got = agree(out);
    for k in 0..x.len() {
        assert_eq!(got[k], x[k].wrapping_mul(x[k].wrapping_pow(4)));
    }
    assert!(elapsed >= std::time::Duration::from_millis(50), "5 rounds at 10 ms one-way took {elapsed:?}");
}

/// Full bit decomposition opens to the value itself, for every kind of word.
#[test]
fn decompose_is_the_value() {
    let xs: Vec<u64> = vec![0, 1, u64::MAX, 1 << 63, (1 << 40) - 1, 1 << 40, 12345, 0xDEAD_BEEF_0123_4567];
    for seed in 0..10 {
        let v = views_a(&xs, seed);
        let got = agree(run3(false, |p| {
            let b = p.decompose(&v[p.id]);
            p.open_b(&b)
        }));
        assert_eq!(got, xs);
    }
}
