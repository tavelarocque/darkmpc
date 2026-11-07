//! Leakage audit of both auctions, from one server's point of view.
//!
//! What a server sees is (1) its own input shares, (2) every message it
//! receives, and (3) every value it learns from an opening. The security
//! argument (docs/design/leakage-audit.md) shows that a simulator knowing only
//! the public parameters can produce all three. These tests are the
//! sanity checks that go with it. They cannot prove anything, but each one
//! catches a specific class of implementation mistake:
//!
//! * **Shape** (exact): for two very different batches of the same size,
//!   every server receives the same number of messages with the same lengths,
//!   and performs the same openings with the same lengths. A branch on secret
//!   data would break this.
//! * **Openings** (statistical): for every opening, its distribution over
//!   many runs is the same under batch A as under batch B (two-sample
//!   chi-squared), and every permutation opening is uniform over all n!
//!   permutations. Openings are the only values a server learns in the clear,
//!   so this is where a leak would surface. The planted leaks
//!   `plant-open-unshuffled` and `plant-stage2-debug-open` keep every result
//!   correct, so only these tests can catch them.
//!
//! Messages that are not openings are masked shares; that they are masked is
//! checked directly in `crates/mpc/tests/leakage.rs`.

use darkmpc_auction::{
    Params, SharedLimitOrder, SharedOrder, Stage2Params, run_auction, run_stage2, share_limit_orders, share_orders,
};
use darkmpc_mpc::{Party, run3};
use darkmpc_reference::{LimitOrder, Order};

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

/// What one run shows each server: received message lengths, and openings.
struct View {
    message_lens: Vec<usize>,
    openings: Vec<Vec<u64>>,
}

fn take_view(p: &mut Party) -> View {
    let t = p.net.transcript.take().unwrap();
    View { message_lens: t.iter().map(Vec::len).collect(), openings: p.opened.take().unwrap() }
}

#[derive(Clone, Copy)]
enum Batch {
    One(&'static [Order]),
    Two(&'static [LimitOrder]),
}

const BITS: usize = 1;

// Two batches of four orders that differ in every way the auction cares
// about: symbols, sides, order within the book, crossing or not.
const S1_A: &[Order] = &[Order::buy(0, 5, 1), Order::buy(0, 5, 1), Order::sell(0, 5, 1), Order::sell(0, 5, 1)];
const S1_B: &[Order] = &[Order::sell(1, 7, 7), Order::buy(0, 1, 1), Order::sell(0, 3, 3), Order::buy(1, 9, 2)];
const S2_A: &[LimitOrder] =
    &[LimitOrder::buy(0, 5, 100), LimitOrder::buy(0, 5, 100), LimitOrder::sell(0, 5, 100), LimitOrder::sell(0, 5, 100)];
const S2_B: &[LimitOrder] =
    &[LimitOrder::sell(1, 7, 900), LimitOrder::buy(0, 1, 3), LimitOrder::sell(0, 3, 2), LimitOrder::buy(1, 9, 77)];

/// One honest run; returns every server's view. Outputs are not opened.
fn run(batch: Batch, malicious: bool, seed: u64) -> [View; 3] {
    match batch {
        Batch::One(o) => {
            let views: [Vec<SharedOrder>; 3] = share_orders(o, BITS, splitmix(seed));
            let params = Params { symbol_bits: BITS, passes: 2, malicious, validate: malicious };
            run3(true, |p| {
                run_auction(p, &views[p.id], params).expect("honest run must not abort");
                take_view(p)
            })
        }
        Batch::Two(o) => {
            let views: [Vec<SharedLimitOrder>; 3] = share_limit_orders(o, BITS, splitmix(seed));
            let params = Stage2Params { symbol_bits: BITS, malicious, validate: malicious };
            run3(true, |p| {
                run_stage2(p, &views[p.id], params).expect("honest run must not abort");
                take_view(p)
            })
        }
    }
}

fn runs() -> usize {
    std::env::var("AUDIT_RUNS").ok().and_then(|v| v.parse().ok()).unwrap_or(300)
}

// ----- shape -----

fn assert_same_shape(a: Batch, b: Batch, malicious: bool, what: &str) {
    let (va, vb) = (run(a, malicious, 1), run(b, malicious, 2));
    for i in 0..3 {
        assert_eq!(va[i].message_lens, vb[i].message_lens, "{what}: server {i} received differently shaped traffic");
        let la: Vec<usize> = va[i].openings.iter().map(Vec::len).collect();
        let lb: Vec<usize> = vb[i].openings.iter().map(Vec::len).collect();
        assert_eq!(la, lb, "{what}: server {i} performed different openings");
    }
}

#[test]
fn traffic_shape_is_independent_of_the_orders() {
    assert_same_shape(Batch::One(S1_A), Batch::One(S1_B), false, "stage 1 semi-honest");
    assert_same_shape(Batch::One(S1_A), Batch::One(S1_B), true, "stage 1 malicious");
    assert_same_shape(Batch::Two(S2_A), Batch::Two(S2_B), false, "stage 2 semi-honest");
    assert_same_shape(Batch::Two(S2_A), Batch::Two(S2_B), true, "stage 2 malicious");
}

// ----- openings -----

/// Hash an opened vector into one of 16 buckets.
fn bucket(v: &[u64]) -> usize {
    let mut h = 0x243F_6A88_85A3_08D3u64;
    for &x in v {
        h = (h ^ x).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        h ^= h >> 29;
    }
    (h >> 60) as usize
}

/// Rank of a permutation of 0..n (n small), or None if it is not one.
fn perm_rank(v: &[u64]) -> Option<usize> {
    let n = v.len();
    let mut seen = vec![false; n];
    let mut rank = 0;
    for (i, &x) in v.iter().enumerate() {
        let x = usize::try_from(x).ok().filter(|&x| x < n && !seen[x])?;
        rank = rank * (n - i) + seen[..x].iter().filter(|s| !**s).count();
        seen[x] = true;
    }
    Some(rank)
}

/// Two-sample chi-squared statistic for equal distributions.
fn chi2_two_sample(a: &[u64], b: &[u64]) -> f64 {
    let (na, nb) = (a.iter().sum::<u64>() as f64, b.iter().sum::<u64>() as f64);
    let mut stat = 0.0;
    for (&x, &y) in a.iter().zip(b) {
        let tot = (x + y) as f64;
        if tot == 0.0 {
            continue;
        }
        let (ea, eb) = (tot * na / (na + nb), tot * nb / (na + nb));
        stat += (x as f64 - ea).powi(2) / ea + (y as f64 - eb).powi(2) / eb;
    }
    stat
}

// Thresholds at p = 1e-9 (scipy.stats.chi2.isf(1e-9, df)): honest runs
// essentially never exceed them, even over hundreds of tests; a leak of a
// fixed value gives a statistic near the number of runs or above.
const CHI2_DF15: f64 = 73.6; // two-sample, 16 buckets
const CHI2_DF23: f64 = 89.1; // uniformity over the 24 permutations of 4 elements

fn audit_openings(a: Batch, b: Batch, malicious: bool, what: &str) {
    let r = runs();
    // Server 0's view; every server learns the same opened values.
    let views_a: Vec<View> = (0..r).map(|k| run(a, malicious, 1000 + k as u64).into_iter().next().unwrap()).collect();
    let views_b: Vec<View> = (0..r).map(|k| run(b, malicious, 5000 + k as u64).into_iter().next().unwrap()).collect();
    let count = views_a[0].openings.len();
    assert!(count > 0, "{what}: no openings recorded");
    let mut perm_openings = 0;
    for k in 0..count {
        let (mut ha, mut hb) = ([0u64; 16], [0u64; 16]);
        for v in &views_a {
            ha[bucket(&v.openings[k])] += 1;
        }
        for v in &views_b {
            hb[bucket(&v.openings[k])] += 1;
        }
        let stat = chi2_two_sample(&ha, &hb);
        assert!(
            stat < CHI2_DF15,
            "{what}: opening {k} of {count} has a different distribution for the two batches (chi2 = {stat:.0})"
        );
        // Permutation openings (in every run of both batches) must be uniform.
        let ranks: Option<Vec<usize>> = views_a
            .iter()
            .chain(&views_b)
            .map(|v| perm_rank(&v.openings[k]).filter(|_| v.openings[k].len() == 4))
            .collect();
        if let Some(ranks) = ranks {
            perm_openings += 1;
            let mut h = [0u64; 24];
            for x in ranks {
                h[x] += 1;
            }
            let e = (2 * r) as f64 / 24.0;
            let stat: f64 = h.iter().map(|&c| (c as f64 - e).powi(2) / e).sum();
            assert!(stat < CHI2_DF23, "{what}: permutation opening {k} is not uniform (chi2 = {stat:.0})");
        }
    }
    assert!(perm_openings > 0, "{what}: no permutation openings found");
}

#[test]
fn stage1_openings_are_independent_of_the_orders() {
    audit_openings(Batch::One(S1_A), Batch::One(S1_B), false, "stage 1 semi-honest");
}

#[test]
fn stage2_openings_are_independent_of_the_orders() {
    audit_openings(Batch::Two(S2_A), Batch::Two(S2_B), false, "stage 2 semi-honest");
}

#[test]
fn malicious_openings_are_independent_of_the_orders() {
    audit_openings(Batch::One(S1_A), Batch::One(S1_B), true, "stage 1 malicious");
    audit_openings(Batch::Two(S2_A), Batch::Two(S2_B), true, "stage 2 malicious");
}
