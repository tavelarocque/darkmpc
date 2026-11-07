//! Property tests for shuffling, secret permutations, the stable radix sort
//! and segmented scans.

use darkmpc_mpc::perm::{apply_public, unapply_public};
use darkmpc_mpc::*;
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

fn views(xs: &[u64], seed: u64) -> [Vec<A>; 3] {
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

fn agree(r: [Vec<u64>; 3]) -> Vec<u64> {
    assert_eq!(r[0], r[1]);
    assert_eq!(r[1], r[2]);
    r[0].clone()
}

/// A permutation of 0..n from a seed (test-side, in the clear).
fn perm_from(seed: u64, n: usize) -> Vec<usize> {
    let mut r = splitmix(seed);
    let mut p: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        p.swap(i, (r() % (i as u64 + 1)) as usize);
    }
    p
}

fn cases() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(128);
    ProptestConfig::with_cases(cases)
}

proptest! {
    #![proptest_config(cases())]

    /// Shuffle permutes the values (same multiset), leaves a consistent
    /// replicated sharing, and unshuffle undoes it exactly.
    #[test]
    fn shuffle_then_unshuffle(xs in prop::collection::vec(any::<u64>(), 1..80), seed in any::<u64>()) {
        let v = views(&xs, seed);
        let out = run3(false, |p| {
            let perm = p.random_shared_perm(xs.len());
            let mut cols = vec![v[p.id].clone()];
            p.shuffle(&perm, &mut cols);
            let shuffled = cols[0].clone();
            let opened = p.open_a(&cols[0]);
            p.unshuffle(&perm, &mut cols);
            (opened, shuffled, p.open_a(&cols[0]))
        });
        for k in 0..xs.len() {
            prop_assert!(reconstruct_a([out[0].1[k], out[1].1[k], out[2].1[k]]).is_some());
        }
        let opened = agree([out[0].0.clone(), out[1].0.clone(), out[2].0.clone()]);
        let (mut a, mut b) = (opened, xs.clone());
        a.sort();
        b.sort();
        prop_assert_eq!(a, b);
        prop_assert_eq!(agree([out[0].2.clone(), out[1].2.clone(), out[2].2.clone()]), xs);
    }

    /// Applying a secret permutation and its inverse matches the plaintext.
    #[test]
    fn secret_permutations(xs in prop::collection::vec(any::<u64>(), 1..64), seed in any::<u64>()) {
        let n = xs.len();
        let rho = perm_from(seed, n);
        let rho_u: Vec<u64> = rho.iter().map(|&x| x as u64).collect();
        let (vx, vr) = (views(&xs, seed ^ 1), views(&rho_u, seed ^ 2));
        let out = run3(false, |p| {
            let mut a = vec![vx[p.id].clone()];
            p.apply_shared_perm(&vr[p.id], &mut a).unwrap();
            let mut b = vec![vx[p.id].clone()];
            p.unapply_shared_perm(&vr[p.id], &mut b).unwrap();
            let mut r = p.open_a(&a[0]);
            r.extend(p.open_a(&b[0]));
            r
        });
        let got = agree(out);
        prop_assert_eq!(&got[..n], &apply_public(&rho, &xs)[..]);
        prop_assert_eq!(&got[n..], &unapply_public(&rho, &xs)[..]);
    }

    /// Radix sort: keys come out non-decreasing, equal keys keep their
    /// original order (stability), and origin records where each came from.
    #[test]
    fn stable_sort_is_a_stable_sort(keys in prop::collection::vec(0u64..8, 1..64), seed in any::<u64>()) {
        let n = keys.len();
        let bits: Vec<Vec<u64>> = (0..3).map(|b| keys.iter().map(|k| (k >> b) & 1).collect()).collect();
        let idx: Vec<u64> = (0..n as u64).collect();
        let vb: Vec<[Vec<A>; 3]> = bits.iter().enumerate().map(|(b, c)| views(c, seed ^ b as u64)).collect();
        let (vk, vi) = (views(&keys, seed ^ 10), views(&idx, seed ^ 11));
        let out = run3(false, |p| {
            let key_bits: Vec<Vec<A>> = vb.iter().map(|v| v[p.id].clone()).collect();
            let mut payload = vec![vk[p.id].clone(), vi[p.id].clone()];
            let origin = p.stable_sort(key_bits, &mut payload).unwrap();
            let mut r = p.open_a(&payload[0]);
            r.extend(p.open_a(&payload[1]));
            r.extend(p.open_a(&origin));
            r
        });
        let got = agree(out);
        let mut want: Vec<(u64, u64)> = keys.iter().copied().zip(idx.iter().copied()).collect();
        want.sort_by_key(|&(k, _)| k); // Rust's sort_by_key is stable
        let want_k: Vec<u64> = want.iter().map(|w| w.0).collect();
        let want_i: Vec<u64> = want.iter().map(|w| w.1).collect();
        prop_assert_eq!(&got[..n], &want_k[..]);
        prop_assert_eq!(&got[n..2 * n], &want_i[..], "not stable");
        prop_assert_eq!(&got[2 * n..], &want_i[..], "origin wrong");
    }

    /// Segmented prefix sums and totals against a plaintext loop.
    #[test]
    fn segmented_scans(rows in prop::collection::vec((0u64..1000, any::<bool>()), 1..70), seed in any::<u64>()) {
        let n = rows.len();
        let vals: Vec<u64> = rows.iter().map(|r| r.0).collect();
        let starts: Vec<u64> = rows.iter().enumerate().map(|(t, r)| (t == 0 || r.1) as u64).collect();
        let (vv, vs) = (views(&vals, seed), views(&starts, seed ^ 1));
        let out = run3(false, |p| {
            let pre = p.segmented_prefix(&vs[p.id], &[vv[p.id].clone()]);
            let tot = p.segmented_total(&vs[p.id], &[vv[p.id].clone()]);
            let mut r = p.open_a(&pre[0]);
            r.extend(p.open_a(&tot[0]));
            r
        });
        let got = agree(out);
        let mut want_pre = vec![0u64; n];
        for t in 0..n {
            want_pre[t] = if starts[t] == 1 { vals[t] } else { want_pre[t - 1] + vals[t] };
        }
        let mut want_tot = vec![0u64; n];
        let mut t = 0;
        while t < n {
            let mut e = t + 1;
            while e < n && starts[e] == 0 { e += 1; }
            let s: u64 = vals[t..e].iter().sum();
            for w in &mut want_tot[t..e] { *w = s; }
            t = e;
        }
        prop_assert_eq!(&got[..n], &want_pre[..]);
        prop_assert_eq!(&got[n..], &want_tot[..]);
    }
}

/// The paper's worked example (CCS 2022, Protocol 4.1): bits (1, 1, 0, 0)
/// give destinations (3, 4, 1, 2), i.e. (2, 3, 0, 1) counting from 0.
#[test]
fn bit_sort_perm_paper_example() {
    let v = views(&[1, 1, 0, 0], 5);
    let got = agree(run3(false, |p| {
        let r = p.bit_sort_perm(&v[p.id]);
        p.open_a(&r)
    }));
    assert_eq!(got, vec![2, 3, 0, 1]);
}

/// Cost of a shuffle: three rounds, and each party sends one word per
/// element in the two steps where it is a pair member.
#[test]
fn shuffle_cost() {
    let n = 50;
    let v = views(&vec![7; n], 3);
    let stats = run3(false, |p| {
        let perm = p.random_shared_perm(n);
        let mut cols = vec![v[p.id].clone()];
        p.shuffle(&perm, &mut cols);
        p.net.stats.clone()
    });
    for s in stats {
        assert_eq!(s.rounds, 3);
        assert_eq!(s.bytes_sent, 2 * 8 * n as u64);
    }
}
