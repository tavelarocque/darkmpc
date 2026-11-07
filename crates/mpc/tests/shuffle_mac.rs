//! Milestone 4b: the MAC-verified shuffle. An honest verified shuffle must
//! apply exactly the right permutation; a tampering server must make every
//! honest server abort before anything is opened.

use darkmpc_mpc::perm::apply_public;
use darkmpc_mpc::*;

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

fn perm_from(seed: u64, n: usize) -> Vec<usize> {
    let mut r = splitmix(seed);
    let mut p: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        p.swap(i, (r() % (i as u64 + 1)) as usize);
    }
    p
}

#[test]
fn verified_secret_permutation_is_correct() {
    for seed in 0..6 {
        let n = 5 + 7 * seed as usize;
        let xs: Vec<u64> = (0..n as u64).map(|i| i.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ u64::MAX).collect();
        let rho = perm_from(seed, n);
        let rho_u: Vec<u64> = rho.iter().map(|&x| x as u64).collect();
        let (vx, vr) = (views(&xs, seed + 10), views(&rho_u, seed + 20));
        let out = run3(false, |p| {
            p.malicious = true;
            let mut cols = vec![vx[p.id].clone(), vx[p.id].clone()];
            p.apply_shared_perm(&vr[p.id], &mut cols)?;
            let mut v = p.open_a_safe(&cols[0])?;
            v.extend(p.open_a_safe(&cols[1])?);
            Ok::<_, Abort>(v)
        });
        let want = apply_public(&rho, &xs);
        for r in out {
            let v = r.expect("honest verified shuffle aborted");
            assert_eq!(&v[..n], &want[..]);
            assert_eq!(&v[n..], &want[..]);
        }
    }
}

/// Party 1 adds 1 to one value while resharing. Nothing in the product
/// checks can see this (a shuffle has no products); only the MAC check can.
#[test]
fn tampering_shuffle_aborts_before_opening() {
    let n = 20;
    let xs: Vec<u64> = (0..n as u64).collect();
    let rho = perm_from(3, n);
    let rho_u: Vec<u64> = rho.iter().map(|&x| x as u64).collect();
    let (vx, vr) = (views(&xs, 1), views(&rho_u, 2));
    let out = run3(false, |p| {
        p.malicious = true;
        p.test_cheat_shuffle = true; // only party 1 acts on it
        let mut cols = vec![vx[p.id].clone()];
        p.apply_shared_perm(&vr[p.id], &mut cols)
    });
    for (i, r) in out.iter().enumerate() {
        assert!(r.is_err(), "server {i} did not abort on a tampered shuffle");
    }
}
