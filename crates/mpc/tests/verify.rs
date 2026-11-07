//! Malicious mode: verified products and checked openings. Honest runs must
//! verify; each planted cheating server (feature flags) must make an honest
//! run here fail, which scripts/check_planted.sh enforces.

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

/// FLNW (Eurocrypt 2017) Table 1: N = 2^20 triples at sigma = 40 gives
/// B = C = 3. Our bound implementation must reproduce that.
#[test]
fn bucket_size_matches_paper_example() {
    assert_eq!(bucket_size_for(1 << 20, 40.0), 3);
    // Smaller batches need bigger buckets; the size never drops below 2.
    assert!(bucket_size_for(1000, 40.0) > 3);
    assert!(bucket_size_for(1, 50.0) >= 2);
}

/// Products, comparisons (AND gates) and a checked opening, all verified.
#[test]
fn honest_malicious_run_verifies_and_is_correct() {
    let x: Vec<u64> = (0..40).map(|k| k * 3 + 1).collect();
    let y: Vec<u64> = (0..40).map(|k| 100 - k).collect();
    let (vx, vy) = (views(&x, 1), views(&y, 2));
    let out = run3(false, |p| {
        p.malicious = true;
        let z = p.mul(&vx[p.id], &vy[p.id]);
        let c = p.lt(&vx[p.id], &vy[p.id]);
        let mut all = z;
        all.extend(c);
        p.open_a_safe(&all)
    });
    for r in &out {
        let v = r.as_ref().expect("honest run aborted");
        for k in 0..x.len() {
            assert_eq!(v[k], x[k] * y[k]);
            assert_eq!(v[x.len() + k], (x[k] < y[k]) as u64);
        }
    }
}

/// The verdict is unanimous: all three servers agree on Ok or Abort.
#[test]
fn verify_with_nothing_pending_passes() {
    let out = run3(false, |p| {
        p.malicious = true;
        p.verify()
    });
    assert!(out.iter().all(|r| r.is_ok()));
}

/// Products recorded in semi-honest mode are not recorded (no cost).
#[test]
fn semi_honest_mode_records_nothing() {
    let x = views(&[3, 4], 9);
    let out = run3(false, |p| {
        p.mul(&x[p.id], &x[p.id]);
        p.malicious = true;
        let before = p.net.stats.rounds;
        p.verify().unwrap();
        p.net.stats.rounds - before
    });
    assert!(out.iter().all(|&r| r == 1), "only the verdict round should run");
}

/// The opt-in checksum path verifies honest runs too (and the planted
/// wrong-copy cheat must break it, like the default path).
#[test]
fn checksum_copies_mode_verifies_and_is_correct() {
    let x: Vec<u64> = (0..30).map(|k| k * 7 + 2).collect();
    let y: Vec<u64> = (0..30).map(|k| 90 - k).collect();
    let (vx, vy) = (views(&x, 3), views(&y, 4));
    let out = run3(false, |p| {
        p.malicious = true;
        p.checksum_copies = true;
        let z = p.mul(&vx[p.id], &vy[p.id]);
        let c = p.lt(&vx[p.id], &vy[p.id]);
        let mut all = z;
        all.extend(c);
        p.open_a_safe(&all)
    });
    for r in &out {
        let v = r.as_ref().expect("honest checksum-mode run aborted");
        for k in 0..x.len() {
            assert_eq!(v[k], x[k] * y[k]);
            assert_eq!(v[x.len() + k], (x[k] < y[k]) as u64);
        }
    }
}
