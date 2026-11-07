//! Leakage checks on a single party's view.
//!
//! These are bug detectors, not security proofs. Each one computes a
//! statistic that an honest protocol makes uniformly random, but that a
//! specific implementation mistake makes predictable.

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

/// Party 2 receives z0 = x0 y0 + x0 y1 + x1 y0 + alpha0 during a
/// multiplication. Party 2 knows x2, x0, y2, y0. Without the mask alpha0,
///     z0 + x0 y2 + x2 y0 + x0 y0 = x0 y + y0 x
/// exactly (see docs/learning/01-secret-sharing.md). Multiplying secret
/// zeros makes the right-hand side 0, so an unmasked protocol hands party 2 a
/// statistic that is always 0. With the mask it is uniform.
#[test]
fn product_message_is_masked() {
    let n = 4096;
    let mut r = splitmix(42);
    let mut views: [Vec<A>; 3] = Default::default();
    let mut views_y: [Vec<A>; 3] = Default::default();
    for _ in 0..n {
        let (sx, sy) = (share_a(0, &mut r), share_a(0, &mut r));
        for i in 0..3 {
            views[i].push(sx[i]);
            views_y[i].push(sy[i]);
        }
    }
    let out = run3(true, |p| {
        p.mul(&views[p.id], &views_y[p.id]);
        p.net.transcript.take().unwrap()
    });
    let received = &out[2][0]; // party 2's first received message: z0 from party 0
    let (x, y) = (&views[2], &views_y[2]); // party 2 holds (x2, x0)
    let t: Vec<u64> = (0..n)
        .map(|k| {
            let (x2, x0, y2, y0) = (x[k].s0, x[k].s1, y[k].s0, y[k].s1);
            received[k]
                .wrapping_add(x0.wrapping_mul(y2))
                .wrapping_add(x2.wrapping_mul(y0))
                .wrapping_add(x0.wrapping_mul(y0))
        })
        .collect();
    assert_uniform_low_byte(&t, "multiplication message");
}

/// The Boolean analogue: party 2 receives z0 for an AND of secret zeros.
#[test]
fn and_message_is_masked() {
    let n = 4096;
    let mut r = splitmix(43);
    let mut vx: [Vec<B>; 3] = Default::default();
    let mut vy: [Vec<B>; 3] = Default::default();
    for _ in 0..n {
        let (sx, sy) = (share_b(0, &mut r), share_b(0, &mut r));
        for i in 0..3 {
            vx[i].push(sx[i]);
            vy[i].push(sy[i]);
        }
    }
    let out = run3(true, |p| {
        p.and(&vx[p.id], &vy[p.id]);
        p.net.transcript.take().unwrap()
    });
    let received = &out[2][0];
    let t: Vec<u64> = (0..n)
        .map(|k| {
            let (x2, x0, y2, y0) = (vx[2][k].s0, vx[2][k].s1, vy[2][k].s0, vy[2][k].s1);
            received[k] ^ (x0 & y2) ^ (x2 & y0) ^ (x0 & y0)
        })
        .collect();
    assert_uniform_low_byte(&t, "AND message");
}

/// Chi-squared test of the low byte against uniform over 256 values. The
/// threshold 400 (255 degrees of freedom) is far in the tail for a uniform
/// source, so the honest protocol essentially never fails; a constant
/// statistic gives roughly n * 255, which always fails.
fn assert_uniform_low_byte(t: &[u64], what: &str) {
    let mut counts = [0u64; 256];
    for v in t {
        counts[(v & 0xff) as usize] += 1;
    }
    let expect = t.len() as f64 / 256.0;
    let chi2: f64 = counts.iter().map(|&c| (c as f64 - expect).powi(2) / expect).sum();
    assert!(chi2 < 400.0, "{what}: receiver's statistic is not uniform (chi2 = {chi2:.0}); missing re-randomisation?");
}
