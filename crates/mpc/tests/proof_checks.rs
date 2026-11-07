//! Exhaustive checks of the two theorems in docs/design/ring-proofs.md on
//! instances small enough to enumerate. They cannot replace the proofs, but
//! a wrong lemma would show up here as a counterexample, the same way the
//! reference matcher catches a wrong auction.

/// Number of times 2 divides x in Z_{2^m} (m for 0).
fn val(x: u64, m: u32) -> u32 {
    if x == 0 { m } else { x.trailing_zeros().min(m) }
}

/// Theorem B in Z_{2^m} with "harmful" meaning nonzero mod 2^k: the best
/// pass probability of the shuffle check, over the coefficients beta and the
/// key alpha, is at most (m + 1 - v0) 2^(v0 - m).
///
/// For fixed E = sum beta_k e_k, the corrupt server picks D after seeing
/// beta, so its best pass probability over alpha is exactly 2^(v(E) - m)
/// (Lemma 5 is tight when 2^v(E) divides D), and 1 when E = 0. So the exact
/// best pass probability is the average of 2^(v(E) - m) over all beta.
fn best_pass_probability(e: &[u64], m: u32) -> f64 {
    let modulus = 1u64 << m;
    let mask = modulus - 1;
    let mut total = 0.0;
    let mut count = 0u64;
    let mut beta = vec![0u64; e.len()];
    loop {
        let big_e = beta.iter().zip(e).fold(0u64, |acc, (b, x)| acc.wrapping_add(b.wrapping_mul(*x))) & mask;
        total += (2f64).powi(val(big_e, m) as i32 - m as i32);
        count += 1;
        // Next beta vector (odometer).
        let mut i = 0;
        loop {
            if i == beta.len() {
                return total / count as f64;
            }
            beta[i] += 1;
            if beta[i] < modulus {
                break;
            }
            beta[i] = 0;
            i += 1;
        }
    }
}

fn theorem_b_bound(v0: u32, m: u32) -> f64 {
    (m + 1 - v0) as f64 * (2f64).powi(v0 as i32 - m as i32)
}

#[test]
fn shuffle_check_bound_holds_for_every_single_error() {
    let (m, k) = (10u32, 5u32);
    let mut worst_ratio = 0f64;
    for e in 1..(1u64 << m) {
        let v0 = val(e, m);
        if v0 >= k {
            continue; // harmless: vanishes mod 2^k
        }
        let p = best_pass_probability(&[e], m);
        let bound = theorem_b_bound(v0, m);
        assert!(p <= bound + 1e-12, "e = {e}: pass {p} > bound {bound}");
        worst_ratio = worst_ratio.max(p / bound);
    }
    // The worst case is v0 = k - 1, and the bound is within a factor 2 of it.
    let worst = best_pass_probability(&[1 << (k - 1)], m);
    assert!(worst <= theorem_b_bound(k - 1, m));
    assert!(worst_ratio > 0.4, "bound should not be wildly loose here: ratio {worst_ratio}");
}

#[test]
fn shuffle_check_bound_holds_for_pairs_of_errors() {
    pairs_of_errors(6, 3);
}

/// The same, in a bigger ring (about 30 s): `cargo test --release -- --ignored`.
#[test]
#[ignore]
fn shuffle_check_bound_holds_for_pairs_of_errors_mod_256() {
    pairs_of_errors(8, 4);
}

fn pairs_of_errors(m: u32, k: u32) {
    let modulus = 1u64 << m;
    // Every pair of errors with at least one harmful coordinate, exhaustive.
    for e0 in 0..modulus {
        for e1 in 0..modulus {
            let v0 = val(e0, m).min(val(e1, m));
            if v0 >= k {
                continue;
            }
            let p = best_pass_probability(&[e0, e1], m);
            let bound = theorem_b_bound(v0, m);
            assert!(p <= bound + 1e-12, "e = ({e0}, {e1}): pass {p} > bound {bound}");
        }
    }
}

#[test]
fn the_real_parameters_give_under_2_to_minus_58_9() {
    // m = 128, harmful means v0 <= 63; the bound grows with v0.
    let bound = |v0: u32| (129 - v0) as f64 * (2f64).powi(v0 as i32 - 128);
    for v0 in 0..63 {
        assert!(bound(v0) < bound(v0 + 1));
    }
    assert!(bound(63).log2() < -58.9, "{}", bound(63).log2());
}

// ----- Theorem A / Lemma 2 -----

fn binom(n: u64, r: u64) -> f64 {
    (0..r).fold(1.0, |acc, j| acc * (n - j) as f64 / (j + 1) as f64)
}

/// All permutations of 0..n (Heap's algorithm).
fn permutations(n: usize) -> Vec<Vec<usize>> {
    fn heap(k: usize, a: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if k == 1 {
            out.push(a.clone());
            return;
        }
        heap(k - 1, a, out);
        for i in 0..k - 1 {
            if k.is_multiple_of(2) {
                a.swap(i, k - 1)
            } else {
                a.swap(0, k - 1)
            }
            heap(k - 1, a, out);
        }
    }
    let mut out = Vec::new();
    heap(n, &mut (0..n).collect(), &mut out);
    out
}

/// The protocol's game: after permuting, open the first c (must all have
/// error 0), split the rest into buckets of b (each must be error-uniform:
/// Lemma 1 says a pair check passes iff errors are equal), and the cheater
/// wins if some bucket's first triple has a nonzero error.
fn ring_win(errors: &[u8], perm: &[usize], b: usize, c: usize) -> bool {
    let t: Vec<u8> = perm.iter().map(|&i| errors[i]).collect();
    if t[..c].iter().any(|&e| e != 0) {
        return false;
    }
    let mut bad_bucket = false;
    for bucket in t[c..].chunks(b) {
        if bucket.iter().any(|&e| e != bucket[0]) {
            return false;
        }
        bad_bucket |= bucket[0] != 0;
    }
    bad_bucket
}

fn check_reduction(n: usize, b: usize, c: usize, error_values: u8) {
    let total = n * b + c;
    let perms = permutations(total);
    let bound = n as f64 / binom(total as u64, b as u64);
    let mut worst = 0f64;
    let mut errors = vec![0u8; total];
    loop {
        let wins = perms.iter().filter(|p| ring_win(&errors, p, b, c)).count();
        let p = wins as f64 / perms.len() as f64;
        // Lemma 2: the ring win is contained in the Boolean win for the same bad set.
        let boolean: Vec<u8> = errors.iter().map(|&e| (e != 0) as u8).collect();
        let p_bool = perms.iter().filter(|q| ring_win(&boolean, q, b, c)).count() as f64 / perms.len() as f64;
        assert!(p <= p_bool + 1e-12, "errors {errors:?}: ring {p} > boolean {p_bool}");
        assert!(p <= bound + 1e-12, "errors {errors:?}: win {p} > FLNW bound {bound}");
        worst = worst.max(p);
        // Next error vector.
        let mut i = 0;
        loop {
            if i == total {
                assert!(worst > 0.0);
                return;
            }
            errors[i] += 1;
            if errors[i] < error_values {
                break;
            }
            errors[i] = 0;
            i += 1;
        }
    }
}

#[test]
fn bucket_game_never_beats_the_flnw_bound_n2_b2() {
    // 6 triples, errors in {0, 1, 2}: every error vector, every permutation.
    check_reduction(2, 2, 2, 3);
}

/// About 15 s: `cargo test --release -- --ignored`.
#[test]
#[ignore]
fn bucket_game_never_beats_the_flnw_bound_n3_b2() {
    // 8 triples, errors in {0, 1, 2}: 6,561 error vectors x 40,320 permutations.
    check_reduction(3, 2, 2, 3);
}
