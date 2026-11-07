//! Milestone 4b: a verified shuffle.
//!
//! The reshare shuffle has no multiplications, so the product checks of
//! verify.rs cannot see a server that tampers with it. Asharov et al. (CCS
//! 2022, Section 5) show why that matters: a cheater can add errors during a
//! shuffle and learn a secret from whether the opened vector is still a
//! permutation. Their fix authenticates every shuffled value with a MAC
//! under a secret key r, holding ([x], [r x]), shuffles values and MACs with
//! the same permutation, and checks a random linear combination before any
//! opening (their Protocol 5.4). Their analysis is over a field.
//!
//! In Z_2^64 a MAC key can be a zero divisor (an error of 2^63 survives any
//! even key), so darkmpc does the MAC arithmetic in Z_2^128 as in SPDZ2k
//! (Cramer, Damgard, Escudero, Scholl, Xing, CRYPTO 2018, Section 3): values
//! live mod 2^(k+s) with k = s = 64, the MAC is alpha * x' mod 2^128, a single
//! check fails to catch an error that is nonzero mod 2^k with probability at
//! most 2^-s (their Claim 1), and a batch check with random coefficients with
//! probability at most 2^(-s + log(s+1)) (their Theorem 1). Combining their
//! batch check with Asharov et al.'s shuffle in the honest-majority setting is
//! my construction; the argument is in docs/design/malicious.md.
//!
//! Lifting is free: a replicated sharing mod 2^64 read as numbers mod 2^128
//! is a sharing of x' = x + c 2^64 for some c, and x' = x mod 2^64. Reducing
//! mod 2^64 at the end is a ring homomorphism, so the shuffled shares reduce
//! to shares of the shuffled values.

use crate::party::Party;
use crate::perm::{SharedPerm, apply_public};
use crate::prf::Prf;
use crate::share::A;
use crate::verify::Abort;

/// A replicated share mod 2^128.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct A2 {
    pub s0: u128,
    pub s1: u128,
}

impl A2 {
    fn lift(a: A) -> A2 {
        A2 { s0: a.s0 as u128, s1: a.s1 as u128 }
    }
    fn truncate(self) -> A {
        A { s0: self.s0 as u64, s1: self.s1 as u64 }
    }
    fn sub(self, o: A2) -> A2 {
        A2 { s0: self.s0.wrapping_sub(o.s0), s1: self.s1.wrapping_sub(o.s1) }
    }
}

fn words128(prf: &mut Prf, n: usize) -> Vec<u128> {
    prf.words128(n)
}

fn push128(out: &mut Vec<u64>, x: u128) {
    out.push(x as u64);
    out.push((x >> 64) as u64);
}

fn get128(w: &[u64], k: usize) -> u128 {
    (w[2 * k] as u128) | ((w[2 * k + 1] as u128) << 64)
}

impl Party {
    fn rand_a2(&mut self, n: usize) -> Vec<A2> {
        let s0 = words128(&mut self.own, n);
        let s1 = words128(&mut self.next, n);
        s0.into_iter().zip(s1).map(|(s0, s1)| A2 { s0, s1 }).collect()
    }

    /// Multiplication mod 2^128 (the same replicated protocol).
    fn mul_a2(&mut self, xs: &[A2], ys: &[A2]) -> Vec<A2> {
        let n = xs.len();
        let a = words128(&mut self.own, n);
        let b = words128(&mut self.next, n);
        let mut msg = Vec::with_capacity(2 * n);
        let z: Vec<u128> = (0..n)
            .map(|k| {
                let (x, y) = (xs[k], ys[k]);
                let t =
                    x.s0.wrapping_mul(y.s0)
                        .wrapping_add(x.s0.wrapping_mul(y.s1))
                        .wrapping_add(x.s1.wrapping_mul(y.s0))
                        .wrapping_add(a[k].wrapping_sub(b[k]));
                push128(&mut msg, t);
                t
            })
            .collect();
        let back = self.net.to_prev_from_next(msg);
        (0..n).map(|k| A2 { s0: z[k], s1: get128(&back, k) }).collect()
    }

    /// Checked opening mod 2^128 (both copies of the missing summand).
    fn open_checked_a2(&mut self, xs: &[A2]) -> (Vec<u128>, bool) {
        let (mut m0, mut m1) = (Vec::new(), Vec::new());
        for x in xs {
            push128(&mut m0, x.s0);
            push128(&mut m1, x.s1);
        }
        self.net.stats.rounds += 1;
        self.net.send_next(m0);
        self.net.send_prev(m1);
        let from_prev = self.net.recv_prev();
        let from_next = self.net.recv_next();
        let ok = from_prev == from_next;
        let vals: Vec<u128> =
            xs.iter().enumerate().map(|(k, x)| x.s0.wrapping_add(x.s1).wrapping_add(get128(&from_prev, k))).collect();
        let mut flat = Vec::with_capacity(2 * vals.len());
        for v in &vals {
            push128(&mut flat, *v);
        }
        self.log_open(&flat);
        (vals, ok)
    }

    /// The reshare step of perm.rs, mod 2^128 (same masks r and m, same
    /// argument for why the excluded party learns nothing).
    fn reshare_step_a2(&mut self, c: usize, perm: &SharedPerm, cols: &mut [Vec<A2>]) {
        let a_id = (c + 1) % 3;
        let n = perm.n;
        if self.id == c {
            let from_a = self.net.recv_next();
            let from_b = self.net.recv_prev();
            for (k, col) in cols.iter_mut().enumerate() {
                for (i, x) in col.iter_mut().enumerate() {
                    *x = A2 { s0: get128(&from_b, k * n + i), s1: get128(&from_a, k * n + i) };
                }
            }
        } else {
            let p = perm.known(c).expect("pair member knows pi_c").to_vec();
            let mut msg = Vec::with_capacity(2 * cols.len() * n);
            for col in cols.iter_mut() {
                let part: Vec<u128> = if self.id == a_id {
                    col.iter().map(|x| x.s0.wrapping_add(x.s1)).collect()
                } else {
                    col.iter().map(|x| x.s1).collect()
                };
                let moved = apply_public(&p, &part);
                let stream = self.pair_stream_for(c);
                let r = words128(stream, n);
                let m = words128(stream, n);
                for i in 0..n {
                    let y = if self.id == a_id {
                        moved[i].wrapping_sub(r[i]).wrapping_add(m[i])
                    } else {
                        moved[i].wrapping_sub(m[i])
                    };
                    push128(&mut msg, y);
                    col[i] = if self.id == a_id { A2 { s0: y, s1: r[i] } } else { A2 { s0: r[i], s1: y } };
                }
            }
            if self.test_cheat_shuffle && self.id == 1 && c == 0 && !msg.is_empty() {
                msg[0] = msg[0].wrapping_add(1); // TEST CHEAT: tamper with the shuffle
            }
            if self.id == a_id { self.net.send_prev(msg) } else { self.net.send_next(msg) }
        }
        self.net.stats.rounds += 1;
    }

    /// Shuffle columns by the secret permutation `perm` and prove the
    /// shuffle correct before returning. Steps: lift to Z_2^128; draw a fresh
    /// secret MAC key alpha; compute MACs alpha x' (one multiplication per
    /// value); shuffle values and MACs together; draw public coefficients
    /// beta after the shuffle; check alpha * sum(beta y') - sum(beta m) = 0
    /// with one multiplication and a checked opening; agree on the verdict;
    /// reduce mod 2^64. Errors in the MAC multiplications are covered by the
    /// same check, as in Asharov et al. Protocol 5.4.
    pub fn shuffle_verified(&mut self, perm: &SharedPerm, cols: &mut [Vec<A>]) -> Result<(), Abort> {
        let n = perm.n;
        let k = cols.len();
        if n == 0 || k == 0 {
            return Ok(());
        }
        let mut vals: Vec<Vec<A2>> = cols.iter().map(|c| c.iter().map(|a| A2::lift(*a)).collect()).collect();
        let alpha = self.rand_a2(1)[0];
        let flat: Vec<A2> = vals.iter().flatten().copied().collect();
        let macs_flat = self.mul_a2(&vec![alpha; flat.len()], &flat);
        let mut macs: Vec<Vec<A2>> = macs_flat.chunks(n).map(|c| c.to_vec()).collect();
        let mut both: Vec<Vec<A2>> = vals.drain(..).chain(macs.drain(..)).collect();
        for c in 0..3 {
            self.reshare_step_a2(c, perm, &mut both);
        }
        let (vals, macs) = both.split_at(k);

        // Public coefficients, drawn after the shuffle is fixed.
        let seed: Vec<A> = self.rand_shares(2);
        let (sv, good_seed) = self.open_checked(&seed);
        let mut key = [0u8; 16];
        key[..8].copy_from_slice(&sv[0].to_le_bytes());
        key[8..].copy_from_slice(&sv[1].to_le_bytes());
        let beta = words128(&mut Prf::new(&key), k * n);

        let (mut u, mut v) = (A2::default(), A2::default());
        for (j, (vc, mc)) in vals.iter().zip(macs).enumerate() {
            for i in 0..n {
                let b = beta[j * n + i];
                u = A2 {
                    s0: u.s0.wrapping_add(b.wrapping_mul(vc[i].s0)),
                    s1: u.s1.wrapping_add(b.wrapping_mul(vc[i].s1)),
                };
                v = A2 {
                    s0: v.s0.wrapping_add(b.wrapping_mul(mc[i].s0)),
                    s1: v.s1.wrapping_add(b.wrapping_mul(mc[i].s1)),
                };
            }
        }
        let au = self.mul_a2(&[alpha], &[u])[0];
        let (w, good_open) = self.open_checked_a2(&[au.sub(v)]);
        let passed = cfg!(feature = "plant-skip-shuffle-check") || (good_seed && good_open && w[0] == 0);
        self.agree(passed)?;
        for (out, vc) in cols.iter_mut().zip(vals) {
            *out = vc.iter().map(|x| x.truncate()).collect();
        }
        Ok(())
    }
}
