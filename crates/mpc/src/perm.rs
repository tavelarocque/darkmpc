//! Oblivious permutation and stable sorting, after Asharov, Hamada, Ikarashi,
//! Kikuchi, Nof, Pinkas, Takahashi and Tomida, "Efficient Secure Three-Party
//! Sorting with Applications to Data Analysis and Heavy Hitters", CCS 2022
//! (ePrint 2022/1595): reshare shuffle (their Protocol 3.2), unshuffle
//! (3.3), applying a secret permutation by shuffle-and-open (4.2) and the
//! one-bit sorting permutation (4.1).
//!
//! Conventions. A permutation is a destination array: applying p to v gives
//! out[p[i]] = v[i]. Applying its inverse gives out[j] = v[p[j]].
//!
//! darkmpc's radix sort is a simplification of the paper's: instead of
//! composing per-bit permutations (their Protocol 4.3/4.4) it carries the
//! remaining key bits, the payload and an origin index through every bit's
//! permutation. That costs more communication for long keys but our key is
//! 14 bits, and it needs only shuffle, open and local reordering.

use crate::party::Party;
use crate::prf::Prf;
use crate::share::A;
use crate::verify::Abort;

/// out[p[i]] = v[i].
pub fn apply_public<T: Copy + Default>(p: &[usize], v: &[T]) -> Vec<T> {
    let mut out = vec![T::default(); v.len()];
    for (i, &d) in p.iter().enumerate() {
        out[d] = v[i];
    }
    out
}

/// out[j] = v[p[j]].
pub fn unapply_public<T: Copy>(p: &[usize], v: &[T]) -> Vec<T> {
    p.iter().map(|&s| v[s]).collect()
}

pub(crate) fn random_perm(prf: &mut Prf, n: usize) -> Vec<usize> {
    let mut p: Vec<usize> = (0..n).collect();
    let w = prf.words(n);
    for i in (1..n).rev() {
        let j = uniform_below(i as u64 + 1, w[i], || prf.words(1)[0]) as usize;
        p.swap(i, j);
    }
    p
}

/// A uniform value in 0..m from uniform 64-bit words, by rejection: `first`
/// is used unless it falls in the top 2^64 mod m values, which would make
/// `% m` biased, in which case further words are drawn from `more`. Both
/// servers reading a shared stream reject identically, so they stay in step.
/// (Plain `% m` was biased by up to m / 2^64 per draw; over a permutation of
/// M items that bounds the distance from uniform only by about M^2 / 2^65,
/// about 2^-23 for the 2^21-item triple permutations of verify.rs, far above
/// the 2^-56 per-batch target. Found while writing docs/design/ring-proofs.md.)
pub(crate) fn uniform_below(m: u64, first: u64, mut more: impl FnMut() -> u64) -> u64 {
    assert!(m > 0);
    // Accept w < zone, where zone is the largest multiple of m that fits in 2^64.
    let zone = u64::MAX - (u64::MAX % m + 1) % m;
    let mut w = first;
    while w > zone {
        w = more();
    }
    w % m
}

/// A secret random permutation pi = pi_2 o pi_1 o pi_0, where pi_j is known
/// to every party except party j. Each party stores the two it knows.
pub struct SharedPerm {
    pub(crate) n: usize,
    known: [Option<Vec<usize>>; 3],
}

impl SharedPerm {
    /// Piece pi_c, if this party knows it (every party except party c does).
    pub(crate) fn known(&self, c: usize) -> Option<&[usize]> {
        self.known[c].as_deref()
    }
}

impl Party {
    /// The pseudorandom stream party `self` shares with its partner in the
    /// pair that excludes party c (that pair holds key k_{c+2}).
    pub(crate) fn pair_stream_for(&mut self, c: usize) -> &mut Prf {
        self.pair_stream(c)
    }

    fn pair_stream(&mut self, c: usize) -> &mut Prf {
        let a = (c + 1) % 3;
        if self.id == a { &mut self.next } else { &mut self.own }
    }

    /// Draw a fresh secret random permutation of n elements. No communication.
    pub fn random_shared_perm(&mut self, n: usize) -> SharedPerm {
        let mut known: [Option<Vec<usize>>; 3] = [None, None, None];
        for (c, slot) in known.iter_mut().enumerate() {
            if self.id != c {
                *slot = Some(random_perm(self.pair_stream(c), n));
            }
        }
        SharedPerm { n, known }
    }

    /// One reshare step: the pair that excludes party c permutes by pi_c (or
    /// its inverse) and reshares the result to the three parties.
    ///
    /// Pair members A = c+1 and B = c+2 together hold x as a two-party sum:
    /// A's part is x_{c+1} + x_{c+2} (its two summands) and B's part is x_c.
    /// Both permute their parts locally. With r and m drawn from their shared
    /// stream, the new summands are y_{c+2} = r, y_{c+1} = a' - r + m and
    /// y_c = b' - m. A sends y_{c+1} to C and B sends y_c to C. C sees two
    /// values each masked by m, whose sum is masked by r. Without m, C would
    /// receive b', a permutation of a vector it already knows, and could read
    /// off pi_c.
    fn reshare_step(&mut self, c: usize, perm: &SharedPerm, inverse: bool, cols: &mut [Vec<A>]) {
        let (a_id, b_id) = ((c + 1) % 3, (c + 2) % 3);
        let n = perm.n;
        if self.id == c {
            let from_a = self.net.recv_next(); // A = c+1 is C's next
            let from_b = self.net.recv_prev(); // B = c+2 is C's previous
            for (k, col) in cols.iter_mut().enumerate() {
                for i in 0..n {
                    col[i] = A { s0: from_b[k * n + i], s1: from_a[k * n + i] };
                }
            }
        } else {
            let p = perm.known[c].as_ref().expect("pair member knows pi_c");
            let mut msg = Vec::with_capacity(cols.len() * n);
            for col in cols.iter_mut() {
                let part: Vec<u64> = if self.id == a_id {
                    col.iter().map(|x| x.s0.wrapping_add(x.s1)).collect()
                } else {
                    col.iter().map(|x| x.s1).collect()
                };
                let moved = if inverse { unapply_public(p, &part) } else { apply_public(p, &part) };
                let stream = self.pair_stream(c);
                let r = stream.words(n);
                let m = stream.words(n);
                for i in 0..n {
                    if self.id == a_id {
                        let y = moved[i].wrapping_sub(r[i]).wrapping_add(m[i]);
                        msg.push(y);
                        col[i] = A { s0: y, s1: r[i] };
                    } else {
                        let y = moved[i].wrapping_sub(m[i]);
                        msg.push(y);
                        col[i] = A { s0: r[i], s1: y };
                    }
                }
            }
            if self.id == a_id {
                self.net.send_prev(msg)
            } else {
                self.net.send_next(msg)
            }
            let _ = b_id;
        }
        self.net.stats.rounds += 1;
    }

    /// Apply the secret permutation pi to every column. Three rounds; each
    /// party sends one word per element per column in two of them.
    pub fn shuffle(&mut self, perm: &SharedPerm, cols: &mut [Vec<A>]) {
        for c in 0..3 {
            self.reshare_step(c, perm, false, cols);
        }
    }

    /// Apply pi^{-1}: the same steps in reverse order with inverse pieces.
    pub fn unshuffle(&mut self, perm: &SharedPerm, cols: &mut [Vec<A>]) {
        for c in (0..3).rev() {
            self.reshare_step(c, perm, true, cols);
        }
    }

    /// Apply a secret-shared permutation `rho` (a destination array) to the
    /// columns: out[rho[i]] = col[i]. Shuffle rho and the columns with a fresh
    /// random pi, open pi(rho), which is a uniformly random permutation to
    /// any single party, and apply it in the clear (their Protocol 4.2).
    /// In malicious mode everything is verified before the opening (the
    /// shuffle itself is not yet verified: Milestone 4b).
    pub fn apply_shared_perm(&mut self, rho: &[A], cols: &mut Vec<Vec<A>>) -> Result<(), Abort> {
        let n = rho.len();
        let perm = self.random_shared_perm(n);
        cols.push(rho.to_vec());
        if cfg!(feature = "plant-open-unshuffled") {
            // PLANTED LEAK: rho is opened unshuffled. Every result stays
            // correct, but the sorting permutation (the data's order) is public.
        } else if self.malicious {
            // Milestone 4b: MAC-verified shuffle; nothing is opened unless it passes.
            self.shuffle_verified(&perm, cols)?;
        } else {
            self.shuffle(&perm, cols);
        }
        let opened = self.open_a_safe(&cols.pop().unwrap())?;
        let public: Vec<usize> = opened.iter().map(|&x| x as usize).collect();
        assert!(public.iter().all(|&x| x < n), "opened value is not a position");
        for col in cols.iter_mut() {
            *col = apply_public(&public, col);
        }
        Ok(())
    }

    /// Apply the inverse of a secret-shared permutation: out[j] = col[rho[j]].
    /// Shuffle rho alone, open pi(rho) = rho o pi^{-1}, gather the columns
    /// publicly, then unshuffle.
    pub fn unapply_shared_perm(&mut self, rho: &[A], cols: &mut [Vec<A>]) -> Result<(), Abort> {
        assert!(
            !self.malicious,
            "unapply_shared_perm has no verified (malicious) version yet; the auction does not use it"
        );
        let n = rho.len();
        let perm = self.random_shared_perm(n);
        let mut r = vec![rho.to_vec()];
        self.shuffle(&perm, &mut r);
        let opened = self.open_a_safe(&r[0])?;
        let public: Vec<usize> = opened.iter().map(|&x| x as usize).collect();
        assert!(public.iter().all(|&x| x < n), "opened value is not a position");
        for col in cols.iter_mut() {
            *col = unapply_public(&public, col);
        }
        self.unshuffle(&perm, cols);
        Ok(())
    }

    /// The stable sorting permutation for one shared key bit (0/1 values):
    /// zeros first, then ones, each in original order. With s0 the running
    /// count of zeros, Z the total number of zeros and s1 = Z + running count
    /// of ones, element i goes to s0_i + k_i (s1_i - s0_i) - 1 (0-indexed).
    /// Prefix sums are local; one multiplication per element.
    pub fn bit_sort_perm(&mut self, bits: &[A]) -> Vec<A> {
        let id = self.id;
        let n = bits.len();
        let mut s0 = Vec::with_capacity(n);
        let mut s1 = Vec::with_capacity(n);
        let (mut z, mut o) = (A::default(), A::default());
        for b in bits {
            z = z + (-*b).add_public(1, id);
            o = o + *b;
            s0.push(z);
            s1.push(o);
        }
        let total_zeros = z;
        let s1: Vec<A> = if cfg!(feature = "plant-unstable-sort") {
            // PLANTED BUG: ones placed in reverse arrival order (still a valid
            // permutation, so only stability breaks).
            let total_ones = o;
            s1.iter().zip(bits).map(|(x, b)| total_zeros + total_ones - *x + *b).collect()
        } else {
            s1.iter().map(|x| total_zeros + *x).collect()
        };
        let diff: Vec<A> = s1.iter().zip(&s0).map(|(a, b)| *a - *b).collect();
        let t = self.mul(bits, &diff);
        s0.iter().zip(&t).map(|(a, b)| (*a + *b).add_public(u64::MAX, id)).collect()
    }

    /// Stable sort by the key whose bits are `key_bits[0]` (least
    /// significant) to `key_bits[last]`, each a column of shared 0/1 values.
    /// `payload` columns are permuted along. Returns the origin column: entry
    /// t is the original index of the element now at position t (shared), so
    /// the caller can route results back with `apply_shared_perm(origin, ..)`.
    pub fn stable_sort(&mut self, key_bits: Vec<Vec<A>>, payload: &mut Vec<Vec<A>>) -> Result<Vec<A>, Abort> {
        let id = self.id;
        let n = payload.first().or(key_bits.first()).map_or(0, |c| c.len());
        let origin: Vec<A> = (0..n as u64).map(|i| A::public(i, id)).collect();
        let n_payload = payload.len();
        let mut cols: Vec<Vec<A>> = std::mem::take(payload);
        cols.push(origin);
        let mut remaining = key_bits;
        remaining.reverse(); // pop() now yields the least significant bit
        while let Some(bit) = remaining.pop() {
            let rho = self.bit_sort_perm(&bit);
            let k = remaining.len();
            let mut all: Vec<Vec<A>> = remaining.drain(..).chain(cols.drain(..)).collect();
            self.apply_shared_perm(&rho, &mut all)?;
            cols = all.split_off(k);
            remaining = all;
        }
        let origin = cols.pop().unwrap();
        debug_assert_eq!(cols.len(), n_payload);
        *payload = cols;
        Ok(origin)
    }
}

#[cfg(test)]
mod tests {
    use super::uniform_below;

    #[test]
    fn rejection_removes_exactly_the_biased_tail() {
        // m = 3: 2^64 = 3 * 6148914691236517205 + 1, so only u64::MAX is rejected.
        let mut extra = vec![7u64].into_iter();
        assert_eq!(uniform_below(3, u64::MAX, || extra.next().unwrap()), 7 % 3);
        assert_eq!(uniform_below(3, u64::MAX - 1, || unreachable!()), (u64::MAX - 1) % 3);
        // m = 2^63 + 1: everything from 2^63 + 1 up is rejected (2^64 / m < 2).
        let m = (1u64 << 63) + 1;
        let mut extra = vec![u64::MAX, 1u64 << 63, 5].into_iter();
        assert_eq!(uniform_below(m, u64::MAX - 3, || extra.next().unwrap()), 1u64 << 63);
        // Powers of two never reject.
        assert_eq!(uniform_below(1 << 20, u64::MAX, || unreachable!()), (1 << 20) - 1);
        // m = 1 never rejects.
        assert_eq!(uniform_below(1, u64::MAX, || unreachable!()), 0);
    }

    #[test]
    fn accepted_range_is_a_multiple_of_m() {
        for m in [2u64, 3, 5, 7, 1000, 1 << 21, (1 << 21) + 3, u64::MAX / 3, u64::MAX] {
            let zone = u64::MAX - (u64::MAX % m + 1) % m;
            // Accepted values are 0..=zone, i.e. zone + 1 of them (as u128).
            let count = zone as u128 + 1;
            assert_eq!(count % m as u128, 0, "m = {m}");
            assert!((1u128 << 64) - count < m as u128, "m = {m}");
        }
    }
}
