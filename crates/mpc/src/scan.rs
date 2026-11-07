//! Segmented prefix sums on shared data.
//!
//! The input is a sequence cut into segments by shared 0/1 flags (flag 1 =
//! this position starts a new segment; position 0 always does). The output at
//! each position is the sum of its segment up to and including that position.
//! This is a Hillis-Steele scan over the segmented-sum operator
//!     (f1, v1) . (f2, v2) = (f1 or f2, if f2 { v2 } else { v1 + v2 }):
//! for d = 1, 2, 4, ... < n, every position t >= d takes
//!     v_t <- v_t + (1 - F_t) v_{t-d},   F_t <- F_t + F_{t-d} - F_t F_{t-d}.
//! That is ceil(log2 n) rounds, each with one multiplication per element per
//! value column plus one for the flags.

use crate::party::Party;
use crate::share::A;

impl Party {
    /// Inclusive segmented prefix sums of several columns sharing one set of
    /// segment-start flags.
    pub fn segmented_prefix(&mut self, starts: &[A], cols: &[Vec<A>]) -> Vec<Vec<A>> {
        let id = self.id;
        let n = starts.len();
        let mut f = starts.to_vec();
        let mut v: Vec<Vec<A>> = cols.to_vec();
        let mut d = 1;
        while d < n {
            let m = n - d; // positions d..n are updated
            let mut lhs = Vec::with_capacity(m * (v.len() + 1));
            let mut rhs = Vec::with_capacity(m * (v.len() + 1));
            for col in &v {
                for t in d..n {
                    let keep = if cfg!(feature = "plant-scan-ignores-segments") {
                        A::public(1, id) // PLANTED BUG: sums run across segment boundaries
                    } else {
                        (-f[t]).add_public(1, id)
                    };
                    lhs.push(keep);
                    rhs.push(col[t - d]);
                }
            }
            for t in d..n {
                lhs.push(f[t]);
                rhs.push(f[t - d]);
            }
            let prod = self.mul(&lhs, &rhs);
            let mut nv = v.clone();
            for (c, col) in nv.iter_mut().enumerate() {
                for t in d..n {
                    col[t] = v[c][t] + prod[c * m + (t - d)];
                }
            }
            let base = v.len() * m;
            let mut nf = f.clone();
            for t in d..n {
                nf[t] = f[t] + f[t - d] - prod[base + (t - d)];
            }
            v = nv;
            f = nf;
            d *= 2;
        }
        v
    }

    /// Inclusive segmented prefix sums and segment totals together. The
    /// total at every position is forward inclusive sum + backward inclusive
    /// sum - the element itself. The backward sum is a forward scan on the
    /// reversed sequence, whose segment starts are the original segment ends
    /// (end_t = start_{t+1}).
    pub fn segmented_prefix_and_total(&mut self, starts: &[A], cols: &[Vec<A>]) -> (Vec<Vec<A>>, Vec<Vec<A>>) {
        self.segmented_prefix_and_total_multi(&[starts], cols).pop().unwrap()
    }

    /// [`Self::segmented_prefix_and_total`] for several segmentations of the
    /// same columns at once. Every forward and backward scan is laid end to
    /// end in one sequence: each piece begins with a start flag, so segments
    /// never cross from one piece into the next, and the whole thing costs
    /// ceil(log2(2 G n)) rounds instead of 2 G ceil(log2 n). Each `starts[g]`
    /// must have a 1 at position 0. Returns (forward, total) per segmentation.
    #[allow(clippy::type_complexity)]
    pub fn segmented_prefix_and_total_multi(
        &mut self,
        starts: &[&[A]],
        cols: &[Vec<A>],
    ) -> Vec<(Vec<Vec<A>>, Vec<Vec<A>>)> {
        let id = self.id;
        let g = starts.len();
        let n = starts.first().map_or(0, |s| s.len());
        let mut big_starts = Vec::with_capacity(2 * g * n);
        for s in starts {
            big_starts.extend_from_slice(s);
        }
        for s in starts {
            // Reversed sequence: its segment starts are the original segment ends.
            big_starts.extend((0..n).map(|r| if r == 0 { A::public(1, id) } else { s[n - r] }));
        }
        let big_cols: Vec<Vec<A>> = cols
            .iter()
            .map(|c| {
                let mut v = Vec::with_capacity(2 * g * n);
                for _ in 0..g {
                    v.extend_from_slice(c);
                }
                for _ in 0..g {
                    v.extend(c.iter().rev().copied());
                }
                v
            })
            .collect();
        let res = self.segmented_prefix(&big_starts, &big_cols);
        (0..g)
            .map(|k| {
                let fwd: Vec<Vec<A>> = res.iter().map(|r| r[k * n..(k + 1) * n].to_vec()).collect();
                let tot = (0..cols.len())
                    .map(|c| {
                        let bwd = &res[c][(g + k) * n..(g + k + 1) * n];
                        (0..n).map(|t| fwd[c][t] + bwd[n - 1 - t] - cols[c][t]).collect()
                    })
                    .collect();
                (fwd, tot)
            })
            .collect()
    }

    /// Segment totals, available at every position of the segment.
    pub fn segmented_total(&mut self, starts: &[A], cols: &[Vec<A>]) -> Vec<Vec<A>> {
        self.segmented_prefix_and_total(starts, cols).1
    }
}
