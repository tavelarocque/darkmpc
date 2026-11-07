//! Malicious security with abort for multiplications and AND gates.
//!
//! Products are computed optimistically (the semi-honest protocol) and
//! recorded. [`Party::verify`] then proves every recorded product correct
//! against a fresh multiplication triple, after first proving the triples
//! correct by cut-and-choose and bucketing. This follows Furukawa, Lindell,
//! Nof and Weinstein, Eurocrypt 2017 (ePrint 2016/944): Protocol 2.24 (check
//! a product against a triple), Protocol 3.2 (triples by cut-and-choose and
//! bucketing), Protocol 4.2 (verify the circuit's gates), Theorem 5.3 (the
//! bound). Their analysis is for Boolean circuits, which our AND words are
//! (64 independent gates each). Its use for products in Z_2^64 rests on the
//! argument in docs/design/malicious.md (an extension, not a citation).
//!
//! Every opening here is a *checked* opening: the missing summand arrives
//! from both servers that hold it and the copies must agree.
//!
//! Verification ends with every server telling both others whether all its
//! checks passed; any "no" makes every honest server abort.

use crate::party::{Cheat, Party};
use crate::perm::{apply_public, random_perm};
use crate::prf::Prf;
use crate::share::{A, B};

/// An honest server detected cheating (or was told another did).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Abort;

impl std::fmt::Display for Abort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "verification failed: protocol aborted")
    }
}
impl std::error::Error for Abort {}

/// Statistical security target per verified batch, in bits (FLNW Theorem
/// 5.3 bound). An AND word is 64 Boolean gates checked together (a union
/// bound costs 6 bits) and an auction verifies many batches (another
/// log2(batches) bits), so the bound for a whole auction is reported by
/// [`overall_security_bits`] rather than assumed.
pub const SIGMA: f64 = 56.0;

/// Products are verified in batches of at most this many, as they
/// accumulate, so memory stays bounded. Verifying earlier is never less
/// secure; no data is opened between a failed batch and the verdict.
pub const CHUNK: usize = 1 << 18;

/// Security of a whole run that verified `batches` batches: per-batch
/// SIGMA, minus 6 bits for 64 gates per AND word, minus log2(batches).
pub fn overall_security_bits(batches: u64) -> f64 {
    SIGMA - 6.0 - (batches.max(1) as f64).log2()
}

/// Smallest bucket size B (with C = B opened triples) such that the bound of
/// FLNW Theorem 5.3, N / binom(NB + C, B), is at most 2^-SIGMA.
pub fn bucket_size(n: usize) -> usize {
    bucket_size_for(n, SIGMA)
}

/// [`bucket_size`] for an arbitrary security target `sigma` (bits).
pub fn bucket_size_for(n: usize, sigma: f64) -> usize {
    let n = n.max(1);
    for b in 2..=128usize {
        let m = (n * b + b) as f64;
        let log2_binom: f64 = (0..b).map(|j| ((m - j as f64) / (j as f64 + 1.0)).log2()).sum();
        if (n as f64).log2() - log2_binom <= -sigma {
            return b;
        }
    }
    panic!("no bucket size reaches the security target");
}

/// The two share domains, so the checks are written once.
pub(crate) trait Dom: Copy + Default + Send {
    const ARITH: bool;
    fn pair(self) -> (u64, u64);
    fn make(s0: u64, s1: u64) -> Self;
    fn plus(a: u64, b: u64) -> u64;
    fn minus(a: u64, b: u64) -> u64;
    fn times(a: u64, b: u64) -> u64;
    fn mul_raw(p: &mut Party, xs: &[Self], ys: &[Self], cheat: Cheat) -> Vec<Self>;

    fn sub(x: Self, y: Self) -> Self {
        let ((a0, a1), (b0, b1)) = (x.pair(), y.pair());
        Self::make(Self::minus(a0, b0), Self::minus(a1, b1))
    }
    fn scale(x: Self, c: u64) -> Self {
        let (a0, a1) = x.pair();
        Self::make(Self::times(a0, c), Self::times(a1, c))
    }
    /// Add a public constant (it becomes summand 0: party 0's s0, party 2's s1).
    fn add_pub(x: Self, c: u64, party: usize) -> Self {
        let (a0, a1) = x.pair();
        match party {
            0 => Self::make(Self::plus(a0, c), a1),
            2 => Self::make(a0, Self::plus(a1, c)),
            _ => x,
        }
    }
}

impl Dom for A {
    const ARITH: bool = true;
    fn pair(self) -> (u64, u64) {
        (self.s0, self.s1)
    }
    fn make(s0: u64, s1: u64) -> Self {
        A { s0, s1 }
    }
    fn plus(a: u64, b: u64) -> u64 {
        a.wrapping_add(b)
    }
    fn minus(a: u64, b: u64) -> u64 {
        a.wrapping_sub(b)
    }
    fn times(a: u64, b: u64) -> u64 {
        a.wrapping_mul(b)
    }
    fn mul_raw(p: &mut Party, xs: &[Self], ys: &[Self], cheat: Cheat) -> Vec<Self> {
        p.mul_inner(xs, ys, cheat)
    }
}

impl Dom for B {
    const ARITH: bool = false;
    fn pair(self) -> (u64, u64) {
        (self.s0, self.s1)
    }
    fn make(s0: u64, s1: u64) -> Self {
        B { s0, s1 }
    }
    fn plus(a: u64, b: u64) -> u64 {
        a ^ b
    }
    fn minus(a: u64, b: u64) -> u64 {
        a ^ b
    }
    fn times(a: u64, b: u64) -> u64 {
        a & b
    }
    fn mul_raw(p: &mut Party, xs: &[Self], ys: &[Self], cheat: Cheat) -> Vec<Self> {
        p.and_inner(xs, ys, cheat)
    }
}

impl Party {
    /// Fresh random sharings with no communication: summand j comes from
    /// key k_j, which exactly its two holders share.
    pub(crate) fn rand_shares<D: Dom>(&mut self, n: usize) -> Vec<D> {
        let s0 = self.own.words(n);
        let s1 = self.next.words(n);
        s0.into_iter().zip(s1).map(|(a, b)| D::make(a, b)).collect()
    }

    /// Checked opening. Each party sends its s0 to the next party, which
    /// is missing exactly that summand. The second copy of the same summand,
    /// held by the receiver's other neighbour, is by default sent in full and
    /// compared on arrival. With `checksum_copies` it is instead folded on
    /// both sides into a keyed running checksum (FLNW compare hashed views in
    /// the same spirit):
    ///
    /// The checksum is sum_k r_k v_k mod 2^128 with 64-bit r_k from the
    /// stream that only the two comparing parties share; the third party, the
    /// only one that could have sent a wrong value, never sees the key. For an
    /// error e (|e| < 2^64, e != 0) its 2-adic valuation v is below 64, and
    /// distinct r < 2^64 give distinct r e mod 2^128 (their difference would
    /// need valuation >= 128 - v > 64), so a wrong value survives with
    /// probability at most 2^-64.
    ///
    /// The two checksums travel back in the same round as the values (16
    /// bytes), so the comparison costs no extra round; the returned flag says
    /// whether every copy so far has matched, and callers fold it into the
    /// verdict before anything depending on the values is released.
    pub(crate) fn open_checked<D: Dom>(&mut self, xs: &[D]) -> (Vec<u64>, bool) {
        let n = xs.len();
        let s0: Vec<u64> = xs.iter().map(|x| x.pair().0).collect();
        let mut s1: Vec<u64> = xs.iter().map(|x| x.pair().1).collect();
        if cfg!(feature = "plant-cheat-open-copy") && self.id == 1 && !self.cheated && !s1.is_empty() {
            self.cheated = true;
            s1[0] ^= 1; // PLANTED CHEAT: wrong copy of a summand
        }
        if !self.checksum_copies {
            // Default: send the second copy in full and compare on arrival.
            self.net.stats.rounds += 1;
            self.net.send_next(s0);
            self.net.send_prev(s1);
            let from_prev = self.net.recv_prev();
            let from_next = self.net.recv_next();
            let ok = from_prev == from_next;
            let vals: Vec<u64> = xs
                .iter()
                .zip(&from_prev)
                .map(|(x, m)| {
                    let (a, b) = x.pair();
                    D::plus(D::plus(a, b), *m)
                })
                .collect();
            self.log_open(&vals);
            return (vals, ok);
        }
        // Opt-in (`checksum_copies`): 38% less data in malicious mode, but
        // more CPU; median-of-5 A/B on a Mac showed no speed gain on the
        // simulated LAN/WAN (docs/learning/07-verified-shuffle.md).
        // My copies are for my previous party: fold them into my running
        // checksum (key shared with that party) BEFORE receiving anything, so
        // the checksum leaves in the same message hop as the values. (An
        // earlier version computed it after receiving, which silently made
        // every opening two dependent hops.)
        let r_out = self.own.words(n);
        for k in 0..n {
            self.acc_out = self.acc_out.wrapping_add((r_out[k] as u128).wrapping_mul(s1[k] as u128));
        }
        self.net.stats.rounds += 1;
        self.net.send_next(s0);
        self.net.send_prev(vec![self.acc_out as u64, (self.acc_out >> 64) as u64]);
        let from_prev = self.net.recv_prev();
        let w = self.net.recv_next();
        // Received values: key shared with the next party (it holds the copy).
        let r_in = self.next.words(n);
        for k in 0..n {
            self.acc_in = self.acc_in.wrapping_add((r_in[k] as u128).wrapping_mul(from_prev[k] as u128));
        }
        // Cumulative sums: an earlier mismatch can never cancel out (the
        // cheater does not know the key). 16 bytes, one hop.
        let copies_ok = ((w[0] as u128) | ((w[1] as u128) << 64)) == self.acc_in;
        let vals: Vec<u64> = xs
            .iter()
            .zip(&from_prev)
            .map(|(x, m)| {
                let (a, b) = x.pair();
                D::plus(D::plus(a, b), *m)
            })
            .collect();
        self.log_open(&vals);
        (vals, copies_ok)
    }

    /// Public checked opening of arithmetic values (malicious mode).
    pub fn open_a_checked(&mut self, xs: &[A]) -> (Vec<u64>, bool) {
        self.open_checked(xs)
    }

    /// A public random permutation from jointly opened randomness. The
    /// random sharing is created after everything it is used to check, and
    /// its opening is checked, so no single party can predict or bias it.
    fn coin_perm(&mut self, n: usize, ok: &mut bool) -> Vec<usize> {
        let r: Vec<A> = self.rand_shares(2);
        let (v, good) = self.open_checked(&r);
        *ok &= good;
        let mut key = [0u8; 16];
        key[..8].copy_from_slice(&v[0].to_le_bytes());
        key[8..].copy_from_slice(&v[1].to_le_bytes());
        random_perm(&mut Prf::new(&key), n)
    }

    /// Check products (x, y, z) against triples (a, b, c), one triple per
    /// product (FLNW Protocol 2.24, ring form): open rho = x - a and
    /// sigma = y - b, then t = z - c - sigma a - rho b - rho sigma must open
    /// to 0, because xy = rho sigma + rho b + sigma a + ab.
    fn check_pairs<D: Dom>(&mut self, xyz: &[(D, D, D)], abc: &[(D, D, D)], ok: &mut bool) {
        let n = xyz.len();
        let id = self.id;
        let mut masked = Vec::with_capacity(2 * n);
        masked.extend(xyz.iter().zip(abc).map(|(p, t)| D::sub(p.0, t.0)));
        masked.extend(xyz.iter().zip(abc).map(|(p, t)| D::sub(p.1, t.1)));
        let (open, good) = self.open_checked(&masked);
        *ok &= good;
        let ts: Vec<D> = (0..n)
            .map(|k| {
                let (rho, sigma) = (open[k], open[n + k]);
                let (z, (a, b, c)) = (xyz[k].2, abc[k]);
                let t = D::sub(D::sub(D::sub(z, c), D::scale(a, sigma)), D::scale(b, rho));
                D::add_pub(t, D::minus(0, D::times(rho, sigma)), id)
            })
            .collect();
        let (vals, good) = self.open_checked(&ts);
        *ok &= good && vals.iter().all(|&v| v == 0);
    }

    /// n verified triples (FLNW Protocol 3.2): generate NB + C, shuffle them
    /// with joint coins, open and check C, split the rest into N buckets of
    /// B, and check every bucket's first triple against the others. The first
    /// triple of each bucket is returned.
    fn triples<D: Dom>(&mut self, n: usize, ok: &mut bool) -> Vec<(D, D, D)> {
        let b = bucket_size(n);
        let c = b;
        let total = n * b + c;
        let a: Vec<D> = self.rand_shares(total);
        let bb: Vec<D> = self.rand_shares(total);
        let cheat = if D::ARITH && cfg!(feature = "plant-cheat-triple") && self.id == 1 && !self.cheated {
            self.cheated = true;
            Cheat::Message // PLANTED CHEAT: one bad triple
        } else {
            Cheat::None
        };
        let cc = D::mul_raw(self, &a, &bb, cheat);
        let all: Vec<(D, D, D)> = (0..total).map(|k| (a[k], bb[k], cc[k])).collect();
        let perm = self.coin_perm(total, ok);
        let t = apply_public(&perm, &all);

        let mut probe = Vec::with_capacity(3 * c);
        for tk in &t[..c] {
            probe.push(tk.0);
            probe.push(tk.1);
            probe.push(tk.2);
        }
        let (v, good) = self.open_checked(&probe);
        *ok &= good && (0..c).all(|k| D::times(v[3 * k], v[3 * k + 1]) == v[3 * k + 2]);

        let firsts: Vec<(D, D, D)> = (0..n).map(|k| t[c + k * b]).collect();
        let mut kept = Vec::with_capacity(n * (b - 1));
        let mut masks = Vec::with_capacity(n * (b - 1));
        for k in 0..n {
            for j in 1..b {
                kept.push(firsts[k]);
                masks.push(t[c + k * b + j]);
            }
        }
        self.check_pairs(&kept, &masks, ok);
        firsts
    }

    /// Verify recorded products in batches of at most CHUNK. With
    /// `force`, verify everything pending; otherwise only full batches. All
    /// three servers record identical counts, so they call this in lockstep.
    pub(crate) fn check_pending(&mut self, force: bool) {
        while self.pending_a.len() >= CHUNK || (force && !self.pending_a.is_empty()) {
            let take = self.pending_a.len().min(CHUNK);
            let batch: Vec<(A, A, A)> = self.pending_a.drain(..take).collect();
            let mut ok = true;
            let tr = self.triples::<A>(batch.len(), &mut ok);
            self.check_pairs(&batch, &tr, &mut ok);
            self.ok_so_far &= ok;
            self.verified_batches += 1;
        }
        while self.pending_b.len() >= CHUNK || (force && !self.pending_b.is_empty()) {
            let take = self.pending_b.len().min(CHUNK);
            let batch: Vec<(B, B, B)> = self.pending_b.drain(..take).collect();
            let mut ok = true;
            let tr = self.triples::<B>(batch.len(), &mut ok);
            self.check_pairs(&batch, &tr, &mut ok);
            self.ok_so_far &= ok;
            self.verified_batches += 1;
        }
    }

    /// Verify every product still pending, then agree with the other two
    /// servers on the verdict (including any earlier failed batch). Must be
    /// called by all three servers at the same point; it runs before every
    /// opening of data in malicious mode.
    pub fn verify(&mut self) -> Result<(), Abort> {
        self.check_pending(true);
        let ok = self.ok_so_far;
        self.agree(ok)
    }

    /// Tell both other servers whether this one's checks passed and learn
    /// theirs; any failure anywhere aborts every honest server. One round.
    pub fn agree(&mut self, ok: bool) -> Result<(), Abort> {
        self.net.stats.rounds += 1;
        self.net.send_next(vec![ok as u64]);
        self.net.send_prev(vec![ok as u64]);
        let a = self.net.recv_prev();
        let b = self.net.recv_next();
        if ok && a == [1] && b == [1] { Ok(()) } else { Err(Abort) }
    }

    /// Open Boolean words: plain in semi-honest mode; checked and agreed in
    /// malicious mode (see [`Self::open_a_safe`]).
    pub fn open_b_safe(&mut self, xs: &[B]) -> Result<Vec<u64>, Abort> {
        if !self.malicious {
            return Ok(self.open_b(xs));
        }
        self.verify()?;
        let (v, good) = self.open_checked(xs);
        self.agree(good)?;
        Ok(v)
    }

    /// Open arithmetic values: plain in semi-honest mode; in malicious mode,
    /// verify everything first, open with both copies, and agree on the result.
    pub fn open_a_safe(&mut self, xs: &[A]) -> Result<Vec<u64>, Abort> {
        if !self.malicious {
            return Ok(self.open_a(xs));
        }
        self.verify()?;
        let (v, good) = self.open_checked(xs);
        self.agree(good)?;
        Ok(v)
    }
}
