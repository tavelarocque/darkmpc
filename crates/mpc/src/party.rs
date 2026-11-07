//! The semi-honest three-party protocols.
//!
//! All operations are vectorised: one call processes a whole batch in the
//! same number of rounds as a single element, which is how auction-sized
//! batches stay cheap in latency.

use crate::net::Net;
use crate::prf::{Key, Prf, random_key};
use crate::share::{A, B};

pub struct Party {
    pub id: usize,
    /// Stream for key k_i, shared with party i - 1.
    pub(crate) own: Prf,
    /// Stream for key k_{i+1}, shared with party i + 1.
    pub(crate) next: Prf,
    pub net: Net,
    /// Malicious mode: record every product for verification before openings.
    pub malicious: bool,
    pub(crate) pending_a: Vec<(A, A, A)>,
    pub(crate) pending_b: Vec<(B, B, B)>,
    /// Used only by planted cheating behaviour: has this party cheated yet?
    pub(crate) cheated: bool,
    /// False once any local check has failed (sticky until the verdict).
    pub(crate) ok_so_far: bool,
    /// Number of verified batches so far (for the overall security bound).
    pub verified_batches: u64,
    /// Deferred copy check for checked openings: a keyed linear checksum of
    /// the values received from the previous party, and of this party's own
    /// copies of those values for its previous party. Compared in `agree`.
    pub(crate) acc_in: u128,
    pub(crate) acc_out: u128,
    /// Malicious mode: check second copies by keyed checksum instead of
    /// sending them (less data, more CPU). Off by default.
    pub checksum_copies: bool,
    /// Test hook: make party 1 tamper with the 4b shuffle (malicious mode).
    #[doc(hidden)]
    pub test_cheat_shuffle: bool,
    /// If set, every value this party learns from an opening is appended
    /// here, one entry per opening (the leakage audit's view of openings).
    pub opened: Option<Vec<Vec<u64>>>,
}

/// How a (planted) cheating party deviates in one multiplication.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cheat {
    None,
    /// Send a wrong first message word.
    Message,
    /// Send the right message but keep a different value as its own copy.
    KeepOwn,
}

impl Party {
    pub fn new(id: usize, k_own: &Key, k_next: &Key, net: Net) -> Self {
        Party {
            id,
            own: Prf::new(k_own),
            next: Prf::new(k_next),
            net,
            malicious: false,
            pending_a: Vec::new(),
            pending_b: Vec::new(),
            cheated: false,
            ok_so_far: true,
            verified_batches: 0,
            test_cheat_shuffle: false,
            acc_in: 0,
            acc_out: 0,
            checksum_copies: false,
            opened: None,
        }
    }

    pub(crate) fn log_open(&mut self, vals: &[u64]) {
        if let Some(log) = self.opened.as_mut() {
            log.push(vals.to_vec());
        }
    }

    /// Additive zero-sharing alpha_i = F(k_i) - F(k_{i+1}); sums to 0 over
    /// the three parties because each key's value appears once with each sign.
    fn zero_shares_add(&mut self, n: usize) -> Vec<u64> {
        if cfg!(feature = "plant-no-rerandomize") {
            // PLANTED BUG: no mask. Results stay correct but the message leaks.
            return vec![0; n];
        }
        let a = self.own.words(n);
        let b = self.next.words(n);
        a.iter().zip(&b).map(|(x, y)| x.wrapping_sub(*y)).collect()
    }

    /// XOR zero-sharing alpha_i = F(k_i) xor F(k_{i+1}).
    fn zero_shares_xor(&mut self, n: usize) -> Vec<u64> {
        if cfg!(feature = "plant-no-rerandomize") {
            return vec![0; n];
        }
        let a = self.own.words(n);
        let b = self.next.words(n);
        a.iter().zip(&b).map(|(x, y)| x ^ y).collect()
    }

    // ----- opening -----

    /// Reveal arithmetic values to all three parties. One round, one word
    /// sent per value.
    pub fn open_a(&mut self, xs: &[A]) -> Vec<u64> {
        let missing = self.net.to_next_from_prev(xs.iter().map(|x| x.s0).collect());
        let v: Vec<u64> = xs.iter().zip(&missing).map(|(x, m)| x.s0.wrapping_add(x.s1).wrapping_add(*m)).collect();
        self.log_open(&v);
        v
    }

    /// Reveal Boolean words to all three parties.
    pub fn open_b(&mut self, xs: &[B]) -> Vec<u64> {
        let missing = self.net.to_next_from_prev(xs.iter().map(|x| x.s0).collect());
        let v: Vec<u64> = xs.iter().zip(&missing).map(|(x, m)| x.s0 ^ x.s1 ^ m).collect();
        self.log_open(&v);
        v
    }

    // ----- multiplication -----

    /// Which planted cheat (if any) this call should perform: party 1 cheats
    /// once, in the first recorded product of the planted kind.
    fn planned_cheat(&mut self, arithmetic: bool) -> Cheat {
        if !self.malicious || self.id != 1 || self.cheated {
            return Cheat::None;
        }
        let c = if (arithmetic && cfg!(feature = "plant-cheat-mul"))
            || (!arithmetic && cfg!(feature = "plant-cheat-and"))
        {
            Cheat::Message
        } else if arithmetic && cfg!(feature = "plant-cheat-keep-own") {
            Cheat::KeepOwn
        } else {
            Cheat::None
        };
        if c != Cheat::None {
            self.cheated = true;
        }
        c
    }

    /// Elementwise product. Party i computes
    /// z_i = x_i y_i + x_i y_{i+1} + x_{i+1} y_i + alpha_i,
    /// sends it to party i - 1, and receives z_{i+1}. One round, one word.
    /// In malicious mode every product is recorded for later verification.
    pub fn mul(&mut self, xs: &[A], ys: &[A]) -> Vec<A> {
        let cheat = self.planned_cheat(true);
        let z = self.mul_inner(xs, ys, cheat);
        if self.malicious {
            self.pending_a.extend(xs.iter().zip(ys).zip(&z).map(|((x, y), z)| (*x, *y, *z)));
            self.check_pending(false);
        }
        z
    }

    pub(crate) fn mul_inner(&mut self, xs: &[A], ys: &[A], cheat: Cheat) -> Vec<A> {
        assert_eq!(xs.len(), ys.len());
        let alpha = self.zero_shares_add(xs.len());
        let z: Vec<u64> = xs
            .iter()
            .zip(ys)
            .zip(&alpha)
            .map(|((x, y), a)| {
                let mut t = x.s0.wrapping_mul(y.s0).wrapping_add(x.s0.wrapping_mul(y.s1));
                if !cfg!(feature = "plant-mul-wrong-share") {
                    t = t.wrapping_add(x.s1.wrapping_mul(y.s0));
                } // PLANTED BUG when the feature is on: cross term x_{i+1} y_i dropped.
                t.wrapping_add(*a)
            })
            .collect();
        let mut sent = z.clone();
        if cheat == Cheat::Message && !sent.is_empty() {
            sent[0] = sent[0].wrapping_add(1); // PLANTED CHEAT: wrong message
        }
        let z_next = self.net.to_prev_from_next(sent);
        let mut own = z;
        if cheat == Cheat::KeepOwn && !own.is_empty() {
            own[0] = own[0].wrapping_add(1); // PLANTED CHEAT: inconsistent own copy
        }
        own.into_iter().zip(z_next).map(|(s0, s1)| A { s0, s1 }).collect()
    }

    /// Elementwise AND of 64-bit words: the same protocol with XOR and AND.
    /// In malicious mode every AND is recorded for later verification.
    pub fn and(&mut self, xs: &[B], ys: &[B]) -> Vec<B> {
        let cheat = self.planned_cheat(false);
        let z = self.and_inner(xs, ys, cheat);
        if self.malicious {
            self.pending_b.extend(xs.iter().zip(ys).zip(&z).map(|((x, y), z)| (*x, *y, *z)));
            self.check_pending(false);
        }
        z
    }

    pub(crate) fn and_inner(&mut self, xs: &[B], ys: &[B], cheat: Cheat) -> Vec<B> {
        assert_eq!(xs.len(), ys.len());
        let alpha = self.zero_shares_xor(xs.len());
        let z: Vec<u64> = xs
            .iter()
            .zip(ys)
            .zip(&alpha)
            .map(|((x, y), a)| (x.s0 & y.s0) ^ (x.s0 & y.s1) ^ (x.s1 & y.s0) ^ a)
            .collect();
        let mut sent = z.clone();
        if cheat == Cheat::Message && !sent.is_empty() {
            sent[0] ^= 1; // PLANTED CHEAT: flipped output bit
        }
        let z_next = self.net.to_prev_from_next(sent);
        z.into_iter().zip(z_next).map(|(s0, s1)| B { s0, s1 }).collect()
    }

    /// Two independent AND batches in one round.
    fn and2(&mut self, x1: &[B], y1: &[B], x2: &[B], y2: &[B]) -> (Vec<B>, Vec<B>) {
        let n = x1.len();
        let xs: Vec<B> = x1.iter().chain(x2).copied().collect();
        let ys: Vec<B> = y1.iter().chain(y2).copied().collect();
        let mut out = self.and(&xs, &ys);
        let second = out.split_off(n);
        (out, second)
    }

    // ----- comparison -----

    /// Most significant bit of s + c (mod 2^64), for Boolean-shared s and c,
    /// returned as a shared bit in position 0.
    ///
    /// Sum bit 63 is p63 xor (carry into bit 63), where p = s xor c. The carry
    /// is computed with a Kogge-Stone parallel prefix over generate g = s and c
    /// and propagate p: at distance d, G <- G xor (P and (G << d)) and
    /// P <- P and (P << d). XOR can stand in for OR because a position (or
    /// group) can never both generate and propagate. Distances 1, 2, ..., 32
    /// cover all 64 bits. Cost: 1 round for g, 6 rounds of prefix.
    pub fn msb_of_sum(&mut self, s: &[B], c: &[B]) -> Vec<B> {
        let (p, g) = self.carries(s, c);
        p.iter().zip(&g).map(|(pi, gi)| (pi.rshift(63) ^ gi.rshift(62)).mask(1)).collect()
    }

    /// Propagate p = s xor c and the carry-out of every position G (bit k of
    /// G = carry out of position k, taking all lower positions into account).
    /// The sum is then s + c = p xor (G << 1).
    fn carries(&mut self, s: &[B], c: &[B]) -> (Vec<B>, Vec<B>) {
        let p: Vec<B> = s.iter().zip(c).map(|(a, b)| *a ^ *b).collect();
        let mut g = self.and(s, c);
        let mut pp = p.clone();
        let distances: &[u32] =
            if cfg!(feature = "plant-short-carry") { &[1, 2, 4, 8, 16] } else { &[1, 2, 4, 8, 16, 32] };
        // PLANTED BUG (plant-short-carry): stops at distance 16, so carries
        // that travel more than 32 positions are lost.
        for (level, &d) in distances.iter().enumerate() {
            let g_shift: Vec<B> = g.iter().map(|x| x.lshift(d)).collect();
            if level + 1 == distances.len() {
                let t = self.and(&pp, &g_shift);
                g = g.iter().zip(&t).map(|(a, b)| *a ^ *b).collect();
            } else {
                let p_shift: Vec<B> = pp.iter().map(|x| x.lshift(d)).collect();
                let (t, np) = self.and2(&pp, &g_shift, &pp, &p_shift);
                g = g.iter().zip(&t).map(|(a, b)| *a ^ *b).collect();
                pp = np;
            }
        }
        (p, g)
    }

    /// Local conversion and carry-save step shared by msb and decompose:
    /// x0 + x1 + x2 becomes s + c with one round of ANDs.
    fn carry_save(&mut self, xs: &[A]) -> (Vec<B>, Vec<B>) {
        let id = self.id;
        let x0: Vec<B> = xs.iter().map(|x| x.summand_bits(0, id)).collect();
        let x1: Vec<B> = xs.iter().map(|x| x.summand_bits(1, id)).collect();
        let x2: Vec<B> = xs.iter().map(|x| x.summand_bits(2, id)).collect();
        let u: Vec<B> = x0.iter().zip(&x1).map(|(a, b)| *a ^ *b).collect();
        let v: Vec<B> = x1.iter().zip(&x2).map(|(a, b)| *a ^ *b).collect();
        let s: Vec<B> = u.iter().zip(&x2).map(|(a, b)| *a ^ *b).collect();
        let m = self.and(&u, &v);
        let c: Vec<B> = m.iter().zip(&x1).map(|(a, b)| (*a ^ *b).lshift(1)).collect();
        (s, c)
    }

    /// Full bit decomposition: Boolean sharing of all 64 bits of each x.
    /// Same circuit and cost as [`Self::msb`] (the carry circuit already
    /// computes every carry), finished with sum = p xor (G << 1).
    pub fn decompose(&mut self, xs: &[A]) -> Vec<B> {
        let (s, c) = self.carry_save(xs);
        let (p, g) = self.carries(&s, &c);
        p.iter().zip(&g).map(|(pi, gi)| *pi ^ gi.lshift(1)).collect()
    }

    /// Most significant bit of arithmetic-shared x, as a shared bit.
    ///
    /// Local conversion: each additive summand x_j is held in the clear by two
    /// parties, so it has a trivial Boolean sharing with no communication.
    /// A carry-save adder turns x0 + x1 + x2 into s + c with one round
    /// (s = x0 xor x1 xor x2, c = majority(x0, x1, x2) << 1, and
    /// majority(a, b, c) = ((a xor b) and (b xor c)) xor b), then
    /// [`Self::msb_of_sum`] finishes. Total 8 rounds.
    pub fn msb(&mut self, xs: &[A]) -> Vec<B> {
        let (s, c) = self.carry_save(xs);
        self.msb_of_sum(&s, &c)
    }

    /// Convert shared bits (position 0) into arithmetic shares of 0 or 1.
    /// With b = b0 xor b1 xor b2 and a xor b = a + b - 2ab over the integers:
    /// d = b0 + b1 - 2 b0 b1, then b = d + b2 - 2 d b2. Two rounds.
    pub fn bit_inject(&mut self, bs: &[B]) -> Vec<A> {
        let id = self.id;
        let t0: Vec<A> = bs.iter().map(|b| b.summand_as_ring(0, id)).collect();
        let t1: Vec<A> = bs.iter().map(|b| b.summand_as_ring(1, id)).collect();
        let t2: Vec<A> = bs.iter().map(|b| b.summand_as_ring(2, id)).collect();
        let m1 = self.mul(&t0, &t1);
        let d: Vec<A> = (0..bs.len()).map(|k| t0[k] + t1[k] - m1[k].scale(2)).collect();
        let m2 = self.mul(&d, &t2);
        (0..bs.len()).map(|k| d[k] + t2[k] - m2[k].scale(2)).collect()
    }

    /// [x < 0] as an arithmetic 0/1, reading x as a signed 64-bit integer.
    pub fn ltz(&mut self, xs: &[A]) -> Vec<A> {
        let bits = self.msb(xs);
        self.bit_inject(&bits)
    }

    /// [a < b]. Correct whenever a - b does not wrap, i.e. |a - b| < 2^63;
    /// darkmpc's input bounds guarantee that for every comparison it makes.
    pub fn lt(&mut self, a: &[A], b: &[A]) -> Vec<A> {
        let id = self.id;
        let d: Vec<A> = a
            .iter()
            .zip(b)
            .map(|(x, y)| {
                let d = *x - *y;
                if cfg!(feature = "plant-lt-off-by-one") {
                    d.add_public(u64::MAX, id) // PLANTED BUG: computes a - b - 1 < 0, i.e. a <= b
                } else {
                    d
                }
            })
            .collect();
        self.ltz(&d)
    }

    /// c ? x : y for a shared 0/1 value c. One multiplication.
    pub fn select(&mut self, c: &[A], x: &[A], y: &[A]) -> Vec<A> {
        let diff: Vec<A> = x.iter().zip(y).map(|(a, b)| *a - *b).collect();
        let t = self.mul(c, &diff);
        y.iter().zip(&t).map(|(a, b)| *a + *b).collect()
    }

    /// Elementwise minimum (same bound as [`Self::lt`]).
    pub fn min(&mut self, a: &[A], b: &[A]) -> Vec<A> {
        let c = self.lt(a, b);
        self.select(&c, a, b)
    }

    /// Elementwise maximum.
    pub fn max(&mut self, a: &[A], b: &[A]) -> Vec<A> {
        let c = self.lt(a, b);
        self.select(&c, b, a)
    }
}

/// Run `f` as each of the three parties on its own thread, with fresh keys.
/// `record` turns on transcript and opening recording for leakage tests.
pub fn run3<R: Send>(record: bool, f: impl Fn(&mut Party) -> R + Sync) -> [R; 3] {
    run3_model(None, record, f)
}

/// [`run3`] over a simulated network (latency and bandwidth per link).
pub fn run3_model<R: Send>(
    model: Option<crate::net::NetModel>,
    record: bool,
    f: impl Fn(&mut Party) -> R + Sync,
) -> [R; 3] {
    let keys = [random_key(), random_key(), random_key()];
    let nets = Net::triangle_with(model);
    let f = &f;
    std::thread::scope(|scope| {
        let handles: Vec<_> = nets
            .into_iter()
            .enumerate()
            .map(|(i, mut net)| {
                if record {
                    net.transcript = Some(Vec::new());
                }
                let (ko, kn) = (keys[i], keys[(i + 1) % 3]);
                scope.spawn(move || {
                    let mut p = Party::new(i, &ko, &kn, net);
                    if record {
                        p.opened = Some(Vec::new());
                    }
                    f(&mut p)
                })
            })
            .collect();
        let mut out: Vec<R> = handles.into_iter().map(|h| h.join().expect("party panicked")).collect();
        let r2 = out.pop().unwrap();
        let r1 = out.pop().unwrap();
        let r0 = out.pop().unwrap();
        [r0, r1, r2]
    })
}
