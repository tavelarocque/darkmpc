//! Replicated shares and the local (communication-free) operations on them.
//!
//! A secret x in Z_2^64 is split as x = x0 + x1 + x2. Party i holds the pair
//! (x_i, x_{i+1}), indices mod 3, stored as `A { s0: x_i, s1: x_{i+1} }`.
//!
//! `B` is the same structure with XOR in place of addition, applied to all 64
//! bit positions of a word at once (bit-slicing): bit k of the word is an
//! independent shared bit. A single shared bit lives in bit 0 unless a
//! function says otherwise.

use std::ops::{Add, BitXor, Neg, Sub};

/// Arithmetic replicated share over Z_2^64, as held by one party.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct A {
    pub s0: u64,
    pub s1: u64,
}

/// Boolean replicated share of 64 bits (bit-sliced), as held by one party.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct B {
    pub s0: u64,
    pub s1: u64,
}

impl Add for A {
    type Output = A;
    fn add(self, o: A) -> A {
        A { s0: self.s0.wrapping_add(o.s0), s1: self.s1.wrapping_add(o.s1) }
    }
}
impl Sub for A {
    type Output = A;
    fn sub(self, o: A) -> A {
        A { s0: self.s0.wrapping_sub(o.s0), s1: self.s1.wrapping_sub(o.s1) }
    }
}
impl Neg for A {
    type Output = A;
    fn neg(self) -> A {
        A { s0: self.s0.wrapping_neg(), s1: self.s1.wrapping_neg() }
    }
}
impl A {
    /// Multiply by a public constant.
    pub fn scale(self, c: u64) -> A {
        A { s0: self.s0.wrapping_mul(c), s1: self.s1.wrapping_mul(c) }
    }
    /// Add a public constant. The constant becomes summand x0, which party 0
    /// holds as s0 and party 2 holds as s1.
    pub fn add_public(self, c: u64, party: usize) -> A {
        match party {
            0 => A { s0: self.s0.wrapping_add(c), s1: self.s1 },
            2 => A { s0: self.s0, s1: self.s1.wrapping_add(c) },
            _ => self,
        }
    }
    /// A sharing of a public constant.
    pub fn public(c: u64, party: usize) -> A {
        A::default().add_public(c, party)
    }
    /// A sharing of summand j of this value on its own: (x_j, 0, 0) placed at
    /// position j. Party i knows x_i and x_{i+1}, so it can build this for
    /// every j without communication (it is all zeros for j = i + 2).
    pub fn summand(self, j: usize, party: usize) -> A {
        A { s0: if j == party { self.s0 } else { 0 }, s1: if j == (party + 1) % 3 { self.s1 } else { 0 } }
    }
    /// The same summand as a Boolean sharing of its 64 bits.
    pub fn summand_bits(self, j: usize, party: usize) -> B {
        let a = self.summand(j, party);
        B { s0: a.s0, s1: a.s1 }
    }
}

impl BitXor for B {
    type Output = B;
    fn bitxor(self, o: B) -> B {
        B { s0: self.s0 ^ o.s0, s1: self.s1 ^ o.s1 }
    }
}
impl B {
    pub fn lshift(self, k: u32) -> B {
        B { s0: self.s0 << k, s1: self.s1 << k }
    }
    pub fn rshift(self, k: u32) -> B {
        B { s0: self.s0 >> k, s1: self.s1 >> k }
    }
    /// AND with a public mask.
    pub fn mask(self, m: u64) -> B {
        B { s0: self.s0 & m, s1: self.s1 & m }
    }
    /// XOR with a public word (the word becomes summand 0).
    pub fn xor_public(self, c: u64, party: usize) -> B {
        match party {
            0 => B { s0: self.s0 ^ c, s1: self.s1 },
            2 => B { s0: self.s0, s1: self.s1 ^ c },
            _ => self,
        }
    }
    /// Boolean summand j (see [`A::summand`]), then lifted to Z_2^64. Only
    /// meaningful for single bits in position 0.
    pub fn summand_as_ring(self, j: usize, party: usize) -> A {
        A { s0: if j == party { self.s0 & 1 } else { 0 }, s1: if j == (party + 1) % 3 { self.s1 & 1 } else { 0 } }
    }
}

/// Split x into the three parties' views of a fresh arithmetic sharing.
/// `rand` must be a cryptographic source in real use (the client side).
pub fn share_a(x: u64, mut rand: impl FnMut() -> u64) -> [A; 3] {
    let x0 = rand();
    let x1 = rand();
    let x2 = x.wrapping_sub(x0).wrapping_sub(x1);
    let s = [x0, x1, x2];
    [0, 1, 2].map(|i| A { s0: s[i], s1: s[(i + 1) % 3] })
}

/// Split 64 bits into the three parties' views of a fresh Boolean sharing.
pub fn share_b(x: u64, mut rand: impl FnMut() -> u64) -> [B; 3] {
    let x0 = rand();
    let x1 = rand();
    let s = [x0, x1, x ^ x0 ^ x1];
    [0, 1, 2].map(|i| B { s0: s[i], s1: s[(i + 1) % 3] })
}

/// Reconstruct from all three views, checking that the two copies of every
/// summand agree (each summand is held by two parties).
pub fn reconstruct_a(v: [A; 3]) -> Option<u64> {
    for i in 0..3 {
        if v[i].s1 != v[(i + 1) % 3].s0 {
            return None;
        }
    }
    Some(v[0].s0.wrapping_add(v[1].s0).wrapping_add(v[2].s0))
}

pub fn reconstruct_b(v: [B; 3]) -> Option<u64> {
    for i in 0..3 {
        if v[i].s1 != v[(i + 1) % 3].s0 {
            return None;
        }
    }
    Some(v[0].s0 ^ v[1].s0 ^ v[2].s0)
}
