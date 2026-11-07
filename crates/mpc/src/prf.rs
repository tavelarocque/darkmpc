//! Pseudorandom streams shared between pairs of parties.
//!
//! A stream is AES-128 in counter mode: block j is AES_k(j). Two parties that
//! hold the same key and draw from it in the same order see the same values,
//! which is how the zero-sharings in multiplication cost no communication.
//! AES comes from the RustCrypto `aes` crate (used as a PRF, its intended
//! building-block role); darkmpc never implements a cipher itself.

use aes::Aes128;
use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};

pub type Key = [u8; 16];

pub struct Prf {
    cipher: Aes128,
    counter: u64,
}

impl Prf {
    pub fn new(key: &Key) -> Self {
        Prf { cipher: Aes128::new(&Array::from(*key)), counter: 0 }
    }

    /// Fill `out` with the next pseudorandom 64-bit words of the stream.
    pub fn fill(&mut self, out: &mut [u64]) {
        let nblocks = out.len().div_ceil(2);
        let mut blocks: Vec<Array<u8, _>> = (0..nblocks)
            .map(|j| {
                let mut b = [0u8; 16];
                b[..8].copy_from_slice(&(self.counter + j as u64).to_le_bytes());
                Array::from(b)
            })
            .collect();
        self.counter += nblocks as u64;
        self.cipher.encrypt_blocks(&mut blocks);
        for (k, w) in out.iter_mut().enumerate() {
            let b = &blocks[k / 2];
            let off = (k % 2) * 8;
            *w = u64::from_le_bytes(b[off..off + 8].try_into().unwrap());
        }
    }

    /// n pseudorandom 128-bit words (two 64-bit words each).
    pub fn words128(&mut self, n: usize) -> Vec<u128> {
        let w = self.words(2 * n);
        (0..n).map(|k| (w[2 * k] as u128) | ((w[2 * k + 1] as u128) << 64)).collect()
    }

    pub fn words(&mut self, n: usize) -> Vec<u64> {
        let mut v = vec![0u64; n];
        self.fill(&mut v);
        v
    }
}

/// A fresh random key from the operating system.
pub fn random_key() -> Key {
    let mut k = [0u8; 16];
    getrandom::fill(&mut k).expect("OS randomness unavailable");
    k
}
