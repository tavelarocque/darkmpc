//! darkmpc MPC core: semi-honest three-party computation with replicated
//! secret sharing over Z_2^64 (arithmetic) and Z_2 (bit-sliced Boolean).
//!
//! Security model of this crate: at most one of the three parties is
//! corrupt and it follows the protocol (semi-honest). Malicious security is
//! Milestone 4. Research prototype, not audited.

pub mod mac;
pub mod net;
pub mod party;
pub mod perm;
pub mod prf;
pub mod scan;
pub mod share;
pub mod verify;

pub use net::{Net, NetModel, RecvHalf, SendHalf, Stats};
pub use party::{Party, run3, run3_model};
pub use share::{A, B, reconstruct_a, reconstruct_b, share_a, share_b};
pub use verify::{Abort, CHUNK, SIGMA, bucket_size, bucket_size_for, overall_security_bits};
