//! darkmpc reference matcher.
//!
//! This crate is the definition of correct output. It is deliberately plain:
//! no cryptography, no cleverness, no dependencies. The MPC matcher must
//! reproduce its fills exactly on every valid input, and must reject exactly
//! the inputs [`validate`] rejects.
//!
//! Research prototype. Not audited, not for real trading.

pub mod matcher;
pub mod stage2;
pub mod types;

pub use matcher::{
    Params, Passes, SymbolTrace, allocate_prefix, allocate_walk, match_batch, match_batch_traced, matched_volume,
};
pub use stage2::{LimitOrder, MAX_PRICE, clearing_price, clearing_price_by_crossing, demand_supply, match_stage2};
pub use types::{InvalidInput, MAX_BATCH, MAX_SIZE, Order, Side, validate};
