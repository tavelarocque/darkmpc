//! Order and fill types, plus the input bounds every implementation must enforce.

use std::fmt;

/// Largest order size accepted, 2^40 - 1 shares.
///
/// The bound is chosen for the MPC layer, not for markets. With at most
/// [`MAX_BATCH`] = 2^17 orders, any sum of sizes stays below 2^57, so every
/// value the matcher compares (sizes, side totals, prefix sums and their
/// differences) lies strictly inside (-2^63, 2^63). That is what makes
/// "compare by taking the most significant bit of a difference in Z_2^64"
/// sound. The reference enforces the same bound so the two agree on what a
/// valid input is.
pub const MAX_SIZE: u64 = (1 << 40) - 1;

/// Largest batch accepted in one auction, 2^17 = 131,072 orders.
pub const MAX_BATCH: usize = 1 << 17;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Side {
    Buy,
    Sell,
}

/// One order in a periodic call auction.
///
/// There is no price: Stage 1 trades at the public reference midpoint, so
/// matching is about volume only. An order's identity and its time priority
/// are both its index in the batch (earlier index = arrived earlier).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Order {
    pub symbol: u32,
    pub side: Side,
    /// Shares wanted, 1..=MAX_SIZE.
    pub size: u64,
    /// Smallest acceptable non-zero fill, 1..=size. A value of 1 means
    /// "no minimum".
    pub min_fill: u64,
}

impl Order {
    pub const fn buy(symbol: u32, size: u64, min_fill: u64) -> Self {
        Order { symbol, side: Side::Buy, size, min_fill }
    }
    pub const fn sell(symbol: u32, size: u64, min_fill: u64) -> Self {
        Order { symbol, side: Side::Sell, size, min_fill }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvalidInput {
    BatchTooLarge { len: usize },
    SizeOutOfRange { index: usize, size: u64 },
    MinFillOutOfRange { index: usize, size: u64, min_fill: u64 },
}

impl fmt::Display for InvalidInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidInput::BatchTooLarge { len } => {
                write!(f, "batch of {len} orders exceeds MAX_BATCH = {MAX_BATCH}")
            }
            InvalidInput::SizeOutOfRange { index, size } => {
                write!(f, "order {index}: size {size} not in 1..={MAX_SIZE}")
            }
            InvalidInput::MinFillOutOfRange { index, size, min_fill } => {
                write!(f, "order {index}: min_fill {min_fill} not in 1..={size}")
            }
        }
    }
}

impl std::error::Error for InvalidInput {}

/// Check every input bound. Implementations must reject exactly these inputs.
pub fn validate(orders: &[Order]) -> Result<(), InvalidInput> {
    if orders.len() > MAX_BATCH {
        return Err(InvalidInput::BatchTooLarge { len: orders.len() });
    }
    for (index, o) in orders.iter().enumerate() {
        if o.size == 0 || o.size > MAX_SIZE {
            return Err(InvalidInput::SizeOutOfRange { index, size: o.size });
        }
        if o.min_fill == 0 || o.min_fill > o.size {
            return Err(InvalidInput::MinFillOutOfRange { index, size: o.size, min_fill: o.min_fill });
        }
    }
    Ok(())
}
