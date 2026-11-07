//! Validation of traders' inputs, on shares (Milestone 4a step 2).
//!
//! Traders are untrusted. A trader can give the two servers that hold the
//! same summand different values (inconsistent shares), or share values out
//! of range (a size of 2^63 would break comparison by sign for everyone).
//! Every check here runs on shares; the only things opened are values that
//! are fixed public constants for an honest order (0 for a key bit's
//! b(1 - b), 0 for the high bits of a size, 1 for the validity bit), so an
//! honest order's opening reveals nothing. A rejected order becomes a
//! zero-size dummy that every server sets to the same public values.
//!
//! Known limitation (documented in the threat model): a corrupt server can
//! falsely report a mismatch and so censor an order. It cannot learn
//! anything by doing so. Equivocation (telling the two other servers
//! different things) is detected and aborts.

use darkmpc_mpc::{A, Abort, Party};
use darkmpc_reference::MAX_SIZE;

use crate::SharedOrder;
use crate::stage2::{PRICE_BITS, SharedLimitOrder};

/// Bits 40..63: must all be zero for size and min_fill (MAX_SIZE = 2^40 - 1).
const HIGH_MASK: u64 = !MAX_SIZE;

fn dummy(symbol_bits: usize, id: usize) -> SharedOrder {
    SharedOrder {
        symbol_bits: vec![A::public(0, id); symbol_bits],
        side: A::public(0, id),
        size: A::public(0, id),
        min_fill: A::public(1, id),
    }
}

fn words(o: &SharedOrder) -> impl Iterator<Item = A> + '_ {
    o.symbol_bits.iter().copied().chain([o.side, o.size, o.min_fill])
}

/// Exchange per-order flags with both other servers, check that neither
/// told the two of us different things, and return the union.
fn share_flags(p: &mut Party, mine: &[bool]) -> Result<Vec<bool>, Abort> {
    let enc = |f: &[bool]| f.iter().map(|&b| b as u64).collect::<Vec<u64>>();
    p.net.stats.rounds += 1;
    p.net.send_next(enc(mine));
    p.net.send_prev(enc(mine));
    let from_prev = p.net.recv_prev();
    let from_next = p.net.recv_next();
    // Echo: tell each neighbour what the other neighbour told us.
    p.net.stats.rounds += 1;
    p.net.send_next(from_prev.clone());
    p.net.send_prev(from_next.clone());
    let next_said_per_prev = p.net.recv_prev(); // prev's copy of what next sent it
    let prev_said_per_next = p.net.recv_next(); // next's copy of what prev sent it
    let consistent = next_said_per_prev == from_next && prev_said_per_next == from_prev;
    p.agree(consistent)?;
    Ok((0..mine.len()).map(|k| mine[k] || from_prev[k] == 1 || from_next[k] == 1).collect())
}

/// Check every order's replicated shares: summand x_{i+1} is party i's s1
/// and party (i+1)'s s0, so each server sends its s1 words forward and
/// compares. Returns which orders are inconsistent (agreed by all servers).
fn consistency(p: &mut Party, orders: &[Vec<A>]) -> Result<Vec<bool>, Abort> {
    let my_s1: Vec<u64> = orders.iter().flat_map(|o| o.iter().map(|w| w.s1)).collect();
    p.net.stats.rounds += 1;
    p.net.send_next(my_s1);
    let prev_s1 = p.net.recv_prev();
    let mut at = 0;
    let local_bad: Vec<bool> = orders
        .iter()
        .map(|o| {
            let bad = o.iter().enumerate().any(|(j, w)| w.s0 != prev_s1[at + j]);
            at += o.len();
            !cfg!(feature = "plant-skip-consistency") && bad
        })
        .collect();
    share_flags(p, &local_bad)
}

/// Validate every order. Rejected orders are replaced by dummies in place.
/// Returns which orders were rejected (public to all servers).
pub fn validate_inputs(p: &mut Party, orders: &mut [SharedOrder], symbol_bits: usize) -> Result<Vec<bool>, Abort> {
    let n = orders.len();
    let id = p.id;

    // 1. Consistency.
    let all: Vec<Vec<A>> = orders.iter().map(|o| words(o).collect()).collect();
    let mut rejected = consistency(p, &all)?;
    for (o, &r) in orders.iter_mut().zip(&rejected) {
        if r {
            *o = dummy(symbol_bits, id);
        }
    }

    // 2. Key bits are 0 or 1: open b - b*b (0 for an honest bit).
    let bits: Vec<A> = orders.iter().flat_map(|o| o.symbol_bits.iter().copied().chain([o.side])).collect();
    let sq = p.mul(&bits, &bits);
    let t: Vec<A> = bits.iter().zip(&sq).map(|(b, s)| *b - *s).collect();
    //    Sizes and minimum fills below 2^40: open their bits 40..63.
    let mut amounts: Vec<A> = orders.iter().map(|o| o.size).collect();
    amounts.extend(orders.iter().map(|o| o.min_fill));
    let high: Vec<_> = p.decompose(&amounts).into_iter().map(|b| b.mask(HIGH_MASK)).collect();
    let t_open = p.open_a_safe(&t)?;
    let high_open = p.open_b_safe(&high)?;
    let per = symbol_bits + 1;
    for k in 0..n {
        let bad_bits =
            !cfg!(feature = "plant-skip-bit-check") && t_open[k * per..(k + 1) * per].iter().any(|&v| v != 0);
        let bad_range = !cfg!(feature = "plant-skip-range-check") && (high_open[k] != 0 || high_open[n + k] != 0);
        rejected[k] |= bad_bits || bad_range;
    }

    // 3. 1 <= min_fill <= size (sound now that both are below 2^40):
    //    valid = [0 < size] [0 < min] (1 - [size < min]), opened.
    let zero = vec![A::default(); n];
    let size: Vec<A> = orders.iter().map(|o| o.size).collect();
    let min: Vec<A> = orders.iter().map(|o| o.min_fill).collect();
    let mut lhs = zero.clone();
    lhs.extend_from_slice(&zero);
    lhs.extend_from_slice(&size);
    let mut rhs = size.clone();
    rhs.extend_from_slice(&min);
    rhs.extend_from_slice(&min);
    let c = p.lt(&lhs, &rhs);
    let both = p.mul(&c[..n], &c[n..2 * n]);
    let not_inverted: Vec<A> = c[2 * n..].iter().map(|x| (-*x).add_public(1, id)).collect();
    let valid = p.mul(&both, &not_inverted);
    let valid_open = p.open_a_safe(&valid)?;
    for k in 0..n {
        rejected[k] |= !cfg!(feature = "plant-skip-order-check") && valid_open[k] != 1;
    }

    for (o, &r) in orders.iter_mut().zip(&rejected) {
        if r {
            *o = dummy(symbol_bits, id);
        }
    }
    Ok(rejected)
}

fn dummy_stage2(symbol_bits: usize, id: usize) -> SharedLimitOrder {
    // Size 0 trades nothing. Limit 1 is the lowest price, where supply is
    // only real sells at 1, so the extra candidate price cannot win unless
    // price 1 is already a real candidate.
    let mut limit_bits = vec![A::public(0, id); PRICE_BITS];
    limit_bits[0] = A::public(1, id);
    SharedLimitOrder {
        symbol_bits: vec![A::public(0, id); symbol_bits],
        side: A::public(0, id),
        size: A::public(0, id),
        limit_bits,
    }
}

/// Stage 2 version of [`validate_inputs`]: consistency; symbol, side and
/// limit bits are 0/1 (so the limit is below 2^20); size below 2^40; and
/// size >= 1 and limit >= 1. Only values that are public constants for an
/// honest order are opened.
pub fn validate_stage2_inputs(
    p: &mut Party,
    orders: &mut [SharedLimitOrder],
    symbol_bits: usize,
) -> Result<Vec<bool>, Abort> {
    let n = orders.len();
    let id = p.id;
    let bit_words = |o: &SharedLimitOrder| -> Vec<A> {
        o.symbol_bits.iter().chain([&o.side]).chain(&o.limit_bits).copied().collect()
    };
    let all: Vec<Vec<A>> = orders.iter().map(|o| [bit_words(o), vec![o.size]].concat()).collect();
    let mut rejected = consistency(p, &all)?;
    for (o, &r) in orders.iter_mut().zip(&rejected) {
        if r {
            *o = dummy_stage2(symbol_bits, id);
        }
    }

    let bits: Vec<A> = orders.iter().flat_map(bit_words).collect();
    let sq = p.mul(&bits, &bits);
    let t: Vec<A> = bits.iter().zip(&sq).map(|(b, s)| *b - *s).collect();
    let sizes: Vec<A> = orders.iter().map(|o| o.size).collect();
    let high: Vec<_> = p.decompose(&sizes).into_iter().map(|b| b.mask(HIGH_MASK)).collect();
    let t_open = p.open_a_safe(&t)?;
    let high_open = p.open_b_safe(&high)?;
    let per = symbol_bits + 1 + PRICE_BITS;
    for k in 0..n {
        let bad_bits =
            !cfg!(feature = "plant-skip-bit-check") && t_open[k * per..(k + 1) * per].iter().any(|&v| v != 0);
        let bad_range = !cfg!(feature = "plant-skip-range-check") && high_open[k] != 0;
        rejected[k] |= bad_bits || bad_range;
    }

    // [0 < size] [0 < limit], opened (sound now that both are in range).
    let limits: Vec<A> = orders
        .iter()
        .map(|o| o.limit_bits.iter().enumerate().fold(A::default(), |acc, (b, x)| acc + x.scale(1u64 << b)))
        .collect();
    let zero = vec![A::default(); 2 * n];
    let c = p.lt(&zero, &[sizes, limits].concat());
    let valid = p.mul(&c[..n], &c[n..]);
    let valid_open = p.open_a_safe(&valid)?;
    for k in 0..n {
        rejected[k] |= !cfg!(feature = "plant-skip-order-check") && valid_open[k] != 1;
    }
    for (o, &r) in orders.iter_mut().zip(&rejected) {
        if r {
            *o = dummy_stage2(symbol_bits, id);
        }
    }
    Ok(rejected)
}
