//! The Stage 1 mechanism: a periodic call auction with volume matching at the
//! reference midpoint, time priority, and minimum fills.
//!
//! # The mechanism, per symbol
//!
//! 1. Let B be the total size of eligible buys and S of eligible sells.
//!    The matched volume is T = min(B, S).
//! 2. Allocate T to each side by time priority: walking a side in arrival
//!    order, each order takes min(its size, what is left of T).
//! 3. Minimum fills. An eligible order whose fill f satisfies 0 < f < min_fill
//!    is a *violator*. Violators become ineligible and steps 1 and 2 repeat.
//!    One repetition is a *pass*. The process stops at the first pass with no
//!    violators, and that pass's allocation is the result.
//! 4. Pass cap. With [`Passes::Fixed`]`(k)`, at most k passes run. If pass k
//!    still has a violator, the symbol matches nothing this auction (every
//!    fill on it is 0). The fail-safe keeps the guarantee that no order is
//!    ever filled below its minimum. [`Passes::UntilStable`] never needs it.
//!
//! An MPC evaluation cannot loop "until stable" without leaking how many
//! passes ran, so it runs a public number k of passes. The reference
//! implements the capped rule exactly so the two can be compared fill for
//! fill. With k >= (orders on the symbol) + 1 the capped rule equals the
//! uncapped one (each pass removes at least one order or stops).
//!
//! # Why at most one violator per pass
//!
//! On the side with the smaller total every eligible order is filled in full,
//! and a full fill is never a violation because min_fill <= size. On the other
//! side, time priority fills a run of orders in full, then at most one order
//! partially (the *marginal* order), then nothing. Only the marginal order can
//! have 0 < f < min_fill. So each pass removes at most one order, and the
//! tests check this lemma directly.
//!
//! # Two allocation formulas that must agree
//!
//! [`allocate_walk`] is the sequential form used in prior MPC dark pool work:
//! carry a running remainder down each side. It needs one step after another.
//! [`allocate_prefix`] is the form darkmpc will evaluate in MPC: order i on a
//! side gets min(size_i, max(0, T - P_i)), where P_i is the total size of the
//! eligible orders ahead of it on that side. Prefix sums of secret-shared
//! values are local additions, so every fill can be computed at once, in a
//! constant number of communication rounds. The tests require the two forms
//! to be identical.

use std::collections::BTreeMap;

use crate::types::{InvalidInput, Order, Side, validate};

/// How many elimination passes to run per symbol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Passes {
    /// Repeat until a pass has no violator. The mechanism's intended meaning.
    UntilStable,
    /// Run at most k >= 1 passes, then apply the fail-safe. What MPC runs.
    Fixed(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    pub passes: Passes,
}

impl Default for Params {
    fn default() -> Self {
        Params { passes: Passes::UntilStable }
    }
}

/// What happened on one symbol, for tests and diagnostics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymbolTrace {
    pub symbol: u32,
    /// Number of violators found in each pass that ran, in order.
    pub violators_per_pass: Vec<usize>,
    /// True if the pass cap was hit with a violator left, so nothing matched.
    pub fail_safe: bool,
}

/// Matched volume T = min(B, S) over the given (side, size) list.
pub fn matched_volume(book: &[(Side, u64)]) -> u64 {
    let total = |s: Side| -> u64 { book.iter().filter(|(side, _)| *side == s).map(|(_, q)| q).sum() };
    total(Side::Buy).min(total(Side::Sell))
}

/// Sequential form: a running remainder per side, in arrival order.
/// `book` lists the eligible orders of one symbol in arrival order.
pub fn allocate_walk(book: &[(Side, u64)]) -> Vec<u64> {
    let t = matched_volume(book);
    let (mut left_buy, mut left_sell) = (t, t);
    book.iter()
        .map(|&(side, size)| {
            let left = match side {
                Side::Buy => &mut left_buy,
                Side::Sell => &mut left_sell,
            };
            let f = size.min(*left);
            *left -= f;
            f
        })
        .collect()
}

/// Prefix form: fill_i = min(size_i, max(0, T - P_i)), where P_i is the total
/// size ahead of order i on its own side. Each fill depends only on T, P_i and
/// size_i, which is what lets MPC compute all of them in parallel.
pub fn allocate_prefix(book: &[(Side, u64)]) -> Vec<u64> {
    let t = matched_volume(book);
    let (mut ahead_buy, mut ahead_sell) = (0u64, 0u64);
    book.iter()
        .map(|&(side, size)| {
            let ahead = match side {
                Side::Buy => &mut ahead_buy,
                Side::Sell => &mut ahead_sell,
            };
            if cfg!(feature = "plant-prefix-inclusive") {
                // PLANTED BUG: counts the order itself as ahead of itself.
                *ahead += size;
                size.min(t.saturating_sub(*ahead))
            } else {
                let f = size.min(t.saturating_sub(*ahead));
                *ahead += size;
                f
            }
        })
        .collect()
}

fn is_violation(fill: u64, min_fill: u64) -> bool {
    if cfg!(feature = "plant-mes-boundary") {
        // PLANTED BUG: treats a fill exactly at the minimum as too small.
        fill > 0 && fill <= min_fill
    } else {
        fill > 0 && fill < min_fill
    }
}

/// Run the mechanism on one symbol. `members` are batch indices in arrival
/// order. Returns fills aligned with `members`.
fn match_symbol(orders: &[Order], members: &[usize], passes: Passes, symbol: u32) -> (Vec<u64>, SymbolTrace) {
    let n = members.len();
    let cap = match passes {
        Passes::UntilStable => n as u64 + 1,
        Passes::Fixed(k) => {
            assert!(k >= 1, "Passes::Fixed needs k >= 1");
            u64::from(k)
        }
    };
    let mut eligible = vec![true; n];
    let mut trace = SymbolTrace { symbol, violators_per_pass: Vec::new(), fail_safe: false };

    for _ in 0..cap {
        let slots: Vec<usize> = (0..n).filter(|&j| eligible[j]).collect();
        let book: Vec<(Side, u64)> = slots
            .iter()
            .map(|&j| {
                let o = &orders[members[j]];
                (o.side, o.size)
            })
            .collect();
        let alloc = allocate_prefix(&book);

        let mut fills = vec![0u64; n];
        let mut violators = Vec::new();
        for (&j, &f) in slots.iter().zip(&alloc) {
            fills[j] = f;
            if is_violation(f, orders[members[j]].min_fill) {
                violators.push(j);
            }
        }
        trace.violators_per_pass.push(violators.len());

        if violators.is_empty() || cfg!(feature = "plant-skip-elimination") {
            return (fills, trace);
        }
        for j in violators {
            eligible[j] = false;
        }
    }

    assert!(matches!(passes, Passes::Fixed(_)), "UntilStable must converge within n + 1 passes");
    trace.fail_safe = true;
    (vec![0; n], trace)
}

/// Group batch indices by symbol, keeping arrival order inside each group.
fn by_symbol(orders: &[Order]) -> BTreeMap<u32, Vec<usize>> {
    let mut groups: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    for (i, o) in orders.iter().enumerate() {
        groups.entry(o.symbol).or_default().push(i);
    }
    groups
}

/// Match a batch. Returns one fill per order, aligned with the input.
pub fn match_batch(orders: &[Order], params: Params) -> Result<Vec<u64>, InvalidInput> {
    match_batch_traced(orders, params).map(|(fills, _)| fills)
}

/// Like [`match_batch`], also returning a per-symbol trace (symbols ascending).
pub fn match_batch_traced(orders: &[Order], params: Params) -> Result<(Vec<u64>, Vec<SymbolTrace>), InvalidInput> {
    validate(orders)?;
    let mut fills = vec![0u64; orders.len()];
    let mut traces = Vec::new();
    for (symbol, members) in by_symbol(orders) {
        let (f, t) = match_symbol(orders, &members, params.passes, symbol);
        for (&i, &q) in members.iter().zip(&f) {
            fills[i] = q;
        }
        traces.push(t);
    }
    Ok((fills, traces))
}
