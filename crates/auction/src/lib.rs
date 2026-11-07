//! The dark pool auctions in three-party MPC: Stage 1 (sizes and minimum
//! fills, this file) and Stage 2 (limit prices, [`stage2`]).
//!
//! Computes exactly what `darkmpc_reference::match_batch` computes with
//! `Passes::Fixed(k)`, on secret-shared orders whose symbol and side are
//! hidden from every server. See docs/design/stage1-mpc.md for the design.
//!
//! With `malicious` or `validate`, traders' inputs are validated on shares
//! first ([`validate`]).
//!
//! Research prototype, not audited.

use darkmpc_mpc::{A, Abort, Party, share_a};
use darkmpc_reference::{Order, Side};

pub mod stage2;
pub mod validate;
pub use stage2::{PRICE_BITS, SharedLimitOrder, Stage2Params, Stage2Shares, run_stage2, share_limit_orders};
pub use validate::{validate_inputs, validate_stage2_inputs};

/// Public parameters of an auction.
#[derive(Clone, Copy, Debug)]
pub struct Params {
    /// Width of the symbol field: symbols are 0..2^symbol_bits.
    pub symbol_bits: usize,
    /// Number of minimum-fill elimination passes (public).
    pub passes: u32,
    /// Malicious security with abort: every multiplication, AND gate,
    /// opening and shuffle is verified (Milestones 4a and 4b).
    pub malicious: bool,
    /// Validate traders' inputs on shares before matching (always on in
    /// malicious mode). Rejected orders become zero-size dummies.
    pub validate: bool,
}

/// One server's view of one order.
#[derive(Clone, Debug)]
pub struct SharedOrder {
    /// Symbol bits, least significant first, each a shared 0/1.
    pub symbol_bits: Vec<A>,
    /// Shared 0 (buy) or 1 (sell).
    pub side: A,
    pub size: A,
    pub min_fill: A,
}

/// Client side: secret-share a batch of orders for the three servers.
/// `rand` must be a cryptographic source outside tests.
pub fn share_orders(orders: &[Order], symbol_bits: usize, mut rand: impl FnMut() -> u64) -> [Vec<SharedOrder>; 3] {
    let mut out: [Vec<SharedOrder>; 3] = Default::default();
    for o in orders {
        assert!(symbol_bits == 64 || u64::from(o.symbol) < (1u64 << symbol_bits), "symbol out of range");
        let bits: Vec<[A; 3]> = (0..symbol_bits).map(|b| share_a((u64::from(o.symbol) >> b) & 1, &mut rand)).collect();
        let side = share_a(matches!(o.side, Side::Sell) as u64, &mut rand);
        let size = share_a(o.size, &mut rand);
        let min_fill = share_a(o.min_fill, &mut rand);
        for (i, view) in out.iter_mut().enumerate() {
            view.push(SharedOrder {
                symbol_bits: bits.iter().map(|b| b[i]).collect(),
                side: side[i],
                size: size[i],
                min_fill: min_fill[i],
            });
        }
    }
    out
}

fn sub(a: &[A], b: &[A]) -> Vec<A> {
    a.iter().zip(b).map(|(x, y)| *x - *y).collect()
}

/// Run the auction as one server. Returns this server's shares of every
/// order's fill, in the original batch order.
pub fn run_auction(p: &mut Party, orders: &[SharedOrder], params: Params) -> Result<Vec<A>, Abort> {
    let n = orders.len();
    let id = p.id;
    p.malicious = params.malicious;
    if n == 0 {
        return Ok(Vec::new());
    }
    // 0. Validate traders' inputs on shares (always in malicious mode).
    let checked: Vec<SharedOrder>;
    let orders = if params.validate || params.malicious {
        let mut v = orders.to_vec();
        validate_inputs(p, &mut v, params.symbol_bits)?;
        checked = v;
        &checked[..]
    } else {
        orders
    };
    assert!(params.passes >= 1);

    // 1. Stable sort by (symbol, side): side is the least significant key bit,
    //    so within a symbol all buys precede all sells, each in arrival order.
    let mut key_bits: Vec<Vec<A>> = vec![orders.iter().map(|o| o.side).collect()];
    for b in 0..params.symbol_bits {
        key_bits.push(orders.iter().map(|o| o.symbol_bits[b]).collect());
    }
    let symbol: Vec<A> = orders
        .iter()
        .map(|o| o.symbol_bits.iter().enumerate().fold(A::default(), |acc, (b, x)| acc + x.scale(1u64 << b)))
        .collect();
    let mut payload = vec![
        orders.iter().map(|o| o.side).collect::<Vec<A>>(),
        orders.iter().map(|o| o.size).collect(),
        orders.iter().map(|o| o.min_fill).collect(),
        symbol,
    ];
    let origin = p.stable_sort(key_bits, &mut payload)?;
    let (side, size, min_fill, symbol) = (&payload[0], &payload[1], &payload[2], &payload[3]);

    // 2. Symbol boundaries: position t starts a segment iff its symbol is
    //    larger than its predecessor's (the order is non-decreasing).
    let mut starts = vec![A::public(1, id)];
    if n > 1 {
        let later: Vec<A> = symbol[1..].to_vec();
        let earlier: Vec<A> = symbol[..n - 1].to_vec();
        starts.extend(p.lt(&earlier, &later));
    }

    // 3. Elimination passes.
    let zero = vec![A::default(); n];
    let mut eligible: Vec<A> = vec![A::public(1, id); n];
    let mut fill = zero.clone();
    let mut violators = zero.clone();
    for _ in 0..params.passes {
        let esize = p.mul(&eligible, size);
        let sell = p.mul(side, &esize);
        let buy = sub(&esize, &sell);
        let (fwd, tot) = p.segmented_prefix_and_total(&starts, &[buy.clone(), sell.clone()]);
        // Volume ahead on the order's own side within its symbol (exclusive).
        let ahead_buy = sub(&fwd[0], &buy);
        let ahead_sell = sub(&fwd[1], &sell);
        let ahead = p.select(side, &ahead_sell, &ahead_buy);
        // T = min(B, S); fill = min(esize, max(0, T - ahead)).
        let t = p.min(&tot[0], &tot[1]);
        let room = sub(&t, &ahead);
        let room = p.max(&room, &zero);
        fill = p.min(&esize, &room);
        // Violation: 0 < fill < min_fill. Both comparisons in one batch.
        let mut lhs = zero.clone();
        lhs.extend_from_slice(&fill);
        let mut rhs = fill.clone();
        rhs.extend_from_slice(min_fill);
        let c = p.lt(&lhs, &rhs);
        violators = p.mul(&c[..n], &c[n..]);
        eligible = sub(&eligible, &violators);
    }

    // 4. Fail-safe: a symbol whose last pass still had a violator matches
    //    nothing.
    let count = p.segmented_total(&starts, &[violators])[0].clone();
    let unstable = p.lt(&zero, &count);
    let cut = p.mul(&unstable, &fill);
    let fill = sub(&fill, &cut);

    // 5. Route every fill back to its order's original slot.
    if cfg!(feature = "plant-skip-unsort") {
        return Ok(fill); // PLANTED BUG: fills left in sorted order
    }
    let mut cols = vec![fill];
    p.apply_shared_perm(&origin, &mut cols)?;
    Ok(cols.pop().unwrap())
}
