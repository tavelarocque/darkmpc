//! The Stage 2 auction (limit prices, one uniform clearing price per symbol)
//! in three-party MPC.
//!
//! Computes exactly what `darkmpc_reference::match_stage2` computes, on
//! secret-shared orders whose symbol, side, size and limit are hidden from
//! every server. Each order's output is its fill and, if the fill is
//! positive, its symbol's clearing price (0 otherwise): a filled trader
//! needs the price to settle, and nobody else learns it. See
//! docs/design/stage2-mpc.md.
//!
//! Outline, all on shares, after sorting by (symbol, limit):
//!
//! * **Runs** are blocks of equal (symbol, limit). Over one symbol, demand
//!   D(p) and supply S(p) at an order's own limit are sums over the symbol
//!   and over its run, so two segmentations of one scan give both.
//! * **Two candidates per symbol** (see `clearing_price_by_crossing` in the
//!   reference): A, the first position with S >= D; B, the first position of
//!   the block of unchanged (D, S) that holds the last position with S < D.
//!   Since D falls and S rises along the symbol, "(D, S) changed" is the
//!   single comparison 0 < (D_prev - D) + (S - S_prev).
//! * **Pick** B over A iff it has more volume, or equal volume and no more
//!   surplus (B is the lower price, so it wins a full tie).
//! * **Allocate** at p* by price then time. Sells are already in priority
//!   order (ascending limit, then arrival). For a buy, the volume ahead is
//!   the eligible buys at higher limits (later runs) plus those earlier in
//!   its own run, which again is symbol sums minus run sums: no second sort.
//!
//! Research prototype, not audited.

use darkmpc_mpc::{A, Abort, Party, share_a};
use darkmpc_reference::{LimitOrder, MAX_PRICE, Side};

use crate::validate::validate_stage2_inputs;

/// Limit prices are shared as this many bits (MAX_PRICE = 2^20 - 1).
pub const PRICE_BITS: usize = 20;
const _: () = assert!(MAX_PRICE == (1 << PRICE_BITS) - 1);

/// Public parameters of a Stage 2 auction.
#[derive(Clone, Copy, Debug)]
pub struct Stage2Params {
    pub symbol_bits: usize,
    pub malicious: bool,
    pub validate: bool,
}

/// One server's view of one limit order.
#[derive(Clone, Debug)]
pub struct SharedLimitOrder {
    /// Symbol bits, least significant first, each a shared 0/1.
    pub symbol_bits: Vec<A>,
    /// Shared 0 (buy) or 1 (sell).
    pub side: A,
    pub size: A,
    /// Limit price bits, least significant first, each a shared 0/1.
    pub limit_bits: Vec<A>,
}

/// One server's shares of the Stage 2 result, in the original batch order.
#[derive(Clone, Debug)]
pub struct Stage2Shares {
    pub fill: Vec<A>,
    /// The clearing price where fill > 0, else 0.
    pub price: Vec<A>,
}

/// Client side: secret-share a batch of limit orders for the three servers.
pub fn share_limit_orders(
    orders: &[LimitOrder],
    symbol_bits: usize,
    mut rand: impl FnMut() -> u64,
) -> [Vec<SharedLimitOrder>; 3] {
    let mut out: [Vec<SharedLimitOrder>; 3] = Default::default();
    for o in orders {
        assert!(symbol_bits == 64 || u64::from(o.symbol) < (1u64 << symbol_bits), "symbol out of range");
        assert!(o.limit <= MAX_PRICE, "limit out of range");
        let sym: Vec<[A; 3]> = (0..symbol_bits).map(|b| share_a((u64::from(o.symbol) >> b) & 1, &mut rand)).collect();
        let lim: Vec<[A; 3]> = (0..PRICE_BITS).map(|b| share_a((o.limit >> b) & 1, &mut rand)).collect();
        let side = share_a(matches!(o.side, Side::Sell) as u64, &mut rand);
        let size = share_a(o.size, &mut rand);
        for (i, view) in out.iter_mut().enumerate() {
            view.push(SharedLimitOrder {
                symbol_bits: sym.iter().map(|b| b[i]).collect(),
                side: side[i],
                size: size[i],
                limit_bits: lim.iter().map(|b| b[i]).collect(),
            });
        }
    }
    out
}

fn sub(a: &[A], b: &[A]) -> Vec<A> {
    a.iter().zip(b).map(|(x, y)| *x - *y).collect()
}

fn add(a: &[A], b: &[A]) -> Vec<A> {
    a.iter().zip(b).map(|(x, y)| *x + *y).collect()
}

fn one_minus(a: &[A], id: usize) -> Vec<A> {
    a.iter().map(|x| (-*x).add_public(1, id)).collect()
}

fn from_bits(bits: &[A]) -> A {
    bits.iter().enumerate().fold(A::default(), |acc, (b, x)| acc + x.scale(1u64 << b))
}

/// Run the Stage 2 auction as one server.
pub fn run_stage2(p: &mut Party, orders: &[SharedLimitOrder], params: Stage2Params) -> Result<Stage2Shares, Abort> {
    let n = orders.len();
    let id = p.id;
    p.malicious = params.malicious;
    if n == 0 {
        return Ok(Stage2Shares { fill: Vec::new(), price: Vec::new() });
    }
    let checked: Vec<SharedLimitOrder>;
    let orders = if params.validate || params.malicious {
        let mut v = orders.to_vec();
        validate_stage2_inputs(p, &mut v, params.symbol_bits)?;
        checked = v;
        &checked[..]
    } else {
        orders
    };

    // 1. Stable sort by (symbol, limit); within a run, arrival order.
    let mut key_bits: Vec<Vec<A>> = Vec::with_capacity(PRICE_BITS + params.symbol_bits);
    for b in 0..PRICE_BITS {
        key_bits.push(orders.iter().map(|o| o.limit_bits[b]).collect());
    }
    for b in 0..params.symbol_bits {
        key_bits.push(orders.iter().map(|o| o.symbol_bits[b]).collect());
    }
    let mut payload = vec![
        orders.iter().map(|o| o.side).collect::<Vec<A>>(),
        orders.iter().map(|o| o.size).collect(),
        orders.iter().map(|o| from_bits(&o.limit_bits)).collect(),
        orders.iter().map(|o| from_bits(&o.symbol_bits)).collect(),
    ];
    let origin = p.stable_sort(key_bits, &mut payload)?;
    let (side, size, lim, sym) = (&payload[0], &payload[1], &payload[2], &payload[3]);

    // 2. Run and symbol starts: one batch of comparisons with predecessors.
    let key: Vec<A> = sym.iter().zip(lim).map(|(s, l)| s.scale(1 << PRICE_BITS) + *l).collect();
    let mut run_start = vec![A::public(1, id)];
    let mut sym_start = vec![A::public(1, id)];
    if n > 1 {
        let mut lhs = key[..n - 1].to_vec();
        lhs.extend_from_slice(&sym[..n - 1]);
        let mut rhs = key[1..].to_vec();
        rhs.extend_from_slice(&sym[1..]);
        let c = p.lt(&lhs, &rhs);
        run_start.extend_from_slice(&c[..n - 1]);
        sym_start.extend_from_slice(&c[n - 1..]);
    }

    // 3. Demand and supply at each order's own limit.
    //    D = buys in the symbol from this run on = sym suffix - (run part before t)
    //      = (symtot - symfwd + x) + (runfwd - x);
    //    S = sells in the symbol up to the end of this run
    //      = symfwd + (runtot - runfwd).
    let sell = p.mul(side, size);
    let buy = sub(size, &sell);
    let (sym_scan, run_scan) = scan_two(p, &sym_start, &run_start, &[buy.clone(), sell.clone()]);
    let d: Vec<A> = (0..n).map(|t| sym_scan.1[0][t] - sym_scan.0[0][t] + run_scan.0[0][t]).collect();
    let s: Vec<A> = (0..n).map(|t| sym_scan.0[1][t] + run_scan.1[1][t] - run_scan.0[1][t]).collect();

    // 4. c = [S >= D], and "(D, S) changed since the previous position".
    let zero = vec![A::default(); n];
    let mut lhs = s.clone();
    let mut rhs = d.clone();
    if n > 1 {
        lhs.extend_from_slice(&zero[1..]);
        rhs.extend((1..n).map(|t| (d[t - 1] - d[t]) + (s[t] - s[t - 1])));
    }
    let cmp = p.lt(&lhs, &rhs);
    let c = one_minus(&cmp[..n], id);
    let changed = &cmp[n..];
    let d_minus_s = sub(&d, &s);
    // sym_end[t] = sym_start[t+1]; the last position ends its symbol.
    let not_start = one_minus(&sym_start, id);
    let mut lhs = c.clone(); // c (D - S)
    let mut rhs = d_minus_s.clone();
    lhs.extend_from_slice(&not_start[1..]); // (1 - start_t) c_{t-1}
    rhs.extend_from_slice(&c[..n - 1]);
    lhs.extend_from_slice(&not_start[1..]); // (1 - end_t) (1 - c_{t+1}), t < n-1
    rhs.extend(one_minus(&c[1..], id));
    lhs.extend_from_slice(&not_start[1..]); // (1 - start_t) changed_t
    rhs.extend_from_slice(changed);
    let prod = p.mul(&lhs, &rhs);
    let m = n - 1;
    let cd = &prod[..n];
    let vol: Vec<A> = add(&s, cd); // c ? D : S
    let surplus: Vec<A> = (0..n).map(|t| d_minus_s[t] - cd[t].scale(2)).collect(); // |D - S|
    // Candidate A: first position with S >= D (c is monotone along a symbol).
    let mut cand_a = vec![c[0]];
    cand_a.extend((1..n).map(|t| c[t] - prod[n + t - 1]));
    // L: the last position with S < D.
    let mut last_below: Vec<A> = (0..m).map(|t| (-c[t]).add_public(1, id) - prod[n + m + t]).collect();
    last_below.push((-c[n - 1]).add_public(1, id));
    // Block starts: new symbol, or (D, S) changed.
    let mut block_start = vec![A::public(1, id)];
    block_start.extend((1..n).map(|t| sym_start[t] + prod[n + 2 * m + t - 1]));

    // 5. Candidate B: the first position of the block holding L.
    let cand_b = if cfg!(feature = "plant-stage2-mpc-drop-flat-stretch") {
        last_below // PLANTED BUG: the last S < D price itself, not its flat stretch's first
    } else {
        let in_block = p.segmented_total(&block_start, &[last_below]).pop().unwrap();
        p.mul(&block_start, &in_block)
    };

    // 6. Spread both candidates' (exists, volume, surplus, price) over the symbol.
    let mut lhs = Vec::with_capacity(6 * n);
    let mut rhs = Vec::with_capacity(6 * n);
    for cand in [&cand_a, &cand_b] {
        for v in [&vol, &surplus, lim] {
            lhs.extend_from_slice(cand);
            rhs.extend_from_slice(v);
        }
    }
    let masked = p.mul(&lhs, &rhs);
    let cols: Vec<Vec<A>> = vec![
        cand_a.clone(),
        masked[..n].to_vec(),
        masked[n..2 * n].to_vec(),
        masked[2 * n..3 * n].to_vec(),
        cand_b.clone(),
        masked[3 * n..4 * n].to_vec(),
        masked[4 * n..5 * n].to_vec(),
        masked[5 * n..].to_vec(),
    ];
    let t = p.segmented_total(&sym_start, &cols);
    let (ea, va, sa, pa, eb, vb, sb, pb) = (&t[0], &t[1], &t[2], &t[3], &t[4], &t[5], &t[6], &t[7]);

    // 7. Pick B iff eb and (not ea, or vb > va, or (vb == va and sb <= sa)).
    let lhs = [va.as_slice(), vb, sa].concat();
    let rhs = [vb.as_slice(), va, sb].concat();
    let cmp = p.lt(&lhs, &rhs);
    let (a_less, b_less, sa_less) = (&cmp[..n], &cmp[n..2 * n], &cmp[2 * n..]);
    let tie: Vec<A> = (0..n).map(|t| (-a_less[t] - b_less[t]).add_public(1, id)).collect();
    let prod = p.mul(&[tie, ea.clone()].concat(), &[one_minus(sa_less, id), eb.clone()].concat());
    let b_wins: Vec<A> = add(a_less, &prod[..n]);
    let both = &prod[n..];
    let pick_b_if_both = p.mul(both, &b_wins);
    let pick_b: Vec<A> = (0..n).map(|t| eb[t] - both[t] + pick_b_if_both[t]).collect();
    let prod = p.mul(&[pick_b.clone(), pick_b].concat(), &[sub(pb, pa), sub(vb, va)].concat());
    let price = add(pa, &prod[..n]);
    let volume = add(va, &prod[n..]);
    if cfg!(feature = "plant-stage2-debug-open") {
        // PLANTED LEAK: a stray debugging opening. Results stay correct.
        let _ = p.open_a_safe(&price)?;
    }

    // 8. Eligibility at p*: buys with limit >= p*, sells with limit <= p*.
    let cmp = p.lt(&[lim.as_slice(), &price].concat(), &[price.as_slice(), lim].concat());
    let buy_ok = one_minus(&cmp[..n], id);
    let sell_ok = if cfg!(feature = "plant-stage2-mpc-strict-sell") {
        cmp[..n].to_vec() // PLANTED BUG: sells need limit < p*
    } else {
        one_minus(&cmp[n..], id)
    };
    let e = p.mul(&[buy_ok, sell_ok].concat(), &[buy, sell].concat());
    let (ebuy, esell) = (e[..n].to_vec(), e[n..].to_vec());
    let esize = add(&ebuy, &esell);

    // 9. Volume ahead in priority order.
    let (sym_scan, run_scan) = scan_two(p, &sym_start, &run_start, &[ebuy.clone(), esell.clone()]);
    let ahead_buy: Vec<A> = if cfg!(feature = "plant-stage2-mpc-buy-time-only") {
        sub(&sym_scan.0[0], &ebuy) // PLANTED BUG: buys in arrival order, price ignored
    } else {
        // Later runs of the symbol, plus earlier in this run:
        // (symtot - symfwd) - (runtot - runfwd) + (runfwd - x).
        (0..n)
            .map(|t| sym_scan.1[0][t] - sym_scan.0[0][t] - run_scan.1[0][t] + run_scan.0[0][t].scale(2) - ebuy[t])
            .collect()
    };
    let ahead_sell = sub(&sym_scan.0[1], &esell);
    let ahead = p.select(side, &ahead_sell, &ahead_buy);
    let room = p.max(&sub(&volume, &ahead), &zero);
    let fill = p.min(&esize, &room);

    // 10. Price for filled orders only, then route back to arrival order.
    let filled = p.lt(&zero, &fill);
    let price_out = p.mul(&filled, &price);
    let mut cols = vec![fill, price_out];
    p.apply_shared_perm(&origin, &mut cols)?;
    let price = cols.pop().unwrap();
    let fill = cols.pop().unwrap();
    Ok(Stage2Shares { fill, price })
}

type Scan = (Vec<Vec<A>>, Vec<Vec<A>>);

/// Forward sums and totals over symbols and over runs, in one scan.
fn scan_two(p: &mut Party, sym_start: &[A], run_start: &[A], cols: &[Vec<A>]) -> (Scan, Scan) {
    let mut r = p.segmented_prefix_and_total_multi(&[sym_start, run_start], cols);
    let run = r.pop().unwrap();
    (r.pop().unwrap(), run)
}
