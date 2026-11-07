//! Hand-worked cases. Each expected answer is computed by hand in the comment
//! above it, not by running the code.

use darkmpc_reference::*;

fn run(orders: &[Order]) -> Vec<u64> {
    match_batch(orders, Params::default()).unwrap()
}

fn passes_of(orders: &[Order], passes: Passes) -> (Vec<u64>, Vec<SymbolTrace>) {
    match_batch_traced(orders, Params { passes }).unwrap()
}

/// The worked example of Cartlidge, Smart and Talibi Alaoui, "MPC Joins the
/// Dark Side" (AsiaCCS 2019), Sec. 4.3: sells (3, 4, 5), buys (5, 2, 11, 1).
/// S = 12, B = 19, T = 12. Every sell fills; buys get 5, 2, 5, 0.
#[test]
fn prior_work_volume_match_example() {
    let o = [
        Order::sell(0, 3, 1),
        Order::sell(0, 4, 1),
        Order::sell(0, 5, 1),
        Order::buy(0, 5, 1),
        Order::buy(0, 2, 1),
        Order::buy(0, 11, 1),
        Order::buy(0, 1, 1),
    ];
    assert_eq!(run(&o), vec![3, 4, 5, 5, 2, 5, 0]);
}

#[test]
fn empty_batch() {
    assert_eq!(run(&[]), Vec::<u64>::new());
}

/// Only one side present: T = min(B, 0) = 0.
#[test]
fn empty_side_matches_nothing() {
    let o = [Order::sell(7, 10, 1), Order::sell(7, 20, 5)];
    assert_eq!(run(&o), vec![0, 0]);
    let o = [Order::buy(7, 10, 1)];
    assert_eq!(run(&o), vec![0]);
}

/// B = S: both sides fill completely, no marginal order.
#[test]
fn balanced_book_fills_everything() {
    let o = [Order::buy(1, 6, 6), Order::sell(1, 2, 2), Order::buy(1, 4, 4), Order::sell(1, 8, 8)];
    assert_eq!(run(&o), vec![6, 2, 4, 8]);
}

/// Buy 10 with minimum 4 against a lone sell of 4. T = 4, the buy fills
/// exactly its minimum, which is allowed (the rule is fill < min_fill).
#[test]
fn fill_exactly_at_minimum_stands() {
    let o = [Order::buy(0, 10, 4), Order::sell(0, 4, 1)];
    assert_eq!(run(&o), vec![4, 4]);
}

/// Buys 6 (min 1), 10 (min 5); sell 9.
/// Pass 1: T = 9, buys get 6 and 3; 3 < 5 so the second buy is removed.
/// Pass 2: B = 6, T = 6, buy 6, sell 6. No violator.
#[test]
fn marginal_order_below_minimum_is_removed() {
    let o = [Order::buy(0, 6, 1), Order::buy(0, 10, 5), Order::sell(0, 9, 1)];
    let (fills, traces) = passes_of(&o, Passes::UntilStable);
    assert_eq!(fills, vec![6, 0, 6]);
    assert_eq!(traces[0].violators_per_pass, vec![1, 0]);
}

/// Buy 100 all-or-none against 90 of sells: nothing can trade.
/// Pass 1: T = 90, buy gets 90 < 100, removed. Pass 2: B = 0, T = 0.
#[test]
fn all_or_none_buy_too_big() {
    let o = [Order::buy(0, 100, 100), Order::sell(0, 60, 60), Order::sell(0, 30, 1)];
    assert_eq!(run(&o), vec![0, 0, 0]);
}

/// Elimination alternates sides.
/// Buys b1 = 50 (min 1), b2 = 40 (min 40); sells s1 = 30 (min 1),
/// s2 = 40 (min 35), s3 = 5 (min 1).
/// Pass 1: B = 90, S = 75, T = 75. Buys 50, 25: b2 violates.
/// Pass 2: B = 50, T = 50. Sells 30, 20, 0: s2 violates.
/// Pass 3: S = 35, T = 35. b1 gets 35, s1 30, s3 5. No violator.
fn three_pass_book() -> Vec<Order> {
    vec![
        Order::buy(0, 50, 1),
        Order::buy(0, 40, 40),
        Order::sell(0, 30, 1),
        Order::sell(0, 40, 35),
        Order::sell(0, 5, 1),
    ]
}

#[test]
fn elimination_can_alternate_sides() {
    let (fills, traces) = passes_of(&three_pass_book(), Passes::UntilStable);
    assert_eq!(fills, vec![35, 0, 30, 0, 5]);
    assert_eq!(traces[0].violators_per_pass, vec![1, 1, 0]);
    assert!(!traces[0].fail_safe);
}

/// The same book with a cap of 2 passes: pass 2 still has a violator, so the
/// fail-safe applies and the symbol matches nothing. A cap of 3 is enough.
#[test]
fn pass_cap_fail_safe() {
    let (fills, traces) = passes_of(&three_pass_book(), Passes::Fixed(2));
    assert_eq!(fills, vec![0; 5]);
    assert!(traces[0].fail_safe);
    let (fills, _) = passes_of(&three_pass_book(), Passes::Fixed(3));
    assert_eq!(fills, vec![35, 0, 30, 0, 5]);
}

/// Two interleaved symbols are matched independently.
/// Symbol 1: buy 5 vs sell 3 -> 3, 3. Symbol 2: sell 4 vs buys 1, 1 -> 2, 1, 1.
#[test]
fn symbols_are_independent() {
    let o = [Order::buy(1, 5, 1), Order::sell(2, 4, 1), Order::buy(2, 1, 1), Order::sell(1, 3, 1), Order::buy(2, 1, 1)];
    assert_eq!(run(&o), vec![3, 2, 1, 3, 1]);
}

/// Equal sizes on one side: arrival order alone breaks the tie.
/// Buys 5, 5, 5 against sell 7: 5, 2, 0.
#[test]
fn ties_broken_by_arrival() {
    let o = [Order::buy(0, 5, 1), Order::buy(0, 5, 1), Order::buy(0, 5, 1), Order::sell(0, 7, 1)];
    assert_eq!(run(&o), vec![5, 2, 0, 7]);
}

/// Largest legal sizes in a large batch: sums reach about 2^56 without overflow.
#[test]
fn maximum_sizes_do_not_overflow() {
    let mut o = vec![Order::buy(0, MAX_SIZE, 1); 40_000];
    o.extend(vec![Order::sell(0, MAX_SIZE, MAX_SIZE); 39_999]);
    let fills = run(&o);
    let buys: u64 = fills[..40_000].iter().sum();
    let sells: u64 = fills[40_000..].iter().sum();
    assert_eq!(buys, sells);
    assert_eq!(sells, 39_999 * MAX_SIZE);
    assert_eq!(fills[39_999], 0, "last buy is behind the matched volume");
}

#[test]
fn rejects_out_of_range_inputs() {
    let p = Params::default();
    assert!(matches!(match_batch(&[Order::buy(0, 0, 1)], p), Err(InvalidInput::SizeOutOfRange { .. })));
    assert!(matches!(match_batch(&[Order::buy(0, MAX_SIZE + 1, 1)], p), Err(InvalidInput::SizeOutOfRange { .. })));
    assert!(matches!(match_batch(&[Order::buy(0, 5, 0)], p), Err(InvalidInput::MinFillOutOfRange { .. })));
    assert!(matches!(match_batch(&[Order::buy(0, 5, 6)], p), Err(InvalidInput::MinFillOutOfRange { .. })));
    let too_many = vec![Order::buy(0, 1, 1); MAX_BATCH + 1];
    assert!(matches!(match_batch(&too_many, p), Err(InvalidInput::BatchTooLarge { .. })));
    let just_right = vec![Order::buy(0, 1, 1); MAX_BATCH];
    assert!(match_batch(&just_right, p).is_ok());
}
