//! Measure Stage 1 and Stage 2 on the same batch size and network, with the
//! three servers as threads in one process. Every result is checked against
//! the reference before it is reported.
//!     cargo run --release -p darkmpc-auction --example stages -- 1024 lan [malicious]
//! Network: none, lan (0.47 ms RTT, 10 Gbit/s) or wan (40 ms RTT, 1 Gbit/s).

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use darkmpc_auction::{Params, Stage2Params, run_auction, run_stage2, share_limit_orders, share_orders};
use darkmpc_mpc::{NetModel, overall_security_bits, run3_model};
use darkmpc_reference::{LimitOrder, Order, Passes, Side, match_batch, match_stage2};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let n: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1024);
    let net = args.get(2).map_or("none", String::as_str);
    let malicious = args.iter().any(|a| a == "malicious");
    let model = match net {
        "lan" => Some(NetModel::new(Duration::from_micros(470), 10_000.0)),
        "wan" => Some(NetModel::new(Duration::from_millis(40), 1_000.0)),
        _ => None,
    };
    let mut s = 1u64;
    let mut r = move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    let bits = 13;
    let raw: Vec<(u32, Side, u64, u64, u64)> = (0..n)
        .map(|_| {
            let size = 1 + r() % 10_000;
            let side = if r() & 1 == 0 { Side::Buy } else { Side::Sell };
            // Limits within +-50 ticks of 10,000 so books cross.
            (((r() % 8192) as u32), side, size, 1 + r() % size, 9_950 + r() % 101)
        })
        .collect();
    let orders1: Vec<Order> =
        raw.iter().map(|&(symbol, side, size, min_fill, _)| Order { symbol, side, size, min_fill }).collect();
    let orders2: Vec<LimitOrder> =
        raw.iter().map(|&(symbol, side, size, _, limit)| LimitOrder { symbol, side, size, limit }).collect();

    // Stage 1
    let views = share_orders(&orders1, bits, &mut r);
    let params = Params { symbol_bits: bits, passes: 3, malicious, validate: malicious };
    let t = Instant::now();
    let out = run3_model(model, false, |p| {
        let f = run_auction(p, &views[p.id], params).expect("aborted");
        let st = (p.net.stats.clone(), p.verified_batches);
        (p.open_a_safe(&f).expect("aborted"), st)
    });
    let secs1 = t.elapsed().as_secs_f64();
    let want1 = match_batch(&orders1, darkmpc_reference::Params { passes: Passes::Fixed(3) }).unwrap();
    assert_eq!(out[0].0, want1, "stage 1 differs from reference");
    report("stage1", n, net, malicious, secs1, &out.map(|o| o.1));

    // Stage 2
    let views = share_limit_orders(&orders2, bits, &mut r);
    let params = Stage2Params { symbol_bits: bits, malicious, validate: malicious };
    let t = Instant::now();
    let out = run3_model(model, false, |p| {
        let o = run_stage2(p, &views[p.id], params).expect("aborted");
        let st = (p.net.stats.clone(), p.verified_batches);
        (p.open_a_safe(&o.fill).expect("aborted"), p.open_a_safe(&o.price).expect("aborted"), st)
    });
    let secs2 = t.elapsed().as_secs_f64();
    let (fills, prices): (Vec<u64>, BTreeMap<u32, u64>) = match_stage2(&orders2).unwrap();
    let want_price: Vec<u64> =
        orders2.iter().zip(&fills).map(|(o, &f)| if f > 0 { prices[&o.symbol] } else { 0 }).collect();
    assert_eq!(out[0].0, fills, "stage 2 fills differ from reference");
    assert_eq!(out[0].1, want_price, "stage 2 prices differ from reference");
    let traded = fills.iter().filter(|&&f| f > 0).count();
    report("stage2", n, net, malicious, secs2, &out.map(|o| o.2));
    println!(
        "  (stage 2: {traded} orders filled over {} traded symbols; both stages match the reference)",
        prices.len()
    );
}

fn report(stage: &str, n: usize, net: &str, malicious: bool, secs: f64, st: &[(darkmpc_mpc::Stats, u64); 3]) {
    // The final opening of the outputs is included in the numbers.
    let bytes = st.iter().map(|s| s.0.bytes_sent).max().unwrap();
    let sec = if malicious { format!(" security>={:.1}bits", overall_security_bits(st[0].1)) } else { String::new() };
    println!(
        "{stage} n={n} net={net} malicious={malicious} rounds={} max_bytes_per_server={bytes} ({:.1} KiB/order) wall={secs:.3}s{sec}",
        st[0].0.rounds,
        bytes as f64 / 1024.0 / n as f64,
    );
}
