//! Measure one auction: per-server bytes sent, rounds, and wall time with
//! the three servers as threads in one process (no network latency).
//!     cargo run --release -p darkmpc-auction --example cost -- 1024 3
//! Arguments: batch size (default 1024), passes (default 3), and the word
//! `malicious` to run with verification.

use std::time::Instant;

use darkmpc_auction::{Params, run_auction, share_orders};
use darkmpc_mpc::{overall_security_bits, run3};
use darkmpc_reference::{Order, Side};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let n: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1024);
    let k: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(3);
    let mut s = 1u64;
    let mut r = move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    let orders: Vec<Order> = (0..n)
        .map(|_| {
            let size = 1 + r() % 10_000;
            let side = if r() & 1 == 0 { Side::Buy } else { Side::Sell };
            Order { symbol: (r() % 8192) as u32, side, size, min_fill: 1 + r() % size }
        })
        .collect();
    let malicious = args.get(3).is_some_and(|a| a == "malicious");
    let params = Params { symbol_bits: 13, passes: k, malicious, validate: malicious };
    let views = share_orders(&orders, 13, r);
    let start = Instant::now();
    let stats = run3(false, |p| {
        run_auction(p, &views[p.id], params).expect("aborted");
        (p.net.stats.clone(), p.verified_batches)
    });
    let secs = start.elapsed().as_secs_f64();
    let batches = stats[0].1;
    let stats: Vec<_> = stats.into_iter().map(|s| s.0).collect();
    let max_bytes = stats.iter().map(|s| s.bytes_sent).max().unwrap();
    println!(
        "n={n} passes={k} malicious={malicious} rounds={} max_bytes_per_server={} ({:.1} KiB/order) wall={:.3}s{}",
        stats[0].rounds,
        max_bytes,
        max_bytes as f64 / 1024.0 / n as f64,
        secs,
        if malicious {
            format!(" verified_batches={batches} security>={:.1}bits", overall_security_bits(batches))
        } else {
            String::new()
        }
    );
}
