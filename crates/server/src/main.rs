//! darkmpc-server: run the three servers as separate processes.
//!
//!   darkmpc-server setup --dir D
//!       Create a deployment CA and one certificate per server.
//!   darkmpc-server deal --dir D --orders N [--symbols U] [--symbol-bits B] [--seed S]
//!       Generate a random batch, write it in the clear (orders.txt, for
//!       checking only) and as three share files (one per server).
//!   darkmpc-server run --dir D --id I --addrs A0,A1,A2 [--passes K] [--rtt-ms R --mbps M]
//!       Run server I. Connects to the other two over mutually authenticated
//!       TLS, agrees PRF keys, runs the auction, writes its fill shares.
//!   darkmpc-server check --dir D [--passes K]
//!       Reconstruct fills from the three outputs, compare with the reference
//!       matcher, and print the measurements.
//!
//! With `--stage2` on deal, run and check, the batch is limit orders and the
//! Stage 2 auction runs instead; each order's output is (fill, price).
//!
//! The `deal` step stands in for the traders: in deployment each trader
//! shares its own orders. Research prototype, not audited.

mod tls;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use darkmpc_auction::{
    Params, SharedLimitOrder, SharedOrder, Stage2Params, run_auction, run_stage2, share_limit_orders, share_orders,
};
use darkmpc_mpc::{A, NetModel, Party, reconstruct_a};
use darkmpc_reference::{LimitOrder, Order, Passes, Side, match_batch, match_stage2};

struct Args(Vec<String>);

impl Args {
    fn get(&self, name: &str) -> Option<&str> {
        self.0.iter().position(|a| a == name).and_then(|i| self.0.get(i + 1)).map(String::as_str)
    }
    fn num<T: std::str::FromStr>(&self, name: &str, default: T) -> T {
        self.get(name).map(|v| v.parse().unwrap_or_else(|_| panic!("bad value for {name}"))).unwrap_or(default)
    }
    fn dir(&self) -> PathBuf {
        PathBuf::from(self.get("--dir").expect("--dir is required"))
    }
}

fn main() {
    let raw: Vec<String> = std::env::args().collect();
    let args = Args(raw.clone());
    match raw.get(1).map(String::as_str) {
        Some("setup") => tls::setup(&args.dir()),
        Some("deal") => deal(&args),
        Some("run") => run(&args),
        Some("check") => check(&args),
        _ => {
            eprintln!("usage: darkmpc-server setup|deal|run|check --dir D ... (see source header)");
            std::process::exit(2);
        }
    }
}

// ----- files -----

fn write_words(path: &Path, words: &[u64]) {
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    fs::write(path, bytes).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

fn read_words(path: &Path) -> Vec<u64> {
    let bytes = fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    bytes.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect()
}

fn push_share(out: &mut Vec<u64>, a: A) {
    out.push(a.s0);
    out.push(a.s1);
}

/// Share file: [n, symbol_bits, then per order: symbol bits, side, size, min_fill as (s0, s1) pairs].
fn encode_view(view: &[SharedOrder], symbol_bits: usize) -> Vec<u64> {
    let mut w = vec![view.len() as u64, symbol_bits as u64];
    for o in view {
        for b in &o.symbol_bits {
            push_share(&mut w, *b);
        }
        push_share(&mut w, o.side);
        push_share(&mut w, o.size);
        push_share(&mut w, o.min_fill);
    }
    w
}

fn decode_view(w: &[u64]) -> (Vec<SharedOrder>, usize) {
    let (n, bits) = (w[0] as usize, w[1] as usize);
    let mut it = w[2..].chunks_exact(2).map(|c| A { s0: c[0], s1: c[1] });
    let view = (0..n)
        .map(|_| {
            let symbol_bits = (0..bits).map(|_| it.next().unwrap()).collect();
            SharedOrder {
                symbol_bits,
                side: it.next().unwrap(),
                size: it.next().unwrap(),
                min_fill: it.next().unwrap(),
            }
        })
        .collect();
    (view, bits)
}

/// Stage 2 share file: [n, symbol_bits, then per order: symbol bits, side, size, limit bits].
fn encode_view2(view: &[SharedLimitOrder], symbol_bits: usize) -> Vec<u64> {
    let mut w = vec![view.len() as u64, symbol_bits as u64];
    for o in view {
        for b in &o.symbol_bits {
            push_share(&mut w, *b);
        }
        push_share(&mut w, o.side);
        push_share(&mut w, o.size);
        for b in &o.limit_bits {
            push_share(&mut w, *b);
        }
    }
    w
}

fn decode_view2(w: &[u64]) -> (Vec<SharedLimitOrder>, usize) {
    let (n, bits) = (w[0] as usize, w[1] as usize);
    let mut it = w[2..].chunks_exact(2).map(|c| A { s0: c[0], s1: c[1] });
    let view = (0..n)
        .map(|_| SharedLimitOrder {
            symbol_bits: (0..bits).map(|_| it.next().unwrap()).collect(),
            side: it.next().unwrap(),
            size: it.next().unwrap(),
            limit_bits: (0..darkmpc_auction::PRICE_BITS).map(|_| it.next().unwrap()).collect(),
        })
        .collect();
    (view, bits)
}

fn raw_flag(args: &Args, name: &str) -> bool {
    args.0.iter().any(|a| a == name)
}

fn os_random() -> u64 {
    getrandom::u64().expect("OS randomness unavailable")
}

// ----- deal -----

fn deal(args: &Args) {
    let dir = args.dir();
    let n: usize = args.num("--orders", 1000);
    let bits: usize = args.num("--symbol-bits", 13);
    let symbols: u64 = args.num("--symbols", 1u64 << bits);
    let mut s: u64 = args.num("--seed", 1);
    assert!(symbols >= 1 && symbols <= 1 << bits, "--symbols must fit in --symbol-bits");
    let mut r = move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    fs::create_dir_all(&dir).unwrap();
    if raw_flag(args, "--stage2") {
        // Limits within +-50 ticks of 10,000 so books cross.
        let orders: Vec<LimitOrder> = (0..n)
            .map(|_| {
                let size = 1 + r() % 10_000;
                let side = if r() & 1 == 0 { Side::Buy } else { Side::Sell };
                LimitOrder { symbol: (r() % symbols) as u32, side, size, limit: 9_950 + r() % 101 }
            })
            .collect();
        let text: String = orders
            .iter()
            .map(|o| format!("{} {} {} {}\n", o.symbol, matches!(o.side, Side::Sell) as u8, o.size, o.limit))
            .collect();
        fs::write(dir.join("limit_orders.txt"), text).unwrap();
        let views = share_limit_orders(&orders, bits, os_random);
        for (i, v) in views.iter().enumerate() {
            write_words(&dir.join(format!("shares{i}.bin")), &encode_view2(v, bits));
        }
        println!("dealt {n} limit orders over {symbols} symbols ({bits}-bit field) into {}", dir.display());
        return;
    }
    let orders: Vec<Order> = (0..n)
        .map(|_| {
            let size = 1 + r() % 10_000;
            let side = if r() & 1 == 0 { Side::Buy } else { Side::Sell };
            Order { symbol: (r() % symbols) as u32, side, size, min_fill: 1 + r() % size }
        })
        .collect();
    let text: String = orders
        .iter()
        .map(|o| format!("{} {} {} {}\n", o.symbol, matches!(o.side, Side::Sell) as u8, o.size, o.min_fill))
        .collect();
    fs::write(dir.join("orders.txt"), text).unwrap();
    let views = share_orders(&orders, bits, os_random);
    for (i, v) in views.iter().enumerate() {
        write_words(&dir.join(format!("shares{i}.bin")), &encode_view(v, bits));
    }
    println!("dealt {n} orders over {symbols} symbols ({bits}-bit field) into {}", dir.display());
}

fn read_orders(dir: &Path) -> Vec<Order> {
    fs::read_to_string(dir.join("orders.txt"))
        .unwrap()
        .lines()
        .map(|l| {
            let f: Vec<u64> = l.split_whitespace().map(|x| x.parse().unwrap()).collect();
            Order {
                symbol: f[0] as u32,
                side: if f[1] == 1 { Side::Sell } else { Side::Buy },
                size: f[2],
                min_fill: f[3],
            }
        })
        .collect()
}

// ----- run -----

fn run(args: &Args) {
    let dir = args.dir();
    let id: usize = args.num("--id", usize::MAX);
    assert!(id < 3, "--id must be 0, 1 or 2");
    let addrs: Vec<String> = args.get("--addrs").expect("--addrs A0,A1,A2").split(',').map(String::from).collect();
    assert_eq!(addrs.len(), 3);
    let passes: u32 = args.num("--passes", 3);
    let model = args.get("--rtt-ms").map(|_| {
        let rtt = Duration::from_secs_f64(args.num::<f64>("--rtt-ms", 0.0) / 1000.0);
        NetModel::new(rtt, args.num("--mbps", f64::INFINITY))
    });

    let t_setup = Instant::now();
    let links = tls::connect(&dir, id, &addrs);
    let (net, k_own, k_next, writers) = tls::into_net(links, model);
    let mut party = Party::new(id, &k_own, &k_next, net);
    party.checksum_copies = raw_flag(args, "--checksum-copies");
    let setup_secs = t_setup.elapsed().as_secs_f64();

    let words = read_words(&dir.join(format!("shares{id}.bin")));
    let malicious = raw_flag(args, "--malicious");
    let validate = malicious || raw_flag(args, "--validate");
    let stage2 = raw_flag(args, "--stage2");
    let t = Instant::now();
    let (n_orders, result) = if stage2 {
        let (view, bits) = decode_view2(&words);
        let params = Stage2Params { symbol_bits: bits, malicious, validate };
        (view.len(), run_stage2(&mut party, &view, params).map(|o| (o.fill, Some(o.price))))
    } else {
        let (view, bits) = decode_view(&words);
        let params = Params { symbol_bits: bits, passes, malicious, validate };
        (view.len(), run_auction(&mut party, &view, params).map(|f| (f, None)))
    };
    let (fills, prices) = match result {
        Ok(r) => r,
        Err(e) => {
            eprintln!("server {id}: {e}");
            std::process::exit(3);
        }
    };
    let secs = t.elapsed().as_secs_f64();

    let mut out = Vec::new();
    for (k, f) in fills.iter().enumerate() {
        push_share(&mut out, *f);
        if let Some(p) = &prices {
            push_share(&mut out, p[k]);
        }
    }
    write_words(&dir.join(format!("fills{id}.bin")), &out);
    let st = party.net.stats.clone();
    // Barrier: nobody closes until both peers have finished reading.
    party.net.send_next(Vec::new());
    party.net.send_prev(Vec::new());
    party.net.recv_next();
    party.net.recv_prev();
    drop(party); // closes the send queues so the writer threads finish
    for w in writers {
        w.join().expect("writer thread panicked");
    }
    let summary = format!(
        "server={id} stage={} orders={n_orders} passes={passes} malicious={malicious} model={} rounds={} bytes_sent={} auction_secs={secs:.4} setup_secs={setup_secs:.4}\n",
        if stage2 { 2 } else { 1 },
        model.map_or("none".into(), |m| format!("rtt={:?},bytes_per_s={:.0}", m.one_way_latency * 2, m.bandwidth)),
        st.rounds,
        st.bytes_sent,
    );
    fs::write(dir.join(format!("stats{id}.txt")), &summary).unwrap();
    print!("{summary}");
}

// ----- check -----

fn check(args: &Args) {
    let dir = args.dir();
    let passes: u32 = args.num("--passes", 3);
    if raw_flag(args, "--stage2") {
        check_stage2(&dir);
        return;
    }
    let orders = read_orders(&dir);
    let parts: Vec<Vec<u64>> = (0..3).map(|i| read_words(&dir.join(format!("fills{i}.bin")))).collect();
    let mut fills = Vec::with_capacity(orders.len());
    for k in 0..orders.len() {
        let v = [0, 1, 2].map(|i| A { s0: parts[i][2 * k], s1: parts[i][2 * k + 1] });
        fills.push(reconstruct_a(v).expect("inconsistent fill shares"));
    }
    let want = match_batch(&orders, darkmpc_reference::Params { passes: Passes::Fixed(passes) }).unwrap();
    let ok = fills == want;
    for i in 0..3 {
        print!("{}", fs::read_to_string(dir.join(format!("stats{i}.txt"))).unwrap_or_default());
    }
    let matched: u64 = fills.iter().sum::<u64>() / 2;
    println!(
        "fills match reference: {ok} ({} orders, {} filled, matched volume {matched})",
        orders.len(),
        fills.iter().filter(|&&f| f > 0).count()
    );
    if !ok {
        std::process::exit(1);
    }
}

fn check_stage2(dir: &Path) {
    let orders: Vec<LimitOrder> = fs::read_to_string(dir.join("limit_orders.txt"))
        .unwrap()
        .lines()
        .map(|l| {
            let f: Vec<u64> = l.split_whitespace().map(|x| x.parse().unwrap()).collect();
            let side = if f[1] == 1 { Side::Sell } else { Side::Buy };
            LimitOrder { symbol: f[0] as u32, side, size: f[2], limit: f[3] }
        })
        .collect();
    let parts: Vec<Vec<u64>> = (0..3).map(|i| read_words(&dir.join(format!("fills{i}.bin")))).collect();
    let open = |k: usize| {
        let v = [0, 1, 2].map(|i| A { s0: parts[i][2 * k], s1: parts[i][2 * k + 1] });
        reconstruct_a(v).expect("inconsistent output shares")
    };
    let got: Vec<(u64, u64)> = (0..orders.len()).map(|k| (open(2 * k), open(2 * k + 1))).collect();
    let (fills, prices) = match_stage2(&orders).unwrap();
    let want: Vec<(u64, u64)> =
        orders.iter().zip(&fills).map(|(o, &f)| (f, if f > 0 { prices[&o.symbol] } else { 0 })).collect();
    let ok = got == want;
    for i in 0..3 {
        print!("{}", fs::read_to_string(dir.join(format!("stats{i}.txt"))).unwrap_or_default());
    }
    println!(
        "fills and prices match reference: {ok} ({} orders, {} filled, {} symbols traded)",
        orders.len(),
        fills.iter().filter(|&&f| f > 0).count(),
        prices.len()
    );
    if !ok {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_file_roundtrip() {
        let orders = vec![Order::buy(5, 100, 10), Order::sell(7, 3, 3), Order::buy(0, 1, 1)];
        let mut s = 7u64;
        let views = share_orders(&orders, 4, move || {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            s
        });
        for v in &views {
            let (back, bits) = decode_view(&encode_view(v, 4));
            assert_eq!(bits, 4);
            assert_eq!(back.len(), v.len());
            for (a, b) in back.iter().zip(v) {
                assert_eq!(a.symbol_bits, b.symbol_bits);
                assert_eq!((a.side, a.size, a.min_fill), (b.side, b.size, b.min_fill));
            }
        }
    }
    #[test]
    fn stage2_share_file_roundtrip() {
        let orders = vec![LimitOrder::buy(5, 100, 9_999), LimitOrder::sell(7, 3, 1), LimitOrder::buy(0, 1, 1_048_575)];
        let mut s = 9u64;
        let views = share_limit_orders(&orders, 4, move || {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            s
        });
        for v in &views {
            let (back, bits) = decode_view2(&encode_view2(v, 4));
            assert_eq!(bits, 4);
            assert_eq!(back.len(), v.len());
            for (a, b) in back.iter().zip(v) {
                assert_eq!(a.symbol_bits, b.symbol_bits);
                assert_eq!(a.limit_bits, b.limit_bits);
                assert_eq!((a.side, a.size), (b.side, b.size));
            }
        }
    }
}
