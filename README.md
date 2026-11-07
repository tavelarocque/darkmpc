# darkmpc

A dark pool that even its operator cannot see into.

Traders split each order into secret shares and send one to each of three independent servers. The servers run a periodic call auction together using secure three-party computation, and each trader gets back only the shares of its own fills. No single server sees any order, total or fill. Symbols and sides are hidden too, so the servers do not even learn which instruments are being traded.

> **Research prototype. Not audited. Not for real trading.**
>
> - **Honest majority.** Security holds if at most one of the three servers is corrupt. Two colluding servers see everything.
> - **Proofs not reviewed.** Malicious security rests on two extensions of published analyses that are proved by the author ([ring-proofs](docs/design/ring-proofs.md)) and have not been reviewed by an expert. There is no end-to-end simulation proof for malicious mode.
> - **Security with selective abort.** A corrupt server can always stop an auction, and can make one honest server stop while the other waits. No honest server outputs a wrong value.
> - **Public batch size.** The number of orders per batch is revealed; padding is not implemented.
>
> The full list of limits is in the [design report, Section 9](docs/design-report.md#9-limits).

## What it does

**Stage 1: midpoint volume matching with minimum fills.** Every trade in a symbol executes at the public midpoint of the lit market. Matched volume per symbol is the smaller of the buy and sell totals, filled in arrival order. Orders whose fill would fall below their minimum are removed and the allocation repeats, up to a public number of passes.

**Stage 2: uniform-price auction with limits.** One clearing price per symbol, chosen by maximum executable volume, then minimum surplus (the first two criteria of Cboe Europe's Periodic Auctions), then the lowest price. Orders fill by price, then time. A filled order also receives the clearing price; nobody else learns it.

Both run in **semi-honest** mode, or in **malicious** mode with security with abort against an actively cheating server. Malicious mode adds:
- input validation on shares;
- cut-and-choose checks of every multiplication;
- MAC-checked shuffles;
- checked openings.

## Results

Three Google Cloud `n2-standard-2` VMs (one physical core each). Every run was reconstructed and checked against the plain reference matcher. Times are medians of 3.

| | LAN (0.2 ms, 9.3 Gbit/s) | WAN, 3 US regions (27 to 69 ms, 0.75 Gbit/s) |
|---|---|---|
| Stage 1, 1,000 orders, semi-honest | 0.055 s | 7.3 s |
| Stage 1, 100,000 orders, semi-honest | 4.33 s | 23.6 s |
| Stage 1, 1,000 orders, malicious | 0.948 s | 17.1 s |
| Stage 1, 10,000 orders, malicious | 9.88 s | 44.2 s |
| Stage 2, 1,000 orders, malicious | 1.45 s | 25.6 s |

The only published three-party actively secure dark pool (Cartlidge, Smart and Talibi Alaoui, [ePrint 2018/1045](https://eprint.iacr.org/2018/1045), Table 8) reports 0.900 s online plus 4.136 s preprocessing for 1,000 orders on a LAN, with 4,509 rounds. darkmpc takes 0.948 s end to end with 566 rounds, while also hiding symbols and sides, validating inputs and running minimum-fill passes. The two differ in mechanism, network, hardware and software. [docs/benchmarks.md](docs/benchmarks.md) sets out what the comparison does and does not support, and has the full tables.

## How it is checked

- **A reference matcher** in plain Rust defines correct output. Property tests require the MPC output to equal it exactly, on random batches biased towards ties, crossings and boundary values, in both modes and both stages.
- **27 planted bugs** live in the code behind feature flags: wrong shares, cheating servers, skipped input checks, mechanism errors, and leaks that keep every output correct. `scripts/check_planted.sh` fails unless the tests catch every one.
- **A leakage audit.** A simulation proof that a server's view reveals nothing beyond the batch size ([leakage-audit](docs/design/leakage-audit.md)), plus tests that every server's traffic has the same shape for any orders and that everything opened is distributed independently of them.
- **Proofs checked by brute force.** The two theorems behind malicious security are also checked exhaustively on small instances ([proof_checks.rs](crates/mpc/tests/proof_checks.rs)).

This process found real problems:
- a counterexample to a price-finding shortcut, caught by a property test;
- a biased permutation sampler, caught while writing a proof;
- a hidden network round in an optimisation;
- three deployment bugs.

The [design report](docs/design-report.md#7-how-it-was-checked) lists them.

## Quick start

Needs Rust 1.85 or newer (edition 2024).

```
cargo test --workspace                 # 96 tests (2 slow proof checks run with -- --ignored)
./scripts/check_planted.sh             # every planted bug must be caught
cargo run --release -p darkmpc-auction --example stages -- 1024 lan malicious
                                       # both stages in one process, simulated LAN, checked
scripts/bench_local.sh 1000 3 lan 8192 stage2
                                       # Stage 2 as three TLS processes, checked
```

To benchmark on real machines, `scripts/gcp_bench.sh` creates three Google Cloud VMs, deploys the current commit, measures the network, runs a checked grid of auctions and deletes the VMs (see the comments at the top of the script). The VMs bill until `scripts/gcp_bench.sh down` runs.

## Layout

| Path | Contents |
|---|---|
| `crates/reference` | The plain reference matchers for both stages |
| `crates/mpc` | The three-party core: replicated sharing over $\mathbb{Z}_{2^{64}}$, multiplication, comparison, oblivious shuffle and sort, scans, malicious-security checks |
| `crates/auction` | Both auctions in MPC, and input validation on shares |
| `crates/server` | The servers as separate processes over mutually authenticated TLS 1.3 |
| `docs/design-report.md` | **Start here**: the whole system, how it was checked, results and limits |
| `docs/design/` | Threat model, leakage proof, ring-extension proofs, per-stage MPC designs |
| `docs/benchmarks.md`, `results/gcp/` | Benchmark report and raw results |
| `docs/learning/`, `docs/*.pdf` | Prose walkthroughs of each milestone, written while building |

## References

The protocols darkmpc builds on:
- replicated secret sharing (Araki et al., CCS 2016);
- malicious-security checks (Furukawa, Lindell, Nof and Weinstein, Eurocrypt 2017);
- the oblivious stable sort and verified shuffle (Asharov et al., CCS 2022);
- MACs modulo $2^{128}$ (SPDZ2k, CRYPTO 2018);
- checked openings (Eerikson et al., ITC 2020).

Full citations are in the [design report](docs/design-report.md#references).

Built by Tave La Rocque, 2026. MIT licensed (see `LICENSE`).
