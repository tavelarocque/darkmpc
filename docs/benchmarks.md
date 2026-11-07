# Benchmarks

All numbers here were measured on real machines: three servers on three Google Cloud VMs, talking over the VPC's internal network through the same mutually authenticated TLS used everywhere else. Nothing is simulated. Every run's output was reconstructed and compared with the plain reference matcher before it was recorded; no run in the tables failed that check. Raw data: `results/gcp/runs.txt`, network measurements in `results/gcp/net-*.txt`. Produced by `scripts/gcp_bench.sh` at commits 832fe01 (LAN) and 9600ae1 (WAN), which contain the same protocol code.

## Setup

**Machines.** `n2-standard-2`: 2 vCPUs (one physical core with two hyperthreads) and 8 GB per server. Larger machines did not fit the free-trial quota (8 C3 vCPUs per region, no increases allowed during the trial), so these numbers are a floor for the hardware, not a ceiling.

**Networks, as measured** (`ping`, 20 packets; `iperf3`, one TCP stream for 5 s):

| Profile | Placement | Round trip between servers | Bandwidth |
|---|---|---|---|
| LAN | all three in us-west1-b | 0.19 to 0.21 ms average | 9.27 Gbit/s |
| WAN | us-west1-b, us-central1-a, us-east4-b | 41.9, 27.3 and 68.5 ms | 0.745 Gbit/s |

**Workload.** Random batches over 8,192 hidden symbols (13-bit symbol field), sizes 1 to 10,000. Stage 1 orders have random minimum fills and run 3 elimination passes. Stage 2 limits fall within 50 ticks of 10,000 so books cross. The protocols are oblivious: their cost does not depend on the orders, only on the batch size and parameters, so the choice of workload does not affect the timings.

**Measured quantity.** Wall-clock time of the auction on the slowest server, from the first protocol message to the final share of each fill (TLS setup and key agreement excluded; they happen once per deployment). Median of 3 runs. Malicious mode includes input validation, all product and shuffle checks and the verdict round. Data is the most bytes sent by any one server.

## Results

### Time (median of 3)

| Orders | Stage 1 semi-honest | Stage 1 malicious | Stage 2 semi-honest | Stage 2 malicious |
|---|---|---|---|---|
| **LAN** | | | | |
| 100 | 0.020 s | 0.130 s | 0.029 s | 0.202 s |
| 1,000 | 0.055 s | 0.948 s | 0.108 s | 1.451 s |
| 10,000 | 0.359 s | 9.878 s | 0.894 s | 15.697 s |
| 100,000 | 4.328 s | | 12.620 s | |
| **WAN** | | | | |
| 100 | 5.978 s | 14.137 s | 6.510 s | 21.402 s |
| 1,000 | 7.329 s | 17.085 s | 8.222 s | 25.623 s |
| 10,000 | 7.932 s | 44.230 s | 10.640 s | 82.048 s |
| 100,000 | 23.626 s | | 63.563 s | |

Malicious mode was run up to 10,000 orders. At 1,000 orders and up, the 3 runs of a configuration were within about 7% of each other on the LAN. On the WAN, three runs were outliers (15.5 s against 7.7 to 7.9 s, 61.8 s against 42 to 44 s, 118 s against 79 to 82 s), which the median absorbs. The Stage 2 semi-honest 1,000-order cell has a fourth run, the smoke test.

### Throughput (orders per second, from the medians)

| Orders | Stage 1 semi | Stage 1 malicious | Stage 2 semi | Stage 2 malicious |
|---|---|---|---|---|
| LAN 1,000 | 18,182 | 1,055 | 9,259 | 689 |
| LAN 10,000 | 27,855 | 1,012 | 11,186 | 637 |
| LAN 100,000 | 23,105 | | 7,924 | |
| WAN 1,000 | 136 | 59 | 122 | 39 |
| WAN 10,000 | 1,261 | 226 | 940 | 122 |
| WAN 100,000 | 4,233 | | 1,573 | |

### Cost per auction

| Orders | Stage 1 semi | Stage 1 malicious | Stage 2 semi | Stage 2 malicious |
|---|---|---|---|---|
| Rounds at 1,000 | 280 | 566 | 297 | 855 |
| Rounds at 10,000 | 296 | 729 | 313 | 1,081 |
| Data per server, per order | 7 to 8 KiB | 158 to 171 KiB | 16 to 20 KiB | 252 to 278 KiB |

**Statistical security of the malicious runs**, from each run's own accounting (FLNW bound per verified batch, union bound over batches and shuffle checks): Stage 1 at least 45.7, 45.6 and 44.6 bits at 100, 1,000 and 10,000 orders; Stage 2 at least 44.7, 44.6 and 43.9 bits. It falls slowly with batch size because more verification batches enter the union bound.

Rounds grow only logarithmically with the batch: from 100 to 100,000 orders, Stage 1 semi-honest goes from 268 to 308. Data grows linearly.

## What the numbers show

**On a LAN, malicious security costs about 13 to 28 times semi-honest time** (Stage 1: 17 times at 1,000 orders, 28 at 10,000; Stage 2: 13 and 18). Malicious mode sends 15 to 23 times the data, and most of it is the Milestone 4a product checks: every multiplication is checked against a bucket of random triples, each of which must itself be produced. The FLNW bound sets the bucket size from how many products are verified together: 4 for a full chunk of $2^{18}$, more for smaller batches.

**On a WAN, rounds set a floor.** Each round costs about 22 to 30 ms, close to half the slowest link's 68.5 ms round trip, because most rounds pass a message one hop around the ring of servers. So any Stage 1 auction takes at least about 6 s and any malicious one at least about 14 s, however small. Larger batches amortise that floor: semi-honest Stage 1 goes from 17 orders/s at 100 orders to 4,233 at 100,000. A WAN deployment should run large, infrequent batches.

**At 100,000 orders, bandwidth takes over.** Stage 2 sends 2 GB per server. On the WAN that run took 64 s against 9 s of pure latency, so most of the time went to moving data at roughly 0.3 Gbit/s per server, below the measured single-stream 0.745 Gbit/s because each server feeds two links and the 68 ms link limits each TCP window.

**Stage 2 costs about 2.5 times Stage 1's data** but nearly the same number of rounds, so on the WAN it is only 1.1 to 1.5 times slower at up to 10,000 orders semi-honest.

## Against prior work

The only published comparable system is Cartlidge, Smart and Talibi Alaoui, "MPC Joins The Dark Side" (AsiaCCS 2019, ePrint 2018/1045). Their three-party volume match with malicious security, N = M = 500 (1,000 orders), Table 8; numbers checked against the paper, see `docs/prior-work.md`:

| | 2018/1045, Table 8 (3 parties) | darkmpc Stage 1, malicious |
|---|---|---|
| Online time | 0.900 s | 0.948 s (no separate offline phase) |
| Offline (preprocessing) | 4.136 s | none |
| End to end | 5.036 s | 0.948 s |
| End-to-end throughput | about 200 orders/s | 1,055 orders/s |
| Rounds | 4,509 (9(max(N,M)+1)) | 566 |
| Largest batch reported | 1,000 | 10,000 (1,012 orders/s) |
| Network | LAN, 0.47 ms ping, 10 Gbit/s | LAN, 0.2 ms round trip, 9.3 Gbit/s |
| Machines | i7-7700K (4 cores), 32 GB | 1 physical core (2 vCPUs), 8 GB |
| Statistical security | 40 bits | at least 45.6 bits (computed per run) |

**What this comparison supports.** On a LAN, darkmpc's end-to-end time for an actively secure 1,000-order batch is about 5 times lower, with 8 times fewer rounds, and it keeps the same throughput at 10 times the batch size.

**What it does not support.** It compares two systems, not one algorithm against another:

- **Mechanism.** Their volume match handles one instrument and has no minimum fills. darkmpc's Stage 1 hides the symbol and side of every order across 8,192 instruments, validates traders' inputs on shares, and runs 3 minimum-fill elimination passes. That is strictly more work, so this direction of difference favours them.
- **Network.** Our LAN round trip is less than half theirs, which favours us. How much is hard to say: 4,509 strictly sequential rounds at 0.47 ms would take 2.1 s, more than their measured 0.9 s, so their round count cannot be a count of sequential round trips (0.9 s over 4,509 rounds is 0.2 ms each, under one 0.235 ms one-way trip). The paper does not say how its rounds map to latency.
- **Hardware.** Our servers have one physical core against their four, but our cores are newer. How much of the 5 times comes from the protocol and how much from the hardware is not separable from these numbers.
- **Software.** They used SCALE-MAMBA, a general-purpose framework over a 128-bit prime field. darkmpc is purpose-built over the 64-bit ring.

**WAN.** Neither 2018/1045 nor 2020/662 measured a WAN, so there is no measured number to compare. An estimate, not a measurement: their LAN figures work out to 0.2 ms per round on a 0.47 ms round trip, about 0.43 of a round trip each. darkmpc's malicious rounds on this WAN cost about 26 to 30 ms on a 68.5 ms slowest round trip, about 0.38 to 0.44 of one. If their rounds scaled the same way, 4,509 of them would take on the order of 2 minutes on this WAN for one 1,000-order batch, against darkmpc's measured 17.1 s. That assumes their rounds behave like ours, which is unverified, so it belongs in the write-up only as a labelled extrapolation.

**Never compare** darkmpc's semi-honest numbers with their malicious ones.

## Reproducing

```
scripts/gcp_bench.sh quota lan
scripts/gcp_bench.sh up lan && scripts/gcp_bench.sh deploy lan && scripts/gcp_bench.sh net lan
scripts/gcp_bench.sh grid lan
scripts/gcp_bench.sh down lan
```

For the WAN, `export WAN_ZONES="us-west1-b us-central1-a us-east4-b"` first (us-east4-a had no `n2-standard-2` capacity at the time) and use `wan`. The LAN grid took about 20 minutes and the WAN grid about 50, most of it uploading dealt orders from a laptop on campus wifi.
