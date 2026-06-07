# libcidr Benchmark Baselines

This file records benchmark baselines for the C and Python benchmark suites.
Each entry includes the benchmark run date and the full hardware/build context
required by TESTING.md §8.2 so future optimization work can compare like for
like.

## C Benchmarks

### Linux x86_64

**Benchmark run date**: 2026-06-07

**Hardware / build context**
- Platform: Linux x86_64
- CPU: AMD Ryzen 7 4800H (Zen 2, 8 physical cores / 16 threads, 2 CCX x 4 cores)
- Base clock: 2.9 GHz (boost enabled; not pinned during benchmark run)
- Cache: L1d 32K/core, L1i 32K/core, L2 512K/core, L3 4MB/CCX (8MB total)
- Cache line: 64 bytes
- RAM: dmidecode unavailable
- Spectre mitigations: active (Retpolines + IBPB + STIBP)
- Compiler: clang version 22.1.6 (Fedora 22.1.6-1.fc44)
- Kernel: 7.0.10-201.fc44.x86_64
- Build: release (-O2)
- Benchmark isolation: single-threaded, no CPU pinning

**Measurement note**: boost is enabled and benchmarks run without CPU
pinning. Run-to-run variance of ±3-5% is normal on this configuration.
Numbers that differ from a previous run within that band are measurement
noise, not regressions or improvements. Only the IPv6 parse improvement
(footnote [1]) and the bulk containment improvement (footnote [3]) reflect
code changes; all other differences from the previous baseline are within
expected variance.

**bench_bulk_parse**

| Family | libcidr (M addrs/s) |
|---|---:|
| IPv4 | 60.73 |
| IPv6 | 23.19 [1] |

**bench_bulk_contains**

| Prefix table size | libcidr (M pairs/s) |
|---|---:|
| 100 | 304.35 [3] |
| 1,000 | 323.33 [3] |
| 10,000 | 327.95 [3] |

**bench_bulk_aggregate**

| Prefix count | libcidr (M prefixes/s) |
|---|---:|
| 1,000 | 5.59 |
| 10,000 | 5.70 |
| 100,000 | 5.65 |
| 800,000 | 5.46 |

**bench_bulk_sort_network_asc**

| Prefix count | libcidr (M prefixes/s) |
|---|---:|
| 800,000 | 10.40 |

**bench_bulk_sort_pfxlen_desc**

| Prefix count | libcidr (M prefixes/s) |
|---|---:|
| 800,000 | 7.72 |

**bench_aggregate_early_exit**

| Prefix count | libcidr (M prefixes/s) |
|---|---:|
| 1,000 | 16.97 |
| 10,000 | 17.11 |
| 100,000 | 16.63 |
| 800,000 | 15.61 |

**bench_index_build**

| Prefix count | libcidr (M prefixes/s) |
|---|---:|
| 1,000 | 0.30 |
| 10,000 | 0.30 |
| 100,000 | 0.29 |
| 800,000 | 0.29 |

**bench_index_lookup**

| Prefix count | Queries | libcidr (M queries/s) |
|---|---:|---:|
| 800,000 | 1,000,000 | 24.49 |

**bench_index_vs_bulk_crossover**

| Prefix count | Queries | Build ms | Bulk kq/s | Index kq/s | Crossover queries |
|---|---:|---:|---:|---:|---:|
| 100 | 100,000 | 0.34 | 1129.18 | 56935.91 | 387 |
| 1,000 | 100,000 | 3.32 | 114.82 | 44062.80 | 382 |
| 10,000 | 10,000 | 32.99 | 11.53 | 32812.38 | 381 |
| 100,000 | 1,000 | 334.18 | 113.38 | 27634.62 | 38046 |
| 800,000 | 128 | 2744.31 | 94.10 [2] | 20056.40 | 259466 |

### Linux ARM64

Not required for the current Task 8.3 scope. No ARM64 benchmark host is
available.

### OpenBSD amd64

Not required for the current Task 8.3 scope. The available OpenBSD amd64
machine is used for validation only and is not treated as a meaningful
benchmark baseline source.

## Optimization Investigation Log

**Date**: 2026-06-07
**Scope**: bench_index_lookup throughput and IPv6 parse throughput
**Hardware**: AMD Ryzen 7 4800H, 4MB effective L3 per CCX, 64-byte cache line

### Investigation 1 — LC-trie node padding (12 -> 16 bytes)

**Hypothesis**: eliminating cache-line straddling (64 / 12 = 5.33 nodes
per cache line) would reduce memory access penalty in the traversal loop.

**Result**: bench_index_lookup at 800k: 24.34 -> 24.92 M queries/s (+2.38%).
Below the 5% keep threshold.

**Reverted.**

The 4MB effective L3 per CCX on this hardware is the binding constraint.
The 800k prefix node array approaches or exceeds that limit at 12 bytes per
node. Making nodes 33% larger increased cache pressure enough to suppress
the alignment benefit. The Zen 2 architecture also handles split-line
accesses with a modest penalty (~2-4 cycles), reducing the upside.

**Hardware dependency**: this result is L3-size-sensitive. On server CPUs
with large unified L3 (Intel Xeon Platinum >= 32MB, AMD EPYC >= 96MB) the
full node array fits cache at 16 bytes per node and cache pressure is not
a competing factor. The alignment benefit would be unobstructed and the
same change could yield 8-15% on those platforms. Re-run this investigation
on any server benchmark target before treating the revert as universal.

### Investigation 2 — Software prefetch in traversal loop

**Hypothesis**: one-ahead __builtin_prefetch() in the LC-trie traversal
descent block would hide dependent-load latency that hardware prefetchers
cannot resolve.

**Result**: bench_index_lookup at 800k: 24.34 -> 23.99 M queries/s (-1.44%).
Regression.

**Reverted.**

Zen 2's out-of-order engine already extracts memory-level parallelism from
the traversal. The prefetch instruction consumed issue slots for work the
hardware was already doing, producing a net regression.

**Hardware dependency**: this result depends on out-of-order engine depth.
Modern Intel Xeon (Ice Lake+) and AMD EPYC (Zen 3+) have similarly deep
OOO engines and would likely reproduce the regression. ARM64 server CPUs
with shallower pipelines -- in particular Neoverse N1 (AWS Graviton 2,
Ampere Altra) -- may show a positive result. Re-run this investigation on
ARM64 when that benchmark column is available.

### Investigation 3 — IPv6 hex digit lookup table

**Hypothesis**: replacing the per-character conditional hex decoder with a
256-entry lookup table would reduce branch pressure in the IPv6 parse hot
path.

**Profiling finding**: on benchmark-shaped IPv6 input, the dominant hot work
was per-character hex digit decode inside the hex-group parse loops. The
mixed-notation path was never taken on this input shape. The :: handling is
one-time bookkeeping per address.

**Result**: bench_bulk_parse IPv6: 21.12 -> 24.08 M addrs/s (+14.0%).
Above the 10% keep threshold.

**Kept.** Change is in src/cidr_addr.c only. Full Linux gate passed:
dev build, tests, valgrind, TSan, format, lint.

### Investigation 4 — bulk containment mask-free comparator

**Date**: 2026-06-07
**Scope**: bench_bulk_contains throughput

**Hypothesis**: cidr_bulk_contains() called the public cidr_prefix_contains()
once per (address, prefix) pair. Because benchmarks link the static archive
under the documented -O2 build with no LTO, that call cannot be inlined: every
pair paid a cross-translation-unit call, full NULL/family/UNSPEC revalidation,
and a stack-materialised mask address. Replacing it with an internal mask-free
comparator -- families are already validated once at the top of the scan, and
the §3.3 host-bits-zero invariant lets the test compare only the top pfxlen
bits -- should remove that per-pair overhead.

**Profiling finding**: the contains benchmark is a deliberate no-match full
scan (all /24 prefixes, all addresses outside the table), so the inner loop
runs addr_count x prefix_count times with no early break. Per-pair compare
cost is the entire benchmark, making the cross-call overhead dominant.

**Result**: bench_bulk_contains: 57.3-57.6 -> 304-328 M pairs/s across the
100 / 1,000 / 10,000 prefix tables (~5.3-5.7x, +430% to +470%). Far above the
10% keep threshold.

**Kept.** Change is in src/cidr_bulk.c only (new internal
bulk_prefix_contains() helper; public cidr_prefix_contains() and the API are
unchanged). RFC containment semantics ((addr & mask) == network) are
preserved; the predicate now matches the index-path comparator
trie_prefix_matches(). Three boundary tests added (non-byte-aligned /20, /0
default route, IPv6 /48 and /36). Full Linux gate passed: dev build (138/138),
tests, valgrind (0 errors, 0 leaks), TSan (140/140, 0 races), format, lint.

[1] Previous baseline: 21.54 M addrs/s. Fresh run differs by more than 3%
after the IPv6 hex decoder optimization landed.

[2] Bulk kq/s at 800k prefixes is measured over only 128 queries and
has high run-to-run variance. The crossover query count derived from it
should be treated as an order-of-magnitude estimate (~250k-300k queries),
not a precise threshold.

[3] Previous baseline: 57.32 / 57.62 / 57.55 M pairs/s. The ~5x gain reflects
the Investigation 4 code change (internal mask-free comparator), not variance.
Values are the stable figure across three consecutive runs.

## Python Benchmarks

Pending Task 8.4 benchmark implementation and recorded comparison baselines.
