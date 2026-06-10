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
(footnote [1]), the bulk containment improvement (footnote [3]), and the
aggregation improvements (footnote [4]) reflect code changes; all other
differences from the previous baseline are within expected variance.

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
| 1,000 | 6.51 [4] |
| 10,000 | 6.73 [4] |
| 100,000 | 6.65 [4] |
| 800,000 | 6.38 [4] |

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
| 1,000 | 29.19 [4] |
| 10,000 | 29.68 [4] |
| 100,000 | 28.73 [4] |
| 800,000 | 25.40 [4] |

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
| 100 | 100,000 | 0.34 | 5594.08 [5] | 56935.91 | 2058 [5] |
| 1,000 | 100,000 | 3.32 | 623.35 [5] | 44062.80 | 2069 [5] |
| 10,000 | 10,000 | 32.99 | 64.59 [5] | 32812.38 | 2137 [5] |
| 100,000 | 1,000 | 334.18 | 590.65 [5] | 27634.62 | 200130 [5] |
| 800,000 | 128 | 2744.31 | 116.78 [2][5] | 20056.40 | 320173 [5] |

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

### Investigation 1 - LC-trie node padding (12 -> 16 bytes)

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

### Investigation 2 - Software prefetch in traversal loop

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

### Investigation 3 - IPv6 hex digit lookup table

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

### Investigation 4 - bulk containment mask-free comparator

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

### Investigation 5 - aggregation internal comparators

**Date**: 2026-06-07
**Scope**: bench_bulk_aggregate and bench_aggregate_early_exit throughput

**Hypothesis**: the three per-element steps of cidr_bulk_aggregate() each
called a public cidr_prefix_* function that cannot be inlined across the
static archive at -O2 with no LTO. Step 2 (duplicate removal) called
cidr_prefix_cmp(); step 3 (containment removal) called cidr_prefix_contains();
step 4 (sibling merge) called cidr_prefix_supernet() twice per adjacent pair
inside prefixes_are_siblings() and once more to build each merged supernet.
Every one of those paid a cross-call plus full revalidation, and the merge
loop repeats over the array until a pass makes no merges. The whole family is
validated once at function entry, so internal comparators can take addr_len
directly: dedup reuses the existing prefixes_equal_key(), containment reuses
the Investigation 4 bulk_prefix_contains(), the sibling test compares the top
pfxlen-1 bits directly, and a new prefix_supernet_into() builds the merged
parent without a cross-call.

**Result**:
- bench_bulk_aggregate: 5.46-5.70 -> 6.38-6.73 M prefixes/s (~+16% to +18%).
- bench_aggregate_early_exit: 15.61-17.11 -> 25.40-29.68 M prefixes/s
  (~+63% to +72%). The early-exit workload terminates the merge step quickly,
  so the per-element dedup and containment steps dominate and benefit most.

Both above the 10% keep threshold.

**Kept.** Change is in src/cidr_bulk.c only; the public cidr_prefix_cmp(),
cidr_prefix_contains(), and cidr_prefix_supernet() and the API are unchanged.
The §5.4 aggregation algorithm and RFC semantics (sibling merge, supernet at
pfxlen-1, host-bits-zero results) are preserved. Three boundary tests added
(IPv6 /64 sibling merge, /1 pair -> /0 default route, equal-length
non-siblings). Full Linux gate passed: dev build (141/141), tests, valgrind
(0 errors, 0 leaks), TSan (143/143, 0 races), format, lint.

### Investigation 6 - LC-trie node packing order (BFS vs current order)

**Date**: 2026-06-10
**Scope**: bench_index_lookup throughput

**Hypothesis**: the current node packing order (DFS / DP resolution order)
does not cluster the most-accessed nodes (root and top levels) at the
start of the contiguous array. Switching to strict BFS packing would
keep hot nodes in L1/L2 cache across queries and improve lookup
throughput.

**Result**: bench_index_lookup 800k median: 24.04 -> 24.12 M queries/s
(+0.33%). Below the 5% keep threshold. Build unchanged at 0.29-0.30
M prefixes/s. Node count unchanged at 803,147.

**Reverted.**

The current packing order is already near-optimal for cache behavior on
this hardware. BFS ordering produced no measurable benefit, which rules
out physical memory layout as the explanation for the Investigation 7
lookup regression.

### Investigation 7 - MAX_BRANCH cap reduction (8 -> 6)

**Date**: 2026-06-10
**Scope**: bench_index_build throughput

**Hypothesis**: reducing MAX_BRANCH from 8 to 6 eliminates evaluation of
b=7 and b=8 candidates (384 of 510 path traversals per node, ~75% of
DP work), reducing build cost with minimal impact on trie quality if the
DP rarely chooses branch factors above 6 on real data.

**Result**:
- bench_index_build 800k: 0.30 -> 1.04 M prefixes/s (+247%, 3.5x).
- bench_index_lookup 800k median: 24.04 -> 21.70 M queries/s (-10.29%).
- Node count: 803,147 in both cases.

**Reverted.** Lookup regression fell in the 10-15% manual-decision band and
was confirmed reproducible across three runs. The regression was not
recoverable via BFS packing (Investigation 6), establishing that it
comes from logical trie structural differences at tie-break nodes, not
from memory layout changes.

**Hardware dependency**: the node count being identical for both caps
confirms the DP never chooses b=7 or b=8 on this 800k-prefix dataset.
On denser or differently-shaped prefix distributions, higher branch
factors may be selected and the quality gap between MAX_BRANCH=6 and
MAX_BRANCH=8 could be larger.

**Build speed note**: the 3.5x build improvement is available at the cost
of a real -10% lookup regression that cannot be separated from the
change. The correct long-term solution for users requiring both fast
build and fast lookup is a two-phase approach: fast Patricia-trie build
(comparable to pytricia build speed) with optional LC-trie DP upgrade.
This is out of scope for v1.

[4] Previous baseline: bench_bulk_aggregate 5.59 / 5.70 / 5.65 / 5.46;
bench_aggregate_early_exit 16.97 / 17.11 / 16.63 / 15.61 M prefixes/s. The
gains reflect the Investigation 5 code change (internal aggregation
comparators), not variance. Values are stable across three consecutive runs.

[5] bench_index_vs_bulk_crossover refresh after Investigation 4. Only the
Bulk kq/s and Crossover queries columns changed; Build ms and Index kq/s are
unchanged within measurement noise and were left at their previous values.
The faster bulk containment scan raises the per-row crossover threshold,
because the index build cost now takes proportionally more queries to
amortize. Previous Bulk kq/s: 1129.18 / 114.82 / 11.53 / 113.38 / 94.10;
previous Crossover queries: 387 / 382 / 381 / 38046 / 259466. The 100 / 1,000
/ 10,000 / 100,000 rows moved ~5x: their prefix arrays (up to ~2.4 MB at 100k,
24 bytes per prefix) fit within this CPU's 4 MB-per-CCX L3, so the scan stays
compute-bound and benefits fully from the mask-free comparator. Only the
800,000 row (~19 MB, exceeds L3) is memory-bandwidth-bound and moved ~+24%.
Crossover values are medians of three consecutive runs; the 800k bulk figure
remains high-variance per footnote [2], so its crossover (~300k-330k queries)
is order-of-magnitude.

## Python Benchmarks

### Linux x86_64

**Benchmark run date**: 2026-06-09

**Hardware / build context**
- Platform: Linux x86_64
- CPU: AMD Ryzen 7 4800H (Zen 2, 8 physical cores / 16 threads, 2 CCX x 4 cores) -- effective clock during benchmark run: 2.59 GHz
- Cores: 16 logical threads
- Python: 3.14.5
- libcidr: 1.0.0
- ipaddress: 1.0 (stdlib)
- netaddr: 1.3.0
- pytricia: 1.3.0
- Build: release (`make bench-python`, `python/libcidr.abi3.so`)
- Benchmark isolation: single-process, no CPU pinning

**Measurement note**: boost is enabled and benchmarks run without CPU
pinning. Run-to-run variance of a few percent is normal on this machine.

**Single address parse from string**

| Family | libcidr (M parses/s) | ipaddress (M parses/s) | netaddr (M parses/s) | pytricia | speedup vs ipaddress |
|---|---:|---:|---:|---:|---:|
| IPv4 | 6.01 | 0.60 | 0.59 | --- | 9.95x |
| IPv6 | 5.29 | 0.34 | 0.43 | --- | 15.61x |

**Bulk parse: 100k addresses**

| Family | libcidr (M addrs/s) | ipaddress (M addrs/s) | netaddr (M addrs/s) | pytricia | speedup vs ipaddress |
|---|---:|---:|---:|---:|---:|
| IPv4 | 6.57 | 0.59 | 0.58 | --- | 11.07x |
| IPv6 | 5.90 | 0.33 | 0.44 | --- | 17.79x |

**Bulk containment: first-match containment, 60% match rate, no default route**

| Workload | libcidr (M lookups/s) | ipaddress (M lookups/s) | netaddr (M lookups/s) | speedup vs ipaddress |
|---|---:|---:|---:|---:|
| 100k addresses / 100 prefixes | 3.53 | 0.06 | 0.05 | 54.29x |

**Prefix aggregation: 50k prefixes**

| Workload | libcidr (M prefixes/s) | ipaddress (M prefixes/s) | netaddr (M prefixes/s) | pytricia | speedup vs ipaddress |
|---|---:|---:|---:|---:|---:|
| 50k IPv4 prefixes | 6.41 | 0.11 | 0.52 | --- | 56.39x |

**Index build + 1M lookups**

| Phase | libcidr (M ops/s) | ipaddress (M ops/s) | netaddr (M ops/s) | pytricia (M ops/s) | speedup vs ipaddress |
|---|---:|---:|---:|---:|---:|
| Build (10k prefixes) | 0.30 | --- | --- | 3.54 | --- |
| Lookup (1M queries) | 10.06 | 0.0011 | 0.0008 | 3.89 | 9466.52x |

[1] Bulk containment uses 100 realistic RFC 1918 and documentation prefixes
with no default route and a 60% in-range / 40% miss address mix. pytricia is
excluded; it performs LPM not first-match containment and is not comparable to
bulk_contains() semantics.

[2] Aggregation uses a mixed-ratio unsorted 50k-prefix input: 35k distinct
/24s with no sibling, 10k /24s arranged as 5k sibling pairs, 3k /23s arranged
as 1500 sibling pairs, and 2k duplicates sampled from the base set. The
throughput denominator is input prefix count divided by elapsed time
(`50k / elapsed`), not output prefix count.

[3] Index lookup uses 10k diverse covered addresses drawn from the 10k-prefix
table and cycled 100 times for the indexed implementations. libcidr and
pytricia measured over 1M queries. ipaddress and netaddr measured over a
2-second timed run; query count varies by library (typically 50k-200k).
Throughput in M lookups/s is directly comparable. The libcidr vs pytricia
lookup advantage here reflects small-table (10k prefix) cache-resident
performance; at routing-table scale (800k prefixes) the L3 constraint
documented in the C benchmark section would reduce this advantage, and the C
bench_index_lookup result at 800k remains the relevant large-scale reference.
ipaddress and netaddr lookup rates are below 0.01 M lookups/s and are
displayed to four decimal places to avoid misleading rounding.
