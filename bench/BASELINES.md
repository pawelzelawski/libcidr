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
- CPU: AMD Ryzen 7 4800H with Radeon Graphics
- Cores: 16
- Build: release (`-O2`)

**bench_bulk_parse**

| Family | libcidr (M addrs/s) |
|---|---:|
| IPv4 | 59.88 |
| IPv6 | 21.54 |

**bench_bulk_contains**

| Prefix table size | libcidr (M pairs/s) |
|---|---:|
| 100 | 57.09 |
| 1,000 | 56.50 |
| 10,000 | 56.58 |

**bench_bulk_aggregate**

| Prefix count | libcidr (M prefixes/s) |
|---|---:|
| 1,000 | 5.62 |
| 10,000 | 5.76 |
| 100,000 | 5.68 |
| 800,000 | 5.51 |

**bench_bulk_sort_network_asc**

| Prefix count | libcidr (M prefixes/s) |
|---|---:|
| 800,000 | 10.54 |

**bench_bulk_sort_pfxlen_desc**

| Prefix count | libcidr (M prefixes/s) |
|---|---:|
| 800,000 | 7.38 |

**bench_aggregate_early_exit**

| Prefix count | libcidr (M prefixes/s) |
|---|---:|
| 1,000 | 16.97 |
| 10,000 | 16.93 |
| 100,000 | 16.38 |
| 800,000 | 15.77 |

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
| 800,000 | 1,000,000 | 23.87 |

**bench_index_vs_bulk_crossover**

| Prefix count | Queries | Build ms | Bulk kq/s | Index kq/s | Crossover queries |
|---|---:|---:|---:|---:|---:|
| 100 | 100,000 | 0.34 | 1135.53 | 56986.99 | 393 |
| 1,000 | 100,000 | 3.32 | 115.95 | 44012.53 | 386 |
| 10,000 | 10,000 | 33.18 | 11.57 | 32690.05 | 384 |
| 100,000 | 1,000 | 332.84 | 114.42 | 27523.78 | 38242 |
| 800,000 | 128 | 2729.82 | 108.25 | 19970.57 | 297106 |

### Linux ARM64

Not required for the current Task 8.3 scope. No ARM64 benchmark host is
available.

### OpenBSD amd64

Not required for the current Task 8.3 scope. The available OpenBSD amd64
machine is used for validation only and is not treated as a meaningful
benchmark baseline source.

## Python Benchmarks

Pending Task 8.4 benchmark implementation and recorded comparison baselines.
