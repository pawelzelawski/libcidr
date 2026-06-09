"""
bench_python.py -- Python benchmark suite for libcidr.

Measures the Python binding against ipaddress, netaddr, and pytricia for the
operations documented in TESTING.md §8.1. Results include full environment
context per TESTING.md §8.2 so recorded baselines remain comparable.
"""

from __future__ import annotations

import datetime
import gc
import importlib.metadata
import ipaddress
import os
import platform
import random
import statistics
import sys
import time
from typing import Callable

import libcidr
import netaddr
import pytricia

LIBCIDR_VERSION = "1.0.0"
REPETITIONS = 3
SINGLE_PARSE_COUNT = 100_000
BULK_PARSE_COUNT = 100_000
BULK_CONTAINS_ADDRS = 100_000
BULK_CONTAINS_PREFIXES = 100
AGGREGATE_PREFIXES = 50_000
INDEX_PREFIXES = 10_000
INDEX_LOOKUPS = 1_000_000
TIMED_LOOKUP_SECONDS = 2.0


def cpu_description() -> str:
    """Return a best-effort CPU model string for benchmark reproducibility."""

    if sys.platform.startswith("linux"):
        try:
            with open("/proc/cpuinfo", "r", encoding="utf-8") as fh:
                model = None
                mhz = None
                for line in fh:
                    if line.startswith("model name") and model is None:
                        model = line.split(":", 1)[1].strip()
                    elif line.startswith("cpu MHz") and mhz is None:
                        mhz = float(line.split(":", 1)[1].strip())
                    if model is not None and mhz is not None:
                        break
                if model is not None and mhz is not None:
                    return f"{model} @ {mhz:.0f} MHz"
                if model is not None:
                    return model
        except OSError:
            pass
    return "unknown"


def version_of(module: object) -> str:
    """Return the distribution version string for a benchmark dependency."""

    version = getattr(module, "__version__", None)
    if version is not None:
        return version
    try:
        return importlib.metadata.version(module.__name__)
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def bench_rate(units: int, func: Callable[[], object]) -> float:
    """Return the median throughput in units/sec across repeated executions."""

    samples: list[float] = []
    for _ in range(REPETITIONS):
        gc.collect()
        gc_was_enabled = gc.isenabled()
        gc.disable()
        start = time.perf_counter()
        result = func()
        elapsed = time.perf_counter() - start
        if gc_was_enabled:
            gc.enable()
        if result is None:
            raise RuntimeError("benchmark function returned None")
        samples.append(units / elapsed)
    return statistics.median(samples)


def bench_timed_rate(func: Callable[[], int]) -> float:
    """Return the median timed throughput in operations/sec.

    The callback must execute a timed run and return the completed operation
    count for that run; throughput is derived from completed operations and
    wall-clock time.
    """

    samples: list[float] = []
    for _ in range(REPETITIONS):
        gc.collect()
        gc_was_enabled = gc.isenabled()
        gc.disable()
        start = time.perf_counter()
        completed = func()
        elapsed = time.perf_counter() - start
        if gc_was_enabled:
            gc.enable()
        samples.append(completed / elapsed)
    return statistics.median(samples)


def fmt_rate(rate: float | None, scale: float = 1_000_000.0) -> str:
    """Format a throughput cell, or --- when the operation is unsupported."""

    if rate is None:
        return "---"
    return f"{rate / scale:.2f}"


def fmt_speedup(libcidr_rate: float | None, ipaddress_rate: float | None) -> str:
    """Format the libcidr/ipaddress throughput ratio for a result row."""

    if libcidr_rate is None or ipaddress_rate is None or ipaddress_rate == 0.0:
        return "---"
    return f"{libcidr_rate / ipaddress_rate:.2f}x"


def print_context() -> None:
    """Print the run context required by TESTING.md §8.2."""

    print("libcidr Python benchmark suite")
    print(f"Platform     : {platform.system()} {platform.machine()}")
    print(f"CPU          : {cpu_description()}")
    print(f"Cores        : {os.cpu_count() or 1}")
    print(f"Python       : {platform.python_version()}")
    print(f"libcidr      : {LIBCIDR_VERSION}")
    print(f"ipaddress    : {version_of(ipaddress)}")
    print(f"netaddr      : {version_of(netaddr)}")
    print(f"pytricia     : {version_of(pytricia)}")
    print("Build        : release")
    print(f"Date         : {datetime.date.today().isoformat()}")
    print()


def print_table(title: str, headers: list[str], rows: list[list[str]]) -> None:
    """Print a simple markdown-compatible result table."""

    print(title)
    print("| " + " | ".join(headers) + " |")
    print("|" + "|".join("---" for _ in headers) + "|")
    for row in rows:
        print("| " + " | ".join(row) + " |")
    print()


def build_ipv4_strings(count: int) -> list[str]:
    """Generate deterministic IPv4 host strings."""

    return [f"10.{(i >> 16) & 0xff}.{(i >> 8) & 0xff}.{(i & 0xff) or 1}"
            for i in range(count)]


def build_ipv6_strings(count: int) -> list[str]:
    """Generate deterministic IPv6 host strings."""

    return [f"2001:db8:{(i >> 16) & 0xffff:x}:{i & 0xffff:x}::1"
            for i in range(count)]


def build_bulk_contains_prefixes() -> list[str]:
    """Create a 100-prefix first-match containment workload."""

    prefixes: list[str] = []

    for i in range(10):
        prefixes.append(f"10.{i}.0.0/16")
    for i in range(20):
        prefixes.append(f"172.{16 + (i // 16)}.{(i % 16) * 16}.0/20")
    for i in range(67):
        prefixes.append(f"192.168.{i}.0/24")
    prefixes.extend([
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
    ])
    return prefixes


def build_bulk_contains_addresses(
    prefixes: list[ipaddress.IPv4Network],
) -> list[str]:
    """Create a 60% match / 40% miss first-match address workload."""

    rng = random.Random(20260610)
    addrs: list[str] = []

    for i in range(60_000):
        prefix = prefixes[i % len(prefixes)]
        host_slots = max(1, int(prefix.num_addresses) - 2)
        addr_int = int(prefix.network_address) + 1 + (i % host_slots)
        addrs.append(str(ipaddress.IPv4Address(addr_int)))

    for i in range(40_000):
        addrs.append(f"11.{(i >> 8) & 0xff}.{i & 0xff}.1")

    rng.shuffle(addrs)
    return addrs


def build_index_prefixes() -> list[str]:
    """Create the PrefixIndex/pytricia build workload."""

    prefixes = ["0.0.0.0/0"]
    for i in range(INDEX_PREFIXES - 1):
        prefixes.append(f"10.{(i >> 8) & 0xff}.{i & 0xff}.0/24")
    return prefixes


def build_index_queries(prefixes: list[str]) -> list[str]:
    """Create 10k diverse covered addresses and repeat them for 1M lookups."""

    rng = random.Random(20260611)
    covered_prefixes = prefixes[1:]
    base_queries: list[str] = []

    for _ in range(10_000):
        prefix = ipaddress.IPv4Network(rng.choice(covered_prefixes))
        host = rng.randint(1, int(prefix.num_addresses) - 2)
        base_queries.append(str(ipaddress.IPv4Address(int(prefix.network_address) + host)))

    return base_queries * 100


def build_aggregate_prefixes() -> list[str]:
    """Create a 50k-prefix mixed-ratio aggregation workload.

    The dataset is intentionally unsorted and combines non-mergeable /24s,
    /24 sibling pairs, /23 sibling pairs, and duplicates. This exercises the
    radix-sort front-end and requires multiple merge/dedup passes in the
    aggregation back-end.
    """

    rng = random.Random(20260609)
    prefixes: list[str] = []
    unique_base = int(ipaddress.IPv4Address("20.0.0.0"))
    pair24_base = int(ipaddress.IPv4Address("60.0.0.0"))
    pair23_base = int(ipaddress.IPv4Address("80.0.0.0"))

    for i in range(35_000):
        prefixes.append(str(ipaddress.IPv4Network((unique_base + (i * 512), 24))))

    for i in range(5_000):
        block = pair24_base + (i * 512)
        prefixes.append(str(ipaddress.IPv4Network((block, 24))))
        prefixes.append(str(ipaddress.IPv4Network((block + 256, 24))))

    for i in range(1_500):
        block = pair23_base + (i * 1024)
        prefixes.append(str(ipaddress.IPv4Network((block, 23))))
        prefixes.append(str(ipaddress.IPv4Network((block + 512, 23))))

    base_entries = prefixes[:]
    for _ in range(2_000):
        prefixes.append(rng.choice(base_entries))

    rng.shuffle(prefixes)
    return prefixes


def first_match_ipaddress(
    addrs: list[ipaddress.IPv4Address],
    prefixes: list[ipaddress.IPv4Network],
) -> list[int]:
    """Return first-match indices matching libcidr.bulk_contains() semantics."""

    result: list[int] = []
    for addr in addrs:
        match = -1
        for idx, prefix in enumerate(prefixes):
            if addr in prefix:
                match = idx
                break
        result.append(match)
    return result


def first_match_netaddr(
    addrs: list[netaddr.IPAddress],
    prefixes: list[netaddr.IPNetwork],
) -> list[int]:
    """Return first-match indices for netaddr containment loops."""

    result: list[int] = []
    for addr in addrs:
        match = -1
        for idx, prefix in enumerate(prefixes):
            if addr in prefix:
                match = idx
                break
        result.append(match)
    return result


def lpm_pytricia(queries: list[str], trie: pytricia.PyTricia) -> list[int]:
    """Return pytricia longest-prefix-match values for each query string."""

    return [trie.get(query, -1) for query in queries]


def lpm_ipaddress_sorted(
    addrs: list[ipaddress.IPv4Address],
    prefixes: list[ipaddress.IPv4Network],
) -> list[int]:
    """Return LPM-equivalent lookup results via pfxlen-desc linear scan.

    NOTE: PrefixIndex.lookup() returns longest-prefix-match indices. The linear
    ipaddress/netaddr baselines reproduce that result only because the lookup
    workload sorts networks by descending prefix length before timing.
    See ARCHITECTURE.md §6 and §8.10.2.
    """

    result: list[int] = []
    for addr in addrs:
        match = -1
        for idx, prefix in enumerate(prefixes):
            if addr in prefix:
                match = idx
                break
        result.append(match)
    return result


def lpm_netaddr_sorted(
    addrs: list[netaddr.IPAddress],
    prefixes: list[netaddr.IPNetwork],
) -> list[int]:
    """Return LPM-equivalent netaddr lookup results via sorted linear scan."""

    result: list[int] = []
    for addr in addrs:
        match = -1
        for idx, prefix in enumerate(prefixes):
            if addr in prefix:
                match = idx
                break
        result.append(match)
    return result


def timed_ipaddress_lookup_rate(
    addrs: list[ipaddress.IPv4Address],
    prefixes: list[ipaddress.IPv4Network],
) -> int:
    """Run timed ipaddress LPM-equivalent lookups over the cyclic query set."""

    completed = 0
    deadline = time.perf_counter() + TIMED_LOOKUP_SECONDS

    while time.perf_counter() < deadline:
        for addr in addrs:
            match = -1
            for idx, prefix in enumerate(prefixes):
                if addr in prefix:
                    match = idx
                    break
            completed += 1
            if time.perf_counter() >= deadline:
                break
            if match < -1:
                raise RuntimeError("unreachable")
    return completed


def timed_netaddr_lookup_rate(
    addrs: list[netaddr.IPAddress],
    prefixes: list[netaddr.IPNetwork],
) -> int:
    """Run timed netaddr LPM-equivalent lookups over the cyclic query set."""

    completed = 0
    deadline = time.perf_counter() + TIMED_LOOKUP_SECONDS

    while time.perf_counter() < deadline:
        for addr in addrs:
            match = -1
            for idx, prefix in enumerate(prefixes):
                if addr in prefix:
                    match = idx
                    break
            completed += 1
            if time.perf_counter() >= deadline:
                break
            if match < -1:
                raise RuntimeError("unreachable")
    return completed


def single_parse_rows() -> list[list[str]]:
    """Benchmark single-address parse throughput for IPv4 and IPv6."""

    rows: list[list[str]] = []
    cases = [
        ("IPv4", "203.0.113.7", libcidr.IPv4Address, ipaddress.IPv4Address,
         netaddr.IPAddress),
        ("IPv6", "2001:db8:abcd::1234", libcidr.IPv6Address,
         ipaddress.IPv6Address, netaddr.IPAddress),
    ]
    for family, src, lib_ctor, ip_ctor, net_ctor in cases:
        lib_rate = bench_rate(SINGLE_PARSE_COUNT,
                              lambda src=src, ctor=lib_ctor:
                              [ctor(src) for _ in range(SINGLE_PARSE_COUNT)])
        ip_rate = bench_rate(SINGLE_PARSE_COUNT,
                             lambda src=src, ctor=ip_ctor:
                             [ctor(src) for _ in range(SINGLE_PARSE_COUNT)])
        net_rate = bench_rate(SINGLE_PARSE_COUNT,
                              lambda src=src, ctor=net_ctor:
                              [ctor(src) for _ in range(SINGLE_PARSE_COUNT)])
        rows.append([
            family,
            fmt_rate(lib_rate),
            fmt_rate(ip_rate),
            fmt_rate(net_rate),
            "---",
            fmt_speedup(lib_rate, ip_rate),
        ])
    return rows


def bulk_parse_rows() -> list[list[str]]:
    """Benchmark 100k-address bulk parse throughput for IPv4 and IPv6."""

    rows: list[list[str]] = []
    cases = [
        ("IPv4", build_ipv4_strings(BULK_PARSE_COUNT), libcidr.IPv4Address,
         ipaddress.IPv4Address, netaddr.IPAddress),
        ("IPv6", build_ipv6_strings(BULK_PARSE_COUNT), libcidr.IPv6Address,
         ipaddress.IPv6Address, netaddr.IPAddress),
    ]
    for family, srcs, _lib_ctor, ip_ctor, net_ctor in cases:
        lib_rate = bench_rate(
            BULK_PARSE_COUNT, lambda srcs=srcs: libcidr.bulk_parse(srcs))
        ip_rate = bench_rate(
            BULK_PARSE_COUNT,
            lambda srcs=srcs, ctor=ip_ctor: [ctor(src) for src in srcs],
        )
        net_rate = bench_rate(
            BULK_PARSE_COUNT,
            lambda srcs=srcs, ctor=net_ctor: [ctor(src) for src in srcs],
        )
        rows.append([
            family,
            fmt_rate(lib_rate),
            fmt_rate(ip_rate),
            fmt_rate(net_rate),
            "---",
            fmt_speedup(lib_rate, ip_rate),
        ])
    return rows


def bulk_contains_rows() -> list[list[str]]:
    """Benchmark 100k-address bulk containment throughput."""

    prefix_strs = build_bulk_contains_prefixes()
    ip_prefixes = [ipaddress.IPv4Network(src) for src in prefix_strs]
    addr_strs = build_bulk_contains_addresses(ip_prefixes)

    lib_prefixes = [libcidr.IPv4Network(src) for src in prefix_strs]
    lib_addrs = [libcidr.IPv4Address(src) for src in addr_strs]
    ip_addrs = [ipaddress.IPv4Address(src) for src in addr_strs]
    net_prefixes = [netaddr.IPNetwork(src) for src in prefix_strs]
    net_addrs = [netaddr.IPAddress(src) for src in addr_strs]

    lib_rate = bench_rate(
        BULK_CONTAINS_ADDRS,
        lambda: libcidr.bulk_contains(lib_addrs, lib_prefixes),
    )
    ip_rate = bench_rate(
        BULK_CONTAINS_ADDRS,
        lambda: first_match_ipaddress(ip_addrs, ip_prefixes),
    )
    net_rate = bench_rate(
        BULK_CONTAINS_ADDRS,
        lambda: first_match_netaddr(net_addrs, net_prefixes),
    )

    return [[
        f"{BULK_CONTAINS_ADDRS} addrs / {BULK_CONTAINS_PREFIXES} prefixes",
        fmt_rate(lib_rate),
        fmt_rate(ip_rate),
        fmt_rate(net_rate),
        fmt_speedup(lib_rate, ip_rate),
    ]]


def aggregate_rows() -> list[list[str]]:
    """Benchmark 50k-prefix aggregation throughput."""

    prefix_strs = build_aggregate_prefixes()
    lib_prefixes = [libcidr.IPv4Network(src) for src in prefix_strs]
    ip_prefixes = [ipaddress.IPv4Network(src) for src in prefix_strs]
    net_prefixes = [netaddr.IPNetwork(src) for src in prefix_strs]

    lib_rate = bench_rate(
        AGGREGATE_PREFIXES,
        lambda: libcidr.bulk_aggregate(lib_prefixes),
    )
    ip_rate = bench_rate(
        AGGREGATE_PREFIXES,
        lambda: list(ipaddress.collapse_addresses(ip_prefixes)),
    )
    net_rate = bench_rate(
        AGGREGATE_PREFIXES,
        lambda: netaddr.cidr_merge(net_prefixes),
    )

    return [[
        f"{AGGREGATE_PREFIXES} IPv4 prefixes",
        fmt_rate(lib_rate),
        fmt_rate(ip_rate),
        fmt_rate(net_rate),
        "---",
        fmt_speedup(lib_rate, ip_rate),
    ]]


def index_rows() -> list[list[str]]:
    """Benchmark PrefixIndex/PyTricia build and 1M-lookups throughput."""

    prefix_strs = build_index_prefixes()
    sorted_prefix_strs = sorted(
        prefix_strs,
        key=lambda src: (-int(src.split("/", 1)[1]), src),
    )
    query_strs = build_index_queries(prefix_strs)

    lib_prefixes = [libcidr.IPv4Network(src) for src in prefix_strs]
    lib_index = libcidr.PrefixIndex(lib_prefixes)
    lib_addrs = [libcidr.IPv4Address(src) for src in query_strs]

    ip_prefixes = [ipaddress.IPv4Network(src) for src in sorted_prefix_strs]
    ip_addrs = [ipaddress.IPv4Address(src) for src in query_strs]

    net_prefixes = [netaddr.IPNetwork(src) for src in sorted_prefix_strs]
    net_addrs = [netaddr.IPAddress(src) for src in query_strs]

    trie = pytricia.PyTricia()
    for idx, prefix in enumerate(prefix_strs):
        trie[prefix] = idx

    lib_build = bench_rate(
        INDEX_PREFIXES,
        lambda: libcidr.PrefixIndex(lib_prefixes),
    )
    py_build = bench_rate(
        INDEX_PREFIXES,
        lambda: build_pytricia(prefix_strs),
    )

    lib_lookup = bench_rate(
        INDEX_LOOKUPS,
        lambda: lib_index.lookup(lib_addrs),
    )
    ip_lookup = bench_timed_rate(
        lambda: timed_ipaddress_lookup_rate(ip_addrs, ip_prefixes),
    )
    net_lookup = bench_timed_rate(
        lambda: timed_netaddr_lookup_rate(net_addrs, net_prefixes),
    )
    py_lookup = bench_rate(
        INDEX_LOOKUPS,
        lambda: lpm_pytricia(query_strs, trie),
    )

    return [
        [
            f"build ({INDEX_PREFIXES} prefixes)",
            fmt_rate(lib_build),
            "---",
            "---",
            fmt_rate(py_build),
            "---",
        ],
        [
            f"lookup ({INDEX_LOOKUPS} queries)",
            fmt_rate(lib_lookup),
            fmt_rate(ip_lookup),
            fmt_rate(net_lookup),
            fmt_rate(py_lookup),
            fmt_speedup(lib_lookup, ip_lookup),
        ],
    ]


def build_pytricia(prefixes: list[str]) -> pytricia.PyTricia:
    """Build a pytricia trie from a prefix string list."""

    trie = pytricia.PyTricia()
    for idx, prefix in enumerate(prefixes):
        trie[prefix] = idx
    return trie


def main() -> None:
    """Run the full benchmark suite and print comparison tables."""

    print_context()
    print_table(
        "Single address parse from string (M parses/s)",
        ["Family", "libcidr", "ipaddress", "netaddr", "pytricia",
         "speedup vs ipaddress"],
        single_parse_rows(),
    )
    print_table(
        "Bulk parse: 100k addresses (M addrs/s)",
        ["Family", "libcidr", "ipaddress", "netaddr", "pytricia",
         "speedup vs ipaddress"],
        bulk_parse_rows(),
    )
    print_table(
        "Bulk containment: first-match containment, 60% match rate, no default route (M lookups/s)",
        ["Workload", "libcidr", "ipaddress", "netaddr",
         "speedup vs ipaddress"],
        bulk_contains_rows(),
    )
    print_table(
        "Prefix aggregation (M prefixes/s)",
        ["Workload", "libcidr", "ipaddress", "netaddr", "pytricia",
         "speedup vs ipaddress"],
        aggregate_rows(),
    )
    print_table(
        "Index build + 1M lookups (M ops/s)",
        ["Phase", "libcidr", "ipaddress", "netaddr", "pytricia",
         "speedup vs ipaddress"],
        index_rows(),
    )


if __name__ == "__main__":
    main()
