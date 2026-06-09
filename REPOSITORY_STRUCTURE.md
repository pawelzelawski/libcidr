# Repository Structure

## 1. Top-Level Layout

```
libcidr/
├── Makefile                    # Build orchestration: dev, release, test, bench, lint, install
├── .clang-format               # Code formatting rules (KNF-based)
├── .clang-tidy                 # Static analysis configuration
├── README.md                   # User-facing introduction and quickstart
├── PROJECT.md                  # Overview, goals, scope, design philosophy
├── ARCHITECTURE.md             # Full technical architecture - types, arithmetic engine,
│                               #   bulk engine, Patricia trie, CPython binding layer,
│                               #   all API decisions and rationale
├── TECH_STACK.md               # Build system, compiler flags, sanitizer integration,
│                               #   Python extension build
├── CODING_STANDARDS.md         # C style, error handling, documentation requirements
├── REPOSITORY_STRUCTURE.md     # This file
├── DEVELOPMENT.md              # Phased build plan, milestones, per-phase task breakdown
├── TESTING.md                  # Test strategy, RFC conformance, stdlib comparison,
│                               #   sanitizer testing, performance benchmarking
├── include/                    # Public C header
├── src/                        # C library source files
├── python/                     # CPython binding layer
├── tests/                      # C and Python tests
└── bench/                      # Performance benchmarks
```

The primary build output is `libcidr.a`. A shared library target (`libcidr.so`)
is also provided. `make install` installs exactly two files: `libcidr.a` into
`$(LIBDIR)` and `include/libcidr.h` into `$(INCLUDEDIR)`. The Python extension
is built separately -- see TECH_STACK.md for the Python extension build.

---

## 2. include/ - Public C Header

```
include/
│
└── libcidr.h           # The only header a C caller includes.
                        # Self-contained: requires only <stddef.h>, <stdint.h>,
                        #   and <stdbool.h>.
                        # Declares all public types:
                        #   cidr_family_t, cidr_addr_t, cidr_prefix_t,
                        #   cidr_err_t, cidr_class_t, cidr_sort_order_t,
                        #   cidr_subnet_iter_t, cidr_index_t (opaque).
                        # Defines all CIDR_CLASS_* flag constants (1u<<0 through
                        #   1u<<22) and CIDR_IANA_SNAPSHOT. See ARCHITECTURE.md §7.2.
                        # Defines CIDR_ADDR_STR_MAX (46) and
                        #   CIDR_PREFIX_STR_MAX (50). See ARCHITECTURE.md §4.2.
                        # Declares all public functions with
                        #   __attribute__((warn_unused_result)), except
                        #   cidr_index_destroy() which returns void and is
                        #   NULL-safe. See ARCHITECTURE.md §1.4.
                        # Does NOT expose any internal types or implementation
                        #   details.
                        # See ARCHITECTURE.md for full API documentation.
```

`libcidr.h` is the entire public C surface of the library. A C caller adds
`-I/usr/local/include` (or wherever installed) and writes
`#include <libcidr.h>`. Nothing else is needed.

---

## 3. src/ - C Library Source Files

Source is organised by component. Each component maps to one `.c` file plus
the shared internal header. The public API (`include/libcidr.h`) is the only
header C callers ever include -- internal headers are never installed.

```
src/
│
│   - Shared internal definitions -
│
├── cidr_internal.h     # Internal shared types, helpers, and compile-time assertions.
│                       # Complete definitions of any types whose internals are
│                       #   needed across source files but must not be exposed
│                       #   in the public header.
│                       # _Static_assert checks on struct sizes:
│                       #   sizeof(cidr_addr_t) == 20,
│                       #   sizeof(cidr_prefix_t) == 24.
│                       # Internal helper declarations shared across components.
│                       # NOT included by callers -- internal only.
│                       # See CODING_STANDARDS.md §1.3 for assertion rules.
│
│   - Arithmetic Engine -
│
├── cidr_addr.c         # Address parsing, formatting, IPv4-mapped extraction,
│                       #   and address comparison.
│                       # cidr_addr_parse(): strict dotted-decimal (RFC 1123) for
│                       #   IPv4; full, compressed, and mixed forms (RFC 4291 /
│                       #   RFC 5952) for IPv6. Uppercase input normalised to
│                       #   lowercase on parse. See ARCHITECTURE.md §4.1.1, §4.1.2.
│                       # cidr_addr_format(): canonical dotted-decimal for IPv4;
│                       #   RFC 5952 canonical form for IPv6 including mixed
│                       #   notation for IPv4-mapped addresses. Writes into
│                       #   caller-provided buffer. See ARCHITECTURE.md §4.2.
│                       # cidr_addr_to_v4(): extracts embedded IPv4 address from
│                       #   an IPv4-mapped IPv6 address (::ffff:0:0/96). Returns
│                       #   CIDR_ERR_INVAL for CIDR_AF_UNSPEC input; CIDR_ERR_FAMILY
│                       #   for valid non-IPv6 or non-mapped IPv6 input.
│                       #   See ARCHITECTURE.md §4.1.3.
│                       # cidr_addr_cmp(): compares two addresses within the same
│                       #   family. Returns -1/0/+1 via int* output parameter.
│                       #   Lexicographic order on address bytes in network byte
│                       #   order. See ARCHITECTURE.md §4.4.
│
├── cidr_prefix.c       # Prefix construction, all prefix arithmetic operations,
│                       #   and prefix comparison.
│                       # cidr_prefix_parse(): strict CIDR parse. Returns
│                       #   CIDR_ERR_HOSTBITS if host bits are set.
│                       #   See ARCHITECTURE.md §4.1.4.
│                       # cidr_prefix_from_host(): explicit host-to-network.
│                       #   Zeros host bits; function name documents the operation.
│                       #   See ARCHITECTURE.md §4.1.4.
│                       # cidr_prefix_format(): writes canonical CIDR string
│                       #   (address + '/' + prefixlen) into caller-provided buffer.
│                       # cidr_prefix_broadcast(): IPv4 only. ORs network address
│                       #   with complement of prefix mask. Returns CIDR_ERR_FAMILY
│                       #   for IPv6. See ARCHITECTURE.md §4.3.2.
│                       # cidr_prefix_mask(): returns prefix mask as cidr_addr_t.
│                       #   See ARCHITECTURE.md §4.3.3.
│                       # cidr_prefix_first(): returns network address.
│                       # cidr_prefix_last(): returns broadcast (IPv4) or
│                       #   host-bits-all-ones (IPv6) address.
│                       #   See ARCHITECTURE.md §4.3.4.
│                       # cidr_prefix_contains(): (addr & mask) == prefix.addr.
│                       #   See ARCHITECTURE.md §4.3.5.
│                       # cidr_prefix_overlaps(): tests mutual containment.
│                       #   See ARCHITECTURE.md §4.3.6.
│                       # cidr_prefix_supernet(): returns parent at pfxlen-1.
│                       #   Returns CIDR_ERR_OVERFLOW on /0.
│                       #   See ARCHITECTURE.md §4.3.7.
│                       # cidr_subnet_iter_init(), cidr_subnet_iter_next():
│                       #   stateful stack-allocated subnet iterator. No allocation.
│                       #   CIDR_ERR_DONE signals normal exhaustion. Subnets
│                       #   enumerated in ascending network address order.
│                       #   See ARCHITECTURE.md §4.3.8.
│                       # cidr_prefix_cmp(): compares two prefixes within the same
│                       #   family. Returns -1/0/+1 via int* output parameter.
│                       #   Order: network address ascending, prefix length ascending
│                       #   within same network address (CIDR_SORT_NETWORK_ASC).
│                       #   See ARCHITECTURE.md §4.4.
│
│   - Bulk Engine -
│
├── cidr_bulk.c         # Batch parse, bulk containment, aggregation, sort.
│                       # Contains the shared radix sort engine used by both
│                       #   cidr_bulk_aggregate() and cidr_bulk_sort().
│                       # cidr_bulk_parse(): parses count address strings into
│                       #   a caller-provided cidr_addr_t array. Per-item error
│                       #   array is optional (NULL suppresses per-item errors).
│                       #   All items attempted; return-code precedence:
│                       #   CIDR_ERR_INVAL > CIDR_ERR_FAMILY > CIDR_ERR_PARSE.
│                       #   See ARCHITECTURE.md §5.2.
│                       # cidr_bulk_contains(): for each address, first-match
│                       #   linear scan over prefix table. O(n*m). Per-item error
│                       #   array optional. See ARCHITECTURE.md §5.3.
│                       # cidr_bulk_aggregate(): in-place aggregation to minimal
│                       #   covering set. Radix sort + dedup + containment removal
│                       #   + sibling merge with early termination. O(n*k).
│                       #   See ARCHITECTURE.md §5.4.
│                       # cidr_bulk_sort(): in-place radix sort with two orderings
│                       #   controlled by cidr_sort_order_t parameter.
│                       #   CIDR_SORT_NETWORK_ASC: for aggregation.
│                       #   CIDR_SORT_PFXLEN_DESC: for LPM preparation (stable;
│                       #   exact duplicates preserve input order).
│                       #   See ARCHITECTURE.md §5.5.
│                       # Radix sort key: 5 bytes for IPv4 (4 addr + 1 pfxlen),
│                       #   17 bytes for IPv6 (16 addr + 1 pfxlen).
│                       #   Stack usage: 17 * 256 * sizeof(size_t) = 34,816 bytes
│                       #   worst case for IPv6 on 64-bit platforms.
│                       #   See ARCHITECTURE.md §5.4.
│
│   - Address Classification -
│
├── cidr_classify.c     # Address classification against IANA special-purpose blocks.
│                       # cidr_addr_classify(): linear scan over compile-time
│                       #   classification table. Returns cidr_class_t bitmask.
│                       #   O(1) -- table is ~50 entries, fixed at compile time.
│                       #   See ARCHITECTURE.md §7.
│                       # Classification table encodes RFC 6890 + RFC 8190 blocks
│                       #   for both IPv4 and IPv6, plus RFC 1112 (IPv4 multicast)
│                       #   and RFC 4291 (IPv6 multicast). Table snapshot version
│                       #   documented via CIDR_IANA_SNAPSHOT in libcidr.h.
│                       #   See ARCHITECTURE.md §7.2.
│                       # CIDR_CLASS_GLOBAL set when no special-purpose block
│                       #   matched. Mutually exclusive with all other flags.
│                       #   Does not imply operational global routability.
│
│   - Patricia Trie Index -
│
└── cidr_index.c        # High-performance prefix index: LC-trie (Level-Compressed
                        # Patricia trie, Nilsson and Karlsson 1999).
                        # cidr_index_create(): builds array-packed LC-trie from
                        #   caller-provided prefix array. Copies prefix array
                        #   internally -- caller may free their array after return.
                        #   Only allocating function in the library. O(n * W).
                        #   Rejects count == 0 (no family to establish).
                        #   See ARCHITECTURE.md §6.
                        # cidr_index_destroy(): releases all trie memory.
                        #   Returns void. NULL-safe. Must be called exactly once
                        #   per successfully created index.
                        # cidr_index_lookup(): longest-prefix match for each address
                        #   in caller-provided array. Empirically O(4-8) for IPv4,
                        #   O(8-15) for IPv6 on real routing tables; worst case O(W).
                        #   Per-item error array optional. Output format identical
                        #   to cidr_bulk_contains() (index or -1 per address);
                        #   selection semantics differ (LPM vs first-match-in-order).
                        #   See ARCHITECTURE.md §6.2.
                        # Node layout: array-packed cidr_lctrie_node_t (12 bytes).
                        #   Single contiguous allocation for entire node array.
                        #   See ARCHITECTURE.md §6.3.
```

---

## 4. python/ - CPython Binding Layer

```
python/
│
└── _libcidr_ext.c      # The entire CPython binding layer. No IP arithmetic logic.
                        # Stable ABI: Py_LIMITED_API = 0x030B0000 (CPython 3.11+).
                        #   Compiled .so loads on 3.11, 3.12, 3.13, and any future
                        #   3.x release without recompilation.
                        #   See ARCHITECTURE.md §8.2.
                        #
                        # Module: libcidr. Exports CIDR_CLASS_* constants,
                        #   CIDR_IANA_SNAPSHOT, AF_INET, AF_INET6,
                        #   SORT_NETWORK_ASC, SORT_PFXLEN_DESC,
                        #   bulk_parse(), bulk_contains(), bulk_aggregate(),
                        #   bulk_sort(), bulk_contains_packed(), and all
                        #   exception types.
                        #
                        # Four Python types (PyType_FromSpec slot definitions):
                        #   IPv4Address -- embeds cidr_addr_t (20 bytes) by value.
                        #   IPv6Address -- embeds cidr_addr_t (20 bytes) by value.
                        #   IPv4Network -- embeds cidr_prefix_t (24 bytes) by value.
                        #   IPv6Network -- embeds cidr_prefix_t (24 bytes) by value.
                        #   See ARCHITECTURE.md §8.3, §8.6, §8.7.
                        #
                        # One index type:
                        #   PrefixIndex -- holds cidr_index_t * (heap-allocated,
                        #   not embedded by value). Constructor accepts list/tuple
                        #   of network objects. lookup() returns list of int.
                        #   Context manager protocol for deterministic resource
                        #   release. See ARCHITECTURE.md §8.10.
                        #
                        # One iterator type:
                        #   SubnetIterator -- embeds cidr_subnet_iter_t by value.
                        #   __iter__ returns self. __next__ raises StopIteration
                        #   on CIDR_ERR_DONE. See ARCHITECTURE.md §8.9.
                        #
                        # Exception hierarchy (PyErr_NewExceptionWithDoc calls,
                        #   bases passed as (CIDRError, BuiltinBase) tuple):
                        #   CIDRError(Exception) -- base, not raised directly.
                        #   ParseError(CIDRError, ValueError) -- CIDR_ERR_PARSE.
                        #   HostBitsError(CIDRError, ValueError) -- CIDR_ERR_HOSTBITS.
                        #   PrefixLengthError(CIDRError, ValueError) -- CIDR_ERR_PFXLEN.
                        #   InvalidArgumentError(CIDRError, ValueError) -- CIDR_ERR_INVAL.
                        #   FamilyError(CIDRError, TypeError) -- CIDR_ERR_FAMILY.
                        #   AddressOverflowError(CIDRError, OverflowError) -- CIDR_ERR_OVERFLOW.
                        #   CIDR_ERR_NOMEM -> built-in MemoryError (no custom type).
                        #   See ARCHITECTURE.md §8.5.
                        #
                        # Address constructors accept: str, bytes (4 or 16),
                        #   int (0..2^32-1 or 0..2^128-1), ipaddress object.
                        # Network constructors accept: str, (str, int) tuple,
                        #   ipaddress object. strict= keyword-only argument
                        #   (default True). See ARCHITECTURE.md §8.6.1, §8.7.1.
                        #
                        # IPv6Address.to_ipv4(): returns IPv4Address if address is
                        #   within ::ffff:0:0/96, otherwise None. Backed by
                        #   cidr_addr_to_v4(). Not present on IPv4Address.
                        #   See ARCHITECTURE.md §8.6.3.
                        #
                        # memoryview entry point bulk_contains_packed():
                        #   1D C-contiguous memoryview of packed binary addresses,
                        #   explicit family parameter, no Python object allocation
                        #   per address. See ARCHITECTURE.md §8.8.2.
                        #
                        # Ownership: address/network structs embedded by value in
                        #   PyObject allocations. PrefixIndex owns a heap-allocated
                        #   cidr_index_t * and frees it in tp_dealloc/__exit__.
                        #   See ARCHITECTURE.md §8.10, §8.11.
```

---

## 5. tests/ - C and Python Tests

```
tests/
│
├── test_harness.h      # Minimal C test harness -- no external framework.
│                       # RUN(name, fn) macro: calls fn(), records pass/fail.
│                       # Each test function returns 0 on pass, non-zero on fail.
│                       # Test binary exits 0 if all pass, 1 if any fail.
│                       # Prints "PASS: name" / "FAIL: name" per test.
│                       # Final summary: "N/M tests passed".
│
├── run_tests.c         # C test binary entry point.
│                       # Calls RUN() for every test function across all C suites.
│                       # Links against libcidr.a -- verifies exported symbols.
│                       # Prints summary and exits with pass/fail code.
│
├── test_addr.c         # cidr_addr_parse, cidr_addr_format, cidr_addr_to_v4,
│                       #   cidr_addr_cmp.
│                       # IPv4 parse: valid dotted-decimal; all rejection cases
│                       #   (leading zeros, hex, octal, whitespace, trailing chars,
│                       #   out-of-range octets, wrong octet count).
│                       # IPv6 parse: all three text forms (full, compressed, mixed);
│                       #   uppercase normalised to lowercase; :: at start, middle,
│                       #   end; single-group compression rejected; IPv4-compatible
│                       #   rejected; IPv4-mapped accepted.
│                       # cidr_addr_format: round-trip for all parse inputs;
│                       #   RFC 5952 canonical form verified for IPv6 (leading zeros,
│                       #   :: placement, tied runs, lowercase, mixed notation).
│                       # cidr_addr_to_v4: valid extraction from IPv4-mapped;
│                       #   CIDR_ERR_INVAL for CIDR_AF_UNSPEC input;
│                       #   CIDR_ERR_FAMILY for plain IPv4 input;
│                       #   CIDR_ERR_FAMILY for non-mapped IPv6; NULL pointer handling.
│                       # cidr_addr_cmp: same-family ordering; IPv4 < IPv4 < IPv4
│                       #   boundary cases; equal addresses return 0; CIDR_ERR_FAMILY
│                       #   on mixed families; CIDR_ERR_INVAL on NULL/CIDR_AF_UNSPEC.
│                       # Buffer boundary: CIDR_ADDR_STR_MAX verified to be correct.
│
├── test_prefix.c       # cidr_prefix_parse, cidr_prefix_from_host, arithmetic ops,
│                       #   cidr_prefix_cmp.
│                       # cidr_prefix_parse: valid CIDR strings; CIDR_ERR_HOSTBITS
│                       #   when host bits set; CIDR_ERR_PFXLEN on out-of-range
│                       #   prefix length; address parse errors propagated.
│                       # cidr_prefix_from_host: host bits zeroed correctly for
│                       #   all prefix lengths; /0 and /32 (/128) edge cases.
│                       # cidr_prefix_broadcast: correct for all /0 through /32;
│                       #   CIDR_ERR_FAMILY for IPv6.
│                       # cidr_prefix_mask: all prefix lengths 0..32 (IPv4) and
│                       #   0..128 (IPv6); boundary values; network byte order.
│                       # cidr_prefix_first, cidr_prefix_last: /0, /32, /128
│                       #   edge cases; IPv4 and IPv6.
│                       # cidr_prefix_contains: address inside, address outside,
│                       #   network address, broadcast address; CIDR_ERR_FAMILY.
│                       # cidr_prefix_overlaps: disjoint, adjacent, partial overlap,
│                       #   one contained in other, identical; CIDR_ERR_FAMILY.
│                       # cidr_prefix_supernet: chain from /32 to /0; CIDR_ERR_OVERFLOW
│                       #   on /0; IPv4 and IPv6.
│                       # cidr_subnet_iter: full enumeration matches expected count
│                       #   (2^(target-prefix) subnets); ascending order verified;
│                       #   early termination safe; CIDR_ERR_PFXLEN when target <=
│                       #   prefix; first and last subnet addresses correct;
│                       #   iterator state after exhaustion.
│                       # cidr_prefix_cmp: ordering consistent with
│                       #   CIDR_SORT_NETWORK_ASC; equal prefixes return 0;
│                       #   CIDR_ERR_FAMILY on mixed families.
│
├── test_bulk.c         # cidr_bulk_parse, cidr_bulk_contains, cidr_bulk_aggregate,
│                       #   cidr_bulk_sort.
│                       # cidr_bulk_parse: all items valid; partial failure with
│                       #   per-item error array; partial failure with NULL error
│                       #   array; NULL element in srcs returns CIDR_ERR_INVAL;
│                       #   mixed-family input returns CIDR_ERR_FAMILY after full
│                       #   batch; return-code precedence verified; empty array;
│                       #   single item.
│                       # cidr_bulk_contains: first-match semantics; no match (-1);
│                       #   LPM ordering when pre-sorted by CIDR_SORT_PFXLEN_DESC;
│                       #   empty prefix array writes all -1; CIDR_ERR_FAMILY on
│                       #   mixed families; NULL error array; NULL matches with
│                       #   addr_count > 0 returns CIDR_ERR_INVAL.
│                       # cidr_bulk_aggregate: known aggregation cases verified
│                       #   against ipaddress.collapse_addresses output; duplicate
│                       #   removal; containment removal; sibling merge; already-
│                       #   aggregated input (early termination path); single prefix;
│                       #   /0 input; CIDR_ERR_FAMILY on mixed families;
│                       #   NULL out_count returns CIDR_ERR_INVAL.
│                       # cidr_bulk_sort: CIDR_SORT_NETWORK_ASC order verified;
│                       #   CIDR_SORT_PFXLEN_DESC order verified with secondary
│                       #   network address key; stability (exact duplicate prefixes
│                       #   preserve input order); invalid order returns CIDR_ERR_INVAL;
│                       #   empty array; single element.
│
├── test_classify.c     # cidr_addr_classify against full IANA snapshot table.
│                       # One address from each special-purpose block yields the
│                       #   correct flag(s) and no other flags.
│                       # CIDR_CLASS_GLOBAL set for public unicast addresses; no
│                       #   other flags set.
│                       # CIDR_CLASS_GLOBAL mutually exclusive with all other flags.
│                       # Multi-flag addresses (e.g. sub-blocks of 2001::/23) yield
│                       #   all applicable flags ORed together.
│                       # Boundary addresses: first and last address of each block
│                       #   classified correctly; addresses just outside blocks
│                       #   classified correctly.
│                       # Terminated entries (192.88.99.0/24, 2001:10::/28)
│                       #   classified correctly.
│                       # IPv4 multicast (224.0.0.0/4) and IPv6 multicast
│                       #   (ff00::/8) yield CIDR_CLASS_MULTICAST.
│
├── test_index.c        # Patricia trie correctness.
│                       # Lookup result matches cidr_bulk_contains (when prefix
│                       #   array sorted by CIDR_SORT_PFXLEN_DESC) for all inputs.
│                       # Longest-prefix match semantics: most specific prefix
│                       #   returned when multiple match, including prefix stored
│                       #   at interior nodes.
│                       # No match returns -1.
│                       # Index preserves original array indices.
│                       # cidr_index_create with count == 0 returns CIDR_ERR_INVAL.
│                       # cidr_index_create with single prefix; full routing table
│                       #   scale (smoke test with 100k prefixes).
│                       # Duplicate prefix handling: lower input index returned.
│                       # CIDR_ERR_FAMILY on mixed-family input.
│                       # cidr_index_destroy NULL-safe.
│                       # Memory clean under Valgrind/ASan after destroy.
│
├── test_python.py      # Python binding layer correctness.
│                       # Uses unittest. Compared against ipaddress stdlib for all
│                       #   operations where ipaddress behaviour is the reference.
│                       # Constructor forms: string, bytes, int, ipaddress object.
│                       #   Family mismatch raises FamilyError.
│                       # Properties: packed, compressed, exploded, version,
│                       #   is_global, is_private, is_loopback, is_multicast,
│                       #   is_link_local, is_unspecified.
│                       # classify(): bitmask matches expected CIDR_CLASS_* flags.
│                       # IPv6Address.to_ipv4(): returns IPv4Address for mapped
│                       #   addresses; returns None for non-mapped; not present on
│                       #   IPv4Address.
│                       # Network constructors: strict=True (default) raises
│                       #   HostBitsError; strict=False zeroes host bits; tuple form;
│                       #   ipaddress object ignores strict parameter.
│                       # Network properties: network_address, broadcast_address,
│                       #   prefixlen, netmask, with_prefixlen, num_addresses.
│                       # Network methods: overlaps, supernet, subnets, contains.
│                       # subnets(prefixlen=n) equivalent to
│                       #   ipaddress.subnets(new_prefix=n).
│                       # __contains__: addr in network syntax.
│                       # Protocol: __str__, __repr__, __eq__, __hash__, __lt__,
│                       #   sortable, usable as dict key and set member.
│                       # bulk_parse, bulk_contains, bulk_aggregate, bulk_sort.
│                       # bulk_parse: all items attempted; error raised after batch.
│                       # bulk_contains_packed: memoryview input; element size
│                       #   mismatch raises InvalidArgumentError; non-contiguous
│                       #   memoryview raises InvalidArgumentError.
│                       # Exception hierarchy: catch at CIDRError level; catch at
│                       #   built-in level (ValueError, TypeError, OverflowError).
│                       # ipaddress compatibility: one-way construction from
│                       #   ipaddress objects for all four types.
└── (run via: python -m pytest tests/test_python.py or make test-python)
```

---

## 6. bench/ - Performance Benchmarks

Benchmarks are built separately under release flags. They do not run as part
of `make test`. Each benchmark prints results with hardware context (CPU model,
core count, clock speed) so numbers are not compared across machines without
this context.

```
bench/
│
├── bench_bulk.c        # C-level bulk operation throughput.
│                       # cidr_bulk_aggregate: prefixes per second at varying n
│                       #   (1k, 10k, 100k, 800k). Measures radix sort + merge.
│                       # cidr_bulk_contains: addresses per second at varying
│                       #   prefix table sizes (100, 1k, 10k prefixes).
│                       # cidr_bulk_sort: sort throughput for both orderings.
│                       # Early termination path: already-aggregated input measured
│                       #   separately to quantify the O(n) detection cost.
│
├── bench_index.c       # Patricia trie vs linear scan crossover benchmark.
│                       # cidr_index_lookup vs cidr_bulk_contains at varying
│                       #   prefix table sizes (100 through 800k).
│                       # Identifies the crossover point where trie build cost
│                       #   is amortised. Documents recommended threshold for
│                       #   TESTING.md and README.md guidance.
│                       # Lookup throughput: queries per second at routing table
│                       #   scale (800k prefixes).
│
└── bench_python.py     # Python binding layer vs ipaddress, netaddr, pytricia.
                        # Benchmark targets: ipaddress (stdlib), netaddr, pytricia.
                        # Operations compared:
                        #   Single address parse from string.
                        #   Bulk parse: 100k addresses.
                        #   Bulk containment: 100k addresses vs 10k prefixes.
                        #   Prefix aggregation: 50k prefixes.
                        #   Patricia trie build + 1M lookups (libcidr only).
                        # Results formatted as a comparison table with speedup
                        #   multipliers. Used to validate library value proposition.
                        # See TESTING.md for benchmarking methodology and
                        #   reproducibility requirements.
```

---

## 7. Top-Level Files

### Makefile

Single top-level Makefile. No per-directory Makefiles. Platform and
architecture detected at build time.

```makefile
# Key targets
make              # same as make release -- builds libcidr.a
make dev          # debug build with ASan/UBSan
make release      # optimised build
make shared       # shared library -- libcidr.so
make test         # build and run C tests (dev flags)
make test-python  # run Python binding tests (requires Python extension built)
make test-tsan    # build and run C tests under ThreadSanitizer (Clang only)
make valgrind     # run C tests under Valgrind (Linux only)
make bench        # build and run C benchmarks (release flags)
make bench-python # run Python benchmarks (release flags)
make lint         # clang-tidy + cppcheck on src/ and python/
make format       # clang-format on src/*.c src/*.h include/libcidr.h
make clean        # remove build artifacts
make install      # install libcidr.a and include/libcidr.h to PREFIX
```

Platform detected via `$(shell uname)`. Architecture detected via
`$(shell uname -m)`. `make install` installs exactly two files -- `libcidr.a`
into `$(LIBDIR)` and `libcidr.h` into `$(INCLUDEDIR)` -- and nothing else.
The Python extension is built separately via the Python extension build (see
TECH_STACK.md).

### .clang-format

KNF-based formatting rules consistent with the project's OpenBSD KNF
code style requirement:

```yaml
BasedOnStyle: LLVM
IndentWidth: 8
UseTab: ForIndentation
BreakBeforeBraces: Linux
ColumnLimit: 80
AllowShortFunctionsOnASingleLine: None
AllowShortIfStatementsOnASingleLine: Never
```

### .clang-tidy

```yaml
Checks: >
  clang-analyzer-*,
  cert-*,
  bugprone-*,
  performance-*,
  portability-*,
  -cert-err33-c,
  -bugprone-easily-swappable-parameters
```

---

## 8. Component-to-File Mapping

| Component | Description | Source file |
|---|---|---|
| Address parsing, formatting, comparison | cidr_addr_parse, cidr_addr_format, cidr_addr_to_v4, cidr_addr_cmp | `src/cidr_addr.c` |
| Prefix construction, arithmetic, comparison | cidr_prefix_parse, cidr_prefix_from_host, all arithmetic ops, subnet iter, cidr_prefix_cmp | `src/cidr_prefix.c` |
| Bulk engine | cidr_bulk_parse, cidr_bulk_contains, cidr_bulk_aggregate, cidr_bulk_sort, radix sort engine | `src/cidr_bulk.c` |
| Address classification | cidr_addr_classify, IANA snapshot table | `src/cidr_classify.c` |
| Patricia trie index | cidr_index_create, cidr_index_destroy, cidr_index_lookup | `src/cidr_index.c` |
| Internal shared types | Internal headers, _Static_assert checks | `src/cidr_internal.h` |
| Public C API | All public types, constants, and function declarations | `include/libcidr.h` |
| CPython binding layer | All four Python types, iterator, bulk entry points, exceptions | `python/_libcidr_ext.c` |

---

## 9. Naming Conventions Across Files

Function names are prefixed by their module. This makes `grep` and code
navigation unambiguous across the codebase.

| Module | File | Internal prefix | Example |
|---|---|---|---|
| Address | `src/cidr_addr.c` | `addr_` | `addr_parse_ipv4()` |
| Prefix | `src/cidr_prefix.c` | `prefix_` | `prefix_mask_compute()` |
| Bulk | `src/cidr_bulk.c` | `bulk_` / `radix_` | `radix_sort_ipv4()` |
| Classification | `src/cidr_classify.c` | `classify_` | `classify_lookup()` |
| Index | `src/cidr_index.c` | `index_` / `trie_` | `trie_node_alloc()` |

Public API functions (declared in `include/libcidr.h`) use the `cidr_` prefix
throughout. No internal function name begins with `cidr_` -- that prefix is
reserved exclusively for the public API.

| Public namespace | Functions |
|---|---|
| `cidr_addr_` | `cidr_addr_parse`, `cidr_addr_format`, `cidr_addr_to_v4`, `cidr_addr_cmp`, `cidr_addr_classify` |
| `cidr_prefix_` | `cidr_prefix_parse`, `cidr_prefix_from_host`, `cidr_prefix_format`, `cidr_prefix_broadcast`, `cidr_prefix_mask`, `cidr_prefix_first`, `cidr_prefix_last`, `cidr_prefix_contains`, `cidr_prefix_overlaps`, `cidr_prefix_supernet`, `cidr_prefix_cmp` |
| `cidr_subnet_iter_` | `cidr_subnet_iter_init`, `cidr_subnet_iter_next` |
| `cidr_bulk_` | `cidr_bulk_parse`, `cidr_bulk_contains`, `cidr_bulk_aggregate`, `cidr_bulk_sort` |
| `cidr_index_` | `cidr_index_create`, `cidr_index_destroy`, `cidr_index_lookup` |

---

**See Also**: PROJECT.md, ARCHITECTURE.md, TECH_STACK.md, CODING_STANDARDS.md,
DEVELOPMENT.md, TESTING.md
