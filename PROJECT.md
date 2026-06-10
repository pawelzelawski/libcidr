# libcidr

## Overview

libcidr is a C11 library for IPv4 and IPv6 address arithmetic, CIDR
manipulation, and bulk prefix operations. It provides strict RFC-compliant
parsing and formatting, prefix arithmetic, bulk containment and aggregation,
high-performance prefix indexing via a Patricia trie, and address
classification against the IANA special-purpose registries. It has no
routing protocol knowledge, no network I/O, and no DNS resolution.

libcidr is usable as a standalone C11 library and as a CPython extension.
The C library has no Python dependency. The Python binding is a separate
compilation unit that wraps the C public API with no logic of its own. A
C application can link against libcidr directly without building the Python
extension.

The design philosophy is the same as the rest of this author's infrastructure
libraries: zero mandatory third-party dependencies, strict RFC semantics,
explicit ownership contracts, first-class OpenBSD support, and code that can
be audited, understood, and trusted.

## Philosophy

### The Problem This Library Solves

Python developers reach for `ipaddress` because it is correct. They hit a
performance wall when input volume grows. The only C alternatives are narrow
trie tools covering one slice of what they need - longest-prefix-match lookup
only, not general address arithmetic. No production-grade, zero-dependency C
extension covering the full IPv4/IPv6 address and CIDR arithmetic surface
exists in the Python ecosystem.

The gap is not that IPv4/IPv6 arithmetic is an unsolved problem. The gap is
that no C library exists offering the complete address and CIDR arithmetic
surface - parsing, formatting, containment, aggregation, bulk operations -
with correct RFC semantics and Python bindings that do not require NumPy or
any other external dependency.

The pain is concrete and well-documented:

- Network security tooling evaluates firewall rules against large CIDR tables.
  Pure Python throughput is the bottleneck; a C implementation is expected to
  reduce per-evaluation latency by orders of magnitude.
- Log enrichment pipelines enrich millions of records with prefix metadata.
  Pure Python throughput is the bottleneck at scale.
- BGP prefix analysis operates on full routing tables of 800,000+ prefixes.
  Aggregation and overlap detection are impractical in pure Python.
- Data engineering enriches large datasets with network metadata indexed by
  IP prefix. Pure Python processing is the throughput ceiling.

The pattern is consistent: Python developers reach for `ipaddress` because
it is correct, hit the performance wall when input volume grows, and find
that the only C alternatives are narrow trie tools covering only one slice
of what they need.

### Primary Goal

The primary goal is **correctness** - parsing and arithmetic behaviour derived
precisely from RFC 791, RFC 1123, RFC 4291, RFC 4632, RFC 5952, RFC 1918,
RFC 4193, RFC 6890, and RFC 8190. No undocumented textual form acceptance.
No silent data normalisation. No behaviour that cannot be traced to a specific
RFC clause.

The correctness target for individual address and network objects is stdlib
`ipaddress`. Any result that differs from `ipaddress` for a given RFC-conforming
input within the documented supported property and method subset is a bug, not
a design choice. Documented exclusions - such as non-RFC parsing forms, full
duck-type compatibility, and integer network constructors - are intentional
and are not bugs.

The secondary goal is **performance** - a C implementation that is an order
of magnitude faster than pure Python for bulk operations, with a Patricia trie
index that reduces prefix lookup from O(n) linear scan to O(address length)
per query.

### Design Priorities

In order, from highest to lowest:

1. **Correctness** - RFC semantics, no exceptions.
2. **Security** - no undefined behaviour, no memory errors, Valgrind clean,
   ASan/UBSan clean on both platforms.
3. **Performance** - object-allocation-free bulk operations, radix sort for
   aggregation, Patricia trie for high-scale prefix lookup.
4. **Ease of use** - idiomatic Python API, stdlib `ipaddress` compatibility
   for individual objects, no surprises for Python developers.

### RFC-First

Every parsing and formatting behaviour is derived from the relevant RFC.
Where an RFC is silent, the behaviour is documented explicitly and justified.
No textual form is accepted that is not defined in the RFCs. No textual form
is produced that does not conform to the canonical representation specified
in RFC 5952 for IPv6 and RFC 1123 for IPv4.

### API Safety

The API must make correct usage the only natural usage. It must be impossible
to accidentally use the library in a way that degrades its algorithmic
complexity guarantees. Bulk operations accept contiguous caller-provided
arrays. Iterator-based operations expose state on the caller's stack. No
hidden allocation occurs after initialisation. No hidden sort or scan occurs
inside any operation whose complexity the caller has not explicitly accepted.

### Two-Layer Architecture

The C library is usable independently of Python. The CPython extension is a
pure binding layer with no logic of its own. All arithmetic, parsing,
formatting, and indexing logic lives in the C library and is accessible
through the C public API to any C caller. The Python layer translates Python
types to C types, calls the C API, and translates results back.

This means libcidr is usable in other C projects - kvd, wraith, or any future
project in this ecosystem - by linking against `libcidr.a` and including
`libcidr.h`. No Python required.

### Caller Owns Memory

The C library writes all output into caller-provided buffers. No allocation
occurs inside any operation except `cidr_index_create()`, which builds a
Patricia trie from a caller-provided prefix array and is explicitly documented
as an allocating operation. All other functions are allocation-free.

### Core Principles

1. **Strict RFC semantics, always.** Parsing and formatting behaviour is
   derived from the RFCs. No undocumented form is accepted or produced.
   Uppercase IPv6 input is accepted and normalised to lowercase on output
   per RFC 5952. IPv4-compatible IPv6 addresses are rejected per RFC 4291
   deprecation.

2. **Errors are returned, never fatal.** All public functions except
   `cidr_index_destroy()` return `cidr_err_t`. Zero is always success. The
   library does not call `abort()` or `exit()`. Every failure condition has a
   named error code. `cidr_index_destroy()` returns `void` and is NULL-safe;
   destructors have no meaningful failure mode to report.

3. **Unchecked return values are a compiler warning.** All public functions
   except `cidr_index_destroy()` carry `__attribute__((warn_unused_result))`.
   Ignoring a return value is a build warning, not a silent runtime failure.

4. **Host bits are enforced at construction.** A `cidr_prefix_t` always
   has host bits zeroed. This invariant is established at construction and
   never re-checked. Two construction paths exist: `cidr_prefix_parse()`
   rejects input with host bits set; `cidr_prefix_from_host()` accepts a
   host address and explicitly zeros host bits.

5. **Family mismatch is always an error.** Passing an IPv6 address to an
   IPv4 operation, or mixing families in a bulk operation, returns
   `CIDR_ERR_FAMILY`. There is no implicit coercion between address families.

6. **No allocation in bulk paths.** Bulk operations write into caller-provided
   output arrays. Per-item error reporting uses a caller-provided parallel
   error array. Passing NULL for the error array is valid and suppresses
   per-item error reporting at zero overhead.

7. **Complexity is explicit.** Every operation's algorithmic complexity is
   documented. No hidden sort, scan, or allocation occurs inside any function
   without documentation. The caller always knows what they are invoking.

## Internal Components

libcidr is organised around four components in the C library and one binding
layer. They have defined responsibilities and clean interfaces between them.

### Address and Prefix Types

Two fundamental types underpin the entire library. `cidr_addr_t` represents
a single IPv4 or IPv6 address: a family discriminator and a union of a 4-byte
IPv4 array and a 16-byte IPv6 array, both in network byte order. `cidr_prefix_t`
represents a CIDR prefix: a `cidr_addr_t` with host bits guaranteed zero and
a prefix length. All arithmetic operates on these two types.

### Arithmetic Engine

Parsing, formatting, and prefix arithmetic. Parsing is strict RFC-only.
Formatting produces canonical RFC 5952 output for IPv6 and RFC 1123 output
for IPv4 into caller-provided buffers. Arithmetic covers network address,
broadcast address, prefix mask, first and last address, containment, overlap,
supernet, and subnet enumeration via a stateful stack-allocated iterator.

### Bulk Engine

Batch parse, bulk containment, prefix aggregation, and prefix sort.
All operations work on caller-provided contiguous arrays. Aggregation uses
radix sort - O(n * k) on fixed-width keys - followed by a linear merge pass with
early termination. Deduplication is internal to aggregation and has no
standalone public API. Sort exposes two orderings: network-address-ascending for
aggregation and prefix-length-descending for longest-prefix-match preparation.

### Patricia Trie Index

A prefix index structure for high-performance bulk containment. Built once
from a caller-provided prefix array via `cidr_index_create()`. Lookup is
O(address length) per query - O(32) for IPv4, O(128) for IPv6, effectively
O(1) - versus O(n) for the linear bulk containment scan. The trie is
implemented in a late phase after the arithmetic and bulk engines are complete
and verified. Designed for routing-table-scale workloads (800,000+ prefixes).

### CPython Binding Layer

A thin `.c` translation unit. No logic. Converts Python objects to C types,
calls the C API, converts results back to Python objects, maps `cidr_err_t`
values to Python exceptions. Uses the CPython stable ABI (`Py_LIMITED_API`)
for forward compatibility across CPython versions.

## What libcidr Is For

libcidr is aimed at:

- **Network security tooling** - firewall rule evaluation, IP reputation
  lookup, access control list processing against large CIDR tables.
- **Log enrichment pipelines** - enriching high-volume network logs with
  prefix, ASN, or region metadata derived from routing tables.
- **BGP prefix analysis** - aggregation, overlap detection, and supernet
  computation over full routing tables.
- **Network automation** - generating firewall rules, ACLs, or routing
  configurations from CIDR inputs where correctness is as important as speed.
- **Security scanners** - expanding CIDR ranges, filtering, deduplicating
  targets at scale.
- **Data engineering** - enriching large datasets with network metadata
  indexed by IP prefix.
- **C infrastructure projects** - any C application needing correct, fast
  IP address arithmetic without pulling in a heavy dependency.

libcidr is **not** aimed at:

- Routing protocol implementation of any kind.
- Network I/O - no sockets, no packet capture.
- Interface or address-lifecycle metadata.
- WHOIS, RIR, or ASN data retrieval.
- DNS reverse mapping.
- Applications that need only a single address or prefix operation and have
  no performance requirement - `ipaddress` is correct and sufficient for
  those cases.

## What libcidr Explicitly Does Not Do

- No routing protocol logic of any kind
- No network I/O - no sockets, no packet capture
- No interface or address-lifecycle metadata
- No WHOIS, RIR, or ASN data
- No DNS reverse mapping helpers
- No NumPy integration - the Python layer works on plain Python sequences
- No dynamic allocation after index creation - all bulk paths are
  allocation-free
- No silent data normalisation - host bits set in a prefix parse is an
  error, not a quiet fix
- No implicit family coercion - IPv4 and IPv6 are always kept distinct
- No undocumented textual form acceptance - strict RFC-only parsing

## Relevant Specifications

| RFC / Standard | Subject |
|---|---|
| RFC 791 | Internet Protocol (IPv4 wire format) |
| RFC 1123 | Host Requirements - IPv4 dotted-decimal text format |
| RFC 4291 | IP Version 6 Addressing Architecture |
| RFC 5952 | A Recommendation for IPv6 Address Text Representation |
| RFC 4632 | Classless Inter-Domain Routing (CIDR) |
| RFC 1918 | Address Allocation for Private Internets |
| RFC 4193 | Unique Local IPv6 Unicast Addresses |
| RFC 6890 | Special-Purpose IP Address Registries |
| RFC 8190 | Updates to the Special-Purpose IP Address Registries |

## Current Status

**Architecture complete. Documentation in progress. Implementation not yet started.**

| Phase | Name | Status |
|---|---|---|
| - | Architecture | COMPLETE |
| - | Documentation | IN PROGRESS |
| 1 | Foundation and types | NOT STARTED |
| 2 | Parsing and formatting | NOT STARTED |
| 3 | Prefix arithmetic | NOT STARTED |
| 4 | Bulk engine | NOT STARTED |
| 5 | Address classification | NOT STARTED |
| 6 | Patricia trie index | NOT STARTED |
| 7 | CPython binding layer | NOT STARTED |
| 8 | Hardening, benchmarks, and release | NOT STARTED |

## Relationship to Existing Libraries

### stdlib `ipaddress`

The correctness reference. Pure Python throughout. Object-allocation overhead
makes bulk operations an order of magnitude slower than a C implementation.
Not designed for vectorized or buffer-oriented workflows. libcidr matches
`ipaddress` semantics for RFC-conforming inputs within the explicitly supported
property and method subset. Full duck-type compatibility is explicitly out of
scope; documented exclusions are intentional.

### `netaddr`

Broader feature set than stdlib but also pure Python. Accepts a wider range
of textual forms than the RFCs specify - a correctness liability. libcidr
rejects non-RFC forms by design.

### `pytricia` and `py-radix`

C extensions for Patricia trie longest-prefix-match lookup. Narrow scope -
lookup only. Do not cover address parsing, formatting, containment arithmetic,
or aggregation. Maintenance is sporadic. libcidr covers the full arithmetic
surface and includes a Patricia trie index as one component among several.

### `CIDR-Man`

Pure Python replacement for `ipaddress`. Measurably faster than stdlib for
some operations but still pure Python. Not a C extension.

## License

ISC License. Simple, permissive, compatible with OpenBSD philosophy.

## Document Index

| Document | Audience | Purpose |
|---|---|---|
| PROJECT.md | Both | Overview, goals, scope, design philosophy (this file) |
| ARCHITECTURE.md | Implementer | Full internal architecture - types, arithmetic engine, bulk engine, Patricia trie, CPython binding layer |
| TECH_STACK.md | Implementer | Build system, compiler flags, sanitizer integration, Python extension build |
| CODING_STANDARDS.md | Implementer | C11 style, naming, error handling, documentation requirements |
| REPOSITORY_STRUCTURE.md | Implementer | Directory layout, file-by-file descriptions, component-to-file mapping |
| DEVELOPMENT.md | Implementer | Phased build plan, milestones, per-phase tasks, test requirements |
| TESTING.md | Implementer primary, reviewer secondary | Test strategy, unit and property-based tests, RFC conformance, stdlib comparison, sanitizer testing, platform testing |

---
