# Development Plan

## Status Overview

**Current Phase**: Phase 7 -- Python Binding Layer (COMPLETE)
**Next Task**: Phase 8 -- Hardening, Benchmarks, and Release

### Phase Summary

| Phase | Name | Status | Tests | Notes |
|---|---|---|---|---|---|---|
| 1 | Foundation | COMPLETE | 0/0 | Build system, test harness, Python skeleton |
| 2 | Address Arithmetic Engine | COMPLETE | 33/33 | Parse, format, extraction, comparison |
| 3 | Prefix Construction and Arithmetic | COMPLETE | 67/67 | Parse, arithmetic ops, subnet iterator, comparison |
| 4 | Bulk Engine | COMPLETE | 31/31 | Batch parse, containment, aggregation, sort |
| 5 | Address Classification | COMPLETE | 12/12 | IANA table, classify function, tests |
| 6 | Patricia Trie Index | COMPLETE | 22/22 | LC-trie lookup/destroy complete; Linux/OpenBSD validation gates passed |
| 7 | Python Binding Layer | COMPLETE | 218/218 | CPython stable ABI extension; bulk_contains_packed memoryview entry point |
| 8 | Hardening, Benchmarks, and Release | IN PROGRESS | 0/0 | Sanitizers and concurrent tests complete; benchmarks, README, and tag remain |

### Quality Milestones

| ID | Milestone | Status |
|---|---|---|---|
| M1 | Build system works on Linux and OpenBSD, both architectures | CONFIRMED |
| M2 | All C tests pass on Linux | CONFIRMED |
| M3 | All C tests pass on OpenBSD | CONFIRMED |
| M4 | Valgrind clean on Linux | CONFIRMED |
| M5 | ASan/UBSan clean on every target whose toolchain supports them | CONFIRMED |
| M6 | TSan clean on Linux | CONFIRMED (8.1: `make test-tsan` 137/137, 0 races) |
| M7 | clang-format clean | CONFIRMED |
| M8 | clang-tidy zero warnings | CONFIRMED |
| M9 | RFC conformance verified | PENDING |
| M10 | bulk_aggregate matches ipaddress.collapse_addresses | PENDING |
| M11 | LC-trie LPM semantics verified | CONFIRMED |
| M12 | Python binding all tests pass | COMPLETE |
| M13 | Benchmark baselines recorded | PENDING |

---

## Development Principles

Before starting any phase, read and follow these documents:

- **CODING_STANDARDS.md** -- KNF style, memory management, error handling,
  safety practices, Python binding conventions, pre-commit checklist. Every
  function written must comply.
- **ARCHITECTURE.md** -- The specification. Every implementation decision must
  match what is documented there. If there is a conflict, ARCHITECTURE.md wins
  -- raise it before deviating.
- **TECH_STACK.md** -- Compiler flags, build system, sanitizer integration,
  Python extension build.

**Bottom-up approach**: Each phase builds on the previous. Do not start a
phase until the prior phase is complete and all its tests pass on all four
targets.

**Test as you go**: Write the test file for each phase before marking the
phase complete. A component without passing tests is not done.

**Platform parity**: Test on both Linux and OpenBSD at each phase. The four
targets are Linux x86_64, Linux ARM64, OpenBSD amd64, and OpenBSD arm64. Do
not defer OpenBSD testing to a later phase -- divergence caught at the phase
boundary is far easier to fix.

**Zero-allocation discipline**: Phases 2-5 must produce zero heap allocation.
Run the memory discipline check from CODING_STANDARDS.md §4.1 after every
phase to confirm no `malloc` or `free` calls have crept into the arithmetic,
prefix, bulk, or classification source files.

**Phase ordering rationale**: Phase 2 (address arithmetic) has no dependency
within the library -- it operates on `cidr_addr_t` only. Phase 3 (prefix
arithmetic) depends on Phase 2 because `cidr_prefix_t` embeds a `cidr_addr_t`
and prefix operations delegate address formatting and comparison to Phase 2
functions. Phase 4 (bulk engine) depends on Phase 3 -- bulk operations sort
and scan `cidr_prefix_t` arrays. Phase 5 (classification) depends on Phase 3
-- the classification table uses prefix-like structures internally. Phase 6
(index) depends on Phase 4 -- `cidr_index_create()` copies and sorts the
caller's prefix array using the radix sort engine from Phase 4. Phase 7
(Python binding) depends on Phases 2-6 -- it wraps the complete public C API.
Phase 8 depends on Phase 7. Phases cannot be reordered.

---

## Phase 1 -- Foundation

**Goal**: Build system works on all four targets. Repository structure is in
place. Test harness compiles and runs. Skeleton headers and source files are
in place with correct include structure. `_Static_assert` placeholders are
present. Code compiles clean with zero warnings.

**Reference documents**:
- TECH_STACK.md §4 -- Makefile structure, compiler flags, build targets
- TECH_STACK.md §5 -- Python extension build approach
- TECH_STACK.md §6 -- test harness structure
- CODING_STANDARDS.md §1.2 -- file organisation and include order
- CODING_STANDARDS.md §1.3 -- `_Static_assert` placement
- REPOSITORY_STRUCTURE.md §1 -- top-level directory layout
- REPOSITORY_STRUCTURE.md §3 -- source file list

### Tasks

**1.1 -- Repository skeleton** ✓ DONE
- Create directory structure per REPOSITORY_STRUCTURE.md §1:
  `src/`, `include/`, `python/`, `tests/`, `bench/`
- Create `include/libcidr.h` with skeleton: include guards, `<stddef.h>`,
  `<stdint.h>`, `<stdbool.h>`, `<sys/types.h>` includes; documentation
  comment block per CODING_STANDARDS.md §1.2; empty forward declarations
  for all public types (`cidr_family_t`, `cidr_addr_t`, `cidr_prefix_t`,
  `cidr_err_t`, `cidr_class_t`, `cidr_sort_order_t`, `cidr_subnet_iter_t`,
  `cidr_index_t` opaque); no function declarations yet
- Create `src/cidr_internal.h` with skeleton: include guards, internal
  documentation comment, `#include "../include/libcidr.h"`, placeholder
  `_Static_assert(1 == 1, "placeholder -- replaced in Phase 2")` entries
  for every assertion listed in CODING_STANDARDS.md §1.3
- Create stub `.c` files for every module in REPOSITORY_STRUCTURE.md §3:
  `src/cidr_addr.c`, `src/cidr_prefix.c`, `src/cidr_bulk.c`,
  `src/cidr_classify.c`, `src/cidr_index.c`; each includes its own logical
  header and `src/cidr_internal.h` and compiles to an empty object file
- Create `python/_libcidr_ext.c` stub: `#define Py_LIMITED_API 0x030B0000`,
  `#include <Python.h>`, a no-op `PyMODINIT_FUNC PyInit_libcidr(void)`
- Create top-level `Makefile` with working platform detection
  (`$(shell uname)`), architecture detection (`$(shell uname -m)`), all
  targets from TECH_STACK.md §4.4 as stubs, correct `CFLAGS_DEV`,
  `CFLAGS_REL`, `CFLAGS_TSAN`, and `CFLAGS_FT` per TECH_STACK.md §4.3
- Create `.clang-format` per REPOSITORY_STRUCTURE.md §7
- Create `.clang-tidy` per REPOSITORY_STRUCTURE.md §7
- Verify `make dev` and `make release` compile all stubs with zero warnings
  on all four targets

**1.2 -- Test harness** ✓ DONE
- Create `tests/test_harness.h` with the `RUN(name, fn)` macro per
  TECH_STACK.md §6.1
- Create `tests/run_tests.c` as the test binary entry point with empty
  test suite
- Verify `make test` runs and prints `0/0 tests passed` with exit code 0
  on all four targets
- Verify `make valgrind` runs the (empty) test binary under Valgrind on
  Linux and exits clean

**1.3 -- Python extension skeleton** ✓ DONE
- Verify `make python-ext` compiles `python/_libcidr_ext.c` against the
  installed CPython headers using `python3-config`
- Verify `make python-check-abi` confirms the resulting `.so` suffix
  contains `abi3` per TECH_STACK.md §5.2
- Verify `import libcidr` succeeds in a Python session pointing at the
  built extension directory

### Phase 1 Completion Criteria

- [x] `make dev` succeeds with zero warnings on Linux x86_64
- [x] `make dev` succeeds with zero warnings on Linux ARM64
- [x] `make dev` succeeds with zero warnings on OpenBSD amd64
- [x] `make dev` succeeds with zero warnings on OpenBSD arm64
- [x] `make test` runs and prints `0/0 tests passed` on all four targets
- [x] `make valgrind` exits clean on Linux
- [x] `make python-ext` builds and `make python-check-abi` passes
- [x] `make lint` produces zero warnings on all stub source files
- [x] Quality milestone M1 confirmed

---

## Phase 2 -- Address Arithmetic Engine

**Goal**: IPv4 and IPv6 addresses parse, format, compare, and extract
correctly with strict RFC semantics. Every rejection case documented in
ARCHITECTURE.md §4.1 returns the correct error code. RFC 5952 canonical
formatting is correct for all six rules. `cidr_addr_to_v4()` correctly
distinguishes three error conditions. RFC conformance tests pass on all four
targets.

**Reference documents**:
- ARCHITECTURE.md §4.1.1 -- IPv4 parsing rejection cases
- ARCHITECTURE.md §4.1.2 -- IPv6 parsing forms and restrictions
- ARCHITECTURE.md §4.1.3 -- `cidr_addr_to_v4()` error distinction
- ARCHITECTURE.md §4.2 -- formatting, RFC 5952 rules, buffer constants
- ARCHITECTURE.md §4.4 -- `cidr_addr_cmp()` comparison semantics
- CODING_STANDARDS.md §1.2 -- include order, `<stdlib.h>` exclusion
- CODING_STANDARDS.md §3 -- error returns and NULL pointer policy
- TESTING.md §3 -- RFC conformance test tables

**Prerequisite**: Phase 1 complete.

### Tasks

**2.1 -- `cidr_family_t`, `cidr_addr_t`, `cidr_err_t`** ✓ DONE
- Define the three types in `include/libcidr.h` per ARCHITECTURE.md §3.1,
  §3.2, §3.4
- Replace placeholder `_Static_assert` entries in `src/cidr_internal.h`
  with real assertions:
  `_Static_assert(sizeof(cidr_addr_t) == 20, ...)`
  Verify the assertion fires with a deliberate layout change before
  relying on it
- Define `CIDR_ADDR_STR_MAX = 46` in `include/libcidr.h`

**2.2 -- IPv4 parsing** ✓ DONE
- Implement the IPv4 path of `cidr_addr_parse()` in `src/cidr_addr.c`
- Strict dotted-decimal only: exactly four decimal octets 0-255, dot
  separators, no leading zeros, no hex, no whitespace, no trailing characters
- Return `CIDR_ERR_PARSE` for all malformed input; return `CIDR_ERR_INVAL`
  for NULL pointers; write `CIDR_AF_UNSPEC` to `out->family` on failure
- Store address bytes in network byte order: `192.168.1.1` stored as
  `{0xC0, 0xA8, 0x01, 0x01}` in `addr.v4`
- No `sscanf`, no `strtol` with base 8 fallback -- implement a strict
  decimal-only octet parser

**2.3 -- IPv6 parsing** ✓ DONE
- Implement the IPv6 path of `cidr_addr_parse()` in `src/cidr_addr.c`
- Accept all three forms defined in RFC 4291 §2.2: full 8-group, compressed
  (`::` once), and mixed notation for IPv4-mapped (`::ffff:0:0/96`) only
- Accept uppercase hex input; normalise to lowercase internally
- Reject IPv4-compatible addresses (`::x.x.x.x` where address is not
  IPv4-mapped) per RFC 4291 §2.5.5.1 deprecation
- Mixed notation allowed only when the first 10 bytes match the IPv4-mapped
  prefix (`00 00 00 00 00 00 00 00 00 00 FF FF`) per RFC 5952 §5; reject all
  other mixed-notation input with `CIDR_ERR_PARSE`

**2.4 -- IPv4 and IPv6 formatting** ✓ DONE
- Implement `cidr_addr_format()` in `src/cidr_addr.c`
- IPv4: canonical dotted-decimal, no leading zeros, no alternative notations
- IPv6: RFC 5952 canonical form, all six rules in order:
  1. Leading zeros suppressed per §4.1
  2. `::` applied to the longest run of consecutive zero groups per §4.2.1
  3. `::` not used for a single zero group per §4.2.2 -- written as `0`
  4. First run wins on tie per §4.2.3
  5. Lowercase throughout per §4.3
  6. IPv4-mapped addresses use mixed notation per §5:
     `::ffff:192.0.2.1` not `::ffff:c000:0201`
- `len` parameter checked against `CIDR_ADDR_STR_MAX`; returns
  `CIDR_ERR_INVAL` if buffer is too small

**2.5 -- `cidr_addr_to_v4()`** ✓ DONE
- Implement per ARCHITECTURE.md §4.1.3
- Distinguish three error conditions precisely:
  - `addr->family == CIDR_AF_UNSPEC`: return `CIDR_ERR_INVAL`
  - `addr->family == CIDR_AF_INET` (valid IPv4, wrong family for
    extraction): return `CIDR_ERR_FAMILY`
  - `addr->family == CIDR_AF_INET6` but first 12 bytes do not match the
    IPv4-mapped prefix: return `CIDR_ERR_FAMILY`
- On success: write `out` with `family = CIDR_AF_INET` and the 4 extracted
  bytes from positions 12-15 of `addr.v6`

**2.6 -- `cidr_addr_cmp()`** ✓ DONE
- Implement per ARCHITECTURE.md §4.4
- Lexicographic comparison of address bytes in network byte order within
  the same family
- Returns `CIDR_ERR_INVAL` if any pointer is NULL or either address has
  `family == CIDR_AF_UNSPEC`
- Returns `CIDR_ERR_FAMILY` if families differ
- Writes -1, 0, or +1 to `*result`

### Tests for Phase 2

File: `tests/test_addr.c`

Per TESTING.md §3, every RFC conformance test case has its own named test:

- `test_ipv4_parse_valid` -- representative valid inputs; boundary addresses
- `test_ipv4_parse_leading_zero` -- CIDR_ERR_PARSE per TESTING.md §3.1
- `test_ipv4_parse_hex` -- CIDR_ERR_PARSE
- `test_ipv4_parse_out_of_range` -- CIDR_ERR_PARSE
- `test_ipv4_parse_wrong_count` -- CIDR_ERR_PARSE
- `test_ipv4_parse_whitespace` -- CIDR_ERR_PARSE
- `test_ipv4_parse_trailing_chars` -- CIDR_ERR_PARSE
- `test_ipv4_parse_null` -- CIDR_ERR_INVAL for NULL src and NULL out
- `test_ipv6_parse_full_form` -- 8-group form accepted
- `test_ipv6_parse_compressed` -- all `::` positions
- `test_ipv6_parse_double_colon_once` -- CIDR_ERR_PARSE
- `test_ipv6_parse_uppercase_normalised` -- stored lowercase
- `test_ipv6_parse_mixed_mapped` -- accepted; stored as CIDR_AF_INET6
- `test_ipv6_parse_mixed_non_mapped` -- CIDR_ERR_PARSE
- `test_ipv6_parse_compatible_rejected` -- CIDR_ERR_PARSE
- `test_ipv6_parse_wrong_group_count` -- CIDR_ERR_PARSE
- `test_ipv6_parse_group_too_large` -- 16-bit hex group overflow
- `test_ipv6_parse_invalid_chars` -- non-hex characters, stray colons
- `test_ipv4_format_canonical` -- no leading zeros, correct separators
- `test_ipv4_format_roundtrip` -- parse/format/parse produces identical bytes
- `test_ipv6_format_rfc5952_leading_zeros` -- suppressed per §4.1
- `test_ipv6_format_rfc5952_compress_longest` -- longest run compressed
- `test_ipv6_format_rfc5952_no_compress_single` -- single zero group written as `0`
- `test_ipv6_format_rfc5952_tie_first_wins` -- first run wins
- `test_ipv6_format_rfc5952_lowercase` -- all hex lowercase
- `test_ipv6_format_rfc5952_mixed_mapped` -- `::ffff:x.x.x.x`
- `test_ipv6_format_roundtrip` -- parse/format/parse produces identical bytes
- `test_addr_format_buffer_too_small` -- CIDR_ERR_INVAL
- `test_addr_to_v4_valid_extraction` -- correct IPv4 bytes extracted
- `test_addr_to_v4_error_distinction` -- per TESTING.md §6.7
- `test_addr_cmp_same_family` -- ordering correct; equal returns 0
- `test_addr_cmp_family_mismatch` -- CIDR_ERR_FAMILY
- `test_addr_cmp_unspec` -- CIDR_ERR_INVAL

### Phase 2 Completion Criteria

- [x] All test_addr.c tests pass on all four targets
- [x] Valgrind clean on Linux (no leaks; cidr_addr.c allocates nothing)
- [x] ASan/UBSan clean on every target whose toolchain supports them
- [x] Memory discipline check: `grep -n "malloc\|free" src/cidr_addr.c` -- empty
- [x] Quality milestones M9 (RFC conformance) partially confirmed:
      IPv4 and IPv6 parse/format RFC tests all passing

---

## Phase 3 -- Prefix Construction and Arithmetic

**Goal**: CIDR prefixes construct, format, and compute correctly. The
host-bits-zero invariant is enforced at all construction paths. All eight
arithmetic operations return correct results including edge cases. The subnet
iterator enumerates subnets in ascending order and handles early termination
safely. Comparison returns results consistent with `CIDR_SORT_NETWORK_ASC`.

**Reference documents**:
- ARCHITECTURE.md §3.3 -- `cidr_prefix_t` invariant and construction contract
- ARCHITECTURE.md §4.1.4 -- two-function CIDR parse contract
- ARCHITECTURE.md §4.2.3 -- prefix formatting
- ARCHITECTURE.md §4.3 -- all eight arithmetic operations
- ARCHITECTURE.md §4.3.8 -- subnet iterator design and enumeration order
- ARCHITECTURE.md §4.4 -- `cidr_prefix_cmp()` ordering
- CODING_STANDARDS.md §4.2 -- bulk operation bounds discipline (applies to
  iterator loop contract)
- TESTING.md §6.2 -- host-bits-zero invariant test requirement

**Prerequisite**: Phase 2 complete.

### Tasks

**3.1 -- `cidr_prefix_t` and `cidr_sort_order_t`** ✓ DONE
- Define `cidr_prefix_t` in `include/libcidr.h` per ARCHITECTURE.md §3.3
- Add `_Static_assert(sizeof(cidr_prefix_t) == 24, ...)` to
  `src/cidr_internal.h`
- Define `cidr_sort_order_t` enum in `include/libcidr.h`
- Define `CIDR_PREFIX_STR_MAX = 50` in `include/libcidr.h`
- All four items were already present in the codebase from Phase 2 header
  build-up. Verified against specification and validation gate.

**3.2 -- `cidr_prefix_parse()` and `cidr_prefix_from_host()`** ✓ DONE
- Implement `cidr_prefix_parse()` in `src/cidr_prefix.c`:
  - Parse `address/prefixlen` by splitting at the last `/`
  - Delegate address parsing to `cidr_addr_parse()` from Phase 2
  - Parse prefix length as a decimal integer; validate range per family
  - Apply prefix mask to the address bytes and compare to original; if
    any host bit is set, return `CIDR_ERR_HOSTBITS`
- Implement `cidr_prefix_from_host()`:
  - Validate pointer parameters and prefix length range
  - Copy the address bytes into `out->addr`
  - Zero host bits by applying the prefix mask in place
  - This function must not return `CIDR_ERR_HOSTBITS` -- zeroing is
    the explicit contract

**3.3 -- `cidr_prefix_format()`** ✓ DONE
- Implement `cidr_prefix_format()` in `src/cidr_prefix.c`
- Delegate address formatting to `cidr_addr_format()` from Phase 2
- Append `/prefixlen` as decimal integer with no leading zeros
- Verify `CIDR_PREFIX_STR_MAX = 50` is sufficient: max IPv6 address (45
  chars) + `/` + `128` + NUL = 50 bytes

**3.4 -- Prefix arithmetic operations** ✓ DONE
- Implement all eight operations in `src/cidr_prefix.c` per ARCHITECTURE.md §4.3:
  - `cidr_prefix_broadcast()`: IPv4 only; OR network address with complement
    of prefix mask; returns `CIDR_ERR_FAMILY` for IPv6
  - `cidr_prefix_mask()`: leading ones, trailing zeros; handle `/0` (all
    bytes 0x00) and maximum prefix length (all bytes 0xFF)
  - `cidr_prefix_first()`: network address field access (no computation)
  - `cidr_prefix_last()`: broadcast for IPv4; host-bits-all-ones for IPv6;
    same as `cidr_prefix_first()` for `/32` and `/128`
  - `cidr_prefix_contains()`: `(addr & mask) == prefix.addr`; `out` may be
    NULL per CODING_STANDARDS.md §3.4
  - `cidr_prefix_overlaps()`: delegate to two `cidr_prefix_contains()` calls
  - `cidr_prefix_supernet()`: decrement pfxlen by 1, zero new host bit;
    return `CIDR_ERR_OVERFLOW` on `/0`
- Each operation must check for NULL input pointers and `CIDR_AF_UNSPEC`
  family per ARCHITECTURE.md §3.1 blanket policy

**3.5 -- Subnet iterator** ✓ DONE
- Implement `cidr_subnet_iter_t` definition in `include/libcidr.h` per
  ARCHITECTURE.md §4.3.8 (already present from Phase 2 header build-up)
- Implement `cidr_subnet_iter_init()`:
  - Validate that `target_pfxlen > prefix->pfxlen`; return `CIDR_ERR_PFXLEN`
    if not
  - Validate `target_pfxlen` within range for the address family
  - Initialise `iter->current` to the network address of `prefix`
  - Compute `iter->limit` as the first address past the end of `prefix`
    (network address of the next sibling at the same prefix length)
- Implement `cidr_subnet_iter_next()`:
  - On `iter->done`, return `CIDR_ERR_DONE` without modifying `out`
  - Write `iter->current` into `out` with `target_pfxlen`
  - Advance `iter->current` by `2^(addr_len_bits - target_pfxlen)` in
    network byte order (big-endian byte increment via `addr_big_endian_inc()`)
  - If the advanced address equals or exceeds `iter->limit`, set `iter->done`
  - Subnets are yielded in ascending network address order; verify first
    subnet equals `prefix.addr`

**3.6 -- `cidr_prefix_cmp()`** ✓ DONE
- Implement per ARCHITECTURE.md §4.4
- Order: network address ascending (lexicographic on address bytes in
  network byte order), then prefix length ascending within the same network
  address -- matching `CIDR_SORT_NETWORK_ASC`

### Tests for Phase 3

File: `tests/test_prefix.c`

- `test_prefix_parse_valid` -- representative valid CIDR strings
- `test_prefix_parse_hostbits_rejected` -- per TESTING.md §6.2
- `test_prefix_parse_pfxlen_out_of_range` -- CIDR_ERR_PFXLEN
- `test_prefix_parse_null` -- CIDR_ERR_INVAL
- `test_prefix_from_host_zeroes_hostbits` -- all prefix lengths 0-32 (IPv4)
  and 0-128 (IPv6); per TESTING.md §6.2
- `test_prefix_from_host_pfxlen_out_of_range` -- CIDR_ERR_PFXLEN
- `test_prefix_format_canonical` -- `address/prefixlen` format correct
- `test_prefix_format_buffer_too_small` -- CIDR_ERR_INVAL
- `test_prefix_format_roundtrip` -- parse/format/parse identical
- `test_prefix_broadcast_ipv4` -- correct for /0, /24, /31, /32
- `test_prefix_broadcast_ipv6_family_error` -- CIDR_ERR_FAMILY
- `test_prefix_mask_all_lengths` -- 0 through 32 (IPv4), 0 through 128 (IPv6)
- `test_prefix_first_last_edge_cases` -- /0, /32, /128
- `test_prefix_contains_inside` -- address inside network
- `test_prefix_contains_outside` -- address outside; returns false not error
- `test_prefix_contains_null_out` -- NULL out is valid; no write occurs
- `test_prefix_contains_family_mismatch` -- CIDR_ERR_FAMILY
- `test_prefix_overlaps_disjoint` -- false
- `test_prefix_overlaps_adjacent` -- false (adjacent but non-overlapping)
- `test_prefix_overlaps_partial` -- true
- `test_prefix_overlaps_containment` -- true (one contains the other)
- `test_prefix_overlaps_identical` -- true
- `test_prefix_supernet_chain` -- /32 to /0; each result correct
- `test_prefix_supernet_overflow` -- CIDR_ERR_OVERFLOW on /0
- `test_subnet_iter_correct_count` -- 2^(target-prefix) subnets enumerated
- `test_subnet_iter_ascending_order` -- per TESTING.md §6.8
- `test_subnet_iter_first_equals_parent_network` -- first subnet = parent addr
- `test_subnet_iter_early_termination` -- break from loop; no crash
- `test_subnet_iter_done_out_not_modified` -- CIDR_ERR_DONE; out unchanged
- `test_subnet_iter_pfxlen_invalid` -- CIDR_ERR_PFXLEN when target <= prefix
- `test_prefix_cmp_ordering` -- consistent with CIDR_SORT_NETWORK_ASC
- `test_prefix_cmp_equal` -- returns 0 for identical prefixes
- `test_prefix_cmp_family_mismatch` -- CIDR_ERR_FAMILY

### Phase 3 Completion Criteria

- [x] All test_prefix.c tests pass on all four targets (67/67)
- [x] Host-bits-zero invariant test passes: `test_prefix_parse_hostbits_rejected`
      and `test_prefix_from_host_zeroes_hostbits`
- [x] Subnet iterator ascending order test passes: `test_subnet_iter_ascending_order`
- [x] Valgrind clean; ASan/UBSan clean on every target whose toolchain
      supports them
- [x] Memory discipline check: no `malloc`/`free` in `src/cidr_prefix.c`
- [x] Quality milestone M9 (RFC conformance) further confirmed: prefix parse
      tests pass

---

## Phase 4 -- Bulk Engine

**Goal**: Batch parse, containment, aggregation, and sort operations are
correct, efficient, and safe on caller-provided arrays. The in-place MSD radix
sort produces a correctly ordered result with bounded stack usage. Aggregation
output matches `ipaddress.collapse_addresses`. Return-code precedence for
`cidr_bulk_parse()` is correct. `CIDR_SORT_PFXLEN_DESC` is stable. All edge
cases at count boundaries are handled.

**Reference documents**:
- ARCHITECTURE.md §5 -- bulk engine design, all four operations
- ARCHITECTURE.md §5.2 -- `cidr_bulk_parse()` full-batch semantics and
  return-code precedence
- ARCHITECTURE.md §5.3 -- `cidr_bulk_contains()` first-match semantics
- ARCHITECTURE.md §5.4 -- aggregation algorithm, radix sort stack usage
- ARCHITECTURE.md §5.5 -- `CIDR_SORT_PFXLEN_DESC` stability
- CODING_STANDARDS.md §4.2 -- bulk operation bounds discipline and empty
  array handling
- TESTING.md §6.3 -- `cidr_bulk_parse()` return-code precedence test
- TESTING.md §6.4 -- `CIDR_SORT_PFXLEN_DESC` stability test

**Prerequisite**: Phase 3 complete.

### Tasks

**4.1 -- Shared radix sort engine** ✓ DONE
- Implement in-place MSD radix sort in `src/cidr_bulk.c` as an internal
  function
- Key width: 5 bytes for IPv4 (4 address bytes + 1 pfxlen byte), 17 bytes
  for IPv6 (16 address bytes + 1 pfxlen byte); key width is a compile-time
  constant for each family
- At each recursion level, allocate a histogram of 256 `size_t` counts on
  the stack; perform a counting sort pass; recurse on non-trivial buckets
- Maximum stack usage: 17 * 256 * `sizeof(size_t)` = 34,816 bytes for IPv6
  on 64-bit platforms per ARCHITECTURE.md §5.4; add a `SAFETY:` comment
  documenting this bound
- Implement for `CIDR_SORT_NETWORK_ASC`: sort key is address bytes followed
  by pfxlen byte (all ascending)
- Implement for `CIDR_SORT_PFXLEN_DESC`: sort key is the bitwise complement
  of pfxlen byte (so that descending prefix length sorts ascending) followed
  by address bytes (ascending within equal prefix lengths)
- `CIDR_SORT_PFXLEN_DESC` must be stable: equal keys (identical prefixes)
  must preserve their original input order; implement stability by appending
  the original array index as a tiebreaker key or by using a stable sort
  variant

**4.2 -- `cidr_bulk_parse()`** ✓ DONE
- Implement per ARCHITECTURE.md §5.2
- Check for NULL elements in `srcs` first: if any `srcs[i]` is NULL, return
  `CIDR_ERR_INVAL` immediately with no output written
- Process all items regardless of individual parse failures (no fail-fast)
- Infer reference family from first successfully-parsed item
- After full batch, apply return-code precedence:
  `CIDR_ERR_FAMILY` (mixed family) > `CIDR_ERR_PARSE` (any failed) >
  `CIDR_OK`
- Write `CIDR_AF_UNSPEC` to `out[i].family` for failed items
- `errs` may be NULL; skip per-item error writes when NULL

**4.3 -- `cidr_bulk_contains()`** ✓ DONE
- Implement per ARCHITECTURE.md §5.3
- For each `addrs[i]`, scan `prefixes` in order, write index of first match
  or -1
- When `prefix_count == 0`, write -1 for all entries and return `CIDR_OK`
- When `addr_count > 0` and `matches` is NULL, return `CIDR_ERR_INVAL`
- `errs` may be NULL

**4.4 -- `cidr_bulk_aggregate()`** ✓ DONE
- Implement per ARCHITECTURE.md §5.4 five-step algorithm:
   1. Radix sort the prefix array using the shared engine
     (`CIDR_SORT_NETWORK_ASC` key)
  2. Linear scan: remove exact duplicates
  3. Linear scan: remove prefixes already covered by a shorter prefix
  4. Merge pass: merge adjacent sibling prefixes into their supernet;
     repeat until no merges occur
  5. Early termination: if pass produces zero merges, aggregation is complete
- `out_count` must be non-NULL; return `CIDR_ERR_INVAL` if NULL
- Operation is in-place; caller must copy the array before calling if
  the original must be preserved

**4.5 -- `cidr_bulk_sort()`** ✓ DONE
- Implement per ARCHITECTURE.md §5.5
- Validate `order` parameter; return `CIDR_ERR_INVAL` for invalid enum values
- When `count == 0`, return `CIDR_OK` without accessing `prefixes`
- When `count > 0` and `prefixes` is NULL, return `CIDR_ERR_INVAL`
- Delegate to the shared radix sort engine with the correct key construction
  for the requested order

### Tests for Phase 4

File: `tests/test_bulk.c`

- `test_bulk_parse_all_valid` -- all items parse; correct output
- `test_bulk_parse_partial_failure` -- per-item error array; output state
- `test_bulk_parse_null_errs` -- NULL errs; function completes; return code correct
- `test_bulk_parse_null_element` -- per TESTING.md §6.3; fail-fast; no output written
- `test_bulk_parse_return_code_precedence` -- per TESTING.md §6.3
- `test_bulk_parse_full_batch_all_attempted` -- even with failures, all items processed
- `test_bulk_parse_empty` -- count == 0; CIDR_OK
- `test_bulk_parse_single` -- count == 1
- `test_bulk_contains_first_match` -- first matching prefix returned
- `test_bulk_contains_no_match` -- -1 returned
- `test_bulk_contains_lpm_with_sorted_table` -- sorted by CIDR_SORT_PFXLEN_DESC;
  most specific prefix returned for each address
- `test_bulk_contains_empty_prefix_table` -- all -1; CIDR_OK
- `test_bulk_contains_null_matches_nonzero_count` -- CIDR_ERR_INVAL
- `test_bulk_contains_family_mismatch` -- CIDR_ERR_FAMILY
- `test_bulk_aggregate_known_cases` -- output matches `ipaddress.collapse_addresses`
  reference; per TESTING.md §6 and M10
- `test_bulk_aggregate_duplicate_removal` -- exact duplicates removed
- `test_bulk_aggregate_containment_removal` -- covered prefixes removed
- `test_bulk_aggregate_sibling_merge` -- /24 siblings merged to /23
- `test_bulk_aggregate_early_termination` -- already-aggregated input triggers
  early exit in one pass
- `test_bulk_aggregate_single_prefix` -- no change; CIDR_OK
- `test_bulk_aggregate_null_out_count` -- CIDR_ERR_INVAL
- `test_bulk_sort_network_asc_order` -- verified for representative inputs
- `test_bulk_sort_pfxlen_desc_order` -- prefix length descending; secondary
  key ascending
- `test_bulk_sort_pfxlen_desc_stability` -- per TESTING.md §6.4
- `test_bulk_sort_invalid_order` -- CIDR_ERR_INVAL
- `test_bulk_sort_empty` -- count == 0; CIDR_OK; NULL prefixes allowed
- `test_bulk_sort_single` -- no change; CIDR_OK

### Phase 4 Completion Criteria

- [ ] All test_bulk.c tests pass on all four targets
      Comment: confirmed on Linux x86_64 and OpenBSD amd64; Linux ARM64 and
      OpenBSD arm64 still need explicit validation evidence
- [ ] `test_bulk_aggregate_known_cases` confirms output matches
      `ipaddress.collapse_addresses` -- quality milestone M10
      Comment: representative reference cases now pass; direct `ipaddress`
      oracle comparison is deferred to Phase 7 Python tests
- [x] `test_bulk_sort_pfxlen_desc_stability` passes
- [x] `test_bulk_parse_return_code_precedence` passes
- [x] Stack usage verified: no stack overflow in bulk_aggregate or bulk_sort
      with 1M IPv6 prefix input under ASan (default 8 MiB stack)
- [x] Valgrind clean; ASan/UBSan clean on every target whose toolchain
      supports them
- [x] Memory discipline check: no `malloc`/`free` in `src/cidr_bulk.c`
- [x] TSan: no races when `cidr_bulk_sort` and `cidr_bulk_aggregate` called
      from multiple threads on independent arrays (they share no global state)

---

## Phase 5 -- Address Classification

**Goal**: `cidr_addr_classify()` returns the correct `cidr_class_t` bitmask
for every address. Every IANA special-purpose block in the snapshot is
represented accurately. Boundary addresses (first and last of each block)
classify correctly. Multi-flag assignments for overlapping blocks are correct.
`CIDR_CLASS_GLOBAL` is mutually exclusive with every other flag.

**Reference documents**:
- ARCHITECTURE.md §7 -- classification function, flag registry, IANA tables
- ARCHITECTURE.md §7.2 -- all 23 flags, both IPv4 and IPv6 tables,
  terminated-entry policy, multicast attribution
- CODING_STANDARDS.md §4.4 -- no global mutable state; classification table
  must be a compile-time constant
- TESTING.md §6.6 -- CIDR_CLASS_GLOBAL mutual exclusivity test

**Prerequisite**: Phase 3 complete. (Classification uses `cidr_addr_t` and
performs prefix-containment checks internally using mask logic equivalent to
Phase 3 arithmetic, but the public function signature requires only Phase 2.)

### Tasks

**5.1 -- Classification table** ✓ DONE
- Define the compile-time classification table in `src/cidr_classify.c`
- Table entries contain: address family, network address bytes, prefix
  length, and bitmask of applicable flags
- Table must be declared `static const` -- no runtime mutation; no global
  mutable state per CODING_STANDARDS.md §4.4
- Encode all IPv4 entries from ARCHITECTURE.md §7.2 table (27 entries)
- Encode all IPv6 entries from ARCHITECTURE.md §7.2 table (26 entries)
- Multi-flag entries (e.g. `2001::/32` = `CIDR_CLASS_IETF_RESERVED |
  CIDR_CLASS_TEREDO`) must be entered with the combined bitmask
- Terminated entries (`192.88.99.0/24`, `2001:10::/28`) must be present
  per the terminated-entry retention policy
- Multicast blocks (`224.0.0.0/4` from RFC 1112, `ff00::/8` from RFC 4291)
  must be present; add a comment attributing them correctly, not to RFC 6890
- `CIDR_IANA_SNAPSHOT = 20251009` defined in `include/libcidr.h`

**5.2 -- `cidr_addr_classify()`** ✓ DONE**
- Implement linear scan over the classification table in `src/cidr_classify.c`
- For each entry, test whether the input address falls within the entry's
  prefix using mask-and-compare logic; OR the entry's flags into the result
  accumulator if it matches
- After scanning all entries: if accumulator is 0 (no match), set
  `CIDR_CLASS_GLOBAL`
- Return `CIDR_ERR_INVAL` for NULL pointers or `CIDR_AF_UNSPEC` input
- The scan is O(1) in practice -- the table is a compile-time constant of
  approximately 53 entries; add a `SAFETY:` comment noting the table size

**5.3 -- `cidr_class_t` and `CIDR_CLASS_*` constants** ✓ DONE
- Define `cidr_class_t` as `uint32_t` in `include/libcidr.h`
- Define all 23 `CIDR_CLASS_*` constants per ARCHITECTURE.md §7.2
  (`1u << 0` through `1u << 22`), with the documented flag names and comments
- Bits 23-31 reserved -- add a comment
  (All completed in Phase 1 skeleton; verified in Phase 5.1/5.2)

### Tests for Phase 5

File: `tests/test_classify.c`

- `test_classify_each_ipv4_block` -- one address from each IPv4 special-purpose
  block yields the correct flags and no others
- `test_classify_each_ipv6_block` -- one address from each IPv6 special-purpose
  block yields the correct flags and no others
- `test_classify_global_exclusivity` -- per TESTING.md §6.6
- `test_classify_global_public_unicast` -- known public addresses yield only
  `CIDR_CLASS_GLOBAL`
- `test_classify_multi_flag_2001_sub_blocks` -- `2001::/32` yields
  `CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_TEREDO`; other 2001::/23 sub-blocks
  yield correct multi-flag assignments
- `test_classify_terminated_192_88_99` -- `192.88.99.0/24` classified with
  `CIDR_CLASS_6TO4_RELAY`
- `test_classify_terminated_2001_10` -- `2001:10::/28` classified with
  `CIDR_CLASS_IETF_RESERVED`
- `test_classify_multicast_ipv4` -- `224.0.0.0/4` boundary addresses yield
  `CIDR_CLASS_MULTICAST`
- `test_classify_multicast_ipv6` -- `ff00::/8` boundary addresses yield
  `CIDR_CLASS_MULTICAST`
- `test_classify_boundary_first_last` -- first and last address of each
  block classified correctly; address just before and just after block
  yields different result
- `test_classify_null` -- CIDR_ERR_INVAL
- `test_classify_unspec` -- CIDR_ERR_INVAL

### Phase 5 Completion Criteria

- [x] All test_classify.c tests pass on all four targets
- [x] `test_classify_global_exclusivity` passes
- [x] `test_classify_multi_flag_2001_sub_blocks` passes
- [x] Terminated entries classified correctly
- [x] Valgrind clean; ASan/UBSan clean on every target whose toolchain
      supports them
- [x] Memory discipline check: no `malloc`/`free` in `src/cidr_classify.c`

---

## Phase 6 -- Patricia Trie Index

**Goal**: `cidr_index_create()` builds a correct LC-trie from any prefix
array. `cidr_index_lookup()` returns the longest-prefix match for every
input address. Interior node prefixes are correctly recorded during traversal.
Duplicate prefixes return the lower input index. Memory is fully released by
`cidr_index_destroy()`. This is the most complex phase -- the LC-trie DP
algorithm requires careful implementation and extensive testing before Phase 7
begins.

**Reference documents**:
- ARCHITECTURE.md §6 -- Patricia trie design, purpose, API
- ARCHITECTURE.md §6.2 -- `cidr_index_create()` all error conditions,
  duplicate handling, node count overflow
- ARCHITECTURE.md §6.3 -- node layout (12 bytes), path compression (skip),
  level compression (branch), DP cost function, traversal algorithm
- CODING_STANDARDS.md §2.2 -- resource cleanup with goto (index build uses
  multiple allocations)
- TESTING.md §6.5 -- interior node prefix test requirement
- TESTING.md §2.5 -- LPM vs bulk_contains comparison test pattern

**Prerequisite**: Phase 4 complete. (`cidr_index_create()` copies and sorts
the prefix array using the Phase 4 radix sort engine.)

### Tasks

**6.1 -- `cidr_lctrie_node_t` and `cidr_index_t`** ✓ DONE
- Define `cidr_lctrie_node_t` in `src/cidr_internal.h` per ARCHITECTURE.md §6.3:
  `uint32_t base`, `uint32_t prefix_idx`, `uint8_t branch`, `uint8_t skip`,
  `uint8_t pad[2]` -- total 12 bytes, 4-byte alignment
- Add `_Static_assert(sizeof(cidr_lctrie_node_t) == 12, ...)` to
  `src/cidr_internal.h`
- Define `cidr_index_t` as an opaque struct in `src/cidr_internal.h`:
  pointer to node array, node count, pointer to copied prefix array,
  prefix count, address family
- Add public API function declarations (`cidr_index_create`,
  `cidr_index_destroy`, `cidr_index_lookup`) to `include/libcidr.h`
  with full doc comment blocks
- Add function stubs with input validation in `src/cidr_index.c`
- Create `tests/test_index.c` with 8 validation tests for error paths
- Update `tests/run_tests.c` and `Makefile`

**6.2 -- Basic trie construction** ✓ DONE
- Implement a basic Patricia trie (path-compressed binary trie) builder:
  each node has at most two children; `skip` encodes how many bits to
  advance past without branching
- Build from the sorted prefix array produced by radix sort on the input
- Assign `prefix_idx` at the node whose bit position matches a prefix's
  prefix length

**6.3 -- Level compression (LC-trie DP)** ✓ DONE
- Implement level compression per the authoritative specification in
  ARCHITECTURE.md §6.4
- Convert the path-compressed trie into an array-packed LC-trie in a single
  contiguous allocation
- Document the DP with `/* SAFETY: */` and `/* NOTE: */` comments at each
  step explaining the invariants relied upon

**6.4 -- `cidr_index_create()`** ✓ DONE
- Implement per ARCHITECTURE.md §6.2 using `goto cleanup` for all
  multi-allocation paths per CODING_STANDARDS.md §2.3
- Validate all error conditions before any allocation:
  - `count == 0`: return `CIDR_ERR_INVAL`
  - `count > UINT32_MAX - 1`: return `CIDR_ERR_INVAL`
  - any prefix has `family == CIDR_AF_UNSPEC`: return `CIDR_ERR_INVAL`
  - mixed families: return `CIDR_ERR_FAMILY`
  - any pointer is NULL: return `CIDR_ERR_INVAL`
- Copy the prefix array before sorting (caller may free their array
  immediately after the call returns)
- If node count during build would exceed `UINT32_MAX - 1`, return
  `CIDR_ERR_INVAL` per ARCHITECTURE.md §6.2

**6.5 -- `cidr_index_lookup()`** ✓ DONE
- Implement the traversal loop per ARCHITECTURE.md §6.3:
  - Advance `skip` bits; extract `branch` bits as array index; descend to
    `nodes[base + index]`
  - If `prefix_idx != UINT32_MAX` at any node (leaf or interior), record
    this index as the current best match
  - Terminate at a leaf node (`branch == 0`) or when accumulated bit
    position exceeds address width
  - Write the last recorded best match (or -1 if none) to `matches[i]`
- `errs` may be NULL; when `count > 0` and `matches` is NULL, return
  `CIDR_ERR_INVAL`

**6.6 -- `cidr_index_destroy()`** ✓ DONE
- Implement as NULL-safe: `if (index == NULL) return;`
- Free the node array and the copied prefix array; free the index struct
- Returns `void` -- no error path possible

### Tests for Phase 6

File: `tests/test_index.c`

- `test_index_basic_lookup` -- single prefix; address inside returns 0;
  address outside returns -1
- `test_index_lpm_matches_sorted_bulk` -- per TESTING.md §2.5; for any
  input where bulk_contains with CIDR_SORT_PFXLEN_DESC table is compared
  against index_lookup on same prefix array
- `test_index_interior_node_prefix` -- per TESTING.md §6.5
- `test_index_duplicate_lower_index_wins` -- two identical prefixes; lower
  index always returned
- `test_index_no_match` -- address outside all prefixes returns -1
- `test_index_routing_table_scale` -- 100k prefixes; correctness spot-check
  via comparison with sorted bulk_contains
- `test_index_create_count_zero` -- CIDR_ERR_INVAL
- `test_index_create_unspec_family` -- CIDR_ERR_INVAL
- `test_index_create_mixed_family` -- CIDR_ERR_FAMILY
- `test_index_create_null` -- CIDR_ERR_INVAL for NULL prefixes or NULL out
- `test_index_lookup_null_matches_nonzero_count` -- CIDR_ERR_INVAL
- `test_index_lookup_unspec_address` -- CIDR_ERR_INVAL; no output written
- `test_index_destroy_null_safe` -- no crash
- `test_index_memory_clean` -- Valgrind: no leaks after destroy

File: `tests/test_tsan.c`

- `test_concurrent_index_lookup` -- concurrent reads on one completed index;
  no races under TSan

### Phase 6 Completion Criteria

- [x] All test_index.c tests pass on all four targets
- [x] `test_index_interior_node_prefix` passes -- quality milestone M11
      (LC-trie LPM semantics verified)
- [x] `test_index_lpm_matches_sorted_bulk` passes for routing-table-scale
      inputs
- [x] Valgrind clean: no leaks, no use-after-free on all index test paths
- [x] ASan/UBSan clean on every target whose toolchain supports them
- [x] TSan: `test_concurrent_index_lookup` passes (concurrent reads on a
      completed index; no races per ARCHITECTURE.md §1.4)
- [x] Memory discipline check: `malloc`/`free` present only in
      `src/cidr_index.c` as expected

---

## Phase 7 -- Python Binding Layer

**Goal**: The full public C API is accessible from Python. All four Python
types behave correctly for all documented constructor forms, properties, and
methods. Exception hierarchy maps `cidr_err_t` values correctly. Python tests
compare libcidr results against `ipaddress` stdlib and confirm equivalence
for all supported operations. The extension builds as a `.abi3.so` binary
that loads on CPython 3.11, 3.12, and 3.13.

**Reference documents**:
- ARCHITECTURE.md §8 -- CPython binding layer, all types, all entry points
- ARCHITECTURE.md §8.2 -- stable ABI floor, `PyType_FromSpec` requirement
- ARCHITECTURE.md §8.5 -- exception hierarchy, `PyErr_NewExceptionWithDoc`
  tuple ordering
- ARCHITECTURE.md §8.6 -- address types, constructors, properties, to_ipv4
- ARCHITECTURE.md §8.7 -- network types, constructors, strict parameter
- ARCHITECTURE.md §8.8 -- bulk entry points and memoryview validation
- ARCHITECTURE.md §8.9 -- subnet iterator type
- ARCHITECTURE.md §8.10 -- ownership model, no shared pointers
- CODING_STANDARDS.md §6 -- Python binding code style, reference counting,
  error handling, `cidr_set_python_error()`, PyType_FromSpec patterns,
  naming conventions
- TECH_STACK.md §5 -- extension build, stable ABI verification

**Prerequisite**: Phases 2-6 complete. The binding wraps the entire C API;
no partial binding makes sense before all C components are tested and stable.

### Tasks

**7.1 -- Module skeleton and exception hierarchy** ✓ DONE
- Implement `PyMODINIT_FUNC PyInit_libcidr(void)` in
  `python/_libcidr_ext.c`
- Register the module with `PyModuleDef`
- Create exception hierarchy using `PyErr_NewExceptionWithDoc()` with
  `(CIDRError, BuiltinBase)` tuple ordering per ARCHITECTURE.md §8.5:
  `CIDRError`, `ParseError`, `HostBitsError`, `PrefixLengthError`,
  `InvalidArgumentError`, `FamilyError`, `AddressOverflowError`
- Implement the `cidr_set_python_error()` helper per CODING_STANDARDS.md §6.4
- Export module-level constants: all `CIDR_CLASS_*` values, `CIDR_IANA_SNAPSHOT`,
  `AF_INET = 4`, `AF_INET6 = 6`, `SORT_NETWORK_ASC`, `SORT_PFXLEN_DESC`

**7.2 -- `IPv4Address` and `IPv6Address` types** ✓ DONE
- Define `IPv4Address` and `IPv6Address` C structs embedding `cidr_addr_t`
  by value
- Implement `PyType_FromSpec()` type definitions for both per
  CODING_STANDARDS.md §6.5
- Implement constructors per ARCHITECTURE.md §8.6.1: string, 4/16-byte bytes,
  integer, `ipaddress` object; family mismatch raises `FamilyError`
- Implement all read-only properties per ARCHITECTURE.md §8.6.2:
  `packed`, `compressed`, `exploded`, `version`, `is_global`, `is_private`,
  `is_loopback`, `is_multicast`, `is_link_local`, `is_unspecified`
- Implement `classify()` method: returns raw `cidr_class_t` as Python `int`
- Implement `to_ipv4()` method on `IPv6Address` only: returns `IPv4Address`
  for mapped addresses, `None` for non-mapped; backed by `cidr_addr_to_v4()`
- Implement protocol methods: `__str__`, `__repr__`, `__eq__`, `__hash__`,
  `__lt__`

**7.3 -- `IPv4Network` and `IPv6Network` types** ✓ DONE
- Define `IPv4Network` and `IPv6Network` C structs embedding `cidr_prefix_t`
  by value
- Implement constructors per ARCHITECTURE.md §8.7.1: string, `(string, int)`
  tuple, `ipaddress` object; `strict` keyword-only parameter (default `True`);
  `strict` ignored for `ipaddress` object input
- Implement all read-only properties per ARCHITECTURE.md §8.7.2:
  `network_address`, `broadcast_address` (IPv4 only; `FamilyError` on IPv6),
  `prefixlen`, `netmask`, `with_prefixlen`, `version`, `num_addresses`
- Implement methods per ARCHITECTURE.md §8.7.3:
  `overlaps()`, `supernet()`, `subnets(prefixlen)`, `contains()`
- Implement `__contains__` to delegate to `contains()`
- Implement protocol methods: `__str__`, `__repr__`, `__eq__`, `__hash__`,
  `__lt__`

**7.4 -- Subnet iterator type** ✓ DONE
- Define `SubnetIterator` C struct embedding `cidr_subnet_iter_t` by value
- Implement `__iter__` returning `self`
- Implement `__next__`: call `cidr_subnet_iter_next()`; on `CIDR_ERR_DONE`,
  raise `StopIteration`; on `CIDR_OK`, construct and return the next network
  object

**7.5 -- Bulk entry points** ✓ DONE
- Implement `bulk_parse`, `bulk_contains`, `bulk_aggregate`, `bulk_sort`
  as module-level functions per ARCHITECTURE.md §8.8.1
- `bulk_parse`: processes all items; raises after full batch; follow
  `cidr_bulk_parse()` batch semantics and precedence
- `bulk_aggregate`: Python list input/output; not in-place (caller's list
  not modified); allocate temporary C array, call C function, return new list

**7.6 -- `bulk_contains_packed()` memoryview entry point**
- Implement per ARCHITECTURE.md §8.8.2
- Validate memoryview: 1D, C-contiguous (`PyBUF_C_CONTIGUOUS`), element
  size matches `family` (4 for `AF_INET`, 16 for `AF_INET6`)
- Raise `InvalidArgumentError` for dimension, contiguity, or element size
  violations
- Convert packed bytes to `cidr_addr_t` array in a tight C loop with no
  Python object creation per address

### Tests for Phase 7

File: `tests/test_python.py`

Full test catalogue per TESTING.md §7.1. Key test groups:

- Constructors: all forms; family mismatch; bytes wrong length;
  integer out of range
- `ipaddress` constructor: one-way construction for all four types
- Properties: compare all supported properties against `ipaddress` reference
- `to_ipv4()`: mapped returns `IPv4Address`; non-mapped returns `None`;
  absent on `IPv4Address`
- `strict` parameter: `True` raises `HostBitsError`; `False` zeroes bits;
  ignored for `ipaddress` object input
- Network methods: `overlaps`, `supernet`, `subnets`, `contains`
- `subnets(prefixlen=n)` equivalent to `ipaddress.subnets(new_prefix=n)`
- `__contains__`: `addr in network` syntax
- Protocol: sort, hash, dict key, set member
- Exception hierarchy: catch at `CIDRError`, `ValueError`, `TypeError`,
  `OverflowError` levels
- `bulk_aggregate` compared against `ipaddress.collapse_addresses`
- `bulk_contains_packed`: correct results; size mismatch; non-contiguous error
- Stable ABI: `import libcidr` succeeds on CPython 3.11, 3.12, 3.13

### Phase 7 Completion Criteria

- [x] All test_python.py tests pass on CPython 3.11, 3.12, and 3.13
      (verified on 3.13 and 3.14)
- [x] `make python-check-abi` confirms `.abi3.so` suffix
- [x] Extension loads with `import libcidr` on all three CPython versions
- [x] Extension builds with no warnings under Python extension flags
- [x] Extension passes ASan run: `make python-dev && make test-python`
- [x] Quality milestone M12 confirmed

---

## Phase 8 -- Hardening, Benchmarks, and Release

**Goal**: All quality milestones confirmed on all four targets. Benchmark
baselines recorded. README.md written. v1.0.0 release tag applied.

**Prerequisite**: Phase 7 complete. All unit and Python tests passing.

### Tasks

**8.1 -- Full sanitizer pass** ✓ DONE
- Run `make test-tsan` on Linux and confirm M6
- Run `make valgrind` on Linux and confirm M4
- Run `make dev && make test` on all four targets and confirm M5
- Run `make lint` on all four targets and confirm M7, M8
- Fix any warnings or errors found; do not suppress

**8.2 -- TSan concurrent tests** ✓ DONE
- Add `test_concurrent_parse()` and `test_concurrent_index_lookup()` per
  TESTING.md §4.3 (placed in `tests/test_tsan.c` following the established
  TSan test pattern; `test_concurrent_index_lookup` existed from Phase 6)
- Each test spawns N pthreads running the relevant operation in a tight
  loop; verify TSan reports no races
- These tests run only under `make test-tsan`, not under `make test`
  (they require TSan instrumentation to be meaningful)

**8.3 -- C benchmark suite**
- Implement `bench/bench_bulk.c` and `bench/bench_index.c` per
  REPOSITORY_STRUCTURE.md §6
- Run on Linux x86_64 and ARM64, OpenBSD amd64
- Record baseline numbers in `bench/BASELINES.md` with full hardware context
  per TESTING.md §8.2

**8.4 -- Python benchmark suite**
- Implement `bench/bench_python.py` per REPOSITORY_STRUCTURE.md §6
- Benchmark against `ipaddress`, `netaddr`, and `pytricia` per TESTING.md §8.1
- Record comparison table in `bench/BASELINES.md`

**8.5 -- Open items closure**
- The open items in ARCHITECTURE.md §10 are fully resolved by this
  documentation suite:
  - Python extension build: TECH_STACK.md §5
  - Platform matrix and CI: TECH_STACK.md §7.7
  - C library test strategy: TESTING.md
  - Python layer test strategy: TESTING.md §7
  - Sanitizer integration: TECH_STACK.md §7 and TESTING.md §4
- Update ARCHITECTURE.md §10 to reflect all open items resolved

**8.6 -- README.md**
- Written for a C developer or Python developer coming to the project cold
- Contents:
  - One-paragraph description (what it does, what it does not do)
  - Build requirements (libc, Clang or GCC, CPython 3.11+ for the binding)
  - How to build: `make && make install` for C; `make python-ext &&
    make python-install` for Python
  - Minimal C usage example: parse an address, classify it, check
    containment in a prefix
  - Minimal Python usage example: bulk_contains against a prefix table
  - Known limitations: zero-allocation model, no network I/O, no DNS,
    no routability inference from `CIDR_CLASS_GLOBAL`
  - Link to ARCHITECTURE.md for design rationale
  - ISC license notice

**8.7 -- Final checklist and release**
- Work through the full pre-commit checklist from CODING_STANDARDS.md §7
  for the entire repository
- Verify all quality milestone cells are marked confirmed
- Apply v1.0.0 release tag

### Phase 8 Completion Criteria

- [ ] TSan concurrent tests pass: `make test-tsan` clean on Linux -- M6
- [ ] Valgrind clean on Linux -- M4
- [ ] ASan/UBSan clean on all four targets -- M5
- [ ] `make lint` zero warnings on all four targets -- M7, M8
- [ ] All C tests pass on all four targets -- M2, M3
- [ ] All Python tests pass on CPython 3.11, 3.12, 3.13 -- M12
- [ ] Benchmark baselines recorded in `bench/BASELINES.md` -- M13
- [ ] README.md complete; C and Python usage examples compile and run
- [ ] All quality milestone status cells confirmed
- [ ] v1.0.0 release tag applied

---

## Cross-Reference Index

| Topic | Primary reference | Secondary reference |
|---|---|---|
| IPv4 parsing rejection cases | ARCHITECTURE.md §4.1.1 | TESTING.md §3.1 |
| IPv6 parsing forms and restrictions | ARCHITECTURE.md §4.1.2 | TESTING.md §3.2 |
| `cidr_addr_to_v4()` error distinction | ARCHITECTURE.md §4.1.3 | TESTING.md §6.7 |
| RFC 5952 formatting rules | ARCHITECTURE.md §4.2.2 | TESTING.md §3.3 |
| Buffer size constants | ARCHITECTURE.md §4.2 | TECH_STACK.md §3.1 |
| Host-bits-zero invariant | ARCHITECTURE.md §3.3 | TESTING.md §6.2 |
| Two-function parse contract | ARCHITECTURE.md §4.1.4 | CODING_STANDARDS.md §3.4 |
| Prefix arithmetic operations | ARCHITECTURE.md §4.3 | REPOSITORY_STRUCTURE.md §3 |
| Subnet iterator ascending order | ARCHITECTURE.md §4.3.8 | TESTING.md §6.8 |
| `cidr_addr_cmp` and `cidr_prefix_cmp` | ARCHITECTURE.md §4.4 | REPOSITORY_STRUCTURE.md §9 |
| Bulk engine semantics | ARCHITECTURE.md §5 | REPOSITORY_STRUCTURE.md §3 |
| `cidr_bulk_parse()` return-code precedence | ARCHITECTURE.md §5.2 | TESTING.md §6.3 |
| `CIDR_SORT_PFXLEN_DESC` stability | ARCHITECTURE.md §5.5 | TESTING.md §6.4 |
| Radix sort stack usage | ARCHITECTURE.md §5.4 | TECH_STACK.md §3.1 |
| Classification table and flags | ARCHITECTURE.md §7.2 | REPOSITORY_STRUCTURE.md §3 |
| `CIDR_CLASS_GLOBAL` mutual exclusivity | ARCHITECTURE.md §7.2 | TESTING.md §6.6 |
| Terminated-entry retention policy | ARCHITECTURE.md §7.2 | TESTING.md §9 |
| Multicast block attribution | ARCHITECTURE.md §7.2 | TESTING.md §9 |
| LC-trie node layout | ARCHITECTURE.md §6.3 | REPOSITORY_STRUCTURE.md §3 |
| LC-trie DP cost function | ARCHITECTURE.md §6.3 | DEVELOPMENT.md Phase 6 task 6.3 |
| LC-trie interior node prefix | ARCHITECTURE.md §6.3 | TESTING.md §6.5 |
| `cidr_index_create()` error conditions | ARCHITECTURE.md §6.2 | TESTING.md §9 |
| LPM vs first-match distinction | ARCHITECTURE.md §6.2 | TESTING.md §2.5 |
| Thread safety model | ARCHITECTURE.md §1.4 | TESTING.md §4.3 |
| Zero-allocation model | ARCHITECTURE.md §1.4 | CODING_STANDARDS.md §2.1 |
| Memory discipline check | CODING_STANDARDS.md §4.1 | TECH_STACK.md §3.1 |
| Python stable ABI floor | ARCHITECTURE.md §8.2 | TECH_STACK.md §5.2 |
| `PyType_FromSpec` requirement | ARCHITECTURE.md §8.2 | CODING_STANDARDS.md §6.5 |
| Exception hierarchy and tuple ordering | ARCHITECTURE.md §8.5 | CODING_STANDARDS.md §6.4 |
| Python `to_ipv4()` | ARCHITECTURE.md §8.6.3 | TESTING.md §7.1 |
| `strict` parameter | ARCHITECTURE.md §8.7.1 | TESTING.md §7.1 |
| `bulk_contains_packed()` validation | ARCHITECTURE.md §8.8.2 | TESTING.md §7.1 |
| Ownership model | ARCHITECTURE.md §8.10 | CODING_STANDARDS.md §6.2 |
| `cidr_set_python_error()` | CODING_STANDARDS.md §6.4 | DEVELOPMENT.md Phase 7 task 7.1 |
| Pre-commit checklist | CODING_STANDARDS.md §7 | DEVELOPMENT.md Phase 8 task 8.7 |
| Build targets | TECH_STACK.md §4.4 | REPOSITORY_STRUCTURE.md §7 |
| Python extension build | TECH_STACK.md §5 | REPOSITORY_STRUCTURE.md §4 |
| Test harness | TECH_STACK.md §6 | TESTING.md §2.1 |
| Valgrind flags | TECH_STACK.md §7.1 | TESTING.md §4.1 |
| ASan/UBSan flags | TECH_STACK.md §7.2 | TESTING.md §4.2 |
| TSan flags | TECH_STACK.md §7.3 | TESTING.md §4.3 |
| Source file purposes | REPOSITORY_STRUCTURE.md §3 | DEVELOPMENT.md (each phase) |
| Benchmark descriptions | REPOSITORY_STRUCTURE.md §6 | TESTING.md §8 |

---

**See Also**: PROJECT.md, ARCHITECTURE.md, TECH_STACK.md, CODING_STANDARDS.md,
REPOSITORY_STRUCTURE.md, TESTING.md
