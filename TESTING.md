# Testing Strategy

## 1. Overview

Testing operates at three levels:

| Level | What | When | Tools |
|---|---|---|---|
| Unit | Individual components in isolation, per C source file | During each phase, before moving on | Plain C test programs, Valgrind, ASan/UBSan, TSan |
| Python binding | Full Python API surface compared against `ipaddress` stdlib | After the C component it wraps is unit-tested | pytest / unittest, ASan extension build |
| Performance | Throughput and latency baselines, Python comparison | Phase 8, under release flags | Benchmark suite in `bench/` |

The rule is simple: **a phase is not done until its tests pass on all four
targets -- Linux and OpenBSD, x86_64 and ARM64**. Do not accumulate untested
code. Each phase is small enough that bugs are easy to find when caught
immediately.

**No external C test framework.** Plain C programs with a minimal assertion
macro. The harness is described in TECH_STACK.md §6. Every test function
returns 0 on success and non-zero on failure. The test binary exits with
code 0 if all tests pass and 1 if any fail.

**Python tests use `unittest`.** No third-party Python framework is required.
pytest is accepted but not required.

---

## 2. Unit Testing

### 2.1 Test Harness

See TECH_STACK.md §6.1 for the `RUN(name, fn)` macro definition and the
test binary contract. The structure is:

```
tests/
├── test_harness.h       ← RUN macro, tests_run and tests_passed counters
├── run_tests.c          ← binary entry point -- calls RUN() for every suite
├── test_addr.c          ← Address parsing, formatting, extraction, comparison
├── test_prefix.c        ← Prefix construction, arithmetic, iteration, comparison
├── test_bulk.c          ← Bulk parse, containment, aggregation, sort
├── test_classify.c      ← Address classification against full IANA table
└── test_index.c         ← Patricia trie correctness
```

`make test` builds all test files against `libcidr.a` and runs the binary.
This verifies that exported symbols are correct -- tests do not link directly
against source files or include internal headers.

### 2.2 Per-Component Test Scope

Every component has a dedicated test file. The scope of each file is strictly
bounded -- `test_addr.c` does not test prefix arithmetic, and `test_index.c`
does not test classification. This makes failures easy to localise.

| Test file | What it tests | What it does NOT test |
|---|---|---|
| `test_addr.c` | `cidr_addr_parse`, `cidr_addr_format`, `cidr_addr_to_v4`, `cidr_addr_cmp` | Prefix arithmetic, bulk ops |
| `test_prefix.c` | `cidr_prefix_parse`, `cidr_prefix_from_host`, all arithmetic ops, subnet iterator, `cidr_prefix_cmp` | Bulk ops, classification |
| `test_bulk.c` | `cidr_bulk_parse`, `cidr_bulk_contains`, `cidr_bulk_aggregate`, `cidr_bulk_sort` | Patricia trie, classification |
| `test_classify.c` | `cidr_addr_classify`, IANA snapshot table accuracy | Prefix arithmetic, bulk ops |
| `test_index.c` | `cidr_index_create`, `cidr_index_destroy`, `cidr_index_lookup`, LPM semantics | Bulk ops, classification |

### 2.3 Test Patterns for Arithmetic Functions

Arithmetic tests follow a consistent pattern: valid input produces the
correct output, invalid input produces the correct error code, and edge
cases at the boundaries of each specification clause are explicitly covered.

```c
/*
 * Pattern for parse tests: valid input, each rejection case, edge cases.
 */
static int
test_ipv4_parse_valid(void)
{
	cidr_addr_t  out;
	cidr_err_t   rc;

	rc = cidr_addr_parse("192.168.1.1", &out);
	if (rc != CIDR_OK) return 1;
	if (out.family != CIDR_AF_INET) return 1;
	if (out.addr.v4[0] != 192 || out.addr.v4[1] != 168 ||
	    out.addr.v4[2] != 1   || out.addr.v4[3] != 1)
		return 1;

	/* boundary values */
	if (cidr_addr_parse("0.0.0.0",         &out) != CIDR_OK) return 1;
	if (cidr_addr_parse("255.255.255.255",  &out) != CIDR_OK) return 1;
	return 0;
}

static int
test_ipv4_parse_rejection_cases(void)
{
	cidr_addr_t out;

	/* each case has its own sub-test so failures are localised */
	if (cidr_addr_parse("192.168.01.1",   &out) != CIDR_ERR_PARSE) return 1;
	if (cidr_addr_parse("0x10.0.0.1",     &out) != CIDR_ERR_PARSE) return 1;
	if (cidr_addr_parse("256.0.0.1",      &out) != CIDR_ERR_PARSE) return 1;
	if (cidr_addr_parse("192.168.1",      &out) != CIDR_ERR_PARSE) return 1;
	if (cidr_addr_parse("192.168.1.1.1",  &out) != CIDR_ERR_PARSE) return 1;
	if (cidr_addr_parse(" 192.168.1.1",   &out) != CIDR_ERR_PARSE) return 1;
	if (cidr_addr_parse("192.168.1.1 ",   &out) != CIDR_ERR_PARSE) return 1;
	if (cidr_addr_parse("",               &out) != CIDR_ERR_PARSE) return 1;
	if (cidr_addr_parse(NULL,             &out) != CIDR_ERR_INVAL)  return 1;
	if (cidr_addr_parse("192.168.1.1",  NULL)   != CIDR_ERR_INVAL)  return 1;
	return 0;
}
```

Round-trip tests verify that `parse(format(parse(x))) == parse(x)`:

```c
static int
test_ipv6_format_roundtrip(void)
{
	const char  *cases[] = {
		"2001:db8::1",
		"::1",
		"::",
		"fe80::1",
		"::ffff:192.0.2.1",       /* IPv4-mapped -- mixed notation */
		"2001:db8::",
		"ff02::1",
		NULL
	};
	char         buf[CIDR_ADDR_STR_MAX];
	cidr_addr_t  addr;

	for (int i = 0; cases[i] != NULL; i++) {
		if (cidr_addr_parse(cases[i], &addr) != CIDR_OK)
			return 1;
		if (cidr_addr_format(&addr, buf, sizeof(buf)) != CIDR_OK)
			return 1;
		/* formatted output is already canonical; re-parsing
		 * must produce bit-identical bytes */
		cidr_addr_t addr2;
		if (cidr_addr_parse(buf, &addr2) != CIDR_OK)
			return 1;
		if (memcmp(&addr, &addr2, sizeof(addr)) != 0)
			return 1;
	}
	return 0;
}
```

### 2.4 Test Patterns for Bulk Operations

Bulk tests verify batch semantics, error propagation, and edge cases at
count boundaries.

```c
/*
 * Pattern for partial-failure batch tests.
 * Verify output and errs state for each item independently.
 */
static int
test_bulk_parse_partial_failure(void)
{
	const char   *srcs[] = { "10.0.0.1", "BAD", "10.0.0.3" };
	cidr_addr_t   out[3];
	cidr_err_t    errs[3];
	cidr_err_t    rc;

	rc = cidr_bulk_parse(srcs, 3, out, errs);

	/* function processes all items; returns CIDR_ERR_PARSE for batch */
	if (rc != CIDR_ERR_PARSE) return 1;

	/* item 0: success */
	if (errs[0] != CIDR_OK)               return 1;
	if (out[0].family != CIDR_AF_INET)     return 1;

	/* item 1: failure -- out written as CIDR_AF_UNSPEC */
	if (errs[1] != CIDR_ERR_PARSE)        return 1;
	if (out[1].family != CIDR_AF_UNSPEC)   return 1;

	/* item 2: success */
	if (errs[2] != CIDR_OK)               return 1;
	if (out[2].family != CIDR_AF_INET)     return 1;

	return 0;
}
```

### 2.5 Test Patterns for the Patricia Trie

Index tests verify LPM semantics by comparing `cidr_index_lookup()` output
against `cidr_bulk_contains()` output for the same inputs when the prefix
table is sorted by `CIDR_SORT_PFXLEN_DESC`:

```c
static int
test_index_lpm_matches_sorted_bulk(void)
{
	cidr_prefix_t  prefixes[4];
	cidr_addr_t    addrs[3];
	ssize_t        idx_matches[3];
	ssize_t        bulk_matches[3];
	cidr_index_t  *index = NULL;

	/* set up overlapping prefixes: /8, /16, /24 */
	cidr_prefix_parse("10.0.0.0/8",   &prefixes[0]);
	cidr_prefix_parse("10.1.0.0/16",  &prefixes[1]);
	cidr_prefix_parse("10.1.2.0/24",  &prefixes[2]);
	cidr_prefix_parse("192.168.0.0/16", &prefixes[3]);

	cidr_addr_parse("10.1.2.5",    &addrs[0]);   /* matches /24, /16, /8 */
	cidr_addr_parse("10.2.0.1",    &addrs[1]);   /* matches /8 only */
	cidr_addr_parse("172.16.0.1",  &addrs[2]);   /* no match */

	/* sort for LPM: longest prefix first */
	cidr_prefix_t sorted[4];
	memcpy(sorted, prefixes, sizeof(prefixes));
	cidr_bulk_sort(sorted, 4, CIDR_SORT_PFXLEN_DESC);

	/* bulk_contains with sorted table gives LPM via first-match */
	cidr_bulk_contains(addrs, 3, sorted, 4, bulk_matches, NULL);

	/* index always returns LPM by construction */
	cidr_index_create(prefixes, 4, &index);
	cidr_index_lookup(index, addrs, 3, idx_matches, NULL);
	cidr_index_destroy(index);

	/*
	 * When using the same sorted table for both operations, results must
	 * match. See ARCHITECTURE.md §6.2.
	 */
	for (int i = 0; i < 3; i++) {
		/*
		 * idx_matches returns indices into the original (unsorted)
		 * prefix array; remap bulk_matches accordingly for comparison.
		 */
		/* ... remap and compare ... */
	}
	return 0;
}
```

### 2.6 What Gets Unit Tests

Every public function in `include/libcidr.h` has unit tests. Internal helpers
are tested implicitly through the public API.

What does **not** need dedicated unit tests:
- `src/cidr_internal.h` -- tested implicitly by every test that links the
  library (the `_Static_assert` checks fire at compile time)
- Build system files and config files

See DEVELOPMENT.md for the specific named test cases required per phase.

---

## 3. RFC Conformance Testing

RFC conformance is the primary correctness requirement. Tests must verify
the exact rejection cases and acceptance cases defined in the applicable RFCs,
not just "it parses correctly" at a high level.

### 3.1 IPv4 Parsing -- RFC 1123

Each rejection case has its own test name so that failures are immediately
localised to a specific rule:

| Test name | Input | Expected result | Rule |
|---|---|---|---|
| `test_ipv4_parse_valid_range` | `0.0.0.0` through `255.255.255.255` boundary values | `CIDR_OK` | RFC 1123 §2.1 |
| `test_ipv4_parse_leading_zero` | `192.168.01.1`, `010.0.0.1` | `CIDR_ERR_PARSE` | Ambiguity rejection |
| `test_ipv4_parse_hex` | `0xc0.0xa8.0x01.0x01`, `0x10.0.0.1` | `CIDR_ERR_PARSE` | Non-RFC form |
| `test_ipv4_parse_out_of_range` | `256.0.0.1`, `192.168.1.300` | `CIDR_ERR_PARSE` | Octet range |
| `test_ipv4_parse_wrong_count` | `192.168.1`, `1.2.3.4.5` | `CIDR_ERR_PARSE` | Exactly four octets |
| `test_ipv4_parse_whitespace` | `" 192.168.1.1"`, `"192.168.1.1 "` | `CIDR_ERR_PARSE` | No whitespace |
| `test_ipv4_parse_trailing_chars` | `"192.168.1.1/"`, `"192.168.1.1x"` | `CIDR_ERR_PARSE` | Exact match |
| `test_ipv4_parse_empty` | `""` | `CIDR_ERR_PARSE` | Minimum length |

### 3.2 IPv6 Parsing -- RFC 4291 / RFC 5952

| Test name | Input | Expected result | Rule |
|---|---|---|---|
| `test_ipv6_parse_full_form` | `2001:0db8:0000:0000:0000:0000:0000:0001` | `CIDR_OK` | RFC 4291 §2.2 |
| `test_ipv6_parse_compressed` | `2001:db8::1`, `::1`, `::`, `fe80::` | `CIDR_OK` | RFC 4291 §2.2 |
| `test_ipv6_parse_double_colon_once` | `2001::db8::1` | `CIDR_ERR_PARSE` | RFC 4291 §2.2 |
| `test_ipv6_parse_uppercase_normalised` | `2001:DB8::1` | `CIDR_OK`, stored as lowercase | RFC 5952 §4.3 |
| `test_ipv6_parse_mixed_mapped` | `::ffff:192.0.2.1` | `CIDR_OK`, `CIDR_AF_INET6` | RFC 5952 §5 |
| `test_ipv6_parse_mixed_non_mapped` | `2001:db8::192.0.2.1` | `CIDR_ERR_PARSE` | RFC 5952 §5 restriction |
| `test_ipv6_parse_compatible_rejected` | `::192.0.2.1` | `CIDR_ERR_PARSE` | RFC 4291 §2.5.5.1 deprecation |
| `test_ipv6_parse_wrong_group_count` | `2001:db8:1:2:3:4:5:6:7` | `CIDR_ERR_PARSE` | Exactly 8 groups |
| `test_ipv6_parse_group_too_large` | `2001:fffff::1` | `CIDR_ERR_PARSE` | 16-bit range |

### 3.3 RFC 5952 Canonical Formatting

The six formatting rules of RFC 5952 §4 and §5 are each tested explicitly:

| Test name | Input | Expected output | Rule |
|---|---|---|---|
| `test_rfc5952_leading_zeros` | `2001:0db8::0001` parsed, then formatted | `2001:db8::1` | §4.1: suppress leading zeros |
| `test_rfc5952_compress_longest` | `2001:0:0:0:0:0:0:1` | `2001::1` | §4.2.1: `::` to maximum |
| `test_rfc5952_no_compress_single` | `2001:db8:0:1::1` | `2001:db8:0:1::1` (single zero as `0`) | §4.2.2: no `::` for one group |
| `test_rfc5952_tie_first_wins` | `2001:0:0:1:0:0:2:1` | `2001::1:0:0:2:1` | §4.2.3: first run when equal |
| `test_rfc5952_lowercase` | `ABCD::EF01` parsed, formatted | `abcd::ef01` | §4.3: always lowercase |
| `test_rfc5952_mixed_notation` | `::ffff:c000:0201` | `::ffff:192.0.2.1` | §5: IPv4-mapped mixed form |
| `test_rfc5952_no_mixed_non_mapped` | `::192.0.2.1` parsed as rejected | N/A -- input rejected | §5 restriction |

---

## 4. Memory Testing

### 4.1 Valgrind (Linux only)

Run after every phase on Linux:

```sh
make dev
make valgrind
# equivalent to:
valgrind --leak-check=full          \
         --show-leak-kinds=all      \
         --track-origins=yes        \
         --error-exitcode=1         \
         ./tests/run_tests
```

libcidr allocates memory only in `cidr_index_create()`. Valgrind checks that:
- Every `cidr_index_create()` call is balanced by a `cidr_index_destroy()` call
- No memory is accessed after `cidr_index_destroy()`
- No memory is leaked on error paths inside `cidr_index_create()`
- Stack-allocated bulk operations introduce no heap leaks

No suppression file is needed. libcidr has no external library dependencies
that would require suppressions.

All C tests must pass Valgrind clean before a phase is considered complete.
Valgrind is not available on OpenBSD -- use the ASan build there.

### 4.2 AddressSanitizer and UndefinedBehaviorSanitizer

Run on both platforms after every phase:

```sh
make dev    # compiles with -fsanitize=address,undefined when supported
make test
```

ASan detects out-of-bounds reads and writes on caller-provided arrays. The
bulk engine's radix sort operates in place on caller memory; any off-by-one
error at array boundaries is caught immediately.

UBSan detects:
- Integer overflow in prefix length arithmetic and bit shift operations
- Null pointer dereferences on checked pointer parameters
- Misaligned memory access (verifies struct layout is correctly aligned)

All C tests must pass ASan/UBSan clean on every target whose toolchain
supports those sanitizers.

### 4.3 ThreadSanitizer

libcidr has no internal concurrency. TSan tests verify the thread safety
model from ARCHITECTURE.md §1.4: non-index functions are fully reentrant,
and concurrent `cidr_index_lookup()` calls on a completed index are safe.

Run on Linux at each phase boundary:

```sh
make test-tsan
```

TSan tests spawn multiple threads and run operations concurrently:

```c
/*
 * test_concurrent_parse -- run cidr_addr_parse from N threads simultaneously.
 * Verifies no data races in the arithmetic engine.
 */
static int
test_concurrent_parse(void)
{
	/* spawn N pthreads, each running parse/format in a tight loop */
	/* verify no TSan races; verify results are correct */
}

/*
 * test_concurrent_index_lookup -- build one index, query from N threads.
 * Verifies concurrent read access to a completed cidr_index_t is safe.
 */
static int
test_concurrent_index_lookup(void)
{
	cidr_index_t *index;
	/* build index on main thread */
	/* spawn N threads all calling cidr_index_lookup on the same index */
	/* verify no TSan races; verify all results match expected */
}
```

TSan is not a per-commit gate. It is a phase-boundary gate. TSan and ASan
are mutually exclusive -- they run as separate targets.

### 4.4 Memory Discipline Check

Run after every phase to verify the zero-allocation constraint:

```sh
grep -n "malloc\|calloc\|realloc\|free" src/*.c
```

Expected output: only `src/cidr_index.c`. Any `malloc` or `free` call in
`src/cidr_addr.c`, `src/cidr_prefix.c`, `src/cidr_bulk.c`, or
`src/cidr_classify.c` is a violation of the allocation model.

---

## 5. Platform Testing

### 5.1 Platform Matrix

Every phase must pass on all four targets before it is complete:

| Platform | Architecture | Sanitizers | Notes |
|---|---|---|---|
| Linux | x86_64 | ASan/UBSan, TSan, Valgrind | Primary development target |
| Linux | ARM64 | ASan/UBSan, TSan | CI via GitHub Actions arm64 runner |
| OpenBSD | amd64 | ASan/UBSan when toolchain supports it | Valgrind not available |
| OpenBSD | arm64 | ASan/UBSan when toolchain supports it | CI via GitHub Actions OpenBSD arm64 |

### 5.2 Platform-Specific Concerns

**No Valgrind on OpenBSD.** When the installed Clang toolchain provides
ASan/UBSan, `make dev` is the memory safety gate. Some OpenBSD base compiler
builds do not ship sanitizer runtimes; in that case `make dev` falls back to a
non-sanitized debug build.

**No platform-conditional C code.** libcidr has no platform-specific
implementation paths -- it uses only portable C11 and POSIX. There are no
`#ifdef CIDR_LINUX` / `#ifdef CIDR_OPENBSD` guards in `src/`. Tests that
exercise the same code on both platforms should produce identical results. Any
divergence is a bug.

**Integer representation.** All address bytes are stored in network byte order
regardless of host byte order. Tests must verify that the stored bytes are
correct on both little-endian (x86_64, most ARM64) and big-endian targets. The
target platforms are all little-endian, but the tests should not assume this.

---

## 6. Correctness Properties Requiring Explicit Tests

These are the most subtle correctness requirements in the architecture. Each
must have at least one dedicated test that specifically targets the property
-- not just tests where the property happens to hold.

### 6.1 Parse/Format Round-Trip Invariant

**Property:** For any address `a` that `cidr_addr_parse()` accepts,
`cidr_addr_parse(cidr_addr_format(a))` must produce bit-identical bytes.

**Dedicated tests:** `test_ipv4_format_roundtrip`, `test_ipv6_format_roundtrip`

Verify for a representative set covering: all special-purpose blocks, boundary
addresses, IPv4-mapped addresses, compressed and full IPv6 forms. The formatted
output of `cidr_addr_format()` must itself be a valid input to `cidr_addr_parse()`.

A round-trip failure indicates either that `format()` produces a non-canonical
form that `parse()` rejects, or that `parse()` and `format()` use different
normalisations. Both are bugs.

### 6.2 Host-Bits-Zero Invariant Enforcement

**Property:** `cidr_prefix_parse()` must reject any input with non-zero host
bits. `cidr_prefix_from_host()` must produce a prefix with zero host bits for
any valid input.

**Dedicated tests:** `test_prefix_parse_hostbits_rejected`,
`test_prefix_from_host_zeroes_hostbits`

For `cidr_prefix_parse()`:
```c
/* Input has host bits set -- must return CIDR_ERR_HOSTBITS */
if (cidr_prefix_parse("192.168.1.5/24",  &out) != CIDR_ERR_HOSTBITS) return 1;
if (cidr_prefix_parse("10.0.0.1/8",      &out) != CIDR_ERR_HOSTBITS) return 1;
if (cidr_prefix_parse("2001:db8::1/32",  &out) != CIDR_ERR_HOSTBITS) return 1;
```

For `cidr_prefix_from_host()`, verify the host bits are zeroed correctly for
every prefix length 0-32 (IPv4) and 0-128 (IPv6). The mask application must
produce the correct network address for all boundary values:

```c
/* /0: all bytes become zero */
/* /1: only the MSB of byte 0 is preserved */
/* /31: only the lowest bit of byte 3 is zeroed */
/* /32: no bytes changed */
```

### 6.3 `cidr_bulk_parse()` Return-Code Precedence

**Property:** When a batch contains both a NULL element and parse failures,
`CIDR_ERR_INVAL` is returned immediately (fail-fast) and no output is written.
When both parse failures and family mismatches occur (no NULL elements),
`CIDR_ERR_FAMILY` takes precedence over `CIDR_ERR_PARSE`.

**Dedicated test:** `test_bulk_parse_precedence`

```c
static int
test_bulk_parse_precedence(void)
{
	cidr_addr_t  out[3];
	cidr_err_t   errs[3];

	/* NULL element -- fail-fast, CIDR_ERR_INVAL, no output written */
	const char *with_null[] = { "10.0.0.1", NULL, "10.0.0.3" };
	if (cidr_bulk_parse(with_null, 3, out, errs) != CIDR_ERR_INVAL) return 1;
	/* verify out[0] was not written: family still CIDR_AF_UNSPEC */
	if (out[0].family != CIDR_AF_UNSPEC) return 1;

	/* mixed family + parse failure: CIDR_ERR_FAMILY wins */
	const char *mixed[] = { "10.0.0.1", "BAD", "2001:db8::1" };
	if (cidr_bulk_parse(mixed, 3, out, errs) != CIDR_ERR_FAMILY) return 1;

	return 0;
}
```

### 6.4 `CIDR_SORT_PFXLEN_DESC` Stability

**Property:** Exact duplicate prefixes must preserve their original input
order after sorting with `CIDR_SORT_PFXLEN_DESC`. This is required for
consistency with `cidr_index_create()`'s lower-index-wins duplicate handling.

**Dedicated test:** `test_sort_pfxlen_desc_stability`

Setup: create an array where the same prefix appears at two indices (say
indices 3 and 7). Sort with `CIDR_SORT_PFXLEN_DESC`. Verify the duplicate
that was at index 3 appears before the one at index 7 in the output.

This test confirms stability is preserved through the radix sort implementation.
An unstable radix sort would non-deterministically reorder duplicates.

### 6.5 LC-Trie Interior Node Prefix Storage

**Property:** A prefix that has more-specific sub-prefixes in the table must
be stored at an interior node in the trie and must be returned as the best
match for addresses that match it but not any more-specific prefix.

**Dedicated test:** `test_index_interior_node_prefix`

Setup:
```c
cidr_prefix_t prefixes[2];
cidr_addr_t   addr;
ssize_t       match;
cidr_index_t *index;

cidr_prefix_parse("10.0.0.0/8",   &prefixes[0]);   /* parent */
cidr_prefix_parse("10.1.0.0/16",  &prefixes[1]);   /* child */

cidr_index_create(prefixes, 2, &index);

/* address matches /8 but NOT /16 -- must return index 0, not -1 */
cidr_addr_parse("10.2.0.1", &addr);
cidr_index_lookup(index, &addr, 1, &match, NULL);
if (match != 0) return 1;   /* must find the /8 interior node */

/* address matches /16 -- must return index 1 (more specific) */
cidr_addr_parse("10.1.0.1", &addr);
cidr_index_lookup(index, &addr, 1, &match, NULL);
if (match != 1) return 1;   /* must find the /16 leaf */

cidr_index_destroy(index);
```

An implementation that stores prefixes only at leaf nodes would return -1
for the first address, incorrectly failing to find the /8 match.

### 6.6 `CIDR_CLASS_GLOBAL` Mutual Exclusivity

**Property:** `CIDR_CLASS_GLOBAL` must be set when and only when no other
flag is set. It must never appear alongside any special-purpose flag.

**Dedicated test:** `test_classify_global_exclusivity`

For every address in the classification table, verify that if the result
includes `CIDR_CLASS_GLOBAL`, no other flag bit is set. For a sample of
addresses outside all special-purpose blocks, verify `CIDR_CLASS_GLOBAL`
is the only flag set:

```c
cidr_addr_t   addr;
cidr_class_t  flags;

/* public unicast -- CIDR_CLASS_GLOBAL only */
cidr_addr_parse("8.8.8.8", &addr);
cidr_addr_classify(&addr, &flags);
if (flags != CIDR_CLASS_GLOBAL) return 1;

cidr_addr_parse("1.1.1.1", &addr);
cidr_addr_classify(&addr, &flags);
if (flags != CIDR_CLASS_GLOBAL) return 1;

/* any special-purpose address must NOT have CIDR_CLASS_GLOBAL */
cidr_addr_parse("192.168.1.1", &addr);
cidr_addr_classify(&addr, &flags);
if (flags & CIDR_CLASS_GLOBAL) return 1;
```

### 6.7 `cidr_addr_to_v4()` Error Distinction

**Property:** The function must distinguish three cases: `CIDR_AF_UNSPEC`
input returns `CIDR_ERR_INVAL`; `CIDR_AF_INET` input (valid but wrong family)
returns `CIDR_ERR_FAMILY`; `CIDR_AF_INET6` non-mapped input returns
`CIDR_ERR_FAMILY`. See ARCHITECTURE.md §4.1.3.

**Dedicated test:** `test_addr_to_v4_error_distinction`

```c
cidr_addr_t unspec = {0};   /* zero-init: CIDR_AF_UNSPEC */
cidr_addr_t ipv4, ipv6, mapped, unmapped;

cidr_addr_parse("192.168.1.1",    &ipv4);
cidr_addr_parse("2001:db8::1",    &unmapped);
cidr_addr_parse("::ffff:192.0.2.1", &mapped);

cidr_addr_t out;
if (cidr_addr_to_v4(&unspec,    &out) != CIDR_ERR_INVAL)  return 1;
if (cidr_addr_to_v4(&ipv4,      &out) != CIDR_ERR_FAMILY)  return 1;
if (cidr_addr_to_v4(&unmapped,  &out) != CIDR_ERR_FAMILY)  return 1;
if (cidr_addr_to_v4(&mapped,    &out) != CIDR_OK)           return 1;
/* verify extracted address */
if (out.addr.v4[0] != 192 || out.addr.v4[3] != 1)          return 1;
```

### 6.8 Subnet Iterator Ascending Order

**Property:** `cidr_subnet_iter_next()` must yield subnets in ascending
network address order. The first subnet yielded has the same network address
as the parent prefix.

**Dedicated test:** `test_subnet_iter_ascending_order`

Enumerate all /25 subnets of a /23 prefix (4 subnets). Verify each yielded
subnet has a network address strictly greater than the previous one. Verify
the first subnet starts at the parent's network address.

---

## 7. Python Binding Tests

Python tests compare libcidr results against `ipaddress` stdlib for all
operations where `ipaddress` is the correctness reference. The test file
is `tests/test_python.py`.

### 7.1 Coverage

```
Constructor forms:
  IPv4Address: string, 4-byte bytes, integer, ipaddress.IPv4Address
  IPv6Address: string, 16-byte bytes, integer, ipaddress.IPv6Address
  IPv4Network: string, (string, int) tuple, ipaddress.IPv4Network
  IPv6Network: string, (string, int) tuple, ipaddress.IPv6Network

Cross-family construction raises FamilyError.
strict=True (default) raises HostBitsError on host bits set.
strict=False zeros host bits.
strict ignored for ipaddress object input.

Properties compared against ipaddress for matching values:
  packed, compressed, exploded, version
  is_global, is_private, is_loopback, is_multicast, is_link_local

IPv6Address.to_ipv4():
  Returns IPv4Address for ::ffff:0:0/96 addresses.
  Returns None for non-mapped IPv6.
  Not present on IPv4Address.

Network properties:
  network_address, prefixlen, netmask, with_prefixlen, num_addresses
  broadcast_address (IPv4Network only; raises FamilyError on IPv6Network)

Network methods:
  overlaps: matches ipaddress behaviour
  supernet: matches ipaddress behaviour; raises AddressOverflowError on /0
  subnets(prefixlen=n): equivalent to ipaddress.subnets(new_prefix=n)
  contains: matches ipaddress __contains__ behaviour

Protocol:
  __str__, __repr__, __eq__, __hash__, __lt__
  sortable: list.sort() produces ascending order
  usable as dict key and set member

Bulk functions:
  bulk_parse: all valid; partial failure; NULL errs; return-code precedence
  bulk_contains: first-match semantics; LPM with pre-sorted table
  bulk_aggregate: output matches ipaddress.collapse_addresses
  bulk_sort: SORT_NETWORK_ASC; SORT_PFXLEN_DESC with secondary key

bulk_contains_packed:
  memoryview input; correct matches returned
  wrong element size raises InvalidArgumentError
  non-contiguous memoryview raises InvalidArgumentError

Exception hierarchy:
  catch at CIDRError level catches all libcidr errors
  catch at ValueError level catches ParseError, HostBitsError,
    PrefixLengthError, InvalidArgumentError
  catch at TypeError level catches FamilyError
  catch at OverflowError level catches AddressOverflowError
```

### 7.2 ipaddress Comparison Pattern

Tests that compare against `ipaddress` use a helper that runs both
implementations and asserts equality:

```python
import ipaddress, libcidr

def test_compressed_matches_ipaddress(self):
    cases = [
        "2001:db8::1",
        "::1",
        "::",
        "fe80::1",
        "::ffff:192.0.2.1",
    ]
    for addr_str in cases:
        expected = str(ipaddress.IPv6Address(addr_str))
        actual   = str(libcidr.IPv6Address(addr_str))
        self.assertEqual(expected, actual,
            f"compressed form differs for {addr_str!r}: "
            f"ipaddress={expected!r} libcidr={actual!r}")
```

### 7.3 bulk_aggregate Reference Comparison

`libcidr.bulk_aggregate()` output is compared directly against
`ipaddress.collapse_addresses()` for the same inputs:

```python
import ipaddress, libcidr

def test_bulk_aggregate_matches_ipaddress(self):
    prefixes_str = [
        "192.168.0.0/24", "192.168.1.0/24",   # adjacent /24s -> /23
        "10.0.0.0/8",     "10.1.0.0/16",       # contained -> /8 covers
        "172.16.0.0/12",
    ]
    libcidr_in  = [libcidr.IPv4Network(p) for p in prefixes_str]
    ipaddr_in   = [ipaddress.IPv4Network(p) for p in prefixes_str]

    libcidr_out = libcidr.bulk_aggregate(libcidr_in)
    ipaddr_out  = list(ipaddress.collapse_addresses(ipaddr_in))

    libcidr_strs = sorted(str(p) for p in libcidr_out)
    ipaddr_strs  = sorted(str(p) for p in ipaddr_out)
    self.assertEqual(libcidr_strs, ipaddr_strs)
```

---

## 8. Performance Benchmarks

Benchmarks live in `bench/` and are built and run by `make bench` and
`make bench-python` under release flags. They are not part of `make test`
-- they have no pass/fail criteria. Their purpose is to establish baselines
and detect regressions between versions.

### 8.1 What Is Measured

**C benchmarks** (`bench/bench_bulk.c`, `bench/bench_index.c`):

| Benchmark | Metric | Notes |
|---|---|---|
| `bench_bulk_parse` | Addresses parsed per second | IPv4 and IPv6 separately; 100k inputs |
| `bench_bulk_contains` | Address-prefix pair tests per second | Varying prefix table sizes: 100, 1k, 10k |
| `bench_bulk_aggregate` | Prefixes per second | Varying n: 1k, 10k, 100k, 800k |
| `bench_bulk_sort_network_asc` | Prefixes sorted per second | CIDR_SORT_NETWORK_ASC |
| `bench_bulk_sort_pfxlen_desc` | Prefixes sorted per second | CIDR_SORT_PFXLEN_DESC |
| `bench_aggregate_early_exit` | Prefixes per second (already aggregated) | Quantifies O(n) detection cost |
| `bench_index_build` | Prefixes indexed per second | Varying n: 1k, 10k, 100k, 800k |
| `bench_index_lookup` | Queries per second | 800k prefix table (routing table scale) |
| `bench_index_vs_bulk_crossover` | Crossover point where index amortises build cost | Identifies recommended threshold |

**Python benchmarks** (`bench/bench_python.py`):

| Benchmark | Comparison targets | Notes |
|---|---|---|
| Single address parse from string | `ipaddress`, `netaddr` | Repeated 100k times |
| Bulk parse: 100k addresses | `ipaddress` (list comp), `netaddr` | Measures construction throughput |
| Bulk containment: 100k addresses vs 10k prefixes | `ipaddress`, `pytricia` | Primary value proposition |
| Prefix aggregation: 50k prefixes | `ipaddress.collapse_addresses`, `netaddr` | |
| Index build + 1M lookups | `pytricia` | libcidr only for build; all three for lookup |

### 8.2 Baseline Recording Format

Each benchmark run prints full hardware context before results:

```
libcidr benchmark - bulk_contains
Platform : Linux x86_64
CPU      : Intel Core i7-12700K @ 4.9 GHz
Cores    : 12 (8P + 4E)
Build    : release (-O2)
Date     : 2026-MM-DD

prefix table size    libcidr (M pairs/s)
100                  ---
1,000                ---
10,000               ---
```

Python benchmark output additionally includes Python version and library
versions:

```
libcidr Python benchmark - bulk_contains
Platform     : Linux x86_64
Python       : 3.12.3
libcidr      : 1.0.0
ipaddress    : stdlib
netaddr      : 1.3.0
pytricia     : 1.0.2
Build        : release

operation          libcidr      ipaddress    netaddr     pytricia    speedup vs ipaddress
bulk_contains      ---          ---          ---         ---         ---x
```

Results without hardware context and library versions are not comparable
across machines or versions and must not be recorded as baselines.

### 8.3 Benchmark Targets (Indicative)

These are design targets derived from the architecture. They are not pass/fail
gates -- actual results on specific hardware will differ. The targets are
recorded here so that significant regressions are identified when benchmarks
are run.

| Benchmark | Design target | Notes |
|---|---|---|
| Bulk parse (IPv4) | > 10M addresses/sec (single core) | O(n) bounded by text scanning |
| Bulk contains (10k prefix table) | > 1M address-prefix pairs/sec | O(n*m), m=10k |
| Index lookup (800k prefix table) | > 50M queries/sec | O(W) per query |
| Python bulk parse vs ipaddress | > 5x faster | Object allocation eliminated |
| Python bulk contains vs pytricia | Comparable or faster | Different LPM semantics |

The Python comparison benchmarks are not expected to show uniform speedup
across all operations. Operations that are already fast in `ipaddress` (single
address parse) show smaller gains than bulk operations (bulk aggregation,
containment at scale) where object allocation overhead dominates.

---

## 9. Test Coverage Tracking

Track coverage manually. Update after each phase. A cell is marked done only
when the test passes cleanly under all sanitisers on both platforms.

### Unit Test Coverage

| Module | Test file | Written | Valgrind clean | ASan clean | TSan clean | OpenBSD |
|---|---|---|---|---|---|---|
| `cidr_addr.c` | test_addr.c | - | - | - | - | - |
| `cidr_prefix.c` | test_prefix.c | - | - | - | - | - |
| `cidr_bulk.c` | test_bulk.c | - | - | - | - | - |
| `cidr_classify.c` | test_classify.c | - | - | - | - | - |
| `cidr_index.c` | test_index.c | - | - | - | - | - |
| `_libcidr_ext.c` | test_python.py | - | - | - | - | - |

### Key Correctness Test Cases

| Test case | File | Reference |
|---|---|---|
| IPv4 leading zero rejected | test_addr.c | ARCHITECTURE.md §4.1.1 |
| IPv4 hex notation rejected | test_addr.c | ARCHITECTURE.md §4.1.1 |
| IPv6 double `::` rejected | test_addr.c | ARCHITECTURE.md §4.1.2 |
| IPv6 uppercase normalised | test_addr.c | ARCHITECTURE.md §4.1.2 |
| Mixed notation non-mapped rejected | test_addr.c | ARCHITECTURE.md §4.1.2 |
| IPv4-compatible rejected | test_addr.c | ARCHITECTURE.md §4.1.2 |
| Parse/format round-trip (IPv4) | test_addr.c | ARCHITECTURE.md §4.2 |
| Parse/format round-trip (IPv6) | test_addr.c | ARCHITECTURE.md §4.2 |
| RFC 5952 `::` placement (longest run) | test_addr.c | ARCHITECTURE.md §4.2.2 |
| RFC 5952 tie-breaking (first run) | test_addr.c | ARCHITECTURE.md §4.2.2 |
| RFC 5952 no `::` for single group | test_addr.c | ARCHITECTURE.md §4.2.2 |
| RFC 5952 mixed notation for mapped | test_addr.c | ARCHITECTURE.md §4.2.2 |
| `cidr_addr_to_v4()` CIDR_AF_UNSPEC → CIDR_ERR_INVAL | test_addr.c | ARCHITECTURE.md §4.1.3 |
| `cidr_addr_to_v4()` CIDR_AF_INET → CIDR_ERR_FAMILY | test_addr.c | ARCHITECTURE.md §4.1.3 |
| `cidr_addr_to_v4()` non-mapped IPv6 → CIDR_ERR_FAMILY | test_addr.c | ARCHITECTURE.md §4.1.3 |
| `cidr_prefix_parse()` host bits → CIDR_ERR_HOSTBITS | test_prefix.c | ARCHITECTURE.md §4.1.4 |
| `cidr_prefix_from_host()` all prefix lengths 0-32 (IPv4) | test_prefix.c | ARCHITECTURE.md §4.1.4 |
| `cidr_prefix_from_host()` all prefix lengths 0-128 (IPv6) | test_prefix.c | ARCHITECTURE.md §4.1.4 |
| `cidr_prefix_supernet()` → CIDR_ERR_OVERFLOW on /0 | test_prefix.c | ARCHITECTURE.md §4.3.7 |
| Subnet iterator ascending order | test_prefix.c | ARCHITECTURE.md §4.3.8 |
| Subnet iterator early termination safe | test_prefix.c | ARCHITECTURE.md §4.3.8 |
| Subnet iterator out not written on CIDR_ERR_DONE | test_prefix.c | ARCHITECTURE.md §4.3.8 |
| `cidr_bulk_parse()` NULL element → CIDR_ERR_INVAL fail-fast | test_bulk.c | ARCHITECTURE.md §5.2 |
| `cidr_bulk_parse()` return-code precedence | test_bulk.c | ARCHITECTURE.md §5.2 |
| `cidr_bulk_parse()` full-batch (all items attempted) | test_bulk.c | ARCHITECTURE.md §5.2 |
| `cidr_bulk_contains()` empty prefix table → all -1 | test_bulk.c | ARCHITECTURE.md §5.3 |
| `cidr_bulk_contains()` first-match semantics | test_bulk.c | ARCHITECTURE.md §5.3 |
| `cidr_bulk_contains()` LPM with pre-sorted table | test_bulk.c | ARCHITECTURE.md §5.3 |
| `cidr_bulk_aggregate()` result matches ipaddress.collapse_addresses | test_bulk.c | ARCHITECTURE.md §5.4 |
| `cidr_bulk_aggregate()` early termination (already aggregated) | test_bulk.c | ARCHITECTURE.md §5.4 |
| `cidr_bulk_sort()` CIDR_SORT_NETWORK_ASC order correct | test_bulk.c | ARCHITECTURE.md §5.5 |
| `cidr_bulk_sort()` CIDR_SORT_PFXLEN_DESC stability | test_bulk.c | ARCHITECTURE.md §5.5 |
| `cidr_bulk_sort()` invalid order → CIDR_ERR_INVAL | test_bulk.c | ARCHITECTURE.md §5.5 |
| CIDR_CLASS_GLOBAL mutually exclusive with all other flags | test_classify.c | ARCHITECTURE.md §7.2 |
| Multi-flag assignment for 2001::/23 sub-blocks | test_classify.c | ARCHITECTURE.md §7.2 |
| Terminated entry 192.88.99.0/24 classified correctly | test_classify.c | ARCHITECTURE.md §7.2 |
| Terminated entry 2001:10::/28 classified correctly | test_classify.c | ARCHITECTURE.md §7.2 |
| Multicast 224.0.0.0/4 → CIDR_CLASS_MULTICAST | test_classify.c | ARCHITECTURE.md §7.2 |
| Multicast ff00::/8 → CIDR_CLASS_MULTICAST | test_classify.c | ARCHITECTURE.md §7.2 |
| Boundary addresses: first/last of each block classified | test_classify.c | ARCHITECTURE.md §7.2 |
| `cidr_index_create()` count == 0 → CIDR_ERR_INVAL | test_index.c | ARCHITECTURE.md §6.2 |
| `cidr_index_create()` CIDR_AF_UNSPEC in array → CIDR_ERR_INVAL | test_index.c | ARCHITECTURE.md §6.2 |
| `cidr_index_create()` mixed family → CIDR_ERR_FAMILY | test_index.c | ARCHITECTURE.md §6.2 |
| Interior node prefix returned correctly | test_index.c | ARCHITECTURE.md §6.3 |
| Duplicate prefix: lower index returned | test_index.c | ARCHITECTURE.md §6.2 |
| `cidr_index_destroy()` NULL-safe | test_index.c | ARCHITECTURE.md §6.2 |
| Index memory clean after destroy (Valgrind) | test_index.c | ARCHITECTURE.md §1.4 |
| Concurrent parse from N threads: no races (TSan) | test_addr.c | ARCHITECTURE.md §1.4 |
| Concurrent `cidr_index_lookup()` from N threads: no races (TSan) | test_index.c | ARCHITECTURE.md §1.4 |
| Python `to_ipv4()` returns IPv4Address for mapped | test_python.py | ARCHITECTURE.md §8.6.3 |
| Python `to_ipv4()` returns None for non-mapped | test_python.py | ARCHITECTURE.md §8.6.3 |
| Python `bulk_aggregate()` matches ipaddress.collapse_addresses | test_python.py | ARCHITECTURE.md §8.8.1 |
| Python `bulk_contains_packed()` wrong element size raises error | test_python.py | ARCHITECTURE.md §8.8.2 |

### Quality Milestone Gate

| Milestone | Confirmed by |
|---|---|
| M1 - Build system works on all four targets | `make dev` passes on all platforms |
| M2 - All C tests pass on Linux | test binary passes on Linux x86_64 and ARM64 |
| M3 - All C tests pass on OpenBSD | test binary passes on OpenBSD amd64 and arm64 |
| M4 - Valgrind clean on Linux | `make valgrind` clean |
| M5 - ASan/UBSan clean on every target whose toolchain supports them | `make dev && make test` clean on all supported sanitizer targets |
| M6 - TSan clean on Linux | `make test-tsan` clean |
| M7 - clang-format clean | `make format` produces no diff |
| M8 - clang-tidy zero warnings | `make lint` clean |
| M9 - RFC conformance verified | all RFC test cases pass |
| M10 - bulk_aggregate matches ipaddress | comparison test passes |
| M11 - LC-trie LPM semantics verified | interior node and sorted-bulk tests pass |
| M12 - Python binding all tests pass | test_python.py passes on 3.11/3.12/3.13 |
| M13 - Benchmark baselines recorded | bench/ run on all platforms, results in BASELINES.md |

---

## 10. Cross-Reference

| Topic | Reference |
|---|---|
| Test harness structure and RUN macro | TECH_STACK.md §6 |
| ASan/UBSan compiler flags | TECH_STACK.md §7.2 |
| TSan compiler flags | TECH_STACK.md §7.3 |
| Valgrind usage | TECH_STACK.md §7.1 |
| Memory discipline check command | CODING_STANDARDS.md §7 pre-commit checklist |
| Per-phase test tasks and named cases | DEVELOPMENT.md (each phase) |
| IPv4 parsing rejection cases | ARCHITECTURE.md §4.1.1 |
| IPv6 parsing acceptance forms | ARCHITECTURE.md §4.1.2 |
| RFC 5952 formatting rules | ARCHITECTURE.md §4.2.2 |
| `cidr_addr_to_v4()` error distinction | ARCHITECTURE.md §4.1.3 |
| Host-bits invariant | ARCHITECTURE.md §3.3 |
| Bulk engine semantics | ARCHITECTURE.md §5 |
| `cidr_bulk_parse()` return-code precedence | ARCHITECTURE.md §5.2 |
| `CIDR_SORT_PFXLEN_DESC` stability | ARCHITECTURE.md §5.5 |
| LC-trie interior node semantics | ARCHITECTURE.md §6.3 |
| LPM vs first-match distinction | ARCHITECTURE.md §6.2 |
| Classification table and flags | ARCHITECTURE.md §7.2 |
| Thread safety model | ARCHITECTURE.md §1.4 |
| Python `to_ipv4()` | ARCHITECTURE.md §8.6.3 |
| Python `bulk_contains_packed()` validation | ARCHITECTURE.md §8.8.2 |
| Source file purposes | REPOSITORY_STRUCTURE.md §3 |
| Benchmark descriptions | REPOSITORY_STRUCTURE.md §6 |

---

**See Also**: PROJECT.md, ARCHITECTURE.md, TECH_STACK.md, CODING_STANDARDS.md,
DEVELOPMENT.md, REPOSITORY_STRUCTURE.md
