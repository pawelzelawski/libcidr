/*
 * test_bulk.c - bulk engine tests: cidr_bulk_parse and cidr_bulk_sort.
 *
 * Tests for cidr_bulk_parse() batch parse semantics and the shared
 * in-place MSD radix sort engine / cidr_bulk_sort().
 *
 * See DEVELOPMENT.md §Phase 4 Tests for the full test catalogue.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/libcidr.h"

#ifdef CIDR_STACK_CHECK
#define BULK_STACK_CHECK_COUNT 1000000U
#endif

static unsigned char *
prefix_marker_ptr(cidr_prefix_t *prefix)
{
	return ((unsigned char *)prefix) + 21;
}

static void
prefix_marker_set(cidr_prefix_t *prefix, uint8_t value)
{
	memset(prefix_marker_ptr(prefix), value, 3);
}

static uint8_t
prefix_marker_get(const cidr_prefix_t *prefix)
{
	return prefix_marker_ptr((cidr_prefix_t *)prefix)[0];
}

static int
expect_prefix_string(const cidr_prefix_t *prefix, const char *expected)
{
	char buf[CIDR_PREFIX_STR_MAX];

	if (cidr_prefix_format(prefix, buf, sizeof(buf)) != CIDR_OK)
		return 1;
	if (strcmp(buf, expected) != 0)
		return 1;
	return 0;
}

/*
 * test_bulk_parse_empty -- count == 0 returns CIDR_OK with no work
 * performed. See ARCHITECTURE.md §3.4 empty array policy.
 */
int
test_bulk_parse_empty(void)
{
	if (cidr_bulk_parse(NULL, 0, NULL, NULL) != CIDR_OK)
		return 1;
	return 0;
}

/*
 * test_bulk_parse_single -- single item parsed correctly.
 */
int
test_bulk_parse_single(void)
{
	const char *srcs[] = {"10.0.0.1"};
	cidr_addr_t out[1];
	cidr_err_t errs[1];
	cidr_err_t rc;

	rc = cidr_bulk_parse(srcs, 1, out, errs);
	if (rc != CIDR_OK)
		return 1;
	if (out[0].family != CIDR_AF_INET)
		return 1;
	if (out[0].addr.v4[0] != 10 || out[0].addr.v4[3] != 1)
		return 1;
	if (errs[0] != CIDR_OK)
		return 1;
	return 0;
}

/*
 * test_bulk_parse_all_valid -- all items parse successfully; correct
 * output and per-item error codes.
 */
int
test_bulk_parse_all_valid(void)
{
	const char *srcs[] = {"10.0.0.1", "192.168.1.1", "172.16.0.1"};
	cidr_addr_t out[3];
	cidr_err_t errs[3];
	cidr_err_t rc;

	rc = cidr_bulk_parse(srcs, 3, out, errs);
	if (rc != CIDR_OK)
		return 1;
	for (size_t i = 0; i < 3; i++) {
		if (out[i].family != CIDR_AF_INET)
			return 1;
		if (errs[i] != CIDR_OK)
			return 1;
	}
	return 0;
}

/*
 * test_bulk_parse_partial_failure -- mix of valid and invalid strings;
 * per-item error array reports each outcome; function returns CIDR_ERR_PARSE.
 */
int
test_bulk_parse_partial_failure(void)
{
	const char *srcs[] = {"10.0.0.1", "BAD", "10.0.0.3"};
	cidr_addr_t out[3];
	cidr_err_t errs[3];
	cidr_err_t rc;

	rc = cidr_bulk_parse(srcs, 3, out, errs);

	/* Batch return code is CIDR_ERR_PARSE (some items failed) */
	if (rc != CIDR_ERR_PARSE)
		return 1;

	/* Item 0: success */
	if (errs[0] != CIDR_OK)
		return 1;
	if (out[0].family != CIDR_AF_INET)
		return 1;

	/* Item 1: failure -- out written as CIDR_AF_UNSPEC */
	if (errs[1] != CIDR_ERR_PARSE)
		return 1;
	if (out[1].family != CIDR_AF_UNSPEC)
		return 1;

	/* Item 2: success */
	if (errs[2] != CIDR_OK)
		return 1;
	if (out[2].family != CIDR_AF_INET)
		return 1;

	return 0;
}

/*
 * test_bulk_parse_failure_zero_initialised -- parse failures must write a
 * zero-initialised cidr_addr_t, not only family = CIDR_AF_UNSPEC.
 */
int
test_bulk_parse_failure_zero_initialised(void)
{
	const char *srcs[] = {"BAD"};
	cidr_addr_t out[1];
	cidr_addr_t zero = {0};

	memset(out, 0x5A, sizeof(out));
	if (cidr_bulk_parse(srcs, 1, out, NULL) != CIDR_ERR_PARSE)
		return 1;
	if (memcmp(&out[0], &zero, sizeof(zero)) != 0)
		return 1;
	return 0;
}

/*
 * test_bulk_parse_null_errs -- NULL errs is valid; per-item errors are
 * suppressed; function still returns correct batch code.
 */
int
test_bulk_parse_null_errs(void)
{
	const char *srcs[] = {"10.0.0.1", "BAD", "10.0.0.3"};
	cidr_addr_t out[3];
	cidr_err_t rc;

	rc = cidr_bulk_parse(srcs, 3, out, NULL);
	if (rc != CIDR_ERR_PARSE)
		return 1;
	if (out[0].family != CIDR_AF_INET)
		return 1;
	if (out[1].family != CIDR_AF_UNSPEC)
		return 1;
	if (out[2].family != CIDR_AF_INET)
		return 1;
	return 0;
}

/*
 * test_bulk_parse_null_element -- NULL element in srcs triggers fail-fast;
 * CIDR_ERR_INVAL returned; no output written.
 * See TESTING.md §6.3 and ARCHITECTURE.md §5.2.
 */
int
test_bulk_parse_null_element(void)
{
	cidr_addr_t out[3];
	cidr_err_t errs[3];
	const char *srcs[] = {"10.0.0.1", NULL, "10.0.0.3"};

	/* Pre-mark out[0].family to verify no output is written */
	memset(out, 0, sizeof(out));
	out[0].family = CIDR_AF_INET;

	if (cidr_bulk_parse(srcs, 3, out, errs) != CIDR_ERR_INVAL)
		return 1;

	/* out[0] must not have been touched (still CIDR_AF_INET) */
	if (out[0].family != CIDR_AF_INET)
		return 1;

	return 0;
}

/*
 * test_bulk_parse_return_code_precedence -- NULL element beats everything;
 * mixed family beats parse failure. See TESTING.md §6.3.
 */
int
test_bulk_parse_return_code_precedence(void)
{
	cidr_addr_t out[3];
	cidr_err_t errs[3];

	/* NULL element -- fail-fast, CIDR_ERR_INVAL, no output */
	memset(out, 0, sizeof(out));
	out[0].family = CIDR_AF_INET;
	{
		const char *with_null[] = {"10.0.0.1", NULL, "10.0.0.3"};
		if (cidr_bulk_parse(with_null, 3, out, errs) != CIDR_ERR_INVAL)
			return 1;
		if (out[0].family != CIDR_AF_INET)
			return 1;
	}

	/* Mixed family + parse failure: CIDR_ERR_FAMILY wins */
	{
		const char *mixed[] = {"10.0.0.1", "BAD", "2001:db8::1"};
		if (cidr_bulk_parse(mixed, 3, out, errs) != CIDR_ERR_FAMILY)
			return 1;
	}

	return 0;
}

/*
 * test_bulk_parse_full_batch_all_attempted -- even when items fail,
 * all items are processed (no fail-fast). Verify items after a failure
 * are still parsed correctly.
 */
int
test_bulk_parse_full_batch_all_attempted(void)
{
	const char *srcs[] = {"BAD1", "10.0.0.2", "BAD3"};
	cidr_addr_t out[3];
	cidr_err_t errs[3];
	cidr_err_t rc;

	rc = cidr_bulk_parse(srcs, 3, out, errs);
	if (rc != CIDR_ERR_PARSE)
		return 1;

	/* Item 0: failure */
	if (errs[0] != CIDR_ERR_PARSE)
		return 1;
	if (out[0].family != CIDR_AF_UNSPEC)
		return 1;

	/* Item 1: success (processed even though item 0 failed) */
	if (errs[1] != CIDR_OK)
		return 1;
	if (out[1].family != CIDR_AF_INET)
		return 1;

	/* Item 2: failure (processed even though item 1 succeeded) */
	if (errs[2] != CIDR_ERR_PARSE)
		return 1;
	if (out[2].family != CIDR_AF_UNSPEC)
		return 1;

	return 0;
}

/*
 * test_bulk_contains_first_match -- first matching prefix returned; later
 * matching prefixes ignored.
 */
int
test_bulk_contains_first_match(void)
{
	cidr_prefix_t prefixes[3];
	cidr_addr_t addrs[3];
	ssize_t matches[3];
	cidr_err_t rc;

	if (cidr_prefix_parse("10.0.0.0/8", &prefixes[0]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("192.168.0.0/16", &prefixes[1]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("10.1.0.0/16", &prefixes[2]) != CIDR_OK)
		return 1;

	if (cidr_addr_parse("10.1.1.1", &addrs[0]) != CIDR_OK)
		return 1;
	if (cidr_addr_parse("192.168.1.1", &addrs[1]) != CIDR_OK)
		return 1;
	if (cidr_addr_parse("172.16.0.1", &addrs[2]) != CIDR_OK)
		return 1;

	rc = cidr_bulk_contains(addrs, 3, prefixes, 3, matches, NULL);
	if (rc != CIDR_OK)
		return 1;

	/* 10.1.1.1 matches 10.0.0.0/8 (index 0) -- first in order */
	if (matches[0] != 0)
		return 1;
	/* 192.168.1.1 matches 192.168.0.0/16 (index 1) */
	if (matches[1] != 1)
		return 1;
	/* 172.16.0.1 matches nothing */
	if (matches[2] != -1)
		return 1;

	return 0;
}

/*
 * test_bulk_contains_no_match -- address not in any prefix returns -1.
 */
int
test_bulk_contains_no_match(void)
{
	cidr_prefix_t prefixes[1];
	cidr_addr_t addrs[1];
	ssize_t matches[1];
	cidr_err_t rc;

	if (cidr_prefix_parse("10.0.0.0/8", &prefixes[0]) != CIDR_OK)
		return 1;
	if (cidr_addr_parse("192.168.1.1", &addrs[0]) != CIDR_OK)
		return 1;

	rc = cidr_bulk_contains(addrs, 1, prefixes, 1, matches, NULL);
	if (rc != CIDR_OK)
		return 1;
	if (matches[0] != -1)
		return 1;

	return 0;
}

/*
 * test_bulk_contains_lpm_with_sorted_table -- after sorting by
 * CIDR_SORT_PFXLEN_DESC, the first match is the most specific prefix.
 * See ARCHITECTURE.md §5.3, §5.5.
 */
int
test_bulk_contains_lpm_with_sorted_table(void)
{
	cidr_prefix_t prefixes[4];
	cidr_addr_t addrs[4];
	ssize_t matches[4];
	cidr_err_t rc;

	if (cidr_prefix_parse("10.0.0.0/8", &prefixes[0]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("10.1.0.0/16", &prefixes[1]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("10.1.2.0/24", &prefixes[2]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("192.168.0.0/16", &prefixes[3]) != CIDR_OK)
		return 1;

	/* Sort by prefix length descending for LPM preparation */
	rc = cidr_bulk_sort(prefixes, 4, CIDR_SORT_PFXLEN_DESC);
	if (rc != CIDR_OK)
		return 1;

	if (cidr_addr_parse("10.1.2.5", &addrs[0]) != CIDR_OK)
		return 1;
	if (cidr_addr_parse("10.1.1.1", &addrs[1]) != CIDR_OK)
		return 1;
	if (cidr_addr_parse("10.2.0.1", &addrs[2]) != CIDR_OK)
		return 1;
	if (cidr_addr_parse("172.16.0.1", &addrs[3]) != CIDR_OK)
		return 1;

	rc = cidr_bulk_contains(addrs, 4, prefixes, 4, matches, NULL);
	if (rc != CIDR_OK)
		return 1;

	/* All addresses except 172.16.0.1 must find a match */
	if (matches[0] < 0 || matches[1] < 0 || matches[2] < 0)
		return 1;
	if (matches[3] != -1)
		return 1;

	/*
	 * With CIDR_SORT_PFXLEN_DESC, longer prefixes sort first.
	 * The matched prefix's pfxlen must be the most specific match.
	 */
	/* 10.1.2.5 matches /24 */
	if (prefixes[matches[0]].pfxlen != 24)
		return 1;
	/* 10.1.1.1 matches /16 (no /24 covers it) */
	if (prefixes[matches[1]].pfxlen != 16)
		return 1;
	/* 10.2.0.1 matches /8 (only /8 covers it) */
	if (prefixes[matches[2]].pfxlen != 8)
		return 1;

	return 0;
}

/*
 * test_bulk_contains_empty_prefix_table -- when prefix_count == 0, all
 * matches are -1 and CIDR_OK is returned. See ARCHITECTURE.md §5.3.
 */
int
test_bulk_contains_empty_prefix_table(void)
{
	cidr_addr_t addrs[2];
	ssize_t matches[2];
	cidr_err_t errs[2] = {CIDR_ERR_PARSE, CIDR_ERR_PARSE};
	cidr_err_t rc;

	if (cidr_addr_parse("10.0.0.1", &addrs[0]) != CIDR_OK)
		return 1;
	if (cidr_addr_parse("192.168.1.1", &addrs[1]) != CIDR_OK)
		return 1;

	rc = cidr_bulk_contains(addrs, 2, NULL, 0, matches, errs);
	if (rc != CIDR_OK)
		return 1;
	if (matches[0] != -1 || matches[1] != -1)
		return 1;
	if (errs[0] != CIDR_OK || errs[1] != CIDR_OK)
		return 1;

	return 0;
}

/*
 * test_bulk_contains_null_matches_nonzero_count -- when addr_count > 0 and
 * matches is NULL, CIDR_ERR_INVAL is returned. See ARCHITECTURE.md §5.3.
 */
int
test_bulk_contains_null_matches_nonzero_count(void)
{
	cidr_addr_t addrs[1];

	if (cidr_addr_parse("10.0.0.1", &addrs[0]) != CIDR_OK)
		return 1;

	if (cidr_bulk_contains(addrs, 1, NULL, 0, NULL, NULL) != CIDR_ERR_INVAL)
		return 1;

	return 0;
}

/*
 * test_bulk_contains_family_mismatch -- CIDR_ERR_FAMILY when address and
 * prefix arrays have different families. See ARCHITECTURE.md §5.3.
 */
int
test_bulk_contains_family_mismatch(void)
{
	cidr_prefix_t prefixes[1];
	cidr_addr_t addrs[1];
	ssize_t matches[1];
	cidr_err_t errs[1] = {CIDR_OK};

	if (cidr_prefix_parse("10.0.0.0/8", &prefixes[0]) != CIDR_OK)
		return 1;
	if (cidr_addr_parse("2001:db8::1", &addrs[0]) != CIDR_OK)
		return 1;

	if (cidr_bulk_contains(addrs, 1, prefixes, 1, matches, errs) !=
	    CIDR_ERR_FAMILY)
		return 1;
	if (matches[0] != -1)
		return 1;
	if (errs[0] != CIDR_ERR_FAMILY)
		return 1;

	return 0;
}

/*
 * test_bulk_contains_partial_byte_boundary -- a non-byte-aligned prefix
 * length (/20) exercises the partial-byte mask branch of the containment
 * comparator. An address inside the prefix matches; a near-miss that differs
 * only in the masked bits of the partial byte does not. See ARCHITECTURE.md
 * §5.3, §4.3.5.
 */
int
test_bulk_contains_partial_byte_boundary(void)
{
	cidr_prefix_t prefixes[1];
	cidr_addr_t addrs[2];
	ssize_t matches[2];
	cidr_err_t rc;

	/*
	 * 10.16.0.0/20 covers 10.16.0.0 .. 10.16.15.255: bytes 0-1 are
	 * compared in full, and only the top 4 bits of byte 2 are masked.
	 */
	if (cidr_prefix_parse("10.16.0.0/20", &prefixes[0]) != CIDR_OK)
		return 1;

	/* 10.16.15.254 is inside (byte 2 = 0x0f, top nibble 0). */
	if (cidr_addr_parse("10.16.15.254", &addrs[0]) != CIDR_OK)
		return 1;
	/*
	 * 10.16.16.1 differs only in the masked bits of the partial byte
	 * (byte 2 = 0x10, top nibble 1), so it falls outside the /20.
	 */
	if (cidr_addr_parse("10.16.16.1", &addrs[1]) != CIDR_OK)
		return 1;

	rc = cidr_bulk_contains(addrs, 2, prefixes, 1, matches, NULL);
	if (rc != CIDR_OK)
		return 1;
	if (matches[0] != 0)
		return 1;
	if (matches[1] != -1)
		return 1;

	return 0;
}

/*
 * test_bulk_contains_default_route -- a /0 prefix matches every address,
 * exercising the pfxlen == 0 short-circuit of the containment comparator.
 * See ARCHITECTURE.md §5.3.
 */
int
test_bulk_contains_default_route(void)
{
	cidr_prefix_t prefixes[1];
	cidr_addr_t addrs[2];
	ssize_t matches[2];
	cidr_err_t rc;

	if (cidr_prefix_parse("0.0.0.0/0", &prefixes[0]) != CIDR_OK)
		return 1;
	if (cidr_addr_parse("10.0.0.1", &addrs[0]) != CIDR_OK)
		return 1;
	if (cidr_addr_parse("203.0.113.255", &addrs[1]) != CIDR_OK)
		return 1;

	rc = cidr_bulk_contains(addrs, 2, prefixes, 1, matches, NULL);
	if (rc != CIDR_OK)
		return 1;
	if (matches[0] != 0 || matches[1] != 0)
		return 1;

	return 0;
}

/*
 * test_bulk_contains_ipv6_match -- IPv6 containment across the 16-byte path.
 * A byte-aligned /48 and a non-byte-aligned /36 exercise both the full-byte
 * and partial-byte branches of the comparator for the wider family.
 * See ARCHITECTURE.md §5.3, §4.3.5.
 */
int
test_bulk_contains_ipv6_match(void)
{
	cidr_prefix_t prefixes[2];
	cidr_addr_t addrs[3];
	ssize_t matches[3];
	cidr_err_t rc;

	/* /48 is byte-aligned (full-byte compare only). */
	if (cidr_prefix_parse("2001:db8:abcd::/48", &prefixes[0]) != CIDR_OK)
		return 1;
	/* /36 is non-byte-aligned (partial-byte mask branch). */
	if (cidr_prefix_parse("2001:db8:a000::/36", &prefixes[1]) != CIDR_OK)
		return 1;

	/* Inside the /48 (and also inside the /36); first match wins -> 0. */
	if (cidr_addr_parse("2001:db8:abcd:1::1", &addrs[0]) != CIDR_OK)
		return 1;
	/* Inside the /36 but not the /48 -> 1. */
	if (cidr_addr_parse("2001:db8:a123::1", &addrs[1]) != CIDR_OK)
		return 1;
	/* Outside both -> -1. */
	if (cidr_addr_parse("2001:db8:b000::1", &addrs[2]) != CIDR_OK)
		return 1;

	rc = cidr_bulk_contains(addrs, 3, prefixes, 2, matches, NULL);
	if (rc != CIDR_OK)
		return 1;
	if (matches[0] != 0)
		return 1;
	if (matches[1] != 1)
		return 1;
	if (matches[2] != -1)
		return 1;

	return 0;
}

/*
 * test_bulk_aggregate_known_cases -- known aggregation cases verified
 * against ipaddress.collapse_addresses reference results.
 * See ARCHITECTURE.md §5.4.
 */
int
test_bulk_aggregate_known_cases(void)
{
	static const struct {
		const char *name;
		const char *inputs[8];
		const char *expected[8];
		size_t input_count;
		size_t expected_count;
	} cases[] = {
	    {
	        .name = "adjacent /24s collapse to /22",
	        .inputs =
	            {
	                "10.0.0.0/24",
	                "10.0.1.0/24",
	                "10.0.2.0/24",
	                "10.0.3.0/24",
	            },
	        .expected = {"10.0.0.0/22"},
	        .input_count = 4,
	        .expected_count = 1,
	    },
	    {
	        .name = "contained prefixes collapse to covering /8",
	        .inputs =
	            {
	                "10.0.0.0/8",
	                "10.1.0.0/16",
	                "10.1.2.0/24",
	                "10.2.0.0/16",
	            },
	        .expected = {"10.0.0.0/8"},
	        .input_count = 4,
	        .expected_count = 1,
	    },
	    {
	        .name = "mixed disjoint and mergeable prefixes match ipaddress",
	        .inputs =
	            {
	                "192.168.0.0/24",
	                "192.168.1.0/24",
	                "10.0.0.0/8",
	                "10.1.0.0/16",
	                "172.16.0.0/12",
	            },
	        .expected =
	            {
	                "10.0.0.0/8",
	                "172.16.0.0/12",
	                "192.168.0.0/23",
	            },
	        .input_count = 5,
	        .expected_count = 3,
	    },
	};
	cidr_prefix_t prefixes[8];
	size_t out_count;
	size_t case_idx;
	size_t i;

	for (case_idx = 0; case_idx < sizeof(cases) / sizeof(cases[0]);
	     case_idx++) {
		for (i = 0; i < cases[case_idx].input_count; i++) {
			if (cidr_prefix_parse(cases[case_idx].inputs[i],
			                      &prefixes[i]) != CIDR_OK)
				return 1;
		}

		if (cidr_bulk_aggregate(prefixes, cases[case_idx].input_count,
		                        &out_count) != CIDR_OK)
			return 1;
		if (out_count != cases[case_idx].expected_count)
			return 1;
		for (i = 0; i < out_count; i++) {
			if (expect_prefix_string(
			        &prefixes[i], cases[case_idx].expected[i]) != 0)
				return 1;
		}
	}

	return 0;
}

/*
 * test_bulk_aggregate_duplicate_removal -- exact duplicates removed
 * before sibling merge.
 */
int
test_bulk_aggregate_duplicate_removal(void)
{
	cidr_prefix_t prefixes[5];
	size_t out_count;
	cidr_err_t rc;

	if (cidr_prefix_parse("10.0.0.0/24", &prefixes[0]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("10.0.0.0/24", &prefixes[1]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("10.0.1.0/24", &prefixes[2]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("10.0.0.0/24", &prefixes[3]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("10.0.1.0/24", &prefixes[4]) != CIDR_OK)
		return 1;

	rc = cidr_bulk_aggregate(prefixes, 5, &out_count);
	if (rc != CIDR_OK)
		return 1;

	/* After dedup: 10.0.0.0/24, 10.0.1.0/24 → merge to /23 */
	if (out_count != 1)
		return 1;

	{
		char buf[CIDR_PREFIX_STR_MAX];

		if (cidr_prefix_format(&prefixes[0], buf, sizeof(buf)) !=
		    CIDR_OK)
			return 1;
		if (strcmp(buf, "10.0.0.0/23") != 0)
			return 1;
	}

	return 0;
}

/*
 * test_bulk_aggregate_containment_removal -- prefix covered by a shorter
 * prefix is removed. See ARCHITECTURE.md §5.4 step 3.
 */
int
test_bulk_aggregate_containment_removal(void)
{
	cidr_prefix_t prefixes[3];
	size_t out_count;
	cidr_err_t rc;

	if (cidr_prefix_parse("10.0.0.0/8", &prefixes[0]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("10.1.0.0/16", &prefixes[1]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("10.0.0.0/16", &prefixes[2]) != CIDR_OK)
		return 1;

	rc = cidr_bulk_aggregate(prefixes, 3, &out_count);
	if (rc != CIDR_OK)
		return 1;

	/* /8 contains both /16s → only /8 remains */
	if (out_count != 1)
		return 1;

	{
		char buf[CIDR_PREFIX_STR_MAX];

		if (cidr_prefix_format(&prefixes[0], buf, sizeof(buf)) !=
		    CIDR_OK)
			return 1;
		if (strcmp(buf, "10.0.0.0/8") != 0)
			return 1;
	}

	return 0;
}

/*
 * test_bulk_aggregate_sibling_merge -- adjacent /24 siblings merge to /23.
 * See ARCHITECTURE.md §5.4 step 4.
 */
int
test_bulk_aggregate_sibling_merge(void)
{
	cidr_prefix_t prefixes[2];
	size_t out_count;
	cidr_err_t rc;

	if (cidr_prefix_parse("192.168.0.0/24", &prefixes[0]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("192.168.1.0/24", &prefixes[1]) != CIDR_OK)
		return 1;

	rc = cidr_bulk_aggregate(prefixes, 2, &out_count);
	if (rc != CIDR_OK)
		return 1;
	if (out_count != 1)
		return 1;

	{
		char buf[CIDR_PREFIX_STR_MAX];

		if (cidr_prefix_format(&prefixes[0], buf, sizeof(buf)) !=
		    CIDR_OK)
			return 1;
		if (strcmp(buf, "192.168.0.0/23") != 0)
			return 1;
	}

	return 0;
}

/*
 * test_bulk_aggregate_early_termination -- already-aggregated input
 * produces no merges and exits immediately. See ARCHITECTURE.md §5.4.
 */
int
test_bulk_aggregate_early_termination(void)
{
	cidr_prefix_t prefixes[2];
	size_t out_count;
	cidr_err_t rc;

	if (cidr_prefix_parse("10.0.0.0/8", &prefixes[0]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("172.16.0.0/12", &prefixes[1]) != CIDR_OK)
		return 1;

	rc = cidr_bulk_aggregate(prefixes, 2, &out_count);
	if (rc != CIDR_OK)
		return 1;
	if (out_count != 2)
		return 1;

	return 0;
}

/*
 * test_bulk_aggregate_single_prefix -- single element is a no-op.
 */
int
test_bulk_aggregate_single_prefix(void)
{
	cidr_prefix_t prefixes[1];
	size_t out_count;
	cidr_err_t rc;

	if (cidr_prefix_parse("10.0.0.0/8", &prefixes[0]) != CIDR_OK)
		return 1;

	rc = cidr_bulk_aggregate(prefixes, 1, &out_count);
	if (rc != CIDR_OK)
		return 1;
	if (out_count != 1)
		return 1;

	return 0;
}

/*
 * test_bulk_aggregate_null_out_count -- NULL out_count returns
 * CIDR_ERR_INVAL. See ARCHITECTURE.md §5.4.
 */
int
test_bulk_aggregate_null_out_count(void)
{
	if (cidr_bulk_aggregate(NULL, 0, NULL) != CIDR_ERR_INVAL)
		return 1;
	return 0;
}

/*
 * test_bulk_sort_empty -- count == 0 returns CIDR_OK without touching
 * the prefixes pointer. See ARCHITECTURE.md §3.4 empty array policy.
 */
int
test_bulk_sort_empty(void)
{
	if (cidr_bulk_sort(NULL, 0, CIDR_SORT_NETWORK_ASC) != CIDR_OK)
		return 1;
	if (cidr_bulk_sort(NULL, 0, CIDR_SORT_PFXLEN_DESC) != CIDR_OK)
		return 1;
	return 0;
}

/*
 * test_bulk_sort_single -- single-element array sorted is a no-op.
 */
int
test_bulk_sort_single(void)
{
	cidr_prefix_t pfx;

	if (cidr_prefix_parse("10.0.0.0/8", &pfx) != CIDR_OK)
		return 1;

	if (cidr_bulk_sort(&pfx, 1, CIDR_SORT_NETWORK_ASC) != CIDR_OK)
		return 1;
	if (cidr_bulk_sort(&pfx, 1, CIDR_SORT_PFXLEN_DESC) != CIDR_OK)
		return 1;
	return 0;
}

/*
 * test_bulk_sort_invalid_order -- returns CIDR_ERR_INVAL for invalid
 * cidr_sort_order_t value.
 */
int
test_bulk_sort_invalid_order(void)
{
	cidr_prefix_t pfx;

	if (cidr_prefix_parse("10.0.0.0/8", &pfx) != CIDR_OK)
		return 1;

	if (cidr_bulk_sort(&pfx, 1, (cidr_sort_order_t)99) != CIDR_ERR_INVAL)
		return 1;
	if (cidr_bulk_sort(&pfx, 1, (cidr_sort_order_t)2) != CIDR_ERR_INVAL)
		return 1;
	/* Also test that NULL prefixes with count == 0 still succeeds */
	if (cidr_bulk_sort(NULL, 0, (cidr_sort_order_t)99) != CIDR_OK)
		return 1;
	return 0;
}

/*
 * test_bulk_sort_network_asc_order -- verify CIDR_SORT_NETWORK_ASC
 * ordering: network address ascending (lexicographic on addr bytes),
 * then prefix length ascending within the same network address.
 */
int
test_bulk_sort_network_asc_order(void)
{
	cidr_prefix_t prefixes[6];
	cidr_err_t rc;

	/* Set up: 10.1.0.0/24, 10.0.0.0/8, 10.1.0.0/16, 192.168.0.0/24,
	 * 10.1.0.0/24 (duplicate of first), 172.16.0.0/12 */
	if (cidr_prefix_parse("10.1.0.0/24", &prefixes[0]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("10.0.0.0/8", &prefixes[1]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("10.1.0.0/16", &prefixes[2]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("192.168.0.0/24", &prefixes[3]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("10.1.0.0/24", &prefixes[4]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("172.16.0.0/12", &prefixes[5]) != CIDR_OK)
		return 1;

	rc = cidr_bulk_sort(prefixes, 6, CIDR_SORT_NETWORK_ASC);
	if (rc != CIDR_OK)
		return 1;

	/* Expected order: 10.0.0.0/8, 10.1.0.0/16, 10.1.0.0/24,
	 * 10.1.0.0/24 (duplicate), 172.16.0.0/12, 192.168.0.0/24 */
	{
		char buf[CIDR_PREFIX_STR_MAX];
		const char *expected[] = {
		    "10.0.0.0/8",  "10.1.0.0/16",   "10.1.0.0/24",
		    "10.1.0.0/24", "172.16.0.0/12", "192.168.0.0/24",
		};

		for (size_t i = 0; i < 6; i++) {
			if (cidr_prefix_format(&prefixes[i], buf,
			                       sizeof(buf)) != CIDR_OK)
				return 1;
			if (strcmp(buf, expected[i]) != 0)
				return 1;
		}
	}

	return 0;
}

/*
 * test_bulk_sort_network_asc_ipv6 -- verify CIDR_SORT_NETWORK_ASC
 * ordering for IPv6 prefixes.
 */
int
test_bulk_sort_network_asc_ipv6(void)
{
	cidr_prefix_t prefixes[4];
	cidr_err_t rc;

	if (cidr_prefix_parse("2001:db8::/32", &prefixes[0]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("::1/128", &prefixes[1]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("2001:db8:1::/48", &prefixes[2]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("fe80::/10", &prefixes[3]) != CIDR_OK)
		return 1;

	rc = cidr_bulk_sort(prefixes, 4, CIDR_SORT_NETWORK_ASC);
	if (rc != CIDR_OK)
		return 1;

	{
		char buf[CIDR_PREFIX_STR_MAX];
		const char *expected[] = {
		    "::1/128",
		    "2001:db8::/32",
		    "2001:db8:1::/48",
		    "fe80::/10",
		};

		for (size_t i = 0; i < 4; i++) {
			if (cidr_prefix_format(&prefixes[i], buf,
			                       sizeof(buf)) != CIDR_OK)
				return 1;
			if (strcmp(buf, expected[i]) != 0)
				return 1;
		}
	}

	return 0;
}

/*
 * test_bulk_sort_pfxlen_desc_order -- verify CIDR_SORT_PFXLEN_DESC
 * ordering: prefix length descending, network address ascending within
 * equal prefix lengths.
 */
int
test_bulk_sort_pfxlen_desc_order(void)
{
	cidr_prefix_t prefixes[5];
	cidr_err_t rc;

	if (cidr_prefix_parse("10.0.0.0/8", &prefixes[0]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("10.1.0.0/24", &prefixes[1]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("10.0.0.0/16", &prefixes[2]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("192.168.0.0/16", &prefixes[3]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("10.1.2.0/24", &prefixes[4]) != CIDR_OK)
		return 1;

	rc = cidr_bulk_sort(prefixes, 5, CIDR_SORT_PFXLEN_DESC);
	if (rc != CIDR_OK)
		return 1;

	/*
	 * Expected order by ~pfxlen then addr:
	 * /24: 10.1.0.0/24, 10.1.2.0/24
	 * /16: 10.0.0.0/16, 192.168.0.0/16
	 * /8:  10.0.0.0/8
	 */
	{
		char buf[CIDR_PREFIX_STR_MAX];
		const char *expected[] = {
		    "10.1.0.0/24",    "10.1.2.0/24", "10.0.0.0/16",
		    "192.168.0.0/16", "10.0.0.0/8",
		};

		for (size_t i = 0; i < 5; i++) {
			if (cidr_prefix_format(&prefixes[i], buf,
			                       sizeof(buf)) != CIDR_OK)
				return 1;
			if (strcmp(buf, expected[i]) != 0)
				return 1;
		}
	}

	return 0;
}

/*
 * test_bulk_sort_pfxlen_desc_stability -- verify that CIDR_SORT_PFXLEN_DESC
 * is stable: exact duplicate prefixes preserve their original input order.
 *
 * Per TESTING.md §6.4 and ARCHITECTURE.md §5.5.
 */
int
test_bulk_sort_pfxlen_desc_stability(void)
{
	cidr_prefix_t prefixes[5];
	uint8_t expected[] = {0x10, 0x13, 0x12, 0x21, 0x24};
	size_t i;

	/*
	 * Set up an array with duplicates at known positions:
	 * index 1 and 4 are identical (10.0.0.0/8).
	 * index 0 and 3 are identical (10.1.0.0/24).
	 */
	if (cidr_prefix_parse("10.1.0.0/24", &prefixes[0]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("10.0.0.0/8", &prefixes[1]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("172.16.0.0/12", &prefixes[2]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("10.1.0.0/24", &prefixes[3]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("10.0.0.0/8", &prefixes[4]) != CIDR_OK)
		return 1;
	prefix_marker_set(&prefixes[0], 0x10);
	prefix_marker_set(&prefixes[1], 0x21);
	prefix_marker_set(&prefixes[2], 0x12);
	prefix_marker_set(&prefixes[3], 0x13);
	prefix_marker_set(&prefixes[4], 0x24);

	if (cidr_bulk_sort(prefixes, 5, CIDR_SORT_PFXLEN_DESC) != CIDR_OK)
		return 1;

	for (i = 0; i < 5; i++) {
		if (prefix_marker_get(&prefixes[i]) != expected[i])
			return 1;
	}
	if (expect_prefix_string(&prefixes[0], "10.1.0.0/24") != 0)
		return 1;
	if (expect_prefix_string(&prefixes[1], "10.1.0.0/24") != 0)
		return 1;
	if (expect_prefix_string(&prefixes[2], "172.16.0.0/12") != 0)
		return 1;
	if (expect_prefix_string(&prefixes[3], "10.0.0.0/8") != 0)
		return 1;
	if (expect_prefix_string(&prefixes[4], "10.0.0.0/8") != 0)
		return 1;

	return 0;
}

#ifdef CIDR_STACK_CHECK
/*
 * test_bulk_sort_ipv6_million_stack_bound -- verify the documented stack
 * bound with a 1M-entry IPv6 input under the ASan/UBSan build.
 */
int
test_bulk_sort_ipv6_million_stack_bound(void)
{
	cidr_prefix_t *prefixes;
	size_t count;
	size_t i;

	count = BULK_STACK_CHECK_COUNT;
	prefixes = calloc(count, sizeof(*prefixes));
	if (prefixes == NULL)
		return 1;

	for (i = 0; i < count; i++) {
		prefixes[i].addr.family = CIDR_AF_INET6;
		prefixes[i].addr.addr.v6[0] = 0x20;
		prefixes[i].addr.addr.v6[1] = 0x01;
		prefixes[i].addr.addr.v6[2] = 0x0d;
		prefixes[i].addr.addr.v6[3] = 0xb8;
		prefixes[i].addr.addr.v6[12] = (uint8_t)(i >> 24);
		prefixes[i].addr.addr.v6[13] = (uint8_t)(i >> 16);
		prefixes[i].addr.addr.v6[14] = (uint8_t)(i >> 8);
		prefixes[i].addr.addr.v6[15] = (uint8_t)i;
		prefixes[i].pfxlen = 128;
	}

	if (cidr_bulk_sort(prefixes, count, CIDR_SORT_PFXLEN_DESC) != CIDR_OK) {
		free(prefixes);
		return 1;
	}
	if (prefixes[0].addr.addr.v6[12] != 0 ||
	    prefixes[0].addr.addr.v6[13] != 0 ||
	    prefixes[0].addr.addr.v6[14] != 0 ||
	    prefixes[0].addr.addr.v6[15] != 0) {
		free(prefixes);
		return 1;
	}
	if (prefixes[count - 1].addr.addr.v6[12] !=
	        (uint8_t)((count - 1) >> 24) ||
	    prefixes[count - 1].addr.addr.v6[13] !=
	        (uint8_t)((count - 1) >> 16) ||
	    prefixes[count - 1].addr.addr.v6[14] !=
	        (uint8_t)((count - 1) >> 8) ||
	    prefixes[count - 1].addr.addr.v6[15] != (uint8_t)(count - 1)) {
		free(prefixes);
		return 1;
	}

	free(prefixes);
	return 0;
}

/*
 * test_bulk_aggregate_ipv6_million_stack_bound -- verify bulk aggregation on
 * a 1M-entry IPv6 input does not overflow the stack.
 */
int
test_bulk_aggregate_ipv6_million_stack_bound(void)
{
	cidr_prefix_t *prefixes;
	size_t count;
	size_t out_count;
	size_t i;

	count = BULK_STACK_CHECK_COUNT;
	prefixes = calloc(count, sizeof(*prefixes));
	if (prefixes == NULL)
		return 1;

	for (i = 0; i < count; i++) {
		prefixes[i].addr.family = CIDR_AF_INET6;
		prefixes[i].addr.addr.v6[0] = 0x20;
		prefixes[i].addr.addr.v6[1] = 0x01;
		prefixes[i].addr.addr.v6[2] = 0x0d;
		prefixes[i].addr.addr.v6[3] = 0xb8;
		prefixes[i].addr.addr.v6[4] = (uint8_t)(i >> 8);
		prefixes[i].addr.addr.v6[5] = (uint8_t)i;
		prefixes[i].pfxlen = 128;
	}

	if (cidr_bulk_aggregate(prefixes, count, &out_count) != CIDR_OK) {
		free(prefixes);
		return 1;
	}
	if (out_count == 0) {
		free(prefixes);
		return 1;
	}

	free(prefixes);
	return 0;
}
#endif

/*
 * test_bulk_sort_null_prefixes -- CIDR_ERR_INVAL when count > 0 and
 * prefixes is NULL.
 */
int
test_bulk_sort_null_prefixes(void)
{
	if (cidr_bulk_sort(NULL, 1, CIDR_SORT_NETWORK_ASC) != CIDR_ERR_INVAL)
		return 1;
	return 0;
}

/*
 * test_bulk_sort_family_mismatch -- CIDR_ERR_FAMILY on mixed families.
 */
int
test_bulk_sort_family_mismatch(void)
{
	cidr_prefix_t prefixes[2];

	if (cidr_prefix_parse("10.0.0.0/8", &prefixes[0]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("2001:db8::/32", &prefixes[1]) != CIDR_OK)
		return 1;

	if (cidr_bulk_sort(prefixes, 2, CIDR_SORT_NETWORK_ASC) !=
	    CIDR_ERR_FAMILY)
		return 1;
	return 0;
}

/*
 * test_bulk_sort_unspec_family -- CIDR_ERR_INVAL when a prefix has
 * CIDR_AF_UNSPEC family.
 */
int
test_bulk_sort_unspec_family(void)
{
	cidr_prefix_t prefixes[2];

	memset(&prefixes, 0, sizeof(prefixes));
	if (cidr_prefix_parse("10.0.0.0/8", &prefixes[0]) != CIDR_OK)
		return 1;
	/* prefixes[1] is left zero-initialised (CIDR_AF_UNSPEC) */

	if (cidr_bulk_sort(prefixes, 2, CIDR_SORT_NETWORK_ASC) !=
	    CIDR_ERR_INVAL)
		return 1;
	return 0;
}
