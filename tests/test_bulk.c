/*
 * test_bulk.c - bulk engine tests: cidr_bulk_parse and cidr_bulk_sort.
 *
 * Tests for cidr_bulk_parse() batch parse semantics and the shared
 * in-place MSD radix sort engine / cidr_bulk_sort().
 *
 * See DEVELOPMENT.md §Phase 4 Tests for the full test catalogue.
 */

#include <string.h>

#include "../include/libcidr.h"

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
	cidr_err_t rc;

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

	rc = cidr_bulk_sort(prefixes, 5, CIDR_SORT_PFXLEN_DESC);
	if (rc != CIDR_OK)
		return 1;

	/*
	 * After sorting by ~pfxlen then addr:
	 * /24: 10.1.0.0/24 (index 0), 10.1.0.0/24 (index 3)  -- stable: 0 < 3
	 * /12: 172.16.0.0/12 (index 2)
	 * /8:  10.0.0.0/8 (index 1), 10.0.0.0/8 (index 4)    -- stable: 1 < 4
	 *
	 * So within each equal-key group, the lower input index
	 * must appear first.
	 */
	{
		char buf[CIDR_PREFIX_STR_MAX];
		int idx_10_1_24_first, idx_10_1_24_second;
		int idx_10_8_first, idx_10_8_second;

		/* Find positions of the two 10.1.0.0/24 entries */
		idx_10_1_24_first = -1;
		idx_10_1_24_second = -1;
		for (int i = 0; i < 5; i++) {
			if (cidr_prefix_format(&prefixes[i], buf,
			                       sizeof(buf)) != CIDR_OK)
				return 1;
			if (strcmp(buf, "10.1.0.0/24") == 0) {
				if (idx_10_1_24_first < 0)
					idx_10_1_24_first = i;
				else
					idx_10_1_24_second = i;
			}
		}

		/* The one from original index 0 must precede original index 3
		 */
		if (idx_10_1_24_first < 0 || idx_10_1_24_second < 0)
			return 1;
		if (idx_10_1_24_first > idx_10_1_24_second)
			return 1;

		/* Find positions of the two 10.0.0.0/8 entries */
		idx_10_8_first = -1;
		idx_10_8_second = -1;
		for (int i = 0; i < 5; i++) {
			if (cidr_prefix_format(&prefixes[i], buf,
			                       sizeof(buf)) != CIDR_OK)
				return 1;
			if (strcmp(buf, "10.0.0.0/8") == 0) {
				if (idx_10_8_first < 0)
					idx_10_8_first = i;
				else
					idx_10_8_second = i;
			}
		}

		/* The one from original index 1 must precede original index 4
		 */
		if (idx_10_8_first < 0 || idx_10_8_second < 0)
			return 1;
		if (idx_10_8_first > idx_10_8_second)
			return 1;

		/* Verify 172.16.0.0/12 is between the /24 and /8 groups */
		if (cidr_prefix_format(&prefixes[2], buf, sizeof(buf)) !=
		    CIDR_OK)
			return 1;
		if (strcmp(buf, "172.16.0.0/12") != 0)
			return 1;
	}

	return 0;
}

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
