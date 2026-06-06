/*
 * test_index.c - Patricia trie index tests.
 *
 * cidr_index_create: input validation, basic trie construction,
 *   duplicate handling.
 * cidr_index_destroy: NULL-safe, memory cleanup.
 * cidr_index_lookup: longest-prefix match, interior node prefixes,
 *   no-match, duplicate resolution.
 *
 * See ARCHITECTURE.md §6 for the trie specification,
 * ARCHITECTURE.md §6.2 for duplicate handling, and
 * ARCHITECTURE.md §6.3 for interior node prefix semantics.
 */

#include <stdlib.h>
#include <string.h>

#include "../include/libcidr.h"
#include "test_harness.h"

int
test_index_create_count_zero(void)
{
	cidr_index_t *index = NULL;

	if (cidr_index_create(NULL, 0, &index) != CIDR_ERR_INVAL)
		return 1;
	if (cidr_index_create(NULL, 0, NULL) != CIDR_ERR_INVAL)
		return 1;
	return 0;
}

int
test_index_create_null(void)
{
	cidr_prefix_t prefix;
	cidr_index_t *index = NULL;

	if (cidr_prefix_parse("10.0.0.0/8", &prefix) != CIDR_OK)
		return 1;
	if (cidr_index_create(NULL, 1, &index) != CIDR_ERR_INVAL)
		return 1;
	if (cidr_index_create(&prefix, 1, NULL) != CIDR_ERR_INVAL)
		return 1;
	return 0;
}

int
test_index_create_unspec_family(void)
{
	cidr_prefix_t prefixes[1];
	cidr_index_t *index = NULL;

	prefixes[0].addr.family = CIDR_AF_UNSPEC;
	prefixes[0].addr.addr.v4[0] = 0;
	prefixes[0].pfxlen = 8;

	if (cidr_index_create(prefixes, 1, &index) != CIDR_ERR_INVAL)
		return 1;
	return 0;
}

int
test_index_create_mixed_family(void)
{
	cidr_prefix_t prefixes[2];
	cidr_index_t *index = NULL;

	if (cidr_prefix_parse("10.0.0.0/8", &prefixes[0]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("2001:db8::/32", &prefixes[1]) != CIDR_OK)
		return 1;

	if (cidr_index_create(prefixes, 2, &index) != CIDR_ERR_FAMILY)
		return 1;
	return 0;
}

int
test_index_destroy_null_safe(void)
{
	cidr_index_destroy(NULL);
	return 0;
}

/*
 * test_index_lookup_null_index - NULL index pointer returns CIDR_ERR_INVAL.
 */
int
test_index_lookup_null_index(void)
{
	if (cidr_index_lookup(NULL, NULL, 0, NULL, NULL) != CIDR_ERR_INVAL)
		return 1;
	return 0;
}

/*
 * test_index_lookup_null_matches_nonzero_count - NULL matches with count > 0
 * returns CIDR_ERR_INVAL. Uses a real valid index to reach the check.
 *
 * See ARCHITECTURE.md §6.2: "If count > 0 and matches is NULL, returns
 * CIDR_ERR_INVAL."
 */
int
test_index_lookup_null_matches_nonzero_count(void)
{
	cidr_prefix_t prefix;
	cidr_addr_t addr;
	cidr_index_t *index = NULL;

	if (cidr_prefix_parse("10.0.0.0/8", &prefix) != CIDR_OK)
		return 1;
	if (cidr_index_create(&prefix, 1, &index) != CIDR_OK)
		return 1;
	if (cidr_addr_parse("10.0.0.1", &addr) != CIDR_OK) {
		cidr_index_destroy(index);
		return 1;
	}

	/* matches == NULL with count > 0 must return CIDR_ERR_INVAL. */
	if (cidr_index_lookup(index, &addr, 1, NULL, NULL) != CIDR_ERR_INVAL) {
		cidr_index_destroy(index);
		return 1;
	}

	cidr_index_destroy(index);
	return 0;
}

int
test_index_lookup_count_zero(void)
{
	cidr_index_t *index = NULL;

	if (cidr_index_lookup((const cidr_index_t *)&index, NULL, 0, NULL,
	                      NULL) != CIDR_OK)
		return 1;
	return 0;
}

int
test_index_create_count_overflow(void)
{
	cidr_prefix_t prefix;
	cidr_index_t *index = NULL;

	if (cidr_prefix_parse("10.0.0.0/8", &prefix) != CIDR_OK)
		return 1;

	if (cidr_index_create(&prefix, (size_t)UINT32_MAX, &index) !=
	    CIDR_ERR_INVAL)
		return 1;
	return 0;
}

/*
 * test_index_basic_lookup - single prefix; address inside returns 0,
 * address outside returns -1.
 *
 * Tests both IPv4 and IPv6 single-prefix indices.
 */
int
test_index_basic_lookup(void)
{
	cidr_prefix_t prefixes[1];
	cidr_addr_t addrs[4];
	ssize_t matches[4];
	cidr_index_t *index = NULL;

	if (cidr_prefix_parse("10.0.0.0/8", &prefixes[0]) != CIDR_OK)
		return 1;
	if (cidr_index_create(prefixes, 1, &index) != CIDR_OK)
		return 1;

	/* Inside the prefix */
	if (cidr_addr_parse("10.0.0.1", &addrs[0]) != CIDR_OK)
		goto fail;
	/* Network address */
	if (cidr_addr_parse("10.0.0.0", &addrs[1]) != CIDR_OK)
		goto fail;
	/* Outside the prefix */
	if (cidr_addr_parse("11.0.0.1", &addrs[2]) != CIDR_OK)
		goto fail;
	/* Completely different */
	if (cidr_addr_parse("192.168.1.1", &addrs[3]) != CIDR_OK)
		goto fail;

	if (cidr_index_lookup(index, addrs, 4, matches, NULL) != CIDR_OK)
		goto fail;

	if (matches[0] != 0)
		goto fail;
	if (matches[1] != 0)
		goto fail;
	if (matches[2] != -1)
		goto fail;
	if (matches[3] != -1)
		goto fail;

	cidr_index_destroy(index);
	return 0;

fail:
	cidr_index_destroy(index);
	return 1;
}

/*
 * test_index_basic_lookup_ipv6 - single IPv6 prefix lookup.
 */
int
test_index_basic_lookup_ipv6(void)
{
	cidr_prefix_t prefixes[1];
	cidr_addr_t addrs[3];
	ssize_t matches[3];
	cidr_index_t *index = NULL;

	if (cidr_prefix_parse("2001:db8::/32", &prefixes[0]) != CIDR_OK)
		return 1;
	if (cidr_index_create(prefixes, 1, &index) != CIDR_OK)
		return 1;

	if (cidr_addr_parse("2001:db8::1", &addrs[0]) != CIDR_OK)
		goto fail;
	if (cidr_addr_parse("2001:db8:ffff::1", &addrs[1]) != CIDR_OK)
		goto fail;
	if (cidr_addr_parse("2001:db9::1", &addrs[2]) != CIDR_OK)
		goto fail;

	if (cidr_index_lookup(index, addrs, 3, matches, NULL) != CIDR_OK)
		goto fail;

	if (matches[0] != 0)
		goto fail;
	if (matches[1] != 0)
		goto fail;
	if (matches[2] != -1)
		goto fail;

	cidr_index_destroy(index);
	return 0;

fail:
	cidr_index_destroy(index);
	return 1;
}

/*
 * test_index_interior_node_prefix - verify that a parent prefix stored
 * at an interior node is returned as the best match for addresses that
 * match it but not any child prefix.
 *
 * Setup: /8 (index 0) and /16 (index 1). Address 10.2.0.1 matches /8
 * but not /16 -- must return 0 (not -1). Address 10.1.0.1 matches both
 * -- must return 1 (the more-specific /16).
 *
 * See ARCHITECTURE.md §6.3 interior node prefix semantics and
 * TESTING.md §6.5 for the dedicated test requirement.
 */
int
test_index_interior_node_prefix(void)
{
	cidr_prefix_t prefixes[2];
	cidr_addr_t addrs[2];
	ssize_t matches[2];
	cidr_index_t *index = NULL;

	if (cidr_prefix_parse("10.0.0.0/8", &prefixes[0]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("10.1.0.0/16", &prefixes[1]) != CIDR_OK)
		return 1;

	if (cidr_index_create(prefixes, 2, &index) != CIDR_OK)
		return 1;

	/*
	 * Address matches /8 but NOT /16 (10.2.x.x is outside 10.1.0.0/16).
	 * Must return index 0.
	 */
	if (cidr_addr_parse("10.2.0.1", &addrs[0]) != CIDR_OK)
		goto fail;

	/*
	 * Address matches /16 (and therefore also /8).
	 * Must return index 1 (more specific).
	 */
	if (cidr_addr_parse("10.1.0.1", &addrs[1]) != CIDR_OK)
		goto fail;

	if (cidr_index_lookup(index, addrs, 2, matches, NULL) != CIDR_OK)
		goto fail;

	if (matches[0] != 0)
		goto fail;
	if (matches[1] != 1)
		goto fail;

	cidr_index_destroy(index);
	return 0;

fail:
	cidr_index_destroy(index);
	return 1;
}

/*
 * test_index_interior_node_ipv6 - IPv6 interior node prefix test.
 *
 * Setup: 2001:db8::/32 (index 0) and 2001:db8:1::/48 (index 1).
 * Must correctly return the /32 for addresses outside /48 but
 * inside /32.
 */
int
test_index_interior_node_ipv6(void)
{
	cidr_prefix_t prefixes[2];
	cidr_addr_t addrs[2];
	ssize_t matches[2];
	cidr_index_t *index = NULL;

	if (cidr_prefix_parse("2001:db8::/32", &prefixes[0]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("2001:db8:1::/48", &prefixes[1]) != CIDR_OK)
		return 1;

	if (cidr_index_create(prefixes, 2, &index) != CIDR_OK)
		return 1;

	if (cidr_addr_parse("2001:db8:2::1", &addrs[0]) != CIDR_OK)
		goto fail;
	if (cidr_addr_parse("2001:db8:1::1", &addrs[1]) != CIDR_OK)
		goto fail;

	if (cidr_index_lookup(index, addrs, 2, matches, NULL) != CIDR_OK)
		goto fail;

	if (matches[0] != 0)
		goto fail;
	if (matches[1] != 1)
		goto fail;

	cidr_index_destroy(index);
	return 0;

fail:
	cidr_index_destroy(index);
	return 1;
}

/*
 * test_index_duplicate_lower_index_wins - two identical prefixes;
 * the lower original input index is always returned.
 *
 * See ARCHITECTURE.md §6.2:
 * "When two prefixes at different input indices are identical, the trie
 * stores the one with the lower index (earlier in the input array)."
 */
int
test_index_duplicate_lower_index_wins(void)
{
	cidr_prefix_t prefixes[3];
	cidr_addr_t addr;
	ssize_t match;
	cidr_index_t *index = NULL;

	/*
	 * Three prefixes: two identical /16 and a smaller /8.
	 * The /16 at index 1 duplicates index 2. Both map to the
	 * lower original index (1).
	 */
	if (cidr_prefix_parse("10.0.0.0/8", &prefixes[0]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("192.168.0.0/16", &prefixes[1]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("192.168.0.0/16", &prefixes[2]) != CIDR_OK)
		return 1;

	if (cidr_index_create(prefixes, 3, &index) != CIDR_OK)
		return 1;

	if (cidr_addr_parse("192.168.1.1", &addr) != CIDR_OK)
		goto fail;

	if (cidr_index_lookup(index, &addr, 1, &match, NULL) != CIDR_OK)
		goto fail;

	/*
	 * Both /16 prefixes match; the lower original index (1) must be
	 * returned.
	 */
	if (match != 1)
		goto fail;

	cidr_index_destroy(index);
	return 0;

fail:
	cidr_index_destroy(index);
	return 1;
}

/*
 * test_index_no_match - address outside all prefixes returns -1.
 */
int
test_index_no_match(void)
{
	cidr_prefix_t prefixes[3];
	cidr_addr_t addrs[2];
	ssize_t matches[2];
	cidr_index_t *index = NULL;

	if (cidr_prefix_parse("10.0.0.0/8", &prefixes[0]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("172.16.0.0/12", &prefixes[1]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("192.168.0.0/16", &prefixes[2]) != CIDR_OK)
		return 1;

	if (cidr_index_create(prefixes, 3, &index) != CIDR_OK)
		return 1;

	/* Matches the first prefix. */
	if (cidr_addr_parse("10.1.1.1", &addrs[0]) != CIDR_OK)
		goto fail;
	/* Does not match any prefix. */
	if (cidr_addr_parse("100.0.0.1", &addrs[1]) != CIDR_OK)
		goto fail;

	if (cidr_index_lookup(index, addrs, 2, matches, NULL) != CIDR_OK)
		goto fail;

	if (matches[0] != 0)
		goto fail;
	if (matches[1] != -1)
		goto fail;

	cidr_index_destroy(index);
	return 0;

fail:
	cidr_index_destroy(index);
	return 1;
}

/*
 * test_index_memory_clean - verify create/destroy cycle releases memory.
 *
 * Create an index with a few prefixes, perform a lookup, destroy it.
 * Repeat several times. Valgrind catches leaks.
 */
int
test_index_memory_clean(void)
{
	cidr_prefix_t prefixes[3];
	cidr_addr_t addr;
	ssize_t match;

	for (int iter = 0; iter < 5; iter++) {
		cidr_index_t *index = NULL;

		if (cidr_prefix_parse("10.0.0.0/8", &prefixes[0]) != CIDR_OK)
			return 1;
		if (cidr_prefix_parse("172.16.0.0/12", &prefixes[1]) != CIDR_OK)
			return 1;
		if (cidr_prefix_parse("192.168.0.0/16", &prefixes[2]) !=
		    CIDR_OK)
			return 1;

		if (cidr_index_create(prefixes, 3, &index) != CIDR_OK)
			return 1;

		if (cidr_addr_parse("10.1.1.1", &addr) != CIDR_OK) {
			cidr_index_destroy(index);
			return 1;
		}

		if (cidr_index_lookup(index, &addr, 1, &match, NULL) !=
		    CIDR_OK) {
			cidr_index_destroy(index);
			return 1;
		}

		if (match != 0) {
			cidr_index_destroy(index);
			return 1;
		}

		cidr_index_destroy(index);
	}

	return 0;
}

/*
 * test_index_lpm_matches_sorted_bulk - verify that index lookup results
 * are consistent with bulk_contains when the prefix table is sorted by
 * CIDR_SORT_PFXLEN_DESC.
 *
 * See TESTING.md §2.5 for the comparison test pattern and
 * ARCHITECTURE.md §6.2 for the LPM semantics guarantee.
 */
int
test_index_lpm_matches_sorted_bulk(void)
{
	cidr_prefix_t prefixes[4];
	cidr_addr_t addrs[3];
	ssize_t idx_matches[3];
	ssize_t bulk_matches[3];
	cidr_prefix_t sorted[4];
	cidr_err_t errs[3];
	cidr_index_t *index = NULL;

	if (cidr_prefix_parse("10.0.0.0/8", &prefixes[0]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("10.1.0.0/16", &prefixes[1]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("10.1.2.0/24", &prefixes[2]) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("192.168.0.0/16", &prefixes[3]) != CIDR_OK)
		return 1;

	if (cidr_addr_parse("10.1.2.5", &addrs[0]) != CIDR_OK)
		return 1;
	if (cidr_addr_parse("10.2.0.1", &addrs[1]) != CIDR_OK)
		return 1;
	if (cidr_addr_parse("172.16.0.1", &addrs[2]) != CIDR_OK)
		return 1;

	/*
	 * Sort a copy by CIDR_SORT_PFXLEN_DESC for bulk_contains LPM.
	 * The results from bulk_contains (first-match with LPM-sorted
	 * table) must be consistent with the index lookup results.
	 */
	memcpy(sorted, prefixes, sizeof(prefixes));
	if (cidr_bulk_sort(sorted, 4, CIDR_SORT_PFXLEN_DESC) != CIDR_OK)
		return 1;

	if (cidr_bulk_contains(addrs, 3, sorted, 4, bulk_matches, errs) !=
	    CIDR_OK)
		return 1;

	/*
	 * Build index from the original (unsorted) prefix array.
	 * The index always returns LPM by construction.
	 */
	if (cidr_index_create(prefixes, 4, &index) != CIDR_OK)
		return 1;

	if (cidr_index_lookup(index, addrs, 3, idx_matches, NULL) != CIDR_OK) {
		cidr_index_destroy(index);
		return 1;
	}

	/*
	 * Verify index matches.
	 * addr 10.1.2.5: LPM = /24 (original index 2)
	 * addr 10.2.0.1: LPM = /8 (original index 0)
	 * addr 172.16.0.1: no match
	 */
	if (idx_matches[0] != 2)
		goto fail;
	if (idx_matches[1] != 0)
		goto fail;
	if (idx_matches[2] != -1)
		goto fail;

	/*
	 * Verify bulk_contains matches (sorted table) identify the
	 * same prefix by value. Compare address bytes and pfxlen only;
	 * the sorted table's addr.family was mutated by
	 * cidr_bulk_sort (PFXLEN_DESC path stashes order tags there).
	 */
	for (int i = 0; i < 3; i++) {
		if (idx_matches[i] == -1) {
			if (bulk_matches[i] != -1)
				goto fail;
		} else {
			const cidr_prefix_t *sp, *op;
			size_t alen;

			if (bulk_matches[i] == -1)
				goto fail;
			sp = &sorted[bulk_matches[i]];
			op = &prefixes[idx_matches[i]];
			alen = 4;
			if (sp->pfxlen != op->pfxlen)
				goto fail;
			if (memcmp(&sp->addr.addr, &op->addr.addr, alen) != 0)
				goto fail;
		}
	}

	cidr_index_destroy(index);
	return 0;

fail:
	cidr_index_destroy(index);
	return 1;
}

/*
 * test_index_lookup_family_mismatch - address family mismatch returns
 * CIDR_ERR_FAMILY in per-item error array, -1 in matches.
 */
int
test_index_lookup_family_mismatch(void)
{
	cidr_prefix_t prefixes[1];
	cidr_addr_t addrs[1];
	ssize_t match;
	cidr_err_t err;
	cidr_index_t *index = NULL;

	if (cidr_prefix_parse("10.0.0.0/8", &prefixes[0]) != CIDR_OK)
		return 1;
	if (cidr_index_create(prefixes, 1, &index) != CIDR_OK)
		return 1;

	if (cidr_addr_parse("2001:db8::1", &addrs[0]) != CIDR_OK) {
		cidr_index_destroy(index);
		return 1;
	}

	if (cidr_index_lookup(index, addrs, 1, &match, &err) != CIDR_OK) {
		cidr_index_destroy(index);
		return 1;
	}

	/* Family mismatch: match is -1, error is CIDR_ERR_FAMILY. */
	if (match != -1) {
		cidr_index_destroy(index);
		return 1;
	}
	if (err != CIDR_ERR_FAMILY) {
		cidr_index_destroy(index);
		return 1;
	}

	cidr_index_destroy(index);
	return 0;
}

/*
 * test_index_routing_table_scale - 100,000 /24 prefixes; index lookup
 * results verified against cidr_bulk_contains with a PFXLEN_DESC-sorted
 * table. Spot-checks 1000 addresses (every 100th prefix) for correct
 * original-index and matching prefix value.
 *
 * See DEVELOPMENT.md Phase 6 Tests.
 */
int
test_index_routing_table_scale(void)
{
	const size_t prefix_count = 100000;
	const size_t spot_count = 1000;
	cidr_prefix_t *prefixes = NULL;
	cidr_prefix_t *sorted = NULL;
	cidr_addr_t *addrs = NULL;
	ssize_t *idx_matches = NULL;
	ssize_t *bulk_matches = NULL;
	cidr_index_t *index = NULL;
	size_t n, k;
	int rc = 1;

	prefixes = malloc(prefix_count * sizeof(cidr_prefix_t));
	sorted = malloc(prefix_count * sizeof(cidr_prefix_t));
	addrs = malloc(spot_count * sizeof(cidr_addr_t));
	idx_matches = malloc(spot_count * sizeof(ssize_t));
	bulk_matches = malloc(spot_count * sizeof(ssize_t));
	if (prefixes == NULL || sorted == NULL || addrs == NULL ||
	    idx_matches == NULL || bulk_matches == NULL)
		goto done;

	/*
	 * Generate 100,000 unique non-overlapping /24 prefixes.
	 * Prefix n: (n>>16).((n>>8)&0xff).(n&0xff).0/24
	 * Range: 0.0.0.0/24 through 1.134.159.0/24 (100k entries).
	 * All are host-bits-zero by construction.
	 */
	for (n = 0; n < prefix_count; n++) {
		prefixes[n].addr.family = CIDR_AF_INET;
		prefixes[n].addr.addr.v4[0] = (uint8_t)((n >> 16) & 0xff);
		prefixes[n].addr.addr.v4[1] = (uint8_t)((n >> 8) & 0xff);
		prefixes[n].addr.addr.v4[2] = (uint8_t)(n & 0xff);
		prefixes[n].addr.addr.v4[3] = 0;
		prefixes[n].pfxlen = 24;
	}

	if (cidr_index_create(prefixes, prefix_count, &index) != CIDR_OK)
		goto done;

	/*
	 * Build a PFXLEN_DESC-sorted copy for cidr_bulk_contains LPM.
	 * All prefixes are /24 so PFXLEN_DESC reduces to NETWORK_ASC.
	 * cidr_bulk_sort restores addr.family on return (internal tags
	 * are cleaned up), so the sorted array is safe for bulk_contains.
	 */
	memcpy(sorted, prefixes, prefix_count * sizeof(cidr_prefix_t));
	if (cidr_bulk_sort(sorted, prefix_count, CIDR_SORT_PFXLEN_DESC) !=
	    CIDR_OK)
		goto done;

	/*
	 * Construct 1000 spot-check addresses: host .1 inside every 100th
	 * prefix (n = 0, 100, 200, ..., 99900).
	 */
	for (k = 0; k < spot_count; k++) {
		n = k * (prefix_count / spot_count);
		addrs[k].family = CIDR_AF_INET;
		addrs[k].addr.v4[0] = (uint8_t)((n >> 16) & 0xff);
		addrs[k].addr.v4[1] = (uint8_t)((n >> 8) & 0xff);
		addrs[k].addr.v4[2] = (uint8_t)(n & 0xff);
		addrs[k].addr.v4[3] = 1;
	}

	if (cidr_index_lookup(index, addrs, spot_count, idx_matches, NULL) !=
	    CIDR_OK)
		goto done;
	if (cidr_bulk_contains(addrs, spot_count, sorted, prefix_count,
	                       bulk_matches, NULL) != CIDR_OK)
		goto done;

	/*
	 * Verify each spot-check address:
	 * 1. Index must return original prefix index n = k * 100.
	 * 2. Bulk must find a match (prefixes are non-overlapping).
	 * 3. Both must identify the same prefix by address bytes and pfxlen.
	 */
	for (k = 0; k < spot_count; k++) {
		const cidr_prefix_t *op, *sp;

		n = k * (prefix_count / spot_count);
		if (idx_matches[k] != (ssize_t)n)
			goto done;
		if (bulk_matches[k] == -1)
			goto done;
		op = &prefixes[idx_matches[k]];
		sp = &sorted[bulk_matches[k]];
		if (op->pfxlen != sp->pfxlen)
			goto done;
		if (memcmp(&op->addr.addr, &sp->addr.addr, 4) != 0)
			goto done;
	}

	/* Address outside all generated prefixes must return -1. */
	addrs[0].family = CIDR_AF_INET;
	addrs[0].addr.v4[0] = 255;
	addrs[0].addr.v4[1] = 255;
	addrs[0].addr.v4[2] = 255;
	addrs[0].addr.v4[3] = 1;
	if (cidr_index_lookup(index, addrs, 1, idx_matches, NULL) != CIDR_OK)
		goto done;
	if (idx_matches[0] != -1)
		goto done;

	rc = 0;
done:
	cidr_index_destroy(index);
	free(prefixes);
	free(sorted);
	free(addrs);
	free(idx_matches);
	free(bulk_matches);
	return rc;
}
