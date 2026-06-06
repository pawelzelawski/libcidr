/*
 * test_index.c - Patricia trie index tests.
 *
 * cidr_index_create: input validation (NULL, count == 0, mixed families).
 * cidr_index_destroy: NULL-safe.
 * cidr_index_lookup: input validation (NULL index, NULL matches).
 *
 * Full trie construction, lookup, and LPM tests are added in later
 * Phase 6 tasks. See DEVELOPMENT.md §Phase 6 Tests.
 */

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

int
test_index_lookup_null_matches_nonzero_count(void)
{
	cidr_index_t *index = NULL;

	if (cidr_index_lookup(NULL, NULL, 0, NULL, NULL) != CIDR_ERR_INVAL)
		return 1;
	if (cidr_index_lookup((const cidr_index_t *)&index, NULL, 1, NULL,
	                      NULL) != CIDR_ERR_INVAL)
		return 1;
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
