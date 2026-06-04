/*
 * run_tests.c - C test binary entry point.
 * See TECH_STACK.md §6.2 for the test binary structure.
 */

#include "test_harness.h"

/*
 * test_addr.c -- Phase 2: address parsing and formatting tests.
 * See TESTING.md §3.1 for IPv4 parsing conformance tests.
 */
extern int test_ipv4_parse_valid(void);
extern int test_ipv4_parse_leading_zero(void);
extern int test_ipv4_parse_hex(void);
extern int test_ipv4_parse_out_of_range(void);
extern int test_ipv4_parse_wrong_count(void);
extern int test_ipv4_parse_whitespace(void);
extern int test_ipv4_parse_trailing_chars(void);
extern int test_ipv4_parse_null(void);
extern int test_ipv6_parse_full_form(void);
extern int test_ipv6_parse_compressed(void);
extern int test_ipv6_parse_double_colon_once(void);
extern int test_ipv6_parse_uppercase_normalised(void);
extern int test_ipv6_parse_mixed_mapped(void);
extern int test_ipv6_parse_mixed_non_mapped(void);
extern int test_ipv6_parse_compatible_rejected(void);
extern int test_ipv6_parse_wrong_group_count(void);
extern int test_ipv6_parse_group_too_large(void);
extern int test_ipv6_parse_invalid_chars(void);

int tests_run = 0;
int tests_passed = 0;

int main(void)
{
	RUN("test_ipv4_parse_valid", test_ipv4_parse_valid);
	RUN("test_ipv4_parse_leading_zero", test_ipv4_parse_leading_zero);
	RUN("test_ipv4_parse_hex", test_ipv4_parse_hex);
	RUN("test_ipv4_parse_out_of_range", test_ipv4_parse_out_of_range);
	RUN("test_ipv4_parse_wrong_count", test_ipv4_parse_wrong_count);
	RUN("test_ipv4_parse_whitespace", test_ipv4_parse_whitespace);
	RUN("test_ipv4_parse_trailing_chars", test_ipv4_parse_trailing_chars);
	RUN("test_ipv4_parse_null", test_ipv4_parse_null);
	RUN("test_ipv6_parse_full_form", test_ipv6_parse_full_form);
	RUN("test_ipv6_parse_compressed", test_ipv6_parse_compressed);
	RUN("test_ipv6_parse_double_colon_once",
	    test_ipv6_parse_double_colon_once);
	RUN("test_ipv6_parse_uppercase_normalised",
	    test_ipv6_parse_uppercase_normalised);
	RUN("test_ipv6_parse_mixed_mapped", test_ipv6_parse_mixed_mapped);
	RUN("test_ipv6_parse_mixed_non_mapped",
	    test_ipv6_parse_mixed_non_mapped);
	RUN("test_ipv6_parse_compatible_rejected",
	    test_ipv6_parse_compatible_rejected);
	RUN("test_ipv6_parse_wrong_group_count",
	    test_ipv6_parse_wrong_group_count);
	RUN("test_ipv6_parse_group_too_large", test_ipv6_parse_group_too_large);
	RUN("test_ipv6_parse_invalid_chars", test_ipv6_parse_invalid_chars);

	fprintf(stderr, "%d/%d tests passed\n", tests_passed, tests_run);
	return (tests_run == tests_passed) ? 0 : 1;
}
