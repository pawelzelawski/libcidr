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

	fprintf(stderr, "%d/%d tests passed\n", tests_passed, tests_run);
	return (tests_run == tests_passed) ? 0 : 1;
}
