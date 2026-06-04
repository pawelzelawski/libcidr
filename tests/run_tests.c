/*
 * run_tests.c - C test binary entry point.
 * See TECH_STACK.md §6.2 for the test binary structure.
 */

#include "test_harness.h"

int tests_run = 0;
int tests_passed = 0;

int main(void)
{
	/* Phase 1: no tests yet. Suite will be populated in later phases. */

	fprintf(stderr, "%d/%d tests passed\n", tests_passed, tests_run);
	return (tests_run == tests_passed) ? 0 : 1;
}
