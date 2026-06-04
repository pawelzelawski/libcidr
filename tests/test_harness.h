/*
 * test_harness.h - minimal C test harness.
 * See TECH_STACK.md §6.1 for the RUN macro specification.
 */

#ifndef TEST_HARNESS_H
#define TEST_HARNESS_H

#include <stdio.h>

#define RUN(name, fn)                                                          \
	do {                                                                   \
		tests_run++;                                                   \
		int _rc = (fn)();                                              \
		if (_rc == 0) {                                                \
			tests_passed++;                                        \
			fprintf(stderr, "PASS: %s\n", (name));                 \
		} else {                                                       \
			fprintf(stderr, "FAIL: %s\n", (name));                 \
		}                                                              \
	} while (0)

extern int tests_run;
extern int tests_passed;

#endif /* TEST_HARNESS_H */
