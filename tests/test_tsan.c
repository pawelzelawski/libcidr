#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../include/libcidr.h"

#define TSAN_THREAD_COUNT 4
#define TSAN_ITERATIONS 200

struct bulk_sort_worker {
	int failed;
};

struct bulk_aggregate_worker {
	int failed;
};

/*
 * parse_worker - per-thread state for test_concurrent_parse.
 *
 * Ownership/lifetime: stack-allocated by the test function, passed by pointer
 * to the worker thread. No shared mutable state between workers.
 */
struct parse_worker {
	int failed;
};

struct index_lookup_worker {
	const cidr_index_t *index;
	int failed;
};

static void *
bulk_sort_worker_main(void *arg)
{
	struct bulk_sort_worker *worker;
	size_t iter;

	worker = arg;
	for (iter = 0; iter < TSAN_ITERATIONS; iter++) {
		cidr_prefix_t prefixes[5];

		if (cidr_prefix_parse("10.0.0.0/8", &prefixes[0]) != CIDR_OK ||
		    cidr_prefix_parse("10.1.0.0/24", &prefixes[1]) != CIDR_OK ||
		    cidr_prefix_parse("10.0.0.0/16", &prefixes[2]) != CIDR_OK ||
		    cidr_prefix_parse("192.168.0.0/16", &prefixes[3]) !=
		        CIDR_OK ||
		    cidr_prefix_parse("10.1.2.0/24", &prefixes[4]) != CIDR_OK) {
			worker->failed = 1;
			return NULL;
		}
		if (cidr_bulk_sort(prefixes, 5, CIDR_SORT_PFXLEN_DESC) !=
		    CIDR_OK) {
			worker->failed = 1;
			return NULL;
		}
		if (prefixes[0].pfxlen != 24 || prefixes[1].pfxlen != 24 ||
		    prefixes[2].pfxlen != 16 || prefixes[3].pfxlen != 16 ||
		    prefixes[4].pfxlen != 8) {
			worker->failed = 1;
			return NULL;
		}
	}

	return NULL;
}

static void *
bulk_aggregate_worker_main(void *arg)
{
	struct bulk_aggregate_worker *worker;
	size_t iter;

	worker = arg;
	for (iter = 0; iter < TSAN_ITERATIONS; iter++) {
		cidr_prefix_t prefixes[4];
		size_t out_count;

		if (cidr_prefix_parse("192.168.0.0/24", &prefixes[0]) !=
		        CIDR_OK ||
		    cidr_prefix_parse("192.168.1.0/24", &prefixes[1]) !=
		        CIDR_OK ||
		    cidr_prefix_parse("10.0.0.0/8", &prefixes[2]) != CIDR_OK ||
		    cidr_prefix_parse("10.1.0.0/16", &prefixes[3]) != CIDR_OK) {
			worker->failed = 1;
			return NULL;
		}
		if (cidr_bulk_aggregate(prefixes, 4, &out_count) != CIDR_OK) {
			worker->failed = 1;
			return NULL;
		}
		if (out_count != 2) {
			worker->failed = 1;
			return NULL;
		}
		if (prefixes[0].pfxlen != 8 || prefixes[1].pfxlen != 23) {
			worker->failed = 1;
			return NULL;
		}
	}

	return NULL;
}

/*
 * parse_worker_main - repeatedly exercise cidr_addr_parse, cidr_addr_format,
 * and cidr_addr_cmp from one thread.
 *
 * Exercises the arithmetic engine's reentrant paths from multiple threads
 * concurrently. Each worker operates on its own stack-allocated storage with
 * no shared mutable state.
 *
 * SAFETY: ARCHITECTURE.md §1.4 guarantees that all functions that do not
 * operate on a cidr_index_t are fully reentrant and thread-safe. This worker
 * exercises no index functions, only the arithmetic engine's parse/format/cmp
 * paths, which must be race-free.
 */
static void *
parse_worker_main(void *arg)
{
	struct parse_worker *worker;
	size_t iter;

	worker = arg;
	for (iter = 0; iter < TSAN_ITERATIONS; iter++) {
		cidr_addr_t a1 = {0}, a2 = {0};
		char buf[CIDR_ADDR_STR_MAX];

		/*
		 * IPv4 parse/format round-trip. Each parse/format/compare
		 * step uses only stack-local storage; no shared state.
		 */
		if (cidr_addr_parse("192.168.1.1", &a1) != CIDR_OK) {
			worker->failed = 1;
			return NULL;
		}
		if (cidr_addr_format(&a1, buf, sizeof(buf)) != CIDR_OK) {
			worker->failed = 1;
			return NULL;
		}
		if (cidr_addr_parse(buf, &a2) != CIDR_OK) {
			worker->failed = 1;
			return NULL;
		}
		if (memcmp(&a1, &a2, sizeof(a1)) != 0) {
			worker->failed = 1;
			return NULL;
		}

		/* IPv6 parse/format round-trip */
		if (cidr_addr_parse("2001:db8::1", &a1) != CIDR_OK) {
			worker->failed = 1;
			return NULL;
		}
		if (cidr_addr_format(&a1, buf, sizeof(buf)) != CIDR_OK) {
			worker->failed = 1;
			return NULL;
		}
		if (cidr_addr_parse(buf, &a2) != CIDR_OK) {
			worker->failed = 1;
			return NULL;
		}
		if (memcmp(&a1, &a2, sizeof(a1)) != 0) {
			worker->failed = 1;
			return NULL;
		}

		/* cidr_addr_cmp ordering */
		{
			cidr_addr_t a = {0}, b = {0};
			int result;

			if (cidr_addr_parse("10.0.0.1", &a) != CIDR_OK ||
			    cidr_addr_parse("10.0.0.2", &b) != CIDR_OK) {
				worker->failed = 1;
				return NULL;
			}
			if (cidr_addr_cmp(&a, &b, &result) != CIDR_OK ||
			    result != -1) {
				worker->failed = 1;
				return NULL;
			}
			if (cidr_addr_cmp(&b, &a, &result) != CIDR_OK ||
			    result != 1) {
				worker->failed = 1;
				return NULL;
			}
			if (cidr_addr_cmp(&a, &a, &result) != CIDR_OK ||
			    result != 0) {
				worker->failed = 1;
				return NULL;
			}
		}

		/* Error paths */
		{
			cidr_addr_t err_out = {0};

			if (cidr_addr_parse(NULL, &err_out) != CIDR_ERR_INVAL) {
				worker->failed = 1;
				return NULL;
			}
			if (cidr_addr_parse("not-an-ip", &err_out) !=
			    CIDR_ERR_PARSE) {
				worker->failed = 1;
				return NULL;
			}
		}
	}

	return NULL;
}

/*
 * index_lookup_worker_main - repeatedly query one shared completed index.
 *
 * Ownership/lifetime: the main thread builds and destroys the index. Worker
 * threads borrow a read-only pointer for the duration of the test and never
 * mutate shared state.
 *
 * SAFETY: this test relies on the ARCHITECTURE.md §1.4 guarantee that
 * concurrent cidr_index_lookup() calls on a completed immutable index are
 * safe from data races.
 */
static void *
index_lookup_worker_main(void *arg)
{
	struct index_lookup_worker *worker;
	size_t iter;

	worker = arg;
	for (iter = 0; iter < TSAN_ITERATIONS; iter++) {
		cidr_addr_t addrs[3];
		ssize_t matches[3];

		if (cidr_addr_parse("10.1.2.3", &addrs[0]) != CIDR_OK ||
		    cidr_addr_parse("10.200.1.1", &addrs[1]) != CIDR_OK ||
		    cidr_addr_parse("192.168.1.1", &addrs[2]) != CIDR_OK) {
			worker->failed = 1;
			return NULL;
		}
		if (cidr_index_lookup(worker->index, addrs, 3, matches, NULL) !=
		    CIDR_OK) {
			worker->failed = 1;
			return NULL;
		}
		if (matches[0] != 1 || matches[1] != 0 || matches[2] != -1) {
			worker->failed = 1;
			return NULL;
		}
	}

	return NULL;
}

int
test_concurrent_bulk_sort_independent(void)
{
	pthread_t threads[TSAN_THREAD_COUNT];
	struct bulk_sort_worker workers[TSAN_THREAD_COUNT];
	size_t i;

	memset(workers, 0, sizeof(workers));
	for (i = 0; i < TSAN_THREAD_COUNT; i++) {
		if (pthread_create(&threads[i], NULL, bulk_sort_worker_main,
		                   &workers[i]) != 0)
			return 1;
	}
	for (i = 0; i < TSAN_THREAD_COUNT; i++) {
		if (pthread_join(threads[i], NULL) != 0)
			return 1;
		if (workers[i].failed)
			return 1;
	}

	return 0;
}

int
test_concurrent_bulk_aggregate_independent(void)
{
	pthread_t threads[TSAN_THREAD_COUNT];
	struct bulk_aggregate_worker workers[TSAN_THREAD_COUNT];
	size_t i;

	memset(workers, 0, sizeof(workers));
	for (i = 0; i < TSAN_THREAD_COUNT; i++) {
		if (pthread_create(&threads[i], NULL,
		                   bulk_aggregate_worker_main,
		                   &workers[i]) != 0)
			return 1;
	}
	for (i = 0; i < TSAN_THREAD_COUNT; i++) {
		if (pthread_join(threads[i], NULL) != 0)
			return 1;
		if (workers[i].failed)
			return 1;
	}

	return 0;
}

/*
 * test_concurrent_parse - run cidr_addr_parse/format/cmp from N threads.
 *
 * Verifies that the arithmetic engine's reentrant paths are free of data
 * races when called concurrently from multiple threads.
 *
 * Worker structs are heap-allocated to avoid TSan false positives on stack
 * memory reuse between consecutive test functions.
 *
 * This is the Phase 8 TSan gate from DEVELOPMENT.md §8.2 and TESTING.md §4.3.
 * Runs only under make test-tsan (requires TSan instrumentation).
 */
int
test_concurrent_parse(void)
{
	pthread_t threads[TSAN_THREAD_COUNT];
	struct parse_worker *workers[TSAN_THREAD_COUNT];
	size_t i;
	int rc;

	rc = 1;
	memset(threads, 0, sizeof(threads));
	memset(workers, 0, sizeof(workers));

	/*
	 * SAFETY: each worker is heap-allocated and freed only after
	 * pthread_join confirms no further access by the worker thread.
	 * See ARCHITECTURE.md §1.4 for reentrancy guarantees.
	 */
	for (i = 0; i < TSAN_THREAD_COUNT; i++) {
		workers[i] = malloc(sizeof(struct parse_worker));
		if (workers[i] == NULL)
			goto cleanup;
		memset(workers[i], 0, sizeof(struct parse_worker));
		if (pthread_create(&threads[i], NULL, parse_worker_main,
		                   workers[i]) != 0)
			goto cleanup;
	}
	rc = 0;

cleanup: {
	size_t joined = (i < TSAN_THREAD_COUNT) ? i : TSAN_THREAD_COUNT;

	for (i = 0; i < joined; i++) {
		pthread_join(threads[i], NULL);
		if (workers[i]->failed)
			rc = 1;
	}
}

	for (i = 0; i < TSAN_THREAD_COUNT; i++)
		free(workers[i]);

	return rc;
}

/*
 * test_concurrent_index_lookup - build one index and query it from multiple
 * threads concurrently.
 *
 * This is the Phase 6 TSan gate from TESTING.md §4.3.
 */
int
test_concurrent_index_lookup(void)
{
	pthread_t threads[TSAN_THREAD_COUNT];
	struct index_lookup_worker workers[TSAN_THREAD_COUNT];
	cidr_prefix_t prefixes[2];
	cidr_index_t *index = NULL;
	size_t i, joined;
	int rc;

	if (cidr_prefix_parse("10.0.0.0/8", &prefixes[0]) != CIDR_OK ||
	    cidr_prefix_parse("10.1.0.0/16", &prefixes[1]) != CIDR_OK)
		return 1;
	if (cidr_index_create(prefixes, 2, &index) != CIDR_OK)
		return 1;

	memset(workers, 0, sizeof(workers));
	for (i = 0; i < TSAN_THREAD_COUNT; i++)
		workers[i].index = index;

	rc = 0;
	for (i = 0; i < TSAN_THREAD_COUNT; i++) {
		if (pthread_create(&threads[i], NULL, index_lookup_worker_main,
		                   &workers[i]) != 0) {
			rc = 1;
			break;
		}
	}

	joined = i;
	for (i = 0; i < joined; i++) {
		if (pthread_join(threads[i], NULL) != 0)
			rc = 1;
	}
	for (i = 0; i < TSAN_THREAD_COUNT; i++) {
		if (workers[i].failed)
			rc = 1;
	}

	cidr_index_destroy(index);
	return rc;
}
