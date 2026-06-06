#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include "../include/libcidr.h"

#define	TSAN_THREAD_COUNT	4
#define	TSAN_ITERATIONS		200

struct bulk_sort_worker {
	int failed;
};

struct bulk_aggregate_worker {
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
		if (cidr_bulk_sort(prefixes, 5, CIDR_SORT_PFXLEN_DESC) != CIDR_OK) {
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
		if (pthread_create(&threads[i], NULL, bulk_aggregate_worker_main,
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
