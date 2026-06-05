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
