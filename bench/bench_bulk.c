/*
 * bench_bulk.c - C benchmark suite for libcidr bulk operations.
 *
 * Measures the throughput of cidr_bulk_parse(), cidr_bulk_contains(),
 * cidr_bulk_aggregate(), and cidr_bulk_sort() under release flags.
 * The benchmark workload sizes and output names follow TESTING.md §8.1.
 * See ARCHITECTURE.md §5 for the bulk engine semantics and complexity.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef CIDR_OPENBSD
#include <sys/param.h>
#include <sys/sysctl.h>
#endif

#include "../include/libcidr.h"

#define BENCH_PARSE_COUNT 100000U
#define BENCH_QUERY_COUNT 100000U
#define BENCH_SORT_COUNT 800000U
#define BENCH_MIN_SECONDS 0.20

struct bench_env {
	const char *platform;
	char cpu[128];
	long cores;
	char date[32];
};

struct parse_case {
	char *storage;
	const char **srcs;
	cidr_addr_t *out;
	size_t count;
};

struct contains_case {
	cidr_addr_t *addrs;
	cidr_prefix_t *prefixes;
	ssize_t *matches;
	size_t addr_count;
	size_t prefix_count;
};

struct aggregate_case {
	cidr_prefix_t *input;
	cidr_prefix_t *work;
	size_t count;
};

struct sort_case {
	cidr_prefix_t *input;
	cidr_prefix_t *work;
	size_t count;
	cidr_sort_order_t order;
};

/*
 * fill_platform_string - format the operating-system and architecture label
 * used in benchmark output.
 */
static void
fill_platform_string(char *buf, size_t len)
{
#ifdef CIDR_LINUX
	const char *os = "Linux";
#elif defined(CIDR_OPENBSD)
	const char *os = "OpenBSD";
#else
	const char *os = "Unknown";
#endif
#if defined(__x86_64__) || defined(_M_X64)
	const char *arch = "x86_64";
#elif defined(__aarch64__)
	const char *arch = "arm64";
#elif defined(__amd64__)
	const char *arch = "amd64";
#else
	const char *arch = "unknown";
#endif

	(void)snprintf(buf, len, "%s %s", os, arch);
}

/*
 * fill_cpu_string - gather a best-effort CPU description for reproducible
 * benchmark output. Linux reads /proc/cpuinfo; OpenBSD uses sysctl(3).
 */
static void
fill_cpu_string(char *buf, size_t len)
{
#ifdef CIDR_LINUX
	FILE *fp;
	char line[256];
	double mhz;

	fp = fopen("/proc/cpuinfo", "r");
	if (fp == NULL) {
		(void)snprintf(buf, len, "unknown");
		return;
	}
	while (fgets(line, sizeof(line), fp) != NULL) {
		char *value;

		if (strncmp(line, "model name", 10) != 0)
			continue;
		value = strchr(line, ':');
		if (value == NULL)
			break;
		value++;
		while (*value == ' ' || *value == '\t')
			value++;
		value[strcspn(value, "\n")] = '\0';
		if (snprintf(buf, len, "%s", value) >= (int)len)
			buf[len - 1] = '\0';
		fclose(fp);

		fp = fopen("/proc/cpuinfo", "r");
		if (fp == NULL)
			return;
		while (fgets(line, sizeof(line), fp) != NULL) {
			value = NULL;
			if (strncmp(line, "cpu MHz", 7) != 0)
				continue;
			value = strchr(line, ':');
			if (value == NULL)
				break;
			value++;
			while (*value == ' ' || *value == '\t')
				value++;
			mhz = strtod(value, NULL);
			if (mhz > 0.0) {
				size_t used;

				used = strnlen(buf, len);
				if (used + 8 < len)
					(void)snprintf(buf + used, len - used,
					               " @ %.0f MHz", mhz);
			}
			break;
		}
		fclose(fp);
		return;
	}
	fclose(fp);
	(void)snprintf(buf, len, "unknown");
#elif defined(CIDR_OPENBSD)
	int mib[2];
	int cpuspeed;
	size_t value_len;
	char model[128];

	mib[0] = CTL_HW;
	mib[1] = HW_MODEL;
	value_len = sizeof(model);
	if (sysctl(mib, 2, model, &value_len, NULL, 0) != 0) {
		(void)snprintf(buf, len, "unknown");
		return;
	}
	model[sizeof(model) - 1] = '\0';
	mib[1] = HW_CPUSPEED;
	value_len = sizeof(cpuspeed);
	if (sysctl(mib, 2, &cpuspeed, &value_len, NULL, 0) == 0 &&
	    cpuspeed > 0) {
		(void)snprintf(buf, len, "%s @ %d MHz", model, cpuspeed);
		return;
	}
	(void)snprintf(buf, len, "%s", model);
#else
	(void)snprintf(buf, len, "unknown");
#endif
}

static void
fill_date_string(char *buf, size_t len)
{
	time_t now;
	struct tm *tm_utc;

	now = time(NULL);
	tm_utc = localtime(&now);
	if (tm_utc == NULL) {
		(void)snprintf(buf, len, "unknown");
		return;
	}
	if (strftime(buf, len, "%Y-%m-%d", tm_utc) == 0)
		(void)snprintf(buf, len, "unknown");
}

/*
 * bench_env_init - populate the hardware context printed before benchmark
 * results. TESTING.md §8.2 requires the output to include platform, CPU,
 * core count, build mode, and date.
 */
static void
bench_env_init(struct bench_env *env)
{
	static char platform[32];

	fill_platform_string(platform, sizeof(platform));
	env->platform = platform;
	fill_cpu_string(env->cpu, sizeof(env->cpu));
	env->cores = sysconf(_SC_NPROCESSORS_ONLN);
	if (env->cores < 1)
		env->cores = 1;
	fill_date_string(env->date, sizeof(env->date));
}

static double
bench_now_seconds(void)
{
	struct timespec ts;

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + ((double)ts.tv_nsec / 1000000000.0);
}

static void *
bench_alloc(size_t size)
{
	void *ptr;

	ptr = malloc(size);
	if (ptr == NULL) {
		fprintf(stderr, "malloc(%zu) failed: %s\n", size,
		        strerror(errno));
		exit(1);
	}
	return ptr;
}

/*
 * addr_from_u32 - construct a deterministic IPv4 host address from a 32-bit
 * integer so benchmarks do not pay text parsing costs during setup.
 */
static void
addr_from_u32(uint32_t value, cidr_addr_t *out)
{
	out->family = CIDR_AF_INET;
	out->addr.v4[0] = (uint8_t)(value >> 24);
	out->addr.v4[1] = (uint8_t)(value >> 16);
	out->addr.v4[2] = (uint8_t)(value >> 8);
	out->addr.v4[3] = (uint8_t)value;
}

/*
 * prefix_from_base - derive a valid IPv4 prefix from a base integer and
 * prefix length. cidr_prefix_from_host() enforces the host-bits-zero
 * construction path documented in ARCHITECTURE.md §4.1.4.
 */
static void
prefix_from_base(uint32_t base, uint8_t pfxlen, cidr_prefix_t *out)
{
	cidr_addr_t addr;
	cidr_err_t rc;

	addr_from_u32(base, &addr);
	rc = cidr_prefix_from_host(&addr, pfxlen, out);
	if (rc != CIDR_OK) {
		fprintf(stderr, "cidr_prefix_from_host failed: %d\n", rc);
		exit(1);
	}
}

/*
 * measure_ops_per_second - run a benchmark callback repeatedly until a
 * minimum elapsed time is reached, then convert completed work units to a
 * throughput figure.
 */
static double
measure_ops_per_second(int (*fn)(void *), void *arg, double units_per_run)
{
	double elapsed;
	double start;
	size_t iters;

	start = bench_now_seconds();
	iters = 0;
	do {
		if (fn(arg) != 0) {
			fprintf(stderr, "benchmark operation failed\n");
			exit(1);
		}
		iters++;
		elapsed = bench_now_seconds() - start;
	} while (elapsed < BENCH_MIN_SECONDS);
	return (units_per_run * (double)iters) / elapsed;
}

/*
 * print_header - emit the reproducibility context required by TESTING.md §8.2.
 */
static void
print_header(const struct bench_env *env)
{
	printf("libcidr benchmark - bulk\n");
	printf("Platform : %s\n", env->platform);
	printf("CPU      : %s\n", env->cpu);
	printf("Cores    : %ld\n", env->cores);
	printf("Build    : release (-O2)\n");
	printf("Date     : %s\n\n", env->date);
}

/*
 * parse_case_init - allocate and populate a 100k-string dataset for bulk
 * parse throughput measurement.
 *
 * Ownership: storage, srcs, and out are owned by the parse_case and freed by
 * parse_case_destroy().
 */
static void
parse_case_init(struct parse_case *pcase, int family)
{
	size_t i;

	pcase->count = BENCH_PARSE_COUNT;
	pcase->storage = bench_alloc(pcase->count * CIDR_ADDR_STR_MAX);
	pcase->srcs = bench_alloc(pcase->count * sizeof(*pcase->srcs));
	pcase->out = bench_alloc(pcase->count * sizeof(*pcase->out));
	for (i = 0; i < pcase->count; i++) {
		char *slot;

		slot = pcase->storage + (i * CIDR_ADDR_STR_MAX);
		pcase->srcs[i] = slot;
		if (family == CIDR_AF_INET) {
			(void)snprintf(slot, CIDR_ADDR_STR_MAX,
			               "10.%zu.%zu.%zu", (i / 65536U) % 256U,
			               (i / 256U) % 256U, i % 256U);
		} else {
			(void)snprintf(slot, CIDR_ADDR_STR_MAX,
			               "2001:db8:%x:%x::%x",
			               (unsigned)((i >> 16) & 0xffffU),
			               (unsigned)((i >> 8) & 0xffU),
			               (unsigned)(i & 0xffU));
		}
	}
}

static void
parse_case_destroy(struct parse_case *pcase)
{
	free(pcase->out);
	free((void *)pcase->srcs);
	free(pcase->storage);
}

static int
run_bulk_parse(void *arg)
{
	struct parse_case *pcase;
	cidr_err_t rc;

	pcase = arg;
	rc = cidr_bulk_parse(pcase->srcs, pcase->count, pcase->out, NULL);
	return (rc == CIDR_OK) ? 0 : 1;
}

/*
 * contains_case_init - create a no-match workload so cidr_bulk_contains()
 * executes the full documented O(n*m) linear scan from ARCHITECTURE.md §5.3.
 *
 * Ownership: addrs, prefixes, and matches are owned by the contains_case and
 * freed by contains_case_destroy().
 */
static void
contains_case_init(struct contains_case *ccase, size_t prefix_count)
{
	size_t i;

	ccase->addr_count = BENCH_QUERY_COUNT;
	ccase->prefix_count = prefix_count;
	ccase->addrs = bench_alloc(ccase->addr_count * sizeof(*ccase->addrs));
	ccase->prefixes = bench_alloc(prefix_count * sizeof(*ccase->prefixes));
	ccase->matches =
	    bench_alloc(ccase->addr_count * sizeof(*ccase->matches));
	for (i = 0; i < prefix_count; i++)
		prefix_from_base((uint32_t)(0x0a000000U + (i << 8)), 24,
		                 &ccase->prefixes[i]);
	for (i = 0; i < ccase->addr_count; i++)
		addr_from_u32((uint32_t)(0xc6336400U + (i % 256U)),
		              &ccase->addrs[i]);
}

static void
contains_case_destroy(struct contains_case *ccase)
{
	free(ccase->matches);
	free(ccase->prefixes);
	free(ccase->addrs);
}

static int
run_bulk_contains(void *arg)
{
	struct contains_case *ccase;
	cidr_err_t rc;

	ccase = arg;
	rc =
	    cidr_bulk_contains(ccase->addrs, ccase->addr_count, ccase->prefixes,
	                       ccase->prefix_count, ccase->matches, NULL);
	return (rc == CIDR_OK) ? 0 : 1;
}

/*
 * aggregate_case_init - create sibling /25 pairs so aggregation performs
 * real merge work instead of measuring only duplicate elimination.
 *
 * Ownership: input and work are owned by the aggregate_case and freed by
 * aggregate_case_destroy().
 */
static void
aggregate_case_init(struct aggregate_case *acase, size_t count, int early_exit)
{
	size_t i;

	acase->count = count;
	acase->input = bench_alloc(count * sizeof(*acase->input));
	acase->work = bench_alloc(count * sizeof(*acase->work));
	for (i = 0; i < count; i++) {
		if (early_exit != 0) {
			prefix_from_base((uint32_t)(i << 8), 24,
			                 &acase->input[i]);
			continue;
		}
		prefix_from_base(
		    (uint32_t)(((i / 2U) << 8) + ((i % 2U) * 128U)), 25,
		    &acase->input[i]);
	}
}

static void
aggregate_case_destroy(struct aggregate_case *acase)
{
	free(acase->work);
	free(acase->input);
}

static int
run_bulk_aggregate(void *arg)
{
	struct aggregate_case *acase;
	size_t out_count;
	cidr_err_t rc;

	acase = arg;
	memcpy(acase->work, acase->input, acase->count * sizeof(*acase->work));

	/*
	 * SAFETY: cidr_bulk_aggregate() operates in place and leaves the tail
	 * of the array undefined. Copy the immutable template before each run.
	 * See ARCHITECTURE.md §5.4.
	 */
	rc = cidr_bulk_aggregate(acase->work, acase->count, &out_count);
	return (rc == CIDR_OK) ? 0 : 1;
}

/*
 * sort_case_init - prepare a deterministic unsorted prefix array that is
 * reused for both sort order benchmarks.
 *
 * Ownership: input and work are owned by the sort_case and freed by
 * sort_case_destroy().
 */
static void
sort_case_init(struct sort_case *scase, size_t count, cidr_sort_order_t order)
{
	size_t i;

	scase->count = count;
	scase->order = order;
	scase->input = bench_alloc(count * sizeof(*scase->input));
	scase->work = bench_alloc(count * sizeof(*scase->work));
	for (i = 0; i < count; i++) {
		uint32_t base;
		uint8_t pfxlen;

		base = (uint32_t)((i * 2654435761U) & 0xffffff00U);
		pfxlen = (uint8_t)(8U + (i % 17U));
		prefix_from_base(base, pfxlen, &scase->input[i]);
	}
}

static void
sort_case_destroy(struct sort_case *scase)
{
	free(scase->work);
	free(scase->input);
}

static int
run_bulk_sort(void *arg)
{
	struct sort_case *scase;
	cidr_err_t rc;

	scase = arg;
	memcpy(scase->work, scase->input, scase->count * sizeof(*scase->work));

	/*
	 * ARCHITECTURE.md §5.5 defines two sort orderings over the same
	 * in-place radix sort engine. Each timed run starts from the same
	 * unsorted input.
	 */
	rc = cidr_bulk_sort(scase->work, scase->count, scase->order);
	return (rc == CIDR_OK) ? 0 : 1;
}

static void
print_parse_results(void)
{
	struct parse_case ipv4;
	struct parse_case ipv6;
	double ipv4_rate;
	double ipv6_rate;

	parse_case_init(&ipv4, CIDR_AF_INET);
	parse_case_init(&ipv6, CIDR_AF_INET6);
	ipv4_rate =
	    measure_ops_per_second(run_bulk_parse, &ipv4, (double)ipv4.count);
	ipv6_rate =
	    measure_ops_per_second(run_bulk_parse, &ipv6, (double)ipv6.count);

	printf("bench_bulk_parse\n");
	printf("family    libcidr (M addrs/s)\n");
	printf("IPv4      %.2f\n", ipv4_rate / 1000000.0);
	printf("IPv6      %.2f\n\n", ipv6_rate / 1000000.0);

	parse_case_destroy(&ipv6);
	parse_case_destroy(&ipv4);
}

static void
print_contains_results(void)
{
	static const size_t table_sizes[] = {100U, 1000U, 10000U};
	size_t i;

	printf("bench_bulk_contains\n");
	printf("prefix table size    libcidr (M pairs/s)\n");
	for (i = 0; i < sizeof(table_sizes) / sizeof(table_sizes[0]); i++) {
		struct contains_case ccase;
		double rate;

		contains_case_init(&ccase, table_sizes[i]);
		rate = measure_ops_per_second(
		    run_bulk_contains, &ccase,
		    (double)(ccase.addr_count * ccase.prefix_count));
		printf("%-20zu %.2f\n", table_sizes[i], rate / 1000000.0);
		contains_case_destroy(&ccase);
	}
	printf("\n");
}

static void
print_aggregate_results(void)
{
	static const size_t counts[] = {1000U, 10000U, 100000U, 800000U};
	size_t i;

	printf("bench_bulk_aggregate\n");
	printf("prefix count         libcidr (M prefixes/s)\n");
	for (i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
		struct aggregate_case acase;
		double rate;

		aggregate_case_init(&acase, counts[i], 0);
		rate = measure_ops_per_second(run_bulk_aggregate, &acase,
		                              (double)acase.count);
		printf("%-20zu %.2f\n", counts[i], rate / 1000000.0);
		aggregate_case_destroy(&acase);
	}
	printf("\n");
}

static void
print_sort_results(void)
{
	struct sort_case network_asc;
	struct sort_case pfxlen_desc;
	double network_rate;
	double pfxlen_rate;

	sort_case_init(&network_asc, BENCH_SORT_COUNT, CIDR_SORT_NETWORK_ASC);
	sort_case_init(&pfxlen_desc, BENCH_SORT_COUNT, CIDR_SORT_PFXLEN_DESC);
	network_rate = measure_ops_per_second(run_bulk_sort, &network_asc,
	                                      (double)network_asc.count);
	pfxlen_rate = measure_ops_per_second(run_bulk_sort, &pfxlen_desc,
	                                     (double)pfxlen_desc.count);

	printf("bench_bulk_sort_network_asc\n");
	printf("prefix count         libcidr (M prefixes/s)\n");
	printf("%-20u %.2f\n\n", BENCH_SORT_COUNT, network_rate / 1000000.0);

	printf("bench_bulk_sort_pfxlen_desc\n");
	printf("prefix count         libcidr (M prefixes/s)\n");
	printf("%-20u %.2f\n\n", BENCH_SORT_COUNT, pfxlen_rate / 1000000.0);

	sort_case_destroy(&pfxlen_desc);
	sort_case_destroy(&network_asc);
}

static void
print_early_exit_results(void)
{
	static const size_t counts[] = {1000U, 10000U, 100000U, 800000U};
	size_t i;

	printf("bench_aggregate_early_exit\n");
	printf("prefix count         libcidr (M prefixes/s)\n");
	for (i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
		struct aggregate_case acase;
		double rate;

		aggregate_case_init(&acase, counts[i], 1);
		rate = measure_ops_per_second(run_bulk_aggregate, &acase,
		                              (double)acase.count);
		printf("%-20zu %.2f\n", counts[i], rate / 1000000.0);
		aggregate_case_destroy(&acase);
	}
	printf("\n");
}

int
main(void)
{
	struct bench_env env;

	bench_env_init(&env);
	print_header(&env);
	print_parse_results();
	print_contains_results();
	print_aggregate_results();
	print_sort_results();
	print_early_exit_results();
	return 0;
}
