/*
 * bench_index.c - C benchmark suite for libcidr prefix index operations.
 *
 * Measures cidr_index_create(), cidr_index_lookup(), and the documented
 * index-vs-bulk crossover from ARCHITECTURE.md §6 under release flags.
 * Output naming and workload sizes follow TESTING.md §8.1.
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

#define BENCH_QUERY_COUNT 100000U
#define BENCH_LOOKUP_COUNT 1000000U
#define BENCH_MIN_SECONDS 0.20
#define BENCH_CROSSOVER_PAIR_BUDGET 100000000U

struct bench_env {
	const char *platform;
	char cpu[128];
	long cores;
	char date[32];
};

struct build_case {
	cidr_prefix_t *prefixes;
	size_t count;
};

struct lookup_case {
	cidr_prefix_t *prefixes;
	cidr_addr_t *addrs;
	ssize_t *matches;
	size_t prefix_count;
	size_t query_count;
};

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
 * fill_cpu_string - gather a best-effort CPU description so benchmark output
 * remains comparable across machines. TESTING.md §8.2 requires this context.
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
	struct tm *tm_local;

	now = time(NULL);
	tm_local = localtime(&now);
	if (tm_local == NULL) {
		(void)snprintf(buf, len, "unknown");
		return;
	}
	if (strftime(buf, len, "%Y-%m-%d", tm_local) == 0)
		(void)snprintf(buf, len, "unknown");
}

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
 * addr_from_u32 - construct deterministic IPv4 host addresses without text
 * parsing overhead during benchmark setup.
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
 * prefix_from_base - build a valid prefix using the host-to-network
 * constructor so the benchmark respects the ARCHITECTURE.md §4.1.4
 * host-bits-zero invariant.
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
 * build_prefix_table - create a deterministic IPv4 routing table workload.
 * All prefixes use /24 so bulk first-match and index LPM semantics coincide.
 */
static void
build_prefix_table(cidr_prefix_t *prefixes, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		prefix_from_base((uint32_t)(i << 8), 24, &prefixes[i]);
}

/*
 * build_query_table - create in-prefix addresses for lookup benchmarks.
 * Each query lands inside one /24 so index and bulk outputs are comparable.
 */
static void
build_query_table(cidr_addr_t *addrs, size_t prefix_count, size_t query_count)
{
	size_t i;

	for (i = 0; i < query_count; i++)
		addr_from_u32((uint32_t)(((i % prefix_count) << 8) | 1U),
		              &addrs[i]);
}

/*
 * crossover_query_count - cap the linear-scan workload so the crossover
 * benchmark remains practical at the largest documented table sizes.
 *
 * ARCHITECTURE.md §6 requires the benchmark to compare index build cost
 * against cidr_bulk_contains(), but not to hold query count constant at
 * every prefix scale. The capped pair budget preserves the comparison while
 * avoiding an impractical 800k-prefix bulk scan.
 */
static size_t
crossover_query_count(size_t prefix_count)
{
	size_t query_count;

	query_count = BENCH_QUERY_COUNT;
	if (prefix_count > 0 &&
	    prefix_count > (BENCH_CROSSOVER_PAIR_BUDGET / query_count))
		query_count = BENCH_CROSSOVER_PAIR_BUDGET / prefix_count;
	if (query_count < 128U)
		query_count = 128U;
	return query_count;
}

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

static double
measure_seconds_once(int (*fn)(void *), void *arg)
{
	double start;
	double end;

	start = bench_now_seconds();
	if (fn(arg) != 0) {
		fprintf(stderr, "benchmark operation failed\n");
		exit(1);
	}
	end = bench_now_seconds();
	return end - start;
}

static void
print_header(const struct bench_env *env)
{
	printf("libcidr benchmark - index\n");
	printf("Platform : %s\n", env->platform);
	printf("CPU      : %s\n", env->cpu);
	printf("Cores    : %ld\n", env->cores);
	printf("Build    : release (-O2)\n");
	printf("Date     : %s\n\n", env->date);
}

/*
 * build_case_init - allocate the prefix storage used by index build timing.
 *
 * Ownership: prefixes are owned by the build_case and freed by
 * build_case_destroy().
 */
static void
build_case_init(struct build_case *bcase, size_t count)
{
	bcase->count = count;
	bcase->prefixes = bench_alloc(count * sizeof(*bcase->prefixes));
	build_prefix_table(bcase->prefixes, count);
}

static void
build_case_destroy(struct build_case *bcase)
{
	free(bcase->prefixes);
}

static int
run_index_build(void *arg)
{
	struct build_case *bcase;
	cidr_index_t *index;
	cidr_err_t rc;

	bcase = arg;
	index = NULL;
	rc = cidr_index_create(bcase->prefixes, bcase->count, &index);
	if (rc != CIDR_OK)
		return 1;
	cidr_index_destroy(index);
	return 0;
}

/*
 * lookup_case_init - allocate the prefix/query arrays used by both
 * cidr_index_lookup() and cidr_bulk_contains() throughput measurements.
 *
 * Ownership: prefixes, addrs, and matches are owned by the lookup_case and
 * freed by lookup_case_destroy().
 */
static void
lookup_case_init(struct lookup_case *lcase, size_t prefix_count,
                 size_t query_count)
{
	lcase->prefix_count = prefix_count;
	lcase->query_count = query_count;
	lcase->prefixes = bench_alloc(prefix_count * sizeof(*lcase->prefixes));
	lcase->addrs = bench_alloc(query_count * sizeof(*lcase->addrs));
	lcase->matches = bench_alloc(query_count * sizeof(*lcase->matches));
	build_prefix_table(lcase->prefixes, prefix_count);
	build_query_table(lcase->addrs, prefix_count, query_count);
}

static void
lookup_case_destroy(struct lookup_case *lcase)
{
	free(lcase->matches);
	free(lcase->addrs);
	free(lcase->prefixes);
}

/*
 * lookup_case_prepare_index - build the reusable index for lookup-only
 * throughput measurement so build cost is excluded from bench_index_lookup.
 */
static cidr_index_t *
lookup_case_prepare_index(const struct lookup_case *lcase)
{
	cidr_index_t *index;
	cidr_err_t rc;

	index = NULL;
	rc = cidr_index_create(lcase->prefixes, lcase->prefix_count, &index);
	if (rc != CIDR_OK) {
		fprintf(stderr, "cidr_index_create failed: %d\n", rc);
		exit(1);
	}
	return index;
}

static int
run_lookup_only(void *arg)
{
	struct {
		const cidr_index_t *index;
		struct lookup_case *lcase;
	} *ctx;
	cidr_err_t rc;

	ctx = arg;
	rc = cidr_index_lookup(ctx->index, ctx->lcase->addrs,
	                       ctx->lcase->query_count, ctx->lcase->matches,
	                       NULL);
	return (rc == CIDR_OK) ? 0 : 1;
}

static int
run_bulk_contains(void *arg)
{
	struct lookup_case *lcase;
	cidr_err_t rc;

	lcase = arg;
	rc = cidr_bulk_contains(lcase->addrs, lcase->query_count,
	                        lcase->prefixes, lcase->prefix_count,
	                        lcase->matches, NULL);
	return (rc == CIDR_OK) ? 0 : 1;
}

static void
print_build_results(void)
{
	static const size_t counts[] = {1000U, 10000U, 100000U, 800000U};
	size_t i;

	printf("bench_index_build\n");
	printf("prefix count         libcidr (M prefixes/s)\n");
	for (i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
		struct build_case bcase;
		double rate;

		build_case_init(&bcase, counts[i]);
		rate = measure_ops_per_second(run_index_build, &bcase,
		                              (double)bcase.count);
		printf("%-20zu %.2f\n", counts[i], rate / 1000000.0);
		build_case_destroy(&bcase);
	}
	printf("\n");
}

static void
print_lookup_results(void)
{
	struct lookup_case lcase;
	cidr_index_t *index;
	double rate;
	struct {
		const cidr_index_t *index;
		struct lookup_case *lcase;
	} ctx;

	lookup_case_init(&lcase, 800000U, BENCH_LOOKUP_COUNT);
	index = lookup_case_prepare_index(&lcase);
	ctx.index = index;
	ctx.lcase = &lcase;
	rate = measure_ops_per_second(run_lookup_only, &ctx,
	                              (double)lcase.query_count);

	printf("bench_index_lookup\n");
	printf("prefix count         queries    libcidr (M queries/s)\n");
	printf("%-20u %-10u %.2f\n\n", 800000U, BENCH_LOOKUP_COUNT,
	       rate / 1000000.0);

	cidr_index_destroy(index);
	lookup_case_destroy(&lcase);
}

static void
print_crossover_results(void)
{
	static const size_t counts[] = {100U, 1000U, 10000U, 100000U, 800000U};
	size_t i;

	printf("bench_index_vs_bulk_crossover\n");
	printf("prefix count         queries    build ms   bulk kq/s  "
	       "index kq/s crossover queries\n");
	for (i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
		struct lookup_case lcase;
		cidr_index_t *index;
		double build_time;
		double bulk_rate;
		double index_rate;
		double crossover;
		size_t query_count;
		struct {
			const cidr_index_t *index;
			struct lookup_case *lcase;
		} ctx;

		query_count = crossover_query_count(counts[i]);
		lookup_case_init(&lcase, counts[i], query_count);
		build_time = measure_seconds_once(
		    run_index_build,
		    &(struct build_case){.prefixes = lcase.prefixes,
		                         .count = lcase.prefix_count});
		index = lookup_case_prepare_index(&lcase);
		ctx.index = index;
		ctx.lcase = &lcase;
		bulk_rate = measure_ops_per_second(run_bulk_contains, &lcase,
		                                   (double)lcase.query_count);
		index_rate = measure_ops_per_second(run_lookup_only, &ctx,
		                                    (double)lcase.query_count);

		if ((1.0 / index_rate) >= (1.0 / bulk_rate)) {
			printf("%-20zu %-10zu %-10.2f %-10.2f %-10.2f "
			       "no crossover\n",
			       counts[i], query_count, build_time * 1000.0,
			       bulk_rate / 1000.0, index_rate / 1000.0);
		} else {
			crossover = build_time /
			            ((1.0 / bulk_rate) - (1.0 / index_rate));
			printf("%-20zu %-10zu %-10.2f %-10.2f %-10.2f %.0f\n",
			       counts[i], query_count, build_time * 1000.0,
			       bulk_rate / 1000.0, index_rate / 1000.0,
			       crossover);
		}

		cidr_index_destroy(index);
		lookup_case_destroy(&lcase);
	}
	printf("\n");
}

int
main(void)
{
	struct bench_env env;

	bench_env_init(&env);
	print_header(&env);
	print_build_results();
	print_lookup_results();
	print_crossover_results();
	return 0;
}
