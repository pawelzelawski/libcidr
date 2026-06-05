/*
 * cidr_bulk.c - batch parse, containment, aggregation, and sort.
 *
 * Implements cidr_bulk_parse(), cidr_bulk_contains(),
 * cidr_bulk_aggregate(), and cidr_bulk_sort(). Contains the shared
 * in-place MSD radix sort engine.
 *
 * All four public bulk functions are implemented.
 * See ARCHITECTURE.md §5 for the bulk engine specification.
 */

#include <string.h>

#include "../include/libcidr.h"
#include "cidr_internal.h"

/*
 * radix_addr_len - return the address byte width for a given family.
 *
 * Returns 4 for CIDR_AF_INET, 16 for CIDR_AF_INET6.
 * Caller must ensure family is valid (not CIDR_AF_UNSPEC).
 */
static inline size_t
radix_addr_len(cidr_family_t family)
{
	return (family == CIDR_AF_INET) ? 4 : 16;
}

/*
 * radix_key_byte - extract one byte of the radix sort key.
 *
 * For CIDR_SORT_NETWORK_ASC (key = addr_bytes in network order, then
 * pfxlen): returns p->addr bytes[byte_pos] when byte_pos < addr_len,
 * p->pfxlen when byte_pos == addr_len.
 *
 * For CIDR_SORT_PFXLEN_DESC (key = ~pfxlen, then addr_bytes in network
 * order): returns ~p->pfxlen when byte_pos == 0, addr bytes[byte_pos - 1]
 * otherwise.
 *
 * p:        pointer to prefix
 * byte_pos: position in the virtual sort key (0-based)
 * addr_len: address byte width (4 or 16)
 * order:    sort ordering
 */
static inline uint8_t
radix_key_byte(const cidr_prefix_t *p, size_t byte_pos, size_t addr_len,
               cidr_sort_order_t order)
{
	const uint8_t *addr_bytes;

	addr_bytes = (const uint8_t *)&p->addr.addr;

	if (order == CIDR_SORT_NETWORK_ASC) {
		if (byte_pos < addr_len)
			return addr_bytes[byte_pos];
		return p->pfxlen;
	}

	/* CIDR_SORT_PFXLEN_DESC */
	if (byte_pos == 0)
		return (uint8_t)(~(p->pfxlen));
	return addr_bytes[byte_pos - 1];
}

/*
 * prefix_swap - swap two cidr_prefix_t values in place.
 */
static inline void
prefix_swap(cidr_prefix_t *restrict a, cidr_prefix_t *restrict b)
{
	cidr_prefix_t tmp;

	tmp = *a;
	*a = *b;
	*b = tmp;
}

/*
 * radix_sort_segment - recursive MSD radix sort over a segment.
 *
 * Sorts prefixes[start..end-1] by the key byte at position byte_pos.
 * Uses a stable in-place counting-sort-based partition at each byte
 * position, then recurses on non-trivial buckets.
 *
 * SAFETY: stack usage per level is bounded by 4 * 256 * sizeof(size_t)
 * = 8192 bytes on 64-bit platforms. Max recursion depth is key_len (17
 * for IPv6), giving a worst-case stack of 17 * 8192 = 139,264 bytes,
 * well within the default 8 MiB stack. See ARCHITECTURE.md §5.4.
 *
 * prefixes:  prefix array
 * start:     start index (inclusive)
 * end:       end index (exclusive)
 * byte_pos:  current byte position in the sort key
 * key_len:   total key length in bytes (addr_len + 1)
 * order:     sort ordering
 * addr_len:  address byte width (4 or 16)
 */
static void
radix_sort_segment(cidr_prefix_t *prefixes, size_t start, size_t end,
                   size_t byte_pos, size_t key_len, cidr_sort_order_t order,
                   size_t addr_len)
{
	size_t count[256] = {0};
	size_t start_pos[256];
	size_t next[256];
	size_t i;
	int b;

	if (end - start <= 1 || byte_pos >= key_len)
		return;

	/*
	 * SAFETY: the stable partition loop below must not overflow
	 * bucket boundaries. Each item is placed into exactly one
	 * bucket, and the scan terminates when all items are within
	 * their correct bucket ranges. The total number of swaps is
	 * bounded by the segment size.
	 */

	/* Count items per digit value */
	for (i = start; i < end; i++)
		count[radix_key_byte(&prefixes[i], byte_pos, addr_len,
		                     order)]++;

	/* Compute bucket start positions */
	start_pos[0] = start;
	for (b = 1; b < 256; b++)
		start_pos[b] = start_pos[b - 1] + count[b - 1];

	/*
	 * Compute bucket end positions (exclusive) and initialise
	 * the next-pointer array from start positions.
	 */
	for (b = 0; b < 255; b++)
		next[b] = start_pos[b];
	next[255] = end;

	/*
	 * Stable in-place partition by digit value.
	 *
	 * For each position i, if the item at i is already within its
	 * digit's bucket range, advance i. Otherwise, swap it to the
	 * next available slot in its bucket (tracked by next[d]) and
	 * process the swapped-in item at the same i.
	 *
	 * This is stable because items within each bucket are placed
	 * in the order they are encountered during the left-to-right
	 * scan, which corresponds to their original relative order.
	 * See CODING_STANDARDS.md §4.1.
	 */
	for (i = start; i < end;) {
		uint8_t d =
		    radix_key_byte(&prefixes[i], byte_pos, addr_len, order);
		size_t end_d = (d < 255) ? start_pos[d + 1] : end;

		if (i >= start_pos[d] && i < end_d) {
			i++;
		} else {
			prefix_swap(&prefixes[i], &prefixes[next[d]++]);
		}
	}

	/* Recurse on non-trivial buckets */
	for (b = 0; b < 256; b++) {
		size_t seg_start = start_pos[b];
		size_t seg_end = (b < 255) ? start_pos[b + 1] : end;

		if (seg_end - seg_start > 1)
			radix_sort_segment(prefixes, seg_start, seg_end,
			                   byte_pos + 1, key_len, order,
			                   addr_len);
	}
}

/*
 * radix_sort_prefixes - in-place MSD radix sort for prefix arrays.
 *
 * See ARCHITECTURE.md §5.4 for the radix sort algorithm, §5.5 for the
 * key construction and CIDR_SORT_PFXLEN_DESC stability semantics.
 *
 * Caller guarantees: count > 0, all prefixes have the same valid family
 * (CIDR_AF_INET or CIDR_AF_INET6), no CIDR_AF_UNSPEC entries.
 */
void
radix_sort_prefixes(cidr_prefix_t *prefixes, size_t count,
                    cidr_sort_order_t order)
{
	size_t addr_len;
	size_t key_len;

	addr_len = radix_addr_len(prefixes[0].addr.family);
	key_len = addr_len + 1;

	radix_sort_segment(prefixes, 0, count, 0, key_len, order, addr_len);
}

/*
 * cidr_bulk_sort - sort a prefix array in place using MSD radix sort.
 *
 * Validates parameters and delegates to the shared radix sort engine.
 * See ARCHITECTURE.md §5.5.
 */
cidr_err_t
cidr_bulk_sort(cidr_prefix_t *prefixes, size_t count, cidr_sort_order_t order)
{
	cidr_family_t family;
	size_t i;

	/* Empty array policy: CIDR_OK, no work. See ARCHITECTURE.md §3.4. */
	if (count == 0)
		return CIDR_OK;

	/* Array pointer must be valid when count > 0 */
	if (prefixes == NULL)
		return CIDR_ERR_INVAL;

	/* Validate sort order */
	if (order != CIDR_SORT_NETWORK_ASC && order != CIDR_SORT_PFXLEN_DESC)
		return CIDR_ERR_INVAL;

	/* Validate family consistency */
	family = prefixes[0].addr.family;
	if (family != CIDR_AF_INET && family != CIDR_AF_INET6)
		return CIDR_ERR_INVAL;

	for (i = 1; i < count; i++) {
		if (prefixes[i].addr.family == CIDR_AF_UNSPEC)
			return CIDR_ERR_INVAL;
		if (prefixes[i].addr.family != family)
			return CIDR_ERR_FAMILY;
	}

	radix_sort_prefixes(prefixes, count, order);
	return CIDR_OK;
}

/*
 * cidr_bulk_parse - batch-parse address strings into a caller-provided array.
 *
 * Parses count address strings from srcs into out. Each string is parsed
 * per cidr_addr_parse() semantics (ARCHITECTURE.md §4.1). On parse failure
 * for item i, out[i].family is set to CIDR_AF_UNSPEC and errs[i] is set to
 * CIDR_ERR_PARSE. On success, errs[i] is CIDR_OK.
 *
 * All items are attempted regardless of individual parse failures. The
 * reference family is inferred from the first successfully-parsed item.
 * After the full batch, return-code precedence applies:
 * CIDR_ERR_FAMILY > CIDR_ERR_PARSE > CIDR_OK.
 *
 * srcs:  array of count null-terminated address strings
 * count: number of entries in srcs and out
 * out:   caller-provided cidr_addr_t array; written on success with the
 *        parsed address, or with family = CIDR_AF_UNSPEC on parse failure
 * errs:  optional per-item error array (may be NULL); when non-NULL, must
 *        have space for count cidr_err_t values
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_INVAL if srcs or out is NULL, or if any srcs[i] is
 *   NULL (fail-fast, no output written on NULL element).
 * Returns CIDR_ERR_PARSE if any item failed to parse.
 * Returns CIDR_ERR_FAMILY if successfully-parsed items have mixed families.
 *
 * When count == 0, returns CIDR_OK with no work performed and all pointer
 * parameters are ignored per ARCHITECTURE.md §3.4 empty array policy.
 *
 * Complexity: O(n) where n is count.
 * No allocation occurs.
 *
 * See ARCHITECTURE.md §5.2 for the full batch parse specification.
 */
cidr_err_t
cidr_bulk_parse(const char **srcs, size_t count, cidr_addr_t *out,
                cidr_err_t *errs)
{
	cidr_family_t ref_family;
	bool has_parse_failure;
	bool has_family_mismatch;
	bool ref_family_set;
	size_t i;

	/* Empty array policy. See ARCHITECTURE.md §3.4. */
	if (count == 0)
		return CIDR_OK;

	/* Validate mandatory pointer parameters. */
	if (srcs == NULL || out == NULL)
		return CIDR_ERR_INVAL;

	/*
	 * SAFETY: NULL element in srcs triggers fail-fast with no output
	 * written. All string pointers in srcs must be non-NULL before any
	 * parsing occurs. See ARCHITECTURE.md §5.2 NULL element policy.
	 */
	for (i = 0; i < count; i++) {
		if (srcs[i] == NULL)
			return CIDR_ERR_INVAL;
	}

	/*
	 * Process all items regardless of individual parse failures.
	 * No fail-fast after the NULL element check.
	 * See ARCHITECTURE.md §5.2.
	 */
	ref_family_set = false;
	has_parse_failure = false;
	has_family_mismatch = false;

	for (i = 0; i < count; i++) {
		cidr_err_t rc = cidr_addr_parse(srcs[i], &out[i]);

		if (rc == CIDR_OK) {
			if (!ref_family_set) {
				ref_family = out[i].family;
				ref_family_set = true;
			} else if (out[i].family != ref_family) {
				has_family_mismatch = true;
			}

			if (errs != NULL)
				errs[i] = CIDR_OK;
		} else {
			/*
			 * Parse failure: write error sentinel to output.
			 * See ARCHITECTURE.md §5.2.
			 */
			out[i].family = CIDR_AF_UNSPEC;
			has_parse_failure = true;

			if (errs != NULL)
				errs[i] = CIDR_ERR_PARSE;
		}
	}

	/*
	 * Return-code precedence:
	 * CIDR_ERR_FAMILY > CIDR_ERR_PARSE > CIDR_OK.
	 * See ARCHITECTURE.md §5.2.
	 */
	if (has_family_mismatch)
		return CIDR_ERR_FAMILY;
	if (has_parse_failure)
		return CIDR_ERR_PARSE;
	return CIDR_OK;
}

/*
 * cidr_bulk_contains - bulk containment: find first matching prefix for
 *                       each address.
 *
 * For each address in addrs, scans prefixes in order and writes the index
 * of the first matching prefix into matches[i], or -1 if no prefix matched.
 * Match is first-match-in-order. Callers needing longest-prefix-match
 * semantics sort prefixes by CIDR_SORT_PFXLEN_DESC before calling.
 *
 * When prefix_count == 0, all matches[i] are written as -1 and the function
 * returns CIDR_OK.
 *
 * addrs:        array of addr_count addresses to test
 * addr_count:   number of entries in addrs and matches
 * prefixes:     array of prefix_count prefixes to scan for each address
 * prefix_count: number of entries in prefixes
 * matches:      caller-provided ssize_t array; on success, each entry is
 *               the index of the first matching prefix, or -1 for no match
 * errs:         optional per-item error array (may be NULL); when non-NULL,
 *               each entry is set to CIDR_OK
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_INVAL if addrs or matches is NULL when addr_count > 0,
 *   if prefixes is NULL when prefix_count > 0, or if any address or prefix
 *   has family == CIDR_AF_UNSPEC.
 * Returns CIDR_ERR_FAMILY if the address array or prefix array contains
 *   mixed families, or if the address family does not match the prefix
 *   family.
 *
 * When addr_count == 0, returns CIDR_OK with no work performed per the
 * empty array policy (ARCHITECTURE.md §3.4).
 *
 * Complexity: O(addr_count * prefix_count).
 * No allocation occurs.
 *
 * See ARCHITECTURE.md §5.3 for the bulk containment specification.
 */
cidr_err_t
cidr_bulk_contains(const cidr_addr_t *addrs, size_t addr_count,
                   const cidr_prefix_t *prefixes, size_t prefix_count,
                   ssize_t *matches, cidr_err_t *errs)
{
	cidr_family_t addr_family;
	cidr_family_t pfx_family;
	size_t i, j;

	/* Empty array policy. See ARCHITECTURE.md §3.4. */
	if (addr_count == 0)
		return CIDR_OK;

	/* Validate mandatory pointers when addr_count > 0 */
	if (addrs == NULL || matches == NULL)
		return CIDR_ERR_INVAL;

	/*
	 * Handle empty prefix table: all addresses have no match.
	 * See ARCHITECTURE.md §5.3.
	 */
	if (prefix_count == 0) {
		for (i = 0; i < addr_count; i++)
			matches[i] = -1;
		return CIDR_OK;
	}

	/* Prefixes pointer must be valid when prefix_count > 0 */
	if (prefixes == NULL)
		return CIDR_ERR_INVAL;

	/*
	 * Validate address array family consistency.
	 * SAFETY: all addresses must share the same valid family before
	 * scanning begins. See ARCHITECTURE.md §3.1 CIDR_AF_UNSPEC policy.
	 */
	addr_family = addrs[0].family;
	if (addr_family != CIDR_AF_INET && addr_family != CIDR_AF_INET6)
		return CIDR_ERR_INVAL;
	for (i = 1; i < addr_count; i++) {
		if (addrs[i].family == CIDR_AF_UNSPEC)
			return CIDR_ERR_INVAL;
		if (addrs[i].family != addr_family)
			return CIDR_ERR_FAMILY;
	}

	/*
	 * Validate prefix array family consistency.
	 * SAFETY: all prefixes must share the same valid family.
	 */
	pfx_family = prefixes[0].addr.family;
	if (pfx_family != CIDR_AF_INET && pfx_family != CIDR_AF_INET6)
		return CIDR_ERR_INVAL;
	for (i = 1; i < prefix_count; i++) {
		if (prefixes[i].addr.family == CIDR_AF_UNSPEC)
			return CIDR_ERR_INVAL;
		if (prefixes[i].addr.family != pfx_family)
			return CIDR_ERR_FAMILY;
	}

	/* Address and prefix families must match */
	if (addr_family != pfx_family)
		return CIDR_ERR_FAMILY;

	/*
	 * For each address, scan prefixes in order. First match wins.
	 * See ARCHITECTURE.md §5.3.
	 */
	for (i = 0; i < addr_count; i++) {
		ssize_t match = -1;

		for (j = 0; j < prefix_count; j++) {
			bool contained;

			if (cidr_prefix_contains(&prefixes[j], &addrs[i],
			                         &contained) == CIDR_OK &&
			    contained) {
				match = (ssize_t)j;
				break;
			}
		}

		matches[i] = match;
		if (errs != NULL)
			errs[i] = CIDR_OK;
	}

	return CIDR_OK;
}

/*
 * prefixes_are_siblings - check whether two prefixes are mergeable
 *                         siblings (same pfxlen, same supernet).
 *
 * Two prefixes are siblings if they have equal prefix length (greater
 * than zero) and their supernets at pfxlen - 1 are identical.
 * See ARCHITECTURE.md §5.4 sibling merge.
 */
static bool
prefixes_are_siblings(const cidr_prefix_t *a, const cidr_prefix_t *b)
{
	cidr_prefix_t super_a, super_b;
	size_t addr_len;

	if (a->pfxlen != b->pfxlen || a->pfxlen == 0)
		return false;
	if (a->addr.family != b->addr.family)
		return false;

	/*
	 * SAFETY: pfxlen > 0 ensures cidr_prefix_supernet will not return
	 * CIDR_ERR_OVERFLOW. Both prefixes have valid, matching families.
	 */
	if (cidr_prefix_supernet(a, &super_a) != CIDR_OK)
		return false;
	if (cidr_prefix_supernet(b, &super_b) != CIDR_OK)
		return false;

	addr_len = (super_a.addr.family == CIDR_AF_INET) ? 4 : 16;

	return super_a.pfxlen == super_b.pfxlen &&
	       memcmp(&super_a.addr.addr, &super_b.addr.addr, addr_len) == 0;
}

/*
 * cidr_bulk_aggregate - aggregate a prefix array to a minimal covering set.
 *
 * Operates in place using the five-step algorithm from ARCHITECTURE.md §5.4:
 * 1. Radix sort by CIDR_SORT_NETWORK_ASC (addr asc, pfxlen asc)
 * 2. Remove exact duplicates
 * 3. Remove prefixes covered by a shorter prefix
 * 4. Merge adjacent sibling prefixes; repeat until no merges occur
 * 5. Early termination (built into step 4)
 *
 * The result covers exactly the same address space as the input. On return,
 * the first *out_count entries are the aggregated prefixes; the remaining
 * entries are undefined.
 *
 * prefixes:  caller-provided prefix array; modified in place
 * count:     number of entries in prefixes
 * out_count: receives the number of prefixes in the aggregated result;
 *            must not be NULL
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_INVAL if prefixes or out_count is NULL, or if any
 *   prefix has addr.family == CIDR_AF_UNSPEC.
 * Returns CIDR_ERR_FAMILY if the array contains mixed families.
 *
 * When count == 0, writes 0 to *out_count and returns CIDR_OK.
 *
 * Complexity: O(n * k) where k is key width in bytes (5 for IPv4, 17 for
 * IPv6); treated as O(n) because k is a compile-time constant.
 * No allocation occurs.
 *
 * See ARCHITECTURE.md §5.4 for the aggregation algorithm.
 */
cidr_err_t
cidr_bulk_aggregate(cidr_prefix_t *prefixes, size_t count, size_t *out_count)
{
	cidr_family_t family;
	size_t i;
	size_t write_idx;
	bool merged;
	int cmp;

	if (out_count == NULL)
		return CIDR_ERR_INVAL;
	if (count == 0) {
		*out_count = 0;
		return CIDR_OK;
	}
	if (prefixes == NULL)
		return CIDR_ERR_INVAL;

	/* Validate family consistency */
	family = prefixes[0].addr.family;
	if (family != CIDR_AF_INET && family != CIDR_AF_INET6)
		return CIDR_ERR_INVAL;
	for (i = 1; i < count; i++) {
		if (prefixes[i].addr.family == CIDR_AF_UNSPEC)
			return CIDR_ERR_INVAL;
		if (prefixes[i].addr.family != family)
			return CIDR_ERR_FAMILY;
	}

	/*
	 * Step 1: Radix sort by CIDR_SORT_NETWORK_ASC.
	 * See ARCHITECTURE.md §5.4 step 1.
	 */
	radix_sort_prefixes(prefixes, count, CIDR_SORT_NETWORK_ASC);

	/*
	 * Step 2: Remove exact duplicates (adjacent after sort).
	 * See ARCHITECTURE.md §5.4 step 2.
	 */
	write_idx = 0;
	for (i = 1; i < count; i++) {
		if (cidr_prefix_cmp(&prefixes[write_idx], &prefixes[i], &cmp) !=
		        CIDR_OK ||
		    cmp != 0) {
			write_idx++;
			if (write_idx != i)
				prefixes[write_idx] = prefixes[i];
		}
	}
	count = write_idx + 1;

	/*
	 * Step 3: Remove prefixes covered by a shorter prefix.
	 * Uses single-pointer scan: any prefix contained by the most
	 * recently kept prefix is redundant. See ARCHITECTURE.md §5.4
	 * step 3.
	 *
	 * SAFETY: after the sort, all prefixes within a given prefix's
	 * range appear contiguously, so a single covering pointer suffices
	 * for the linear scan.
	 */
	write_idx = 0;
	for (i = 1; i < count; i++) {
		bool contained;

		if (cidr_prefix_contains(&prefixes[write_idx],
		                         &prefixes[i].addr,
		                         &contained) == CIDR_OK &&
		    contained)
			continue;

		write_idx++;
		if (write_idx != i)
			prefixes[write_idx] = prefixes[i];
	}
	count = write_idx + 1;

	/*
	 * Step 4 & 5: Merge adjacent sibling prefixes repeatedy until
	 * no merges occur (early termination). See ARCHITECTURE.md §5.4
	 * steps 4-5.
	 */
	do {
		merged = false;
		write_idx = 0;

		for (i = 0; i < count; i++) {
			if (write_idx > 0 &&
			    prefixes_are_siblings(&prefixes[write_idx - 1],
			                          &prefixes[i])) {
				cidr_prefix_t super;

				/*
				 * SAFETY: prefixes_are_siblings confirmed
				 * pfxlen > 0 and matching supernets --
				 * cidr_prefix_supernet cannot fail here.
				 */
				(void)cidr_prefix_supernet(&prefixes[i],
				                           &super);
				prefixes[write_idx - 1] = super;
				merged = true;
			} else {
				if (write_idx != i)
					prefixes[write_idx] = prefixes[i];
				write_idx++;
			}
		}
		count = write_idx;
	} while (merged);

	*out_count = count;
	return CIDR_OK;
}
