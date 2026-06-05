/*
 * cidr_bulk.c - batch parse, containment, aggregation, and sort.
 *
 * Implements cidr_bulk_parse(), cidr_bulk_contains(),
 * cidr_bulk_aggregate(), and cidr_bulk_sort(). Contains the shared
 * in-place MSD radix sort engine.
 *
 * cidr_bulk_parse() is implemented in this phase. See ARCHITECTURE.md §5.2
 * for the batch parse specification and return-code precedence.
 * See ARCHITECTURE.md §5 for the bulk engine specification.
 */

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
