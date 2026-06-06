/*
 * cidr_index.c - high-performance prefix index: LC-trie
 *                (Level-Compressed Patricia trie).
 *
 * cidr_index_create(): builds array-packed LC-trie from caller-provided
 *   prefix array. Only allocating function in the library. O(n * W).
 * cidr_index_destroy(): releases all trie memory. NULL-safe.
 * cidr_index_lookup(): longest-prefix match for each address in
 *   caller-provided array.
 *
 * Phase 6.2: basic Patricia trie (binary, path-compressed) construction
 * with full lookup and destroy. Level compression is implemented in
 * Phase 6.3.
 *
 * See ARCHITECTURE.md §6 for the Patricia trie specification.
 */

/*
 * SAFETY: This is the only source file that includes <stdlib.h> in the
 * library. malloc/free appear only in this file. Verify with:
 *   grep -n "malloc\|free" src/
 * See CODING_STANDARDS.md §2.1 and ARCHITECTURE.md §1.4.
 */
#include <stdlib.h>
#include <string.h>

#include "../include/libcidr.h"
#include "cidr_internal.h"

/*
 * prefix_order_tag_set - stash a uint32_t tag in the addr.family field.
 *
 * Used to record the original input index before sorting. The radix
 * sort for CIDR_SORT_NETWORK_ASC does not use addr.family in its key
 * extraction, so the tag survives the sort intact and moves with its
 * prefix. The true family is restored after trie construction.
 */
static inline void
prefix_order_tag_set(cidr_prefix_t *prefix, uint32_t order_tag)
{
	unsigned char *bytes;

	bytes = (unsigned char *)&prefix->addr.family;
	bytes[0] = (unsigned char)(order_tag & 0xFF);
	bytes[1] = (unsigned char)((order_tag >> 8) & 0xFF);
	bytes[2] = (unsigned char)((order_tag >> 16) & 0xFF);
	bytes[3] = (unsigned char)((order_tag >> 24) & 0xFF);
}

/*
 * prefix_order_tag_get - load the stashed uint32_t tag from addr.family.
 */
static inline uint32_t
prefix_order_tag_get(const cidr_prefix_t *prefix)
{
	const unsigned char *bytes;

	bytes = (const unsigned char *)&prefix->addr.family;
	return ((uint32_t)bytes[0]) | ((uint32_t)bytes[1] << 8) |
	       ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

/*
 * trie_addr_bit - extract a single bit from an address.
 *
 * Bits are numbered 0-based from the MSB of the first address byte
 * (network byte order). For IPv4 (4 bytes), valid positions are 0-31.
 * For IPv6 (16 bytes), valid positions are 0-127.
 *
 * addr:    pointer to a valid cidr_addr_t (family CIDR_AF_INET or
 *          CIDR_AF_INET6)
 * bit_pos: bit position (0-based from MSB of byte 0)
 * addr_len: address byte width (4 or 16)
 *
 * Returns 0 or 1.
 *
 * See ARCHITECTURE.md §6.3: bits are tested in MSB-first order
 * consistent with network-byte-order storage.
 */
static inline int
trie_addr_bit(const cidr_addr_t *addr, int bit_pos, size_t addr_len)
{
	const uint8_t *bytes;
	int byte_idx, bit_offset;

	bytes = (const uint8_t *)&addr->addr;
	byte_idx = bit_pos / 8;
	bit_offset = 7 - (bit_pos % 8);

	if (byte_idx >= (int)addr_len)
		return 0;
	return (bytes[byte_idx] >> bit_offset) & 1;
}

/*
 * trie_prefix_matches - verify that an address falls within a prefix.
 *
 * Performs mask-and-compare: (addr & mask) == prefix->addr.
 * Used during lookup to validate that a prefix stored at a trie node
 * actually covers the queried address.
 *
 * pfx:     pointer to a valid cidr_prefix_t
 * addr:    pointer to a valid cidr_addr_t (same family)
 * addr_len: address byte width (4 or 16)
 *
 * Returns true if the address is within the prefix.
 */
static bool
trie_prefix_matches(const cidr_prefix_t *pfx, const cidr_addr_t *addr,
                    size_t addr_len)
{
	const uint8_t *pfx_bytes, *addr_bytes;
	uint8_t pfxlen;
	size_t full_bytes, bit_rem;

	(void)addr_len;

	pfxlen = pfx->pfxlen;
	pfx_bytes = (const uint8_t *)&pfx->addr.addr;
	addr_bytes = (const uint8_t *)&addr->addr;

	if (pfxlen == 0)
		return true;

	full_bytes = pfxlen / 8;
	bit_rem = pfxlen % 8;

	for (size_t i = 0; i < full_bytes; i++) {
		if (pfx_bytes[i] != addr_bytes[i])
			return false;
	}

	if (bit_rem > 0) {
		uint8_t mask = (uint8_t)(0xFF << (8 - bit_rem));

		if ((pfx_bytes[full_bytes] & mask) !=
		    (addr_bytes[full_bytes] & mask))
			return false;
	}

	return true;
}

/*
 * trie_subtree_build - recursively build a binary Patricia trie subtree
 * at an explicit position in the node array.
 *
 * Builds a subtree for prefixes in the range [start, end) of the sorted
 * array. All prefixes in this range share the same first (bit_pos) bits.
 * The `inherited` parameter is the best matching prefix from ancestors
 * (UINT32_MAX if none). The function writes the subtree root node at
 * `nodes[write_at]`. Child roots for a branch node are reserved at
 * contiguous indices `nodes[base]` and `nodes[base + 1]`, with deeper
 * descendants allocated after those root slots via `next_free`.
 *
 * Algorithm: find the first bit position >= bit_pos where either a
 * prefix ends or the remaining prefixes diverge. Create a node at that
 * position. If prefixes extend past the split point, split into left
 * (bit=0) and right (bit=1) subtrees and recurse.
 *
 * sorted:      sorted prefix array (by CIDR_SORT_NETWORK_ASC)
 * start, end:  range of prefixes for this subtree [start, end)
 * bit_pos:     current bit position (prefixes share bits [0, bit_pos))
 * key_bits:    total key width in bits (32 for IPv4, 128 for IPv6)
 * addr_len:    address byte width (4 or 16)
 * nodes:       pre-allocated node array
 * write_at:    index in nodes where this subtree's root is placed
 * next_free:   next unallocated node slot; updated as descendants are
 *              reserved during recursive construction
 * inherited:   best prefix_idx from ancestor chain (UINT32_MAX if none)
 *
 * NOTE: prefix_idx stored in each node is the SORTED position (index
 * into the sorted prefix array), NOT the original caller index. The
 * caller is responsible for mapping sorted->original via orig_indices.
 *
 * See ARCHITECTURE.md §6.3 for node layout and traversal semantics.
 */
static void
trie_subtree_build(const cidr_prefix_t *sorted, size_t start, size_t end,
                   int bit_pos, int key_bits, size_t addr_len,
                   cidr_lctrie_node_t *nodes, uint32_t write_at,
                   uint32_t *next_free, uint32_t inherited)
{
	uint32_t best_prefix_idx;
	bool has_extending, diverges;
	int split_bit, skip;
	size_t ext_start, pivot, i;

	/*
	 * No prefixes in this range: create a dead leaf.
	 * The lookup will return the best match recorded from ancestors.
	 */
	if (start == end) {
		nodes[write_at].prefix_idx = UINT32_MAX;
		nodes[write_at].skip = 0;
		nodes[write_at].branch = 0;
		nodes[write_at].base = 0;
		nodes[write_at].pad[0] = 0;
		nodes[write_at].pad[1] = 0;
		return;
	}

	/*
	 * SAFETY: at most 2*original_count nodes are allocated.
	 * The recursive build must not exceed this bound. Each subtree
	 * uses at least 1 node. For a binary trie (branch=0 or 1),
	 * total nodes <= 2n+1 where n is prefix count.
	 * See ARCHITECTURE.md §6.3.
	 */

	/*
	 * Find the first bit position >= bit_pos where either:
	 *   a) a prefix ends (pfxlen == p), or
	 *   b) prefixes with pfxlen > p diverge at bit p.
	 */
	split_bit = bit_pos;
	best_prefix_idx = UINT32_MAX;
	diverges = false;
	for (int p = bit_pos; p < key_bits; p++) {
		bool ends_here = false;
		uint32_t end_idx = UINT32_MAX;

		for (i = start; i < end; i++) {
			if ((int)sorted[i].pfxlen == p) {
				if (!ends_here || (uint32_t)i < end_idx) {
					ends_here = true;
					end_idx = (uint32_t)i;
				}
			}
		}

		diverges = false;
		{
			int first_val = -1;

			for (i = start; i < end; i++) {
				if ((int)sorted[i].pfxlen <= p)
					continue;
				if (first_val < 0) {
					first_val = trie_addr_bit(
					    &sorted[i].addr, p, addr_len);
				} else if (trie_addr_bit(&sorted[i].addr, p,
				                         addr_len) !=
				           first_val) {
					diverges = true;
					break;
				}
			}
		}

		if (ends_here || diverges) {
			split_bit = p;
			if (ends_here)
				best_prefix_idx = end_idx;
			break;
		}
	}

	/*
	 * If no interesting position was found before key_bits, all
	 * prefixes in this range are identical in all significant bits.
	 * Create a leaf storing the prefix with the lowest sorted index.
	 *
	 * NOTE: This only triggers when the loop terminated without
	 * finding any prefix-end or divergence point. If divergence was
	 * found at split_bit with no prefix ending there, we continue
	 * to the normal node creation below.
	 */
	if (split_bit == bit_pos && best_prefix_idx == UINT32_MAX &&
	    !diverges) {
		uint32_t min_idx = UINT32_MAX;

		for (i = start; i < end; i++) {
			if ((uint32_t)i < min_idx)
				min_idx = (uint32_t)i;
		}
		best_prefix_idx = (min_idx != UINT32_MAX) ? min_idx : inherited;

		nodes[write_at].prefix_idx = best_prefix_idx;
		nodes[write_at].skip = 0;
		nodes[write_at].branch = 0;
		nodes[write_at].base = 0;
		nodes[write_at].pad[0] = 0;
		nodes[write_at].pad[1] = 0;
		return;
	}

	/*
	 * Determine if there are prefixes extending past split_bit.
	 * If so, the node is an interior node (branch=1); otherwise a leaf.
	 * NOTE: even if all extending prefixes agree on the split bit
	 * (all go one way), we still set branch=1 because the lookup
	 * must test this bit to distinguish between the extending path
	 * and the dead-end path.
	 */
	has_extending = false;
	ext_start = end;
	for (i = start; i < end; i++) {
		if ((int)sorted[i].pfxlen > split_bit) {
			has_extending = true;
			if (i < ext_start)
				ext_start = i;
			break;
		}
	}

	/*
	 * SAFETY: skip must fit in uint8_t. For IPv4 max skip is 32,
	 * for IPv6 max skip is 128. Both are <= 255.
	 */
	skip = split_bit - bit_pos;

	/* Write the node. */
	nodes[write_at].skip = (uint8_t)skip;
	nodes[write_at].branch = has_extending ? 1 : 0;
	nodes[write_at].prefix_idx =
	    (best_prefix_idx != UINT32_MAX) ? best_prefix_idx : inherited;
	nodes[write_at].pad[0] = 0;
	nodes[write_at].pad[1] = 0;

	if (!has_extending) {
		nodes[write_at].base = 0;
		return;
	}

	/*
	 * Interior node: reserve 2 child-root slots contiguously, then
	 * place descendants after them.
	 *
	 * See ARCHITECTURE.md §6.3: for branch=1, node has 2^1=2 children
	 * at nodes[base] and nodes[base+1]. The traversal indexes directly
	 * into those root slots, so deeper descendants must not displace the
	 * right child root.
	 */
	nodes[write_at].base = *next_free;
	*next_free += 2;

	/*
	 * Partition extending prefixes by bit value at split_bit.
	 * Since the array is sorted by network address, prefixes with
	 * bit=0 come before those with bit=1.
	 *
	 * NOTE: prefixes that ended at or before split_bit are not
	 * included in the child ranges -- they have been handled at
	 * this node (stored in prefix_idx or inherited).
	 */
	pivot = end;
	for (i = ext_start; i < end; i++) {
		if ((int)sorted[i].pfxlen <= split_bit)
			continue;
		if (trie_addr_bit(&sorted[i].addr, split_bit, addr_len) == 1) {
			pivot = i;
			break;
		}
	}

	/*
	 * The "inherited" prefix for children is the prefix stored at
	 * this node (if any), or the inherited prefix from above.
	 */
	{
		uint32_t child_inherited;

		child_inherited = (best_prefix_idx != UINT32_MAX)
		                      ? best_prefix_idx
		                      : inherited;

		trie_subtree_build(
		    sorted, ext_start, pivot, split_bit + 1, key_bits, addr_len,
		    nodes, nodes[write_at].base, next_free, child_inherited);
		trie_subtree_build(sorted, pivot, end, split_bit + 1, key_bits,
		                   addr_len, nodes, nodes[write_at].base + 1,
		                   next_free, child_inherited);
	}
}

/*
 * prefixes_tag_original_indices - record original input index in the
 * addr.family field before sorting.
 */
static void
prefixes_tag_original_indices(cidr_prefix_t *prefixes, size_t count)
{
	for (size_t i = 0; i < count; i++)
		prefix_order_tag_set(&prefixes[i], (uint32_t)i);
}

/*
 * prefixes_restore_family - restore the true address family after the
 * tag-based trie construction is complete.
 */
static void
prefixes_restore_family(cidr_prefix_t *prefixes, size_t count,
                        cidr_family_t family)
{
	for (size_t i = 0; i < count; i++)
		prefixes[i].addr.family = family;
}

/*
 * prefixes_resolve_duplicates - resolve duplicate prefixes in the sorted
 * array.
 *
 * After sorting by CIDR_SORT_NETWORK_ASC, identical prefixes (same
 * address bytes and same prefix length) appear consecutively. Sets the
 * order tag of every entry in a duplicate run to the tag of the first
 * entry (lowest original index per ARCHITECTURE.md §6.2).
 *
 * sorted:   prefix array sorted by CIDR_SORT_NETWORK_ASC
 * count:    number of prefixes
 * addr_len: address byte width (4 or 16)
 */
static void
prefixes_resolve_duplicates(cidr_prefix_t *sorted, size_t count,
                            size_t addr_len)
{
	size_t run_start, i;

	if (count < 2)
		return;

	run_start = 0;
	for (i = 1; i < count; i++) {
		const cidr_prefix_t *a = &sorted[i - 1];
		const cidr_prefix_t *b = &sorted[i];
		bool same;

		same = (a->pfxlen == b->pfxlen) &&
		       (memcmp(&a->addr.addr, &b->addr.addr, addr_len) == 0);

		if (!same) {
			uint32_t best_tag;

			best_tag = prefix_order_tag_get(&sorted[run_start]);
			for (size_t j = run_start + 1; j < i; j++)
				prefix_order_tag_set(&sorted[j], best_tag);
			run_start = i;
		}
	}

	if (run_start < count - 1) {
		uint32_t best_tag;

		best_tag = prefix_order_tag_get(&sorted[run_start]);
		for (size_t j = run_start + 1; j < count; j++)
			prefix_order_tag_set(&sorted[j], best_tag);
	}
}

/*
 * cidr_index_create - build a Patricia trie index from a prefix array.
 *
 * Validates inputs, copies and sorts the prefix array, builds a
 * basic binary Patricia trie with path compression, and returns the
 * index. Level compression is implemented in Phase 6.3.
 *
 * See ARCHITECTURE.md §6.2 for the full specification.
 */
cidr_err_t
cidr_index_create(const cidr_prefix_t *prefixes, size_t count,
                  cidr_index_t **out)
{
	cidr_index_t *idx = NULL;
	cidr_prefix_t *copy = NULL;
	cidr_lctrie_node_t *nodes = NULL;
	uint32_t *orig_map = NULL;
	cidr_family_t family;
	size_t addr_len, max_nodes;
	int key_bits;
	uint32_t node_count;
	cidr_err_t rc;

	if (prefixes == NULL || out == NULL)
		return CIDR_ERR_INVAL;
	if (count == 0)
		return CIDR_ERR_INVAL;
	if (count > (size_t)(UINT32_MAX - 1))
		return CIDR_ERR_INVAL;

	family = prefixes[0].addr.family;
	if (family == CIDR_AF_UNSPEC)
		return CIDR_ERR_INVAL;

	for (size_t i = 1; i < count; i++) {
		if (prefixes[i].addr.family == CIDR_AF_UNSPEC)
			return CIDR_ERR_INVAL;
		if (prefixes[i].addr.family != family)
			return CIDR_ERR_FAMILY;
	}

	addr_len = (family == CIDR_AF_INET) ? 4 : 16;
	key_bits = (family == CIDR_AF_INET) ? 32 : 128;

	/*
	 * Allocate the index struct.
	 * SAFETY: this is the only allocating function in the library.
	 * Use goto cleanup for all multi-allocation error paths per
	 * CODING_STANDARDS.md §2.3.
	 */
	rc = CIDR_ERR_NOMEM;
	idx = malloc(sizeof(cidr_index_t));
	if (idx == NULL)
		goto cleanup;

	/*
	 * Copy the prefix array. Original indices are stashed in the
	 * family field before sorting. After sorting and duplicate
	 * resolution, the tags are used to build the sorted->original
	 * index mapping.
	 *
	 * See ARCHITECTURE.md §6.2: "The prefix array is copied into
	 * the index -- the caller may free or modify their array after
	 * the call returns."
	 */
	copy = malloc(count * sizeof(cidr_prefix_t));
	if (copy == NULL)
		goto cleanup;

	orig_map = malloc(count * sizeof(uint32_t));
	if (orig_map == NULL)
		goto cleanup;

	for (size_t i = 0; i < count; i++)
		copy[i] = prefixes[i];
	prefixes_tag_original_indices(copy, count);

	/*
	 * Sort by CIDR_SORT_NETWORK_ASC. The radix sort does not use
	 * addr.family in its NETWORK_ASC sort key, so the stashed
	 * original-index tags survive intact.
	 */
	radix_sort_prefixes(copy, count, CIDR_SORT_NETWORK_ASC, family);

	/* Resolve duplicate prefixes: pick lowest original index. */
	prefixes_resolve_duplicates(copy, count, addr_len);

	/*
	 * Build the sorted->original index mapping from the tags.
	 * After duplicate resolution, all entries in a duplicate run
	 * have the same tag (lowest original index). The mapping
	 * sorted_position -> lowest_original_index is stored for the
	 * lookup function to translate node prefix_idx values back
	 * to the caller's input indices.
	 */
	for (size_t i = 0; i < count; i++)
		orig_map[i] = prefix_order_tag_get(&copy[i]);

	/*
	 * Restore the true address family now that tags are extracted.
	 * The copy array's family field must be valid for
	 * trie_prefix_matches() in the lookup path.
	 */
	prefixes_restore_family(copy, count, family);

	/*
	 * Allocate the node array. For a binary trie, the maximum
	 * node count is bounded by 2 * count + 1.
	 *
	 * SAFETY: the node array is a single contiguous allocation
	 * per the architecture. See ARCHITECTURE.md §6.3.
	 */
	max_nodes = 2 * count + 2;
	if (max_nodes > (size_t)(UINT32_MAX - 1))
		max_nodes = (size_t)(UINT32_MAX - 1);

	nodes = malloc(max_nodes * sizeof(cidr_lctrie_node_t));
	if (nodes == NULL)
		goto cleanup;

	/*
	 * Build the binary Patricia trie.
	 * Nodes store SORTED position indices (indexes into the copy
	 * array), not original caller indices. The orig_map array
	 * translates sorted positions back to original indices.
	 */
	node_count = 1;
	trie_subtree_build(copy, 0, count, 0, key_bits, addr_len, nodes, 0,
	                   &node_count, UINT32_MAX);

	/*
	 * Populate the index struct. Ownership of nodes, copy, orig_map,
	 * and idx transfers to the caller via *out. The caller must call
	 * cidr_index_destroy() to release them.
	 */
	idx->nodes = nodes;
	idx->node_count = node_count;
	idx->prefixes = copy;
	idx->prefix_count = count;
	idx->orig_indices = orig_map;
	idx->family = family;

	*out = idx;
	return CIDR_OK;

cleanup:
	free(copy);
	free(nodes);
	free(orig_map);
	free(idx);
	return rc;
}

/*
 * cidr_index_destroy - release all memory for a Patricia trie index.
 *
 * Frees the node array, the copied prefix array, the original-index
 * mapping, and the index struct itself. NULL-safe.
 *
 * See ARCHITECTURE.md §6.2.
 */
void
cidr_index_destroy(cidr_index_t *index)
{
	if (index == NULL)
		return;

	free(index->nodes);
	free(index->prefixes);
	free(index->orig_indices);
	free(index);
}

/*
 * cidr_index_lookup - longest-prefix match for each address in an array.
 *
 * Traverses the index trie for each address. The lookup advances skip
 * bits, extracts branch bits as a child index, and descends. At each
 * node with prefix_idx != UINT32_MAX, the stored prefix is verified
 * against the address using trie_prefix_matches(); if it matches, the
 * original index (via orig_indices) is recorded as the current best.
 * Traversal ends at a leaf node (branch == 0) or when the accumulated
 * bit position exceeds the key width.
 *
 * See ARCHITECTURE.md §6.3 for the traversal algorithm.
 */
cidr_err_t
cidr_index_lookup(const cidr_index_t *index, const cidr_addr_t *addrs,
                  size_t count, ssize_t *matches, cidr_err_t *errs)
{
	size_t addr_len;
	int key_bits, bit_pos, extracted;
	size_t i;
	const cidr_lctrie_node_t *node;

	if (index == NULL)
		return CIDR_ERR_INVAL;
	if (count == 0)
		return CIDR_OK;
	if (addrs == NULL || matches == NULL)
		return CIDR_ERR_INVAL;

	addr_len = (index->family == CIDR_AF_INET) ? 4 : 16;
	key_bits = (index->family == CIDR_AF_INET) ? 32 : 128;

	for (i = 0; i < count; i++) {
		ssize_t best;

		/* Validate input address. */
		if (addrs[i].family == CIDR_AF_UNSPEC) {
			if (errs != NULL)
				errs[i] = CIDR_ERR_INVAL;
			matches[i] = -1;
			continue;
		}
		if (addrs[i].family != index->family) {
			if (errs != NULL)
				errs[i] = CIDR_ERR_FAMILY;
			matches[i] = -1;
			continue;
		}

		/*
		 * SAFETY: node array bounds. The traversal uses
		 * node->base + extracted where extracted < 2^branch.
		 * For branch=0 traversal stops. For branch=1 extracted
		 * is 0 or 1. The node array was allocated for all valid
		 * paths during construction. Each branch node reserves
		 * contiguous child-root slots at nodes[base] and
		 * nodes[base + 1] before recursing, so the extracted
		 * index always lands on a valid child root.
		 *
		 * See ARCHITECTURE.md §6.3.
		 */
		best = -1;
		bit_pos = 0;
		node = &index->nodes[0];

		for (;;) {
			/*
			 * If this node stores a prefix, verify that the
			 * address actually matches it before recording.
			 *
			 * NOTE: prefix_idx is the SORTED position in
			 * the prefix copy array. We verify the match
			 * using mask-and-compare, then translate to the
			 * caller's original index via orig_indices.
			 */
			if (node->prefix_idx != UINT32_MAX) {
				const cidr_prefix_t *pfx;

				pfx = &index->prefixes[node->prefix_idx];
				if (trie_prefix_matches(pfx, &addrs[i],
				                        addr_len))
					best = (ssize_t)index->orig_indices
					           [node->prefix_idx];
			}

			if (node->branch == 0)
				break;

			bit_pos += node->skip;
			if (bit_pos + node->branch > key_bits)
				break;

			/*
			 * Extract branch bits from the address, then advance
			 * bit_pos by the CURRENT node's branch count before
			 * updating node. After the pointer update node->branch
			 * refers to the child, not the current node.
			 */
			extracted = 0;
			for (int b = 0; b < node->branch; b++)
				extracted =
				    (extracted << 1) |
				    trie_addr_bit(&addrs[i], bit_pos + b,
				                  addr_len);

			bit_pos += node->branch;
			node = &index->nodes[node->base + (uint32_t)extracted];
		}

		matches[i] = best;
		if (errs != NULL)
			errs[i] = CIDR_OK;
	}

	return CIDR_OK;
}
