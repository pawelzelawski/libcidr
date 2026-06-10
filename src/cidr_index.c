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
 * Implements level compression on top of the path-compressed Patricia trie.
 * The final packed array follows the
 * precise DP recurrence in ARCHITECTURE.md §6.4.
 *
 * See ARCHITECTURE.md §6 for the Patricia trie specification.
 */

/*
 * SAFETY: This is the only source file that includes <stdlib.h> in the
 * library. malloc/free appear only in this file. Verify with:
 *   grep -n "malloc\|free" src/
 * See CODING_STANDARDS.md §2.1 and ARCHITECTURE.md §1.4.
 */
#ifdef CIDR_DEBUG
#include <assert.h>
#endif
#include <stdlib.h>
#include <string.h>

#include "../include/libcidr.h"
#include "cidr_internal.h"

#define CIDR_PAT_NONE UINT32_MAX
#define CIDR_LCTRIE_MAX_BRANCH 8

/*
 * cidr_pat_node_t - internal Patricia trie node.
 *
 * The LC-trie build first constructs a basic path-compressed binary trie.
 * The DP and packing passes then operate on this internal representation.
 *
 * left/right:    live child subtrees, or CIDR_PAT_NONE when absent
 * prefix_idx:    sorted-prefix index stored exactly at bit_position, or
 *                UINT32_MAX when no prefix terminates here
 * repr_idx:      any sorted-prefix index from this subtree; used to read the
 *                fixed path bits spanned by Patricia compression
 * bit_position:  cumulative tested bits from the root in the conceptual
 *                binary trie
 * optimal_branch: DP-selected LC branch factor for this subtree; 0 = leaf
 * dp_cost:       total packed node count for this subtree per the DP
 */
typedef struct {
	uint32_t left;
	uint32_t right;
	uint32_t prefix_idx;
	uint32_t repr_idx;
	size_t dp_cost;
	uint16_t bit_position;
	uint8_t optimal_branch;
} cidr_pat_node_t;

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
 * addr:     pointer to a valid cidr_addr_t
 * bit_pos:  bit position (0-based from MSB of byte 0)
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
 * pfx:      pointer to a valid cidr_prefix_t
 * addr:     pointer to a valid cidr_addr_t (same family)
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
 * slot_pattern_bit - extract one bit from a packed child-slot index.
 *
 * slot:         slot number in the range 0 .. (2^branch - 1)
 * branch:       number of tested bits in the slot pattern
 * rel_bit_pos:  0-based position within the pattern
 *
 * Returns the bit at rel_bit_pos, MSB first.
 */
static inline int
slot_pattern_bit(uint32_t slot, uint8_t branch, uint8_t rel_bit_pos)
{
	return (int)((slot >> (branch - rel_bit_pos - 1U)) & 1U);
}

/*
 * patricia_node_alloc - reserve one live Patricia node slot.
 *
 * Enforces the ARCHITECTURE.md §6.2 node-count limit during build rather than
 * relying only on the caller's prefix count. UINT32_MAX is reserved as the
 * "no prefix" sentinel, so the live Patricia node count must never exceed
 * UINT32_MAX - 1.
 *
 * next_free:  next unused node index in the caller-provided arena
 * node_limit: maximum representable live node count (UINT32_MAX - 1)
 * out_idx:    receives the reserved node index on success
 *
 * Returns true when one slot was reserved. Returns false when the next live
 * node would exceed node_limit.
 */
static bool
patricia_node_alloc(uint32_t *next_free, size_t node_limit, uint32_t *out_idx)
{
	/*
	 * SAFETY: UINT32_MAX is reserved throughout the trie build as the
	 * sentinel for "no prefix"/"no child". Stop before next_free can
	 * advance past UINT32_MAX - 1. See ARCHITECTURE.md §6.2.
	 */
	if ((size_t)*next_free >= node_limit)
		return false;

	*out_idx = *next_free;
	*next_free += 1;
	return true;
}

/*
 * patricia_subtree_build - recursively build a path-compressed binary trie.
 *
 * Builds one live Patricia subtree for the sorted prefix range [start, end).
 * No dead child nodes are materialized here; missing descendants are encoded
 * as CIDR_PAT_NONE and are expanded later by the LC packing pass.
 *
 * sorted:       prefix array sorted by CIDR_SORT_NETWORK_ASC
 * start, end:   subtree range [start, end)
 * bit_pos:      prefixes share bits [0, bit_pos)
 * key_bits:     total key width in bits (32 or 128)
 * addr_len:     address byte width (4 or 16)
 * nodes:        caller-allocated Patricia node arena
 * next_free:    next free slot in nodes; updated on each live node creation
 * node_limit:   maximum representable live Patricia node count
 * overflowed:   set true when the next live node would exceed node_limit
 *
 * Returns the index of the live subtree root, or CIDR_PAT_NONE when the range
 * is empty.
 *
 * See ARCHITECTURE.md §6.3 for the Patricia structure that the
 * LC-trie DP consumes.
 */
static uint32_t
patricia_subtree_build(const cidr_prefix_t *sorted, size_t start, size_t end,
                       int bit_pos, int key_bits, size_t addr_len,
                       cidr_pat_node_t *nodes, uint32_t *next_free,
                       size_t node_limit, bool *overflowed)
{
	uint32_t node_idx, best_prefix_idx;
	bool has_extending, diverges;
	int split_bit;
	size_t ext_start, pivot, i;
	cidr_pat_node_t *node;

	if (start == end)
		return CIDR_PAT_NONE;

	if (!patricia_node_alloc(next_free, node_limit, &node_idx)) {
		*overflowed = true;
		return CIDR_PAT_NONE;
	}

	node = &nodes[node_idx];
	node->left = CIDR_PAT_NONE;
	node->right = CIDR_PAT_NONE;
	node->prefix_idx = UINT32_MAX;
	node->repr_idx = (uint32_t)start;
	node->dp_cost = 0;
	node->bit_position = (uint16_t)bit_pos;
	node->optimal_branch = 0;

	split_bit = bit_pos;
	best_prefix_idx = UINT32_MAX;
	diverges = false;
	for (int p = bit_pos; p < key_bits; p++) {
		bool ends_here = false;
		uint32_t end_idx = UINT32_MAX;
		int first_val;

		for (i = start; i < end; i++) {
			if ((int)sorted[i].pfxlen == p) {
				if (!ends_here || (uint32_t)i < end_idx) {
					ends_here = true;
					end_idx = (uint32_t)i;
				}
			}
		}

		diverges = false;
		first_val = -1;
		for (i = start; i < end; i++) {
			if ((int)sorted[i].pfxlen <= p)
				continue;
			if (first_val < 0) {
				first_val =
				    trie_addr_bit(&sorted[i].addr, p, addr_len);
			} else if (trie_addr_bit(&sorted[i].addr, p,
			                         addr_len) != first_val) {
				diverges = true;
				break;
			}
		}

		if (ends_here || diverges) {
			split_bit = p;
			if (ends_here)
				best_prefix_idx = end_idx;
			break;
		}
	}

	if (split_bit == bit_pos && best_prefix_idx == UINT32_MAX &&
	    !diverges) {
		uint32_t min_idx;

		min_idx = (uint32_t)start;
		for (i = start + 1; i < end; i++) {
			if ((uint32_t)i < min_idx)
				min_idx = (uint32_t)i;
		}

		node->bit_position = (uint16_t)key_bits;
		node->prefix_idx = min_idx;
		node->repr_idx = min_idx;
		return node_idx;
	}

	node->bit_position = (uint16_t)split_bit;
	node->prefix_idx = best_prefix_idx;

	has_extending = false;
	ext_start = end;
	for (i = start; i < end; i++) {
		if ((int)sorted[i].pfxlen > split_bit) {
			has_extending = true;
			ext_start = i;
			break;
		}
	}

	if (!has_extending)
		return node_idx;

	pivot = end;
	for (i = ext_start; i < end; i++) {
		if (trie_addr_bit(&sorted[i].addr, split_bit, addr_len) == 1) {
			pivot = i;
			break;
		}
	}

	node->left = patricia_subtree_build(
	    sorted, ext_start, pivot, split_bit + 1, key_bits, addr_len, nodes,
	    next_free, node_limit, overflowed);
	if (*overflowed)
		return CIDR_PAT_NONE;
	node->right = patricia_subtree_build(sorted, pivot, end, split_bit + 1,
	                                     key_bits, addr_len, nodes,
	                                     next_free, node_limit, overflowed);
	if (*overflowed)
		return CIDR_PAT_NONE;
	return node_idx;
}

/*
 * patricia_slot_target - resolve one LC child slot against a Patricia node.
 *
 * The slot pattern is matched against the conceptual binary trie starting at
 * pat_idx.bit_position. Missing descendants yield CIDR_PAT_NONE. When the
 * pattern ends in the middle of a Patricia-compressed path, the target is the
 * Patricia node reached by that path; the packing pass will duplicate that
 * subtree once per referencing slot per ARCHITECTURE.md §6.4.3. If a slot
 * reaches a live Patricia node with a stored prefix but no more-specific child
 * for the remaining pattern bits, the slot resolves to that current node so
 * lookup can fall back to the nearest covering ancestor.
 *
 * nodes:       Patricia node arena
 * pat_idx:     root of the current live subtree
 * sorted:      sorted prefix array
 * addr_len:    address width in bytes (4 or 16)
 * branch:      candidate LC branch factor for pat_idx
 * slot:        slot number in 0 .. (2^branch - 1)
 *
 * Returns the target Patricia node for this slot, or CIDR_PAT_NONE when the
 * slot is dead.
 */
static uint32_t
patricia_slot_target(const cidr_pat_node_t *nodes, uint32_t pat_idx,
                     const cidr_prefix_t *sorted, size_t addr_len,
                     uint8_t branch, uint32_t slot)
{
	const cidr_pat_node_t *node;
	uint32_t child_idx;
	int abs_bit_pos;
	uint8_t rel_bit_pos;

	node = &nodes[pat_idx];
	if (node->left == CIDR_PAT_NONE && node->right == CIDR_PAT_NONE)
		return CIDR_PAT_NONE;

	child_idx =
	    (slot_pattern_bit(slot, branch, 0) == 0) ? node->left : node->right;
	if (child_idx == CIDR_PAT_NONE)
		return CIDR_PAT_NONE;

	abs_bit_pos = node->bit_position + 1;
	rel_bit_pos = 1;

	while (rel_bit_pos < branch) {
		const cidr_pat_node_t *child;

		child = &nodes[child_idx];

		while (rel_bit_pos < branch &&
		       abs_bit_pos < child->bit_position) {
			int required_bit;

			required_bit =
			    trie_addr_bit(&sorted[child->repr_idx].addr,
			                  abs_bit_pos, addr_len);
			if (slot_pattern_bit(slot, branch, rel_bit_pos) !=
			    required_bit)
				return CIDR_PAT_NONE;
			abs_bit_pos++;
			rel_bit_pos++;
		}

		if (rel_bit_pos == branch)
			break;

		if (child->left == CIDR_PAT_NONE &&
		    child->right == CIDR_PAT_NONE) {
			if (child->prefix_idx != UINT32_MAX)
				return child_idx;
			return CIDR_PAT_NONE;
		}

		child_idx = (slot_pattern_bit(slot, branch, rel_bit_pos) == 0)
		                ? child->left
		                : child->right;
		if (child_idx == CIDR_PAT_NONE) {
			if (child->prefix_idx != UINT32_MAX)
				return (uint32_t)(child - nodes);
			return CIDR_PAT_NONE;
		}

		abs_bit_pos++;
		rel_bit_pos++;
	}

	return child_idx;
}

/*
 * patricia_dp_compute - bottom-up LC-trie cost DP over the Patricia tree.
 *
 * Computes DP(T) and the selected branching factor for the live subtree
 * rooted at pat_idx. The cost function and tie-break rule are defined by
 * ARCHITECTURE.md §6.4.
 *
 * nodes:      Patricia node arena
 * pat_idx:    root of the live subtree to evaluate
 * sorted:     sorted prefix array
 * addr_len:   address width in bytes (4 or 16)
 * key_bits:   address width in bits (32 or 128)
 * node_limit: maximum representable packed node count (UINT32_MAX - 1)
 *
 * Returns true on success. Returns false when every candidate branch factor
 * overflows node_limit.
 */
static bool
patricia_dp_compute(cidr_pat_node_t *nodes, uint32_t pat_idx,
                    const cidr_prefix_t *sorted, size_t addr_len, int key_bits,
                    size_t node_limit)
{
	cidr_pat_node_t *node;
	size_t best_cost;
	uint8_t best_branch, max_branch;
	bool best_valid;
	int remaining_bits;

	node = &nodes[pat_idx];

	if (node->left != CIDR_PAT_NONE &&
	    !patricia_dp_compute(nodes, node->left, sorted, addr_len, key_bits,
	                         node_limit))
		return false;
	if (node->right != CIDR_PAT_NONE &&
	    !patricia_dp_compute(nodes, node->right, sorted, addr_len, key_bits,
	                         node_limit))
		return false;

	if (node->left == CIDR_PAT_NONE && node->right == CIDR_PAT_NONE) {
		node->dp_cost = 1;
		node->optimal_branch = 0;
		return true;
	}

	remaining_bits = key_bits - node->bit_position;
	max_branch = (remaining_bits < CIDR_LCTRIE_MAX_BRANCH)
	                 ? (uint8_t)remaining_bits
	                 : (uint8_t)CIDR_LCTRIE_MAX_BRANCH;

	best_cost = 0;
	best_branch = 1;
	best_valid = false;

	for (uint8_t branch = 1; branch <= max_branch; branch++) {
		size_t cost;
		uint32_t fanout;
		bool valid;

		cost = 1;
		fanout = 1U << branch;
		valid = true;

		for (uint32_t slot = 0; slot < fanout; slot++) {
			uint32_t target_idx;
			size_t slot_cost;

			target_idx = patricia_slot_target(
			    nodes, pat_idx, sorted, addr_len, branch, slot);
			slot_cost = (target_idx == CIDR_PAT_NONE)
			                ? 1
			                : nodes[target_idx].dp_cost;

			if (slot_cost > node_limit - cost) {
				valid = false;
				break;
			}
			cost += slot_cost;
		}

		if (!valid)
			continue;

		if (!best_valid || cost < best_cost ||
		    (cost == best_cost && branch > best_branch)) {
			best_cost = cost;
			best_branch = branch;
			best_valid = true;
		}
	}

	if (!best_valid)
		return false;

	node->dp_cost = best_cost;
	node->optimal_branch = best_branch;
	return true;
}

/*
 * lctrie_pack_dead_leaf - materialize one dead LC-trie child slot.
 *
 * Dead slots are explicit array entries because lookup computes child
 * addresses by direct indexing. See ARCHITECTURE.md §6.4.2.
 *
 * SAFETY: dead descendants use the sentinel contract:
 * branch == 0 and prefix_idx == UINT32_MAX. The lookup terminates at these
 * leaves without treating them as matches. See ARCHITECTURE.md §6.2, §6.4.
 */
static void
lctrie_pack_dead_leaf(cidr_lctrie_node_t *nodes, uint32_t node_idx)
{
	nodes[node_idx].base = 0;
	nodes[node_idx].prefix_idx = UINT32_MAX;
	nodes[node_idx].branch = 0;
	nodes[node_idx].skip = 0;
	nodes[node_idx].pad[0] = 0;
	nodes[node_idx].pad[1] = 0;
}

/*
 * lctrie_pack_subtree - emit one DP-optimised Patricia subtree into the
 * final packed LC-trie array.
 *
 * nodes:         Patricia node arena
 * pat_idx:       subtree to copy
 * sorted:        sorted prefix array
 * addr_len:      address width in bytes (4 or 16)
 * packed:        caller-allocated final LC node array
 * packed_idx:    slot where this subtree root must be written
 * next_free:     next unallocated packed slot after all reserved roots
 * parent_depth:  conceptual tested-bit depth after the parent consumed its
 *                branch bits; root uses 0
 *
 * The function duplicates live Patricia subtrees when multiple LC child slots
 * reference the same compressed path, as required by ARCHITECTURE.md §6.4.3.
 */
static void
lctrie_pack_subtree(const cidr_pat_node_t *nodes, uint32_t pat_idx,
                    const cidr_prefix_t *sorted, size_t addr_len,
                    cidr_lctrie_node_t *packed, uint32_t packed_idx,
                    uint32_t *next_free, int parent_depth)
{
	const cidr_pat_node_t *pat_node;
	cidr_lctrie_node_t *packed_node;
	uint8_t branch;

	pat_node = &nodes[pat_idx];
	packed_node = &packed[packed_idx];

	/*
	 * SAFETY: skip is recomputed from conceptual Patricia bit positions,
	 * not copied from the Patricia node. The formula matches
	 * ARCHITECTURE.md §6.4.4 exactly.
	 */
	packed_node->base = 0;
	packed_node->prefix_idx = pat_node->prefix_idx;
	packed_node->branch = pat_node->optimal_branch;
	packed_node->skip = (uint8_t)(pat_node->bit_position - parent_depth);
	packed_node->pad[0] = 0;
	packed_node->pad[1] = 0;

	branch = pat_node->optimal_branch;
	if (branch == 0)
		return;

	packed_node->base = *next_free;
	*next_free += (uint32_t)(1U << branch);

	for (uint32_t slot = 0; slot < (1U << branch); slot++) {
		uint32_t child_packed_idx, child_pat_idx;

		child_packed_idx = packed_node->base + slot;
		child_pat_idx = patricia_slot_target(nodes, pat_idx, sorted,
		                                     addr_len, branch, slot);

		/*
		 * SAFETY: when multiple slot patterns resolve to the same
		 * Patricia node, the packed array stores a full duplicate
		 * copy per slot. The LC-trie never aliases child slots to one
		 * shared subtree pointer. See ARCHITECTURE.md §6.4.3.
		 */
		if (child_pat_idx == CIDR_PAT_NONE) {
			lctrie_pack_dead_leaf(packed, child_packed_idx);
			continue;
		}

		lctrie_pack_subtree(nodes, child_pat_idx, sorted, addr_len,
		                    packed, child_packed_idx, next_free,
		                    pat_node->bit_position + branch);
	}
}

#ifdef CIDR_DEBUG
/*
 * lctrie_assert_invariants - validate the packed LC-trie after emission.
 *
 * Runs the ARCHITECTURE.md §6.4.6 post-packing assertions before the index is
 * returned to the caller.
 */
static void
lctrie_assert_invariants(const cidr_lctrie_node_t *nodes, uint32_t node_count,
                         size_t prefix_count)
{
	for (uint32_t i = 0; i < node_count; i++) {
		const cidr_lctrie_node_t *node;

		node = &nodes[i];
		assert(node->prefix_idx == UINT32_MAX ||
		       node->prefix_idx < prefix_count);

		if (node->branch == 0) {
			if (node->prefix_idx == UINT32_MAX) {
				assert(node->base == 0);
				assert(node->skip == 0);
			}
			continue;
		}

		assert(node->branch <= CIDR_LCTRIE_MAX_BRANCH);
		assert(node->base < node_count);
		assert((size_t)node->base + (1U << node->branch) <= node_count);
	}
}
#endif

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
		const cidr_prefix_t *a, *b;
		bool same;

		a = &sorted[i - 1];
		b = &sorted[i];
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
 * Validates inputs, copies and sorts the prefix array, builds a basic
 * path-compressed Patricia trie, runs the LC-trie DP from
 * ARCHITECTURE.md §6.4, and packs the result into one contiguous node
 * allocation. The copied prefix array and sorted->original index mapping
 * remain owned by the returned index.
 *
 * See ARCHITECTURE.md §6.2, §6.3, §6.4 for the full specification.
 */
cidr_err_t
cidr_index_create(const cidr_prefix_t *prefixes, size_t count,
                  cidr_index_t **out)
{
	cidr_index_t *idx;
	cidr_prefix_t *copy;
	cidr_lctrie_node_t *nodes;
	cidr_pat_node_t *pat_nodes;
	uint32_t *orig_map;
	cidr_family_t family;
	size_t addr_len, max_pat_nodes, node_limit;
	int key_bits;
	uint32_t pat_root, pat_count, packed_next;
	cidr_err_t rc;
	bool pat_overflowed;

	idx = NULL;
	copy = NULL;
	nodes = NULL;
	pat_nodes = NULL;
	orig_map = NULL;

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
	node_limit = (size_t)(UINT32_MAX - 1);

	/*
	 * Allocate the index struct.
	 * SAFETY: this is the only allocating function in the library.
	 * Use goto cleanup for all multi-allocation error paths per
	 * CODING_STANDARDS.md §2.2.
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
	 * See ARCHITECTURE.md §6.2: the caller may free or modify their
	 * prefix array immediately after cidr_index_create() returns.
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

	radix_sort_prefixes(copy, count, CIDR_SORT_NETWORK_ASC, family);
	prefixes_resolve_duplicates(copy, count, addr_len);

	for (size_t i = 0; i < count; i++)
		orig_map[i] = prefix_order_tag_get(&copy[i]);

	prefixes_restore_family(copy, count, family);

	max_pat_nodes = 2 * count + 2;
	if (max_pat_nodes > node_limit)
		max_pat_nodes = node_limit;

	pat_nodes = malloc(max_pat_nodes * sizeof(cidr_pat_node_t));
	if (pat_nodes == NULL)
		goto cleanup;

	pat_count = 0;
	pat_overflowed = false;
	pat_root = patricia_subtree_build(copy, 0, count, 0, key_bits, addr_len,
	                                  pat_nodes, &pat_count, node_limit,
	                                  &pat_overflowed);
	if (pat_overflowed || pat_root == CIDR_PAT_NONE) {
		rc = CIDR_ERR_INVAL;
		goto cleanup;
	}

	if (!patricia_dp_compute(pat_nodes, pat_root, copy, addr_len, key_bits,
	                         node_limit)) {
		rc = CIDR_ERR_INVAL;
		goto cleanup;
	}

	if (pat_nodes[pat_root].dp_cost > node_limit) {
		rc = CIDR_ERR_INVAL;
		goto cleanup;
	}

	/*
	 * SAFETY: the final LC-trie is one contiguous allocation sized from
	 * the DP's total node count. No per-subtree allocation occurs during
	 * packing. See ARCHITECTURE.md §6.3, §6.4.
	 */
	nodes =
	    malloc(pat_nodes[pat_root].dp_cost * sizeof(cidr_lctrie_node_t));
	if (nodes == NULL)
		goto cleanup;

	packed_next = 1;
	lctrie_pack_subtree(pat_nodes, pat_root, copy, addr_len, nodes, 0,
	                    &packed_next, 0);

	if ((size_t)packed_next != pat_nodes[pat_root].dp_cost) {
		rc = CIDR_ERR_INVAL;
		goto cleanup;
	}

#ifdef CIDR_DEBUG
	lctrie_assert_invariants(nodes, packed_next, count);
#endif

	/*
	 * Ownership/lifetime: nodes, copy, and orig_map transfer into idx.
	 * The caller receives idx through *out and must release all three via
	 * cidr_index_destroy().
	 */
	idx->nodes = nodes;
	idx->node_count = packed_next;
	idx->prefixes = copy;
	idx->prefix_count = count;
	idx->orig_indices = orig_map;
	idx->family = family;

	free(pat_nodes);

	*out = idx;
	return CIDR_OK;

cleanup:
	free(copy);
	free(nodes);
	free(pat_nodes);
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
 * Validates the full input batch before any traversal. If any address has
 * family CIDR_AF_UNSPEC, returns CIDR_ERR_INVAL with no output written. If
 * any address family does not match the index family, returns
 * CIDR_ERR_FAMILY with no output written. When validation succeeds,
 * traverses the packed LC-trie for each address. The traversal advances
 * skip bits, extracts branch bits as a direct child-slot index, and
 * descends to nodes[base + index]. At every node with prefix_idx !=
 * UINT32_MAX, the prefix is verified against the queried address and then
 * recorded as the current best match.
 *
 * See ARCHITECTURE.md §6.3 for lookup semantics and ARCHITECTURE.md §6.4
 * for the packed-array invariants relied upon by traversal.
 */
cidr_err_t
cidr_index_lookup(const cidr_index_t *index, const cidr_addr_t *addrs,
                  size_t count, ssize_t *matches, cidr_err_t *errs)
{
	size_t addr_len;
	int key_bits;

	if (index == NULL)
		return CIDR_ERR_INVAL;
	if (count == 0)
		return CIDR_OK;
	if (addrs == NULL || matches == NULL)
		return CIDR_ERR_INVAL;

	/*
	 * SAFETY: structural input errors fail the whole call with no side
	 * effects. Validate the entire address batch before touching matches
	 * or errs so the caller never observes partially written output.
	 * See ARCHITECTURE.md §6.2.
	 */
	for (size_t i = 0; i < count; i++) {
		if (addrs[i].family == CIDR_AF_UNSPEC)
			return CIDR_ERR_INVAL;
		if (addrs[i].family != index->family)
			return CIDR_ERR_FAMILY;
	}

	addr_len = (index->family == CIDR_AF_INET) ? 4 : 16;
	key_bits = (index->family == CIDR_AF_INET) ? 32 : 128;

	for (size_t i = 0; i < count; i++) {
		ssize_t best;
		int bit_pos;
		const cidr_lctrie_node_t *node;

		best = -1;
		bit_pos = 0;
		node = &index->nodes[0];

		for (;;) {
			if (node->prefix_idx != UINT32_MAX) {
				const cidr_prefix_t *pfx;

				/*
				 * NOTE: prefix_idx stores the sorted-prefix
				 * position in index->prefixes. After a match is
				 * confirmed, orig_indices translates it back to
				 * the caller's original input index.
				 */
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
			 * LC-trie traversal: advance skip bits, extract branch
			 * bits as index, descend to nodes[base + index]. Record
			 * the best match at every interior node with prefix_idx
			 * != UINT32_MAX. See ARCHITECTURE.md §6.3.
			 *
			 * SAFETY: the DP and debug invariant pass guarantee
			 * that every interior node has 2^branch consecutive
			 * children starting at base, so base + extracted always
			 * lands on a valid child slot within the array.
			 */
			{
				uint32_t extracted;

				extracted = 0;
				for (uint8_t b = 0; b < node->branch; b++)
					extracted = (extracted << 1) |
					            (uint32_t)trie_addr_bit(
					                &addrs[i], bit_pos + b,
					                addr_len);

				bit_pos += node->branch;
				node = &index->nodes[node->base + extracted];
			}
		}

		matches[i] = best;
		if (errs != NULL)
			errs[i] = CIDR_OK;
	}

	return CIDR_OK;
}
