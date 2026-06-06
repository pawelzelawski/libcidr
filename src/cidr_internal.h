#ifndef CIDR_INTERNAL_H
#define CIDR_INTERNAL_H

/*
 * cidr_internal.h - internal definitions shared across libcidr source files.
 * Not installed. Not included by callers.
 * See ARCHITECTURE.md §3 for type design rationale and invariants.
 */

#include "../include/libcidr.h"

/* Compile-time layout checks. See ARCHITECTURE.md §3.2, §3.3, §6.3. */
_Static_assert(
    sizeof(cidr_addr_t) == 20,
    "cidr_addr_t size changed -- check family enum size and union padding");
_Static_assert(
    sizeof(cidr_prefix_t) == 24,
    "cidr_prefix_t size changed -- check addr + pfxlen + trailing padding");

/* LC-trie node. See ARCHITECTURE.md §6.3 for field semantics. */
typedef struct {
	uint32_t base;
	uint32_t prefix_idx;
	uint8_t branch;
	uint8_t skip;
	uint8_t pad[2];
} cidr_lctrie_node_t;

_Static_assert(
    sizeof(cidr_lctrie_node_t) == 12,
    "cidr_lctrie_node_t size changed -- update ARCHITECTURE.md §6.3");

/* Patricia trie index (opaque to callers).
 * See ARCHITECTURE.md §6 for full specification. */
struct cidr_index {
	cidr_lctrie_node_t *nodes;
	uint32_t node_count;
	cidr_prefix_t *prefixes;
	size_t prefix_count;
	uint32_t *orig_indices;
	cidr_family_t family;
};

/*
 * radix_sort_prefixes -- in-place MSD radix sort shared by cidr_bulk_sort()
 * and cidr_index_create(). No allocation; all workspace is on the stack.
 * Caller must ensure count > 0 and all prefixes share one valid family.
 * No parameter validation. See ARCHITECTURE.md §5.4.
 */
void radix_sort_prefixes(cidr_prefix_t *prefixes, size_t count,
                         cidr_sort_order_t order, cidr_family_t family);

#endif /* CIDR_INTERNAL_H */
