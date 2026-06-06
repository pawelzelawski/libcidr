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

/*
 * cidr_lctrie_node_t - Level-Compressed trie node.
 *
 * Each node in the array-packed LC-trie. Path compression (skip) collapses
 * single-child chains; level compression (branch) enables multi-bit branching.
 * See ARCHITECTURE.md §6.3 for the node layout specification.
 *
 * base:       index of first child in the contiguous node array; undefined
 *             when branch == 0
 * prefix_idx: index into the copied prefix array, or UINT32_MAX for no prefix
 * branch:     branching factor: the node has 2^branch children; 0 = leaf
 * skip:       number of bits to advance past without branching
 * pad[2]:     alignment padding to reach 12 bytes
 */
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

/*
 * cidr_index - Patricia trie index (opaque to callers).
 *
 * The full struct definition is visible only internally. Callers see the
 * opaque typedef struct cidr_index cidr_index_t declared in libcidr.h.
 * See ARCHITECTURE.md §6 for the index specification.
 *
 * nodes:         contiguous LC-trie node array (heap-allocated, owned)
 * node_count:    number of nodes in nodes
 * prefixes:      copy of the caller-provided prefix array (heap-allocated,
 *                owned); caller may free their array after index_create
 *                returns
 * prefix_count:  number of prefixes
 * family:        CIDR_AF_INET or CIDR_AF_INET6 -- all prefixes share one
 *                family; mixed-family indices are not allowed
 */
struct cidr_index {
	cidr_lctrie_node_t *nodes;
	uint32_t node_count;
	cidr_prefix_t *prefixes;
	size_t prefix_count;
	cidr_family_t family;
};

/*
 * radix_sort_prefixes - in-place MSD radix sort for prefix arrays.
 *
 * Sorts the prefix array in place using the shared in-place MSD radix sort
 * engine. Used internally by cidr_bulk_sort() and cidr_index_create().
 * No allocation occurs -- all workspace is on the stack.
 *
 * prefixes: caller-provided prefix array; modified in place
 * count:    number of entries in prefixes (must be > 0)
 * order:    CIDR_SORT_NETWORK_ASC or CIDR_SORT_PFXLEN_DESC
 *
 * The caller must ensure that all prefixes have the same valid address
 * family (CIDR_AF_INET or CIDR_AF_INET6) and that count > 0. No parameter
 * validation is performed by this function -- callers are responsible for
 * checking preconditions.
 *
 * See ARCHITECTURE.md §5.4, §5.5.
 */
void radix_sort_prefixes(cidr_prefix_t *prefixes, size_t count,
                         cidr_sort_order_t order, cidr_family_t family);

#endif /* CIDR_INTERNAL_H */
