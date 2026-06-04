/*
 * cidr_index.c - high-performance prefix index: LC-trie
 *                (Level-Compressed Patricia trie).
 *
 * cidr_index_create(): builds array-packed LC-trie from caller-provided
 *   prefix array. Only allocating function in the library. O(n * W).
 * cidr_index_destroy(): releases all trie memory. NULL-safe.
 * cidr_index_lookup(): longest-prefix match for each address in
 *   caller-provided array.
 * See ARCHITECTURE.md §6 for the Patricia trie specification.
 */

#include "../include/libcidr.h"
#include "cidr_internal.h"
