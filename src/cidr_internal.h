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
_Static_assert(
    1 == 1, "placeholder -- replaced in Phase 6 with cidr_lctrie_node_t == 12");

#endif /* CIDR_INTERNAL_H */
