#ifndef CIDR_INTERNAL_H
#define CIDR_INTERNAL_H

/*
 * cidr_internal.h - internal definitions shared across libcidr source files.
 * Not installed. Not included by callers.
 * See ARCHITECTURE.md §3 for type design rationale and invariants.
 */

#include "../include/libcidr.h"

/* Compile-time layout checks. See ARCHITECTURE.md §3.2, §3.3.
 * These will be replaced with real assertions when the types are defined
 * in Phase 2. */
_Static_assert(1 == 1, "placeholder -- replaced in Phase 2");

#endif /* CIDR_INTERNAL_H */
