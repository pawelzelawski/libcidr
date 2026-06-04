/*
 * cidr_classify.c - address classification against IANA special-purpose blocks.
 *
 * cidr_addr_classify() performs a linear scan over the compile-time
 * classification table and returns a cidr_class_t bitmask.
 * See ARCHITECTURE.md §7 for the classification specification.
 */

#include "../include/libcidr.h"
#include "cidr_internal.h"
