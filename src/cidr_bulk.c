/*
 * cidr_bulk.c - batch parse, containment, aggregation, and sort.
 *
 * Implements cidr_bulk_parse(), cidr_bulk_contains(),
 * cidr_bulk_aggregate(), and cidr_bulk_sort(). Contains the shared
 * in-place MSD radix sort engine.
 * See ARCHITECTURE.md §5 for the bulk engine specification.
 */

#include "../include/libcidr.h"
#include "cidr_internal.h"
