/*
 * run_tests.c - C test binary entry point.
 * See TECH_STACK.md §6.2 for the test binary structure.
 */

#include "test_harness.h"

/*
 * test_addr.c -- Phase 2: address parsing and formatting tests.
 * See TESTING.md §3.1 for IPv4 parsing conformance tests.
 */
extern int test_ipv4_parse_valid(void);
extern int test_ipv4_parse_leading_zero(void);
extern int test_ipv4_parse_hex(void);
extern int test_ipv4_parse_out_of_range(void);
extern int test_ipv4_parse_wrong_count(void);
extern int test_ipv4_parse_empty(void);
extern int test_ipv4_parse_whitespace(void);
extern int test_ipv4_parse_trailing_chars(void);
extern int test_ipv4_parse_null(void);
extern int test_ipv6_parse_full_form(void);
extern int test_ipv6_parse_compressed(void);
extern int test_ipv6_parse_double_colon_once(void);
extern int test_ipv6_parse_uppercase_normalised(void);
extern int test_ipv6_parse_mixed_mapped(void);
extern int test_ipv6_parse_mixed_non_mapped(void);
extern int test_ipv6_parse_compatible_rejected(void);
extern int test_ipv6_parse_wrong_group_count(void);
extern int test_ipv6_parse_group_too_large(void);
extern int test_ipv6_parse_invalid_chars(void);
extern int test_ipv4_format_canonical(void);
extern int test_ipv4_format_roundtrip(void);
extern int test_ipv6_format_rfc5952_leading_zeros(void);
extern int test_ipv6_format_rfc5952_compress_longest(void);
extern int test_ipv6_format_rfc5952_no_compress_single(void);
extern int test_ipv6_format_rfc5952_tie_first_wins(void);
extern int test_ipv6_format_rfc5952_lowercase(void);
extern int test_ipv6_format_rfc5952_mixed_mapped(void);
extern int test_ipv6_format_roundtrip(void);
extern int test_addr_format_buffer_too_small(void);
extern int test_addr_to_v4_valid_extraction(void);
extern int test_addr_to_v4_error_distinction(void);
extern int test_addr_cmp_same_family(void);
extern int test_addr_cmp_family_mismatch(void);
extern int test_addr_cmp_unspec(void);

/*
 * test_prefix.c -- Phase 3: prefix construction, arithmetic, iteration,
 *                  and comparison tests.
 * See DEVELOPMENT.md §Phase 3 Tests for the full test catalogue.
 */
extern int test_prefix_parse_valid(void);
extern int test_prefix_parse_hostbits_rejected(void);
extern int test_prefix_parse_pfxlen_out_of_range(void);
extern int test_prefix_parse_null(void);
extern int test_prefix_from_host_zeroes_hostbits(void);
extern int test_prefix_from_host_pfxlen_out_of_range(void);
extern int test_prefix_format_canonical(void);
extern int test_prefix_format_buffer_too_small(void);
extern int test_prefix_format_roundtrip(void);
extern int test_prefix_broadcast_ipv4(void);
extern int test_prefix_broadcast_ipv6_family_error(void);
extern int test_prefix_mask_all_lengths(void);
extern int test_prefix_first_last_edge_cases(void);
extern int test_prefix_contains_inside(void);
extern int test_prefix_contains_outside(void);
extern int test_prefix_contains_null_out(void);
extern int test_prefix_contains_family_mismatch(void);
extern int test_prefix_overlaps_disjoint(void);
extern int test_prefix_overlaps_adjacent(void);
extern int test_prefix_overlaps_partial(void);
extern int test_prefix_overlaps_containment(void);
extern int test_prefix_overlaps_identical(void);
extern int test_prefix_supernet_chain(void);
extern int test_prefix_supernet_overflow(void);
extern int test_subnet_iter_correct_count(void);
extern int test_subnet_iter_ascending_order(void);
extern int test_subnet_iter_first_equals_parent_network(void);
extern int test_subnet_iter_early_termination(void);
extern int test_subnet_iter_done_out_not_modified(void);
extern int test_subnet_iter_pfxlen_invalid(void);
extern int test_prefix_cmp_ordering(void);
extern int test_prefix_cmp_equal(void);
extern int test_prefix_cmp_family_mismatch(void);

/*
 * test_bulk.c -- Phase 4: bulk engine tests.
 * See DEVELOPMENT.md §Phase 4 Tests for the test catalogue.
 */
extern int test_bulk_parse_empty(void);
extern int test_bulk_parse_single(void);
extern int test_bulk_parse_all_valid(void);
extern int test_bulk_parse_partial_failure(void);
extern int test_bulk_parse_null_errs(void);
extern int test_bulk_parse_null_element(void);
extern int test_bulk_parse_return_code_precedence(void);
extern int test_bulk_parse_full_batch_all_attempted(void);
extern int test_bulk_sort_empty(void);
extern int test_bulk_sort_single(void);
extern int test_bulk_sort_invalid_order(void);
extern int test_bulk_sort_network_asc_order(void);
extern int test_bulk_sort_network_asc_ipv6(void);
extern int test_bulk_sort_pfxlen_desc_order(void);
extern int test_bulk_sort_pfxlen_desc_stability(void);
extern int test_bulk_sort_null_prefixes(void);
extern int test_bulk_sort_family_mismatch(void);
extern int test_bulk_sort_unspec_family(void);

int tests_run = 0;
int tests_passed = 0;

int
main(void)
{
	RUN("test_ipv4_parse_valid", test_ipv4_parse_valid);
	RUN("test_ipv4_parse_leading_zero", test_ipv4_parse_leading_zero);
	RUN("test_ipv4_parse_hex", test_ipv4_parse_hex);
	RUN("test_ipv4_parse_out_of_range", test_ipv4_parse_out_of_range);
	RUN("test_ipv4_parse_wrong_count", test_ipv4_parse_wrong_count);
	RUN("test_ipv4_parse_empty", test_ipv4_parse_empty);
	RUN("test_ipv4_parse_whitespace", test_ipv4_parse_whitespace);
	RUN("test_ipv4_parse_trailing_chars", test_ipv4_parse_trailing_chars);
	RUN("test_ipv4_parse_null", test_ipv4_parse_null);
	RUN("test_ipv6_parse_full_form", test_ipv6_parse_full_form);
	RUN("test_ipv6_parse_compressed", test_ipv6_parse_compressed);
	RUN("test_ipv6_parse_double_colon_once",
	    test_ipv6_parse_double_colon_once);
	RUN("test_ipv6_parse_uppercase_normalised",
	    test_ipv6_parse_uppercase_normalised);
	RUN("test_ipv6_parse_mixed_mapped", test_ipv6_parse_mixed_mapped);
	RUN("test_ipv6_parse_mixed_non_mapped",
	    test_ipv6_parse_mixed_non_mapped);
	RUN("test_ipv6_parse_compatible_rejected",
	    test_ipv6_parse_compatible_rejected);
	RUN("test_ipv6_parse_wrong_group_count",
	    test_ipv6_parse_wrong_group_count);
	RUN("test_ipv6_parse_group_too_large", test_ipv6_parse_group_too_large);
	RUN("test_ipv6_parse_invalid_chars", test_ipv6_parse_invalid_chars);
	RUN("test_ipv4_format_canonical", test_ipv4_format_canonical);
	RUN("test_ipv4_format_roundtrip", test_ipv4_format_roundtrip);
	RUN("test_ipv6_format_rfc5952_leading_zeros",
	    test_ipv6_format_rfc5952_leading_zeros);
	RUN("test_ipv6_format_rfc5952_compress_longest",
	    test_ipv6_format_rfc5952_compress_longest);
	RUN("test_ipv6_format_rfc5952_no_compress_single",
	    test_ipv6_format_rfc5952_no_compress_single);
	RUN("test_ipv6_format_rfc5952_tie_first_wins",
	    test_ipv6_format_rfc5952_tie_first_wins);
	RUN("test_ipv6_format_rfc5952_lowercase",
	    test_ipv6_format_rfc5952_lowercase);
	RUN("test_ipv6_format_rfc5952_mixed_mapped",
	    test_ipv6_format_rfc5952_mixed_mapped);
	RUN("test_ipv6_format_roundtrip", test_ipv6_format_roundtrip);
	RUN("test_addr_format_buffer_too_small",
	    test_addr_format_buffer_too_small);
	RUN("test_addr_to_v4_valid_extraction",
	    test_addr_to_v4_valid_extraction);
	RUN("test_addr_to_v4_error_distinction",
	    test_addr_to_v4_error_distinction);
	RUN("test_addr_cmp_same_family", test_addr_cmp_same_family);
	RUN("test_addr_cmp_family_mismatch", test_addr_cmp_family_mismatch);
	RUN("test_addr_cmp_unspec", test_addr_cmp_unspec);

	RUN("test_prefix_parse_valid", test_prefix_parse_valid);
	RUN("test_prefix_parse_hostbits_rejected",
	    test_prefix_parse_hostbits_rejected);
	RUN("test_prefix_parse_pfxlen_out_of_range",
	    test_prefix_parse_pfxlen_out_of_range);
	RUN("test_prefix_parse_null", test_prefix_parse_null);
	RUN("test_prefix_from_host_zeroes_hostbits",
	    test_prefix_from_host_zeroes_hostbits);
	RUN("test_prefix_from_host_pfxlen_out_of_range",
	    test_prefix_from_host_pfxlen_out_of_range);
	RUN("test_prefix_format_canonical", test_prefix_format_canonical);
	RUN("test_prefix_format_buffer_too_small",
	    test_prefix_format_buffer_too_small);
	RUN("test_prefix_format_roundtrip", test_prefix_format_roundtrip);
	RUN("test_prefix_broadcast_ipv4", test_prefix_broadcast_ipv4);
	RUN("test_prefix_broadcast_ipv6_family_error",
	    test_prefix_broadcast_ipv6_family_error);
	RUN("test_prefix_mask_all_lengths", test_prefix_mask_all_lengths);
	RUN("test_prefix_first_last_edge_cases",
	    test_prefix_first_last_edge_cases);
	RUN("test_prefix_contains_inside", test_prefix_contains_inside);
	RUN("test_prefix_contains_outside", test_prefix_contains_outside);
	RUN("test_prefix_contains_null_out", test_prefix_contains_null_out);
	RUN("test_prefix_contains_family_mismatch",
	    test_prefix_contains_family_mismatch);
	RUN("test_prefix_overlaps_disjoint", test_prefix_overlaps_disjoint);
	RUN("test_prefix_overlaps_adjacent", test_prefix_overlaps_adjacent);
	RUN("test_prefix_overlaps_partial", test_prefix_overlaps_partial);
	RUN("test_prefix_overlaps_containment",
	    test_prefix_overlaps_containment);
	RUN("test_prefix_overlaps_identical", test_prefix_overlaps_identical);
	RUN("test_prefix_supernet_chain", test_prefix_supernet_chain);
	RUN("test_prefix_supernet_overflow", test_prefix_supernet_overflow);
	RUN("test_subnet_iter_correct_count", test_subnet_iter_correct_count);
	RUN("test_subnet_iter_ascending_order",
	    test_subnet_iter_ascending_order);
	RUN("test_subnet_iter_first_equals_parent_network",
	    test_subnet_iter_first_equals_parent_network);
	RUN("test_subnet_iter_early_termination",
	    test_subnet_iter_early_termination);
	RUN("test_subnet_iter_done_out_not_modified",
	    test_subnet_iter_done_out_not_modified);
	RUN("test_subnet_iter_pfxlen_invalid", test_subnet_iter_pfxlen_invalid);
	RUN("test_prefix_cmp_ordering", test_prefix_cmp_ordering);
	RUN("test_prefix_cmp_equal", test_prefix_cmp_equal);
	RUN("test_prefix_cmp_family_mismatch", test_prefix_cmp_family_mismatch);

	RUN("test_bulk_parse_empty", test_bulk_parse_empty);
	RUN("test_bulk_parse_single", test_bulk_parse_single);
	RUN("test_bulk_parse_all_valid", test_bulk_parse_all_valid);
	RUN("test_bulk_parse_partial_failure", test_bulk_parse_partial_failure);
	RUN("test_bulk_parse_null_errs", test_bulk_parse_null_errs);
	RUN("test_bulk_parse_null_element", test_bulk_parse_null_element);
	RUN("test_bulk_parse_return_code_precedence",
	    test_bulk_parse_return_code_precedence);
	RUN("test_bulk_parse_full_batch_all_attempted",
	    test_bulk_parse_full_batch_all_attempted);
	RUN("test_bulk_sort_empty", test_bulk_sort_empty);
	RUN("test_bulk_sort_single", test_bulk_sort_single);
	RUN("test_bulk_sort_invalid_order", test_bulk_sort_invalid_order);
	RUN("test_bulk_sort_network_asc_order",
	    test_bulk_sort_network_asc_order);
	RUN("test_bulk_sort_network_asc_ipv6", test_bulk_sort_network_asc_ipv6);
	RUN("test_bulk_sort_pfxlen_desc_order",
	    test_bulk_sort_pfxlen_desc_order);
	RUN("test_bulk_sort_pfxlen_desc_stability",
	    test_bulk_sort_pfxlen_desc_stability);
	RUN("test_bulk_sort_null_prefixes", test_bulk_sort_null_prefixes);
	RUN("test_bulk_sort_family_mismatch", test_bulk_sort_family_mismatch);
	RUN("test_bulk_sort_unspec_family", test_bulk_sort_unspec_family);

	fprintf(stderr, "%d/%d tests passed\n", tests_passed, tests_run);
	return (tests_run == tests_passed) ? 0 : 1;
}
