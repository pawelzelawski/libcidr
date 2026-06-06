/*
 * cidr_classify.c - address classification against IANA special-purpose blocks.
 *
 * Contains the compile-time classification table encoding the IANA
 * special-purpose IPv4 and IPv6 address registry snapshot 2025-10-09.
 * Implements cidr_addr_classify() which performs a linear scan over the
 * table and returns a cidr_class_t bitmask.
 *
 * See ARCHITECTURE.md §7 for the classification specification,
 * ARCHITECTURE.md §7.2 for the flag registry and block tables.
 */

#include "../include/libcidr.h"
#include "cidr_internal.h"

/*
 * Classification table entry: address family, network address bytes
 * (16-byte array; IPv4 entries use only the first 4 bytes, remaining
 * bytes are zero), prefix length, and combined flag bitmask.
 */

/* SAFETY: This table is a compile-time constant (static const) placed in the
 * .rodata segment. No runtime mutation occurs. See CODING_STANDARDS.md §4.4
 * (no global mutable state) and ARCHITECTURE.md §1.4 (thread safety --
 * classification is thread-safe because the table is read-only). */
static const struct {
	cidr_family_t family;
	uint8_t prefix[16];
	uint8_t pfxlen;
	cidr_class_t flags;
} classify_table[] = {
    /*
     * IPv4 special-purpose blocks -- IANA snapshot 2025-10-09.
     * See ARCHITECTURE.md §7.2 for the full table specification.
     */
    {CIDR_AF_INET,
     {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     8,
     CIDR_CLASS_THIS_HOST},
    {CIDR_AF_INET,
     {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     32,
     CIDR_CLASS_THIS_HOST},
    {CIDR_AF_INET,
     {10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     8,
     CIDR_CLASS_PRIVATE},
    {CIDR_AF_INET,
     {100, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     10,
     CIDR_CLASS_SHARED},
    {CIDR_AF_INET,
     {127, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     8,
     CIDR_CLASS_LOOPBACK},
    {CIDR_AF_INET,
     {169, 254, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     16,
     CIDR_CLASS_LINK_LOCAL},
    {CIDR_AF_INET,
     {172, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     12,
     CIDR_CLASS_PRIVATE},
    {CIDR_AF_INET,
     {192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     24,
     CIDR_CLASS_IETF_RESERVED},
    {CIDR_AF_INET,
     {192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     29,
     CIDR_CLASS_IETF_RESERVED},
    {CIDR_AF_INET,
     {192, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     32,
     CIDR_CLASS_IETF_RESERVED},
    {CIDR_AF_INET,
     {192, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     32,
     CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_ANYCAST},
    {CIDR_AF_INET,
     {192, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     32,
     CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_ANYCAST},
    {CIDR_AF_INET,
     {192, 0, 0, 170, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     32,
     CIDR_CLASS_IETF_RESERVED},
    {CIDR_AF_INET,
     {192, 0, 0, 171, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     32,
     CIDR_CLASS_IETF_RESERVED},
    {CIDR_AF_INET,
     {192, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     24,
     CIDR_CLASS_DOCUMENTATION},
    {CIDR_AF_INET,
     {192, 31, 196, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     24,
     CIDR_CLASS_ANYCAST},
    {CIDR_AF_INET,
     {192, 52, 193, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     24,
     CIDR_CLASS_ANYCAST},
    /*
     * Terminated entry (IANA deprecated 2015-03). Retained per the
     * terminated-entry retention policy documented in ARCHITECTURE.md §7.2.
     */
    {CIDR_AF_INET,
     {192, 88, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     24,
     CIDR_CLASS_6TO4_RELAY},
    {CIDR_AF_INET,
     {192, 88, 99, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     32,
     CIDR_CLASS_6TO4_RELAY},
    {CIDR_AF_INET,
     {192, 168, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     16,
     CIDR_CLASS_PRIVATE},
    {CIDR_AF_INET,
     {192, 175, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     24,
     CIDR_CLASS_ANYCAST},
    {CIDR_AF_INET,
     {198, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     15,
     CIDR_CLASS_BENCHMARKING},
    {CIDR_AF_INET,
     {198, 51, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     24,
     CIDR_CLASS_DOCUMENTATION},
    {CIDR_AF_INET,
     {203, 0, 113, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     24,
     CIDR_CLASS_DOCUMENTATION},
    /*
     * Multicast block from RFC 1112, not RFC 6890. Per ARCHITECTURE.md §7.2,
     * the IANA special-purpose registry does not list multicast ranges,
     * but they are universally defined as multicast in RFC 1112 and
     * are included because treating them as globally routable unicast
     * would be incorrect for all callers.
     */
    {CIDR_AF_INET,
     {224, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     4,
     CIDR_CLASS_MULTICAST},
    {CIDR_AF_INET,
     {240, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     4,
     CIDR_CLASS_RESERVED},
    {CIDR_AF_INET,
     {255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     32,
     CIDR_CLASS_BROADCAST},

    /*
     * IPv6 special-purpose blocks -- IANA snapshot 2025-10-09.
     * See ARCHITECTURE.md §7.2 for the full table specification.
     */
    {CIDR_AF_INET6,
     {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     128,
     CIDR_CLASS_UNSPECIFIED},
    {CIDR_AF_INET6,
     {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
     128,
     CIDR_CLASS_LOOPBACK},
    {CIDR_AF_INET6,
     {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0},
     96,
     CIDR_CLASS_V4MAPPED},
    {CIDR_AF_INET6,
     {0, 100, 255, 155, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     96,
     CIDR_CLASS_V4TRANSLATED},
    {CIDR_AF_INET6,
     {0, 100, 255, 155, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     48,
     CIDR_CLASS_V4TRANSLATED},
    {CIDR_AF_INET6,
     {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     64,
     CIDR_CLASS_DISCARD},
    {CIDR_AF_INET6,
     {1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0},
     64,
     CIDR_CLASS_IETF_RESERVED},
    {CIDR_AF_INET6,
     {32, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     23,
     CIDR_CLASS_IETF_RESERVED},
    /*
     * 2001::/32 sub-block of 2001::/23. Inherits IETF_RESERVED from the
     * parent block and adds TEREDO.
     */
    {CIDR_AF_INET6,
     {32, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     32,
     CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_TEREDO},
    {CIDR_AF_INET6,
     {32, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
     128,
     CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_ANYCAST},
    {CIDR_AF_INET6,
     {32, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
     128,
     CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_ANYCAST},
    {CIDR_AF_INET6,
     {32, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3},
     128,
     CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_ANYCAST},
    {CIDR_AF_INET6,
     {32, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     48,
     CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_BENCHMARKING},
    {CIDR_AF_INET6,
     {32, 1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     32,
     CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_ANYCAST},
    {CIDR_AF_INET6,
     {32, 1, 0, 4, 1, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     48,
     CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_ANYCAST},
    /*
     * Terminated entry (previously ORCHID, terminated 2014-03). Retained
     * per the terminated-entry retention policy. See ARCHITECTURE.md §7.2.
     */
    {CIDR_AF_INET6,
     {32, 1, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     28,
     CIDR_CLASS_IETF_RESERVED},
    {CIDR_AF_INET6,
     {32, 1, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     28,
     CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_ORCHID},
    {CIDR_AF_INET6,
     {32, 1, 0, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     28,
     CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_ORCHID},
    {CIDR_AF_INET6,
     {32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     32,
     CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_DOCUMENTATION},
    {CIDR_AF_INET6,
     {32, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     16,
     CIDR_CLASS_6TO4},
    {CIDR_AF_INET6,
     {38, 32, 0, 79, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     48,
     CIDR_CLASS_ANYCAST},
    {CIDR_AF_INET6,
     {63, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     20,
     CIDR_CLASS_DOCUMENTATION},
    {CIDR_AF_INET6,
     {95, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     16,
     CIDR_CLASS_SRV6},
    {CIDR_AF_INET6,
     {252, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     7,
     CIDR_CLASS_UNIQUE_LOCAL},
    {CIDR_AF_INET6,
     {254, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     10,
     CIDR_CLASS_LINK_LOCAL},
    /*
     * Multicast block from RFC 4291, not RFC 6890. Per ARCHITECTURE.md §7.2,
     * the IPv6 multicast range is defined in RFC 4291 and is included
     * because treating it as globally routable unicast would be incorrect.
     */
    {CIDR_AF_INET6,
     {255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     8,
     CIDR_CLASS_MULTICAST},
};

/* Table element count, computed at compile time. */
#define CLASSIFY_TABLE_COUNT                                                   \
	(sizeof(classify_table) / sizeof(classify_table[0]))

/*
 * cidr_addr_classify - classify an address against the IANA special-purpose
 *                      registry.
 *
 * Performs a linear scan of the compile-time classification table
 * (ARCHITECTURE.md S.7.2) and returns a bitmask of all matching flags.
 * Multiple flags may be set when the address falls within overlapping blocks
 * (e.g. a 2001::/32 address matches both the /23 parent block and the /32
 * Teredo sub-block).
 *
 * If no special-purpose block matches, CIDR_CLASS_GLOBAL is returned.
 * CIDR_CLASS_GLOBAL is mutually exclusive with every other flag -- when
 * any special-purpose flag is set, CIDR_CLASS_GLOBAL is not set.
 * See ARCHITECTURE.md S.7.2 for the mutual exclusivity contract.
 *
 * addr: pointer to a valid cidr_addr_t (family must be CIDR_AF_INET or
 *       CIDR_AF_INET6)
 * out:  caller-provided cidr_class_t; on success receives the classification
 *       bitmask
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_INVAL if addr or out is NULL, or if addr->family is
 *   CIDR_AF_UNSPEC.
 *
 * Complexity: O(n) where n is the number of table entries (approximately 53,
 * a compile-time constant per ARCHITECTURE.md S.7.3). In practice O(1).
 * No allocation occurs.
 *
 * See ARCHITECTURE.md S.7.1 for the classification function specification.
 */
cidr_err_t
cidr_addr_classify(const cidr_addr_t *addr, cidr_class_t *out)
{
	cidr_class_t result = 0;
	size_t addr_len;
	const uint8_t *addr_bytes;

	if (addr == NULL || out == NULL)
		return CIDR_ERR_INVAL;
	if (addr->family == CIDR_AF_UNSPEC)
		return CIDR_ERR_INVAL;

	if (addr->family == CIDR_AF_INET) {
		addr_len = 4;
		addr_bytes = addr->addr.v4;
	} else {
		addr_len = 16;
		addr_bytes = addr->addr.v6;
	}

	/*
	 * SAFETY: CLASSIFY_TABLE_COUNT is a compile-time constant (53 entries).
	 * The linear scan is O(1) in practice per ARCHITECTURE.md S.7.3.
	 */
	for (size_t i = 0; i < CLASSIFY_TABLE_COUNT; i++) {
		uint8_t byte_mask;
		size_t byte;
		bool matches = true;

		/* Skip entries of a different address family. */
		if (classify_table[i].family != addr->family)
			continue;

		/*
		 * Mask-and-compare: for each byte of the address, apply the
		 * prefix mask derived from pfxlen and compare to the table
		 * entry's prefix byte. This is equivalent to
		 * cidr_prefix_contains() logic per ARCHITECTURE.md §4.3.5.
		 */
		for (byte = 0; byte < addr_len; byte++) {
			if (classify_table[i].pfxlen >= (byte + 1) * 8) {
				byte_mask = 0xFF;
			} else if (classify_table[i].pfxlen <= byte * 8) {
				byte_mask = 0x00;
			} else {
				int remaining =
				    classify_table[i].pfxlen - (int)(byte * 8);
				byte_mask = (uint8_t)(0xFF << (8 - remaining));
			}

			if ((addr_bytes[byte] & byte_mask) !=
			    classify_table[i].prefix[byte]) {
				matches = false;
				break;
			}
		}

		if (matches)
			result |= classify_table[i].flags;
	}

	/* SAFETY: CIDR_CLASS_GLOBAL is set only when no special-purpose block
	 * matched. It is mutually exclusive with all other flags, as documented
	 * in ARCHITECTURE.md S.7.2. */
	if (result == 0)
		result = CIDR_CLASS_GLOBAL;

	*out = result;
	return CIDR_OK;
}
