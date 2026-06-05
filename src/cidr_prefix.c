/*
 * cidr_prefix.c - prefix construction, prefix arithmetic operations,
 *                 and prefix comparison.
 *
 * cidr_prefix_parse():  strict CIDR prefix parse (rejects host bits).
 * cidr_prefix_from_host(): explicit host-to-network (zeros host bits).
 *
 * See ARCHITECTURE.md §4.3 for prefix arithmetic specification.
 * See ARCHITECTURE.md §4.1.4 for the CIDR prefix parsing contract.
 */

#include <string.h>

#include "../include/libcidr.h"
#include "cidr_internal.h"

/*
 * prefix_pfxlen_max - return the maximum prefix length for a given
 *                     address family.
 *
 * Returns 32 for CIDR_AF_INET, 128 for CIDR_AF_INET6.
 * Caller must ensure family is valid (not CIDR_AF_UNSPEC).
 * See ARCHITECTURE.md §3.3.
 */
static uint8_t
prefix_pfxlen_max(cidr_family_t family)
{
	if (family == CIDR_AF_INET)
		return 32;
	return 128;
}

/*
 * prefix_mask_apply - zero host bits in a cidr_addr_t for the given
 *                     prefix length.
 *
 * Modifies addr in place. Bytes fully covered by the prefix are
 * preserved. The partial byte (if any) has its host bits (bottom
 * (8 - rem) bits) zeroed. Bytes beyond the prefix are zeroed entirely.
 *
 * pfxlen: prefix length (caller must validate range per family)
 * addr:   address to modify in place; family field determines byte width
 *
 * SAFETY: pfxlen must be in the valid range for addr->family. Family
 * must be CIDR_AF_INET or CIDR_AF_INET6 (not CIDR_AF_UNSPEC). These
 * invariants are the caller's responsibility. The byte-level operations
 * are bounded by addr_len which is derived from the validated family.
 *
 * See ARCHITECTURE.md §3.3 for the host-bits-zero invariant.
 */
static void
prefix_mask_apply(uint8_t pfxlen, cidr_addr_t *addr)
{
	uint8_t *bytes;
	size_t addr_len;
	size_t full_bytes;
	int rem;

	if (addr->family == CIDR_AF_INET) {
		bytes = addr->addr.v4;
		addr_len = 4;
	} else {
		bytes = addr->addr.v6;
		addr_len = 16;
	}

	full_bytes = (size_t)(pfxlen / 8);
	rem = pfxlen % 8;

	if (full_bytes < addr_len) {
		if (rem > 0) {
			/*
			 * Preserve top rem bits, zero bottom (8-rem) bits
			 * in the partial byte.
			 */
			bytes[full_bytes] &= (uint8_t)(0xFF << (8 - rem));
			for (size_t i = full_bytes + 1; i < addr_len; i++)
				bytes[i] = 0;
		} else {
			for (size_t i = full_bytes; i < addr_len; i++)
				bytes[i] = 0;
		}
	}
}

/*
 * parse_pfxlen - parse a decimal prefix length string.
 *
 * Parses a null-terminated decimal string into a uint8_t value.
 * Rejects empty strings, non-digit characters, and values exceeding 128
 * (the maximum prefix length for any address family).
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_PFXLEN on any malformed input or overflow.
 */
static cidr_err_t
parse_pfxlen(const char *s, uint8_t *out)
{
	int val = 0;

	if (*s == '\0')
		return CIDR_ERR_PFXLEN;

	while (*s >= '0' && *s <= '9') {
		val = val * 10 + (*s - '0');
		if (val > 128)
			return CIDR_ERR_PFXLEN;
		s++;
	}

	if (*s != '\0')
		return CIDR_ERR_PFXLEN;

	*out = (uint8_t)val;
	return CIDR_OK;
}

/*
 * cidr_prefix_parse - parse a CIDR prefix from text (strict).
 *
 * Input must be "address/prefixlen". The address portion is parsed
 * by cidr_addr_parse(). The prefix length is parsed as a decimal
 * integer. If the address has any host bits set, CIDR_ERR_HOSTBITS
 * is returned.
 *
 * src:  null-terminated CIDR string
 * out:  caller-provided cidr_prefix_t; on failure out->addr.family
 *       is written as CIDR_AF_UNSPEC
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_INVAL if src or out is NULL.
 * Returns CIDR_ERR_PARSE if the address portion does not parse.
 * Returns CIDR_ERR_PFXLEN if prefix length is out of range for the
 *   address family.
 * Returns CIDR_ERR_HOSTBITS if the address has host bits set.
 *
 * No allocation occurs.
 *
 * See ARCHITECTURE.md §4.1.4.
 */
cidr_err_t
cidr_prefix_parse(const char *src, cidr_prefix_t *out)
{
	const char *slash;
	const char *p;
	char addr_buf[CIDR_ADDR_STR_MAX];
	cidr_addr_t parsed_addr;
	cidr_err_t rc;
	uint8_t pfxlen;
	size_t addr_len;
	size_t addr_part_len;
	uint8_t saved_bytes[16];
	int cmp;

	if (src == NULL || out == NULL)
		return CIDR_ERR_INVAL;

	/* Find the last '/' in the input string. */
	slash = NULL;
	for (p = src; *p != '\0'; p++) {
		if (*p == '/')
			slash = p;
	}

	if (slash == NULL || slash == src)
		return CIDR_ERR_PARSE;

	/* Extract the address portion (before the last '/'). */
	addr_part_len = (size_t)(slash - src);
	if (addr_part_len >= CIDR_ADDR_STR_MAX)
		return CIDR_ERR_PARSE;

	for (size_t i = 0; i < addr_part_len; i++)
		addr_buf[i] = src[i];
	addr_buf[addr_part_len] = '\0';

	/* Parse the address. */
	rc = cidr_addr_parse(addr_buf, &parsed_addr);
	if (rc != CIDR_OK)
		return rc;

	/* Parse the prefix length. */
	rc = parse_pfxlen(slash + 1, &pfxlen);
	if (rc != CIDR_OK)
		return rc;

	/* Validate pfxlen range per family. */
	if (pfxlen > prefix_pfxlen_max(parsed_addr.family))
		return CIDR_ERR_PFXLEN;

	/*
	 * Save original address bytes for host-bits comparison.
	 * addr_len is derived from validated family, so saved_bytes[]
	 * (size 16) is always large enough.
	 */
	if (parsed_addr.family == CIDR_AF_INET) {
		addr_len = 4;
		for (size_t i = 0; i < addr_len; i++)
			saved_bytes[i] = parsed_addr.addr.v4[i];
	} else {
		addr_len = 16;
		for (size_t i = 0; i < addr_len; i++)
			saved_bytes[i] = parsed_addr.addr.v6[i];
	}

	/* Apply prefix mask to zero host bits. */
	prefix_mask_apply(pfxlen, &parsed_addr);

	/*
	 * SAFETY: host-bits-zero invariant. If the original address
	 * differs from the masked address after applying the prefix
	 * mask, host bits were set in the input and must be rejected.
	 * See ARCHITECTURE.md §3.3.
	 */
	if (parsed_addr.family == CIDR_AF_INET)
		cmp = memcmp(saved_bytes, parsed_addr.addr.v4, addr_len);
	else
		cmp = memcmp(saved_bytes, parsed_addr.addr.v6, addr_len);
	if (cmp != 0)
		return CIDR_ERR_HOSTBITS;

	/* Write output. */
	out->addr = parsed_addr;
	out->pfxlen = pfxlen;
	return CIDR_OK;
}

/*
 * cidr_prefix_from_host - construct a prefix from a host address.
 *
 * Accepts a host address and a prefix length. Computes the network
 * address by zeroing host bits. The zeroing is explicit -- the function
 * name documents the operation.
 *
 * This function must not return CIDR_ERR_HOSTBITS -- zeroing host bits
 * is the explicit contract.
 *
 * addr:   pointer to a valid cidr_addr_t (family must be CIDR_AF_INET
 *         or CIDR_AF_INET6)
 * pfxlen: prefix length; validated against the address family range
 * out:    caller-provided cidr_prefix_t; on success addr.family matches
 *         addr->family and host bits are zeroed
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_INVAL if addr or out is NULL, or if addr->family is
 *   CIDR_AF_UNSPEC.
 * Returns CIDR_ERR_PFXLEN if pfxlen is out of range for the address
 *   family.
 *
 * No allocation occurs.
 *
 * See ARCHITECTURE.md §4.1.4.
 */
cidr_err_t
cidr_prefix_from_host(const cidr_addr_t *addr, uint8_t pfxlen,
                      cidr_prefix_t *out)
{
	if (addr == NULL || out == NULL)
		return CIDR_ERR_INVAL;
	if (addr->family == CIDR_AF_UNSPEC)
		return CIDR_ERR_INVAL;

	/* Validate pfxlen range per family. */
	if (pfxlen > prefix_pfxlen_max(addr->family))
		return CIDR_ERR_PFXLEN;

	/*
	 * Copy the address into out, then zero host bits in place.
	 * CIDR_ERR_HOSTBITS must not be returned -- the function name
	 * documents that zeroing occurs. See ARCHITECTURE.md §4.1.4.
	 */
	out->addr.family = addr->family;
	if (addr->family == CIDR_AF_INET) {
		for (size_t i = 0; i < 4; i++)
			out->addr.addr.v4[i] = addr->addr.v4[i];
	} else {
		for (size_t i = 0; i < 16; i++)
			out->addr.addr.v6[i] = addr->addr.v6[i];
	}

	prefix_mask_apply(pfxlen, &out->addr);

	out->pfxlen = pfxlen;
	return CIDR_OK;
}
