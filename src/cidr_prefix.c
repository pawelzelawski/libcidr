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

/*
 * cidr_prefix_format - format a CIDR prefix as canonical text.
 *
 * Writes the canonical CIDR string "address/prefixlen" into buf.
 * Delegates address formatting to cidr_addr_format() and appends
 * "/<prefixlen>" as a decimal integer with no leading zeros.
 *
 * prefix: pointer to a valid cidr_prefix_t
 * buf:    caller-provided output buffer of size len
 * len:    must be at least CIDR_PREFIX_STR_MAX (50)
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_INVAL if prefix or buf is NULL, if
 *   prefix->addr.family is CIDR_AF_UNSPEC, or if len < CIDR_PREFIX_STR_MAX.
 *
 * On failure, buf content is undefined.
 * No allocation occurs.
 *
 * See ARCHITECTURE.md §4.2.3.
 */
cidr_err_t
cidr_prefix_format(const cidr_prefix_t *prefix, char *buf, size_t len)
{
	cidr_err_t rc;
	size_t pos;
	int val;
	char tmp[4];
	int n;

	if (prefix == NULL || buf == NULL)
		return CIDR_ERR_INVAL;
	if (prefix->addr.family == CIDR_AF_UNSPEC)
		return CIDR_ERR_INVAL;
	if (len < CIDR_PREFIX_STR_MAX)
		return CIDR_ERR_INVAL;

	/*
	 * Format the address portion. cidr_addr_format writes the
	 * NUL-terminated canonical address into buf.
	 * See ARCHITECTURE.md §4.2.3.
	 */
	rc = cidr_addr_format(&prefix->addr, buf, len);
	if (rc != CIDR_OK)
		return rc;

	/* Find the NUL terminator to append "/<pfxlen>". */
	pos = strlen(buf);
	buf[pos++] = '/';

	/*
	 * SAFETY: CIDR_PREFIX_STR_MAX (50) accommodates the maximum
	 * address text (45 chars per ARCHITECTURE.md §4.2) + '/' +
	 * "128" (3 digits) + NUL = 50. The buffer check above ensures
	 * sufficient space. Convert pfxlen to decimal with no leading
	 * zeros. See ARCHITECTURE.md §4.2.3.
	 */
	val = (int)prefix->pfxlen;
	n = 0;
	if (val >= 100) {
		tmp[n++] = (char)('0' + val / 100);
		val %= 100;
	}
	if (val >= 10 || n > 0) {
		tmp[n++] = (char)('0' + val / 10);
		val %= 10;
	}
	tmp[n++] = (char)('0' + val);

	for (int i = 0; i < n; i++)
		buf[pos + (size_t)i] = tmp[i];
	buf[pos + (size_t)n] = '\0';

	return CIDR_OK;
}

/*
 * prefix_mask_compute - compute prefix mask bytes into a cidr_addr_t.
 *
 * Writes pfxlen leading 1-bits followed by zero-bits into the
 * address bytes of out, in network byte order. Sets out->family to
 * match the prefix family.
 *
 * SAFETY: prefix must have a valid family (CIDR_AF_INET or
 * CIDR_AF_INET6) and pfxlen within range. The host-bits-zero invariant
 * of prefix->addr (ARCHITECTURE.md §3.3) is not relied upon here --
 * only the family and pfxlen fields are used.
 *
 * See ARCHITECTURE.md §4.3.3.
 */
static void
prefix_mask_compute(const cidr_prefix_t *prefix, cidr_addr_t *out)
{
	uint8_t *bytes;
	size_t addr_len;
	size_t full_bytes;
	int rem;

	out->family = prefix->addr.family;
	if (prefix->addr.family == CIDR_AF_INET) {
		bytes = out->addr.v4;
		addr_len = 4;
	} else {
		bytes = out->addr.v6;
		addr_len = 16;
	}

	full_bytes = (size_t)(prefix->pfxlen / 8);
	rem = prefix->pfxlen % 8;

	/* Leading full bytes: all 1s. */
	for (size_t i = 0; i < full_bytes && i < addr_len; i++)
		bytes[i] = 0xFF;

	/* Partial byte (if any) followed by zeroed tail. */
	if (full_bytes < addr_len) {
		if (rem > 0) {
			bytes[full_bytes] = (uint8_t)(0xFF << (8 - rem));
			full_bytes++;
		}
		for (size_t i = full_bytes; i < addr_len; i++)
			bytes[i] = 0x00;
	}
}

/*
 * addr_big_endian_inc - increment a big-endian address byte array by
 *                        a power-of-two value.
 *
 * Adds 2^bit_count to the address bytes in network byte order (big
 * endian) with carry propagation from LSB to MSB. This is used by the
 * subnet iterator to advance the current subnet address and compute
 * the iteration limit.
 *
 * bytes:     address byte array, modified in place
 * addr_len:  number of bytes in the array (4 for IPv4, 16 for IPv6)
 * bit_count: exponent of the power-of-two increment
 *
 * SAFETY: bit_count must be <= addr_len * 8. If bit_count == addr_len
 * * 8 the function is a no-op (adds beyond the address width, which
 * wraps to the same value on overflow).
 */
static void
addr_big_endian_inc(uint8_t *bytes, size_t addr_len, int bit_count)
{
	int byte_shift;
	int bit_shift;
	size_t idx;
	uint16_t val;

	/*
	 * When bit_count == addr_len * 8, the increment exceeds the
	 * address width and would wrap around. This is a no-op.
	 */
	if (bit_count >= (int)(addr_len * 8))
		return;

	byte_shift = bit_count / 8;
	bit_shift = bit_count % 8;
	idx = addr_len - 1 - (size_t)byte_shift;

	/*
	 * SAFETY: idx is guaranteed in [0, addr_len-1] because
	 * bit_count < addr_len * 8 implies byte_shift < (int)addr_len.
	 */
	val = (uint16_t)bytes[idx] + (uint16_t)(1u << bit_shift);
	bytes[idx] = (uint8_t)(val & 0xFF);

	/*
	 * Carry propagation: if the byte overflowed, carry 1 to the
	 * next more significant byte.
	 */
	while (val > 0xFF && idx > 0) {
		idx--;
		val = (uint16_t)bytes[idx] + 1;
		bytes[idx] = (uint8_t)(val & 0xFF);
	}
}

/*
 * cidr_prefix_broadcast - compute the broadcast address of an IPv4
 *                         prefix.
 *
 * IPv4 only. ORs the network address with the bitwise complement of
 * the prefix mask. See ARCHITECTURE.md §4.3.2.
 */
cidr_err_t
cidr_prefix_broadcast(const cidr_prefix_t *prefix, cidr_addr_t *out)
{
	cidr_addr_t mask;
	size_t addr_len = 4;

	if (prefix == NULL || out == NULL)
		return CIDR_ERR_INVAL;
	if (prefix->addr.family == CIDR_AF_UNSPEC)
		return CIDR_ERR_INVAL;
	if (prefix->addr.family != CIDR_AF_INET)
		return CIDR_ERR_FAMILY;

	prefix_mask_compute(prefix, &mask);

	out->family = CIDR_AF_INET;
	for (size_t i = 0; i < addr_len; i++)
		out->addr.v4[i] =
		    prefix->addr.addr.v4[i] | (uint8_t)~mask.addr.v4[i];

	return CIDR_OK;
}

/*
 * cidr_prefix_mask - compute the prefix mask (network mask).
 *
 * See ARCHITECTURE.md §4.3.3.
 */
cidr_err_t
cidr_prefix_mask(const cidr_prefix_t *prefix, cidr_addr_t *out)
{
	if (prefix == NULL || out == NULL)
		return CIDR_ERR_INVAL;
	if (prefix->addr.family == CIDR_AF_UNSPEC)
		return CIDR_ERR_INVAL;

	prefix_mask_compute(prefix, out);
	return CIDR_OK;
}

/*
 * cidr_prefix_first - return the network (first) address of a prefix.
 *
 * The network address is prefix->addr directly -- host bits are
 * guaranteed zero by construction. See ARCHITECTURE.md §4.3.4.
 */
cidr_err_t
cidr_prefix_first(const cidr_prefix_t *prefix, cidr_addr_t *out)
{
	if (prefix == NULL || out == NULL)
		return CIDR_ERR_INVAL;
	if (prefix->addr.family == CIDR_AF_UNSPEC)
		return CIDR_ERR_INVAL;

	out->family = prefix->addr.family;
	if (prefix->addr.family == CIDR_AF_INET) {
		for (size_t i = 0; i < 4; i++)
			out->addr.v4[i] = prefix->addr.addr.v4[i];
	} else {
		for (size_t i = 0; i < 16; i++)
			out->addr.v6[i] = prefix->addr.addr.v6[i];
	}

	return CIDR_OK;
}

/*
 * cidr_prefix_last - return the last address of a prefix.
 *
 * For IPv4: the broadcast address. For IPv6: the host-bits-all-ones
 * address. Both are computed by ORing the network address with the
 * complement of the prefix mask. See ARCHITECTURE.md §4.3.4.
 */
cidr_err_t
cidr_prefix_last(const cidr_prefix_t *prefix, cidr_addr_t *out)
{
	cidr_addr_t mask;
	uint8_t *out_bytes;
	const uint8_t *mask_bytes;
	const uint8_t *net_bytes;
	size_t addr_len;

	if (prefix == NULL || out == NULL)
		return CIDR_ERR_INVAL;
	if (prefix->addr.family == CIDR_AF_UNSPEC)
		return CIDR_ERR_INVAL;

	prefix_mask_compute(prefix, &mask);

	out->family = prefix->addr.family;
	if (prefix->addr.family == CIDR_AF_INET) {
		addr_len = 4;
		out_bytes = out->addr.v4;
		mask_bytes = mask.addr.v4;
		net_bytes = prefix->addr.addr.v4;
	} else {
		addr_len = 16;
		out_bytes = out->addr.v6;
		mask_bytes = mask.addr.v6;
		net_bytes = prefix->addr.addr.v6;
	}

	for (size_t i = 0; i < addr_len; i++)
		out_bytes[i] = net_bytes[i] | (uint8_t)~mask_bytes[i];

	return CIDR_OK;
}

/*
 * cidr_prefix_contains - test whether a prefix contains an address.
 *
 * Computed as (addr & mask) == prefix->addr. out may be NULL; when
 * NULL the computation is performed and the status code is returned
 * without writing the result. See ARCHITECTURE.md §4.3.5.
 */
cidr_err_t
cidr_prefix_contains(const cidr_prefix_t *prefix, const cidr_addr_t *addr,
                     bool *out)
{
	cidr_addr_t mask;
	uint8_t masked[16] = {0};
	const uint8_t *mask_bytes;
	const uint8_t *addr_bytes;
	const uint8_t *net_bytes;
	size_t addr_len;
	bool result;

	if (prefix == NULL || addr == NULL)
		return CIDR_ERR_INVAL;
	if (prefix->addr.family == CIDR_AF_UNSPEC ||
	    addr->family == CIDR_AF_UNSPEC)
		return CIDR_ERR_INVAL;
	if (prefix->addr.family != addr->family)
		return CIDR_ERR_FAMILY;

	prefix_mask_compute(prefix, &mask);

	if (prefix->addr.family == CIDR_AF_INET) {
		addr_len = 4;
		addr_bytes = addr->addr.v4;
		mask_bytes = mask.addr.v4;
		net_bytes = prefix->addr.addr.v4;
	} else {
		addr_len = 16;
		addr_bytes = addr->addr.v6;
		mask_bytes = mask.addr.v6;
		net_bytes = prefix->addr.addr.v6;
	}

	for (size_t i = 0; i < addr_len; i++)
		masked[i] = addr_bytes[i] & mask_bytes[i];

	result = (memcmp(masked, net_bytes, addr_len) == 0);
	if (out != NULL)
		*out = result;

	return CIDR_OK;
}

/*
 * cidr_prefix_overlaps - test whether two prefixes share any address.
 *
 * Two prefixes overlap if and only if one contains the network address
 * of the other. out may be NULL. See ARCHITECTURE.md §4.3.6.
 */
cidr_err_t
cidr_prefix_overlaps(const cidr_prefix_t *a, const cidr_prefix_t *b, bool *out)
{
	bool result;
	cidr_err_t rc;

	if (a == NULL || b == NULL)
		return CIDR_ERR_INVAL;
	if (a->addr.family == CIDR_AF_UNSPEC ||
	    b->addr.family == CIDR_AF_UNSPEC)
		return CIDR_ERR_INVAL;
	if (a->addr.family != b->addr.family)
		return CIDR_ERR_FAMILY;

	/*
	 * Check a contains b->addr first. Delegate to
	 * cidr_prefix_contains for the mask-and-compare logic.
	 * See ARCHITECTURE.md §4.3.6.
	 */
	rc = cidr_prefix_contains(a, &b->addr, &result);
	if (rc != CIDR_OK)
		return rc;
	if (result) {
		if (out != NULL)
			*out = true;
		return CIDR_OK;
	}

	rc = cidr_prefix_contains(b, &a->addr, &result);
	if (rc != CIDR_OK)
		return rc;

	if (out != NULL)
		*out = result;
	return CIDR_OK;
}

/*
 * cidr_prefix_supernet - compute the parent prefix at pfxlen - 1.
 *
 * Decrements pfxlen by one and zeroes the new host bit in the network
 * address using prefix_mask_apply. Returns CIDR_ERR_OVERFLOW when
 * called on a /0 prefix -- the entire address space has no parent.
 * See ARCHITECTURE.md §4.3.7.
 */
cidr_err_t
cidr_prefix_supernet(const cidr_prefix_t *prefix, cidr_prefix_t *out)
{
	if (prefix == NULL || out == NULL)
		return CIDR_ERR_INVAL;
	if (prefix->addr.family == CIDR_AF_UNSPEC)
		return CIDR_ERR_INVAL;
	if (prefix->pfxlen == 0)
		return CIDR_ERR_OVERFLOW;

	out->addr.family = prefix->addr.family;
	if (prefix->addr.family == CIDR_AF_INET) {
		for (size_t i = 0; i < 4; i++)
			out->addr.addr.v4[i] = prefix->addr.addr.v4[i];
	} else {
		for (size_t i = 0; i < 16; i++)
			out->addr.addr.v6[i] = prefix->addr.addr.v6[i];
	}

	out->pfxlen = (uint8_t)(prefix->pfxlen - 1);

	/*
	 * Zero the new host bit (the bit that was the last bit of the
	 * prefix at the original pfxlen).
	 */
	prefix_mask_apply(out->pfxlen, &out->addr);

	return CIDR_OK;
}

/*
 * cidr_subnet_iter_init - initialise a subnet iterator.
 *
 * Validates target_pfxlen, initialises current to the prefix's network
 * address, and computes limit as the first address past the end of the
 * parent prefix. See ARCHITECTURE.md §4.3.8.
 */
cidr_err_t
cidr_subnet_iter_init(cidr_subnet_iter_t *iter, const cidr_prefix_t *prefix,
                      uint8_t target_pfxlen)
{
	uint8_t max_pfxlen;
	uint8_t *limit_bytes;
	size_t addr_len;
	int limit_power;

	if (iter == NULL || prefix == NULL)
		return CIDR_ERR_INVAL;
	if (prefix->addr.family == CIDR_AF_UNSPEC)
		return CIDR_ERR_INVAL;

	max_pfxlen = prefix_pfxlen_max(prefix->addr.family);

	/* target_pfxlen must be strictly greater and within range. */
	if (target_pfxlen <= prefix->pfxlen || target_pfxlen > max_pfxlen)
		return CIDR_ERR_PFXLEN;

	/*
	 * Initialise current to the prefix's network address.
	 * pfxlen is set to target_pfxlen for the yielded subnets.
	 */
	iter->current.addr.family = prefix->addr.family;
	iter->current.pfxlen = target_pfxlen;
	if (prefix->addr.family == CIDR_AF_INET) {
		for (size_t i = 0; i < 4; i++) {
			iter->current.addr.addr.v4[i] = prefix->addr.addr.v4[i];
			iter->limit.addr.addr.v4[i] = prefix->addr.addr.v4[i];
		}
		addr_len = 4;
		limit_bytes = iter->limit.addr.addr.v4;
	} else {
		for (size_t i = 0; i < 16; i++) {
			iter->current.addr.addr.v6[i] = prefix->addr.addr.v6[i];
			iter->limit.addr.addr.v6[i] = prefix->addr.addr.v6[i];
		}
		addr_len = 16;
		limit_bytes = iter->limit.addr.addr.v6;
	}

	/*
	 * Compute limit as the parent network address plus the parent's
	 * total address span: 2^(addr_bits - prefix->pfxlen).
	 */
	iter->limit.addr.family = prefix->addr.family;
	iter->limit.pfxlen = prefix->pfxlen;

	limit_power = (int)((addr_len * 8) - prefix->pfxlen);
	addr_big_endian_inc(limit_bytes, addr_len, limit_power);

	iter->target_pfxlen = target_pfxlen;
	iter->done = false;

	return CIDR_OK;
}

/*
 * cidr_subnet_iter_next - yield the next subnet from a subnet iterator.
 *
 * Writes the current subnet into out, then advances the iterator's
 * current address by the subnet step (2^(addr_bits - target_pfxlen)).
 * When the advanced address reaches or exceeds the limit, done is set
 * to true. On CIDR_ERR_DONE, out is not modified. Subnets are yielded
 * in ascending network address order. See ARCHITECTURE.md §4.3.8.
 */
cidr_err_t
cidr_subnet_iter_next(cidr_subnet_iter_t *iter, cidr_prefix_t *out)
{
	uint8_t *current_bytes;
	const uint8_t *limit_bytes;
	size_t addr_len;
	int step_power;

	if (iter == NULL || out == NULL)
		return CIDR_ERR_INVAL;

	if (iter->done)
		return CIDR_ERR_DONE;

	/*
	 * Write the current subnet address into out with the target
	 * prefix length.
	 */
	out->addr.family = iter->current.addr.family;
	out->pfxlen = iter->target_pfxlen;
	if (iter->current.addr.family == CIDR_AF_INET) {
		for (size_t i = 0; i < 4; i++)
			out->addr.addr.v4[i] = iter->current.addr.addr.v4[i];
		current_bytes = iter->current.addr.addr.v4;
		limit_bytes = iter->limit.addr.addr.v4;
		addr_len = 4;
	} else {
		for (size_t i = 0; i < 16; i++)
			out->addr.addr.v6[i] = iter->current.addr.addr.v6[i];
		current_bytes = iter->current.addr.addr.v6;
		limit_bytes = iter->limit.addr.addr.v6;
		addr_len = 16;
	}

	/*
	 * Advance current by the subnet step:
	 * 2^(addr_bits - target_pfxlen).
	 */
	step_power = (int)((addr_len * 8) - iter->target_pfxlen);
	addr_big_endian_inc(current_bytes, addr_len, step_power);

	/*
	 * Check whether the advanced address has reached or passed
	 * the limit. Lexicographic comparison on network-byte-order
	 * bytes is correct for big-endian address ordering.
	 * See ARCHITECTURE.md §4.3.8.
	 */
	if (memcmp(current_bytes, limit_bytes, addr_len) >= 0)
		iter->done = true;

	return CIDR_OK;
}

/*
 * cidr_prefix_cmp - compare two prefixes within the same family.
 *
 * Ordering matches CIDR_SORT_NETWORK_ASC: network address ascending
 * (lexicographic on address bytes in network byte order), then prefix
 * length ascending within the same network address. Writes -1, 0, or
 * +1 into *result. See ARCHITECTURE.md §4.4.
 */
cidr_err_t
cidr_prefix_cmp(const cidr_prefix_t *a, const cidr_prefix_t *b, int *result)
{
	int cmp;
	size_t addr_len;

	if (a == NULL || b == NULL || result == NULL)
		return CIDR_ERR_INVAL;
	if (a->addr.family == CIDR_AF_UNSPEC ||
	    b->addr.family == CIDR_AF_UNSPEC)
		return CIDR_ERR_INVAL;
	if (a->addr.family != b->addr.family)
		return CIDR_ERR_FAMILY;

	if (a->addr.family == CIDR_AF_INET) {
		addr_len = 4;
		cmp = memcmp(a->addr.addr.v4, b->addr.addr.v4, addr_len);
	} else {
		addr_len = 16;
		cmp = memcmp(a->addr.addr.v6, b->addr.addr.v6, addr_len);
	}

	if (cmp != 0) {
		*result = (cmp > 0) ? 1 : -1;
		return CIDR_OK;
	}

	/* Same network address: compare prefix length ascending. */
	if (a->pfxlen < b->pfxlen)
		*result = -1;
	else if (a->pfxlen > b->pfxlen)
		*result = 1;
	else
		*result = 0;

	return CIDR_OK;
}
