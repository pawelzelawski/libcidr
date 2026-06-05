/*
 * cidr_addr.c - address parsing, formatting, IPv4-mapped extraction,
 *               and address comparison.
 *
 * See ARCHITECTURE.md §4 for the arithmetic engine specification.
 */

#include "../include/libcidr.h"
#include "cidr_internal.h"

/*
 * hex_val - convert a hex digit character to its integer value.
 * Returns -1 if the character is not a valid hex digit.
 */
static int hex_val(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/*
 * addr_parse_ipv4 - strict dotted-decimal IPv4 parser.
 *
 * Parses exactly four decimal octets 0-255 separated by dots.
 * Rejects leading zeros ("01" is invalid; "0" alone is valid),
 * hex notation, whitespace, empty octets, trailing characters,
 * and any value outside 0-255.
 *
 * No sscanf, no strtol -- all parsing is character-by-character
 * to avoid base-8 fallback and locale-dependent behaviour.
 *
 * src:  null-terminated address string (validated non-NULL by caller)
 * out:  caller-provided cidr_addr_t
 *
 * Returns CIDR_OK on success (out->family = CIDR_AF_INET, addr.v4
 * in network byte order).
 * Returns CIDR_ERR_PARSE on any malformed input.
 *
 * See ARCHITECTURE.md §4.1.1 for the full rejection case table.
 */
static cidr_err_t addr_parse_ipv4(const char *src, cidr_addr_t *out)
    __attribute__((warn_unused_result));

static cidr_err_t addr_parse_ipv4(const char *src, cidr_addr_t *out)
{
	const char *p = src;
	int octet_count = 0;
	uint8_t octets[4];

	if (*p == '\0')
		return CIDR_ERR_PARSE;

	while (*p != '\0') {
		int value = 0;

		if (*p < '0' || *p > '9')
			return CIDR_ERR_PARSE;

		/*
		 * Leading zero check: a single '0' is valid for an octet;
		 * "0" followed by another digit (e.g. "01") is rejected.
		 * See ARCHITECTURE.md §4.1.1 -- ambiguous interpretation.
		 */
		if (*p == '0') {
			p++;
			if (*p >= '0' && *p <= '9')
				return CIDR_ERR_PARSE;
		} else {
			while (*p >= '0' && *p <= '9') {
				value = value * 10 + (*p - '0');
				if (value > 255)
					return CIDR_ERR_PARSE;
				p++;
			}
		}

		if (octet_count >= 4)
			return CIDR_ERR_PARSE;

		octets[octet_count] = (uint8_t)value;
		octet_count++;

		if (*p == '.') {
			p++;
			if (*p == '\0')
				return CIDR_ERR_PARSE;
			continue;
		}
		if (*p == '\0')
			break;
		return CIDR_ERR_PARSE;
	}

	if (octet_count != 4)
		return CIDR_ERR_PARSE;

	/*
	 * Store address bytes in network byte order.
	 * See ARCHITECTURE.md §3.2 -- storage format matches wire format.
	 */
	out->family = CIDR_AF_INET;
	out->addr.v4[0] = octets[0];
	out->addr.v4[1] = octets[1];
	out->addr.v4[2] = octets[2];
	out->addr.v4[3] = octets[3];
	return CIDR_OK;
}

/*
 * ipv4_suffix_parse - parse a strict dotted-decimal IPv4 address
 * at the end of a mixed-notation IPv6 input.
 *
 * Parses exactly four decimal octets 0-255 separated by dots.
 * Leading zeros rejected. No hex, no whitespace, no trailing chars.
 *
 * Writes the four octets into octets[0..3]. The caller has
 * validated that suffix is non-empty.
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_PARSE on malformed input.
 */
static cidr_err_t ipv4_suffix_parse(const char *suffix, uint8_t *octets)
{
	const char *p = suffix;
	int octet_count = 0;

	if (*p == '\0')
		return CIDR_ERR_PARSE;

	while (*p != '\0') {
		int value = 0;

		if (*p < '0' || *p > '9')
			return CIDR_ERR_PARSE;

		if (*p == '0') {
			p++;
			if (*p >= '0' && *p <= '9')
				return CIDR_ERR_PARSE;
		} else {
			while (*p >= '0' && *p <= '9') {
				value = value * 10 + (*p - '0');
				if (value > 255)
					return CIDR_ERR_PARSE;
				p++;
			}
		}

		if (octet_count >= 4)
			return CIDR_ERR_PARSE;

		octets[octet_count] = (uint8_t)value;
		octet_count++;

		if (*p == '.') {
			p++;
			if (*p == '\0')
				return CIDR_ERR_PARSE;
			continue;
		}
		if (*p == '\0')
			break;
		return CIDR_ERR_PARSE;
	}

	if (octet_count != 4)
		return CIDR_ERR_PARSE;
	return CIDR_OK;
}

/*
 * is_mixed_suffix - return true if the text after last_colon
 * looks like a strict dotted-decimal IPv4 address.
 *
 * Quick check: must contain at least one '.'. Full validity is
 * verified by ipv4_suffix_parse() which is called afterwards.
 */
static bool is_mixed_suffix(const char *s)
{
	if (*s == '\0')
		return false;
	while (*s != '\0') {
		if (*s == '.')
			return true;
		s++;
	}
	return false;
}

/*
 * addr_parse_ipv6 - parse an IPv6 address from text.
 *
 * Accepts the three text forms defined in RFC 4291 §2.2, as
 * updated by RFC 5952:
 *
 *   1. Full form: eight 16-bit hex groups separated by colons.
 *   2. Compressed form: :: replaces one or more consecutive
 *      all-zero 16-bit groups. :: may appear at most once.
 *   3. Mixed form: six hex groups followed by an IPv4
 *      dotted-decimal tail. Accepted only when the result
 *      falls within the IPv4-mapped prefix ::ffff:0:0/96
 *      (first 10 bytes zero, bytes 10-11 = 0xFF 0xFF).
 *
 * Uppercase and mixed-case hex digits are accepted on input.
 * The stored address is always in binary network byte order.
 *
 * IPv4-compatible addresses (::x.x.x.x where the first 12 bytes
 * are all zero) are rejected per RFC 4291 §2.5.5.1 deprecation.
 *
 * src:  null-terminated IPv6 address string (validated non-NULL
 *       and confirmed to contain ':' by the caller)
 * out:  caller-provided cidr_addr_t; family NOT written on failure
 *       (the caller, cidr_addr_parse, handles this)
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_PARSE on any malformed input.
 *
 * See ARCHITECTURE.md §4.1.2 for the full IPv6 parsing specification.
 */
static cidr_err_t addr_parse_ipv6(const char *src, cidr_addr_t *out)
    __attribute__((warn_unused_result));

static cidr_err_t addr_parse_ipv6(const char *src, cidr_addr_t *out)
{
	const char *p;
	const char *last_colon = NULL;
	bool has_cc = false;
	int max_groups, total_explicit;
	uint16_t before[8], after[8];
	int before_count = 0, after_count = 0;
	int i, byte_idx, zero_groups;

	if (*src == '\0')
		return CIDR_ERR_PARSE;

	/*
	 * Find the last colon in the string to test for mixed
	 * (IPv4-mapped) notation. If the suffix after the last
	 * colon looks like a dotted-decimal IPv4 address, try
	 * the mixed-notation parse path.
	 * See ARCHITECTURE.md §4.1.2.
	 */
	for (p = src; *p != '\0'; p++) {
		if (*p == ':')
			last_colon = p;
	}

	/*
	 * If the suffix after the last colon could be an IPv4
	 * address, attempt mixed-notation parse. This covers
	 * ::ffff:192.0.2.1 (accepted) and ::192.0.2.1 (rejected
	 * by the prefix check below).
	 */
	if (last_colon != NULL && is_mixed_suffix(last_colon + 1)) {
		uint8_t ipv4_octets[4];
		const char *ipv4_src = last_colon + 1;

		if (ipv4_suffix_parse(ipv4_src, ipv4_octets) != CIDR_OK)
			return CIDR_ERR_PARSE;

		const char *hex_end;

		/*
		 * The hex part is everything before the last colon.
		 * If the last colon is the second colon of :: (as in
		 * ::192.0.2.1), the hex part is just ":" (one colon).
		 * We handle this degeneracy below.
		 */
		hex_end = last_colon;
		max_groups = 6;

		/* Parse the hex prefix, bounded by hex_end. */
		p = src;
		has_cc = false;
		before_count = 0;
		after_count = 0;

		while (p < hex_end) {
			int digit_count = 0;
			uint16_t value = 0;

			/*
			 * Check for :: at current position.
			 * If the second colon would be at or past
			 * hex_end, treat the lone ':' as a
			 * degenerate :: that spans the boundary.
			 * See ARCHITECTURE.md §4.1.2.
			 */
			if (*p == ':') {
				if (p + 1 < hex_end && *(p + 1) == ':') {
					if (has_cc)
						return CIDR_ERR_PARSE;
					has_cc = true;
					p += 2;
					continue;
				}
				/*
				 * Lone colon at the end of the hex part:
				 * the :: straddles the hex/IPv4 boundary.
				 * This is the degenerate case like
				 * ::192.0.2.1 where the IPv4 suffix
				 * follows :: directly.
				 */
				if (p + 1 == hex_end) {
					if (has_cc)
						return CIDR_ERR_PARSE;
					has_cc = true;
					p++;
					continue;
				}
				return CIDR_ERR_PARSE;
			}

			/* Parse 1-4 hex digits. */
			while (p < hex_end) {
				int dig;

				dig = hex_val(*p);
				if (dig < 0)
					break;
				value = (uint16_t)(value * 16 + (uint16_t)dig);
				digit_count++;
				p++;
			}
			if (digit_count < 1 || digit_count > 4)
				return CIDR_ERR_PARSE;

			if (has_cc) {
				if (after_count >= max_groups)
					return CIDR_ERR_PARSE;
				after[after_count++] = value;
			} else {
				if (before_count >= max_groups)
					return CIDR_ERR_PARSE;
				before[before_count++] = value;
			}

			/*
			 * Separator or end of hex part.
			 * If the colon is part of :: (next char is also ':'
			 * and within the hex part), do not consume it; the
			 * top of loop will detect ::. Also skip consumption
			 * when :: straddles the hex boundary.
			 */
			if (p >= hex_end)
				break;
			if (*p != ':')
				return CIDR_ERR_PARSE;
			if (p + 1 < hex_end && *(p + 1) == ':')
				continue;
			if (p + 1 == hex_end)
				continue;
			p++;
		}

		total_explicit = before_count + after_count;

		if (!has_cc) {
			if (total_explicit != max_groups)
				return CIDR_ERR_PARSE;
		} else {
			/*
			 * SAFETY: :: must expand to at least one zero group.
			 * If explicit groups already equal max_groups, there
			 * is no room for expansion -- reject.
			 */
			if (total_explicit >= max_groups)
				return CIDR_ERR_PARSE;
		}
		zero_groups = max_groups - total_explicit;

		/*
		 * Build the first 12 address bytes from hex groups
		 * in network byte order (big-endian per group).
		 * See ARCHITECTURE.md §3.2.
		 */
		byte_idx = 0;
		for (i = 0; i < before_count; i++) {
			out->addr.v6[byte_idx++] = (uint8_t)(before[i] >> 8);
			out->addr.v6[byte_idx++] = (uint8_t)(before[i] & 0xFF);
		}
		for (i = 0; i < zero_groups; i++) {
			out->addr.v6[byte_idx++] = 0;
			out->addr.v6[byte_idx++] = 0;
		}
		for (i = 0; i < after_count; i++) {
			out->addr.v6[byte_idx++] = (uint8_t)(after[i] >> 8);
			out->addr.v6[byte_idx++] = (uint8_t)(after[i] & 0xFF);
		}

		/* Append the IPv4 suffix bytes (octets 12-15). */
		out->addr.v6[12] = ipv4_octets[0];
		out->addr.v6[13] = ipv4_octets[1];
		out->addr.v6[14] = ipv4_octets[2];
		out->addr.v6[15] = ipv4_octets[3];

		/*
		 * SAFETY: verify the IPv4-mapped prefix.
		 * First 10 bytes must be zero, bytes 10-11 must be
		 * 0xFF 0xFF. This rejects non-mapped mixed notation
		 * (e.g. 2001:db8::192.0.2.1) and IPv4-compatible
		 * addresses (e.g. ::192.0.2.1).
		 * See ARCHITECTURE.md §4.1.2, RFC 5952 §5,
		 * RFC 4291 §2.5.5.1.
		 */
		for (i = 0; i < 10; i++) {
			if (out->addr.v6[i] != 0)
				return CIDR_ERR_PARSE;
		}
		if (out->addr.v6[10] != 0xFF || out->addr.v6[11] != 0xFF)
			return CIDR_ERR_PARSE;

		out->family = CIDR_AF_INET6;
		return CIDR_OK;
	}

	/*
	 * Pure IPv6 path (full or compressed form).
	 * Parse up to 8 hex groups, with :: appearing at most once.
	 * See ARCHITECTURE.md §4.1.2.
	 */
	max_groups = 8;
	p = src;
	has_cc = false;
	before_count = 0;
	after_count = 0;

	while (*p != '\0') {
		int digit_count = 0;
		uint16_t value = 0;

		/* Detect :: token. */
		if (*p == ':' && *(p + 1) == ':') {
			if (has_cc)
				return CIDR_ERR_PARSE;
			has_cc = true;
			p += 2;
			continue;
		}

		/* Parse 1-4 hex digits. */
		while (*p != '\0') {
			int dig;

			dig = hex_val(*p);
			if (dig < 0)
				break;
			value = (uint16_t)(value * 16 + (uint16_t)dig);
			digit_count++;
			p++;
		}
		if (digit_count < 1 || digit_count > 4)
			return CIDR_ERR_PARSE;

		if (has_cc) {
			if (after_count >= max_groups)
				return CIDR_ERR_PARSE;
			after[after_count++] = value;
		} else {
			if (before_count >= max_groups)
				return CIDR_ERR_PARSE;
			before[before_count++] = value;
		}

		/*
		 * Expect separator, ::, or end of string.
		 * If the colon is part of :: (next char is also ':'),
		 * do not consume it; the top of loop will detect ::.
		 */
		if (*p == ':') {
			if (*(p + 1) != ':') {
				p++;
				if (*p == '\0')
					break;
			}
			continue;
		}
		if (*p == '\0')
			break;
		return CIDR_ERR_PARSE;
	}

	total_explicit = before_count + after_count;

	/*
	 * SAFETY: validate group count.
	 * Without :: : exactly 8 groups.
	 * With ::    : explicit groups must be strictly less than 8;
	 *              :: expands to at least one zero group.
	 * See ARCHITECTURE.md §4.1.2.
	 */
	if (!has_cc) {
		if (total_explicit != 8)
			return CIDR_ERR_PARSE;
	} else {
		if (total_explicit >= 8)
			return CIDR_ERR_PARSE;
	}
	zero_groups = 8 - total_explicit;

	/*
	 * Build 16 address bytes in network byte order.
	 * See ARCHITECTURE.md §3.2.
	 */
	byte_idx = 0;
	for (i = 0; i < before_count; i++) {
		out->addr.v6[byte_idx++] = (uint8_t)(before[i] >> 8);
		out->addr.v6[byte_idx++] = (uint8_t)(before[i] & 0xFF);
	}
	for (i = 0; i < zero_groups; i++) {
		out->addr.v6[byte_idx++] = 0;
		out->addr.v6[byte_idx++] = 0;
	}
	for (i = 0; i < after_count; i++) {
		out->addr.v6[byte_idx++] = (uint8_t)(after[i] >> 8);
		out->addr.v6[byte_idx++] = (uint8_t)(after[i] & 0xFF);
	}

	out->family = CIDR_AF_INET6;
	return CIDR_OK;
}

/*
 * cidr_addr_parse - parse an IPv4 or IPv6 address from text.
 *
 * Dispatches based on input text: strings containing ':' are
 * treated as IPv6 per ARCHITECTURE.md §4.1.2; all other input
 * is parsed as strict dotted-decimal IPv4 per §4.1.1.
 *
 * IPv6 accepts full (8-group), compressed (:: once), and mixed
 * (IPv4-mapped only) forms. IPv4-compatible addresses are
 * rejected per RFC 4291 §2.5.5.1 deprecation. Non-mapped mixed
 * notation is rejected per RFC 5952 §5.
 *
 * src:  null-terminated address string
 * out:  caller-provided cidr_addr_t; on failure out->family is
 *       written as CIDR_AF_UNSPEC so the caller can detect
 *       failure by inspecting the output even after discarding
 *       the return code
 *
 * Returns CIDR_OK on success (out->family set to CIDR_AF_INET
 * or CIDR_AF_INET6, address bytes in network byte order).
 * Returns CIDR_ERR_INVAL if src or out is NULL.
 * Returns CIDR_ERR_PARSE if the text does not match a valid
 * address form for either family.
 *
 * See ARCHITECTURE.md §4.1.1 and §4.1.2.
 */
cidr_err_t cidr_addr_parse(const char *src, cidr_addr_t *out)
{
	cidr_err_t rc;
	const char *p;

	if (src == NULL || out == NULL)
		return CIDR_ERR_INVAL;

	/*
	 * IPv6 dispatch: if the input contains a colon, delegate
	 * to the IPv6 parser. See ARCHITECTURE.md §4.1.2.
	 */
	for (p = src; *p != '\0'; p++) {
		if (*p == ':') {
			rc = addr_parse_ipv6(src, out);
			if (rc != CIDR_OK)
				out->family = CIDR_AF_UNSPEC;
			return rc;
		}
	}

	rc = addr_parse_ipv4(src, out);
	if (rc != CIDR_OK)
		out->family = CIDR_AF_UNSPEC;
	return rc;
}

/*
 * uint8_to_dec - write the decimal representation of val (0-255)
 * into out and return the number of characters written (1-3).
 * No leading zeros. No NUL terminator -- the caller handles it.
 */
static int uint8_to_dec(uint8_t val, char *out)
{
	if (val >= 100) {
		out[0] = (char)('0' + (val / 100));
		out[1] = (char)('0' + ((val / 10) % 10));
		out[2] = (char)('0' + (val % 10));
		return 3;
	}
	if (val >= 10) {
		out[0] = (char)('0' + (val / 10));
		out[1] = (char)('0' + (val % 10));
		return 2;
	}
	out[0] = (char)('0' + val);
	return 1;
}

/*
 * uint16_to_hex - write the lowercase hexadecimal representation
 * of val (0-65535) into out without leading zeros and return the
 * number of characters written (1-4). The value 0 is written as "0".
 * No NUL terminator -- the caller handles it.
 */
static int uint16_to_hex(uint16_t val, char *out)
{
	static const char hex_digits[] = "0123456789abcdef";
	int shift = 12;
	int pos = 0;

	if (val == 0) {
		out[0] = '0';
		return 1;
	}
	/* Skip leading zero hex digits (4 bits each, starting at bit 12). */
	while (shift > 0 && (val >> shift) == 0)
		shift -= 4;
	while (shift >= 0) {
		out[pos++] = hex_digits[(val >> shift) & 0xF];
		shift -= 4;
	}
	return pos;
}

/*
 * find_zero_compress - find the best :: compression position in
 * an array of 8 IPv6 uint16_t groups per RFC 5952.
 *
 * Scans groups for the longest consecutive run of zero groups.
 * Returns the start index of the run and sets *run_len.
 * Returns -1 and sets *run_len to 0 if no run of length >= 2 exists.
 *
 * Rules applied:
 *   RFC 5952 §4.2.1 -- longest run compressed (:: to maximum extent)
 *   RFC 5952 §4.2.2 -- single zero group written as "0", not ::
 *   RFC 5952 §4.2.3 -- first run wins on tie
 *
 * See ARCHITECTURE.md §4.2.2 rules 2-4.
 */
static int find_zero_compress(const uint16_t *groups, int *run_len)
{
	int best_start = -1;
	int best_len = 0;
	int curr_start = -1;
	int curr_len = 0;
	int i;

	for (i = 0; i < 8; i++) {
		if (groups[i] == 0) {
			if (curr_start < 0)
				curr_start = i;
			curr_len++;
		} else {
			/* Strict greater -- first run wins on tie
			 * per RFC 5952 §4.2.3. */
			if (curr_len > best_len) {
				best_start = curr_start;
				best_len = curr_len;
			}
			curr_start = -1;
			curr_len = 0;
		}
	}
	/* Handle trailing zero run. */
	if (curr_len > best_len) {
		best_start = curr_start;
		best_len = curr_len;
	}
	/*
	 * RFC 5952 §4.2.2: do not compress a single zero group.
	 * A run of length 0 or 1 is not eligible for :: compression.
	 */
	if (best_len < 2) {
		*run_len = 0;
		return -1;
	}
	*run_len = best_len;
	return best_start;
}

/*
 * addr_format_ipv4 - format an IPv4 address as canonical dotted-decimal.
 *
 * Writes four decimal octets separated by dots into buf. No leading
 * zeros, no alternative notations.
 *
 * buf must be at least CIDR_ADDR_STR_MAX bytes (validated by caller).
 *
 * See ARCHITECTURE.md §4.2.1.
 */
static cidr_err_t addr_format_ipv4(const cidr_addr_t *addr, char *buf)
    __attribute__((warn_unused_result));

static cidr_err_t addr_format_ipv4(const cidr_addr_t *addr, char *buf)
{
	int pos = 0;

	pos += uint8_to_dec(addr->addr.v4[0], buf + pos);
	buf[pos++] = '.';
	pos += uint8_to_dec(addr->addr.v4[1], buf + pos);
	buf[pos++] = '.';
	pos += uint8_to_dec(addr->addr.v4[2], buf + pos);
	buf[pos++] = '.';
	pos += uint8_to_dec(addr->addr.v4[3], buf + pos);
	buf[pos] = '\0';
	return CIDR_OK;
}

/*
 * addr_format_ipv6 - format an IPv6 address in RFC 5952 canonical form.
 *
 * Builds 8 uint16_t groups from the 16 address bytes in network byte
 * order. Checks for IPv4-mapped addresses (::ffff:0:0/96) and formats
 * them with a dotted-decimal tail per RFC 5952 §5. For all other IPv6
 * addresses, finds the best :: compression point and formats groups
 * as colon-separated lowercase hex with leading zeros suppressed.
 *
 * Rules applied, per RFC 5952:
 *   1. Leading zeros suppressed §4.1
 *   2. :: applied to the longest run of zero groups §4.2.1
 *   3. :: not used for a single zero group §4.2.2
 *   4. First run wins on tie §4.2.3
 *   5. Lowercase hex throughout §4.3
 *   6. IPv4-mapped addresses use mixed notation §5
 *
 * buf must be at least CIDR_ADDR_STR_MAX bytes (validated by caller).
 *
 * See ARCHITECTURE.md §4.2.2.
 */
static cidr_err_t addr_format_ipv6(const cidr_addr_t *addr, char *buf)
    __attribute__((warn_unused_result));

static cidr_err_t addr_format_ipv6(const cidr_addr_t *addr, char *buf)
{
	uint16_t groups[8];
	int pos = 0;
	int start, len;
	int i;

	/*
	 * Build 8 uint16_t groups from 16 address bytes in network
	 * byte order. See ARCHITECTURE.md §3.2.
	 */
	for (i = 0; i < 8; i++)
		groups[i] = ((uint16_t)addr->addr.v6[(ptrdiff_t)i * 2] << 8) |
		            addr->addr.v6[(ptrdiff_t)i * 2 + 1];

	/*
	 * IPv4-mapped address check: ::ffff:0:0/96.
	 * Groups 0-4 must be zero, group 5 must be 0xFFFF.
	 * Format as ::ffff:x.x.x.x per RFC 5952 §5.
	 * See ARCHITECTURE.md §4.2.2 rule 6.
	 */
	if (groups[0] == 0 && groups[1] == 0 && groups[2] == 0 &&
	    groups[3] == 0 && groups[4] == 0 && groups[5] == 0xFFFF) {
		buf[0] = ':';
		buf[1] = ':';
		buf[2] = 'f';
		buf[3] = 'f';
		buf[4] = 'f';
		buf[5] = 'f';
		buf[6] = ':';
		pos = 7;
		pos += uint8_to_dec(addr->addr.v6[12], buf + pos);
		buf[pos++] = '.';
		pos += uint8_to_dec(addr->addr.v6[13], buf + pos);
		buf[pos++] = '.';
		pos += uint8_to_dec(addr->addr.v6[14], buf + pos);
		buf[pos++] = '.';
		pos += uint8_to_dec(addr->addr.v6[15], buf + pos);
		buf[pos] = '\0';
		return CIDR_OK;
	}

	/*
	 * Find the best :: compression position per RFC 5952 §4.2.1-4.2.3.
	 * Longest consecutive run of zero groups; first run wins on tie;
	 * single zero group not compressed.
	 */
	start = find_zero_compress(groups, &len);

	if (start < 0) {
		/* No compression: format all 8 groups with separators. */
		pos += uint16_to_hex(groups[0], buf + pos);
		for (i = 1; i < 8; i++) {
			buf[pos++] = ':';
			pos += uint16_to_hex(groups[i], buf + pos);
		}
	} else {
		/* Groups before ::. */
		for (i = 0; i < start; i++) {
			pos += uint16_to_hex(groups[i], buf + pos);
			buf[pos++] = ':';
		}
		/* :: itself. */
		if (start == 0)
			buf[pos++] = ':';
		buf[pos++] = ':';
		/* Groups after ::. */
		for (i = start + len; i < 8; i++) {
			pos += uint16_to_hex(groups[i], buf + pos);
			if (i < 7)
				buf[pos++] = ':';
		}
	}

	buf[pos] = '\0';
	return CIDR_OK;
}

/*
 * cidr_addr_format - format an address as canonical text.
 *
 * Writes the canonical text representation of addr into the caller-provided
 * buffer buf of length len. Dispatches to addr_format_ipv4() for
 * CIDR_AF_INET and addr_format_ipv6() for CIDR_AF_INET6.
 *
 * addr: pointer to a valid cidr_addr_t
 * buf:  caller-provided output buffer
 * len:  size of buf in bytes; must be at least CIDR_ADDR_STR_MAX
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_INVAL if addr or buf is NULL, if addr->family is
 * CIDR_AF_UNSPEC, or if len < CIDR_ADDR_STR_MAX.
 *
 * On failure, buf content is undefined.
 * No allocation occurs.
 *
 * See ARCHITECTURE.md §4.2.
 */
cidr_err_t cidr_addr_format(const cidr_addr_t *addr, char *buf, size_t len)
{
	/*
	 * SAFETY: buffer size check before any write. CIDR_ADDR_STR_MAX (46)
	 * accommodates the longest possible IPv6 canonical form including
	 * NUL terminator. See ARCHITECTURE.md §4.2.
	 */
	if (addr == NULL || buf == NULL)
		return CIDR_ERR_INVAL;
	if (addr->family == CIDR_AF_UNSPEC)
		return CIDR_ERR_INVAL;
	if (len < CIDR_ADDR_STR_MAX)
		return CIDR_ERR_INVAL;

	if (addr->family == CIDR_AF_INET)
		return addr_format_ipv4(addr, buf);
	return addr_format_ipv6(addr, buf);
}
