/*
 * cidr_addr.c - address parsing, formatting, IPv4-mapped extraction,
 *               and address comparison.
 *
 * See ARCHITECTURE.md §4 for the arithmetic engine specification.
 */

#include "../include/libcidr.h"
#include "cidr_internal.h"

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
 * cidr_addr_parse - parse an IPv4 or IPv6 address from text.
 *
 * Dispatches based on input text: strings containing ':' are treated
 * as IPv6 (handled in a later phase; returns CIDR_ERR_PARSE for now);
 * all other input is parsed as strict dotted-decimal IPv4.
 *
 * src:  null-terminated address string
 * out:  caller-provided cidr_addr_t; on failure out->family is written
 *       as CIDR_AF_UNSPEC so the caller can detect failure by
 *       inspecting the output even after discarding the return code
 *
 * Returns CIDR_OK on success (out->family = CIDR_AF_INET, IPv4 bytes
 * in network byte order).
 * Returns CIDR_ERR_INVAL if src or out is NULL.
 * Returns CIDR_ERR_PARSE if the text does not match a valid IPv4
 * address form (or is an IPv6 form not yet implemented).
 *
 * See ARCHITECTURE.md §4.1.1 for IPv4 parsing rejection cases.
 */
cidr_err_t cidr_addr_parse(const char *src, cidr_addr_t *out)
{
	cidr_err_t rc;
	const char *p;

	if (src == NULL || out == NULL)
		return CIDR_ERR_INVAL;

	/*
	 * IPv6 dispatch: if the input contains a colon, it is an
	 * attempted IPv6 address. IPv6 parsing is implemented in a
	 * later phase; return CIDR_ERR_PARSE for now.
	 * See ARCHITECTURE.md §4.1.2.
	 */
	for (p = src; *p != '\0'; p++) {
		if (*p == ':') {
			out->family = CIDR_AF_UNSPEC;
			return CIDR_ERR_PARSE;
		}
	}

	rc = addr_parse_ipv4(src, out);
	if (rc != CIDR_OK)
		out->family = CIDR_AF_UNSPEC;
	return rc;
}
