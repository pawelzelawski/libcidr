/*
 * test_prefix.c - prefix construction, arithmetic, iteration, and
 *                 comparison tests.
 *
 * Tests: cidr_prefix_parse, cidr_prefix_from_host, cidr_prefix_format,
 * cidr_prefix_broadcast, cidr_prefix_mask, cidr_prefix_first,
 * cidr_prefix_last, cidr_prefix_contains, cidr_prefix_overlaps,
 * cidr_prefix_supernet, cidr_subnet_iter_init, cidr_subnet_iter_next,
 * cidr_prefix_cmp.
 *
 * See TESTING.md §2.2 for test scope boundaries.
 * See DEVELOPMENT.md §Phase 3 Tests for the named test case catalogue.
 */

#include <string.h>

#include "../include/libcidr.h"

static void
expected_mask_bytes(uint8_t *bytes, size_t addr_len, uint8_t pfxlen)
{
	size_t full_bytes;
	int rem;

	full_bytes = (size_t)(pfxlen / 8);
	rem = pfxlen % 8;

	memset(bytes, 0x00, addr_len);
	for (size_t i = 0; i < full_bytes && i < addr_len; i++)
		bytes[i] = 0xFF;
	if (full_bytes < addr_len && rem > 0)
		bytes[full_bytes] = (uint8_t)(0xFF << (8 - rem));
}

int
test_prefix_parse_valid(void)
{
	cidr_prefix_t out;

	if (cidr_prefix_parse("192.168.1.0/24", &out) != CIDR_OK)
		return 1;
	if (out.addr.family != CIDR_AF_INET)
		return 1;
	if (out.addr.addr.v4[0] != 192 || out.addr.addr.v4[1] != 168 ||
	    out.addr.addr.v4[2] != 1 || out.addr.addr.v4[3] != 0)
		return 1;
	if (out.pfxlen != 24)
		return 1;

	/* boundary: /0 */
	if (cidr_prefix_parse("0.0.0.0/0", &out) != CIDR_OK)
		return 1;
	if (out.pfxlen != 0)
		return 1;

	/* boundary: /32 */
	if (cidr_prefix_parse("192.168.1.0/32", &out) != CIDR_OK)
		return 1;
	if (out.pfxlen != 32)
		return 1;

	/* IPv6 */
	if (cidr_prefix_parse("2001:db8::/32", &out) != CIDR_OK)
		return 1;
	if (out.addr.family != CIDR_AF_INET6)
		return 1;
	if (out.pfxlen != 32)
		return 1;

	/* IPv6 /128 */
	if (cidr_prefix_parse("::1/128", &out) != CIDR_OK)
		return 1;
	if (out.pfxlen != 128)
		return 1;

	return 0;
}

int
test_prefix_parse_hostbits_rejected(void)
{
	cidr_prefix_t out;

	/* IPv4 host bits set */
	if (cidr_prefix_parse("192.168.1.5/24", &out) != CIDR_ERR_HOSTBITS)
		return 1;
	if (cidr_prefix_parse("10.0.0.1/8", &out) != CIDR_ERR_HOSTBITS)
		return 1;

	/* IPv6 host bits set */
	if (cidr_prefix_parse("2001:db8::1/32", &out) != CIDR_ERR_HOSTBITS)
		return 1;

	return 0;
}

int
test_prefix_parse_pfxlen_out_of_range(void)
{
	cidr_prefix_t out;

	/* IPv4 */
	if (cidr_prefix_parse("192.168.0.0/33", &out) != CIDR_ERR_PFXLEN)
		return 1;
	if (cidr_prefix_parse("10.0.0.0/255", &out) != CIDR_ERR_PFXLEN)
		return 1;

	/* IPv6 */
	if (cidr_prefix_parse("::/129", &out) != CIDR_ERR_PFXLEN)
		return 1;

	return 0;
}

int
test_prefix_parse_null(void)
{
	cidr_prefix_t out;

	if (cidr_prefix_parse(NULL, &out) != CIDR_ERR_INVAL)
		return 1;
	if (cidr_prefix_parse("192.168.1.0/24", NULL) != CIDR_ERR_INVAL)
		return 1;

	return 0;
}

int
test_prefix_from_host_zeroes_hostbits(void)
{
	cidr_addr_t addr;
	cidr_addr_t mask;
	cidr_prefix_t out;
	uint8_t expected[16];

	/* /0: all bytes zeroed */
	addr.family = CIDR_AF_INET;
	addr.addr.v4[0] = 255;
	addr.addr.v4[1] = 255;
	addr.addr.v4[2] = 255;
	addr.addr.v4[3] = 255;
	if (cidr_prefix_from_host(&addr, 0, &out) != CIDR_OK)
		return 1;
	if (out.addr.addr.v4[0] != 0 || out.addr.addr.v4[1] != 0 ||
	    out.addr.addr.v4[2] != 0 || out.addr.addr.v4[3] != 0)
		return 1;

	/* /1: only MSB of byte 0 preserved */
	addr.family = CIDR_AF_INET;
	addr.addr.v4[0] = 128;
	addr.addr.v4[1] = 255;
	addr.addr.v4[2] = 255;
	addr.addr.v4[3] = 255;
	if (cidr_prefix_from_host(&addr, 1, &out) != CIDR_OK)
		return 1;
	if (out.addr.addr.v4[0] != 128 || out.addr.addr.v4[1] != 0 ||
	    out.addr.addr.v4[2] != 0 || out.addr.addr.v4[3] != 0)
		return 1;

	/* /31: only the lowest bit of byte 3 zeroed */
	addr.family = CIDR_AF_INET;
	addr.addr.v4[0] = 192;
	addr.addr.v4[1] = 168;
	addr.addr.v4[2] = 1;
	addr.addr.v4[3] = 1;
	if (cidr_prefix_from_host(&addr, 31, &out) != CIDR_OK)
		return 1;
	if (out.addr.addr.v4[0] != 192 || out.addr.addr.v4[1] != 168 ||
	    out.addr.addr.v4[2] != 1 || out.addr.addr.v4[3] != 0)
		return 1;

	/* /32: no bytes changed */
	addr.family = CIDR_AF_INET;
	addr.addr.v4[0] = 192;
	addr.addr.v4[1] = 168;
	addr.addr.v4[2] = 1;
	addr.addr.v4[3] = 0;
	if (cidr_prefix_from_host(&addr, 32, &out) != CIDR_OK)
		return 1;
	if (out.addr.addr.v4[0] != 192 || out.addr.addr.v4[1] != 168 ||
	    out.addr.addr.v4[2] != 1 || out.addr.addr.v4[3] != 0)
		return 1;

	/*
	 * Exhaustive IPv4 coverage required by TESTING.md §6.2:
	 * verify zeroing for every prefix length 0-32.
	 */
	addr.family = CIDR_AF_INET;
	addr.addr.v4[0] = 203;
	addr.addr.v4[1] = 17;
	addr.addr.v4[2] = 99;
	addr.addr.v4[3] = 255;
	for (uint8_t pfxlen = 0; pfxlen <= 32; pfxlen++) {
		if (cidr_prefix_from_host(&addr, pfxlen, &out) != CIDR_OK)
			return 1;
		if (out.addr.family != CIDR_AF_INET || out.pfxlen != pfxlen)
			return 1;
		if (cidr_prefix_mask(&out, &mask) != CIDR_OK)
			return 1;
		expected_mask_bytes(expected, 4, pfxlen);
		for (size_t i = 0; i < 4; i++) {
			if (mask.addr.v4[i] != expected[i])
				return 1;
			if (out.addr.addr.v4[i] !=
			    (uint8_t)(addr.addr.v4[i] & expected[i]))
				return 1;
		}
	}

	/*
	 * Exhaustive IPv6 coverage required by TESTING.md §6.2:
	 * verify zeroing for every prefix length 0-128.
	 */
	addr.family = CIDR_AF_INET6;
	for (size_t i = 0; i < 16; i++)
		addr.addr.v6[i] = (uint8_t)(0xFFu - (uint8_t)(i * 7u));
	for (int pfxlen = 0; pfxlen <= 128; pfxlen++) {
		if (cidr_prefix_from_host(&addr, (uint8_t)pfxlen, &out) !=
		    CIDR_OK)
			return 1;
		if (out.addr.family != CIDR_AF_INET6 ||
		    out.pfxlen != (uint8_t)pfxlen)
			return 1;
		if (cidr_prefix_mask(&out, &mask) != CIDR_OK)
			return 1;
		expected_mask_bytes(expected, 16, (uint8_t)pfxlen);
		for (size_t i = 0; i < 16; i++) {
			if (mask.addr.v6[i] != expected[i])
				return 1;
			if (out.addr.addr.v6[i] !=
			    (uint8_t)(addr.addr.v6[i] & expected[i]))
				return 1;
		}
	}

	return 0;
}

int
test_prefix_from_host_pfxlen_out_of_range(void)
{
	cidr_addr_t addr;
	cidr_prefix_t out;

	addr.family = CIDR_AF_INET;
	memset(addr.addr.v4, 0, 4);

	if (cidr_prefix_from_host(&addr, 33, &out) != CIDR_ERR_PFXLEN)
		return 1;

	addr.family = CIDR_AF_INET6;
	memset(addr.addr.v6, 0, 16);

	if (cidr_prefix_from_host(&addr, 129, &out) != CIDR_ERR_PFXLEN)
		return 1;

	return 0;
}

int
test_prefix_format_canonical(void)
{
	cidr_prefix_t p;
	char buf[CIDR_PREFIX_STR_MAX];

	if (cidr_prefix_parse("10.0.0.0/8", &p) != CIDR_OK)
		return 1;
	if (cidr_prefix_format(&p, buf, sizeof(buf)) != CIDR_OK)
		return 1;
	if (strcmp(buf, "10.0.0.0/8") != 0)
		return 1;

	if (cidr_prefix_parse("192.168.0.0/24", &p) != CIDR_OK)
		return 1;
	if (cidr_prefix_format(&p, buf, sizeof(buf)) != CIDR_OK)
		return 1;
	if (strcmp(buf, "192.168.0.0/24") != 0)
		return 1;

	if (cidr_prefix_parse("2001:db8::/32", &p) != CIDR_OK)
		return 1;
	if (cidr_prefix_format(&p, buf, sizeof(buf)) != CIDR_OK)
		return 1;
	if (strcmp(buf, "2001:db8::/32") != 0)
		return 1;

	if (cidr_prefix_parse("::/0", &p) != CIDR_OK)
		return 1;
	if (cidr_prefix_format(&p, buf, sizeof(buf)) != CIDR_OK)
		return 1;
	if (strcmp(buf, "::/0") != 0)
		return 1;

	return 0;
}

int
test_prefix_format_buffer_too_small(void)
{
	cidr_prefix_t p;
	char buf[10];

	if (cidr_prefix_parse("10.0.0.0/8", &p) != CIDR_OK)
		return 1;
	if (cidr_prefix_format(&p, buf, 10) != CIDR_ERR_INVAL)
		return 1;

	return 0;
}

int
test_prefix_format_roundtrip(void)
{
	const char *cases[] = {"10.0.0.0/8",
	                       "192.168.0.0/24",
	                       "0.0.0.0/0",
	                       "255.255.255.255/32",
	                       "2001:db8::/32",
	                       "::/0",
	                       "::1/128",
	                       "2001:db8:dead:beef::/64",
	                       NULL};
	char buf[CIDR_PREFIX_STR_MAX];
	cidr_prefix_t p, p2;

	for (int i = 0; cases[i] != NULL; i++) {
		if (cidr_prefix_parse(cases[i], &p) != CIDR_OK)
			return 1;
		if (cidr_prefix_format(&p, buf, sizeof(buf)) != CIDR_OK)
			return 1;
		if (cidr_prefix_parse(buf, &p2) != CIDR_OK)
			return 1;
		/* Compare addr bytes based on family, then pfxlen.
		 * Avoid memcmp on the full struct (union padding). */
		if (p.addr.family != p2.addr.family)
			return 1;
		if (p.pfxlen != p2.pfxlen)
			return 1;
		if (p.addr.family == CIDR_AF_INET) {
			if (memcmp(p.addr.addr.v4, p2.addr.addr.v4, 4) != 0)
				return 1;
		} else {
			if (memcmp(p.addr.addr.v6, p2.addr.addr.v6, 16) != 0)
				return 1;
		}
	}
	return 0;
}

int
test_prefix_broadcast_ipv4(void)
{
	cidr_prefix_t p;
	cidr_addr_t out;

	/* /24: 192.168.1.0/24 -> 192.168.1.255 */
	if (cidr_prefix_parse("192.168.1.0/24", &p) != CIDR_OK)
		return 1;
	if (cidr_prefix_broadcast(&p, &out) != CIDR_OK)
		return 1;
	if (out.family != CIDR_AF_INET)
		return 1;
	if (out.addr.v4[0] != 192 || out.addr.v4[1] != 168 ||
	    out.addr.v4[2] != 1 || out.addr.v4[3] != 255)
		return 1;

	/* /0: 0.0.0.0/0 -> 255.255.255.255 */
	if (cidr_prefix_parse("0.0.0.0/0", &p) != CIDR_OK)
		return 1;
	if (cidr_prefix_broadcast(&p, &out) != CIDR_OK)
		return 1;
	if (out.addr.v4[0] != 255 || out.addr.v4[1] != 255 ||
	    out.addr.v4[2] != 255 || out.addr.v4[3] != 255)
		return 1;

	/* /31: 192.168.1.0/31 -> 192.168.1.1 */
	if (cidr_prefix_parse("192.168.1.0/31", &p) != CIDR_OK)
		return 1;
	if (cidr_prefix_broadcast(&p, &out) != CIDR_OK)
		return 1;
	if (out.addr.v4[3] != 1)
		return 1;

	/* /32: 192.168.1.0/32 -> 192.168.1.0 */
	if (cidr_prefix_parse("192.168.1.0/32", &p) != CIDR_OK)
		return 1;
	if (cidr_prefix_broadcast(&p, &out) != CIDR_OK)
		return 1;
	if (out.addr.v4[3] != 0)
		return 1;

	return 0;
}

int
test_prefix_broadcast_ipv6_family_error(void)
{
	cidr_prefix_t p;
	cidr_addr_t out;

	if (cidr_prefix_parse("2001:db8::/32", &p) != CIDR_OK)
		return 1;
	if (cidr_prefix_broadcast(&p, &out) != CIDR_ERR_FAMILY)
		return 1;

	return 0;
}

int
test_prefix_mask_all_lengths(void)
{
	cidr_prefix_t p;
	cidr_addr_t out;
	uint8_t expected[16];

	/* Exhaustive IPv4 coverage: every prefix length 0-32. */
	if (cidr_prefix_parse("0.0.0.0/0", &p) != CIDR_OK)
		return 1;
	for (int pfxlen = 0; pfxlen <= 32; pfxlen++) {
		p.pfxlen = (uint8_t)pfxlen;
		if (cidr_prefix_mask(&p, &out) != CIDR_OK)
			return 1;
		if (out.family != CIDR_AF_INET)
			return 1;
		expected_mask_bytes(expected, 4, (uint8_t)pfxlen);
		for (size_t i = 0; i < 4; i++) {
			if (out.addr.v4[i] != expected[i])
				return 1;
		}
	}

	/* Exhaustive IPv6 coverage: every prefix length 0-128. */
	if (cidr_prefix_parse("::/0", &p) != CIDR_OK)
		return 1;
	for (int pfxlen = 0; pfxlen <= 128; pfxlen++) {
		p.pfxlen = (uint8_t)pfxlen;
		if (cidr_prefix_mask(&p, &out) != CIDR_OK)
			return 1;
		if (out.family != CIDR_AF_INET6)
			return 1;
		expected_mask_bytes(expected, 16, (uint8_t)pfxlen);
		for (size_t i = 0; i < 16; i++) {
			if (out.addr.v6[i] != expected[i])
				return 1;
		}
	}

	return 0;
}

int
test_prefix_first_last_edge_cases(void)
{
	cidr_prefix_t p;
	cidr_addr_t first, last;

	/* IPv4 /0: first = 0.0.0.0, last = 255.255.255.255 */
	if (cidr_prefix_parse("0.0.0.0/0", &p) != CIDR_OK)
		return 1;
	if (cidr_prefix_first(&p, &first) != CIDR_OK)
		return 1;
	if (cidr_prefix_last(&p, &last) != CIDR_OK)
		return 1;
	if (first.addr.v4[0] != 0 || first.addr.v4[1] != 0 ||
	    first.addr.v4[2] != 0 || first.addr.v4[3] != 0)
		return 1;
	if (last.addr.v4[0] != 255 || last.addr.v4[1] != 255 ||
	    last.addr.v4[2] != 255 || last.addr.v4[3] != 255)
		return 1;

	/* IPv4 /32: first == last */
	if (cidr_prefix_parse("192.168.1.1/32", &p) != CIDR_OK)
		return 1;
	if (cidr_prefix_first(&p, &first) != CIDR_OK)
		return 1;
	if (cidr_prefix_last(&p, &last) != CIDR_OK)
		return 1;
	if (first.family != last.family)
		return 1;
	if (memcmp(first.addr.v4, last.addr.v4, 4) != 0)
		return 1;

	/* IPv6 /0 */
	if (cidr_prefix_parse("::/0", &p) != CIDR_OK)
		return 1;
	if (cidr_prefix_first(&p, &first) != CIDR_OK)
		return 1;
	if (cidr_prefix_last(&p, &last) != CIDR_OK)
		return 1;
	for (int i = 0; i < 16; i++) {
		if (first.addr.v6[i] != 0)
			return 1;
		if (last.addr.v6[i] != 0xFF)
			return 1;
	}

	/* IPv6 /128: first == last */
	if (cidr_prefix_parse("2001:db8::1/128", &p) != CIDR_OK)
		return 1;
	if (cidr_prefix_first(&p, &first) != CIDR_OK)
		return 1;
	if (cidr_prefix_last(&p, &last) != CIDR_OK)
		return 1;
	if (first.family != last.family)
		return 1;
	if (memcmp(first.addr.v6, last.addr.v6, 16) != 0)
		return 1;

	return 0;
}

int
test_prefix_contains_inside(void)
{
	cidr_prefix_t prefix;
	cidr_addr_t addr;
	bool result;

	if (cidr_prefix_parse("192.168.1.0/24", &prefix) != CIDR_OK)
		return 1;

	/* address inside */
	if (cidr_addr_parse("192.168.1.1", &addr) != CIDR_OK)
		return 1;
	if (cidr_prefix_contains(&prefix, &addr, &result) != CIDR_OK)
		return 1;
	if (!result)
		return 1;

	/* network address */
	if (cidr_addr_parse("192.168.1.0", &addr) != CIDR_OK)
		return 1;
	if (cidr_prefix_contains(&prefix, &addr, &result) != CIDR_OK)
		return 1;
	if (!result)
		return 1;

	/* broadcast address */
	if (cidr_addr_parse("192.168.1.255", &addr) != CIDR_OK)
		return 1;
	if (cidr_prefix_contains(&prefix, &addr, &result) != CIDR_OK)
		return 1;
	if (!result)
		return 1;

	/* IPv6 inside */
	if (cidr_prefix_parse("2001:db8::/32", &prefix) != CIDR_OK)
		return 1;
	if (cidr_addr_parse("2001:db8::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_prefix_contains(&prefix, &addr, &result) != CIDR_OK)
		return 1;
	if (!result)
		return 1;

	return 0;
}

int
test_prefix_contains_outside(void)
{
	cidr_prefix_t prefix;
	cidr_addr_t addr;
	bool result;

	if (cidr_prefix_parse("192.168.1.0/24", &prefix) != CIDR_OK)
		return 1;

	/* address outside */
	if (cidr_addr_parse("192.168.2.1", &addr) != CIDR_OK)
		return 1;
	if (cidr_prefix_contains(&prefix, &addr, &result) != CIDR_OK)
		return 1;
	if (result)
		return 1;

	/* address before */
	if (cidr_addr_parse("192.168.0.255", &addr) != CIDR_OK)
		return 1;
	if (cidr_prefix_contains(&prefix, &addr, &result) != CIDR_OK)
		return 1;
	if (result)
		return 1;

	return 0;
}

int
test_prefix_contains_null_out(void)
{
	cidr_prefix_t prefix;
	cidr_addr_t addr;

	if (cidr_prefix_parse("10.0.0.0/8", &prefix) != CIDR_OK)
		return 1;
	if (cidr_addr_parse("10.0.0.1", &addr) != CIDR_OK)
		return 1;

	/* NULL out is valid; returns CIDR_OK */
	if (cidr_prefix_contains(&prefix, &addr, NULL) != CIDR_OK)
		return 1;

	return 0;
}

int
test_prefix_contains_family_mismatch(void)
{
	cidr_prefix_t prefix;
	cidr_addr_t addr;
	bool result;

	if (cidr_prefix_parse("192.168.0.0/16", &prefix) != CIDR_OK)
		return 1;
	if (cidr_addr_parse("2001:db8::1", &addr) != CIDR_OK)
		return 1;

	if (cidr_prefix_contains(&prefix, &addr, &result) != CIDR_ERR_FAMILY)
		return 1;

	return 0;
}

int
test_prefix_overlaps_disjoint(void)
{
	cidr_prefix_t a, b;
	bool result;

	if (cidr_prefix_parse("192.168.0.0/24", &a) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("10.0.0.0/8", &b) != CIDR_OK)
		return 1;

	if (cidr_prefix_overlaps(&a, &b, &result) != CIDR_OK)
		return 1;
	if (result)
		return 1;

	return 0;
}

int
test_prefix_overlaps_adjacent(void)
{
	cidr_prefix_t a, b;
	bool result;

	/* Adjacent /24s: 192.168.0.0/24 and 192.168.1.0/24 */
	if (cidr_prefix_parse("192.168.0.0/24", &a) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("192.168.1.0/24", &b) != CIDR_OK)
		return 1;

	if (cidr_prefix_overlaps(&a, &b, &result) != CIDR_OK)
		return 1;
	if (result)
		return 1;

	return 0;
}

int
test_prefix_overlaps_partial(void)
{
	cidr_prefix_t a, b;
	bool result;

	/* 10.0.0.0/16 and 10.0.128.0/17 overlap */
	if (cidr_prefix_parse("10.0.0.0/16", &a) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("10.0.128.0/17", &b) != CIDR_OK)
		return 1;

	if (cidr_prefix_overlaps(&a, &b, &result) != CIDR_OK)
		return 1;
	if (!result)
		return 1;

	return 0;
}

int
test_prefix_overlaps_containment(void)
{
	cidr_prefix_t a, b;
	bool result;

	/* /8 contains /16 */
	if (cidr_prefix_parse("10.0.0.0/8", &a) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("10.1.0.0/16", &b) != CIDR_OK)
		return 1;

	if (cidr_prefix_overlaps(&a, &b, &result) != CIDR_OK)
		return 1;
	if (!result)
		return 1;

	return 0;
}

int
test_prefix_overlaps_identical(void)
{
	cidr_prefix_t a, b;
	bool result;

	if (cidr_prefix_parse("192.168.0.0/24", &a) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("192.168.0.0/24", &b) != CIDR_OK)
		return 1;

	if (cidr_prefix_overlaps(&a, &b, &result) != CIDR_OK)
		return 1;
	if (!result)
		return 1;

	return 0;
}

int
test_prefix_supernet_chain(void)
{
	cidr_prefix_t p, out;

	/* Chain from /32 down to /0 */
	if (cidr_prefix_parse("192.168.1.0/32", &p) != CIDR_OK)
		return 1;

	uint8_t expected_pfxlen[] = {31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21,
	                             20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10,
	                             9,  8,  7,  6,  5,  4,  3,  2,  1,  0};

	for (size_t i = 0; i < sizeof(expected_pfxlen); i++) {
		if (cidr_prefix_supernet(&p, &out) != CIDR_OK)
			return 1;
		if (out.pfxlen != expected_pfxlen[i])
			return 1;
		p = out;
	}

	/* /0 should still be 0.0.0.0 */
	if (out.addr.addr.v4[0] != 0 || out.addr.addr.v4[1] != 0 ||
	    out.addr.addr.v4[2] != 0 || out.addr.addr.v4[3] != 0)
		return 1;

	return 0;
}

int
test_prefix_supernet_overflow(void)
{
	cidr_prefix_t p, out;

	if (cidr_prefix_parse("0.0.0.0/0", &p) != CIDR_OK)
		return 1;
	if (cidr_prefix_supernet(&p, &out) != CIDR_ERR_OVERFLOW)
		return 1;

	/* IPv6 */
	if (cidr_prefix_parse("::/0", &p) != CIDR_OK)
		return 1;
	if (cidr_prefix_supernet(&p, &out) != CIDR_ERR_OVERFLOW)
		return 1;

	return 0;
}

int
test_subnet_iter_correct_count(void)
{
	cidr_prefix_t p;
	cidr_subnet_iter_t iter;
	cidr_prefix_t subnet;
	cidr_err_t rc;
	int count = 0;

	/* 10.0.0.0/24 -> /28: 2^(28-24) = 16 subnets */
	if (cidr_prefix_parse("10.0.0.0/24", &p) != CIDR_OK)
		return 1;
	if (cidr_subnet_iter_init(&iter, &p, 28) != CIDR_OK)
		return 1;

	while ((rc = cidr_subnet_iter_next(&iter, &subnet)) == CIDR_OK)
		count++;
	if (rc != CIDR_ERR_DONE)
		return 1;
	if (count != 16)
		return 1;

	/* 10.0.0.0/25 -> /26: 2 subnets */
	if (cidr_prefix_parse("10.0.0.0/25", &p) != CIDR_OK)
		return 1;
	if (cidr_subnet_iter_init(&iter, &p, 26) != CIDR_OK)
		return 1;

	count = 0;
	while ((rc = cidr_subnet_iter_next(&iter, &subnet)) == CIDR_OK)
		count++;
	if (rc != CIDR_ERR_DONE)
		return 1;
	if (count != 2)
		return 1;

	/* IPv6: 2001:db8::/32 -> /36: 16 subnets */
	if (cidr_prefix_parse("2001:db8::/32", &p) != CIDR_OK)
		return 1;
	if (cidr_subnet_iter_init(&iter, &p, 36) != CIDR_OK)
		return 1;

	count = 0;
	while ((rc = cidr_subnet_iter_next(&iter, &subnet)) == CIDR_OK)
		count++;
	if (rc != CIDR_ERR_DONE)
		return 1;
	if (count != 16)
		return 1;

	/* IPv4: 0.0.0.0/0 -> /1 yields 2 subnets */
	if (cidr_prefix_parse("0.0.0.0/0", &p) != CIDR_OK)
		return 1;
	if (cidr_subnet_iter_init(&iter, &p, 1) != CIDR_OK)
		return 1;

	count = 0;
	while ((rc = cidr_subnet_iter_next(&iter, &subnet)) == CIDR_OK)
		count++;
	if (rc != CIDR_ERR_DONE)
		return 1;
	if (count != 2)
		return 1;

	/* IPv6: ::/0 -> /1 yields 2 subnets */
	if (cidr_prefix_parse("::/0", &p) != CIDR_OK)
		return 1;
	if (cidr_subnet_iter_init(&iter, &p, 1) != CIDR_OK)
		return 1;

	count = 0;
	while ((rc = cidr_subnet_iter_next(&iter, &subnet)) == CIDR_OK)
		count++;
	if (rc != CIDR_ERR_DONE)
		return 1;
	if (count != 2)
		return 1;

	return 0;
}

int
test_subnet_iter_ascending_order(void)
{
	cidr_prefix_t p;
	cidr_subnet_iter_t iter;
	cidr_prefix_t prev, curr;
	cidr_err_t rc;
	int first = 1;

	/* Enumerate /25 subnets of 10.0.0.0/23 -> 4 subnets */
	if (cidr_prefix_parse("10.0.0.0/23", &p) != CIDR_OK)
		return 1;
	if (cidr_subnet_iter_init(&iter, &p, 25) != CIDR_OK)
		return 1;

	while ((rc = cidr_subnet_iter_next(&iter, &curr)) == CIDR_OK) {
		if (!first) {
			/* Each subnet must be strictly greater than previous.
			 * Compare address bytes based on family (union padding
			 * is uninitialized for the inactive member). */
			if (curr.addr.family != prev.addr.family)
				return 1;
			if (curr.addr.family == CIDR_AF_INET) {
				if (memcmp(curr.addr.addr.v4, prev.addr.addr.v4,
				           4) <= 0)
					return 1;
			} else {
				if (memcmp(curr.addr.addr.v6, prev.addr.addr.v6,
				           16) <= 0)
					return 1;
			}
		}
		prev = curr;
		first = 0;
	}
	if (rc != CIDR_ERR_DONE)
		return 1;
	if (first)
		return 1; /* at least one subnet yielded */

	return 0;
}

int
test_subnet_iter_first_equals_parent_network(void)
{
	cidr_prefix_t p;
	cidr_subnet_iter_t iter;
	cidr_prefix_t subnet;
	cidr_err_t rc;

	if (cidr_prefix_parse("10.0.0.0/24", &p) != CIDR_OK)
		return 1;
	if (cidr_subnet_iter_init(&iter, &p, 28) != CIDR_OK)
		return 1;

	rc = cidr_subnet_iter_next(&iter, &subnet);
	if (rc != CIDR_OK)
		return 1;

	/* First subnet must have the same network address as the parent.
	 * Compare address bytes based on family (union padding is
	 * uninitialized for the inactive member). */
	if (subnet.addr.family != p.addr.family)
		return 1;
	if (subnet.addr.family == CIDR_AF_INET) {
		if (memcmp(subnet.addr.addr.v4, p.addr.addr.v4, 4) != 0)
			return 1;
	} else {
		if (memcmp(subnet.addr.addr.v6, p.addr.addr.v6, 16) != 0)
			return 1;
	}

	return 0;
}

int
test_subnet_iter_early_termination(void)
{
	cidr_prefix_t p;
	cidr_subnet_iter_t iter;
	cidr_prefix_t subnet;
	cidr_err_t rc;
	int count = 0;

	/* Enumerate /28 subnets of 10.0.0.0/24, break after 3 */
	if (cidr_prefix_parse("10.0.0.0/24", &p) != CIDR_OK)
		return 1;
	if (cidr_subnet_iter_init(&iter, &p, 28) != CIDR_OK)
		return 1;

	while ((rc = cidr_subnet_iter_next(&iter, &subnet)) == CIDR_OK) {
		count++;
		if (count >= 3)
			break;
	}

	if (count != 3)
		return 1;

	/* Iterator state still valid; no cleanup needed */
	return 0;
}

int
test_subnet_iter_done_out_not_modified(void)
{
	cidr_prefix_t p;
	cidr_subnet_iter_t iter;
	cidr_prefix_t subnet, last_subnet;
	cidr_err_t rc;

	/* /30 -> /31: 2 subnets */
	if (cidr_prefix_parse("10.0.0.0/30", &p) != CIDR_OK)
		return 1;
	if (cidr_subnet_iter_init(&iter, &p, 31) != CIDR_OK)
		return 1;

	/* Exhaust the iterator */
	rc = cidr_subnet_iter_next(&iter, &subnet);
	if (rc != CIDR_OK)
		return 1;
	last_subnet = subnet;

	rc = cidr_subnet_iter_next(&iter, &subnet);
	if (rc != CIDR_OK)
		return 1;
	last_subnet = subnet;

	/* Third call should return CIDR_ERR_DONE; out not modified */
	rc = cidr_subnet_iter_next(&iter, &subnet);
	if (rc != CIDR_ERR_DONE)
		return 1;

	/* On CIDR_ERR_DONE, out must not be modified.
	 * Compare fields individually to avoid uninitialised padding
	 * in cidr_prefix_t (3 trailing bytes) and in the addr union
	 * (inactive member). */
	if (subnet.addr.family != last_subnet.addr.family)
		return 1;
	if (subnet.pfxlen != last_subnet.pfxlen)
		return 1;
	if (subnet.addr.family == CIDR_AF_INET) {
		if (memcmp(subnet.addr.addr.v4, last_subnet.addr.addr.v4, 4) !=
		    0)
			return 1;
	} else {
		if (memcmp(subnet.addr.addr.v6, last_subnet.addr.addr.v6, 16) !=
		    0)
			return 1;
	}

	return 0;
}

int
test_subnet_iter_pfxlen_invalid(void)
{
	cidr_prefix_t p;
	cidr_subnet_iter_t iter;

	if (cidr_prefix_parse("10.0.0.0/24", &p) != CIDR_OK)
		return 1;

	/* target_pfxlen == prefix_pfxlen -> CIDR_ERR_PFXLEN */
	if (cidr_subnet_iter_init(&iter, &p, 24) != CIDR_ERR_PFXLEN)
		return 1;

	/* target_pfxlen < prefix_pfxlen -> CIDR_ERR_PFXLEN */
	if (cidr_subnet_iter_init(&iter, &p, 20) != CIDR_ERR_PFXLEN)
		return 1;

	/* target_pfxlen > max for family -> CIDR_ERR_PFXLEN */
	if (cidr_subnet_iter_init(&iter, &p, 33) != CIDR_ERR_PFXLEN)
		return 1;

	/* IPv6: target_pfxlen > 128 */
	if (cidr_prefix_parse("2001:db8::/32", &p) != CIDR_OK)
		return 1;
	if (cidr_subnet_iter_init(&iter, &p, 129) != CIDR_ERR_PFXLEN)
		return 1;

	return 0;
}

int
test_prefix_cmp_ordering(void)
{
	cidr_prefix_t a, b;
	int result;

	/* Different network addresses: 10.0.0.0/8 vs 192.168.0.0/16 */
	if (cidr_prefix_parse("10.0.0.0/8", &a) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("192.168.0.0/16", &b) != CIDR_OK)
		return 1;

	if (cidr_prefix_cmp(&a, &b, &result) != CIDR_OK)
		return 1;
	if (result >= 0)
		return 1; /* 10.0.0.0 < 192.168.0.0 */

	if (cidr_prefix_cmp(&b, &a, &result) != CIDR_OK)
		return 1;
	if (result <= 0)
		return 1; /* 192.168.0.0 > 10.0.0.0 */

	/* Same network, different prefix lengths: 10.0.0.0/8 vs 10.0.0.0/16
	 * CIDR_SORT_NETWORK_ASC: same network -> pfxlen ascending */
	if (cidr_prefix_parse("10.0.0.0/8", &a) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("10.0.0.0/16", &b) != CIDR_OK)
		return 1;

	if (cidr_prefix_cmp(&a, &b, &result) != CIDR_OK)
		return 1;
	if (result >= 0)
		return 1; /* /8 < /16 */

	if (cidr_prefix_cmp(&b, &a, &result) != CIDR_OK)
		return 1;
	if (result <= 0)
		return 1; /* /16 > /8 */

	/* IPv6 ordering */
	if (cidr_prefix_parse("2001:db8::/32", &a) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("2001:db8:1::/48", &b) != CIDR_OK)
		return 1;

	if (cidr_prefix_cmp(&a, &b, &result) != CIDR_OK)
		return 1;
	if (result >= 0)
		return 1; /* 2001:db8:: < 2001:db8:1:: */

	return 0;
}

int
test_prefix_cmp_equal(void)
{
	cidr_prefix_t a, b;
	int result;

	if (cidr_prefix_parse("192.168.0.0/24", &a) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("192.168.0.0/24", &b) != CIDR_OK)
		return 1;

	if (cidr_prefix_cmp(&a, &b, &result) != CIDR_OK)
		return 1;
	if (result != 0)
		return 1;

	/* IPv6 */
	if (cidr_prefix_parse("2001:db8::/32", &a) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("2001:db8::/32", &b) != CIDR_OK)
		return 1;

	if (cidr_prefix_cmp(&a, &b, &result) != CIDR_OK)
		return 1;
	if (result != 0)
		return 1;

	return 0;
}

int
test_prefix_cmp_family_mismatch(void)
{
	cidr_prefix_t a, b;
	int result;

	if (cidr_prefix_parse("10.0.0.0/8", &a) != CIDR_OK)
		return 1;
	if (cidr_prefix_parse("2001:db8::/32", &b) != CIDR_OK)
		return 1;

	if (cidr_prefix_cmp(&a, &b, &result) != CIDR_ERR_FAMILY)
		return 1;

	return 0;
}
