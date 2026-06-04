/*
 * test_addr.c - address parsing, formatting, IPv4-mapped extraction,
 *               and address comparison tests.
 *
 * See DEVELOPMENT.md §Phase 2 for the required test cases.
 * See TESTING.md §3.1 for IPv4 parsing conformance tests.
 * See TESTING.md §3.2 for IPv6 parsing conformance tests.
 */

#include <string.h>

#include "../include/libcidr.h"

/*
 * test_ipv4_parse_valid - representative valid inputs and boundary
 * addresses per TESTING.md §3.1.
 */
int test_ipv4_parse_valid(void)
{
	cidr_addr_t out;

	if (cidr_addr_parse("192.168.1.1", &out) != CIDR_OK)
		return 1;
	if (out.family != CIDR_AF_INET)
		return 1;
	if (out.addr.v4[0] != 192 || out.addr.v4[1] != 168 ||
	    out.addr.v4[2] != 1 || out.addr.v4[3] != 1)
		return 1;

	if (cidr_addr_parse("0.0.0.0", &out) != CIDR_OK)
		return 1;
	if (out.addr.v4[0] != 0 || out.addr.v4[1] != 0 || out.addr.v4[2] != 0 ||
	    out.addr.v4[3] != 0)
		return 1;

	if (cidr_addr_parse("255.255.255.255", &out) != CIDR_OK)
		return 1;
	if (out.addr.v4[0] != 255 || out.addr.v4[1] != 255 ||
	    out.addr.v4[2] != 255 || out.addr.v4[3] != 255)
		return 1;

	if (cidr_addr_parse("10.0.0.1", &out) != CIDR_OK)
		return 1;
	if (out.addr.v4[0] != 10 || out.addr.v4[1] != 0 ||
	    out.addr.v4[2] != 0 || out.addr.v4[3] != 1)
		return 1;

	if (cidr_addr_parse("172.16.0.1", &out) != CIDR_OK)
		return 1;
	if (cidr_addr_parse("127.0.0.1", &out) != CIDR_OK)
		return 1;
	if (cidr_addr_parse("1.1.1.1", &out) != CIDR_OK)
		return 1;
	if (cidr_addr_parse("224.0.0.1", &out) != CIDR_OK)
		return 1;

	return 0;
}

/*
 * test_ipv4_parse_leading_zero - reject leading zeros per TESTING.md §3.1.
 * Leading zeros are ambiguous (some parsers treat them as octal)
 * and are rejected by the strict parser. See ARCHITECTURE.md §4.1.1.
 */
int test_ipv4_parse_leading_zero(void)
{
	cidr_addr_t out;

	if (cidr_addr_parse("192.168.01.1", &out) != CIDR_ERR_PARSE)
		return 1;
	if (cidr_addr_parse("010.0.0.1", &out) != CIDR_ERR_PARSE)
		return 1;
	if (cidr_addr_parse("0.0.0.00", &out) != CIDR_ERR_PARSE)
		return 1;
	if (cidr_addr_parse("01.02.03.04", &out) != CIDR_ERR_PARSE)
		return 1;

	return 0;
}

/*
 * test_ipv4_parse_hex - reject hex notation per TESTING.md §3.1.
 */
int test_ipv4_parse_hex(void)
{
	cidr_addr_t out;

	if (cidr_addr_parse("0xc0.0xa8.0x01.0x01", &out) != CIDR_ERR_PARSE)
		return 1;
	if (cidr_addr_parse("0x10.0.0.1", &out) != CIDR_ERR_PARSE)
		return 1;
	if (cidr_addr_parse("C0.A8.01.01", &out) != CIDR_ERR_PARSE)
		return 1;

	return 0;
}

/*
 * test_ipv4_parse_out_of_range - reject octet values exceeding 255
 * per TESTING.md §3.1.
 */
int test_ipv4_parse_out_of_range(void)
{
	cidr_addr_t out;

	if (cidr_addr_parse("256.0.0.1", &out) != CIDR_ERR_PARSE)
		return 1;
	if (cidr_addr_parse("192.168.1.300", &out) != CIDR_ERR_PARSE)
		return 1;
	if (cidr_addr_parse("999.999.999.999", &out) != CIDR_ERR_PARSE)
		return 1;

	return 0;
}

/*
 * test_ipv4_parse_wrong_count - reject fewer or more than four octets
 * per TESTING.md §3.1.
 */
int test_ipv4_parse_wrong_count(void)
{
	cidr_addr_t out;

	if (cidr_addr_parse("192.168.1", &out) != CIDR_ERR_PARSE)
		return 1;
	if (cidr_addr_parse("1.2.3.4.5", &out) != CIDR_ERR_PARSE)
		return 1;
	if (cidr_addr_parse("1", &out) != CIDR_ERR_PARSE)
		return 1;
	if (cidr_addr_parse("192.168", &out) != CIDR_ERR_PARSE)
		return 1;

	return 0;
}

/*
 * test_ipv4_parse_whitespace - reject leading and trailing whitespace
 * per TESTING.md §3.1.
 */
int test_ipv4_parse_whitespace(void)
{
	cidr_addr_t out;

	if (cidr_addr_parse(" 192.168.1.1", &out) != CIDR_ERR_PARSE)
		return 1;
	if (cidr_addr_parse("192.168.1.1 ", &out) != CIDR_ERR_PARSE)
		return 1;
	if (cidr_addr_parse("\t192.168.1.1", &out) != CIDR_ERR_PARSE)
		return 1;

	return 0;
}

/*
 * test_ipv4_parse_trailing_chars - reject characters after the
 * final octet per TESTING.md §3.1.
 */
int test_ipv4_parse_trailing_chars(void)
{
	cidr_addr_t out;

	if (cidr_addr_parse("192.168.1.1/", &out) != CIDR_ERR_PARSE)
		return 1;
	if (cidr_addr_parse("192.168.1.1x", &out) != CIDR_ERR_PARSE)
		return 1;
	if (cidr_addr_parse("192.168.1.1\n", &out) != CIDR_ERR_PARSE)
		return 1;
	if (cidr_addr_parse("192.168.1.1.", &out) != CIDR_ERR_PARSE)
		return 1;

	return 0;
}

/*
 * test_ipv4_parse_null - verify CIDR_ERR_INVAL for NULL pointers
 * per TESTING.md §3.1 and ARCHITECTURE.md §4.1.1.
 */
int test_ipv4_parse_null(void)
{
	cidr_addr_t out;

	if (cidr_addr_parse(NULL, &out) != CIDR_ERR_INVAL)
		return 1;
	if (cidr_addr_parse("192.168.1.1", NULL) != CIDR_ERR_INVAL)
		return 1;
	if (cidr_addr_parse(NULL, NULL) != CIDR_ERR_INVAL)
		return 1;

	return 0;
}

/*
 * test_ipv6_parse_full_form - verify that the full 8-group form
 * is accepted per RFC 4291 §2.2. See TESTING.md §3.2.
 */
int test_ipv6_parse_full_form(void)
{
	cidr_addr_t out;
	uint8_t expected[16] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
	                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

	if (cidr_addr_parse("2001:0db8:0000:0000:0000:0000:0000:0001", &out) !=
	    CIDR_OK)
		return 1;
	if (out.family != CIDR_AF_INET6)
		return 1;
	if (memcmp(out.addr.v6, expected, 16) != 0)
		return 1;

	if (cidr_addr_parse("2001:db8:0:0:0:0:0:1", &out) != CIDR_OK)
		return 1;
	if (out.family != CIDR_AF_INET6)
		return 1;

	if (cidr_addr_parse("fe80:0:0:0:0:0:0:1", &out) != CIDR_OK)
		return 1;

	if (cidr_addr_parse("ff02:0:0:0:0:0:0:1", &out) != CIDR_OK)
		return 1;

	return 0;
}

/*
 * test_ipv6_parse_compressed - verify that :: compression at
 * various positions is accepted. See TESTING.md §3.2.
 */
int test_ipv6_parse_compressed(void)
{
	cidr_addr_t out;
	uint8_t expect_loopback[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	                               0x00, 0x00, 0x00, 0x01};
	uint8_t expect_unspec[16] = {0};

	/* :: at end */
	if (cidr_addr_parse("2001:db8::", &out) != CIDR_OK)
		return 1;
	if (out.family != CIDR_AF_INET6)
		return 1;
	if (out.addr.v6[0] != 0x20 || out.addr.v6[1] != 0x01 ||
	    out.addr.v6[2] != 0x0d || out.addr.v6[3] != 0xb8)
		return 1;

	/* :: at start */
	if (cidr_addr_parse("::1", &out) != CIDR_OK)
		return 1;
	if (memcmp(out.addr.v6, expect_loopback, 16) != 0)
		return 1;

	/* :: alone (unspecified address) */
	if (cidr_addr_parse("::", &out) != CIDR_OK)
		return 1;
	if (memcmp(out.addr.v6, expect_unspec, 16) != 0)
		return 1;

	/* :: in middle */
	if (cidr_addr_parse("fe80::1", &out) != CIDR_OK)
		return 1;
	if (out.family != CIDR_AF_INET6)
		return 1;

	/* :: after prefix */
	if (cidr_addr_parse("2001:db8:85a3::8a2e:370:7334", &out) != CIDR_OK)
		return 1;

	return 0;
}

/*
 * test_ipv6_parse_double_colon_once - reject :: appearing more than
 * once. See TESTING.md §3.2, RFC 4291 §2.2.
 */
int test_ipv6_parse_double_colon_once(void)
{
	cidr_addr_t out;

	if (cidr_addr_parse("2001::db8::1", &out) != CIDR_ERR_PARSE)
		return 1;
	if (cidr_addr_parse("::1::", &out) != CIDR_ERR_PARSE)
		return 1;

	return 0;
}

/*
 * test_ipv6_parse_uppercase_normalised - verify that uppercase
 * hex input is accepted and stored as correct binary values.
 * See TESTING.md §3.2, RFC 5952 §4.3.
 */
int test_ipv6_parse_uppercase_normalised(void)
{
	cidr_addr_t out;
	uint8_t expected[16] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
	                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

	/* all uppercase */
	if (cidr_addr_parse("2001:0DB8:0000:0000:0000:0000:0000:0001", &out) !=
	    CIDR_OK)
		return 1;
	if (memcmp(out.addr.v6, expected, 16) != 0)
		return 1;

	/* mixed case */
	if (cidr_addr_parse("2001:DB8::1", &out) != CIDR_OK)
		return 1;
	if (out.family != CIDR_AF_INET6)
		return 1;

	/* all uppercase compressed */
	if (cidr_addr_parse("ABCD::EF01", &out) != CIDR_OK)
		return 1;
	if (out.addr.v6[0] != 0xAB || out.addr.v6[1] != 0xCD)
		return 1;
	if (out.addr.v6[14] != 0xEF || out.addr.v6[15] != 0x01)
		return 1;

	return 0;
}

/*
 * test_ipv6_parse_mixed_mapped - verify that ::ffff:x.x.x.x mixed
 * notation is accepted for IPv4-mapped addresses.
 * See TESTING.md §3.2, RFC 5952 §5.
 */
int test_ipv6_parse_mixed_mapped(void)
{
	cidr_addr_t out;

	/* ::ffff:192.0.2.1 */
	if (cidr_addr_parse("::ffff:192.0.2.1", &out) != CIDR_OK)
		return 1;
	if (out.family != CIDR_AF_INET6)
		return 1;
	if (out.addr.v6[10] != 0xFF || out.addr.v6[11] != 0xFF)
		return 1;
	if (out.addr.v6[12] != 192 || out.addr.v6[13] != 0 ||
	    out.addr.v6[14] != 2 || out.addr.v6[15] != 1)
		return 1;

	/* ::ffff:0:0 without mixed form goes through pure IPv6 path */
	if (cidr_addr_parse("::ffff:0:0", &out) != CIDR_OK)
		return 1;
	if (out.family != CIDR_AF_INET6)
		return 1;

	return 0;
}

/*
 * test_ipv6_parse_mixed_non_mapped - reject mixed notation where
 * the hex prefix does NOT match the IPv4-mapped prefix.
 * See TESTING.md §3.2, RFC 5952 §5.
 */
int test_ipv6_parse_mixed_non_mapped(void)
{
	cidr_addr_t out;

	if (cidr_addr_parse("2001:db8::192.0.2.1", &out) != CIDR_ERR_PARSE)
		return 1;
	if (cidr_addr_parse("fe80::192.0.2.1", &out) != CIDR_ERR_PARSE)
		return 1;

	return 0;
}

/*
 * test_ipv6_parse_compatible_rejected - reject IPv4-compatible
 * addresses per RFC 4291 §2.5.5.1 deprecation.
 * ::x.x.x.x where x.x.x.x != 0.0.0.0.
 * See TESTING.md §3.2.
 */
int test_ipv6_parse_compatible_rejected(void)
{
	cidr_addr_t out;

	/* ::192.0.2.1 -- IPv4-compatible, deprecated */
	if (cidr_addr_parse("::192.0.2.1", &out) != CIDR_ERR_PARSE)
		return 1;
	if (cidr_addr_parse("::10.0.0.1", &out) != CIDR_ERR_PARSE)
		return 1;

	return 0;
}

/*
 * test_ipv6_parse_wrong_group_count - reject too many or too few
 * hex groups. See TESTING.md §3.2.
 */
int test_ipv6_parse_wrong_group_count(void)
{
	cidr_addr_t out;

	/* 9 groups -- too many */
	if (cidr_addr_parse("2001:db8:1:2:3:4:5:6:7", &out) != CIDR_ERR_PARSE)
		return 1;

	/* 7 groups, no :: */
	if (cidr_addr_parse("2001:db8:1:2:3:4:5", &out) != CIDR_ERR_PARSE)
		return 1;

	/* :: with 8 explicit groups -- no room for expansion */
	if (cidr_addr_parse("1:2:3:4:5:6:7::8", &out) != CIDR_ERR_PARSE)
		return 1;

	/* single group, no :: */
	if (cidr_addr_parse("2001", &out) != CIDR_ERR_PARSE)
		return 1;

	/* empty after :: yields too many groups */
	if (cidr_addr_parse("1:2:3:4:5:6:7:8::", &out) != CIDR_ERR_PARSE)
		return 1;

	return 0;
}

/*
 * test_ipv6_parse_group_too_large - reject hex group values
 * exceeding 0xFFFF (16-bit range). See TESTING.md §3.2.
 */
int test_ipv6_parse_group_too_large(void)
{
	cidr_addr_t out;

	if (cidr_addr_parse("2001:fffff::1", &out) != CIDR_ERR_PARSE)
		return 1;
	if (cidr_addr_parse("::10000", &out) != CIDR_ERR_PARSE)
		return 1;

	return 0;
}

/*
 * test_ipv6_parse_invalid_chars - reject inputs with invalid
 * characters in the hex part.
 */
int test_ipv6_parse_invalid_chars(void)
{
	cidr_addr_t out;

	if (cidr_addr_parse("2001:db8::g001", &out) != CIDR_ERR_PARSE)
		return 1;
	if (cidr_addr_parse("2001:db8::-1", &out) != CIDR_ERR_PARSE)
		return 1;
	if (cidr_addr_parse(":::", &out) != CIDR_ERR_PARSE)
		return 1;

	return 0;
}
