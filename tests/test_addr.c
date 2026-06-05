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

/*
 * test_ipv4_format_canonical - verify IPv4 formatting produces
 * correct dotted-decimal with no leading zeros.
 * See TESTING.md §3.3, ARCHITECTURE.md §4.2.1.
 */
int test_ipv4_format_canonical(void)
{
	static const struct {
		const char *input;
		const char *expected;
	} cases[] = {
	    {"192.168.1.1", "192.168.1.1"},
	    {"0.0.0.0", "0.0.0.0"},
	    {"255.255.255.255", "255.255.255.255"},
	    {"10.0.0.1", "10.0.0.1"},
	    {"127.0.0.1", "127.0.0.1"},
	    {"1.1.1.1", "1.1.1.1"},
	    {"172.16.0.1", "172.16.0.1"},
	    {"8.8.8.8", "8.8.8.8"},
	    {"224.0.0.1", "224.0.0.1"},
	};
	const int ncases = sizeof(cases) / sizeof(cases[0]);
	char buf[CIDR_ADDR_STR_MAX];
	cidr_addr_t addr;
	int i;

	for (i = 0; i < ncases; i++) {
		if (cidr_addr_parse(cases[i].input, &addr) != CIDR_OK)
			return 1;
		if (cidr_addr_format(&addr, buf, sizeof(buf)) != CIDR_OK)
			return 1;
		if (strcmp(buf, cases[i].expected) != 0)
			return 1;
	}
	return 0;
}

/*
 * test_ipv4_format_roundtrip - verify parse/format/parse produces
 * bit-identical bytes. See TESTING.md §6.1.
 */
int test_ipv4_format_roundtrip(void)
{
	static const char *cases[] = {
	    "192.168.1.1", "0.0.0.0", "255.255.255.255", "10.0.0.1",
	    "127.0.0.1",   "1.1.1.1", "172.16.0.1",      NULL};
	char buf[CIDR_ADDR_STR_MAX];
	cidr_addr_t addr = {0}, addr2 = {0};
	int i;

	for (i = 0; cases[i] != NULL; i++) {
		if (cidr_addr_parse(cases[i], &addr) != CIDR_OK)
			return 1;
		if (cidr_addr_format(&addr, buf, sizeof(buf)) != CIDR_OK)
			return 1;
		if (cidr_addr_parse(buf, &addr2) != CIDR_OK)
			return 1;
		if (memcmp(&addr, &addr2, sizeof(addr)) != 0)
			return 1;
	}
	return 0;
}

/*
 * test_ipv6_format_rfc5952_leading_zeros - verify leading zeros
 * are suppressed per RFC 5952 §4.1.
 * See TESTING.md §3.3, ARCHITECTURE.md §4.2.2 rule 1.
 */
int test_ipv6_format_rfc5952_leading_zeros(void)
{
	static const struct {
		const char *input;
		const char *expected;
	} cases[] = {
	    {"2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"},
	    {"2001:0db8::0001", "2001:db8::1"},
	    {"0000:0000:0000:0000:0000:0000:0000:0001", "::1"},
	};
	const int ncases = sizeof(cases) / sizeof(cases[0]);
	char buf[CIDR_ADDR_STR_MAX];
	cidr_addr_t addr;
	int i;

	for (i = 0; i < ncases; i++) {
		if (cidr_addr_parse(cases[i].input, &addr) != CIDR_OK)
			return 1;
		if (cidr_addr_format(&addr, buf, sizeof(buf)) != CIDR_OK)
			return 1;
		if (strcmp(buf, cases[i].expected) != 0)
			return 1;
	}
	return 0;
}

/*
 * test_ipv6_format_rfc5952_compress_longest - verify the longest
 * run of consecutive zero groups is compressed with ::.
 * See TESTING.md §3.3, RFC 5952 §4.2.1, ARCHITECTURE.md §4.2.2 rule 2.
 */
int test_ipv6_format_rfc5952_compress_longest(void)
{
	static const struct {
		const char *input;
		const char *expected;
	} cases[] = {
	    {"2001:0:0:0:0:0:0:1", "2001::1"},
	    {"2001:db8:0:0:0:0:0:1", "2001:db8::1"},
	    {"fe80:0:0:0:0:0:0:1", "fe80::1"},
	    {"0:0:0:0:0:0:0:1", "::1"},
	    {"0:0:0:0:0:0:0:0", "::"},
	};
	const int ncases = sizeof(cases) / sizeof(cases[0]);
	char buf[CIDR_ADDR_STR_MAX];
	cidr_addr_t addr;
	int i;

	for (i = 0; i < ncases; i++) {
		if (cidr_addr_parse(cases[i].input, &addr) != CIDR_OK)
			return 1;
		if (cidr_addr_format(&addr, buf, sizeof(buf)) != CIDR_OK)
			return 1;
		if (strcmp(buf, cases[i].expected) != 0)
			return 1;
	}
	return 0;
}

/*
 * test_ipv6_format_rfc5952_no_compress_single - verify a single
 * zero group is written as "0", not compressed with ::.
 * See TESTING.md §3.3, RFC 5952 §4.2.2, ARCHITECTURE.md §4.2.2 rule 3.
 */
int test_ipv6_format_rfc5952_no_compress_single(void)
{
	cidr_addr_t addr;
	char buf[CIDR_ADDR_STR_MAX];

	if (cidr_addr_parse("2001:db8:0:1::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_format(&addr, buf, sizeof(buf)) != CIDR_OK)
		return 1;
	/*
	 * The zero group at position 2 is a single zero:
	 * the run of length 5 at positions 3-7 is compressed,
	 * but the single zero at position 2 stays as "0".
	 * Expected: 2001:db8:0:1::1
	 */
	if (strcmp(buf, "2001:db8:0:1::1") != 0)
		return 1;

	return 0;
}

/*
 * test_ipv6_format_rfc5952_tie_first_wins - verify that when two
 * consecutive zero runs are equal length, the first is compressed.
 * See TESTING.md §3.3, RFC 5952 §4.2.3, ARCHITECTURE.md §4.2.2 rule 4.
 */
int test_ipv6_format_rfc5952_tie_first_wins(void)
{
	cidr_addr_t addr;
	char buf[CIDR_ADDR_STR_MAX];

	/*
	 * 2001:0:0:1:0:0:2:1 has two zero runs at positions [1,2] and
	 * [4,5], both length 2. RFC 5952 §4.2.3: first run wins.
	 * Expected: 2001::1:0:0:2:1
	 */
	if (cidr_addr_parse("2001:0:0:1:0:0:2:1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_format(&addr, buf, sizeof(buf)) != CIDR_OK)
		return 1;
	if (strcmp(buf, "2001::1:0:0:2:1") != 0)
		return 1;

	return 0;
}

/*
 * test_ipv6_format_rfc5952_lowercase - verify hex digits are always
 * lowercase per RFC 5952 §4.3.
 * See TESTING.md §3.3, ARCHITECTURE.md §4.2.2 rule 5.
 */
int test_ipv6_format_rfc5952_lowercase(void)
{
	cidr_addr_t addr;
	char buf[CIDR_ADDR_STR_MAX];

	/* Uppercase input "ABCD::EF01" must format as "abcd::ef01". */
	if (cidr_addr_parse("ABCD::EF01", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_format(&addr, buf, sizeof(buf)) != CIDR_OK)
		return 1;
	if (strcmp(buf, "abcd::ef01") != 0)
		return 1;

	/* Mixed case input. */
	if (cidr_addr_parse("2001:DB8::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_format(&addr, buf, sizeof(buf)) != CIDR_OK)
		return 1;
	if (strcmp(buf, "2001:db8::1") != 0)
		return 1;

	return 0;
}

/*
 * test_ipv6_format_rfc5952_mixed_mapped - verify IPv4-mapped addresses
 * format with a dotted-decimal tail per RFC 5952 §5.
 * See TESTING.md §3.3, ARCHITECTURE.md §4.2.2 rule 6.
 */
int test_ipv6_format_rfc5952_mixed_mapped(void)
{
	cidr_addr_t addr;
	char buf[CIDR_ADDR_STR_MAX];

	/* ::ffff:192.0.2.1 -> ::ffff:192.0.2.1 */
	if (cidr_addr_parse("::ffff:192.0.2.1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_format(&addr, buf, sizeof(buf)) != CIDR_OK)
		return 1;
	if (strcmp(buf, "::ffff:192.0.2.1") != 0)
		return 1;

	/* ::ffff:c000:0201 -> ::ffff:192.0.2.1 */
	if (cidr_addr_parse("::ffff:c000:0201", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_format(&addr, buf, sizeof(buf)) != CIDR_OK)
		return 1;
	if (strcmp(buf, "::ffff:192.0.2.1") != 0)
		return 1;

	/* ::ffff:0:0 (stored with mixed-notation bytes, parsed as
	 * pure IPv6 via ::ffff:0:0 path) -> ::ffff:0.0.0.0 */
	if (cidr_addr_parse("::ffff:0:0", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_format(&addr, buf, sizeof(buf)) != CIDR_OK)
		return 1;
	if (strcmp(buf, "::ffff:0.0.0.0") != 0)
		return 1;

	return 0;
}

/*
 * test_ipv6_format_roundtrip - verify parse/format/parse produces
 * bit-identical bytes for representative IPv6 addresses.
 * See TESTING.md §6.1, ARCHITECTURE.md §4.2.
 */
int test_ipv6_format_roundtrip(void)
{
	static const char *cases[] = {"2001:db8::1",
	                              "::1",
	                              "::",
	                              "fe80::1",
	                              "::ffff:192.0.2.1",
	                              "2001:db8::",
	                              "ff02::1",
	                              "2001:db8:0:1::1",
	                              "2001::1:0:0:2:1",
	                              "2001:db8:85a3::8a2e:370:7334",
	                              NULL};
	char buf[CIDR_ADDR_STR_MAX];
	cidr_addr_t addr = {0}, addr2 = {0};
	int i;

	for (i = 0; cases[i] != NULL; i++) {
		if (cidr_addr_parse(cases[i], &addr) != CIDR_OK)
			return 1;
		if (cidr_addr_format(&addr, buf, sizeof(buf)) != CIDR_OK)
			return 1;
		if (cidr_addr_parse(buf, &addr2) != CIDR_OK)
			return 1;
		if (memcmp(&addr, &addr2, sizeof(addr)) != 0)
			return 1;
	}
	return 0;
}

/*
 * test_addr_format_buffer_too_small - verify CIDR_ERR_INVAL when
 * the output buffer is smaller than CIDR_ADDR_STR_MAX.
 * See ARCHITECTURE.md §4.2.
 */
int test_addr_format_buffer_too_small(void)
{
	cidr_addr_t addr;
	char small_buf[16];

	if (cidr_addr_parse("192.168.1.1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_format(&addr, small_buf, sizeof(small_buf)) !=
	    CIDR_ERR_INVAL)
		return 1;

	/* NULL buf */
	if (cidr_addr_format(&addr, NULL, CIDR_ADDR_STR_MAX) != CIDR_ERR_INVAL)
		return 1;

	/* NULL addr */
	if (cidr_addr_format(NULL, small_buf, CIDR_ADDR_STR_MAX) !=
	    CIDR_ERR_INVAL)
		return 1;

	return 0;
}

/*
 * test_addr_to_v4_valid_extraction - verify correct IPv4 bytes
 * are extracted from an IPv4-mapped IPv6 address.
 * See TESTING.md §6.7, ARCHITECTURE.md §4.1.3.
 */
int test_addr_to_v4_valid_extraction(void)
{
	cidr_addr_t mapped, out;

	if (cidr_addr_parse("::ffff:192.0.2.1", &mapped) != CIDR_OK)
		return 1;
	if (cidr_addr_to_v4(&mapped, &out) != CIDR_OK)
		return 1;
	if (out.family != CIDR_AF_INET)
		return 1;
	if (out.addr.v4[0] != 192 || out.addr.v4[1] != 0 ||
	    out.addr.v4[2] != 2 || out.addr.v4[3] != 1)
		return 1;

	/* ::ffff:10.0.0.1 */
	if (cidr_addr_parse("::ffff:10.0.0.1", &mapped) != CIDR_OK)
		return 1;
	if (cidr_addr_to_v4(&mapped, &out) != CIDR_OK)
		return 1;
	if (out.addr.v4[0] != 10 || out.addr.v4[1] != 0 ||
	    out.addr.v4[2] != 0 || out.addr.v4[3] != 1)
		return 1;

	/* ::ffff:255.255.255.255 -- boundary IPv4 */
	if (cidr_addr_parse("::ffff:255.255.255.255", &mapped) != CIDR_OK)
		return 1;
	if (cidr_addr_to_v4(&mapped, &out) != CIDR_OK)
		return 1;
	if (out.addr.v4[0] != 255 || out.addr.v4[1] != 255 ||
	    out.addr.v4[2] != 255 || out.addr.v4[3] != 255)
		return 1;

	return 0;
}

/*
 * test_addr_to_v4_error_distinction - verify the three error
 * conditions are distinguished correctly.
 *
 * CIDR_AF_UNSPEC  -> CIDR_ERR_INVAL
 * CIDR_AF_INET    -> CIDR_ERR_FAMILY  (valid IPv4, wrong family)
 * CIDR_AF_INET6 non-mapped -> CIDR_ERR_FAMILY
 *
 * See TESTING.md §6.7, ARCHITECTURE.md §4.1.3.
 */
int test_addr_to_v4_error_distinction(void)
{
	cidr_addr_t unspec = {0};
	cidr_addr_t ipv4, unmapped, out;

	if (cidr_addr_parse("192.168.1.1", &ipv4) != CIDR_OK)
		return 1;
	if (cidr_addr_parse("2001:db8::1", &unmapped) != CIDR_OK)
		return 1;

	/* CIDR_AF_UNSPEC -> CIDR_ERR_INVAL */
	if (cidr_addr_to_v4(&unspec, &out) != CIDR_ERR_INVAL)
		return 1;

	/* CIDR_AF_INET -> CIDR_ERR_FAMILY */
	if (cidr_addr_to_v4(&ipv4, &out) != CIDR_ERR_FAMILY)
		return 1;

	/* CIDR_AF_INET6 non-mapped -> CIDR_ERR_FAMILY */
	if (cidr_addr_to_v4(&unmapped, &out) != CIDR_ERR_FAMILY)
		return 1;

	/* NULL pointers -> CIDR_ERR_INVAL */
	if (cidr_addr_to_v4(NULL, &out) != CIDR_ERR_INVAL)
		return 1;
	if (cidr_addr_to_v4(&ipv4, NULL) != CIDR_ERR_INVAL)
		return 1;

	return 0;
}

/*
 * test_addr_cmp_same_family - verify comparison ordering and
 * equality for addresses within the same family.
 * See TESTING.md §3, ARCHITECTURE.md §4.4.
 */
int test_addr_cmp_same_family(void)
{
	cidr_addr_t a, b, c;
	int result;

	/*
	 * IPv4: test ordering.
	 * 10.0.0.1 < 10.0.0.2, 192.168.1.1 > 10.0.0.1
	 */
	if (cidr_addr_parse("10.0.0.1", &a) != CIDR_OK)
		return 1;
	if (cidr_addr_parse("10.0.0.2", &b) != CIDR_OK)
		return 1;
	if (cidr_addr_parse("192.168.1.1", &c) != CIDR_OK)
		return 1;

	if (cidr_addr_cmp(&a, &b, &result) != CIDR_OK)
		return 1;
	if (result != -1)
		return 1;

	if (cidr_addr_cmp(&b, &a, &result) != CIDR_OK)
		return 1;
	if (result != 1)
		return 1;

	if (cidr_addr_cmp(&c, &a, &result) != CIDR_OK)
		return 1;
	if (result != 1)
		return 1;

	/* IPv4: equality returns 0. */
	if (cidr_addr_cmp(&a, &a, &result) != CIDR_OK)
		return 1;
	if (result != 0)
		return 1;

	/*
	 * IPv6: test ordering.
	 * 2001:db8::1 < 2001:db8::2, fe80::1 > 2001:db8::1
	 */
	if (cidr_addr_parse("2001:db8::1", &a) != CIDR_OK)
		return 1;
	if (cidr_addr_parse("2001:db8::2", &b) != CIDR_OK)
		return 1;
	if (cidr_addr_parse("fe80::1", &c) != CIDR_OK)
		return 1;

	if (cidr_addr_cmp(&a, &b, &result) != CIDR_OK)
		return 1;
	if (result != -1)
		return 1;

	if (cidr_addr_cmp(&b, &a, &result) != CIDR_OK)
		return 1;
	if (result != 1)
		return 1;

	if (cidr_addr_cmp(&c, &a, &result) != CIDR_OK)
		return 1;
	if (result != 1)
		return 1;

	/* IPv6: equality returns 0. */
	if (cidr_addr_cmp(&a, &a, &result) != CIDR_OK)
		return 1;
	if (result != 0)
		return 1;

	/* Boundary: :: (all zero) < ::1 */
	if (cidr_addr_parse("::", &a) != CIDR_OK)
		return 1;
	if (cidr_addr_parse("::1", &b) != CIDR_OK)
		return 1;

	if (cidr_addr_cmp(&a, &b, &result) != CIDR_OK)
		return 1;
	if (result != -1)
		return 1;

	return 0;
}

/*
 * test_addr_cmp_family_mismatch - verify CIDR_ERR_FAMILY when
 * comparing an IPv4 address with an IPv6 address.
 * See ARCHITECTURE.md §4.4.
 */
int test_addr_cmp_family_mismatch(void)
{
	cidr_addr_t ipv4, ipv6;
	int result;

	if (cidr_addr_parse("10.0.0.1", &ipv4) != CIDR_OK)
		return 1;
	if (cidr_addr_parse("2001:db8::1", &ipv6) != CIDR_OK)
		return 1;

	if (cidr_addr_cmp(&ipv4, &ipv6, &result) != CIDR_ERR_FAMILY)
		return 1;

	return 0;
}

/*
 * test_addr_cmp_unspec - verify CIDR_ERR_INVAL when one or both
 * addresses have CIDR_AF_UNSPEC family or pointers are NULL.
 * See ARCHITECTURE.md §4.4.
 */
int test_addr_cmp_unspec(void)
{
	cidr_addr_t valid = {0}, unspec = {0};
	int result;

	if (cidr_addr_parse("10.0.0.1", &valid) != CIDR_OK)
		return 1;
	/* unspec is zero-initialised: family == CIDR_AF_UNSPEC */

	/* one UNSPEC -> CIDR_ERR_INVAL */
	if (cidr_addr_cmp(&unspec, &valid, &result) != CIDR_ERR_INVAL)
		return 1;
	if (cidr_addr_cmp(&valid, &unspec, &result) != CIDR_ERR_INVAL)
		return 1;

	/* both UNSPEC -> CIDR_ERR_INVAL */
	if (cidr_addr_cmp(&unspec, &unspec, &result) != CIDR_ERR_INVAL)
		return 1;

	/* NULL pointers -> CIDR_ERR_INVAL */
	if (cidr_addr_cmp(NULL, &valid, &result) != CIDR_ERR_INVAL)
		return 1;
	if (cidr_addr_cmp(&valid, NULL, &result) != CIDR_ERR_INVAL)
		return 1;
	if (cidr_addr_cmp(&valid, &valid, NULL) != CIDR_ERR_INVAL)
		return 1;

	return 0;
}
