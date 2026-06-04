/*
 * test_addr.c - address parsing, formatting, IPv4-mapped extraction,
 *               and address comparison tests.
 *
 * See DEVELOPMENT.md §Phase 2 for the required test cases.
 * See TESTING.md §3.1 for IPv4 parsing conformance tests.
 */

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
