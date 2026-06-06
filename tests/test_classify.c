/*
 * test_classify.c - address classification tests for
 *                   cidr_addr_classify().
 *
 * Tests every IPv4 and IPv6 special-purpose block from the IANA snapshot
 * 2025-10-09, multi-flag assignments, terminated entries, multicast ranges,
 * boundary addresses, CIDR_CLASS_GLOBAL mutual exclusivity, and error paths.
 *
 * See ARCHITECTURE.md §7 for the classification specification,
 * ARCHITECTURE.md §7.2 for the block tables.
 * See DEVELOPMENT.md §Phase 5 Tests for the full test catalogue.
 */

#include <string.h>

#include "../include/libcidr.h"
#include "test_harness.h"

/*
 * Test that one representative address from each IPv4 special-purpose block
 * yields exactly the expected flags and no spurious ones.
 */
int
test_classify_each_ipv4_block(void)
{
	cidr_addr_t addr;
	cidr_class_t flags;

	/* 0.0.0.0/8 -- THIS_HOST */
	if (cidr_addr_parse("0.0.0.1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_THIS_HOST)
		return 1;

	/* 0.0.0.0/32 -- THIS_HOST */
	if (cidr_addr_parse("0.0.0.0", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_THIS_HOST)
		return 1;

	/* 10.0.0.0/8 -- PRIVATE */
	if (cidr_addr_parse("10.0.0.1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_PRIVATE)
		return 1;

	/* 100.64.0.0/10 -- SHARED */
	if (cidr_addr_parse("100.64.0.1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_SHARED)
		return 1;

	/* 127.0.0.0/8 -- LOOPBACK */
	if (cidr_addr_parse("127.0.0.1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_LOOPBACK)
		return 1;

	/* 169.254.0.0/16 -- LINK_LOCAL */
	if (cidr_addr_parse("169.254.1.1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_LINK_LOCAL)
		return 1;

	/* 172.16.0.0/12 -- PRIVATE */
	if (cidr_addr_parse("172.16.0.1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_PRIVATE)
		return 1;
	if (cidr_addr_parse("172.31.255.254", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_PRIVATE)
		return 1;

	/* 192.0.0.0/24 -- IETF_RESERVED */
	if (cidr_addr_parse("192.0.0.1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_IETF_RESERVED)
		return 1;

	/* 192.0.0.9/32 -- IETF_RESERVED | ANYCAST */
	if (cidr_addr_parse("192.0.0.9", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != (CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_ANYCAST))
		return 1;

	/* 192.0.0.10/32 -- IETF_RESERVED | ANYCAST */
	if (cidr_addr_parse("192.0.0.10", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != (CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_ANYCAST))
		return 1;

	/* 192.0.0.170/32 -- IETF_RESERVED */
	if (cidr_addr_parse("192.0.0.170", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_IETF_RESERVED)
		return 1;

	/* 192.0.0.171/32 -- IETF_RESERVED */
	if (cidr_addr_parse("192.0.0.171", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_IETF_RESERVED)
		return 1;

	/* 192.0.2.0/24 -- DOCUMENTATION */
	if (cidr_addr_parse("192.0.2.1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_DOCUMENTATION)
		return 1;

	/* 192.31.196.0/24 -- ANYCAST */
	if (cidr_addr_parse("192.31.196.1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_ANYCAST)
		return 1;

	/* 192.52.193.0/24 -- ANYCAST */
	if (cidr_addr_parse("192.52.193.1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_ANYCAST)
		return 1;

	/* 192.88.99.0/24 -- 6TO4_RELAY */
	if (cidr_addr_parse("192.88.99.1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_6TO4_RELAY)
		return 1;

	/* 192.88.99.2/32 -- 6TO4_RELAY */
	if (cidr_addr_parse("192.88.99.2", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_6TO4_RELAY)
		return 1;

	/* 192.168.0.0/16 -- PRIVATE */
	if (cidr_addr_parse("192.168.1.1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_PRIVATE)
		return 1;

	/* 192.175.48.0/24 -- ANYCAST */
	if (cidr_addr_parse("192.175.48.1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_ANYCAST)
		return 1;

	/* 198.18.0.0/15 -- BENCHMARKING */
	if (cidr_addr_parse("198.18.0.1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_BENCHMARKING)
		return 1;
	if (cidr_addr_parse("198.19.255.255", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_BENCHMARKING)
		return 1;

	/* 198.51.100.0/24 -- DOCUMENTATION */
	if (cidr_addr_parse("198.51.100.1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_DOCUMENTATION)
		return 1;

	/* 203.0.113.0/24 -- DOCUMENTATION */
	if (cidr_addr_parse("203.0.113.1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_DOCUMENTATION)
		return 1;

	/* 224.0.0.0/4 -- MULTICAST */
	if (cidr_addr_parse("224.0.0.1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_MULTICAST)
		return 1;
	if (cidr_addr_parse("239.255.255.255", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_MULTICAST)
		return 1;

	/* 240.0.0.0/4 -- RESERVED */
	if (cidr_addr_parse("240.0.0.1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_RESERVED)
		return 1;

	/*
	 * 255.255.255.255/32 -- BROADCAST.
	 * NOTE: also falls within 240.0.0.0/4 (RESERVED), so RESERVED
	 * will be ORed in. Verify BROADCAST is set, not exact equality.
	 */
	if (cidr_addr_parse("255.255.255.255", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (!(flags & CIDR_CLASS_BROADCAST))
		return 1;
	if (flags & CIDR_CLASS_GLOBAL)
		return 1;

	return 0;
}

/*
 * Test that one representative address from each IPv6 special-purpose block
 * yields exactly the expected flags.
 */
int
test_classify_each_ipv6_block(void)
{
	cidr_addr_t addr;
	cidr_class_t flags;

	/* ::/128 -- UNSPECIFIED */
	if (cidr_addr_parse("::", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_UNSPECIFIED)
		return 1;

	/* ::1/128 -- LOOPBACK */
	if (cidr_addr_parse("::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_LOOPBACK)
		return 1;

	/* ::ffff:0:0/96 -- V4MAPPED */
	if (cidr_addr_parse("::ffff:192.0.2.1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_V4MAPPED)
		return 1;

	/* 64:ff9b::/96 -- V4TRANSLATED */
	if (cidr_addr_parse("64:ff9b::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_V4TRANSLATED)
		return 1;

	/* 64:ff9b:1::/48 -- V4TRANSLATED */
	if (cidr_addr_parse("64:ff9b:1::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_V4TRANSLATED)
		return 1;

	/* 100::/64 -- DISCARD */
	if (cidr_addr_parse("100::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_DISCARD)
		return 1;

	/* 100:0:0:1::/64 -- IETF_RESERVED */
	if (cidr_addr_parse("100:0:0:1::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_IETF_RESERVED)
		return 1;

	/*
	 * 2001::/23 -- IETF_RESERVED.
	 * Use an address in the /23 range but outside all sub-blocks
	 * (2001:80::1 is in 2001::/23, not in 2001::/32).
	 */
	if (cidr_addr_parse("2001:80::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_IETF_RESERVED)
		return 1;

	/* 2001:1::1/128 -- IETF_RESERVED | ANYCAST */
	if (cidr_addr_parse("2001:1::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != (CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_ANYCAST))
		return 1;

	/* 2001:1::2/128 -- IETF_RESERVED | ANYCAST */
	if (cidr_addr_parse("2001:1::2", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != (CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_ANYCAST))
		return 1;

	/* 2001:1::3/128 -- IETF_RESERVED | ANYCAST */
	if (cidr_addr_parse("2001:1::3", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != (CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_ANYCAST))
		return 1;

	/* 2001:2::/48 -- IETF_RESERVED | BENCHMARKING */
	if (cidr_addr_parse("2001:2::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != (CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_BENCHMARKING))
		return 1;

	/* 2001:3::/32 -- IETF_RESERVED | ANYCAST */
	if (cidr_addr_parse("2001:3::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != (CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_ANYCAST))
		return 1;

	/* 2001:4:112::/48 -- IETF_RESERVED | ANYCAST */
	if (cidr_addr_parse("2001:4:112::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != (CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_ANYCAST))
		return 1;

	/* 2001:10::/28 -- IETF_RESERVED (terminated) */
	if (cidr_addr_parse("2001:10::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_IETF_RESERVED)
		return 1;

	/* 2001:20::/28 -- IETF_RESERVED | ORCHID */
	if (cidr_addr_parse("2001:20::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != (CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_ORCHID))
		return 1;

	/* 2001:30::/28 -- IETF_RESERVED | ORCHID */
	if (cidr_addr_parse("2001:30::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != (CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_ORCHID))
		return 1;

	/* 2001:db8::/32 -- IETF_RESERVED | DOCUMENTATION */
	if (cidr_addr_parse("2001:db8::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != (CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_DOCUMENTATION))
		return 1;

	/* 2002::/16 -- 6TO4 */
	if (cidr_addr_parse("2002::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_6TO4)
		return 1;

	/* 2620:4f:8000::/48 -- ANYCAST */
	if (cidr_addr_parse("2620:4f:8000::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_ANYCAST)
		return 1;

	/* 3fff::/20 -- DOCUMENTATION */
	if (cidr_addr_parse("3fff::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_DOCUMENTATION)
		return 1;

	/* 5f00::/16 -- SRV6 */
	if (cidr_addr_parse("5f00::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_SRV6)
		return 1;

	/* fc00::/7 -- UNIQUE_LOCAL */
	if (cidr_addr_parse("fc00::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_UNIQUE_LOCAL)
		return 1;
	if (cidr_addr_parse("fdff::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_UNIQUE_LOCAL)
		return 1;

	/* fe80::/10 -- LINK_LOCAL */
	if (cidr_addr_parse("fe80::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_LINK_LOCAL)
		return 1;

	/* ff00::/8 -- MULTICAST */
	if (cidr_addr_parse("ff00::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_MULTICAST)
		return 1;
	if (cidr_addr_parse("ffff::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_MULTICAST)
		return 1;

	return 0;
}

/*
 * Test that CIDR_CLASS_GLOBAL is never set alongside any other flag.
 * For every flag in the classification system, verify that addresses
 * matching that flag do NOT have CIDR_CLASS_GLOBAL.
 */
int
test_classify_global_exclusivity(void)
{
	cidr_addr_t addr;
	cidr_class_t flags;

	/* Test known special-purpose addresses -- none should have GLOBAL */
	if (cidr_addr_parse("10.0.0.1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags & CIDR_CLASS_GLOBAL)
		return 1;

	if (cidr_addr_parse("192.168.1.1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags & CIDR_CLASS_GLOBAL)
		return 1;

	if (cidr_addr_parse("127.0.0.1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags & CIDR_CLASS_GLOBAL)
		return 1;

	if (cidr_addr_parse("224.0.0.1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags & CIDR_CLASS_GLOBAL)
		return 1;

	if (cidr_addr_parse("::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags & CIDR_CLASS_GLOBAL)
		return 1;

	if (cidr_addr_parse("fe80::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags & CIDR_CLASS_GLOBAL)
		return 1;

	if (cidr_addr_parse("ff00::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags & CIDR_CLASS_GLOBAL)
		return 1;

	if (cidr_addr_parse("2001:db8::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags & CIDR_CLASS_GLOBAL)
		return 1;

	return 0;
}

/*
 * Test that known public unicast addresses yield only CIDR_CLASS_GLOBAL
 * and no other flags.
 */
int
test_classify_global_public_unicast(void)
{
	cidr_addr_t addr;
	cidr_class_t flags;

	/* 8.8.8.8 -- Google DNS, a public globally routable address */
	if (cidr_addr_parse("8.8.8.8", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_GLOBAL)
		return 1;

	/* 1.1.1.1 -- Cloudflare DNS */
	if (cidr_addr_parse("1.1.1.1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_GLOBAL)
		return 1;

	/* 93.184.216.34 -- example.com */
	if (cidr_addr_parse("93.184.216.34", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_GLOBAL)
		return 1;

	/* 2606:2800:220:1:248:1893:25c8:1946 -- example.com IPv6 */
	if (cidr_addr_parse("2606:2800:220:1:248:1893:25c8:1946", &addr) !=
	    CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_GLOBAL)
		return 1;

	return 0;
}

/*
 * Test multi-flag assignments for sub-blocks of 2001::/23.
 * 2001::/32 should yield IETF_RESERVED | TEREDO.
 */
int
test_classify_multi_flag_2001_sub_blocks(void)
{
	cidr_addr_t addr;
	cidr_class_t flags;

	/* 2001::/32 -- Teredo: IETF_RESERVED | TEREDO */
	if (cidr_addr_parse("2001:0:ffff::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != (CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_TEREDO))
		return 1;

	/* 2001:1::1 -- IETF_RESERVED | ANYCAST */
	if (cidr_addr_parse("2001:1::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != (CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_ANYCAST))
		return 1;

	/* 2001:2::1 -- IETF_RESERVED | BENCHMARKING */
	if (cidr_addr_parse("2001:2::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != (CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_BENCHMARKING))
		return 1;

	/* 2001:20::1 -- IETF_RESERVED | ORCHID */
	if (cidr_addr_parse("2001:20::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != (CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_ORCHID))
		return 1;

	/* 2001:30::1 -- IETF_RESERVED | ORCHID */
	if (cidr_addr_parse("2001:30::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != (CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_ORCHID))
		return 1;

	/* 2001:db8::1 -- IETF_RESERVED | DOCUMENTATION */
	if (cidr_addr_parse("2001:db8::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != (CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_DOCUMENTATION))
		return 1;

	return 0;
}

/*
 * Test that the terminated entry 192.88.99.0/24 is classified as
 * CIDR_CLASS_6TO4_RELAY.
 */
int
test_classify_terminated_192_88_99(void)
{
	cidr_addr_t addr;
	cidr_class_t flags;

	if (cidr_addr_parse("192.88.99.0", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_6TO4_RELAY)
		return 1;

	if (cidr_addr_parse("192.88.99.255", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_6TO4_RELAY)
		return 1;

	if (cidr_addr_parse("192.88.99.2", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_6TO4_RELAY)
		return 1;

	/* Address just outside: 192.88.100.0 should NOT be 6TO4_RELAY */
	if (cidr_addr_parse("192.88.100.0", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags & CIDR_CLASS_6TO4_RELAY)
		return 1;

	return 0;
}

/*
 * Test that the terminated entry 2001:10::/28 is classified as
 * CIDR_CLASS_IETF_RESERVED.
 */
int
test_classify_terminated_2001_10(void)
{
	cidr_addr_t addr;
	cidr_class_t flags;

	if (cidr_addr_parse("2001:10::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_IETF_RESERVED)
		return 1;

	/* Address just outside: 2001:20::1 is ORCHID, not IETF_RESERVED alone
	 */
	if (cidr_addr_parse("2001:20::1", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags == CIDR_CLASS_IETF_RESERVED)
		return 1;

	return 0;
}

/*
 * Test that IPv4 multicast range 224.0.0.0/4 yields CIDR_CLASS_MULTICAST.
 * Test boundary addresses: first, last, just before, just after.
 */
int
test_classify_multicast_ipv4(void)
{
	cidr_addr_t addr;
	cidr_class_t flags;

	/* First address of 224.0.0.0/4 */
	if (cidr_addr_parse("224.0.0.0", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_MULTICAST)
		return 1;

	/* Last address of 224.0.0.0/4 */
	if (cidr_addr_parse("239.255.255.255", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_MULTICAST)
		return 1;

	/* Just before: 223.255.255.255 should NOT be MULTICAST */
	if (cidr_addr_parse("223.255.255.255", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags & CIDR_CLASS_MULTICAST)
		return 1;

	/* Just after: 240.0.0.0 is RESERVED, not MULTICAST */
	if (cidr_addr_parse("240.0.0.0", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags & CIDR_CLASS_MULTICAST)
		return 1;

	return 0;
}

/*
 * Test that IPv6 multicast range ff00::/8 yields CIDR_CLASS_MULTICAST.
 * Test boundary addresses.
 */
int
test_classify_multicast_ipv6(void)
{
	cidr_addr_t addr;
	cidr_class_t flags;

	/* First address of ff00::/8 */
	if (cidr_addr_parse("ff00::", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_MULTICAST)
		return 1;

	/* Last address of ff00::/8 */
	if (cidr_addr_parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", &addr) !=
	    CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_MULTICAST)
		return 1;

	/* Just before: feff:... should NOT be MULTICAST */
	if (cidr_addr_parse("feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", &addr) !=
	    CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags & CIDR_CLASS_MULTICAST)
		return 1;

	return 0;
}

/*
 * Test boundary addresses: first and last address of selected blocks are
 * classified correctly; addresses just before and just after yield different
 * results.
 */
int
test_classify_boundary_first_last(void)
{
	cidr_addr_t addr;
	cidr_class_t flags;

	/* 10.0.0.0/8 boundaries */
	if (cidr_addr_parse("10.0.0.0", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_PRIVATE)
		return 1;
	if (cidr_addr_parse("10.255.255.255", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_PRIVATE)
		return 1;
	if (cidr_addr_parse("9.255.255.255", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags & CIDR_CLASS_PRIVATE)
		return 1;
	if (cidr_addr_parse("11.0.0.0", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags & CIDR_CLASS_PRIVATE)
		return 1;

	/* 192.168.0.0/16 boundaries */
	if (cidr_addr_parse("192.168.0.0", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_PRIVATE)
		return 1;
	if (cidr_addr_parse("192.168.255.255", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_PRIVATE)
		return 1;
	if (cidr_addr_parse("192.167.255.255", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags & CIDR_CLASS_PRIVATE)
		return 1;
	if (cidr_addr_parse("192.169.0.0", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags & CIDR_CLASS_PRIVATE)
		return 1;

	/* 127.0.0.0/8 boundaries */
	if (cidr_addr_parse("127.0.0.0", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_LOOPBACK)
		return 1;
	if (cidr_addr_parse("127.255.255.255", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != CIDR_CLASS_LOOPBACK)
		return 1;
	if (cidr_addr_parse("126.255.255.255", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags & CIDR_CLASS_LOOPBACK)
		return 1;
	if (cidr_addr_parse("128.0.0.0", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags & CIDR_CLASS_LOOPBACK)
		return 1;

	/* 2001:db8::/32 boundaries */
	if (cidr_addr_parse("2001:db8::", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != (CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_DOCUMENTATION))
		return 1;
	if (cidr_addr_parse("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", &addr) !=
	    CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags != (CIDR_CLASS_IETF_RESERVED | CIDR_CLASS_DOCUMENTATION))
		return 1;
	if (cidr_addr_parse("2001:db7:ffff:ffff:ffff:ffff:ffff:ffff", &addr) !=
	    CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags & CIDR_CLASS_DOCUMENTATION)
		return 1;
	if (cidr_addr_parse("2001:db9::", &addr) != CIDR_OK)
		return 1;
	if (cidr_addr_classify(&addr, &flags) != CIDR_OK)
		return 1;
	if (flags & CIDR_CLASS_DOCUMENTATION)
		return 1;

	return 0;
}

/*
 * Test that NULL addr returns CIDR_ERR_INVAL.
 */
int
test_classify_null(void)
{
	cidr_class_t flags;

	if (cidr_addr_classify(NULL, &flags) != CIDR_ERR_INVAL)
		return 1;

	{
		cidr_addr_t addr;
		if (cidr_addr_parse("10.0.0.1", &addr) != CIDR_OK)
			return 1;
		if (cidr_addr_classify(&addr, NULL) != CIDR_ERR_INVAL)
			return 1;
	}

	if (cidr_addr_classify(NULL, NULL) != CIDR_ERR_INVAL)
		return 1;

	return 0;
}

/*
 * Test that CIDR_AF_UNSPEC input returns CIDR_ERR_INVAL.
 */
int
test_classify_unspec(void)
{
	cidr_addr_t addr;
	cidr_class_t flags;

	memset(&addr, 0, sizeof(addr));
	if (cidr_addr_classify(&addr, &flags) != CIDR_ERR_INVAL)
		return 1;

	return 0;
}
