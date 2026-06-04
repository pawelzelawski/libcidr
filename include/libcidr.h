#ifndef LIBCIDR_H
#define LIBCIDR_H

/*
 * libcidr.h - libcidr public API
 *
 * Parse and format IPv4/IPv6 addresses: cidr_addr_parse(), cidr_addr_format()
 * Parse and format CIDR prefixes:       cidr_prefix_parse(),
 * cidr_prefix_from_host() Prefix arithmetic: cidr_prefix_contains(),
 * cidr_prefix_overlaps() Subnet enumeration: cidr_subnet_iter_init(),
 * cidr_subnet_iter_next() Bulk operations: cidr_bulk_parse(),
 * cidr_bulk_aggregate() Prefix index: cidr_index_create(), cidr_index_lookup()
 * Address classification:               cidr_addr_classify()
 *
 * See ARCHITECTURE.md for the full API specification and design rationale.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* Address family discriminator. See ARCHITECTURE.md §3.1. */
typedef enum {
	CIDR_AF_UNSPEC = 0,
	CIDR_AF_INET = 4,
	CIDR_AF_INET6 = 6,
} cidr_family_t;

/* IP address: family discriminator + union of v4/v6 byte arrays.
 * See ARCHITECTURE.md §3.2. */
typedef struct {
	cidr_family_t family;
	union {
		uint8_t v4[4];
		uint8_t v6[16];
	} addr;
} cidr_addr_t;

/* CIDR prefix: network address with host bits guaranteed zero + prefix length.
 * See ARCHITECTURE.md §3.3. */
typedef struct {
	cidr_addr_t addr;
	uint8_t pfxlen;
} cidr_prefix_t;

/* Error codes. Zero is always success. See ARCHITECTURE.md §3.4. */
typedef enum {
	CIDR_OK = 0,
	CIDR_ERR_INVAL = 1,
	CIDR_ERR_PARSE = 2,
	CIDR_ERR_PFXLEN = 3,
	CIDR_ERR_HOSTBITS = 4,
	CIDR_ERR_NOMEM = 5,
	CIDR_ERR_FAMILY = 6,
	CIDR_ERR_OVERFLOW = 7,
	CIDR_ERR_DONE = 8,
} cidr_err_t;

/* Classification bitmask. See ARCHITECTURE.md §7.2. */
typedef uint32_t cidr_class_t;

#define CIDR_CLASS_GLOBAL (1u << 0)
#define CIDR_CLASS_THIS_HOST (1u << 1)
#define CIDR_CLASS_PRIVATE (1u << 2)
#define CIDR_CLASS_SHARED (1u << 3)
#define CIDR_CLASS_LOOPBACK (1u << 4)
#define CIDR_CLASS_LINK_LOCAL (1u << 5)
#define CIDR_CLASS_IETF_RESERVED (1u << 6)
#define CIDR_CLASS_DOCUMENTATION (1u << 7)
#define CIDR_CLASS_6TO4_RELAY (1u << 8)
#define CIDR_CLASS_BENCHMARKING (1u << 9)
#define CIDR_CLASS_RESERVED (1u << 10)
#define CIDR_CLASS_BROADCAST (1u << 11)
#define CIDR_CLASS_UNSPECIFIED (1u << 12)
#define CIDR_CLASS_V4MAPPED (1u << 13)
#define CIDR_CLASS_V4TRANSLATED (1u << 14)
#define CIDR_CLASS_DISCARD (1u << 15)
#define CIDR_CLASS_UNIQUE_LOCAL (1u << 16)
#define CIDR_CLASS_MULTICAST (1u << 17)
#define CIDR_CLASS_ANYCAST (1u << 18)
#define CIDR_CLASS_TEREDO (1u << 19)
#define CIDR_CLASS_6TO4 (1u << 20)
#define CIDR_CLASS_ORCHID (1u << 21)
#define CIDR_CLASS_SRV6 (1u << 22)
/* bits 23-31 reserved for future IANA additions */

/* Sort order for cidr_bulk_sort(). See ARCHITECTURE.md §5.5. */
typedef enum {
	CIDR_SORT_NETWORK_ASC = 0,
	CIDR_SORT_PFXLEN_DESC = 1,
} cidr_sort_order_t;

/* Subnet iterator state. See ARCHITECTURE.md §4.3.8. */
typedef struct {
	cidr_prefix_t current;
	cidr_prefix_t limit;
	uint8_t target_pfxlen;
	bool done;
} cidr_subnet_iter_t;

/* Opaque Patricia trie index. See ARCHITECTURE.md §6. */
typedef struct cidr_index cidr_index_t;

/* Buffer size constants. See ARCHITECTURE.md §4.2. */
#define CIDR_ADDR_STR_MAX 46
#define CIDR_PREFIX_STR_MAX 50

/* IANA special-purpose registry snapshot date. See ARCHITECTURE.md §7.2. */
#define CIDR_IANA_SNAPSHOT 20251009

#endif /* LIBCIDR_H */
