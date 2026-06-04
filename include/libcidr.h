#ifndef LIBCIDR_H
#define LIBCIDR_H

/*
 * libcidr.h - libcidr public API
 *
 * Parse and format IPv4/IPv6 addresses:
 *     cidr_addr_parse(), cidr_addr_format()
 * Parse and format CIDR prefixes:
 *     cidr_prefix_parse(), cidr_prefix_from_host()
 * Prefix arithmetic:
 *     cidr_prefix_contains(), cidr_prefix_overlaps()
 * Subnet enumeration:
 *     cidr_subnet_iter_init(), cidr_subnet_iter_next()
 * Bulk operations:
 *     cidr_bulk_parse(), cidr_bulk_aggregate()
 * Prefix index:
 *     cidr_index_create(), cidr_index_lookup()
 * Address classification:
 *     cidr_addr_classify()
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

/*
 * Error codes.
 *
 * CIDR_OK (0) is always success. All public functions except
 * cidr_index_destroy() return cidr_err_t and carry
 * __attribute__((warn_unused_result)).
 *
 * CIDR_ERR_DONE is a sentinel returned by cidr_subnet_iter_next() when
 * the iterator is exhausted. It is not an error -- it is the normal
 * termination condition.
 *
 * CIDR_ERR_NOMEM appears only in cidr_index_create(). No other function
 * allocates memory and therefore no other function can return this code.
 *
 * See ARCHITECTURE.md §3.4 for the full error code semantics.
 */
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

/*
 * cidr_addr_parse - parse an IPv4 or IPv6 address from text.
 *
 * Accepts strict dotted-decimal notation for IPv4 per ARCHITECTURE.md §4.1.1:
 * exactly four decimal octets 0-255 separated by dots, no leading zeros,
 * no hex, no whitespace, no trailing characters.
 * IPv6 parsing per ARCHITECTURE.md §4.1.2 is implemented in a later phase.
 *
 * src:  null-terminated address string
 * out:  caller-provided cidr_addr_t; written with CIDR_AF_INET on success,
 *       CIDR_AF_UNSPEC on failure
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_INVAL if src or out is NULL.
 * Returns CIDR_ERR_PARSE if the text does not match a valid address form.
 *
 * See ARCHITECTURE.md §4.1.1 for the full IPv4 rejection case table.
 */
cidr_err_t cidr_addr_parse(const char *src, cidr_addr_t *out)
    __attribute__((warn_unused_result));

#endif /* LIBCIDR_H */
