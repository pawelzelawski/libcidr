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
 * Accepts full, compressed, and IPv4-mapped mixed forms for IPv6 per
 * RFC 4291 §2.2 and RFC 5952 §5. IPv4-compatible addresses are rejected
 * per RFC 4291 §2.5.5.1 deprecation. See ARCHITECTURE.md §4.1.2.
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

/*
 * cidr_addr_format - format an address as canonical text.
 *
 * Writes the canonical text representation of addr into the caller-provided
 * buffer buf of length len. IPv4 is formatted as strict dotted-decimal
 * (no leading zeros, no alternative notations). IPv6 is formatted per
 * RFC 5952 canonical form: leading zeros suppressed, longest run of
 * consecutive zero groups compressed with ::, single zero group written
 * as "0", first run wins on tie, lowercase hex throughout, and IPv4-mapped
 * addresses use mixed notation ::ffff:x.x.x.x.
 *
 * addr: pointer to a valid cidr_addr_t (family must be CIDR_AF_INET or
 *       CIDR_AF_INET6)
 * buf:  caller-provided output buffer; on success contains the
 *       NUL-terminated canonical address string
 * len:  size of buf in bytes; must be at least CIDR_ADDR_STR_MAX (46)
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_INVAL if addr or buf is NULL, if addr->family is
 * CIDR_AF_UNSPEC, or if len < CIDR_ADDR_STR_MAX.
 *
 * On failure, buf content is undefined.
 * No allocation occurs.
 *
 * See ARCHITECTURE.md §4.2, §4.2.1, §4.2.2.
 */
cidr_err_t cidr_addr_format(const cidr_addr_t *addr, char *buf, size_t len)
    __attribute__((warn_unused_result));

/*
 * cidr_addr_to_v4 - extract embedded IPv4 address from an IPv4-mapped
 *                   IPv6 address (::ffff:0:0/96).
 *
 * The input must be a CIDR_AF_INET6 address whose first 12 bytes match
 * the IPv4-mapped prefix (00 00 00 00 00 00 00 00 00 00 FF FF).
 * On success, out is written as a cidr_addr_t with family = CIDR_AF_INET
 * and the 4 extracted bytes in addr.v4. The input and output are clean,
 * distinct structs -- no family mixing occurs in any single struct.
 *
 * addr: pointer to a cidr_addr_t with family CIDR_AF_INET6
 * out:  caller-provided cidr_addr_t; on success, written with family
 *       CIDR_AF_INET and the 4 extracted bytes in addr.v4
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_INVAL if either pointer is NULL or if
 *   addr->family is CIDR_AF_UNSPEC.
 * Returns CIDR_ERR_FAMILY if addr->family is CIDR_AF_INET (valid IPv4,
 *   wrong family for extraction), or if addr->family is CIDR_AF_INET6
 *   but the first 12 bytes do not match the IPv4-mapped prefix.
 *
 * No allocation occurs.
 *
 * See ARCHITECTURE.md §4.1.3.
 */
cidr_err_t cidr_addr_to_v4(const cidr_addr_t *addr, cidr_addr_t *out)
    __attribute__((warn_unused_result));

/*
 * cidr_addr_cmp - compare two addresses within the same family.
 *
 * Compares two cidr_addr_t values lexicographically on the address bytes
 * in network byte order. Writes -1, 0, or +1 into *result indicating
 * a < b, a == b, or a > b respectively. This ordering is consistent
 * with CIDR_SORT_NETWORK_ASC.
 *
 * a:      pointer to a valid cidr_addr_t (family must not be
 *         CIDR_AF_UNSPEC)
 * b:      pointer to a valid cidr_addr_t (family must not be
 *         CIDR_AF_UNSPEC)
 * result: caller-provided int pointer; on success, receives -1, 0, or +1
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_INVAL if any pointer is NULL or if either address has
 *   family == CIDR_AF_UNSPEC.
 * Returns CIDR_ERR_FAMILY if a->family != b->family.
 *
 * Complexity: O(W) where W is address width in bytes (4 for IPv4,
 * 16 for IPv6). No allocation occurs.
 *
 * See ARCHITECTURE.md §4.4.
 */
cidr_err_t cidr_addr_cmp(const cidr_addr_t *a, const cidr_addr_t *b,
                         int *result) __attribute__((warn_unused_result));

/*
 * cidr_prefix_parse - parse a CIDR prefix from text (strict).
 *
 * Input must be "address/prefixlen" where address is a valid IPv4 or
 * IPv6 address per ARCHITECTURE.md §4.1.1 or §4.1.2 and prefixlen is a
 * decimal integer in the valid range for the address family. Returns
 * CIDR_ERR_HOSTBITS if the address has any host bits set. On failure,
 * out->addr.family is written as CIDR_AF_UNSPEC.
 *
 * src:  null-terminated CIDR string ("address/prefixlen")
 * out:  caller-provided cidr_prefix_t; on success addr.family is
 *       CIDR_AF_INET or CIDR_AF_INET6
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
cidr_err_t cidr_prefix_parse(const char *src, cidr_prefix_t *out)
    __attribute__((warn_unused_result));

/*
 * cidr_prefix_from_host - construct a prefix from a host address
 *                         (explicit host-to-network).
 *
 * Accepts a host address and a prefix length. Computes the network
 * address by zeroing host bits. The zeroing is explicit -- the function
 * name documents the operation. Must not return CIDR_ERR_HOSTBITS.
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
cidr_err_t cidr_prefix_from_host(const cidr_addr_t *addr, uint8_t pfxlen,
                                 cidr_prefix_t *out)
    __attribute__((warn_unused_result));

/*
 * cidr_prefix_format - format a CIDR prefix as canonical text.
 *
 * Writes the canonical CIDR string "address/prefixlen" into buf.
 * The address portion is formatted per §4.2.1 or §4.2.2 depending
 * on family. The prefix length is written as a decimal integer with
 * no leading zeros. Example output: "192.168.1.0/24", "2001:db8::/32".
 *
 * prefix: pointer to a valid cidr_prefix_t (addr.family must be
 *         CIDR_AF_INET or CIDR_AF_INET6)
 * buf:    caller-provided output buffer; on success contains the
 *         NUL-terminated canonical CIDR string
 * len:    size of buf in bytes; must be at least CIDR_PREFIX_STR_MAX (50)
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
cidr_err_t cidr_prefix_format(const cidr_prefix_t *prefix, char *buf,
                              size_t len) __attribute__((warn_unused_result));

#endif /* LIBCIDR_H */
