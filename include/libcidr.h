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

/*
 * cidr_prefix_broadcast - compute the broadcast address of an IPv4 prefix.
 *
 * IPv4 only. Returns CIDR_ERR_FAMILY for CIDR_AF_INET6 prefixes -- IPv6
 * has no broadcast address per RFC 4291. Computed by ORing the network
 * address with the bitwise complement of the prefix mask.
 *
 * prefix: pointer to a valid cidr_prefix_t (addr.family must be
 *         CIDR_AF_INET)
 * out:    caller-provided cidr_addr_t; on success receives the broadcast
 *         address with family CIDR_AF_INET
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_INVAL if prefix or out is NULL, or if
 *   prefix->addr.family is CIDR_AF_UNSPEC.
 * Returns CIDR_ERR_FAMILY if prefix->addr.family is CIDR_AF_INET6.
 *
 * No allocation occurs.
 *
 * See ARCHITECTURE.md §4.3.2.
 */
cidr_err_t cidr_prefix_broadcast(const cidr_prefix_t *prefix, cidr_addr_t *out)
    __attribute__((warn_unused_result));

/*
 * cidr_prefix_mask - compute the prefix mask (network mask).
 *
 * Returns a cidr_addr_t with pfxlen leading bits set to one and remaining
 * bits set to zero, in network byte order. For pfxlen 0: all bytes zero.
 * For maximum prefix length (32 for IPv4, 128 for IPv6): all bytes 0xFF.
 *
 * prefix: pointer to a valid cidr_prefix_t
 * out:    caller-provided cidr_addr_t; on success receives the prefix mask
 *         with family matching prefix->addr.family
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_INVAL if prefix or out is NULL, or if
 *   prefix->addr.family is CIDR_AF_UNSPEC.
 *
 * No allocation occurs.
 *
 * See ARCHITECTURE.md §4.3.3.
 */
cidr_err_t cidr_prefix_mask(const cidr_prefix_t *prefix, cidr_addr_t *out)
    __attribute__((warn_unused_result));

/*
 * cidr_prefix_first - return the network (first) address of a prefix.
 *
 * The network address is prefix->addr directly -- host bits are guaranteed
 * zero by construction. This function copies the address to out.
 *
 * prefix: pointer to a valid cidr_prefix_t
 * out:    caller-provided cidr_addr_t; on success receives the network
 *         address with family matching prefix->addr.family
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_INVAL if prefix or out is NULL, or if
 *   prefix->addr.family is CIDR_AF_UNSPEC.
 *
 * No allocation occurs.
 *
 * See ARCHITECTURE.md §4.3.4.
 */
cidr_err_t cidr_prefix_first(const cidr_prefix_t *prefix, cidr_addr_t *out)
    __attribute__((warn_unused_result));

/*
 * cidr_prefix_last - return the last address of a prefix.
 *
 * For IPv4: the broadcast address (network address ORed with complement
 * of prefix mask). For IPv6: the host-bits-all-ones address (same
 * computation). For /32 (IPv4) or /128 (IPv6), the first and last
 * addresses are identical.
 *
 * prefix: pointer to a valid cidr_prefix_t
 * out:    caller-provided cidr_addr_t; on success receives the last
 *         address with family matching prefix->addr.family
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_INVAL if prefix or out is NULL, or if
 *   prefix->addr.family is CIDR_AF_UNSPEC.
 *
 * No allocation occurs.
 *
 * See ARCHITECTURE.md §4.3.4.
 */
cidr_err_t cidr_prefix_last(const cidr_prefix_t *prefix, cidr_addr_t *out)
    __attribute__((warn_unused_result));

/*
 * cidr_prefix_contains - test whether a prefix contains an address.
 *
 * Writes true into *out if addr falls within prefix, false otherwise.
 * Computed as (addr & mask) == prefix->addr. out may be NULL -- when
 * NULL, the computation is performed and the status code is returned
 * without writing the result.
 *
 * prefix: pointer to a valid cidr_prefix_t
 * addr:   pointer to a valid cidr_addr_t
 * out:    optional result pointer (may be NULL); on success receives
 *         true or false
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_INVAL if prefix or addr is NULL, or if either has
 *   family == CIDR_AF_UNSPEC.
 * Returns CIDR_ERR_FAMILY if prefix->addr.family != addr->family.
 *
 * No allocation occurs.
 *
 * See ARCHITECTURE.md §4.3.5.
 */
cidr_err_t cidr_prefix_contains(const cidr_prefix_t *prefix,
                                const cidr_addr_t *addr, bool *out)
    __attribute__((warn_unused_result));

/*
 * cidr_prefix_overlaps - test whether two prefixes share any address.
 *
 * Two prefixes overlap if and only if one contains the network address
 * of the other: cidr_prefix_contains(a, b->addr) ||
 * cidr_prefix_contains(b, a->addr). out may be NULL.
 *
 * a, b: pointers to valid cidr_prefix_t values (same family)
 * out:  optional result pointer (may be NULL); on success receives
 *       true or false
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_INVAL if a or b is NULL, or if either has
 *   family == CIDR_AF_UNSPEC.
 * Returns CIDR_ERR_FAMILY if a->addr.family != b->addr.family.
 *
 * No allocation occurs.
 *
 * See ARCHITECTURE.md §4.3.6.
 */
cidr_err_t cidr_prefix_overlaps(const cidr_prefix_t *a, const cidr_prefix_t *b,
                                bool *out) __attribute__((warn_unused_result));

/*
 * cidr_prefix_supernet - compute the parent prefix at pfxlen - 1.
 *
 * The supernet of 192.168.1.0/24 is 192.168.0.0/23. Computed by
 * decrementing pfxlen by one and zeroing the new host bit in the
 * network address.
 *
 * prefix: pointer to a valid cidr_prefix_t (pfxlen must be > 0)
 * out:    caller-provided cidr_prefix_t; on success receives the
 *         supernet with family matching prefix->addr.family
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_INVAL if prefix or out is NULL, or if
 *   prefix->addr.family is CIDR_AF_UNSPEC.
 * Returns CIDR_ERR_OVERFLOW if prefix->pfxlen is 0 (the entire
 *   address space has no parent).
 *
 * No allocation occurs.
 *
 * See ARCHITECTURE.md §4.3.7.
 */
cidr_err_t cidr_prefix_supernet(const cidr_prefix_t *prefix, cidr_prefix_t *out)
    __attribute__((warn_unused_result));

/*
 * cidr_subnet_iter_init - initialise a subnet iterator.
 *
 * Prepares the iterator to enumerate all subnets of prefix at the given
 * target prefix length. target_pfxlen must be strictly greater than
 * prefix->pfxlen and within the valid range for the address family.
 * Iterator state lives on the caller's stack -- no allocation.
 *
 * iter:         caller-provided cidr_subnet_iter_t; initialised on success
 * prefix:       pointer to a valid cidr_prefix_t
 * target_pfxlen: prefix length of the subnets to enumerate
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_INVAL if iter or prefix is NULL, or if
 *   prefix->addr.family is CIDR_AF_UNSPEC.
 * Returns CIDR_ERR_PFXLEN if target_pfxlen <= prefix->pfxlen or
 *   target_pfxlen exceeds the maximum for the address family.
 *
 * No allocation occurs.
 *
 * See ARCHITECTURE.md §4.3.8.
 */
cidr_err_t cidr_subnet_iter_init(cidr_subnet_iter_t *iter,
                                 const cidr_prefix_t *prefix,
                                 uint8_t target_pfxlen)
    __attribute__((warn_unused_result));

/*
 * cidr_subnet_iter_next - yield the next subnet from a subnet iterator.
 *
 * Writes the next subnet into out and advances the iterator. Subnets
 * are yielded in ascending network address order. The first subnet
 * yielded has the same network address as the parent prefix.
 *
 * iter: pointer to an initialised cidr_subnet_iter_t
 * out:  caller-provided cidr_prefix_t; on success receives the next
 *       subnet's address and target_pfxlen
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_DONE when all subnets have been yielded -- out is
 *   NOT modified on this return. This is the normal termination
 *   condition, not an error.
 *
 * The caller's loop pattern:
 *   cidr_subnet_iter_init(&iter, &prefix, target_pfxlen);
 *   while ((err = cidr_subnet_iter_next(&iter, &subnet)) == CIDR_OK) {
 *       // process subnet
 *   }
 *   if (err != CIDR_ERR_DONE) {
 *       // handle unexpected error
 *   }
 *
 * No allocation occurs.
 *
 * See ARCHITECTURE.md §4.3.8.
 */
cidr_err_t cidr_subnet_iter_next(cidr_subnet_iter_t *iter, cidr_prefix_t *out)
    __attribute__((warn_unused_result));

/*
 * cidr_prefix_cmp - compare two prefixes within the same family.
 *
 * Compares two cidr_prefix_t values. Ordering matches
 * CIDR_SORT_NETWORK_ASC: network address ascending (lexicographic on
 * address bytes in network byte order), then prefix length ascending
 * within the same network address. Writes -1, 0, or +1 into *result.
 *
 * a, b:   pointers to valid cidr_prefix_t values (same family)
 * result: caller-provided int pointer; on success receives -1, 0, or +1
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_INVAL if a, b, or result is NULL, or if either
 *   prefix has addr.family == CIDR_AF_UNSPEC.
 * Returns CIDR_ERR_FAMILY if a->addr.family != b->addr.family.
 *
 * Complexity: O(W) where W is address width in bytes (4 for IPv4,
 * 16 for IPv6). No allocation occurs.
 *
 * See ARCHITECTURE.md §4.4.
 */
cidr_err_t cidr_prefix_cmp(const cidr_prefix_t *a, const cidr_prefix_t *b,
                           int *result) __attribute__((warn_unused_result));

/*
 * cidr_bulk_sort - sort a prefix array in place using MSD radix sort.
 *
 * Sorts the caller-provided prefix array in place using the shared in-place
 * MSD radix sort engine. Two orderings are supported:
 *
 * CIDR_SORT_NETWORK_ASC (0) -- network address ascending (lexicographic on
 *   address bytes in network byte order), prefix length ascending within
 *   the same network address. Used by cidr_bulk_aggregate().
 *
 * CIDR_SORT_PFXLEN_DESC (1) -- prefix length descending (longest prefix
 *   first), network address ascending within equal prefix lengths. Used to
 *   prepare a prefix table for longest-prefix-match with
 *   cidr_bulk_contains(). Stable: exact duplicate prefixes preserve their
 *   original input order.
 *
 * prefixes: caller-provided prefix array; modified in place
 * count:    number of entries in prefixes
 * order:    CIDR_SORT_NETWORK_ASC or CIDR_SORT_PFXLEN_DESC
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_INVAL if order is not a valid cidr_sort_order_t value,
 *   if count > 0 and prefixes is NULL, or if any prefix has
 *   addr.family == CIDR_AF_UNSPEC.
 * Returns CIDR_ERR_FAMILY if the array contains mixed IPv4 and IPv6 prefixes.
 *
 * When count == 0, prefixes may be NULL; returns CIDR_OK with no work
 * performed. See ARCHITECTURE.md §3.4 for the empty array policy.
 *
 * Complexity: O(n * k) where k is key width in bytes (5 for IPv4, 17 for
 * IPv6); treated as O(n) because k is a compile-time constant.
 * No allocation occurs. Stack usage: bounded per ARCHITECTURE.md §5.4.
 *
 * See ARCHITECTURE.md §5.5 for the sort specification, §5.4 for the radix
 * sort algorithm and stack bound.
 */
cidr_err_t cidr_bulk_sort(cidr_prefix_t *prefixes, size_t count,
                          cidr_sort_order_t order)
    __attribute__((warn_unused_result));

#endif /* LIBCIDR_H */
