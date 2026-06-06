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
 * IPv4: strict dotted-decimal. IPv6: full, compressed, and
 * IPv4-mapped mixed forms per RFC 4291 §2.2 and RFC 5952 §5.
 * See ARCHITECTURE.md §4.1.
 *
 * Returns CIDR_ERR_INVAL if src or out is NULL.
 * Returns CIDR_ERR_PARSE on malformed input.
 */
cidr_err_t cidr_addr_parse(const char *src, cidr_addr_t *out)
    __attribute__((warn_unused_result));

/*
 * cidr_addr_format - format an address as canonical text.
 * IPv4: strict dotted-decimal. IPv6: RFC 5952 canonical form.
 * See ARCHITECTURE.md §4.2.
 *
 * buf must be >= CIDR_ADDR_STR_MAX bytes.
 *
 * Returns CIDR_ERR_INVAL if addr or buf is NULL, family is
 * CIDR_AF_UNSPEC, or len < CIDR_ADDR_STR_MAX.
 */
cidr_err_t cidr_addr_format(const cidr_addr_t *addr, char *buf, size_t len)
    __attribute__((warn_unused_result));

/*
 * cidr_addr_to_v4 - extract embedded IPv4 from an IPv4-mapped IPv6
 * address (::ffff:0:0/96). See ARCHITECTURE.md §4.1.3.
 *
 * Returns CIDR_ERR_INVAL if either pointer is NULL or family is UNSPEC.
 * Returns CIDR_ERR_FAMILY if addr is IPv4 (wrong family), or if addr
 * is IPv6 but not within the IPv4-mapped prefix.
 */
cidr_err_t cidr_addr_to_v4(const cidr_addr_t *addr, cidr_addr_t *out)
    __attribute__((warn_unused_result));

/*
 * cidr_addr_cmp - compare two addresses within the same family.
 * Lexicographic on address bytes in network byte order.
 * Result: -1, 0, or +1. See ARCHITECTURE.md §4.4.
 *
 * Returns CIDR_ERR_FAMILY if families differ.
 */
cidr_err_t cidr_addr_cmp(const cidr_addr_t *a, const cidr_addr_t *b,
                         int *result) __attribute__((warn_unused_result));

/*
 * cidr_prefix_parse - parse a CIDR prefix from text (strict).
 * Input must be "address/prefixlen". See ARCHITECTURE.md §4.1.4.
 *
 * Returns CIDR_ERR_INVAL if src or out is NULL.
 * Returns CIDR_ERR_PARSE if the address portion does not parse.
 * Returns CIDR_ERR_PFXLEN if prefix length is out of family range.
 * Returns CIDR_ERR_HOSTBITS if the address has any host bits set.
 */
cidr_err_t cidr_prefix_parse(const char *src, cidr_prefix_t *out)
    __attribute__((warn_unused_result));

/*
 * cidr_prefix_from_host - construct a prefix from a host address
 * (explicit host-to-network). Host bits are zeroed. Must not return
 * CIDR_ERR_HOSTBITS. See ARCHITECTURE.md §4.1.4.
 *
 * Returns CIDR_ERR_INVAL if addr or out is NULL or family is UNSPEC.
 * Returns CIDR_ERR_PFXLEN if pfxlen is out of family range.
 */
cidr_err_t cidr_prefix_from_host(const cidr_addr_t *addr, uint8_t pfxlen,
                                 cidr_prefix_t *out)
    __attribute__((warn_unused_result));

/*
 * cidr_prefix_format - format a CIDR prefix as "address/prefixlen".
 * buf must be >= CIDR_PREFIX_STR_MAX bytes.
 * See ARCHITECTURE.md §4.2.3.
 *
 * Returns CIDR_ERR_INVAL if prefix or buf is NULL, family is
 * CIDR_AF_UNSPEC, or len < CIDR_PREFIX_STR_MAX.
 */
cidr_err_t cidr_prefix_format(const cidr_prefix_t *prefix, char *buf,
                              size_t len) __attribute__((warn_unused_result));

/*
 * cidr_prefix_broadcast - broadcast address of an IPv4 prefix.
 * IPv4 only; returns CIDR_ERR_FAMILY for IPv6.
 * See ARCHITECTURE.md §4.3.2.
 */
cidr_err_t cidr_prefix_broadcast(const cidr_prefix_t *prefix, cidr_addr_t *out)
    __attribute__((warn_unused_result));

/*
 * cidr_prefix_mask - prefix mask (network mask).
 * pfxlen leading 1-bits, remaining zero; network byte order.
 * See ARCHITECTURE.md §4.3.3.
 */
cidr_err_t cidr_prefix_mask(const cidr_prefix_t *prefix, cidr_addr_t *out)
    __attribute__((warn_unused_result));

/*
 * cidr_prefix_first - network (first) address of a prefix.
 * Host bits are guaranteed zero by construction.
 * See ARCHITECTURE.md §4.3.4.
 */
cidr_err_t cidr_prefix_first(const cidr_prefix_t *prefix, cidr_addr_t *out)
    __attribute__((warn_unused_result));

/*
 * cidr_prefix_last - last address of a prefix (broadcast for IPv4,
 * host-bits-all-ones for IPv6). See ARCHITECTURE.md §4.3.4.
 */
cidr_err_t cidr_prefix_last(const cidr_prefix_t *prefix, cidr_addr_t *out)
    __attribute__((warn_unused_result));

/*
 * cidr_prefix_contains - test whether a prefix contains an address.
 * Computed as (addr & mask) == prefix->addr. out may be NULL.
 * See ARCHITECTURE.md §4.3.5.
 *
 * Returns CIDR_ERR_FAMILY if families differ.
 */
cidr_err_t cidr_prefix_contains(const cidr_prefix_t *prefix,
                                const cidr_addr_t *addr, bool *out)
    __attribute__((warn_unused_result));

/*
 * cidr_prefix_overlaps - test whether two prefixes share any address.
 * One contains the other's network address. out may be NULL.
 * See ARCHITECTURE.md §4.3.6.
 *
 * Returns CIDR_ERR_FAMILY if families differ.
 */
cidr_err_t cidr_prefix_overlaps(const cidr_prefix_t *a, const cidr_prefix_t *b,
                                bool *out) __attribute__((warn_unused_result));

/*
 * cidr_prefix_supernet - parent prefix at pfxlen - 1.
 * Returns CIDR_ERR_OVERFLOW when pfxlen is 0 (no parent).
 * See ARCHITECTURE.md §4.3.7.
 */
cidr_err_t cidr_prefix_supernet(const cidr_prefix_t *prefix, cidr_prefix_t *out)
    __attribute__((warn_unused_result));

/*
 * cidr_subnet_iter_init - initialise a subnet iterator.
 * target_pfxlen must be > prefix->pfxlen and within family range.
 * Iterator state lives on the caller's stack. See ARCHITECTURE.md §4.3.8.
 *
 * Returns CIDR_ERR_PFXLEN if target_pfxlen is out of range.
 */
cidr_err_t cidr_subnet_iter_init(cidr_subnet_iter_t *iter,
                                 const cidr_prefix_t *prefix,
                                 uint8_t target_pfxlen)
    __attribute__((warn_unused_result));

/*
 * cidr_subnet_iter_next - yield the next subnet in ascending order.
 * Returns CIDR_ERR_DONE when exhausted (out not modified).
 * See ARCHITECTURE.md §4.3.8.
 *
 * Typical loop:
 *   cidr_subnet_iter_init(&iter, &prefix, target);
 *   while ((err = cidr_subnet_iter_next(&iter, &subnet)) == CIDR_OK)
 *       process(subnet);
 */
cidr_err_t cidr_subnet_iter_next(cidr_subnet_iter_t *iter, cidr_prefix_t *out)
    __attribute__((warn_unused_result));

/*
 * cidr_prefix_cmp - compare two prefixes (CIDR_SORT_NETWORK_ASC order).
 * Result: -1, 0, or +1. See ARCHITECTURE.md §4.4.
 *
 * Returns CIDR_ERR_FAMILY if families differ.
 */
cidr_err_t cidr_prefix_cmp(const cidr_prefix_t *a, const cidr_prefix_t *b,
                           int *result) __attribute__((warn_unused_result));

/*
 * cidr_bulk_sort - sort a prefix array in place using MSD radix sort.
 * See ARCHITECTURE.md §5.5.
 *
 * CIDR_SORT_NETWORK_ASC (0): network address ascending, pfxlen ascending
 *   within the same address. Used by cidr_bulk_aggregate().
 *
 * CIDR_SORT_PFXLEN_DESC (1): prefix length descending, network address
 *   ascending within equal lengths. Used to prepare a prefix table for
 *   longest-prefix-match with cidr_bulk_contains(). Stable: exact
 *   duplicate prefixes preserve their original input order.
 *
 * When count == 0, prefixes may be NULL; returns CIDR_OK.
 *
 * Returns CIDR_ERR_INVAL if order is invalid, count > 0 and prefixes
 *   is NULL, or any prefix has family CIDR_AF_UNSPEC.
 * Returns CIDR_ERR_FAMILY on mixed IPv4/IPv6 arrays.
 */
cidr_err_t cidr_bulk_sort(cidr_prefix_t *prefixes, size_t count,
                          cidr_sort_order_t order)
    __attribute__((warn_unused_result));

/*
 * cidr_bulk_parse - batch-parse address strings.
 *
 * Parses count address strings from the srcs array into the out array.
 * Each string is parsed per cidr_addr_parse() semantics (ARCHITECTURE.md
 * §4.1). The errs array receives per-item error codes (CIDR_OK on success,
 * CIDR_ERR_PARSE on failure). errs may be NULL to suppress per-item errors.
 *
 * All items are attempted regardless of individual parse failures. The
 * expected address family is inferred from the first successfully-parsed
 * item. After the full batch, return-code precedence applies:
 *
 *   CIDR_ERR_FAMILY > CIDR_ERR_PARSE > CIDR_OK
 *
 * A NULL element in srcs causes immediate fail-fast: CIDR_ERR_INVAL is
 * returned and no output is written.
 *
 * srcs:  array of count null-terminated address strings
 * count: number of entries in srcs, out, and errs
 * out:   caller-provided cidr_addr_t array; on success receives parsed
 *        addresses; on parse failure out[i].family is CIDR_AF_UNSPEC
 * errs:  optional per-item error array (may be NULL); when non-NULL, must
 *        have space for count cidr_err_t values
 *
 * Returns CIDR_OK on success (all items parsed to the same family).
 * Returns CIDR_ERR_INVAL if srcs or out is NULL, or if any srcs[i] is
 *   NULL (fail-fast).
 * Returns CIDR_ERR_PARSE if any item failed to parse.
 * Returns CIDR_ERR_FAMILY if successfully-parsed items have mixed families.
 *
 * When count == 0, returns CIDR_OK with no work performed per the empty
 * array policy (ARCHITECTURE.md §3.4).
 *
 * Complexity: O(n) where n = count.
 * No allocation occurs.
 *
 * See ARCHITECTURE.md §5.2 for the batch parse specification.
 */
cidr_err_t cidr_bulk_parse(const char **srcs, size_t count, cidr_addr_t *out,
                           cidr_err_t *errs)
    __attribute__((warn_unused_result));

/*
 * cidr_bulk_contains - bulk containment: find first matching prefix for
 *                      each address.
 *
 * For each address in addrs, scans prefixes in order and writes the index
 * of the first matching prefix into matches[i], or -1 if no prefix matched.
 * Match is first-match-in-order. Callers needing longest-prefix-match
 * semantics should sort prefixes by CIDR_SORT_PFXLEN_DESC via
 * cidr_bulk_sort() before calling.
 *
 * When prefix_count == 0, all matches[i] are written as -1 and the function
 * returns CIDR_OK. When addr_count == 0, returns CIDR_OK with no work.
 *
 * addrs:        array of addr_count addresses to test
 * addr_count:   number of entries in addrs and matches
 * prefixes:     array of prefix_count prefixes to scan per address
 * prefix_count: number of entries in prefixes
 * matches:      caller-provided ssize_t array; receives match index or -1
 * errs:         optional per-item error array (may be NULL); when non-NULL,
 *               each entry is set to CIDR_OK on match or no-match, or
 *               CIDR_ERR_FAMILY when the address family does not match the
 *               prefix table family
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_INVAL if addrs or matches is NULL when addr_count > 0,
 *   if prefixes is NULL when prefix_count > 0, or if any address or prefix
 *   has family == CIDR_AF_UNSPEC.
 * Returns CIDR_ERR_FAMILY if the address array or prefix array contains
 *   mixed families, or if the address family does not match the prefix
 *   family.
 *
 * Complexity: O(addr_count * prefix_count).
 * No allocation occurs.
 *
 * See ARCHITECTURE.md §5.3 for the bulk containment specification.
 */
cidr_err_t cidr_bulk_contains(const cidr_addr_t *addrs, size_t addr_count,
                              const cidr_prefix_t *prefixes,
                              size_t prefix_count, ssize_t *matches,
                              cidr_err_t *errs)
    __attribute__((warn_unused_result));

/*
 * cidr_bulk_aggregate - aggregate a prefix array to a minimal covering set.
 *
 * Aggregates prefixes in place using a five-step algorithm: radix sort,
 * duplicate removal, containment removal, and repeated sibling merge with
 * early termination. The result covers exactly the same address space as
 * the input -- no more, no less.
 *
 * On return, the first *out_count entries are the aggregated prefixes;
 * the remaining entries are undefined.
 *
 * prefixes:  caller-provided prefix array; modified in place
 * count:     number of entries in prefixes
 * out_count: receives the number of prefixes in the aggregated result;
 *            must not be NULL
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_INVAL if prefixes or out_count is NULL, or if any
 *   prefix has addr.family == CIDR_AF_UNSPEC.
 * Returns CIDR_ERR_FAMILY if the array contains mixed IPv4 and IPv6
 *   prefixes.
 *
 * When count == 0, writes 0 to *out_count and returns CIDR_OK.
 *
 * The caller's array is modified directly. If the original must be
 * preserved, copy the array before calling.
 *
 * Complexity: O(n * k) where k is key width in bytes (5 for IPv4, 17 for
 * IPv6); treated as O(n) because k is a compile-time constant.
 * No allocation occurs.
 *
 * See ARCHITECTURE.md §5.4 for the aggregation algorithm.
 */
cidr_err_t cidr_bulk_aggregate(cidr_prefix_t *prefixes, size_t count,
                               size_t *out_count)
    __attribute__((warn_unused_result));

/*
 * cidr_addr_classify - classify an address against the IANA
 * special-purpose registry. Returns a bitmask of CIDR_CLASS_* flags;
 * CIDR_CLASS_GLOBAL when no block matches (mutually exclusive).
 * See ARCHITECTURE.md §7.1, §7.2.
 */
cidr_err_t cidr_addr_classify(const cidr_addr_t *addr, cidr_class_t *out)
    __attribute__((warn_unused_result));

/*
 * cidr_index_create - build a Patricia trie index from a prefix array.
 *
 * Builds an array-packed LC-trie (Level-Compressed Patricia trie) from the
 * caller-provided prefix array. The prefix array is copied internally -- the
 * caller may free or modify their array after the call returns. This is the
 * only allocating function in the library; callers must balance every
 * successful create with a cidr_index_destroy() call.
 *
 * prefixes:      caller-provided prefix array (all same family)
 * count:         number of entries in prefixes; must be >= 1
 * out:           receives pointer to the allocated index on success
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_INVAL if prefixes or out is NULL, if count == 0, if
 *   count > UINT32_MAX - 1, or if any prefix has addr.family == CIDR_AF_UNSPEC.
 * Returns CIDR_ERR_FAMILY if the array contains mixed IPv4 and IPv6 prefixes.
 * Returns CIDR_ERR_NOMEM on allocation failure.
 *
 * Complexity: O(n * W) where n is prefix count and W is address width in
 * bits (32 for IPv4, 128 for IPv6). See ARCHITECTURE.md §6.2.
 */
cidr_err_t cidr_index_create(const cidr_prefix_t *prefixes, size_t count,
                             cidr_index_t **out)
    __attribute__((warn_unused_result));

/*
 * cidr_index_destroy - release all memory for a Patricia trie index.
 *
 * Frees the node array, the copied prefix array, and the index struct.
 * Must be called exactly once per index created by a successful
 * cidr_index_create() call. NULL-safe: passing NULL is a valid no-op.
 *
 * index: pointer to an index previously returned by cidr_index_create(),
 *        or NULL
 *
 * No error return -- destructors have no meaningful failure mode.
 * See ARCHITECTURE.md §6.2.
 */
void cidr_index_destroy(cidr_index_t *index);

/*
 * cidr_index_lookup - longest-prefix match for each address in an array.
 *
 * For each address in addrs, traverses the index trie and writes the index
 * of the longest-prefix match into matches[i], or -1 if no prefix matched.
 * Lookup is O(address length) per query by construction of the LC-trie.
 * Concurrent calls on the same index from multiple threads are safe (the
 * index is immutable after cidr_index_create() completes).
 *
 * index:   pointer to a valid index (must not be NULL)
 * addrs:   array of count addresses to query
 * count:   number of entries in addrs and matches
 * matches: caller-provided ssize_t array; receives match index or -1
 * errs:    optional per-item error array (may be NULL)
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_INVAL if index is NULL, if count > 0 and addrs or
 *   matches is NULL, or if any address has family == CIDR_AF_UNSPEC.
 * Returns CIDR_ERR_FAMILY if any address family does not match the index
 *   family.
 *
 * When count == 0, returns CIDR_OK with no work performed per the empty
 * array policy (ARCHITECTURE.md §3.4).
 *
 * Complexity: O(count * W) where W is address width in bits -- empirically
 * O(4-8) for IPv4 and O(8-15) for IPv6 on real routing tables per
 * ARCHITECTURE.md §6.3.
 *
 * See ARCHITECTURE.md §6.2 for the full lookup specification.
 */
cidr_err_t cidr_index_lookup(const cidr_index_t *index,
                             const cidr_addr_t *addrs, size_t count,
                             ssize_t *matches, cidr_err_t *errs)
    __attribute__((warn_unused_result));

#endif /* LIBCIDR_H */
