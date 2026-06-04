# Architecture

## 1. Library Overview

### 1.1 Design Model

libcidr is an address arithmetic library, not a routing library and not a
network I/O library. It parses, formats, and computes over IPv4 and IPv6
addresses and CIDR prefixes with strict RFC semantics. It has no knowledge
of routing protocols, network interfaces, DNS, or packet capture. Its scope
begins when it receives a text string or binary address value and ends when
it returns a computed result to the caller.

The library is organised in two independent layers. The C library layer
(`libcidr.a` / `libcidr.so`) is a standalone C11 library with a clean public
API in `libcidr.h`. It has no Python dependency and is usable directly from
any C application. The CPython binding layer is a separate compilation unit
that wraps the C public API with no logic of its own. Building the Python
extension requires the C library but not vice versa.

The design target is correctness first, security second, performance third,
and ease of use fourth. This priority order is not aspirational -- it governs
every decision in this document. A result that is fast but wrong is a bug.
A result that is safe but inconvenient is correct behaviour.

### 1.2 What the Library Does Not Do

libcidr does not implement any routing protocol logic. It does not perform
network I/O -- no sockets, no packet capture, no DNS resolution. It does not
manage interface metadata or address lifecycle. It does not retrieve WHOIS,
RIR, or ASN data. It does not perform DNS reverse mapping. It does not
integrate with NumPy -- the Python layer works on plain Python sequences. It
does not silently normalise invalid input -- host bits set in a prefix is an
error, not a quiet fix. It does not coerce between address families -- IPv4
and IPv6 are always kept distinct. It does not accept textual forms that are
not defined in the relevant RFCs.

### 1.3 Design Influences and Rejected Alternatives

**Separate IPv4 and IPv6 types were rejected.** A design with distinct
`cidr_addr4_t` and `cidr_addr6_t` types doubles the function surface, makes
mixed-family bulk operations awkward, and moves family dispatch to the caller
at every call site. A single type with a family discriminator -- matching the
`struct sockaddr` / `sa_family_t` model -- is the correct abstraction. The
family branch is cheap and always necessary; centralising it in the type is
cleaner than forcing the caller to own it.

**Host-byte-order integer storage was rejected.** Storing IPv4 addresses as
`uint32_t` and IPv6 as two `uint64_t` values in host byte order requires
`htonl`/`ntohl` on every parse and format on little-endian hosts, introduces
a class of byte-order conversion bugs, and diverges from the wire format the
RFCs define. Network byte order `uint8_t` arrays are identical on all
platforms, match the RFC representation directly, and eliminate the conversion
path entirely.

**Silent host-bit zeroing on prefix parse was rejected.** A single
`cidr_prefix_parse()` that silently zeros host bits hides caller bugs. A
caller passing `192.168.1.5/24` when they meant `192.168.1.0/24` receives
a result they did not ask for, with no indication that their input was wrong.
Two functions with distinct documented contracts -- one strict, one explicit
-- surface the error when the caller is confused and document the intent when
the caller is deliberate.

**Liberal input parsing was rejected.** `netaddr`'s acceptance of
non-RFC textual forms is identified in the gap analysis as a correctness
liability. Leading zeros in IPv4 octets are ambiguous -- some parsers treat
them as octal, some ignore them. Hex IPv4 notation is not defined in any
RFC. Accepting these forms introduces parser-dependent behaviour that cannot
be validated against a specification. libcidr accepts exactly the forms
defined in RFC 1123 (IPv4) and RFC 4291 as updated by RFC 5952 (IPv6).
Uppercase IPv6 input is the one exception: RFC 4291 does not prohibit it,
so it is accepted on input and normalised to lowercase per RFC 5952 §4.3.

**Callback-based subnet iteration was rejected.** A callback model for
subnet enumeration drives iteration from inside the library, preventing the
caller from pausing or stopping early, requiring error propagation through
a context struct, and mapping poorly to Python's iterator protocol. A
stateful iterator with state on the caller's stack gives the caller control,
maps directly to a Python `__iter__`/`__next__` implementation, and requires
no allocation.

**Library-allocated output buffers for bulk operations were rejected.**
Bulk operations that allocate their output arrays introduce hidden latency,
require the caller to free memory, and make the memory footprint of a bulk
call non-deterministic. Caller-provided contiguous arrays are allocated
once by the caller, cache-friendly, and consistent with the zero-allocation
model applied throughout the library.

### 1.4 API Philosophy

**Errors are returned, never fatal.** Every public function except
`cidr_index_destroy()` returns `cidr_err_t`. Zero is always success. The
library does not call `abort()` or `exit()`. Every failure condition has a
named code. Functions are marked `__attribute__((warn_unused_result))` --
ignoring a return value is a compiler warning, not a silent runtime failure.
`cidr_index_destroy()` returns `void` and is NULL-safe; destructors have no
meaningful failure mode to report.

**Output is written into caller-provided storage.** Functions that produce
a value take an output pointer as their last parameter. Functions that produce
text take a caller-provided buffer and its length. No allocation occurs inside
any function except `cidr_index_create()`, which is explicitly documented as
an allocating operation.

**Correct usage is the only natural usage.** The API is designed so that
accidentally misusing it results in a compiler error or a named error code,
not silent wrong behaviour. Family mismatches return `CIDR_ERR_FAMILY`.
Host bits set in a strict prefix parse return `CIDR_ERR_HOSTBITS`. Buffer
too small for formatting returns `CIDR_ERR_INVAL`. There is no code path
that silently produces a wrong result from a wrong input.

**Complexity is explicit and documented.** Every function's algorithmic
complexity is stated in its documentation. No hidden sort, scan, or
allocation occurs inside any function without documentation. The caller
always knows what they are invoking.

**Thread safety.** The C library has no global mutable state. All functions
that do not operate on a `cidr_index_t` are fully reentrant and thread-safe
-- they operate exclusively on caller-provided stack and heap storage. A
`cidr_index_t` object is immutable after `cidr_index_create()` completes;
concurrent calls to `cidr_index_lookup()` on the same index from multiple
threads are safe. `cidr_index_create()` and `cidr_index_destroy()` must be
externally synchronised with respect to any other use of the same index.
The classification table is a compile-time constant; `cidr_addr_classify()`
is thread-safe.

---

## 2. Internal Component Map

```
+------------------------------------------------------------------+
|  C Public API  (libcidr.h)                                       |
|  cidr_addr_*  cidr_prefix_*  cidr_bulk_*  cidr_index_*           |
|  cidr_addr_classify()                                            |
+------------------------------------------------------------------+
|  CPython Binding Layer  (_libcidr_ext.c)                         |
|  PyType_FromSpec slot definitions, PyMethodDef tables            |
|  cidr_err_t -> Python exception mapping                          |
|  Stable ABI (Py_LIMITED_API = 0x030B0000)                        |
+-------------------------------+----------------------------------+
|  Arithmetic Engine            |  Bulk Engine                     |
|  cidr_addr_parse()            |  cidr_bulk_parse()               |
|  cidr_addr_format()           |  cidr_bulk_contains()            |
|  cidr_addr_to_v4()            |  cidr_bulk_aggregate()           |
|  cidr_addr_cmp()              |  cidr_bulk_sort()                |
|  cidr_prefix_parse()          |  In-place MSD radix sort         |
|  cidr_prefix_from_host()      |  Per-item error arrays           |
|  cidr_prefix_format()         +----------------------------------+
|  cidr_prefix_broadcast()      |  Patricia Trie Index             |
|  cidr_prefix_mask()           |  cidr_index_create()             |
|  cidr_prefix_first()          |  cidr_index_destroy()            |
|  cidr_prefix_last()           |  cidr_index_lookup()             |
|  cidr_prefix_contains()       |  O(address length) per lookup    |
|  cidr_prefix_overlaps()       |  Built in late phase             |
|  cidr_prefix_supernet()       |                                  |
|  cidr_prefix_cmp()            |                                  |
|  cidr_subnet_iter_*()         |                                  |
+-------------------------------+----------------------------------+
|  Address and Prefix Types                                        |
|  cidr_addr_t   -- family discriminator + uint8_t array           |
|  cidr_prefix_t -- cidr_addr_t with host bits zero + pfxlen       |
|  cidr_err_t    -- typed error enum                               |
+------------------------------------------------------------------+
|  Address Classification                                          |
|  cidr_addr_classify()                                            |
|  IANA special-purpose registries -- snapshot 2025-10-09          |
+------------------------------------------------------------------+
```

---

## 3. Core Types

### 3.1 `cidr_family_t` -- Address Family Discriminator

```c
typedef enum {
    CIDR_AF_UNSPEC = 0,  /* uninitialised or error sentinel */
    CIDR_AF_INET   = 4,  /* IPv4 */
    CIDR_AF_INET6  = 6,  /* IPv6 */
} cidr_family_t;
```

`CIDR_AF_UNSPEC` is the zero value. A zero-initialised `cidr_addr_t` has
family `CIDR_AF_UNSPEC` and is an invalid address. Functions that return a
`cidr_addr_t` via output pointer write `CIDR_AF_UNSPEC` into the output on
failure. Callers can check the family field as a secondary validity signal
after checking the return code, but the return code is the authoritative
error indicator.

The enum values 4 and 6 match the IP version numbers in the protocol headers.
This is intentional -- the values have semantic meaning and may be used in
diagnostic output and protocol-level code.

**`CIDR_AF_UNSPEC` input policy.** Any function that receives a `cidr_addr_t`
or `cidr_prefix_t` with `family == CIDR_AF_UNSPEC` returns `CIDR_ERR_INVAL`.
`CIDR_AF_UNSPEC` is a construction failure sentinel, not a valid input family.
This applies to all arithmetic, bulk, classification, and index functions.

### 3.2 `cidr_addr_t` -- IP Address

```c
typedef struct {
    cidr_family_t family;
    union {
        uint8_t v4[4];   /* IPv4, network byte order */
        uint8_t v6[16];  /* IPv6, network byte order */
    } addr;
} cidr_addr_t;
```

**Family:** Determines which union member is valid. Every function that
reads `addr` checks `family` first. Accessing `addr.v4` when `family` is
`CIDR_AF_INET6` or vice versa is a programming error -- no function does
this internally and no caller should.

**Storage:** Network byte order throughout. IPv4 `192.168.1.1` is stored
as `{0xC0, 0xA8, 0x01, 0x01}`. IPv6 `2001:db8::1` is stored as
`{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x01}`. This matches the wire format, the RFC
representation, and the format used by `struct in_addr`, `struct in6_addr`,
and Python's `ipaddress` internally. No conversion is required between
internal storage and any of these representations.

**Byte order rationale:** Network byte order is the format the RFCs define.
Storing addresses in the same format eliminates any byte-order conversion
path and the class of bugs at that path. The approach is identical on
x86_64 and ARM64 on both Linux and OpenBSD -- no `#ifdef` for host byte order,
no `htonl`/`ntohl` anywhere in the arithmetic layer.

**Size:** `cidr_addr_t` is 20 bytes on all target platforms (4 bytes family
enum + 16 bytes union). The union is sized to its larger member (16 bytes).
The enum alignment is 4 bytes. No padding is inserted between the enum and
the union because the union requires no alignment beyond 1 byte (it contains
only `uint8_t` arrays). The `_Static_assert(sizeof(cidr_addr_t) == 20)` in
`cidr_internal.h` enforces this at compile time.

### 3.3 `cidr_prefix_t` -- CIDR Prefix

```c
typedef struct {
    cidr_addr_t addr;   /* network address -- host bits always zero */
    uint8_t     pfxlen; /* prefix length: 0-32 (IPv4), 0-128 (IPv6) */
} cidr_prefix_t;
```

**Invariant:** `addr.addr` always contains the network address with host
bits zeroed. This invariant is established at construction and never
re-checked inside the library. Every function that receives a `cidr_prefix_t`
relies on this invariant being true. Constructing a `cidr_prefix_t` directly
(bypassing the construction functions) and passing it to any library function
with host bits set is undefined behaviour.

**Construction:** Two functions construct a `cidr_prefix_t`:

- `cidr_prefix_parse()` -- parses `address/prefixlen` text. Returns
  `CIDR_ERR_HOSTBITS` if the address has host bits set. The input must be
  a network address. This is the strict constructor.
- `cidr_prefix_from_host()` -- takes a `cidr_addr_t` and a prefix length,
  explicitly zeros host bits, and writes the result. The zeroing is
  guaranteed and documented -- this function exists for callers who have a
  host address and prefix length from system configuration or user input
  and want to derive the network address. The zeroing is not silent; the
  function name documents the operation.

**`pfxlen` range:** 0 to 32 inclusive for `CIDR_AF_INET`. 0 to 128
inclusive for `CIDR_AF_INET6`. Values outside these ranges are
`CIDR_ERR_PFXLEN`. A `pfxlen` of 0 is valid -- it represents the entire
address space for the given family.

**Size:** `cidr_prefix_t` is 24 bytes on all target platforms. The struct
contains a 20-byte `cidr_addr_t` (alignment 4) followed by a 1-byte `uint8_t`
`pfxlen`. The compiler inserts 3 bytes of trailing padding to align the
struct to a 4-byte boundary, which is required for correct array layout.
The total is 20 + 1 + 3 = 24 bytes. The `_Static_assert(sizeof(cidr_prefix_t)
== 24)` in `cidr_internal.h` enforces this at compile time. The struct is
not packed -- packing would cause unaligned access to `addr.family` at non-zero
array indices, which degrades performance on ARM64.

### 3.4 `cidr_err_t` -- Error Codes

```c
typedef enum {
    CIDR_OK           = 0, /* success */
    CIDR_ERR_INVAL    = 1, /* invalid argument -- NULL pointer, buffer too
                              small, CIDR_AF_UNSPEC family, count exceeds
                              internal limit, NULL element in string array */
    CIDR_ERR_PARSE    = 2, /* text did not parse as a valid address or
                              prefix per the applicable RFC */
    CIDR_ERR_PFXLEN   = 3, /* prefix length out of range for family */
    CIDR_ERR_HOSTBITS = 4, /* host bits set in prefix address -- strict
                              parse only */
    CIDR_ERR_NOMEM    = 5, /* allocation failure -- cidr_index_create()
                              only */
    CIDR_ERR_FAMILY   = 6, /* address family mismatch between operands,
                              or mixed families in a bulk array */
    CIDR_ERR_OVERFLOW = 7, /* result not representable -- supernet of /0 */
    CIDR_ERR_DONE     = 8, /* iterator exhausted -- not a failure */
} cidr_err_t;
```

Zero is always success. All public functions return `cidr_err_t` and carry
`__attribute__((warn_unused_result))`.

`CIDR_ERR_DONE` is a sentinel returned by `cidr_subnet_iter_next()` when
the iterator is exhausted. It is not an error -- it is the normal termination
condition. It is a named code rather than a boolean flag so that the caller's
loop condition is a single return-code check rather than two separate checks.

`CIDR_ERR_NOMEM` appears only in `cidr_index_create()`. No other function
allocates memory and therefore no other function can return this code.

**Empty array policy.** All bulk functions accept `count == 0` as a valid
input and return `CIDR_OK` with no work performed. This applies to
`cidr_bulk_parse()`, `cidr_bulk_contains()`, `cidr_bulk_aggregate()`,
`cidr_bulk_sort()`, and `cidr_index_lookup()`. Exception: `cidr_index_create()`
rejects `count == 0` with `CIDR_ERR_INVAL` because an index without any
prefixes has no address family and is not useful.

---

## 4. Arithmetic Engine

### 4.1 Parsing

#### 4.1.1 IPv4 Address Parsing -- `cidr_addr_parse()`

```c
cidr_err_t cidr_addr_parse(const char *src, cidr_addr_t *out)
    __attribute__((warn_unused_result));
```

Accepts strict dotted-decimal notation: four decimal octets in the range
0-255, separated by dots, with no leading zeros, no whitespace, no trailing
characters, and no alternative notations (no hex, no octal, no partial
addresses). This grammar is the widely-accepted interpretation of IPv4
dotted-decimal as implemented by compliant stacks; the textual representation
originates in RFC 1123 §2.1 which normalised the dotted-decimal convention.

**Rejection cases:**
- Fewer or more than four octets
- Any octet value outside 0-255
- Leading zeros in any octet (`010` is rejected; `10` is accepted).
  Leading zeros are rejected because they are historically ambiguous -- some
  parsers treat them as octal -- and no RFC specifies a canonical
  interpretation. Rejecting them ensures deterministic behaviour.
- Hex prefix (`0x...`)
- Whitespace anywhere in the string
- Trailing characters after the final octet

Returns `CIDR_ERR_INVAL` if either pointer is NULL.
Returns `CIDR_ERR_PARSE` on all malformed input.
On failure, `out->family` is written as `CIDR_AF_UNSPEC`.

#### 4.1.2 IPv6 Address Parsing -- `cidr_addr_parse()`

`cidr_addr_parse()` handles both IPv4 and IPv6; the family is determined by
the input text.

Accepts any of the three text forms defined in RFC 4291 §2.2, as updated by
RFC 5952:

1. **Full form:** eight 16-bit hex groups separated by colons.
   `2001:0db8:0000:0000:0000:0000:0000:0001`
2. **Compressed form:** `::` replaces one or more consecutive all-zero
   16-bit groups. `::` may appear at most once. `2001:db8::1`
3. **Mixed form:** six hex groups followed by an IPv4 dotted-decimal tail.
   Accepted only when the address falls within the IPv4-mapped prefix
   `::ffff:0:0/96`. `::ffff:192.0.2.1` is accepted. `2001:db8::192.0.2.1`
   is rejected with `CIDR_ERR_PARSE`. This restriction follows RFC 5952 §5,
   which limits mixed notation recommendations to addresses identifiable
   as having embedded IPv4 solely from the address field through a
   well-known prefix. This is stricter than RFC 4291, which permits mixed
   notation anywhere; the restriction avoids ambiguity and is applied
   consistently to both input and output.

**Case handling:** RFC 4291 does not specify case for input. Uppercase and
mixed-case hex digits are accepted on input and normalised to lowercase
internally, consistent with RFC 5952 §4.3.

**IPv4-mapped addresses (`::ffff:0:0/96`):** Accepted and stored as
`CIDR_AF_INET6` with the full 16-byte representation. No family mixing
occurs in storage -- `family` is `CIDR_AF_INET6` and `addr.v6` is the valid
member, with the embedded IPv4 bytes at octets 12-15. The embedded IPv4
address is extractable as a separate `cidr_addr_t` via `cidr_addr_to_v4()`.

**IPv4-compatible addresses (`::0:0/96` with non-zero IPv4 part):**
Rejected with `CIDR_ERR_PARSE`. RFC 4291 §2.5.5.1 explicitly deprecates
this form and states new implementations are not required to support it.

#### 4.1.3 IPv4-Mapped Address Extraction -- `cidr_addr_to_v4()`

```c
cidr_err_t cidr_addr_to_v4(const cidr_addr_t *addr, cidr_addr_t *out)
    __attribute__((warn_unused_result));
```

Extracts the embedded IPv4 address from an IPv4-mapped IPv6 address
(`::ffff:0:0/96`). The input must be a `CIDR_AF_INET6` address whose first
12 bytes match the IPv4-mapped prefix (`00 00 00 00 00 00 00 00 00 00 FF FF`).
On success, `out` is written as a `cidr_addr_t` with `family = CIDR_AF_INET`
and the 4 extracted bytes in `addr.v4`.

This function produces two clean, distinct structs -- the input is a valid
`CIDR_AF_INET6` address and the output is a valid `CIDR_AF_INET` address.
No family mixing occurs in any single struct. The family-discriminator
invariant is preserved in both the input and output.

Returns `CIDR_ERR_INVAL` if either pointer is NULL or if `addr->family ==
CIDR_AF_UNSPEC`.
Returns `CIDR_ERR_FAMILY` if `addr->family` is `CIDR_AF_INET` (valid IPv4,
wrong family for extraction), or if `addr->family` is `CIDR_AF_INET6` but the
address does not match the IPv4-mapped prefix.

#### 4.1.4 CIDR Prefix Parsing

Two functions parse CIDR notation:

```c
cidr_err_t cidr_prefix_parse(const char *src, cidr_prefix_t *out)
    __attribute__((warn_unused_result));

cidr_err_t cidr_prefix_from_host(const cidr_addr_t *addr, uint8_t pfxlen,
    cidr_prefix_t *out)
    __attribute__((warn_unused_result));
```

**`cidr_prefix_parse(src, out)`** -- strict. Input must be
`address/prefixlen` where `address` is a valid address per §4.1.1 or §4.1.2
and `prefixlen` is a decimal integer in the valid range for the address
family. Returns `CIDR_ERR_HOSTBITS` if the address has any host bits set.
The input must be a network address. This matches the RFC 4632 definition
of a prefix as a network address plus prefix length.
Returns `CIDR_ERR_INVAL` if either pointer is NULL.

**`cidr_prefix_from_host(addr, pfxlen, out)`** -- explicit host-to-network.
Accepts a `cidr_addr_t` host address and a prefix length. Computes the
network address by zeroing host bits. Documents explicitly that this zeroing
occurs. The function name makes the operation visible at every call site.
Returns `CIDR_ERR_INVAL` if any pointer is NULL or if `addr->family ==
CIDR_AF_UNSPEC`.
Returns `CIDR_ERR_PFXLEN` if `pfxlen` is out of range for the address family.

RFC 4632 §3.1 defines CIDR notation in terms of network addresses. It does
not define the behaviour when host bits are set in CIDR input. The strict
rejection in `cidr_prefix_parse()` is the correct interpretation of the RFC's
definition -- a prefix is a network address plus prefix length by definition,
so input with host bits set is not a prefix.

### 4.2 Formatting

All formatting functions write into caller-provided buffers. The caller is
responsible for allocating a buffer of sufficient size. Two named constants
define the maximum buffer sizes:

```c
#define CIDR_ADDR_STR_MAX    46   /* max IPv6 text length including NUL  */
#define CIDR_PREFIX_STR_MAX  50   /* max IPv6 CIDR: 45 addr chars + '/'
                                     + "128" + NUL = 50                  */
```

These values are statically derivable from the RFC specifications. No runtime
computation is required to size a buffer correctly. All formatting functions
return `CIDR_ERR_INVAL` if `len < CIDR_ADDR_STR_MAX` or `len < CIDR_PREFIX_STR_MAX`
respectively.

#### 4.2.1 IPv4 Address Formatting -- `cidr_addr_format()`

```c
cidr_err_t cidr_addr_format(const cidr_addr_t *addr, char *buf, size_t len)
    __attribute__((warn_unused_result));
```

Produces dotted-decimal notation. Four decimal octets separated by dots.
No leading zeros. No alternative notations. Output is always in the
canonical form -- there is only one canonical form for IPv4 text.

For IPv6 addresses, produces RFC 5952 canonical form per §4.2.2.

Returns `CIDR_ERR_INVAL` if any pointer is NULL, if `len < CIDR_ADDR_STR_MAX`,
or if `addr->family == CIDR_AF_UNSPEC`.

#### 4.2.2 IPv6 Address Formatting

Produces canonical text per RFC 5952. The rules applied, in order:

1. **Leading zeros suppressed** -- RFC 5952 §4.1. `0db8` becomes `db8`.
   A single all-zero 16-bit field is written as `0`, not omitted.
2. **`::` used to maximum extent** -- RFC 5952 §4.2.1. The longest
   consecutive run of all-zero 16-bit fields is compressed.
3. **`::` not used for a single 16-bit zero field** -- RFC 5952 §4.2.2.
   A single zero field is written as `0`, not `::`.
4. **First run wins on tie** -- RFC 5952 §4.2.3. When two consecutive
   zero runs are of equal length, the first is compressed.
5. **Lowercase** -- RFC 5952 §4.3. Hex digits `a`-`f` always lowercase.
6. **Mixed notation for IPv4-mapped** -- RFC 5952 §5. IPv4-mapped addresses
   (`::ffff:0:0/96`) are formatted with a dotted-decimal tail:
   `::ffff:192.0.2.1`. This is RECOMMENDED by RFC 5952 for addresses that
   can be identified as having an embedded IPv4 address solely from the
   address field through a well-known prefix.

#### 4.2.3 Prefix Formatting -- `cidr_prefix_format()`

```c
cidr_err_t cidr_prefix_format(const cidr_prefix_t *prefix, char *buf, size_t len)
    __attribute__((warn_unused_result));
```

Writes the canonical CIDR string `address/prefixlen` into `buf`. The address
portion is formatted per §4.2.1 or §4.2.2 depending on family. The prefix
length is written as a decimal integer with no leading zeros. Example output:
`192.168.1.0/24`, `2001:db8::/32`.

Returns `CIDR_ERR_INVAL` if any pointer is NULL or `len < CIDR_PREFIX_STR_MAX`.

### 4.3 Prefix Arithmetic Operations

All operations return `CIDR_ERR_FAMILY` if operands have mismatched families.
All output is written into caller-provided storage. All pointer parameters
return `CIDR_ERR_INVAL` if NULL. Any input with `family == CIDR_AF_UNSPEC`
returns `CIDR_ERR_INVAL`.

#### 4.3.1 Network Address

The network address is `cidr_prefix_t.addr` directly. It is a field access,
not a function call. The invariant that host bits are zero is established at
construction and never recomputed.

#### 4.3.2 Broadcast Address -- `cidr_prefix_broadcast()`

```c
cidr_err_t cidr_prefix_broadcast(const cidr_prefix_t *prefix, cidr_addr_t *out)
    __attribute__((warn_unused_result));
```

IPv4 only. Returns `CIDR_ERR_FAMILY` for `CIDR_AF_INET6` -- IPv6 has no
broadcast address; its function is superseded by multicast per RFC 4291.
Computed by ORing the network address with the bitwise complement of the
prefix mask.

#### 4.3.3 Prefix Mask -- `cidr_prefix_mask()`

```c
cidr_err_t cidr_prefix_mask(const cidr_prefix_t *prefix, cidr_addr_t *out)
    __attribute__((warn_unused_result));
```

Returns a `cidr_addr_t` with `pfxlen` leading bits set to one and remaining
bits set to zero, in network byte order. For `CIDR_AF_INET` with `pfxlen`
24: `{0xFF, 0xFF, 0xFF, 0x00}`. For `pfxlen` 0: all bytes zero. For `pfxlen`
equal to the maximum for the family: all bytes `0xFF`.

#### 4.3.4 First and Last Address -- `cidr_prefix_first()`, `cidr_prefix_last()`

```c
cidr_err_t cidr_prefix_first(const cidr_prefix_t *prefix, cidr_addr_t *out)
    __attribute__((warn_unused_result));

cidr_err_t cidr_prefix_last(const cidr_prefix_t *prefix, cidr_addr_t *out)
    __attribute__((warn_unused_result));
```

First address is the network address -- identical to `cidr_prefix_t.addr`.
Last address is the broadcast address for `CIDR_AF_INET` and the
host-bits-all-ones address for `CIDR_AF_INET6`. A `/128` IPv6 prefix has
the same first and last address. A `/0` prefix has last address
`255.255.255.255` (IPv4) or `ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff` (IPv6).

#### 4.3.5 Containment -- `cidr_prefix_contains()`

```c
cidr_err_t cidr_prefix_contains(const cidr_prefix_t *prefix,
                                  const cidr_addr_t   *addr,
                                  bool                *out)
    __attribute__((warn_unused_result));
```

Writes `true` into `*out` if `addr` falls within `prefix`, `false` otherwise.
Computed by masking `addr` with the prefix mask and comparing to the network
address: `(addr & mask) == prefix.addr`. `out` may be NULL; if NULL, the
function performs the computation and returns the status code only.

Returns `CIDR_ERR_FAMILY` if `addr->family` does not match
`prefix->addr.family`. On error, `*out` is not written. A family mismatch
is a caller bug, not a valid query with a negative answer.

#### 4.3.6 Overlap -- `cidr_prefix_overlaps()`

```c
cidr_err_t cidr_prefix_overlaps(const cidr_prefix_t *a,
                                  const cidr_prefix_t *b,
                                  bool                *out)
    __attribute__((warn_unused_result));
```

Writes `true` into `*out` if two prefixes share at least one address. Two
prefixes overlap if and only if one contains the network address of the other:
`cidr_prefix_contains(a, b->addr) || cidr_prefix_contains(b, a->addr)`.
`out` may be NULL.

Returns `CIDR_ERR_FAMILY` on family mismatch. On error, `*out` is not written.
Does not distinguish between partial overlap, containment, and equality.
Callers needing to distinguish these cases combine `cidr_prefix_overlaps()`
with `cidr_prefix_contains()`.

#### 4.3.7 Supernet -- `cidr_prefix_supernet()`

```c
cidr_err_t cidr_prefix_supernet(const cidr_prefix_t *prefix, cidr_prefix_t *out)
    __attribute__((warn_unused_result));
```

Returns the parent prefix at `pfxlen - 1`. The supernet of `192.168.1.0/24`
is `192.168.0.0/23`. Computed by decrementing `pfxlen` by one and zeroing
the new host bit in the network address.

Returns `CIDR_ERR_OVERFLOW` when called on a `/0` prefix. A `/0` prefix
covers the entire address space for its family and has no parent. The input
is valid but the result is not representable -- `CIDR_ERR_OVERFLOW` is the
correct code because the operation would require a prefix length of `-1`.
`CIDR_ERR_INVAL` would imply the input is malformed, which it is not.

#### 4.3.8 Subnet Enumeration -- `cidr_subnet_iter_t`

Stateful iterator for enumerating all subnets of a prefix at a longer target
prefix length. Iterator state lives on the caller's stack -- no allocation.

```c
typedef struct {
    cidr_prefix_t current;      /* current subnet, valid after successful next() */
    cidr_prefix_t limit;        /* first address past the end of the parent      */
    uint8_t       target_pfxlen;
    bool          done;
} cidr_subnet_iter_t;

cidr_err_t cidr_subnet_iter_init(cidr_subnet_iter_t  *iter,
                                  const cidr_prefix_t *prefix,
                                  uint8_t              target_pfxlen)
    __attribute__((warn_unused_result));

cidr_err_t cidr_subnet_iter_next(cidr_subnet_iter_t *iter,
                                  cidr_prefix_t      *out)
    __attribute__((warn_unused_result));
```

`cidr_subnet_iter_init()` validates that `target_pfxlen` is greater than
`prefix->pfxlen` and within the valid range for the address family. Returns
`CIDR_ERR_PFXLEN` otherwise. Returns `CIDR_ERR_INVAL` if any pointer is NULL.

`cidr_subnet_iter_next()` writes the next subnet into `out` and advances
the iterator. Returns `CIDR_OK` on success. Returns `CIDR_ERR_DONE` when
all subnets have been yielded -- this is the normal termination condition.
On `CIDR_ERR_DONE`, `out` is not modified. The caller must not inspect `out`
unless the return value is `CIDR_OK`.

Subnets are enumerated in ascending order of their network address
(lexicographic order on address bytes in network byte order). The first
subnet yielded has the same network address as `prefix`.

The caller's loop:

```c
cidr_subnet_iter_t iter;
cidr_prefix_t      subnet;
cidr_err_t         err;

cidr_subnet_iter_init(&iter, &prefix, target_pfxlen);
while ((err = cidr_subnet_iter_next(&iter, &subnet)) == CIDR_OK) {
    /* process subnet */
}
if (err != CIDR_ERR_DONE) {
    /* handle unexpected error */
}
```

The iterator is pauseable and resumeable -- the caller may stop iteration
early by simply not calling `cidr_subnet_iter_next()` again. No cleanup
function is required -- the iterator struct holds no allocated resources.

**Subnet count:** The number of subnets is `2^(target_pfxlen - prefix->pfxlen)`.
For large bit differences this count is astronomically large. The iterator
model is the only correct design for this operation -- returning all subnets
in a buffer would require unbounded allocation. The caller controls iteration
and stops when they have what they need.

### 4.4 Address and Prefix Comparison

```c
cidr_err_t cidr_addr_cmp(const cidr_addr_t *a, const cidr_addr_t *b, int *result)
    __attribute__((warn_unused_result));

cidr_err_t cidr_prefix_cmp(const cidr_prefix_t *a, const cidr_prefix_t *b,
    int *result)
    __attribute__((warn_unused_result));
```

These are comparison functions (comparators), not sort functions. They compare
two individual values and write -1, 0, or +1 to `*result`. They are the
building blocks for C callers who need to implement ordered data structures,
binary search, or manual ordering checks. The bulk sort operations (`cidr_bulk_sort()`)
are the correct choice for sorting arrays; these functions compare single pairs.

**`cidr_addr_cmp(a, b, result)`** -- compares two addresses within the same
family. Writes -1 if a < b, 0 if a == b, +1 if a > b. Ordering is
lexicographic on the address bytes in network byte order. This is consistent
with the sort order used by `CIDR_SORT_NETWORK_ASC`.

Returns `CIDR_ERR_INVAL` if any pointer is NULL or if either address has
`family == CIDR_AF_UNSPEC`.
Returns `CIDR_ERR_FAMILY` if `a->family != b->family`.

**`cidr_prefix_cmp(a, b, result)`** -- compares two prefixes within the same
family. Ordering matches `CIDR_SORT_NETWORK_ASC`: network address ascending
first (lexicographic on address bytes), prefix length ascending within the
same network address. Writes -1, 0, or +1 accordingly.

Returns `CIDR_ERR_INVAL` if any pointer is NULL or if either prefix has
`family == CIDR_AF_UNSPEC`.
Returns `CIDR_ERR_FAMILY` if the families differ.

Both functions complete in O(W) time where W is address width in bytes --
a compile-time constant. No allocation occurs.

---

## 5. Bulk Engine

### 5.1 General Model

All bulk operations share a common model: caller-provided contiguous input
arrays, caller-provided contiguous output arrays, explicit counts, zero
allocation inside the library. This model is cache-friendly -- linear scans
over contiguous arrays are predictable for the hardware prefetcher. It is
also complexity-transparent -- the caller controls memory layout and knows
exactly what the library touches.

Mixed-family input is rejected by all bulk operations with `CIDR_ERR_FAMILY`.
IPv4 and IPv6 operations must be performed separately. A mixed-family array
is a caller bug.

All bulk functions accept `count == 0`. When `count` is zero, the function
returns `CIDR_OK` and performs no work. See §3.4 for the empty array policy
and the exception for `cidr_index_create()`.

### 5.2 Batch Parse -- `cidr_bulk_parse()`

```c
cidr_err_t cidr_bulk_parse(const char  **srcs,
                            size_t        count,
                            cidr_addr_t  *out,
                            cidr_err_t   *errs)
    __attribute__((warn_unused_result));
```

Parses `count` address strings from `srcs` into `out`. Each string is parsed
per §4.1. On parse failure for item `i`, `out[i]` is written as a
zero-initialised `cidr_addr_t` with `family = CIDR_AF_UNSPEC` and
`errs[i]` is written as `CIDR_ERR_PARSE`. On success, `errs[i]` is
`CIDR_OK`.

`errs` may be NULL. When NULL, per-item error reporting is suppressed at
zero overhead. The return value of the function itself follows this
precedence: `CIDR_ERR_INVAL` if any `srcs[i]` is NULL (fail-fast, no output
written); `CIDR_ERR_FAMILY` if all items were attempted but any
successfully-parsed item has a different family than the reference family;
`CIDR_ERR_PARSE` if any item failed to parse; `CIDR_OK` if all items parsed
to the same family.

**NULL element policy.** If any element `srcs[i]` is NULL, the function
returns `CIDR_ERR_INVAL` immediately and no output is written. All string
pointers in `srcs` must be non-NULL.

All items are attempted regardless of individual parse failures. The function
does not fail fast -- it completes the full batch and reports all errors.
Output is fully written: `out[i]` contains the parsed address on success, or
a zero-initialised `cidr_addr_t` with `family = CIDR_AF_UNSPEC` on failure.

**Mixed-family detection.** The expected address family is inferred from the
first successfully-parsed item. After the full batch completes, if any
successfully-parsed item has a different family, `CIDR_ERR_FAMILY` is returned.
`CIDR_ERR_FAMILY` takes precedence over `CIDR_ERR_PARSE` in the return code.

Complexity: O(n) where n is `count`.

### 5.3 Bulk Containment -- `cidr_bulk_contains()`

```c
cidr_err_t cidr_bulk_contains(const cidr_addr_t   *addrs,
                               size_t               addr_count,
                               const cidr_prefix_t *prefixes,
                               size_t               prefix_count,
                               ssize_t             *matches,
                               cidr_err_t          *errs)
    __attribute__((warn_unused_result));
```

For each address in `addrs`, scans `prefixes` in order and writes the index
of the first matching prefix into `matches[i]`, or `-1` if no prefix matched.
Match is first-match-in-order -- the library does not impose a matching
strategy. Callers needing longest-prefix-match semantics sort `prefixes` by
descending prefix length using `cidr_bulk_sort()` before calling.

When `prefix_count == 0`, all `matches[i]` are written as `-1` and the
function returns `CIDR_OK`.

If `addr_count > 0` and `matches` is NULL, returns `CIDR_ERR_INVAL`.

`errs` may be NULL. When non-NULL, `errs[i]` is set to `CIDR_OK` on match
or no-match, and `CIDR_ERR_FAMILY` if `addrs[i].family` does not match the
family of any prefix. Returns `CIDR_ERR_FAMILY` if the address and prefix
arrays contain mixed families.

Complexity: O(n * m) where n is `addr_count` and m is `prefix_count`. For
high-performance lookup against large prefix tables, use `cidr_index_lookup()`
instead (see §6).

**Complexity transparency note:** The O(n * m) complexity is visible to the
caller -- two array sizes are passed explicitly. There is no hidden scan. The
caller who passes a table of 800,000 prefixes has explicitly accepted O(n *
800,000) work. For routing-table-scale workloads, the Patricia trie index
(§6) reduces this to O(n * 128).

### 5.4 Prefix Aggregation -- `cidr_bulk_aggregate()`

```c
cidr_err_t cidr_bulk_aggregate(cidr_prefix_t *prefixes,
                                size_t         count,
                                size_t        *out_count)
    __attribute__((warn_unused_result));
```

Aggregates `prefixes` in place to a minimal covering set. The result covers
exactly the same address space as the input -- no more, no less. `out_count`
receives the number of prefixes in the aggregated result, which is less than
or equal to `count`. The first `*out_count` entries of `prefixes` on return
are the aggregated prefixes. The remaining entries are undefined.

Returns `CIDR_ERR_INVAL` if `out_count` is NULL.

**Algorithm:**

1. In-place MSD radix sort the prefix array -- O(n * k) where k is the key
   width in bytes (5 for IPv4, 17 for IPv6); k is a compile-time constant so
   the sort is O(n) in asymptotic analysis. Sort key: network address bytes
   ascending, then `pfxlen` ascending within the same network address. This
   brings siblings and contained prefixes adjacent.
2. Remove exact duplicates -- O(n) linear scan.
3. Remove prefixes already covered by a shorter prefix in the sorted list --
   O(n) linear scan.
4. Merge sibling prefixes into their supernet repeatedly until no more merges
   are possible -- O(n) per pass. The number of passes is bounded by the
   prefix length range (0-32 for IPv4, 0-128 for IPv6).
5. Early termination: if no merges occur in a pass, aggregation is complete.

**Radix sort detail:** IPv4 prefix keys are 5 bytes (4 address bytes + 1
pfxlen byte). IPv6 prefix keys are 17 bytes (16 address bytes + 1 pfxlen
byte). The sort is implemented as an in-place MSD (most-significant-digit)
radix sort. At each recursion level, a histogram of 256 bucket counts is
maintained on the stack; each count is a `size_t` (8 bytes on 64-bit
platforms). The per-level stack cost is 256 * 8 = 2,048 bytes. With a
recursion depth of at most k (17 for IPv6), the worst-case stack usage is
17 * 2,048 = 34,816 bytes -- within normal stack bounds (8 MiB) on all target
platforms. No heap allocation occurs during sort. This preserves the
zero-allocation guarantee for all bulk operations.

**Early termination:** When the input is already fully aggregated -- common
when aggregating incrementally -- the merge phase detects this in O(n) and
returns immediately without further passes.

**In-place operation:** The caller's array is modified directly. No copy is
made. The caller who needs to preserve the original array must copy it before
calling.

Returns `CIDR_ERR_FAMILY` if the array contains mixed families. IPv4 and
IPv6 must be aggregated separately.

Complexity: O(n * k) where k is key width in bytes; treated as O(n) because
k is a compile-time constant.

### 5.5 Prefix Sort -- `cidr_bulk_sort()`

```c
typedef enum {
    CIDR_SORT_NETWORK_ASC  = 0, /* network address ascending, pfxlen
                                   ascending -- for aggregation */
    CIDR_SORT_PFXLEN_DESC  = 1, /* prefix length descending -- for
                                   longest-prefix-match preparation */
} cidr_sort_order_t;

cidr_err_t cidr_bulk_sort(cidr_prefix_t    *prefixes,
                           size_t            count,
                           cidr_sort_order_t order)
    __attribute__((warn_unused_result));
```

Sorts `prefixes` in place using in-place MSD radix sort. Two orderings:

`CIDR_SORT_NETWORK_ASC` -- network address ascending, prefix length ascending
within the same network address. This is the ordering required by
`cidr_bulk_aggregate()`. `cidr_bulk_aggregate()` calls this internally --
callers do not need to pre-sort before aggregating.

`CIDR_SORT_PFXLEN_DESC` -- prefix length descending, network address ascending
within equal prefix lengths. This prepares a prefix table for longest-prefix-match
semantics with `cidr_bulk_contains()`. A subsequent `cidr_bulk_contains()` call
with first-match-in-order semantics will return the most specific matching
prefix for each address. The secondary key (network address ascending within
equal prefix lengths) makes the result deterministic for overlapping prefixes.
The sort is stable -- exact duplicate prefixes preserve their original input
order.

Both orderings use the same radix sort engine with different key construction.
The enum is extensible -- additional orderings may be added without API surface
growth.

If `order` is not a valid `cidr_sort_order_t` value, returns `CIDR_ERR_INVAL`.
Returns `CIDR_ERR_FAMILY` on mixed-family input.
If `count > 0` and `prefixes` is NULL, returns `CIDR_ERR_INVAL`. If
`count == 0`, `prefixes` may be NULL and the function returns `CIDR_OK`.

Complexity: O(n * k) where k is key width in bytes; treated as O(n).

---

## 6. Patricia Trie Index

### 6.1 Purpose and Scope

The Patricia trie index is a prefix index structure for high-performance bulk
containment queries. It is built once from a caller-provided prefix array and
supports repeated lookup queries against the same prefix table efficiently.

**When to use the index vs. `cidr_bulk_contains()`:**

- Small prefix tables (< 1,000 prefixes): `cidr_bulk_contains()` -- the O(n*m)
  linear scan has negligible cost and no index build overhead.
- Large prefix tables (routing table scale, 10,000+ prefixes):
  `cidr_index_lookup()` -- O(address length) per query amortises the index
  build cost over many lookups.

The index is the only component in libcidr that allocates memory after
initialisation. `cidr_index_create()` is explicitly documented as an
allocating operation. All other functions are allocation-free.

### 6.2 API

```c
typedef struct cidr_index cidr_index_t;  /* opaque */

cidr_err_t cidr_index_create(const cidr_prefix_t *prefixes,
                              size_t               count,
                              cidr_index_t       **out)
    __attribute__((warn_unused_result));

void cidr_index_destroy(cidr_index_t *index);

cidr_err_t cidr_index_lookup(const cidr_index_t  *index,
                              const cidr_addr_t   *addrs,
                              size_t               count,
                              ssize_t             *matches,
                              cidr_err_t          *errs)
    __attribute__((warn_unused_result));
```

`cidr_index_create()` builds the trie from the caller-provided prefix array.
The prefix array is copied into the index -- the caller may free or modify
their array after the call returns. Returns `CIDR_ERR_NOMEM` on allocation
failure. Returns `CIDR_ERR_FAMILY` on mixed-family input -- separate indices
must be built for IPv4 and IPv6. Returns `CIDR_ERR_INVAL` if `count == 0`
(an index must contain at least one prefix to establish the address family),
if `count > UINT32_MAX - 1` (the internal node representation uses `uint32_t`
indices and `UINT32_MAX` is reserved as a sentinel), if any prefix in the
array has `addr.family == CIDR_AF_UNSPEC`, or if any pointer is NULL.

Note on node count: a trie with n prefixes may require up to 2n-1 nodes
before compression. If during construction the node count would exceed
`UINT32_MAX - 1`, the function returns `CIDR_ERR_INVAL`. Prefix-count
validation alone does not guarantee the node count stays within range for
pathological inputs; the implementation must check node count during build.

`cidr_index_destroy()` releases all memory allocated by `cidr_index_create()`.
Must be called exactly once per successfully created index. NULL-safe.

`cidr_index_lookup()` writes `matches[i]` as the index of the longest-prefix
match for `addrs[i]` in the prefix array passed to `cidr_index_create()`, or
`-1` if no prefix matched. `errs` may be NULL. If `count > 0` and `matches`
is NULL, returns `CIDR_ERR_INVAL`.

**Output format vs. `cidr_bulk_contains()`.** The output format is identical
(index or -1 per address) but the selection semantics differ. `cidr_index_lookup()`
always returns the longest-prefix match by construction of the trie traversal.
`cidr_bulk_contains()` returns first-match-in-caller-array-order. These produce
the same result only when the prefix array passed to `cidr_index_create()` was
sorted by `CIDR_SORT_PFXLEN_DESC` before index creation, and the same array
with the same element order is used for both. Callers who need deterministic
LPM semantics from both functions must apply this sort.

**Duplicate prefix handling.** When two prefixes at different input indices are
identical, the trie stores the one with the lower index (earlier in the input
array). This is consistent with the first-match-in-order semantics of
`cidr_bulk_contains()`. This consistency holds when the same prefix array with
the same element order is used for both `cidr_bulk_contains()` and
`cidr_index_create()`.

### 6.3 Node Layout and Compression Model

The index uses an array-packed Level-Compressed trie (LC-trie) as defined
by Nilsson and Karlsson (1999). Two compression techniques are applied:

**Path compression (skip):** chains of single-child nodes are collapsed into
a single node with a `skip` field indicating how many bits to advance past
without branching. This is standard Patricia-style compression.

**Level compression (branch):** where multiple levels of the trie share the
same branching structure they are merged into a single node with a larger
branching factor. A node that would require four sequential one-bit tests in
a basic Patricia trie becomes one node with `branch = 4`, testing four bits
simultaneously and indexing directly into `2^4 = 16` children. This is the
key distinction from basic Patricia and the source of the depth reduction.

Each node in the array:

```c
typedef struct {
    uint32_t base;         /* index of first child in node array */
    uint32_t prefix_idx;   /* index into prefix array; UINT32_MAX = no prefix */
    uint8_t  branch;       /* branching factor: node has 2^branch children */
    uint8_t  skip;         /* bits to advance before testing */
    uint8_t  pad[2];       /* alignment */
} cidr_lctrie_node_t;      /* 12 bytes */
```

`branch == 0` indicates a leaf node -- no children, traversal ends here.
`prefix_idx == UINT32_MAX` indicates no prefix is stored at this node.
A leaf node with `prefix_idx != UINT32_MAX` is a valid and necessary state
-- it represents a leaf that stores a matching prefix; traversal terminates
after recording that prefix as the current best match.

An interior node (`branch > 0`) may also have `prefix_idx != UINT32_MAX`.
This occurs when a prefix that has more-specific sub-prefixes is stored at
an interior node. During lookup, if a node has a valid `prefix_idx`, that
prefix is recorded as the current best match before descending to children.
This is required for correct longest-prefix-match semantics.

The entire node array for one trie is allocated in a single contiguous block
inside `cidr_index_create()` -- consistent with the single-allocating-operation
model. Separate tries are built for IPv4 and IPv6: different key widths keep
the implementation clean and eliminate family dispatch from the lookup hot path.

**Lookup:** advance `skip` bits, extract `branch` bits as an index, descend
to `nodes[base + index]`, repeat. Track the most specific matching prefix
seen during descent. Terminate at a leaf node or when the accumulated bit
position exceeds the key width.

**Traversal depth:** on real Internet routing tables the LC-trie achieves
approximately 4-8 node accesses for IPv4 and 8-15 for IPv6. These figures
are empirical measurements on realistic routing table distributions; they are
not algorithmic guarantees and will vary with table composition. The
algorithmic worst-case traversal depth is 32 for IPv4 and 128 for IPv6.

**Build complexity:** O(n * W) where n is prefix count and W is key width
(32 for IPv4, 128 for IPv6). The build algorithm constructs a basic trie,
applies path compression, then applies level compression via a tree DP pass
that computes the branching factor at each node. The DP minimises the total
number of nodes in the resulting trie, following the optimisation criterion
defined in Nilsson and Karlsson (1999). Traversal-depth reduction is an
expected practical result of node-count minimisation, not an equivalent
objective.

**Implementation phase:** the LC-trie is implemented after the arithmetic
engine, bulk engine, and address classification are complete and verified.

Complexity: `cidr_index_create()` O(n * W). `cidr_index_lookup()` empirically
O(4-8) for IPv4 and O(8-15) for IPv6 on real routing tables; worst case O(W).

---

## 7. Address Classification

### 7.1 Classification Function

```c
typedef uint32_t cidr_class_t;  /* bitmask of CIDR_CLASS_* flags */

cidr_err_t cidr_addr_classify(const cidr_addr_t *addr, cidr_class_t *out)
    __attribute__((warn_unused_result));
```

Returns a bitmask of classification flags for `addr`. Multiple flags may be
set simultaneously -- an address within a sub-block of `2001::/23` receives
both `CIDR_CLASS_IETF_RESERVED` (from the parent block match) and whichever
more specific flag applies to the sub-block. The flags are defined as named
constants against the IANA special-purpose registries.

### 7.2 Classification Flag Registry

The classification flags encode the IANA special-purpose address registries.
The table encodes a specific IANA snapshot; the snapshot date and version are
documented in `libcidr.h` via a compile-time constant:

```c
#define CIDR_IANA_SNAPSHOT  20251009   /* YYYYMMDD of encoded registry snapshot */
```

The IANA live registries at https://www.iana.org/assignments/iana-ipv4-special-registry
and https://www.iana.org/assignments/iana-ipv6-special-registry are the
upstream source of truth. The encoded table must be updated when either
registry is updated.

**Multicast ranges.** `224.0.0.0/4` (IPv4) and `ff00::/8` (IPv6) are not
listed in the IANA special-purpose registry but are universally defined as
multicast address ranges in RFC 1112 and RFC 4291 respectively. These are
included in the classification table under `CIDR_CLASS_MULTICAST` because
treating them as globally routable unicast would be incorrect for all callers.

**Terminated entries.** IANA entries with a termination date are retained in
the classification table. Addresses in terminated ranges can still appear in
real traffic, and classifying them correctly is more useful than treating them
as globally routable. Terminated entries are noted in the table.

**Flag values:**

```c
#define CIDR_CLASS_GLOBAL        (1u <<  0)  /* not matched by any special-purpose block */
#define CIDR_CLASS_THIS_HOST     (1u <<  1)  /* 0.0.0.0/8, 0.0.0.0/32 */
#define CIDR_CLASS_PRIVATE       (1u <<  2)  /* RFC 1918: 10/8, 172.16/12, 192.168/16 */
#define CIDR_CLASS_SHARED        (1u <<  3)  /* 100.64.0.0/10 shared address space */
#define CIDR_CLASS_LOOPBACK      (1u <<  4)  /* 127.0.0.0/8, ::1/128 */
#define CIDR_CLASS_LINK_LOCAL    (1u <<  5)  /* 169.254.0.0/16, fe80::/10 */
#define CIDR_CLASS_IETF_RESERVED (1u <<  6)  /* IETF special-purpose protocol
                                                assignments: 192.0.0.0/24 and
                                                sub-blocks; 2001::/23 and sub-
                                                blocks; other IETF-reserved
                                                blocks not covered by more
                                                specific flags */
#define CIDR_CLASS_DOCUMENTATION (1u <<  7)  /* 192.0.2/24, 198.51.100/24,
                                                203.0.113/24, 2001:db8::/32,
                                                3fff::/20 */
#define CIDR_CLASS_6TO4_RELAY    (1u <<  8)  /* 192.88.99.0/24 (deprecated 2015-03),
                                                192.88.99.2/32 */
#define CIDR_CLASS_BENCHMARKING  (1u <<  9)  /* 198.18.0.0/15, 2001:2::/48 */
#define CIDR_CLASS_RESERVED      (1u << 10)  /* 240.0.0.0/4 */
#define CIDR_CLASS_BROADCAST     (1u << 11)  /* 255.255.255.255/32 */
#define CIDR_CLASS_UNSPECIFIED   (1u << 12)  /* ::/128 */
#define CIDR_CLASS_V4MAPPED      (1u << 13)  /* ::ffff:0:0/96 */
#define CIDR_CLASS_V4TRANSLATED  (1u << 14)  /* 64:ff9b::/96, 64:ff9b:1::/48 */
#define CIDR_CLASS_DISCARD       (1u << 15)  /* 100::/64 */
#define CIDR_CLASS_UNIQUE_LOCAL  (1u << 16)  /* fc00::/7 */
#define CIDR_CLASS_MULTICAST     (1u << 17)  /* 224.0.0.0/4 (IPv4, RFC 1112),
                                                ff00::/8 (IPv6, RFC 4291) */
#define CIDR_CLASS_ANYCAST       (1u << 18)  /* globally reachable anycast
                                                infrastructure: AS112, AMT,
                                                PCP/TURN/DNS-SD anycast */
#define CIDR_CLASS_TEREDO        (1u << 19)  /* 2001::/32 Teredo tunneling */
#define CIDR_CLASS_6TO4          (1u << 20)  /* 2002::/16 6to4 routing */
#define CIDR_CLASS_ORCHID        (1u << 21)  /* 2001:20::/28 ORCHIDv2,
                                                2001:30::/28 Drone DETs */
#define CIDR_CLASS_SRV6          (1u << 22)  /* 5f00::/16 SRv6 SIDs */
/* bits 23-31 reserved for future IANA additions */
```

`CIDR_CLASS_GLOBAL` is set when no special-purpose block matched. It does
not imply operational global routability -- the IANA registries explicitly
state that special-purpose registry entries are not guaranteed routability
in any particular local or global context, and that absence from the registry
similarly does not guarantee routability. `CIDR_CLASS_GLOBAL` means "not
matched by any entry in this classification table." It is a named bit rather
than zero so callers can test it with a uniform bitmask expression.

`CIDR_CLASS_GLOBAL` is always mutually exclusive with every other flag.

**IPv4 special-purpose blocks (IANA snapshot 2025-10-09):**

| Block | Name | Flag |
|---|---|---|
| `0.0.0.0/8` | This Network | `CIDR_CLASS_THIS_HOST` |
| `0.0.0.0/32` | This Host on This Network | `CIDR_CLASS_THIS_HOST` |
| `10.0.0.0/8` | Private-Use | `CIDR_CLASS_PRIVATE` |
| `100.64.0.0/10` | Shared Address Space | `CIDR_CLASS_SHARED` |
| `127.0.0.0/8` | Loopback | `CIDR_CLASS_LOOPBACK` |
| `169.254.0.0/16` | Link Local | `CIDR_CLASS_LINK_LOCAL` |
| `172.16.0.0/12` | Private-Use | `CIDR_CLASS_PRIVATE` |
| `192.0.0.0/24` | IETF Protocol Assignments | `CIDR_CLASS_IETF_RESERVED` |
| `192.0.0.0/29` | IPv4 Service Continuity Prefix | `CIDR_CLASS_IETF_RESERVED` |
| `192.0.0.8/32` | IPv4 Dummy Address | `CIDR_CLASS_IETF_RESERVED` |
| `192.0.0.9/32` | Port Control Protocol Anycast | `CIDR_CLASS_IETF_RESERVED \| CIDR_CLASS_ANYCAST` |
| `192.0.0.10/32` | TURN Anycast | `CIDR_CLASS_IETF_RESERVED \| CIDR_CLASS_ANYCAST` |
| `192.0.0.170/32` | NAT64/DNS64 Discovery | `CIDR_CLASS_IETF_RESERVED` |
| `192.0.0.171/32` | NAT64/DNS64 Discovery | `CIDR_CLASS_IETF_RESERVED` |
| `192.0.2.0/24` | Documentation (TEST-NET-1) | `CIDR_CLASS_DOCUMENTATION` |
| `192.31.196.0/24` | AS112-v4 | `CIDR_CLASS_ANYCAST` |
| `192.52.193.0/24` | AMT | `CIDR_CLASS_ANYCAST` |
| `192.88.99.0/24` | 6to4 Relay Anycast (deprecated 2015-03) | `CIDR_CLASS_6TO4_RELAY` |
| `192.88.99.2/32` | 6a44 Relay Anycast | `CIDR_CLASS_6TO4_RELAY` |
| `192.168.0.0/16` | Private-Use | `CIDR_CLASS_PRIVATE` |
| `192.175.48.0/24` | Direct Delegation AS112 Service | `CIDR_CLASS_ANYCAST` |
| `198.18.0.0/15` | Benchmarking | `CIDR_CLASS_BENCHMARKING` |
| `198.51.100.0/24` | Documentation (TEST-NET-2) | `CIDR_CLASS_DOCUMENTATION` |
| `203.0.113.0/24` | Documentation (TEST-NET-3) | `CIDR_CLASS_DOCUMENTATION` |
| `224.0.0.0/4` | Multicast | `CIDR_CLASS_MULTICAST` |
| `240.0.0.0/4` | Reserved | `CIDR_CLASS_RESERVED` |
| `255.255.255.255/32` | Limited Broadcast | `CIDR_CLASS_BROADCAST` |

**IPv6 special-purpose blocks (IANA snapshot 2025-10-09):**

| Block | Name | Flag |
|---|---|---|
| `::/128` | Unspecified Address | `CIDR_CLASS_UNSPECIFIED` |
| `::1/128` | Loopback Address | `CIDR_CLASS_LOOPBACK` |
| `::ffff:0:0/96` | IPv4-Mapped Address | `CIDR_CLASS_V4MAPPED` |
| `64:ff9b::/96` | IPv4-IPv6 Translation | `CIDR_CLASS_V4TRANSLATED` |
| `64:ff9b:1::/48` | IPv4-IPv6 Translation | `CIDR_CLASS_V4TRANSLATED` |
| `100::/64` | Discard-Only | `CIDR_CLASS_DISCARD` |
| `100:0:0:1::/64` | Dummy IPv6 Prefix | `CIDR_CLASS_IETF_RESERVED` |
| `2001::/23` | IETF Protocol Assignments | `CIDR_CLASS_IETF_RESERVED` |
| `2001::/32` | Teredo | `CIDR_CLASS_IETF_RESERVED \| CIDR_CLASS_TEREDO` |
| `2001:1::1/128` | Port Control Protocol Anycast | `CIDR_CLASS_IETF_RESERVED \| CIDR_CLASS_ANYCAST` |
| `2001:1::2/128` | TURN Anycast | `CIDR_CLASS_IETF_RESERVED \| CIDR_CLASS_ANYCAST` |
| `2001:1::3/128` | DNS-SD Service Registration Protocol Anycast | `CIDR_CLASS_IETF_RESERVED \| CIDR_CLASS_ANYCAST` |
| `2001:2::/48` | Benchmarking | `CIDR_CLASS_IETF_RESERVED \| CIDR_CLASS_BENCHMARKING` |
| `2001:3::/32` | AMT | `CIDR_CLASS_IETF_RESERVED \| CIDR_CLASS_ANYCAST` |
| `2001:4:112::/48` | AS112-v6 | `CIDR_CLASS_IETF_RESERVED \| CIDR_CLASS_ANYCAST` |
| `2001:10::/28` | Deprecated (previously ORCHID, terminated 2014-03) | `CIDR_CLASS_IETF_RESERVED` |
| `2001:20::/28` | ORCHIDv2 | `CIDR_CLASS_IETF_RESERVED \| CIDR_CLASS_ORCHID` |
| `2001:30::/28` | Drone Remote ID Protocol (DETs) | `CIDR_CLASS_IETF_RESERVED \| CIDR_CLASS_ORCHID` |
| `2001:db8::/32` | Documentation | `CIDR_CLASS_IETF_RESERVED \| CIDR_CLASS_DOCUMENTATION` |
| `2002::/16` | 6to4 | `CIDR_CLASS_6TO4` |
| `2620:4f:8000::/48` | Direct Delegation AS112 Service | `CIDR_CLASS_ANYCAST` |
| `3fff::/20` | Documentation | `CIDR_CLASS_DOCUMENTATION` |
| `5f00::/16` | Segment Routing (SRv6) SIDs | `CIDR_CLASS_SRV6` |
| `fc00::/7` | Unique-Local | `CIDR_CLASS_UNIQUE_LOCAL` |
| `fe80::/10` | Link-Local Unicast | `CIDR_CLASS_LINK_LOCAL` |
| `ff00::/8` | Multicast | `CIDR_CLASS_MULTICAST` |

Addresses not matching any entry receive `CIDR_CLASS_GLOBAL`.

### 7.3 Implementation Note

Classification is a linear scan of the special-purpose block table against
the input address. The table is fixed at compile time. The scan is O(1) in
practice -- the table size is a compile-time constant of approximately 50
entries. For addresses that fall within overlapping blocks (e.g. a sub-block
of `2001::/23`), multiple entries match and their flags are ORed into the
result.

---

## 8. CPython Binding Layer

### 8.1 Overview

The CPython binding layer is a separate compilation unit (`_libcidr_ext.c`).
It has no IP arithmetic logic of its own. Its sole responsibilities are to
define Python types wrapping `cidr_addr_t` and `cidr_prefix_t`, translate
Python call arguments to C types, call the C public API, translate results
back to Python objects, and map `cidr_err_t` values to Python exceptions.

All arithmetic, parsing, formatting, classification, and indexing logic lives
in the C library. The Python layer is a translation layer only. Translation
work -- such as inspecting a C error array after a batch operation and raising
on the first error found -- is part of the binding's translation
responsibility, not IP logic.

### 8.2 Stable ABI and Module Identity

**Stable ABI target:** `Py_LIMITED_API = 0x030B0000` (CPython 3.11).

The stable ABI guarantees that a `.so` compiled against Python 3.11 will
load and run correctly on Python 3.12, 3.13, and any future 3.x release
without recompilation. The extension uses only APIs available since 3.11
and avoids the full CPython API which would tie the compiled binary to a
specific minor version. All Python type definitions use `PyType_FromSpec()`
and the slot-based type specification -- direct `PyTypeObject` struct
initialization is not used, as it requires the full API.

Python 3.11 was chosen as the floor based on deployment targets: the
extension is aimed at server-side network tooling (log enrichment, BGP
analysis, firewall rule evaluation), where Debian 13, Ubuntu 24.04 LTS,
RHEL 9 AppStream, and RHEL 10 are the primary platforms. Python 3.11 covers
this range without excluding any realistic deployment. The version matrix is
tested via GitHub Actions venv targets covering 3.11 through current.

**Module name:** `libcidr`. Imported as:

```python
import libcidr
```

The `lib` prefix is intentional -- it signals the C library underneath,
makes the relationship between the C and Python components unambiguous in
documentation, and avoids namespace conflicts on PyPI.

### 8.3 Python Types

The binding layer exposes four family-specific Python types:

- `libcidr.IPv4Address`
- `libcidr.IPv6Address`
- `libcidr.IPv4Network`
- `libcidr.IPv6Network`

Family is encoded in the type name, matching the stdlib `ipaddress`
convention. This is the correct design for the Python layer -- Python
developers think in terms of `IPv4Address` vs `IPv6Address`, not a unified
address with a `.family` attribute. The C library uses a single type with a
family discriminator because that is correct for C; the Python layer uses
four types because that is correct for Python. The binding code is mechanical
boilerplate; the extra types add no design complexity.

Each Python type embeds its corresponding C struct by value directly in the
`PyObject` allocation. See §8.10 for the ownership model.

### 8.4 ipaddress Compatibility Contract

The stdlib `ipaddress` module is the correctness reference and the de facto
API standard for Python network tooling. libcidr's Python types maintain
targeted compatibility with `ipaddress` on two axes:

**One-way construction from `ipaddress` objects.** Each libcidr type accepts
a matching `ipaddress` object as a constructor argument:

```python
import ipaddress, libcidr

addr = libcidr.IPv4Address(ipaddress.IPv4Address('192.168.1.1'))
net  = libcidr.IPv4Network(ipaddress.IPv4Network('192.168.1.0/24'))
```

This covers the dominant migration pattern -- a developer switching a
codebase from `ipaddress` to libcidr can construct libcidr objects from
existing `ipaddress` values without string round-trips. Output always stays
libcidr; there is no automatic coercion back to `ipaddress`.

**Targeted read-only property subset.** The properties listed in §8.6 and
§8.7 match `ipaddress` naming exactly. Code using these properties against
`ipaddress` objects will work against libcidr objects without modification.

Full duck-type compatibility is explicitly out of scope. The `ipaddress`
type hierarchy is not subclassed. Properties and methods beyond those listed
in §8.6 and §8.7 are not implemented. The pytricia ecosystem's failure to
provide stdlib-compatible key handling is a documented market complaint;
libcidr avoids repeating it by providing the most-used property surface.

### 8.5 Exception Hierarchy

libcidr defines a custom exception hierarchy. All libcidr exceptions inherit
from both `libcidr.CIDRError` and an appropriate stdlib built-in, so callers
can catch at either level:

```python
# Catch any libcidr error
except libcidr.CIDRError:

# Catch any ValueError -- catches libcidr parse and argument errors too
except ValueError:

# Catch specifically a parse error
except libcidr.ParseError:
```

**Exception types and `cidr_err_t` mapping:**

| Exception | Inherits from | Maps from |
|---|---|---|
| `libcidr.CIDRError` | `Exception` | base -- not raised directly |
| `libcidr.ParseError` | `CIDRError`, `ValueError` | `CIDR_ERR_PARSE` |
| `libcidr.HostBitsError` | `CIDRError`, `ValueError` | `CIDR_ERR_HOSTBITS` |
| `libcidr.PrefixLengthError` | `CIDRError`, `ValueError` | `CIDR_ERR_PFXLEN` |
| `libcidr.InvalidArgumentError` | `CIDRError`, `ValueError` | `CIDR_ERR_INVAL` |
| `libcidr.FamilyError` | `CIDRError`, `TypeError` | `CIDR_ERR_FAMILY` |
| `libcidr.AddressOverflowError` | `CIDRError`, `OverflowError` | `CIDR_ERR_OVERFLOW` |
| `MemoryError` (built-in) | -- | `CIDR_ERR_NOMEM` |
| `StopIteration` (built-in) | -- | `CIDR_ERR_DONE` (internal, §8.9) |

Each custom exception class is created via `PyErr_NewExceptionWithDoc()` with
a tuple of bases passed in MRO-compatible order: `(CIDRError, BuiltinBase)`.
`CIDRError` must be first in the tuple so that `catch libcidr.CIDRError` works
correctly. CPython's MRO resolves multiple inheritance from built-in exception
types without layout conflicts when bases are passed in this order.

`CIDR_ERR_NOMEM` maps to the built-in `MemoryError` directly -- no custom
wrapper is warranted for an allocation failure. `CIDR_ERR_DONE` is consumed
internally by the subnet iterator's `__next__` implementation and never
surfaces as a catchable exception in normal iteration.

**Exception message strings are implementation-defined and not part of the
public API.** Tests must not assert on specific message text.

### 8.6 Address Types -- `IPv4Address` and `IPv6Address`

#### 8.6.1 Constructors

Both address types accept the following argument forms:

**String** -- parsed via the C arithmetic engine per §4.1:
```python
libcidr.IPv4Address('192.168.1.1')
libcidr.IPv6Address('2001:db8::1')
```

**Packed bytes** -- exactly 4 bytes for IPv4, exactly 16 bytes for IPv6,
in network byte order. This is the format produced by `socket.inet_pton()`:
```python
libcidr.IPv4Address(b'\xc0\xa8\x01\x01')
libcidr.IPv6Address(b'\x20\x01\x0d\xb8' + b'\x00' * 12 + b'\x00\x01')
```

**Integer** -- a non-negative integer in the valid range for the family
(0 to 2^32-1 for IPv4, 0 to 2^128-1 for IPv6). Matches `ipaddress`
constructor semantics:
```python
libcidr.IPv4Address(3232235777)   # 192.168.1.1
```

**`ipaddress` object** -- a matching `ipaddress.IPv4Address` or
`ipaddress.IPv6Address` instance. Construction extracts the packed bytes
from the `ipaddress` object internally:
```python
libcidr.IPv4Address(ipaddress.IPv4Address('192.168.1.1'))
```

Passing an `ipaddress.IPv6Address` to `libcidr.IPv4Address` or vice versa
raises `libcidr.FamilyError`.

#### 8.6.2 Properties

All properties are read-only.

| Property | Return type | Description |
|---|---|---|
| `packed` | `bytes` | Raw address bytes -- 4 bytes for IPv4, 16 for IPv6, network byte order |
| `compressed` | `str` | Canonical string form per RFC 1123 (IPv4) or RFC 5952 (IPv6) |
| `exploded` | `str` | Full uncompressed form -- dotted-decimal for IPv4, full 8-group hex for IPv6 |
| `version` | `int` | `4` or `6` |
| `is_global` | `bool` | `True` if `CIDR_CLASS_GLOBAL` |
| `is_private` | `bool` | `True` if `CIDR_CLASS_PRIVATE` |
| `is_loopback` | `bool` | `True` if `CIDR_CLASS_LOOPBACK` |
| `is_multicast` | `bool` | `True` if `CIDR_CLASS_MULTICAST` |
| `is_link_local` | `bool` | `True` if `CIDR_CLASS_LINK_LOCAL` |
| `is_unspecified` | `bool` | `True` if `CIDR_CLASS_UNSPECIFIED` (IPv6 only; always `False` for IPv4) |

`is_reserved` is intentionally omitted. Its definition in `ipaddress` is
ambiguous and has been inconsistent across Python versions. The `classify()`
method provides precise, unambiguous flag inspection for callers who need
fine-grained classification.

#### 8.6.3 Methods

**`classify() -> int`**

Returns the raw `cidr_class_t` bitmask as a Python `int`. Exposes the full
IANA classification result, including flags for which no boolean property
exists (`CIDR_CLASS_SHARED`, `CIDR_CLASS_DOCUMENTATION`, `CIDR_CLASS_ANYCAST`,
etc.):

```python
addr = libcidr.IPv4Address('192.0.2.1')
flags = addr.classify()
if flags & libcidr.CIDR_CLASS_DOCUMENTATION:
    print('documentation address')
```

The `CIDR_CLASS_*` constants and `CIDR_IANA_SNAPSHOT` are exported at
module level.

**`to_ipv4() -> IPv4Address | None`** (`IPv6Address` only)

Extracts the embedded IPv4 address if this IPv6 address is within the
IPv4-mapped prefix `::ffff:0:0/96`. Returns a new `IPv4Address` on success.
Returns `None` if the address is not IPv4-mapped. Backed by
`cidr_addr_to_v4()`.

```python
addr = libcidr.IPv6Address('::ffff:192.0.2.1')
ipv4 = addr.to_ipv4()   # libcidr.IPv4Address('192.0.2.1')

addr6 = libcidr.IPv6Address('2001:db8::1')
ipv4 = addr6.to_ipv4()  # None
```

This method is only present on `IPv6Address`. It is not present on
`IPv4Address` -- there is no inverse operation defined in the C API.

#### 8.6.4 Protocol Support

| Method | Behaviour |
|---|---|
| `__str__` | Returns `compressed` -- canonical string form |
| `__repr__` | Returns `IPv4Address('x.x.x.x')` or `IPv6Address('...')` |
| `__eq__` | True if family and address bytes are identical |
| `__hash__` | Stable hash of family and address bytes; enables use in sets and dicts |
| `__lt__` | Lexicographic order on address bytes within the same family; enables sorting |

Comparison between `IPv4Address` and `IPv6Address` raises `libcidr.FamilyError`.

### 8.7 Network Types -- `IPv4Network` and `IPv6Network`

#### 8.7.1 Constructors

Both network types accept the following argument forms:

**String CIDR** -- parsed via `cidr_prefix_parse()` (strict by default):
```python
libcidr.IPv4Network('192.168.1.0/24')
libcidr.IPv6Network('2001:db8::/32')
```

**String CIDR with `strict=False`** -- parsed via `cidr_prefix_from_host()`,
which zeros host bits explicitly. Matches `ipaddress.IPv4Network` behaviour:
```python
libcidr.IPv4Network('192.168.1.5/24', strict=False)
# constructs 192.168.1.0/24
```

`strict=True` is the default. With `strict=True`, host bits set raises
`libcidr.HostBitsError`. `strict` is a keyword-only argument.

**Tuple** -- `(address_string, prefixlen)` where `address_string` is parsed
per §4.1 and `prefixlen` is an integer. Useful when address and prefix length
come from separate variables. `strict` applies to the address parsing:
```python
libcidr.IPv4Network(('192.168.1.0', 24))
libcidr.IPv4Network(('192.168.1.5', 24), strict=False)
```

**`ipaddress` object** -- a matching `ipaddress.IPv4Network` or
`ipaddress.IPv6Network` instance. When constructed from an `ipaddress` object,
the `strict` parameter is ignored -- the object is already a valid network
with host bits zero:
```python
libcidr.IPv4Network(ipaddress.IPv4Network('192.168.1.0/24'))
```

#### 8.7.2 Properties

All properties are read-only.

| Property | Return type | Description |
|---|---|---|
| `network_address` | `IPv4Address` / `IPv6Address` | Network address (host bits zero) |
| `broadcast_address` | `IPv4Address` | Broadcast address -- `IPv4Network` only; raises `libcidr.FamilyError` on IPv6 |
| `prefixlen` | `int` | Prefix length |
| `netmask` | `IPv4Address` / `IPv6Address` | Prefix mask -- leading ones, trailing zeros |
| `with_prefixlen` | `str` | Canonical CIDR string, e.g. `'192.168.1.0/24'` |
| `version` | `int` | `4` or `6` |
| `num_addresses` | `int` | Total address count -- `2^(max_pfxlen - prefixlen)` |

#### 8.7.3 Methods

**`overlaps(other) -> bool`**

Returns `True` if this network and `other` share at least one address.
Backed by `cidr_prefix_overlaps()`. Raises `libcidr.FamilyError` if
`other` is a different address family.

**`supernet() -> IPv4Network | IPv6Network`**

Returns the parent network at `prefixlen - 1`. Backed by
`cidr_prefix_supernet()`. Raises `libcidr.AddressOverflowError` on a `/0`
network.

**`subnets(prefixlen: int) -> iterator`**

Returns a Python iterator over all subnets at `prefixlen`. Backed by a
pure C iterator object implementing `__iter__` and `__next__`. The
`subnets(prefixlen=n)` call is equivalent to `ipaddress.IPv4Network.subnets(new_prefix=n)`.
`CIDR_ERR_DONE` is consumed internally by `__next__` and surfaces as
`StopIteration` per the Python iterator protocol.

```python
for subnet in net.subnets(prefixlen=25):
    print(subnet)
```

The iterator is lazy -- subnets are computed on demand with no allocation
beyond the iterator object itself. Early termination (breaking from the
loop) is safe and incurs no cleanup cost.

**`contains(addr) -> bool`**

Returns `True` if `addr` falls within this network. Backed by
`cidr_prefix_contains()`. Explicit complement to the `__contains__`
protocol for callers who prefer method syntax. Raises `libcidr.FamilyError`
on family mismatch.

#### 8.7.4 Protocol Support

| Method | Behaviour |
|---|---|
| `__str__` | Returns `with_prefixlen` -- canonical CIDR string |
| `__repr__` | Returns `IPv4Network('x.x.x.x/n')` or `IPv6Network('...')` |
| `__eq__` | True if family, network address bytes, and prefix length are identical |
| `__hash__` | Stable hash of family, address bytes, and prefix length |
| `__lt__` | Order by network address ascending, prefix length ascending within same address |
| `__contains__` | Delegates to `contains()` -- enables `addr in network` syntax |

### 8.8 Bulk Operation Entry Points

All bulk functions are module-level, not methods on the type objects.

#### 8.8.1 Standard Entry Points

**`libcidr.bulk_parse(srcs) -> list`**

Accepts a `list` or `tuple` of address strings. All items are attempted
regardless of individual parse failures. Returns a `list` of `IPv4Address`
or `IPv6Address` objects. Family is inferred from the first successfully-parsed
item; subsequent items must parse to the same family. If any item fails to
parse or if the family is mixed, `libcidr.ParseError` or `libcidr.FamilyError`
is raised after the full batch completes. The binding calls the C function in
batch mode, then inspects the error array and raises on the first error found.

**`libcidr.bulk_contains(addrs, prefixes) -> list`**

Accepts a `list` or `tuple` of address objects and a `list` or `tuple` of
network objects. Returns a `list` of `int` values where `result[i]` is the
index of the first matching prefix in `prefixes` for `addrs[i]`, or `-1`
if no prefix matched. Backed by `cidr_bulk_contains()`. Mixed-family input
raises `libcidr.FamilyError`.

**`libcidr.bulk_aggregate(prefixes) -> list`**

Accepts a `list` or `tuple` of network objects. Returns a new `list` of
network objects representing the minimal covering set. The input is not
modified. Backed by `cidr_bulk_aggregate()`. Mixed-family input raises
`libcidr.FamilyError`.

**`libcidr.bulk_sort(prefixes, order) -> list`**

Accepts a `list` or `tuple` of network objects and a sort order constant
(`libcidr.SORT_NETWORK_ASC` or `libcidr.SORT_PFXLEN_DESC`). Returns a new
sorted `list`. The input is not modified. Backed by `cidr_bulk_sort()`.

#### 8.8.2 memoryview Entry Points

`memoryview` entry points are provided for callers who have addresses in
packed binary format and want to avoid constructing Python address objects
per element. The primary benefit is eliminating Python object allocation
overhead at the call site; zero-copy is not achievable because the C layer
requires `cidr_addr_t` structs (20 bytes with family discriminator) rather
than raw packed bytes (4 or 16 bytes). The binding
layer iterates the `memoryview` in C and constructs `cidr_addr_t` structs
in a tight loop with no Python object creation per address.

**`libcidr.bulk_contains_packed(mv, prefixes, family) -> list`**

Accepts a `memoryview` of packed binary address data, a `list` or `tuple`
of network objects, and an explicit `family` constant
(`libcidr.AF_INET` or `libcidr.AF_INET6`). The `memoryview` must be
one-dimensional, C-contiguous (`PyBUF_C_CONTIGUOUS`), and contain elements
of exactly 4 bytes for `AF_INET` or 16 bytes for `AF_INET6`. Returns a
`list` of `int` match indices identical in format to `bulk_contains()`.

The `family` parameter is required because a binary buffer carries no family
signal. `libcidr.AF_INET = 4` and `libcidr.AF_INET6 = 6` are exported at
module level, matching the `cidr_family_t` values.

Raises `libcidr.InvalidArgumentError` for: non-contiguous or
multi-dimensional memoryview; element size not matching `family`.

```python
import struct, libcidr

# Pack addresses directly from binary source
buf = struct.pack('4s4s', b'\xc0\xa8\x01\x01', b'\x0a\x00\x00\x01')
mv  = memoryview(buf).cast('B').cast('4s')   # shape: (2,), itemsize: 4
results = libcidr.bulk_contains_packed(mv, prefixes, libcidr.AF_INET)
```

`memoryview` support is intentionally limited to `bulk_contains` on the
address input side. `bulk_aggregate` and `bulk_sort` operate on networks
(address plus prefix length), which have no standard packed binary format
and no natural `memoryview` representation.

### 8.9 Subnet Iterator

The subnet iterator is a pure C Python object implementing `__iter__` and
`__next__`. It wraps a `cidr_subnet_iter_t` embedded by value in the Python
object allocation. No heap allocation occurs beyond the iterator object
itself.

`__iter__` returns `self` -- the iterator is its own iterable per the Python
iterator protocol.

`__next__` calls `cidr_subnet_iter_next()`. On `CIDR_OK`, it constructs and
returns the next network object. On `CIDR_ERR_DONE`, it raises `StopIteration`
-- the standard Python signal for iterator exhaustion. The `CIDR_ERR_DONE`
code is consumed entirely within `__next__` and is never visible to the
Python caller as an exception to catch.

The iterator is pauseable -- a `break` from the iteration loop is safe. The
iterator object is freed by CPython's reference counting when it goes out of
scope. No cleanup call is required.

### 8.10 Ownership and Reference Counting

Each Python type object (`IPv4Address`, `IPv6Address`, `IPv4Network`,
`IPv6Network`) embeds its corresponding C struct by value directly in the
`PyObject` allocation:

- `IPv4Address` and `IPv6Address` embed a `cidr_addr_t` (20 bytes)
- `IPv4Network` and `IPv6Network` embed a `cidr_prefix_t` (24 bytes)
- The subnet iterator embeds a `cidr_subnet_iter_t`

**No shared pointers exist between Python objects and C library memory.**
Every Python object owns its C struct exclusively. When CPython frees a
Python object via reference counting, the embedded C struct is freed with
it. No custom `tp_dealloc` logic is required beyond the default object
deallocation -- there are no heap-allocated members to free separately.

**No cross-object lifetime dependencies exist.** An `IPv4Address` returned
by `network.network_address` is a newly constructed object with its own
copy of the C struct, not a pointer into the network object's storage.
This design eliminates an entire class of use-after-free bugs.

**Reference count rules in the binding layer** follow CPython stable ABI
conventions throughout: functions that return a new reference must be
balanced with `Py_DECREF` on error paths; borrowed references must not be
decremented. All type definitions use `PyType_FromSpec()` with slot-based
method tables.

---

## 9. Error Handling Summary

| Code | Value | Meaning | Returned by |
|---|---|---|---|
| `CIDR_OK` | 0 | Success | All functions |
| `CIDR_ERR_INVAL` | 1 | NULL pointer, buffer too small, `CIDR_AF_UNSPEC` input, count out of valid range, NULL element in string array, NULL required output pointer | All functions |
| `CIDR_ERR_PARSE` | 2 | Text does not parse per applicable RFC | Parse functions, bulk parse |
| `CIDR_ERR_PFXLEN` | 3 | Prefix length out of range for family | Prefix functions, iterator init |
| `CIDR_ERR_HOSTBITS` | 4 | Host bits set -- strict parse only | `cidr_prefix_parse()` |
| `CIDR_ERR_NOMEM` | 5 | Allocation failure | `cidr_index_create()` only |
| `CIDR_ERR_FAMILY` | 6 | Address family mismatch between operands, or mixed families in a bulk array | All operations on two or more values |
| `CIDR_ERR_OVERFLOW` | 7 | Result not representable | `cidr_prefix_supernet()` on `/0` |
| `CIDR_ERR_DONE` | 8 | Iterator exhausted -- normal termination | `cidr_subnet_iter_next()` |

---

## 10. Open Items

Items not yet designed. Each must be resolved before the relevant
implementation phase begins.

| Item | Blocks | Notes |
|---|---|---|
| Build system for Python extension | Build | Makefile confirmed for C library; Python extension build TBD |
| Platform matrix and CI | Build | Linux + OpenBSD, amd64 + arm64; CI approach TBD |
| C library test strategy | Testing | RFC conformance, property-based, round-trip TBD |
| Python layer test strategy | Testing | stdlib comparison approach TBD |
| Sanitizer integration | Testing | Valgrind, ASan, UBSan, TSan TBD |

**Confirmed out-of-scope decisions (permanently excluded):**

| Decision | Rationale |
|---|---|
| Liberal input parsing | Correctness liability; non-RFC forms are ambiguous |
| Silent host-bit zeroing on prefix parse | Hides caller bugs; two explicit functions are correct |
| IPv4-compatible IPv6 address support | Deprecated by RFC 4291; new implementations not required to support |
| Mixed-family bulk operations | IPv4 and IPv6 are distinct address spaces; mixing is a caller bug |
| Library-allocated output buffers | Hidden allocation violates zero-allocation model |
| Callback-based subnet iteration | Caller cannot pause; maps poorly to Python iterator protocol |
| Routing protocol logic | Out of scope by definition |
| Network I/O | Out of scope by definition |
| NumPy integration | Dependency-free requirement; plain Python sequences used |
| Prefix index in bulk containment (hidden) | O(n*m) is explicit; index is a separate explicit API |
| `is_reserved` Python property | Ambiguous definition; inconsistent across ipaddress versions; `classify()` is the correct tool |
| Full ipaddress duck-type compatibility | Maintenance liability tied to stdlib internals; targeted property subset covers the 80% use case |
| Integer constructor for Network types | Awkward signature requiring separate prefix length; not a natural input format for networks |
| memoryview for bulk_aggregate / bulk_sort | Network types (address + prefix length) have no standard packed binary format; memoryview is supported for packed binary address input to bulk_contains_packed() only |
| Runtime IANA registry updates | Classification table is a compile-time constant; live fetching is out of scope |
| Reverse construction to ipaddress objects | One-way construction from ipaddress is sufficient; reverse conversion belongs in caller code |
| Operational routability guarantee from CIDR_CLASS_GLOBAL | IANA explicitly states registry absence does not imply global routability; the flag means "not in any special-purpose block" only |
| ABI stability across libcidr major versions | No ABI stability guarantee is made across major version increments |
| Standalone prefix dedup API | Deduplication is internal to `cidr_bulk_aggregate()`; no public dedup function is provided |
| IPv6 zone identifiers (scope indices) | Addresses with zone IDs such as `fe80::1%eth0` are not supported; only the address portion is parsed and formatted |
| Netmask notation | CIDR prefix length notation only; dotted-decimal netmask notation such as `192.168.1.0/255.255.255.0` is not accepted |
| `IPv6Address.to_ipv4()` returning libcidr type for non-mapped input | Returns `None` for non-mapped input rather than raising; callers can use `classify()` to check `CIDR_CLASS_V4MAPPED` first if they want to avoid the None check |

---

**See Also**: PROJECT.md, TECH_STACK.md, CODING_STANDARDS.md, DEVELOPMENT.md,
TESTING.md, REPOSITORY_STRUCTURE.md
