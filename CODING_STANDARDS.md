# Coding Standards

## 1. Code Style

### 1.1 OpenBSD KNF (Kernel Normal Form)

libcidr follows OpenBSD's Kernel Normal Form style. This is the style used
throughout the OpenBSD base system and is required for all source files in
`src/`, `include/`, and `python/`.

**Indentation**:
- Tabs for indentation, 8-character display width
- Spaces only for alignment within a line, never for indentation
- Never mix tabs and spaces for indentation

```c
/* Correct */
static cidr_err_t
prefix_mask_apply(const cidr_prefix_t *prefix, uint8_t *addr_bytes)
{
	uint8_t   mask;
	int       byte, bit;

	if (prefix->pfxlen == 0)
		return CIDR_OK;
	byte = (int)(prefix->pfxlen / 8);
	bit  = (int)(prefix->pfxlen % 8);
	for (int i = 0; i < byte; i++)
		addr_bytes[i] &= 0xFF;
	if (bit > 0)
		addr_bytes[byte] &= (uint8_t)(0xFF << (8 - bit));
	return CIDR_OK;
}

/* Wrong - spaces used for indentation */
static cidr_err_t
prefix_mask_apply(const cidr_prefix_t *prefix, uint8_t *addr_bytes)
{
    uint8_t   mask;   /* spaces, not tabs */
}
```

**Braces**:
```c
/* Functions: opening brace on its own line */
cidr_err_t
cidr_prefix_contains(const cidr_prefix_t *prefix,
    const cidr_addr_t *addr, bool *out)
{
	/* body */
}

/* Control structures: opening brace on same line */
if (prefix->addr.family == CIDR_AF_INET) {
	if (addr->family != CIDR_AF_INET)
		return CIDR_ERR_FAMILY;
}

/* Single-statement bodies: no braces, indented on next line */
if (addr == NULL)
	return CIDR_ERR_INVAL;

/* Loop with single statement */
for (size_t i = 0; i < count; i++)
	out[i] = CIDR_OK;
```

**Line length**: Maximum 80 characters. Break long lines at logical points,
aligning continuation with the opening parenthesis or using one extra tab:

```c
/* Break at logical point, align with opening paren */
rc = cidr_prefix_parse(src, len,
    out);

/* Extra tab indent for continuation when alignment would be too deep */
if (cidr_prefix_from_host(&addr, (uint8_t)pfxlen, out) != CIDR_OK)
	return CIDR_ERR_INVAL;
```

**Naming conventions**:
```c
/* Variables and function parameters: lowercase with underscores */
size_t       count;
uint8_t      pfxlen;
cidr_addr_t *addr;
cidr_err_t   rc;

/* Public API functions: cidr_ prefix, lowercase with underscores */
cidr_err_t  cidr_addr_parse(const char *, cidr_addr_t *);
cidr_err_t  cidr_prefix_contains(const cidr_prefix_t *, const cidr_addr_t *,
                bool *);
cidr_err_t  cidr_bulk_aggregate(cidr_prefix_t *, size_t, size_t *);

/* Internal functions: module prefix, no cidr_ prefix */
static cidr_err_t  addr_parse_ipv4(const char *, size_t, cidr_addr_t *);
static cidr_err_t  addr_parse_ipv6(const char *, size_t, cidr_addr_t *);
static void        radix_sort_pass(cidr_prefix_t *, size_t, int);

/* Constants and macros: uppercase with underscores, CIDR_ prefix */
#define CIDR_ADDR_STR_MAX     46
#define CIDR_PREFIX_STR_MAX   50
#define CIDR_IANA_SNAPSHOT    20251009

/* Structs and typedefs: lowercase, _t suffix */
typedef struct cidr_addr     cidr_addr_t;
typedef struct cidr_prefix   cidr_prefix_t;
typedef struct cidr_index    cidr_index_t;

/* Enums: uppercase values with CIDR_ prefix */
typedef enum {
	CIDR_AF_UNSPEC = 0,
	CIDR_AF_INET   = 4,
	CIDR_AF_INET6  = 6,
} cidr_family_t;

typedef enum {
	CIDR_OK           = 0,
	CIDR_ERR_INVAL    = 1,
	CIDR_ERR_PARSE    = 2,
	/* ... */
} cidr_err_t;
```

**Spacing**:
```c
/* Space after keywords, not after function names */
if (rc != CIDR_OK)           /* correct */
if(rc != CIDR_OK)            /* wrong */
cidr_addr_parse(src, out)    /* correct */
cidr_addr_parse (src, out)   /* wrong */

/* No space inside parentheses */
if (count > 0)               /* correct */
if ( count > 0 )             /* wrong */

/* Space around binary operators */
len = end - start;
idx = (byte * 256) + digit;

/* No space for unary operators */
ptr   = &entry;
val   = *ptr;
flags = ~mask;
```

**Return type on its own line**:
```c
/* Correct */
static cidr_err_t
addr_parse_ipv4(const char *src, size_t len, cidr_addr_t *out)
{
	/* ... */
}

/* Wrong */
static cidr_err_t addr_parse_ipv4(const char *src, size_t len,
    cidr_addr_t *out)
{
	/* ... */
}
```

### 1.2 File Organisation

**Public header** (`include/libcidr.h`):

The public header exposes only what callers need. Internal types, internal
function declarations, and implementation details are never declared here.
The header is self-contained -- a caller includes only `libcidr.h`.

```c
#ifndef LIBCIDR_H
#define LIBCIDR_H

/*
 * libcidr.h - libcidr public API
 *
 * Parse and format IPv4/IPv6 addresses: cidr_addr_parse(), cidr_addr_format()
 * Parse and format CIDR prefixes:       cidr_prefix_parse(), cidr_prefix_from_host()
 * Prefix arithmetic:                    cidr_prefix_contains(), cidr_prefix_overlaps()
 * Subnet enumeration:                   cidr_subnet_iter_init(), cidr_subnet_iter_next()
 * Bulk operations:                      cidr_bulk_parse(), cidr_bulk_aggregate()
 * Prefix index:                         cidr_index_create(), cidr_index_lookup()
 * Address classification:               cidr_addr_classify()
 *
 * See ARCHITECTURE.md for the full API specification and design rationale.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>   /* ssize_t */

/* ... public types, constants, and function declarations ... */

#endif /* LIBCIDR_H */
```

**Internal header** (`src/cidr_internal.h`):

```c
#ifndef CIDR_INTERNAL_H
#define CIDR_INTERNAL_H

/*
 * cidr_internal.h - internal definitions shared across libcidr source files.
 * Not installed. Not included by callers.
 * See ARCHITECTURE.md §3 for type design rationale and invariants.
 */

#include "../include/libcidr.h"

/* Compile-time layout checks. See ARCHITECTURE.md §3.2, §3.3. */
_Static_assert(sizeof(cidr_addr_t)   == 20,
    "cidr_addr_t size changed -- update ARCHITECTURE.md §3.2");
_Static_assert(sizeof(cidr_prefix_t) == 24,
    "cidr_prefix_t size changed -- update ARCHITECTURE.md §3.3");

/* ... internal helper declarations ... */

#endif /* CIDR_INTERNAL_H */
```

**Source files** (`.c`):
```c
/*
 * cidr_bulk.c - batch parse, containment, aggregation, and sort
 *
 * Implements cidr_bulk_parse(), cidr_bulk_contains(), cidr_bulk_aggregate(),
 * and cidr_bulk_sort(). Contains the shared in-place MSD radix sort engine.
 * See ARCHITECTURE.md §5 for the bulk engine design and complexity analysis.
 */

#include <string.h>

#include "../include/libcidr.h"
#include "cidr_internal.h"
```

**Include order** (within each group, alphabetical):
```c
/* 1. System headers */
#include <stdint.h>
#include <string.h>

/* 2. POSIX headers */
#include <sys/types.h>

/* 3. Public library header */
#include "../include/libcidr.h"

/* 4. Internal header */
#include "cidr_internal.h"
```

`<stdlib.h>` appears only in `src/cidr_index.c`. No other source file
includes it. This constraint is enforced at code review and verified by:
```sh
grep -n "#include <stdlib.h>" src/*.c
# expected output: only src/cidr_index.c
```

### 1.3 Static Assertions

Use `_Static_assert` to catch layout changes at compile time. Place them in
`src/cidr_internal.h` where the types are fully defined.

```c
/* In src/cidr_internal.h */
_Static_assert(sizeof(cidr_addr_t) == 20,
    "cidr_addr_t size changed -- check family enum size and union padding");
_Static_assert(sizeof(cidr_prefix_t) == 24,
    "cidr_prefix_t size changed -- check addr + pfxlen + trailing padding");
_Static_assert(sizeof(cidr_lctrie_node_t) == 12,
    "cidr_lctrie_node_t size changed -- update ARCHITECTURE.md §6.3");
```

These assertions fire at compile time if any struct layout changes. A layout
change in `cidr_addr_t` or `cidr_prefix_t` would silently corrupt every
caller that uses these types in arrays or embeds them in other structs. The
assertion messages name the documentation section that must be updated if the
size is intentionally changed.

---

## 2. Memory Management

### 2.1 Allocation Policy

libcidr uses `malloc` and `free` in exactly one place: `cidr_index_create()`
and `cidr_index_destroy()`. Every other function is allocation-free. This
is a design invariant, not a preference.

```c
/* Correct - cidr_index.c only */
nodes = malloc(node_count * sizeof(cidr_lctrie_node_t));
if (nodes == NULL)
	return CIDR_ERR_NOMEM;

/* Wrong - malloc in any other source file */
/* src/cidr_bulk.c */
cidr_prefix_t *tmp = malloc(count * sizeof(*tmp));  /* VIOLATION */
```

All radix sort workspace is on the stack. The radix sort engine uses a
fixed histogram array at each recursion level -- no heap allocation occurs
during any bulk operation. The maximum stack usage is documented in
ARCHITECTURE.md §5.4 (34,816 bytes worst case for IPv6 on 64-bit platforms,
well within the default stack limit).

### 2.2 Error Checking

Every `malloc` call must check for `NULL`:

```c
nodes = malloc(node_count * sizeof(cidr_lctrie_node_t));
if (nodes == NULL)
	return CIDR_ERR_NOMEM;
```

Set pointers to `NULL` after freeing to prevent accidental use-after-free:

```c
cidr_index_destroy(index);
index = NULL;
```

### 2.3 Resource Cleanup with goto

Use the `goto cleanup` pattern for functions that acquire multiple resources.
This ensures cleanup on every error path without duplication. The pattern is
mandatory for any function that acquires more than one resource.

```c
static cidr_err_t
index_build(const cidr_prefix_t *prefixes, size_t count,
    cidr_index_t **out)
{
	cidr_index_t       *idx  = NULL;
	cidr_lctrie_node_t *nodes = NULL;
	cidr_prefix_t      *copy  = NULL;
	cidr_err_t          rc   = CIDR_ERR_NOMEM;

	idx = malloc(sizeof(cidr_index_t));
	if (idx == NULL)
		goto cleanup;

	nodes = malloc(node_count * sizeof(cidr_lctrie_node_t));
	if (nodes == NULL)
		goto cleanup;

	copy = malloc(count * sizeof(cidr_prefix_t));
	if (copy == NULL)
		goto cleanup;

	/* ... build the trie ... */
	rc = CIDR_OK;

cleanup:
	if (rc != CIDR_OK) {
		free(copy);
		free(nodes);
		free(idx);
		return rc;
	}
	idx->nodes    = nodes;
	idx->prefixes = copy;
	*out = idx;
	return CIDR_OK;
}
```

---

## 3. Error Handling

### 3.1 Error Returns

Every public function except `cidr_index_destroy()` returns `cidr_err_t`.
Zero is always success. Callers must check return values. `cidr_index_destroy()`
returns `void` and is NULL-safe -- destructors have no meaningful failure mode.

```c
/* Correct */
cidr_err_t rc = cidr_addr_parse(src, &addr);
if (rc != CIDR_OK) {
	/* handle error */
}

/* Internal functions: same convention */
if (addr_parse_ipv4(src, len, out) != CIDR_OK)
	return CIDR_ERR_PARSE;
```

Do not silently discard return values. If a return value is intentionally
ignored, cast to `(void)`:

```c
(void)cidr_addr_format(&addr, buf, sizeof(buf));  /* only for debug logging */
```

### 3.2 warn_unused_result

All public functions except `cidr_index_destroy()` carry
`__attribute__((warn_unused_result))`. This is declared in `libcidr.h` on
every function prototype. Ignoring a return value is a compiler warning and
therefore a build error under `-Werror`.

Internal static functions that can fail must also carry this attribute:

```c
static cidr_err_t
addr_parse_ipv6(const char *src, size_t len, cidr_addr_t *out)
    __attribute__((warn_unused_result));
```

### 3.3 CIDR_OK as Zero

`CIDR_OK == 0`. Error codes are non-zero. This means:

```c
/* Correct - explicit comparison */
if (rc != CIDR_OK)
	return rc;

/* Wrong - implicit truthiness; misleads the reader */
if (rc)
	return rc;

/* Correct - explicit comparison for success */
if (rc == CIDR_OK)
	*out_count = count;
```

Always use named comparisons. The enum value names are documentation.

### 3.4 NULL Pointer Policy

All public functions return `CIDR_ERR_INVAL` if any pointer parameter that
is required to be non-NULL is NULL. This is the blanket rule documented in
ARCHITECTURE.md §1.4. Every pointer parameter must be checked:

```c
cidr_err_t
cidr_addr_parse(const char *src, cidr_addr_t *out)
{
	if (src == NULL || out == NULL)
		return CIDR_ERR_INVAL;
	/* ... */
}
```

Optional pointer parameters (documented as "may be NULL") must not be checked
with the blanket rule -- the documentation must explicitly state they are
optional. Example: `errs` in bulk functions, `out` in `cidr_prefix_contains()`.

```c
/*
 * cidr_prefix_contains -- out may be NULL; caller interested only in
 * the return code uses NULL to skip the write.
 */
cidr_err_t
cidr_prefix_contains(const cidr_prefix_t *prefix, const cidr_addr_t *addr,
    bool *out)
{
	bool result;

	if (prefix == NULL || addr == NULL)
		return CIDR_ERR_INVAL;
	/* out is optional -- NULL is documented as valid */
	/* ... compute result ... */
	if (out != NULL)
		*out = result;
	return CIDR_OK;
}
```

---

## 4. Safety Practices

### 4.1 SAFETY Comments

Mark safety-critical invariants explicitly so they are never accidentally
removed during refactoring. The comment format is `/* SAFETY: ... */` on its
own line before the guarded code.

```c
/*
 * SAFETY: family must be CIDR_AF_INET or CIDR_AF_INET6 -- CIDR_AF_UNSPEC
 * is rejected at entry. All internal arithmetic assumes a valid family.
 * See ARCHITECTURE.md §3.1.
 */
assert(prefix->addr.family == CIDR_AF_INET ||
    prefix->addr.family == CIDR_AF_INET6);

/*
 * SAFETY: host bits in prefix->addr are always zero -- this invariant
 * is established at construction and relied upon by all arithmetic.
 * Never construct a cidr_prefix_t directly; use cidr_prefix_parse() or
 * cidr_prefix_from_host(). See ARCHITECTURE.md §3.3.
 */

/*
 * SAFETY: cidr_index.c only -- no other source file may call malloc
 * or free. Verify with: grep -n "malloc\|free" src/*.c
 * See ARCHITECTURE.md §1.4 and TECH_STACK.md §3.1.
 */
nodes = malloc(node_count * sizeof(cidr_lctrie_node_t));
```

### 4.2 Bulk Operation Bounds Discipline

Bulk functions accept caller-provided arrays with explicit counts. The library
must never read or write outside the bounds declared by the caller. Every
loop over a caller-provided array must use the caller-provided count as the
exclusive upper bound, with no arithmetic that could overflow `size_t`:

```c
/* Correct */
for (size_t i = 0; i < count; i++) {
	rc = cidr_addr_parse(srcs[i], &out[i]);
	errs[i] = rc;
}

/* Wrong - could overflow if count is near SIZE_MAX */
for (size_t i = 0; i <= count - 1; i++) { /* UB if count == 0 */
	/* ... */
}
```

Empty array (`count == 0`) must return `CIDR_OK` immediately without touching
any array pointer:

```c
cidr_err_t
cidr_bulk_sort(cidr_prefix_t *prefixes, size_t count,
    cidr_sort_order_t order)
{
	if (count == 0)
		return CIDR_OK;
	if (prefixes == NULL)
		return CIDR_ERR_INVAL;
	/* ... */
}
```

The NULL check for the array pointer comes after the count check. When
`count == 0`, a NULL array pointer is valid and must not be dereferenced.

### 4.3 Integer Safety

Use fixed-width types for all size calculations and index arithmetic.
The `count` and array index types are `size_t`. Prefix lengths are `uint8_t`.
Addresses are `uint8_t` arrays. No signed integers are used for sizes or
counts internally.

```c
/* Correct -- sized types */
uint8_t   pfxlen;
size_t    count;
size_t    byte_index;
uint32_t  flag;

/* Correct -- bounds check before bit shift */
if (bit > 0 && bit <= 8)
	addr_bytes[byte] &= (uint8_t)(0xFF << (8 - bit));
```

Integer overflow in prefix length arithmetic must be guarded. A `pfxlen`
of 0 must produce a mask of all zeros, not invoke undefined behaviour:

```c
/* Correct */
if (pfxlen == 0) {
	memset(mask_bytes, 0x00, addr_len);
} else if (pfxlen >= (uint8_t)(addr_len * 8)) {
	memset(mask_bytes, 0xFF, addr_len);
} else {
	/* ... safe partial mask computation ... */
}
```

### 4.4 No Global Mutable State

libcidr has no global mutable state. The classification table
(`src/cidr_classify.c`) is a compile-time constant array -- it is read-only
data placed in the `.rodata` segment. No function modifies any file-scope
variable at runtime.

Do not add file-scope mutable variables to any source file. If a future
feature requires shared state, raise it against ARCHITECTURE.md before
implementing -- it would affect the thread safety model.

```c
/* Correct -- compile-time constant table */
static const struct {
	cidr_family_t  family;
	uint8_t        prefix[16];
	uint8_t        pfxlen;
	cidr_class_t   flags;
} classify_table[] = {
	/* ... RFC 6890 entries ... */
};

/* Wrong -- mutable global */
static size_t classify_table_count = 0;   /* VIOLATION */
```

---

## 5. Documentation

### 5.1 Function Comments

Every public function requires a block comment describing what it does,
its parameters, return values, and any preconditions. Internal static helpers
require a brief comment unless the function name is entirely self-explanatory.

```c
/*
 * cidr_bulk_aggregate - aggregate a prefix array to a minimal covering set.
 *
 * Modifies the prefix array in place. The result covers exactly the same
 * address space as the input -- no more, no less. On return, the first
 * *out_count entries are the aggregated prefixes; the remaining entries
 * are undefined.
 *
 * prefixes:   caller-provided prefix array; modified in place
 * count:      number of entries in prefixes
 * out_count:  receives the number of prefixes in the aggregated result;
 *             must not be NULL
 *
 * Returns CIDR_OK on success.
 * Returns CIDR_ERR_INVAL if prefixes or out_count is NULL, or count == 0.
 * Returns CIDR_ERR_FAMILY if the array contains mixed IPv4 and IPv6 prefixes.
 *
 * Complexity: O(n * k) where k is key width in bytes (5 for IPv4, 17 for
 * IPv6); treated as O(n) because k is a compile-time constant.
 * No allocation occurs. Stack usage: at most 34,816 bytes for IPv6 on
 * 64-bit platforms. See ARCHITECTURE.md §5.4.
 */
cidr_err_t
cidr_bulk_aggregate(cidr_prefix_t *prefixes, size_t count, size_t *out_count)
```

### 5.2 Architecture Cross-Reference Comments

When implementing logic described in ARCHITECTURE.md, reference the relevant
section. This makes it possible to navigate from code to specification and
back.

```c
/*
 * RFC 5952 §4.2.3 tie-breaking: when two consecutive zero runs are equal
 * length, compress the first. See ARCHITECTURE.md §4.2.2.
 */

/*
 * Host-bits-zero invariant: established at construction, never re-checked.
 * cidr_prefix_parse rejects non-zero host bits; cidr_prefix_from_host zeros
 * them explicitly. See ARCHITECTURE.md §3.3.
 */

/*
 * In-place MSD radix sort -- O(n*k), k is key width in bytes.
 * Stack usage documented in ARCHITECTURE.md §5.4.
 */

/*
 * LC-trie traversal: advance skip bits, extract branch bits as index,
 * descend to nodes[base + index]. Record best match at each interior node
 * with prefix_idx != UINT32_MAX. See ARCHITECTURE.md §6.3.
 */

/*
 * CIDR_CLASS_GLOBAL is set when no special-purpose block matched.
 * It does not imply operational routability. See ARCHITECTURE.md §7.2.
 */
```

### 5.3 TODO and FIXME

```c
/* TODO: SIMD-accelerated comparison for 16-byte IPv6 address equality */
/* FIXME: classification scan is linear; consider binary search for n > 64 */
/* NOTE: pfxlen == 0 means the default route -- host bits are by definition
 *       all zero, so the mask computation path must handle this correctly */
/* NOTE: CIDR_OK == 0; check rc == CIDR_OK explicitly, never rc == 0 */
```

---

## 6. Python Binding Code Style

The Python binding layer (`python/_libcidr_ext.c`) is C code and follows
all KNF style rules from §1. The following additional rules apply specifically
to CPython extension code.

### 6.1 Stable ABI Conventions

The extension is compiled against the CPython 3.11 stable ABI
(`Py_LIMITED_API = 0x030B0000`). This restricts the usable CPython API
surface. The binding must never use APIs not available in the stable ABI:

```c
/* Correct -- stable ABI since 3.0 */
PyType_FromSpec(&ipv4_address_spec)
PyErr_NewExceptionWithDoc(name, doc, bases, dict)
PyArg_ParseTupleAndKeywords(args, kwargs, fmt, kwlist, ...)
PyLong_AsLongLong(obj)
PyBytes_AsStringAndSize(obj, &buf, &len)
PyMemoryView_GET_BUFFER(obj)

/* Wrong -- not available under Py_LIMITED_API */
PyTypeObject my_type = { ... };              /* direct struct init */
PyLong_AS_LONG(obj)                          /* macro, not ABI-stable */
((PyBytesObject *)obj)->ob_val               /* direct struct access */
```

Never define `PyTypeObject` directly. All Python type definitions use
`PyType_FromSpec()` with a `PyType_Spec` and slot array. This is mandatory,
not optional -- direct `PyTypeObject` initialization requires the full API.

### 6.2 Reference Counting Discipline

Reference counting errors are silent and produce use-after-free bugs or
memory leaks. Follow these rules without exception.

**New reference vs. borrowed reference:** Know which every function returns.
Most `PyObject_GetAttr*`, `PyArg_Parse*` extractions, and `PyTuple_GetItem`
return borrowed references. Most `PyObject_New`, `PyLong_FromLong`,
`PyBytes_FromStringAndSize`, and `PyErr_NewExceptionWithDoc` return new
references.

```c
/* Correct -- new reference from PyLong_FromLong; must DECREF when done */
PyObject *version = PyLong_FromLong(4L);
if (version == NULL)
	return NULL;
rc = PyDict_SetItemString(dict, "version", version);
Py_DECREF(version);   /* release our reference; dict holds its own */
if (rc != 0)
	return NULL;

/* Correct -- borrowed reference from PyTuple_GetItem; do NOT DECREF */
PyObject *first = PyTuple_GetItem(args, 0);   /* borrowed */
/* use first without DECREF */

/* Wrong -- DECREF on a borrowed reference */
PyObject *item = PyTuple_GetItem(args, 0);
Py_DECREF(item);   /* VIOLATION: we did not own this reference */
```

**Error paths must release all acquired references.** Use the `goto error`
pattern when a function acquires multiple Python objects:

```c
static PyObject *
ipv4network_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	PyObject       *result   = NULL;
	PyObject       *addr_obj = NULL;
	PyObject       *net_obj  = NULL;
	IPv4Network    *self;

	/* ... parse arguments ... */

	addr_obj = PyObject_CallFunction(ipv4address_type, "O", src);
	if (addr_obj == NULL)
		goto error;

	net_obj = build_network_obj(addr_obj, pfxlen);
	if (net_obj == NULL)
		goto error;

	self = (IPv4Network *)type->tp_alloc(type, 0);
	if (self == NULL)
		goto error;

	/* ... populate self ... */

	result = (PyObject *)self;
	/* fall through to cleanup, result is non-NULL */

error:
	Py_XDECREF(net_obj);
	Py_XDECREF(addr_obj);
	return result;
}
```

Use `Py_XDECREF` (not `Py_DECREF`) for pointers that may be NULL on the
error path. Use `Py_DECREF` only when the pointer is guaranteed non-NULL.

**Py_None requires INCREF.** `Py_None` is a singleton; it must be
reference-counted like any other object:

```c
/* Correct -- returning None */
Py_INCREF(Py_None);
return Py_None;

/* Correct -- assigning None to a dict value */
Py_INCREF(Py_None);
PyDict_SetItemString(d, "key", Py_None);
Py_DECREF(Py_None);   /* dict holds its own reference */

/* Wrong -- returning Py_None without INCREF */
return Py_None;   /* VIOLATION: caller takes ownership, refcount not incremented */
```

### 6.3 Error Handling in the Binding Layer

Two invariants govern error handling in extension functions:

1. **Return NULL if and only if an exception is set.** A function that
   returns NULL with no exception set will propagate a garbage exception
   to the caller.
2. **Return non-NULL if and only if no exception is set.** A function that
   sets an exception and returns non-NULL will corrupt the Python exception
   state.

```c
/* Correct -- exception set, return NULL */
if (count > PY_SSIZE_T_MAX) {
	PyErr_SetString(PyExc_OverflowError, "count exceeds platform maximum");
	return NULL;
}

/* Correct -- no exception, return value */
return PyLong_FromLong((long)count);

/* Wrong -- returns NULL without setting exception */
if (addr == NULL)
	return NULL;   /* VIOLATION: what exception? */

/* Wrong -- sets exception then returns non-NULL */
PyErr_SetString(libcidr_ParseError, "bad input");
return Py_None;   /* VIOLATION: caller sees Py_None but exception is set */
```

Before returning from any error path, verify the exception state is correct
during development:

```c
#ifdef CIDR_DEBUG
	assert(result == NULL ? PyErr_Occurred() != NULL
	                      : PyErr_Occurred() == NULL);
#endif
```

### 6.4 cidr_err_t to Python Exception Mapping

All C API calls are translated through a single helper function that maps
`cidr_err_t` to the appropriate Python exception. Never set Python exceptions
inline based on `cidr_err_t` values -- always go through this helper:

```c
/*
 * cidr_set_python_error -- translate cidr_err_t to a Python exception.
 *
 * Sets the appropriate Python exception for the given error code and
 * optional context string. Returns -1 (convention for "error was set")
 * for all error codes; returns 0 for CIDR_OK (no exception set).
 *
 * Call as: if (cidr_set_python_error(rc, NULL) < 0) return NULL;
 */
static int
cidr_set_python_error(cidr_err_t rc, const char *context)
{
	switch (rc) {
	case CIDR_OK:
		return 0;
	case CIDR_ERR_INVAL:
		PyErr_SetString(libcidr_InvalidArgumentError,
		    context ? context : "invalid argument");
		return -1;
	case CIDR_ERR_PARSE:
		PyErr_SetString(libcidr_ParseError,
		    context ? context : "parse error");
		return -1;
	case CIDR_ERR_HOSTBITS:
		PyErr_SetString(libcidr_HostBitsError,
		    context ? context : "host bits set in prefix");
		return -1;
	case CIDR_ERR_PFXLEN:
		PyErr_SetString(libcidr_PrefixLengthError,
		    context ? context : "prefix length out of range");
		return -1;
	case CIDR_ERR_NOMEM:
		PyErr_NoMemory();
		return -1;
	case CIDR_ERR_FAMILY:
		PyErr_SetString(libcidr_FamilyError,
		    context ? context : "address family mismatch");
		return -1;
	case CIDR_ERR_OVERFLOW:
		PyErr_SetString(libcidr_AddressOverflowError,
		    context ? context : "result not representable");
		return -1;
	default:
		PyErr_Format(PyExc_RuntimeError,
		    "unexpected cidr_err_t value: %d", (int)rc);
		return -1;
	}
}
```

Pattern for wrapping a C call:

```c
rc = cidr_addr_parse(src, &addr);
if (cidr_set_python_error(rc, src) < 0)
	return NULL;
```

### 6.5 PyType_FromSpec Slot Patterns

Type definitions use `PyType_FromSpec()` with a slot array. The slots must
be terminated with a `{0, NULL}` sentinel. Required slots for each type:

```c
static PyType_Slot ipv4address_slots[] = {
	{ Py_tp_new,      (void *)ipv4address_new      },
	{ Py_tp_dealloc,  (void *)ipv4address_dealloc   },
	{ Py_tp_richcompare, (void *)ipv4address_richcmp },
	{ Py_tp_hash,     (void *)ipv4address_hash      },
	{ Py_tp_str,      (void *)ipv4address_str       },
	{ Py_tp_repr,     (void *)ipv4address_repr      },
	{ Py_tp_methods,  (void *)ipv4address_methods   },
	{ Py_tp_getset,   (void *)ipv4address_getset    },
	{ Py_tp_doc,      (void *)ipv4address_doc       },
	{ 0, NULL }
};

static PyType_Spec ipv4address_spec = {
	.name      = "libcidr.IPv4Address",
	.basicsize = sizeof(IPv4Address),
	.flags     = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.slots     = ipv4address_slots,
};
```

`tp_dealloc` must call `type->tp_free((PyObject *)self)` as its last action.
It must not call `Py_TYPE(self)->tp_free` -- use the `type` argument for the
call when the type is fixed.

### 6.6 Naming Conventions in the Binding Layer

Python method implementations follow a consistent naming scheme so that
ownership and purpose are unambiguous:

```c
/* Python type structs: named after the Python type */
typedef struct {
	PyObject_HEAD
	cidr_addr_t addr;
} IPv4Address;

/* tp_new slot: TypeName_new */
static PyObject *ipv4address_new(PyTypeObject *, PyObject *, PyObject *);

/* tp_dealloc slot: TypeName_dealloc */
static void ipv4address_dealloc(IPv4Address *);

/* Python method implementations: TypeName_MethodName */
static PyObject *ipv4address_classify(IPv4Address *, PyObject *);
static PyObject *ipv4address_to_ipv4(IPv6Address *, PyObject *);

/* Property getter implementations: TypeName_get_PropertyName */
static PyObject *ipv4address_get_packed(IPv4Address *, void *);
static PyObject *ipv4address_get_compressed(IPv4Address *, void *);

/* Module-level function implementations: libcidr_FunctionName */
static PyObject *libcidr_bulk_parse(PyObject *, PyObject *, PyObject *);
static PyObject *libcidr_bulk_contains(PyObject *, PyObject *, PyObject *);

/* Internal helpers: binding_HelperName */
static int binding_family_from_arg(PyObject *, cidr_family_t *);
static int binding_parse_memoryview(PyObject *, cidr_family_t,
    const uint8_t **, size_t *);
```

Module-level constants are exported in `PyModuleDef.m_methods` and defined
at the top of `_libcidr_ext.c` with the prefix `PYCIDR_`:

```c
#define PYCIDR_AF_INET    4
#define PYCIDR_AF_INET6   6
```

---

## 7. Pre-Commit Checklist

Before every commit:

**C library**
- [ ] Compiles without warnings on Linux (`-Wall -Wextra -Werror`)
- [ ] Compiles without warnings on OpenBSD (`-Wall -Wextra -Werror`)
- [ ] All C tests pass (`make test`)
- [ ] Valgrind clean on Linux (`make valgrind`)
- [ ] ASan/UBSan clean on both platforms (`make dev && make test`)
- [ ] `<stdlib.h>` included only in `src/cidr_index.c`:
      `grep -n "#include <stdlib.h>" src/*.c` -- must show only cidr_index.c
- [ ] Every `malloc` call in `cidr_index.c` checks for NULL return
- [ ] Every allocation failure path returns `CIDR_ERR_NOMEM` or propagates it
- [ ] `goto cleanup` pattern used for all multi-resource acquisition
      in `cidr_index.c`
- [ ] No file-scope mutable variables introduced in any source file
- [ ] All new public functions carry `__attribute__((warn_unused_result))`,
      except destructors
- [ ] `_Static_assert` present for any struct whose size or alignment is
      relied upon by the bulk sort, LC-trie, or classification table
- [ ] `SAFETY:` comment present on every new safety-critical invariant
- [ ] Empty array (`count == 0`) handled before NULL pointer check in all
      bulk functions
- [ ] All new public functions have complete doc comment blocks per §5.1
- [ ] New arithmetic or classification logic has ARCHITECTURE.md
      cross-reference comment per §5.2

**Python extension**
- [ ] Python extension compiles without warnings
      (`make python-ext` with `-Wall -Wextra -Werror`)
- [ ] Python extension suffix contains `abi3`:
      `make python-check-abi` passes
- [ ] All Python tests pass (`make test-python`) against CPython 3.11, 3.12, 3.13
- [ ] No direct `PyTypeObject` struct initialization -- all types use
      `PyType_FromSpec()` with slot arrays
- [ ] Every `goto error` path `Py_XDECREF`s all acquired references
- [ ] Every function that returns NULL has an exception set
- [ ] Every function that returns non-NULL has no exception set
- [ ] `Py_None` returned with `Py_INCREF(Py_None)` before return
- [ ] All `cidr_err_t` to Python exception translation goes through
      `cidr_set_python_error()`, never inline
- [ ] All new Python methods follow the naming conventions in §6.6
- [ ] Extension passes ASan run (`make python-dev && make test-python`)

**Format and lint**
- [ ] `make format` produces no diff
- [ ] `make lint` produces zero clang-tidy and cppcheck warnings

---

**See Also**: PROJECT.md, ARCHITECTURE.md, TECH_STACK.md, DEVELOPMENT.md
