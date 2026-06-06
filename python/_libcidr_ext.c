/*
 * _libcidr_ext.c - CPython binding layer for libcidr.
 *
 * Stable ABI: Py_LIMITED_API = 0x030B0000 (CPython 3.11+).
 * No IP arithmetic logic. Pure translation layer.
 * See ARCHITECTURE.md §8 for the binding specification.
 *
 * Module init: PyInit_libcidr creates the "libcidr" module with:
 *   - Exception hierarchy (ARCHITECTURE.md §8.5)
 *   - Module-level constants (ARCHITECTURE.md §7.2, §8.1)
 *   - cidr_set_python_error() helper (CODING_STANDARDS.md §6.4)
 *   - IPv4Address, IPv6Address types (ARCHITECTURE.md §8.6)
 *
 * Later phases add:
 *   7.3 - IPv4Network, IPv6Network types
 *   7.4 - SubnetIterator type
 *   7.5 - Bulk entry points
 *   7.6 - memoryview entry point
 */

#define Py_LIMITED_API 0x030B0000
#include <Python.h>

#include <stdio.h>
#include <string.h>

#include "../include/libcidr.h"

/* Module-level constants not present in libcidr.h.
 * See ARCHITECTURE.md §8.1. */
#define PYCIDR_AF_INET 4
#define PYCIDR_AF_INET6 6
#define PYCIDR_SORT_NETWORK_ASC 0
#define PYCIDR_SORT_PFXLEN_DESC 1

/*
 * Exception object references.
 * Initialised in PyInit_libcidr and stored here for use by
 * cidr_set_python_error() and type methods in later phases.
 * See ARCHITECTURE.md §8.5 for the exception hierarchy.
 */
static PyObject *libcidr_CIDRError = NULL;
static PyObject *libcidr_ParseError = NULL;
static PyObject *libcidr_HostBitsError = NULL;
static PyObject *libcidr_PrefixLengthError = NULL;
static PyObject *libcidr_InvalidArgumentError = NULL;
static PyObject *libcidr_FamilyError = NULL;
static PyObject *libcidr_AddressOverflowError = NULL;

/* Forward declaration. */
static int cidr_set_python_error(cidr_err_t, const char *);

/*
 * cidr_set_python_error - translate a cidr_err_t to the corresponding
 *                         Python exception.
 *
 * Sets the appropriate Python exception for the given error code.
 * Returns 0 for CIDR_OK (no exception set) and -1 for all error codes
 * (exception set). Designed for the calling pattern:
 *   if (cidr_set_python_error(rc, context) < 0) return NULL;
 *
 * rc:      the cidr_err_t value to translate
 * context: optional context string prepended to the exception message;
 *          may be NULL for a generic message
 *
 * Returns 0 on CIDR_OK, -1 on any error (exception set).
 * See CODING_STANDARDS.md §6.4.
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
		                context ? context
		                        : "prefix length out of range");
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

/* ===================================================================
 * IPv4Address and IPv6Address types.
 * See ARCHITECTURE.md §8.6, CODING_STANDARDS.md §6.
 * =================================================================== */

/* -------------------------------------------------------------------
 * Struct definitions.
 * cidr_addr_t embedded by value in the PyObject allocation.
 * No heap-allocated members to free separately.
 * See ARCHITECTURE.md §8.10.
 * ------------------------------------------------------------------- */

typedef struct {
	PyObject_HEAD cidr_addr_t addr;
} IPv4Address;

typedef struct {
	PyObject_HEAD cidr_addr_t addr;
} IPv6Address;

/* Static type references (initialised in PyInit_libcidr). */
static PyTypeObject *ipv4address_type = NULL;
static PyTypeObject *ipv6address_type = NULL;

/* -------------------------------------------------------------------
 * Helpers.
 * ------------------------------------------------------------------- */

/*
 * ipv6_format_exploded - format an IPv6 address in fully-expanded form
 *                        (all 8 groups with zero-padding, no ::).
 *
 * Writes into buf (must be >= CIDR_ADDR_STR_MAX). Returns 0 on success.
 */
static int
ipv6_format_exploded(const cidr_addr_t *addr, char *buf, size_t len)
{
	const uint8_t *v6 = addr->addr.v6;

	// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
	int n = snprintf(buf, len,
	                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
	                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
	                 v6[0], v6[1], v6[2], v6[3], v6[4], v6[5], v6[6], v6[7],
	                 v6[8], v6[9], v6[10], v6[11], v6[12], v6[13], v6[14],
	                 v6[15]);
	if (n < 0 || (size_t)n >= len)
		return -1;
	return 0;
}

/*
 * binding_string_to_addr - parse an address from a Python str/unicode
 *                          object via cidr_addr_parse and validate the
 *                          family against expected.
 *
 * Returns 0 on success, -1 on error (exception set).
 */
static int
binding_string_to_addr(PyObject *obj, cidr_addr_t *addr, cidr_family_t expected)
{
	PyObject *utf8;
	const char *s;
	cidr_err_t rc;

	utf8 = PyUnicode_AsEncodedString(obj, "utf-8", "strict");
	if (utf8 == NULL)
		return -1;
	s = PyBytes_AsString(utf8);
	if (s == NULL) {
		Py_DECREF(utf8);
		return -1;
	}
	rc = cidr_addr_parse(s, addr);
	Py_DECREF(utf8);
	if (rc != CIDR_OK)
		return cidr_set_python_error(rc, s);
	if (addr->family != expected) {
		PyErr_SetString(libcidr_FamilyError, "address family mismatch");
		return -1;
	}
	return 0;
}

/*
 * binding_bytes_to_addr - copy packed bytes from a Python bytes object
 *                         with length validation.
 *
 * Returns 0 on success, -1 on error (exception set).
 */
static int
binding_bytes_to_addr(PyObject *obj, cidr_addr_t *addr, cidr_family_t expected)
{
	char *buf;
	Py_ssize_t len;
	size_t want = (expected == CIDR_AF_INET) ? 4 : 16;

	if (PyBytes_AsStringAndSize(obj, &buf, &len) < 0)
		return -1;
	if ((size_t)len != want) {
		PyErr_Format(libcidr_InvalidArgumentError,
		             "address requires exactly %zu bytes", want);
		return -1;
	}
	addr->family = expected;
	if (expected == CIDR_AF_INET)
		// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
		memcpy(addr->addr.v4, buf, 4);
	else
		// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
		memcpy(addr->addr.v6, buf, 16);
	return 0;
}

/*
 * binding_int_to_addr - convert a Python int to address bytes via
 *                       int.to_bytes().
 *
 * Returns 0 on success, -1 on error (exception set).
 */
static int
binding_int_to_addr(PyObject *obj, cidr_addr_t *addr, cidr_family_t expected)
{
	PyObject *zero;
	int is_neg;
	PyObject *bytes;
	const char *buf;
	int nbytes;

	zero = PyLong_FromLong(0);
	if (zero == NULL)
		return -1;
	is_neg = PyObject_RichCompareBool(obj, zero, Py_LT);
	Py_DECREF(zero);
	if (is_neg < 0)
		return -1;
	if (is_neg == 1) {
		PyErr_SetString(libcidr_InvalidArgumentError,
		                "address must be non-negative");
		return -1;
	}

	nbytes = (expected == CIDR_AF_INET) ? 4 : 16;
	bytes = PyObject_CallMethod(obj, "to_bytes", "is", nbytes, "big");
	if (bytes == NULL) {
		/* OverflowError from to_bytes is expected for out-of-range. */
		if (PyErr_ExceptionMatches(PyExc_OverflowError)) {
			PyErr_Clear();
			PyErr_Format(libcidr_InvalidArgumentError,
			             "address value out of range for %s",
			             expected == CIDR_AF_INET ? "IPv4"
			                                      : "IPv6");
		}
		return -1;
	}

	buf = PyBytes_AsString(bytes);
	if (buf == NULL) {
		Py_DECREF(bytes);
		return -1;
	}
	addr->family = expected;
	if (expected == CIDR_AF_INET)
		// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
		memcpy(addr->addr.v4, buf, 4);
	else
		// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
		memcpy(addr->addr.v6, buf, 16);
	Py_DECREF(bytes);
	return 0;
}

/*
 * binding_ipaddress_to_addr - extract packed bytes from an ipaddress
 *                             object (stdlib ipaddress module).
 *
 * Returns 0 on success, -1 on error (exception set).
 */
static int
binding_ipaddress_to_addr(PyObject *obj, cidr_addr_t *addr,
                          cidr_family_t expected)
{
	PyObject *packed;
	const char *buf;
	size_t want;

	packed = PyObject_GetAttrString(obj, "packed");
	if (packed == NULL) {
		PyErr_Clear();
		PyErr_Format(PyExc_TypeError,
		             "cannot construct %s from non-ipaddress object",
		             expected == CIDR_AF_INET ? "IPv4Address"
		                                      : "IPv6Address");
		return -1;
	}

	if (!PyBytes_Check(packed)) {
		Py_DECREF(packed);
		PyErr_Format(PyExc_TypeError,
		             "'packed' attribute is not bytes");
		return -1;
	}

	want = (expected == CIDR_AF_INET) ? 4 : 16;
	if ((size_t)PyBytes_Size(packed) != want) {
		Py_DECREF(packed);
		PyErr_SetString(libcidr_FamilyError, "address family mismatch");
		return -1;
	}

	buf = PyBytes_AsString(packed);
	addr->family = expected;
	if (expected == CIDR_AF_INET)
		// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
		memcpy(addr->addr.v4, buf, 4);
	else
		// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
		memcpy(addr->addr.v6, buf, 16);
	Py_DECREF(packed);
	return 0;
}

/* -------------------------------------------------------------------
 * tp_new constructors.
 * Accept: string, packed bytes, integer, ipaddress object.
 * See ARCHITECTURE.md §8.6.1.
 * ------------------------------------------------------------------- */

static PyObject *
ipv4address_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	PyObject *arg;
	cidr_addr_t addr;
	IPv4Address *self;

	(void)kwargs;
	addr.family = CIDR_AF_UNSPEC;

	if (!PyArg_ParseTuple(args, "O", &arg))
		return NULL;

	if (PyUnicode_Check(arg)) {
		if (binding_string_to_addr(arg, &addr, CIDR_AF_INET) < 0)
			return NULL;
	} else if (PyBytes_Check(arg)) {
		if (binding_bytes_to_addr(arg, &addr, CIDR_AF_INET) < 0)
			return NULL;
	} else if (PyLong_Check(arg)) {
		if (binding_int_to_addr(arg, &addr, CIDR_AF_INET) < 0)
			return NULL;
	} else {
		if (binding_ipaddress_to_addr(arg, &addr, CIDR_AF_INET) < 0)
			return NULL;
	}

	self = (IPv4Address *)PyType_GenericNew(type, NULL, NULL);
	if (self == NULL)
		return NULL;
	// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
	memcpy(&self->addr, &addr, sizeof(cidr_addr_t));
	return (PyObject *)self;
}

static PyObject *
ipv6address_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	PyObject *arg;
	cidr_addr_t addr;
	IPv6Address *self;

	(void)kwargs;
	addr.family = CIDR_AF_UNSPEC;

	if (!PyArg_ParseTuple(args, "O", &arg))
		return NULL;

	if (PyUnicode_Check(arg)) {
		if (binding_string_to_addr(arg, &addr, CIDR_AF_INET6) < 0)
			return NULL;
	} else if (PyBytes_Check(arg)) {
		if (binding_bytes_to_addr(arg, &addr, CIDR_AF_INET6) < 0)
			return NULL;
	} else if (PyLong_Check(arg)) {
		if (binding_int_to_addr(arg, &addr, CIDR_AF_INET6) < 0)
			return NULL;
	} else {
		if (binding_ipaddress_to_addr(arg, &addr, CIDR_AF_INET6) < 0)
			return NULL;
	}

	self = (IPv6Address *)PyType_GenericNew(type, NULL, NULL);
	if (self == NULL)
		return NULL;
	// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
	memcpy(&self->addr, &addr, sizeof(cidr_addr_t));
	return (PyObject *)self;
}

/* -------------------------------------------------------------------
 * tp_dealloc.
 * No heap-allocated members to free; just the base object dealloc.
 * See ARCHITECTURE.md §8.10.
 * ------------------------------------------------------------------- */

static void
ipv4address_dealloc(PyObject *self)
{
	PyObject_Del(self);
}

static void
ipv6address_dealloc(PyObject *self)
{
	PyObject_Del(self);
}

/* -------------------------------------------------------------------
 * Property getters.
 * All properties are read-only per ARCHITECTURE.md §8.6.2.
 * ------------------------------------------------------------------- */

static PyObject *
ipv4address_get_packed(PyObject *self, void *closure)
{
	IPv4Address *a = (IPv4Address *)self;

	(void)closure;
	return PyBytes_FromStringAndSize((const char *)a->addr.addr.v4, 4);
}

static PyObject *
ipv6address_get_packed(PyObject *self, void *closure)
{
	IPv6Address *a = (IPv6Address *)self;

	(void)closure;
	return PyBytes_FromStringAndSize((const char *)a->addr.addr.v6, 16);
}

static PyObject *
ipv4address_get_compressed(PyObject *self, void *closure)
{
	IPv4Address *a = (IPv4Address *)self;
	char buf[CIDR_ADDR_STR_MAX];
	cidr_err_t rc;

	(void)closure;
	rc = cidr_addr_format(&a->addr, buf, sizeof(buf));
	if (rc != CIDR_OK) {
		cidr_set_python_error(rc, NULL);
		return NULL;
	}
	return PyUnicode_FromString(buf);
}

static PyObject *
ipv6address_get_compressed(PyObject *self, void *closure)
{
	IPv6Address *a = (IPv6Address *)self;
	char buf[CIDR_ADDR_STR_MAX];
	cidr_err_t rc;

	(void)closure;
	rc = cidr_addr_format(&a->addr, buf, sizeof(buf));
	if (rc != CIDR_OK) {
		cidr_set_python_error(rc, NULL);
		return NULL;
	}
	return PyUnicode_FromString(buf);
}

static PyObject *
ipv4address_get_exploded(PyObject *self, void *closure)
{
	(void)closure;
	return ipv4address_get_compressed(self, NULL);
}

static PyObject *
ipv6address_get_exploded(PyObject *self, void *closure)
{
	IPv6Address *a = (IPv6Address *)self;
	char buf[CIDR_ADDR_STR_MAX];

	(void)closure;
	if (ipv6_format_exploded(&a->addr, buf, sizeof(buf)) < 0) {
		PyErr_SetString(PyExc_RuntimeError,
		                "failed to format expanded IPv6 address");
		return NULL;
	}
	return PyUnicode_FromString(buf);
}

static PyObject *
ipv4address_get_version(PyObject *self, void *closure)
{
	(void)self;
	(void)closure;
	return PyLong_FromLong(4);
}

static PyObject *
ipv6address_get_version(PyObject *self, void *closure)
{
	(void)self;
	(void)closure;
	return PyLong_FromLong(6);
}

/* Address classification helper. */
static int
addr_classify_impl(const cidr_addr_t *addr, cidr_class_t *cls)
{
	cidr_err_t rc;

	rc = cidr_addr_classify(addr, cls);
	if (rc != CIDR_OK) {
		cidr_set_python_error(rc, NULL);
		return -1;
	}
	return 0;
}

/*
 * Classification-based property helpers.
 * Each checks the appropriate CIDR_CLASS_* flag.
 * See ARCHITECTURE.md §7.2 for flag semantics.
 */
static PyObject *
addr_is_global_impl(const cidr_addr_t *addr)
{
	cidr_class_t cls;

	if (addr_classify_impl(addr, &cls) < 0)
		return NULL;
	if (cls & CIDR_CLASS_GLOBAL) {
		Py_INCREF(Py_True);
		return Py_True;
	}
	Py_INCREF(Py_False);
	return Py_False;
}

static PyObject *
addr_is_private_impl(const cidr_addr_t *addr)
{
	cidr_class_t cls;

	if (addr_classify_impl(addr, &cls) < 0)
		return NULL;
	if (cls & CIDR_CLASS_PRIVATE) {
		Py_INCREF(Py_True);
		return Py_True;
	}
	Py_INCREF(Py_False);
	return Py_False;
}

static PyObject *
addr_is_loopback_impl(const cidr_addr_t *addr)
{
	cidr_class_t cls;

	if (addr_classify_impl(addr, &cls) < 0)
		return NULL;
	if (cls & CIDR_CLASS_LOOPBACK) {
		Py_INCREF(Py_True);
		return Py_True;
	}
	Py_INCREF(Py_False);
	return Py_False;
}

static PyObject *
addr_is_multicast_impl(const cidr_addr_t *addr)
{
	cidr_class_t cls;

	if (addr_classify_impl(addr, &cls) < 0)
		return NULL;
	if (cls & CIDR_CLASS_MULTICAST) {
		Py_INCREF(Py_True);
		return Py_True;
	}
	Py_INCREF(Py_False);
	return Py_False;
}

static PyObject *
addr_is_link_local_impl(const cidr_addr_t *addr)
{
	cidr_class_t cls;

	if (addr_classify_impl(addr, &cls) < 0)
		return NULL;
	if (cls & CIDR_CLASS_LINK_LOCAL) {
		Py_INCREF(Py_True);
		return Py_True;
	}
	Py_INCREF(Py_False);
	return Py_False;
}

static PyObject *
addr_is_unspecified_impl(const cidr_addr_t *addr)
{
	cidr_class_t cls;

	if (addr_classify_impl(addr, &cls) < 0)
		return NULL;
	if (cls & CIDR_CLASS_UNSPECIFIED) {
		Py_INCREF(Py_True);
		return Py_True;
	}
	Py_INCREF(Py_False);
	return Py_False;
}

static PyObject *
ipv4address_get_is_global(PyObject *self, void *closure)
{
	(void)closure;
	return addr_is_global_impl(&((IPv4Address *)self)->addr);
}

static PyObject *
ipv6address_get_is_global(PyObject *self, void *closure)
{
	(void)closure;
	return addr_is_global_impl(&((IPv6Address *)self)->addr);
}

static PyObject *
ipv4address_get_is_private(PyObject *self, void *closure)
{
	(void)closure;
	return addr_is_private_impl(&((IPv4Address *)self)->addr);
}

static PyObject *
ipv6address_get_is_private(PyObject *self, void *closure)
{
	(void)closure;
	return addr_is_private_impl(&((IPv6Address *)self)->addr);
}

static PyObject *
ipv4address_get_is_loopback(PyObject *self, void *closure)
{
	(void)closure;
	return addr_is_loopback_impl(&((IPv4Address *)self)->addr);
}

static PyObject *
ipv6address_get_is_loopback(PyObject *self, void *closure)
{
	(void)closure;
	return addr_is_loopback_impl(&((IPv6Address *)self)->addr);
}

static PyObject *
ipv4address_get_is_multicast(PyObject *self, void *closure)
{
	(void)closure;
	return addr_is_multicast_impl(&((IPv4Address *)self)->addr);
}

static PyObject *
ipv6address_get_is_multicast(PyObject *self, void *closure)
{
	(void)closure;
	return addr_is_multicast_impl(&((IPv6Address *)self)->addr);
}

static PyObject *
ipv4address_get_is_link_local(PyObject *self, void *closure)
{
	(void)closure;
	return addr_is_link_local_impl(&((IPv4Address *)self)->addr);
}

static PyObject *
ipv6address_get_is_link_local(PyObject *self, void *closure)
{
	(void)closure;
	return addr_is_link_local_impl(&((IPv6Address *)self)->addr);
}

/*
 * IPv4 is_unspecified always returns False per ARCHITECTURE.md §8.6.2.
 */
static PyObject *
ipv4address_get_is_unspecified(PyObject *self, void *closure)
{
	(void)self;
	(void)closure;
	Py_INCREF(Py_False);
	return Py_False;
}

static PyObject *
ipv6address_get_is_unspecified(PyObject *self, void *closure)
{
	(void)closure;
	return addr_is_unspecified_impl(&((IPv6Address *)self)->addr);
}

/* -------------------------------------------------------------------
 * Methods.
 * ------------------------------------------------------------------- */

/*
 * classify() -> int
 *
 * Returns the raw cidr_class_t bitmask. See ARCHITECTURE.md §8.6.3.
 */
static PyObject *
ipv4address_classify(PyObject *self, PyObject *noargs)
{
	cidr_class_t cls;

	(void)noargs;
	if (addr_classify_impl(&((IPv4Address *)self)->addr, &cls) < 0)
		return NULL;
	return PyLong_FromUnsignedLong((unsigned long)cls);
}

static PyObject *
ipv6address_classify(PyObject *self, PyObject *noargs)
{
	cidr_class_t cls;

	(void)noargs;
	if (addr_classify_impl(&((IPv6Address *)self)->addr, &cls) < 0)
		return NULL;
	return PyLong_FromUnsignedLong((unsigned long)cls);
}

/*
 * to_ipv4() -> IPv4Address | None   (IPv6Address only)
 *
 * Extracts embedded IPv4 from an IPv4-mapped IPv6 address.
 * Returns None for non-mapped addresses. See ARCHITECTURE.md §8.6.3.
 */
static PyObject *
ipv6address_to_ipv4(PyObject *self, PyObject *noargs)
{
	IPv6Address *a = (IPv6Address *)self;
	cidr_addr_t v4addr;
	cidr_err_t rc;
	PyObject *packed;
	PyObject *result;

	(void)noargs;
	rc = cidr_addr_to_v4(&a->addr, &v4addr);
	if (rc == CIDR_ERR_FAMILY) {
		Py_INCREF(Py_None);
		return Py_None;
	}
	if (rc != CIDR_OK) {
		cidr_set_python_error(rc, NULL);
		return NULL;
	}

	packed = PyBytes_FromStringAndSize((const char *)v4addr.addr.v4, 4);
	if (packed == NULL)
		return NULL;
	result = PyObject_CallFunctionObjArgs((PyObject *)ipv4address_type,
	                                      packed, NULL);
	Py_DECREF(packed);
	return result;
}

/* -------------------------------------------------------------------
 * Protocol: __str__, __repr__, __hash__.
 * See ARCHITECTURE.md §8.6.4.
 * ------------------------------------------------------------------- */

static PyObject *
ipv4address_str(PyObject *self)
{
	IPv4Address *a = (IPv4Address *)self;
	char buf[CIDR_ADDR_STR_MAX];
	cidr_err_t rc;

	rc = cidr_addr_format(&a->addr, buf, sizeof(buf));
	if (rc != CIDR_OK) {
		cidr_set_python_error(rc, NULL);
		return NULL;
	}
	return PyUnicode_FromString(buf);
}

static PyObject *
ipv6address_str(PyObject *self)
{
	IPv6Address *a = (IPv6Address *)self;
	char buf[CIDR_ADDR_STR_MAX];
	cidr_err_t rc;

	rc = cidr_addr_format(&a->addr, buf, sizeof(buf));
	if (rc != CIDR_OK) {
		cidr_set_python_error(rc, NULL);
		return NULL;
	}
	return PyUnicode_FromString(buf);
}

static PyObject *
ipv4address_repr(PyObject *self)
{
	IPv4Address *a = (IPv4Address *)self;
	char buf[CIDR_ADDR_STR_MAX];
	cidr_err_t rc;

	rc = cidr_addr_format(&a->addr, buf, sizeof(buf));
	if (rc != CIDR_OK) {
		cidr_set_python_error(rc, NULL);
		return NULL;
	}
	return PyUnicode_FromFormat("IPv4Address('%s')", buf);
}

static PyObject *
ipv6address_repr(PyObject *self)
{
	IPv6Address *a = (IPv6Address *)self;
	char buf[CIDR_ADDR_STR_MAX];
	cidr_err_t rc;

	rc = cidr_addr_format(&a->addr, buf, sizeof(buf));
	if (rc != CIDR_OK) {
		cidr_set_python_error(rc, NULL);
		return NULL;
	}
	return PyUnicode_FromFormat("IPv6Address('%s')", buf);
}

/* djb2-derived hash of family + address bytes. */
static Py_hash_t
ipv4address_hash(PyObject *self)
{
	IPv4Address *a = (IPv4Address *)self;
	const uint8_t *v4 = a->addr.addr.v4;
	Py_hash_t h = 5381;

	/*
	 * SAFETY: family is guaranteed to be CIDR_AF_INET for a valid
	 * IPv4Address instance. No hash state is shared with IPv6.
	 */
	h = ((h << 5) + h) + (Py_hash_t)a->addr.family;
	for (int i = 0; i < 4; i++)
		h = ((h << 5) + h) + (Py_hash_t)v4[i];
	return h;
}

static Py_hash_t
ipv6address_hash(PyObject *self)
{
	IPv6Address *a = (IPv6Address *)self;
	const uint8_t *v6 = a->addr.addr.v6;
	Py_hash_t h = 5381;

	/*
	 * SAFETY: family is guaranteed to be CIDR_AF_INET6 for a valid
	 * IPv6Address instance. No hash state is shared with IPv4.
	 */
	h = ((h << 5) + h) + (Py_hash_t)a->addr.family;
	for (int i = 0; i < 16; i++)
		h = ((h << 5) + h) + (Py_hash_t)v6[i];
	return h;
}

/* -------------------------------------------------------------------
 * Rich comparison: __eq__, __ne__, __lt__, __le__, __gt__, __ge__.
 * See ARCHITECTURE.md §8.6.4.
 * ------------------------------------------------------------------- */

/*
 * Address comparison implementation (same-family only).
 * Returns -1, 0, or +1 via memcmp of address bytes.
 */
static cidr_err_t
addr_cmp_bytes(const uint8_t *a, const uint8_t *b, size_t len, int *result)
{
	int cmp = memcmp(a, b, len);
	*result = (cmp < 0) ? -1 : (cmp > 0) ? 1 : 0;
	return CIDR_OK;
}

static PyObject *
ipv4address_richcmp(PyObject *a, PyObject *b, int op)
{
	PyObject *result;
	int cmp;

	if (!PyObject_TypeCheck(b, ipv4address_type)) {
		if (PyObject_TypeCheck(b, ipv6address_type)) {
			/* Cross-family: IPv4 vs IPv6. */
			cidr_set_python_error(CIDR_ERR_FAMILY, NULL);
			return NULL;
		}
		Py_RETURN_NOTIMPLEMENTED;
	}

	(void)addr_cmp_bytes(((IPv4Address *)a)->addr.addr.v4,
	                     ((IPv4Address *)b)->addr.addr.v4, 4, &cmp);

	switch (op) {
	case Py_EQ:
		result = (cmp == 0) ? Py_True : Py_False;
		break;
	case Py_NE:
		result = (cmp != 0) ? Py_True : Py_False;
		break;
	case Py_LT:
		result = (cmp < 0) ? Py_True : Py_False;
		break;
	case Py_LE:
		result = (cmp <= 0) ? Py_True : Py_False;
		break;
	case Py_GT:
		result = (cmp > 0) ? Py_True : Py_False;
		break;
	case Py_GE:
		result = (cmp >= 0) ? Py_True : Py_False;
		break;
	default:
		Py_RETURN_NOTIMPLEMENTED;
	}
	Py_INCREF(result);
	return result;
}

static PyObject *
ipv6address_richcmp(PyObject *a, PyObject *b, int op)
{
	PyObject *result;
	int cmp;

	if (!PyObject_TypeCheck(b, ipv6address_type)) {
		if (PyObject_TypeCheck(b, ipv4address_type)) {
			/* Cross-family: IPv6 vs IPv4. */
			cidr_set_python_error(CIDR_ERR_FAMILY, NULL);
			return NULL;
		}
		Py_RETURN_NOTIMPLEMENTED;
	}

	(void)addr_cmp_bytes(((IPv6Address *)a)->addr.addr.v6,
	                     ((IPv6Address *)b)->addr.addr.v6, 16, &cmp);

	switch (op) {
	case Py_EQ:
		result = (cmp == 0) ? Py_True : Py_False;
		break;
	case Py_NE:
		result = (cmp != 0) ? Py_True : Py_False;
		break;
	case Py_LT:
		result = (cmp < 0) ? Py_True : Py_False;
		break;
	case Py_LE:
		result = (cmp <= 0) ? Py_True : Py_False;
		break;
	case Py_GT:
		result = (cmp > 0) ? Py_True : Py_False;
		break;
	case Py_GE:
		result = (cmp >= 0) ? Py_True : Py_False;
		break;
	default:
		Py_RETURN_NOTIMPLEMENTED;
	}
	Py_INCREF(result);
	return result;
}

/* -------------------------------------------------------------------
 * PyGetSetDef tables.
 * ------------------------------------------------------------------- */

static PyGetSetDef ipv4address_getset[] = {
    {"packed", ipv4address_get_packed, NULL, "raw address bytes (4 bytes)",
     NULL},
    {"compressed", ipv4address_get_compressed, NULL, "canonical string form",
     NULL},
    {"exploded", ipv4address_get_exploded, NULL,
     "exploded string form (same as compressed for IPv4)", NULL},
    {"version", ipv4address_get_version, NULL, "address family version (4)",
     NULL},
    {"is_global", ipv4address_get_is_global, NULL,
     "whether the address is globally reachable", NULL},
    {"is_private", ipv4address_get_is_private, NULL,
     "whether the address is private (RFC 1918)", NULL},
    {"is_loopback", ipv4address_get_is_loopback, NULL,
     "whether the address is a loopback address", NULL},
    {"is_multicast", ipv4address_get_is_multicast, NULL,
     "whether the address is a multicast address", NULL},
    {"is_link_local", ipv4address_get_is_link_local, NULL,
     "whether the address is link-local", NULL},
    {"is_unspecified", ipv4address_get_is_unspecified, NULL,
     "whether the address is unspecified (always False)", NULL},
    {NULL, NULL, NULL, NULL, NULL}};

static PyGetSetDef ipv6address_getset[] = {
    {"packed", ipv6address_get_packed, NULL, "raw address bytes (16 bytes)",
     NULL},
    {"compressed", ipv6address_get_compressed, NULL,
     "canonical string form (RFC 5952)", NULL},
    {"exploded", ipv6address_get_exploded, NULL,
     "fully-expanded string form (all 8 groups)", NULL},
    {"version", ipv6address_get_version, NULL, "address family version (6)",
     NULL},
    {"is_global", ipv6address_get_is_global, NULL,
     "whether the address is globally reachable", NULL},
    {"is_private", ipv6address_get_is_private, NULL,
     "whether the address is unique-local (RFC 4193)", NULL},
    {"is_loopback", ipv6address_get_is_loopback, NULL,
     "whether the address is the loopback address (::1)", NULL},
    {"is_multicast", ipv6address_get_is_multicast, NULL,
     "whether the address is a multicast address", NULL},
    {"is_link_local", ipv6address_get_is_link_local, NULL,
     "whether the address is link-local (fe80::/10)", NULL},
    {"is_unspecified", ipv6address_get_is_unspecified, NULL,
     "whether the address is unspecified (::)", NULL},
    {NULL, NULL, NULL, NULL, NULL}};

/* -------------------------------------------------------------------
 * PyMethodDef tables.
 * ------------------------------------------------------------------- */

static PyMethodDef ipv4address_methods[] = {
    {"classify", ipv4address_classify, METH_NOARGS,
     "classify() -> int\n\n"
     "Return the IANA classification bitmask."},
    {NULL, NULL, 0, NULL}};

static PyMethodDef ipv6address_methods[] = {
    {"classify", ipv6address_classify, METH_NOARGS,
     "classify() -> int\n\n"
     "Return the IANA classification bitmask."},
    {"to_ipv4", ipv6address_to_ipv4, METH_NOARGS,
     "to_ipv4() -> IPv4Address | None\n\n"
     "Extract embedded IPv4 address from an IPv4-mapped IPv6 "
     "address. Returns None if the address is not IPv4-mapped."},
    {NULL, NULL, 0, NULL}};

/* -------------------------------------------------------------------
 * PyType_Slot arrays and PyType_Spec definitions.
 * ------------------------------------------------------------------- */

static PyType_Slot ipv4address_slots[] = {
    {Py_tp_new, (void *)ipv4address_new},
    {Py_tp_dealloc, (void *)ipv4address_dealloc},
    {Py_tp_richcompare, (void *)ipv4address_richcmp},
    {Py_tp_hash, (void *)ipv4address_hash},
    {Py_tp_str, (void *)ipv4address_str},
    {Py_tp_repr, (void *)ipv4address_repr},
    {Py_tp_methods, (void *)ipv4address_methods},
    {Py_tp_getset, (void *)ipv4address_getset},
    {Py_tp_doc, (void *)"IPv4 address representation."},
    {0, NULL}};

static PyType_Slot ipv6address_slots[] = {
    {Py_tp_new, (void *)ipv6address_new},
    {Py_tp_dealloc, (void *)ipv6address_dealloc},
    {Py_tp_richcompare, (void *)ipv6address_richcmp},
    {Py_tp_hash, (void *)ipv6address_hash},
    {Py_tp_str, (void *)ipv6address_str},
    {Py_tp_repr, (void *)ipv6address_repr},
    {Py_tp_methods, (void *)ipv6address_methods},
    {Py_tp_getset, (void *)ipv6address_getset},
    {Py_tp_doc, (void *)"IPv6 address representation."},
    {0, NULL}};

static PyType_Spec ipv4address_spec = {"libcidr.IPv4Address",
                                       sizeof(IPv4Address), 0,
                                       Py_TPFLAGS_DEFAULT, ipv4address_slots};

static PyType_Spec ipv6address_spec = {"libcidr.IPv6Address",
                                       sizeof(IPv6Address), 0,
                                       Py_TPFLAGS_DEFAULT, ipv6address_slots};

/*
 * Module method table.
 * Populated in later phases as module-level functions are added:
 *   7.5 - bulk_parse, bulk_contains, bulk_aggregate, bulk_sort
 *   7.6 - bulk_contains_packed
 */
static PyMethodDef libcidr_methods[] = {{NULL, NULL, 0, NULL}};

static struct PyModuleDef libcidr_module = {
    PyModuleDef_HEAD_INIT,
    "libcidr",
    "IPv4/IPv6 address arithmetic and CIDR manipulation",
    -1, /* m_size: per-module state (none) */
    libcidr_methods,
    NULL, /* m_slots */
    NULL, /* m_traverse */
    NULL, /* m_clear */
    NULL  /* m_free */
};

PyMODINIT_FUNC
PyInit_libcidr(void)
{
	PyObject *m = PyModule_Create(&libcidr_module);
	PyObject *bases;
	PyObject *exc;

	if (m == NULL)
		return NULL;

	/*
	 * Exception hierarchy.
	 *
	 * Each custom exception inherits from CIDRError and a matching
	 * stdlib built-in so that callers can catch at either level.
	 * Base tuple ordering: (CIDRError, Builtin) per ARCHITECTURE.md
	 * §8.5. CIDRError must be first so that "except CIDRError" catches
	 * all libcidr exceptions correctly.
	 */

	/* CIDRError(Exception) -- base, not raised directly. */
	exc = PyErr_NewExceptionWithDoc(
	    "libcidr.CIDRError", "Base exception for all libcidr errors.",
	    PyExc_Exception, NULL);
	if (exc == NULL)
		goto error;
	if (PyModule_AddObject(m, "CIDRError", exc) < 0)
		goto error;
	libcidr_CIDRError = exc;
	Py_INCREF(libcidr_CIDRError);

	/* ParseError(CIDRError, ValueError) -- maps from CIDR_ERR_PARSE. */
	bases = PyTuple_Pack(2, libcidr_CIDRError, PyExc_ValueError);
	if (bases == NULL)
		goto error;
	exc = PyErr_NewExceptionWithDoc(
	    "libcidr.ParseError",
	    "Raised when an address or prefix string does not parse per "
	    "the applicable RFC.",
	    bases, NULL);
	Py_DECREF(bases);
	if (exc == NULL)
		goto error;
	if (PyModule_AddObject(m, "ParseError", exc) < 0)
		goto error;
	libcidr_ParseError = exc;
	Py_INCREF(libcidr_ParseError);

	/*
	 * HostBitsError(CIDRError, ValueError) -- maps from
	 * CIDR_ERR_HOSTBITS.
	 */
	bases = PyTuple_Pack(2, libcidr_CIDRError, PyExc_ValueError);
	if (bases == NULL)
		goto error;
	exc = PyErr_NewExceptionWithDoc(
	    "libcidr.HostBitsError",
	    "Raised when host bits are set in a strict prefix parse.", bases,
	    NULL);
	Py_DECREF(bases);
	if (exc == NULL)
		goto error;
	if (PyModule_AddObject(m, "HostBitsError", exc) < 0)
		goto error;
	libcidr_HostBitsError = exc;
	Py_INCREF(libcidr_HostBitsError);

	/*
	 * PrefixLengthError(CIDRError, ValueError) -- maps from
	 * CIDR_ERR_PFXLEN.
	 */
	bases = PyTuple_Pack(2, libcidr_CIDRError, PyExc_ValueError);
	if (bases == NULL)
		goto error;
	exc = PyErr_NewExceptionWithDoc(
	    "libcidr.PrefixLengthError",
	    "Raised when a prefix length is outside the valid range for "
	    "the address family.",
	    bases, NULL);
	Py_DECREF(bases);
	if (exc == NULL)
		goto error;
	if (PyModule_AddObject(m, "PrefixLengthError", exc) < 0)
		goto error;
	libcidr_PrefixLengthError = exc;
	Py_INCREF(libcidr_PrefixLengthError);

	/*
	 * InvalidArgumentError(CIDRError, ValueError) -- maps from
	 * CIDR_ERR_INVAL.
	 */
	bases = PyTuple_Pack(2, libcidr_CIDRError, PyExc_ValueError);
	if (bases == NULL)
		goto error;
	exc = PyErr_NewExceptionWithDoc(
	    "libcidr.InvalidArgumentError",
	    "Raised when an invalid argument is passed (NULL pointer, "
	    "buffer too small, etc.).",
	    bases, NULL);
	Py_DECREF(bases);
	if (exc == NULL)
		goto error;
	if (PyModule_AddObject(m, "InvalidArgumentError", exc) < 0)
		goto error;
	libcidr_InvalidArgumentError = exc;
	Py_INCREF(libcidr_InvalidArgumentError);

	/*
	 * FamilyError(CIDRError, TypeError) -- maps from CIDR_ERR_FAMILY.
	 * Subclasses TypeError rather than ValueError to match the
	 * semantic of "you used the wrong type of address."
	 * See ARCHITECTURE.md §8.5.
	 */
	bases = PyTuple_Pack(2, libcidr_CIDRError, PyExc_TypeError);
	if (bases == NULL)
		goto error;
	exc = PyErr_NewExceptionWithDoc(
	    "libcidr.FamilyError",
	    "Raised when an address family mismatch is detected "
	    "(IPv4 vs IPv6).",
	    bases, NULL);
	Py_DECREF(bases);
	if (exc == NULL)
		goto error;
	if (PyModule_AddObject(m, "FamilyError", exc) < 0)
		goto error;
	libcidr_FamilyError = exc;
	Py_INCREF(libcidr_FamilyError);

	/*
	 * AddressOverflowError(CIDRError, OverflowError) -- maps from
	 * CIDR_ERR_OVERFLOW. Subclasses OverflowError to signal that
	 * the result is not representable.
	 * See ARCHITECTURE.md §8.5.
	 */
	bases = PyTuple_Pack(2, libcidr_CIDRError, PyExc_OverflowError);
	if (bases == NULL)
		goto error;
	exc = PyErr_NewExceptionWithDoc(
	    "libcidr.AddressOverflowError",
	    "Raised when a result is not representable "
	    "(e.g. supernet of /0).",
	    bases, NULL);
	Py_DECREF(bases);
	if (exc == NULL)
		goto error;
	if (PyModule_AddObject(m, "AddressOverflowError", exc) < 0)
		goto error;
	libcidr_AddressOverflowError = exc;
	Py_INCREF(libcidr_AddressOverflowError);

	/* --- Module-level constants --- */

	/*
	 * Address family constants matching cidr_family_t values.
	 * See ARCHITECTURE.md §8.1.
	 */
	if (PyModule_AddIntConstant(m, "AF_INET", PYCIDR_AF_INET) < 0)
		goto error;
	if (PyModule_AddIntConstant(m, "AF_INET6", PYCIDR_AF_INET6) < 0)
		goto error;

	/* Sort order constants matching cidr_sort_order_t values. */
	if (PyModule_AddIntConstant(m, "SORT_NETWORK_ASC",
	                            PYCIDR_SORT_NETWORK_ASC) < 0)
		goto error;
	if (PyModule_AddIntConstant(m, "SORT_PFXLEN_DESC",
	                            PYCIDR_SORT_PFXLEN_DESC) < 0)
		goto error;

	/*
	 * IANA snapshot date. See ARCHITECTURE.md §7.2.
	 */
	if (PyModule_AddIntConstant(m, "CIDR_IANA_SNAPSHOT",
	                            CIDR_IANA_SNAPSHOT) < 0)
		goto error;

	/*
	 * CIDR_CLASS_* classification flags matching the C constants in
	 * libcidr.h. See ARCHITECTURE.md §7.2.
	 */
	if (PyModule_AddIntConstant(m, "CIDR_CLASS_GLOBAL", CIDR_CLASS_GLOBAL) <
	    0)
		goto error;
	if (PyModule_AddIntConstant(m, "CIDR_CLASS_THIS_HOST",
	                            CIDR_CLASS_THIS_HOST) < 0)
		goto error;
	if (PyModule_AddIntConstant(m, "CIDR_CLASS_PRIVATE",
	                            CIDR_CLASS_PRIVATE) < 0)
		goto error;
	if (PyModule_AddIntConstant(m, "CIDR_CLASS_SHARED", CIDR_CLASS_SHARED) <
	    0)
		goto error;
	if (PyModule_AddIntConstant(m, "CIDR_CLASS_LOOPBACK",
	                            CIDR_CLASS_LOOPBACK) < 0)
		goto error;
	if (PyModule_AddIntConstant(m, "CIDR_CLASS_LINK_LOCAL",
	                            CIDR_CLASS_LINK_LOCAL) < 0)
		goto error;
	if (PyModule_AddIntConstant(m, "CIDR_CLASS_IETF_RESERVED",
	                            CIDR_CLASS_IETF_RESERVED) < 0)
		goto error;
	if (PyModule_AddIntConstant(m, "CIDR_CLASS_DOCUMENTATION",
	                            CIDR_CLASS_DOCUMENTATION) < 0)
		goto error;
	if (PyModule_AddIntConstant(m, "CIDR_CLASS_6TO4_RELAY",
	                            CIDR_CLASS_6TO4_RELAY) < 0)
		goto error;
	if (PyModule_AddIntConstant(m, "CIDR_CLASS_BENCHMARKING",
	                            CIDR_CLASS_BENCHMARKING) < 0)
		goto error;
	if (PyModule_AddIntConstant(m, "CIDR_CLASS_RESERVED",
	                            CIDR_CLASS_RESERVED) < 0)
		goto error;
	if (PyModule_AddIntConstant(m, "CIDR_CLASS_BROADCAST",
	                            CIDR_CLASS_BROADCAST) < 0)
		goto error;
	if (PyModule_AddIntConstant(m, "CIDR_CLASS_UNSPECIFIED",
	                            CIDR_CLASS_UNSPECIFIED) < 0)
		goto error;
	if (PyModule_AddIntConstant(m, "CIDR_CLASS_V4MAPPED",
	                            CIDR_CLASS_V4MAPPED) < 0)
		goto error;
	if (PyModule_AddIntConstant(m, "CIDR_CLASS_V4TRANSLATED",
	                            CIDR_CLASS_V4TRANSLATED) < 0)
		goto error;
	if (PyModule_AddIntConstant(m, "CIDR_CLASS_DISCARD",
	                            CIDR_CLASS_DISCARD) < 0)
		goto error;
	if (PyModule_AddIntConstant(m, "CIDR_CLASS_UNIQUE_LOCAL",
	                            CIDR_CLASS_UNIQUE_LOCAL) < 0)
		goto error;
	if (PyModule_AddIntConstant(m, "CIDR_CLASS_MULTICAST",
	                            CIDR_CLASS_MULTICAST) < 0)
		goto error;
	if (PyModule_AddIntConstant(m, "CIDR_CLASS_ANYCAST",
	                            CIDR_CLASS_ANYCAST) < 0)
		goto error;
	if (PyModule_AddIntConstant(m, "CIDR_CLASS_TEREDO", CIDR_CLASS_TEREDO) <
	    0)
		goto error;
	if (PyModule_AddIntConstant(m, "CIDR_CLASS_6TO4", CIDR_CLASS_6TO4) < 0)
		goto error;
	if (PyModule_AddIntConstant(m, "CIDR_CLASS_ORCHID", CIDR_CLASS_ORCHID) <
	    0)
		goto error;
	if (PyModule_AddIntConstant(m, "CIDR_CLASS_SRV6", CIDR_CLASS_SRV6) < 0)
		goto error;

	/* --- Type registration: IPv4Address, IPv6Address --- */

	{
		PyObject *v4type = PyType_FromSpec(&ipv4address_spec);

		if (v4type == NULL)
			goto error;
		ipv4address_type = (PyTypeObject *)v4type;
		Py_INCREF(v4type);
		if (PyModule_AddObject(m, "IPv4Address", v4type) < 0)
			goto error;
	}
	{
		PyObject *v6type = PyType_FromSpec(&ipv6address_spec);

		if (v6type == NULL)
			goto error;
		ipv6address_type = (PyTypeObject *)v6type;
		Py_INCREF(v6type);
		if (PyModule_AddObject(m, "IPv6Address", v6type) < 0)
			goto error;
	}

	return m;

error:
	Py_XDECREF((PyObject *)ipv4address_type);
	ipv4address_type = NULL;
	Py_XDECREF((PyObject *)ipv6address_type);
	ipv6address_type = NULL;
	Py_DECREF(m);
	return NULL;
}
