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
 *   7.6 - memoryview entry point
 */

#define Py_LIMITED_API 0x030B0000
#include <Python.h>

#include <stdio.h>
#include <stdlib.h>
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
static PyTypeObject *ipv4network_type = NULL;
static PyTypeObject *ipv6network_type = NULL;
static PyTypeObject *subnetiterator_type = NULL;

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

/* ===================================================================
 * IPv4Network and IPv6Network types.
 * See ARCHITECTURE.md §8.7, CODING_STANDARDS.md §6.
 * =================================================================== */

/* -------------------------------------------------------------------
 * Struct definitions.
 * cidr_prefix_t embedded by value in the PyObject allocation.
 * No heap-allocated members to free separately.
 * See ARCHITECTURE.md §8.10.
 * ------------------------------------------------------------------- */

typedef struct {
	PyObject_HEAD cidr_prefix_t prefix;
} IPv4Network;

typedef struct {
	PyObject_HEAD cidr_prefix_t prefix;
} IPv6Network;

/*
 * SubnetIterator struct.
 * cidr_subnet_iter_t embedded by value. Family saved for constructing
 * the correct network type (IPv4Network vs IPv6Network) on each yield.
 * See ARCHITECTURE.md §8.9.
 */
typedef struct {
	PyObject_HEAD cidr_subnet_iter_t iter;
	cidr_family_t family;
} SubnetIterator;

/* -------------------------------------------------------------------
 * Helpers shared by address types and network types.
 * ------------------------------------------------------------------- */

/*
 * binding_addr_to_pyobj - create an IPv4Address or IPv6Address from a
 *                         cidr_addr_t.
 *
 * Allocates a new Python address object of the correct family and copies
 * the C struct into it. Caller owns the returned reference.
 *
 * Returns NULL on allocation failure (MemoryError set).
 */
static PyObject *
binding_addr_to_pyobj(const cidr_addr_t *addr)
{
	PyTypeObject *tp;
	PyObject *self;

	tp = (addr->family == CIDR_AF_INET) ? ipv4address_type
	                                    : ipv6address_type;
	self = PyType_GenericNew(tp, NULL, NULL);
	if (self == NULL)
		return NULL;
	if (addr->family == CIDR_AF_INET)
		// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
		memcpy(&((IPv4Address *)self)->addr, addr, sizeof(cidr_addr_t));
	else
		// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
		memcpy(&((IPv6Address *)self)->addr, addr, sizeof(cidr_addr_t));
	return self;
}

/*
 * binding_prefix_to_pyobj - create an IPv4Network or IPv6Network from a
 *                           cidr_prefix_t.
 *
 * Allocates a new Python network object of the correct family and copies
 * the C struct into it. Caller owns the returned reference.
 *
 * Returns NULL on allocation failure (MemoryError set).
 */
static PyObject *
binding_prefix_to_pyobj(const cidr_prefix_t *prefix)
{
	PyTypeObject *tp;
	PyObject *self;

	tp = (prefix->addr.family == CIDR_AF_INET) ? ipv4network_type
	                                           : ipv6network_type;
	self = PyType_GenericNew(tp, NULL, NULL);
	if (self == NULL)
		return NULL;
	if (prefix->addr.family == CIDR_AF_INET)
		// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
		memcpy(&((IPv4Network *)self)->prefix, prefix,
		       sizeof(cidr_prefix_t));
	else
		// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
		memcpy(&((IPv6Network *)self)->prefix, prefix,
		       sizeof(cidr_prefix_t));
	return self;
}

/*
 * binding_parse_cidr_string - parse a CIDR string into a cidr_prefix_t
 *                             with strict/non-strict control.
 *
 * strict=True:  delegate to cidr_prefix_parse() which rejects host bits.
 * strict=False: parse address and prefix length separately, then call
 *               cidr_prefix_from_host() which zeros host bits explicitly.
 *               See ARCHITECTURE.md §8.7.1.
 *
 * Returns 0 on success, -1 on error (exception set).
 */
static int
binding_parse_cidr_string(const char *s, cidr_prefix_t *out,
                          cidr_family_t expected, int strict)
{
	cidr_err_t rc;

	if (strict) {
		rc = cidr_prefix_parse(s, out);
		if (rc != CIDR_OK)
			return cidr_set_python_error(rc, s);
		if (out->addr.family != expected) {
			PyErr_SetString(libcidr_FamilyError,
			                "address family mismatch");
			return -1;
		}
		return 0;
	}

	/*
	 * Non-strict: split at the last '/', parse addr and pfxlen
	 * separately, then zero host bits via cidr_prefix_from_host().
	 */
	const char *slash = strrchr(s, '/');
	if (slash == NULL) {
		PyErr_SetString(libcidr_ParseError,
		                "missing '/' in CIDR notation");
		return -1;
	}

	/* Parse the address part (up to the slash). */
	size_t addr_len = (size_t)(slash - s);
	char addr_buf[CIDR_ADDR_STR_MAX];
	cidr_addr_t addr;
	if (addr_len >= sizeof(addr_buf)) {
		PyErr_SetString(libcidr_ParseError, "address part too long");
		return -1;
	}
	// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
	memcpy(addr_buf, s, addr_len);
	addr_buf[addr_len] = '\0';

	rc = cidr_addr_parse(addr_buf, &addr);
	if (rc != CIDR_OK)
		return cidr_set_python_error(rc, addr_buf);
	if (addr.family != expected) {
		PyErr_SetString(libcidr_FamilyError, "address family mismatch");
		return -1;
	}

	/* Parse the prefix length. */
	char *end;
	long pfxlen = strtol(slash + 1, &end, 10);
	if (*end != '\0' || pfxlen < 0 ||
	    (size_t)pfxlen > (expected == CIDR_AF_INET ? 32U : 128U)) {
		PyErr_SetString(libcidr_PrefixLengthError,
		                "invalid prefix length");
		return -1;
	}

	/* cidr_prefix_from_host zeros host bits explicitly. */
	rc = cidr_prefix_from_host(&addr, (uint8_t)pfxlen, out);
	if (rc != CIDR_OK)
		return cidr_set_python_error(rc, NULL);
	return 0;
}

/*
 * binding_tuple_to_prefix - parse a (address_string, prefixlen) tuple
 *                           into a cidr_prefix_t with strict control.
 *
 * strict=True:  parse address, construct prefix, verify no host bits.
 * strict=False: parse address, call cidr_prefix_from_host().
 *
 * Returns 0 on success, -1 on error (exception set).
 */
static int
binding_tuple_to_prefix(PyObject *tuple, cidr_prefix_t *out,
                        cidr_family_t expected, int strict)
{
	PyObject *addr_obj;
	PyObject *pfxlen_obj;
	long pfxlen;
	cidr_addr_t addr;
	cidr_prefix_t tmp;
	cidr_err_t rc;

	if (!PyArg_ParseTuple(tuple, "OO", &addr_obj, &pfxlen_obj))
		return -1;

	/* Parse the address part. */
	if (PyUnicode_Check(addr_obj)) {
		if (binding_string_to_addr(addr_obj, &addr, expected) < 0)
			return -1;
	} else if (PyObject_TypeCheck(addr_obj, ipv4address_type) ||
	           PyObject_TypeCheck(addr_obj, ipv6address_type)) {
		const cidr_addr_t *src = (expected == CIDR_AF_INET)
		                             ? &((IPv4Address *)addr_obj)->addr
		                             : &((IPv6Address *)addr_obj)->addr;
		if (src->family != expected) {
			PyErr_SetString(libcidr_FamilyError,
			                "address family mismatch");
			return -1;
		}
		// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
		memcpy(&addr, src, sizeof(addr));
	} else {
		PyErr_SetString(PyExc_TypeError,
		                "address string or address object expected");
		return -1;
	}

	/* Parse the prefix length. */
	pfxlen = PyLong_AsLong(pfxlen_obj);
	if (pfxlen == -1 && PyErr_Occurred())
		return -1;
	if (pfxlen < 0 ||
	    (size_t)pfxlen > (expected == CIDR_AF_INET ? 32U : 128U)) {
		PyErr_SetString(libcidr_PrefixLengthError,
		                "prefix length out of range");
		return -1;
	}

	if (strict) {
		/*
		 * Construct via from_host (zeros host bits), then verify
		 * that no zeroing was needed. Compare only the active
		 * address bytes for the family to avoid reading
		 * uninitialised union padding.
		 */
		rc = cidr_prefix_from_host(&addr, (uint8_t)pfxlen, &tmp);
		if (rc != CIDR_OK)
			return cidr_set_python_error(rc, NULL);

		/* Compare address bytes based on family. */
		size_t addr_bytes = (expected == CIDR_AF_INET) ? 4 : 16;
		const uint8_t *orig =
		    (expected == CIDR_AF_INET) ? addr.addr.v4 : addr.addr.v6;
		const uint8_t *masked = (expected == CIDR_AF_INET)
		                            ? tmp.addr.addr.v4
		                            : tmp.addr.addr.v6;
		if (memcmp(orig, masked, addr_bytes) != 0) {
			PyErr_SetString(libcidr_HostBitsError,
			                "host bits set in prefix");
			return -1;
		}
		// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
		memcpy(out, &tmp, sizeof(*out));
	} else {
		rc = cidr_prefix_from_host(&addr, (uint8_t)pfxlen, out);
		if (rc != CIDR_OK)
			return cidr_set_python_error(rc, NULL);
	}
	return 0;
}

/*
 * prefix_extract_ipaddress - extract cidr_prefix_t from an ipaddress
 *                            network object.
 *
 * ipaddress.IPv4Network/.IPv6Network have packed on their .network_address,
 * not directly. We extract network_address.packed and prefixlen.
 *
 * Returns 0 on success, -1 on error (exception set).
 */
static int
prefix_extract_ipaddress(PyObject *obj, cidr_prefix_t *out,
                         cidr_family_t expected)
{
	PyObject *net_addr;
	PyObject *packed;
	PyObject *pfxlen_obj;
	const char *buf;
	long pfxlen;
	size_t want;

	/* Get the network_address object from the ipaddress network. */
	net_addr = PyObject_GetAttrString(obj, "network_address");
	if (net_addr == NULL) {
		PyErr_Clear();
		PyErr_Format(PyExc_TypeError,
		             "cannot construct %s from non-ipaddress object",
		             expected == CIDR_AF_INET ? "IPv4Network"
		                                      : "IPv6Network");
		return -1;
	}

	/* Get packed bytes from the network address object. */
	packed = PyObject_GetAttrString(net_addr, "packed");
	Py_DECREF(net_addr);
	if (packed == NULL) {
		Py_DECREF(packed);
		return -1;
	}

	if (!PyBytes_Check(packed)) {
		Py_DECREF(packed);
		PyErr_Format(PyExc_TypeError,
		             "'network_address.packed' is not bytes");
		return -1;
	}

	want = (expected == CIDR_AF_INET) ? 4 : 16;
	if ((size_t)PyBytes_Size(packed) != want) {
		Py_DECREF(packed);
		PyErr_SetString(libcidr_FamilyError, "address family mismatch");
		return -1;
	}

	buf = PyBytes_AsString(packed);
	out->addr.family = expected;
	if (expected == CIDR_AF_INET)
		// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
		memcpy(out->addr.addr.v4, buf, 4);
	else
		// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
		memcpy(out->addr.addr.v6, buf, 16);
	Py_DECREF(packed);

	pfxlen_obj = PyObject_GetAttrString(obj, "prefixlen");
	if (pfxlen_obj == NULL)
		return -1;
	pfxlen = PyLong_AsLong(pfxlen_obj);
	Py_DECREF(pfxlen_obj);
	if (pfxlen == -1 && PyErr_Occurred())
		return -1;
	out->pfxlen = (uint8_t)pfxlen;
	return 0;
}

/* -------------------------------------------------------------------
 * tp_new constructors.
 * Accept: string CIDR, (addr_str, pfxlen) tuple, ipaddress object.
 * strict= keyword-only argument (default True).
 * See ARCHITECTURE.md §8.7.1.
 * ------------------------------------------------------------------- */

/*
 * Network constructor implementation shared by IPv4Network and
 * IPv6Network.
 *
 * arg:       the positional argument (string, tuple, or object)
 * expected:  the expected address family
 * strict:    whether host bits are rejected (1) or zeroed (0)
 * out:       receives the constructed cidr_prefix_t
 *
 * Returns 0 on success, -1 on error (exception set).
 */
static int
network_construct_impl(PyObject *arg, cidr_family_t expected, int strict,
                       cidr_prefix_t *out)
{
	if (PyUnicode_Check(arg)) {
		PyObject *utf8;
		const char *s;
		int rc;

		utf8 = PyUnicode_AsEncodedString(arg, "utf-8", "strict");
		if (utf8 == NULL)
			return -1;
		s = PyBytes_AsString(utf8);
		if (s == NULL) {
			Py_DECREF(utf8);
			return -1;
		}
		rc = binding_parse_cidr_string(s, out, expected, strict);
		Py_DECREF(utf8);
		return rc;
	}

	if (PyTuple_Check(arg))
		return binding_tuple_to_prefix(arg, out, expected, strict);

	/* Assume ipaddress object; strict is ignored per §8.7.1. */
	return prefix_extract_ipaddress(arg, out, expected);
}

static PyObject *
ipv4network_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	PyObject *arg;
	cidr_prefix_t prefix;
	int strict = 1;
	IPv4Network *self;

	static char *kwlist[] = {"", "strict", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O|p", kwlist, &arg,
	                                 &strict))
		return NULL;

	prefix.addr.family = CIDR_AF_UNSPEC;

	if (network_construct_impl(arg, CIDR_AF_INET, strict, &prefix) < 0)
		return NULL;

	self = (IPv4Network *)PyType_GenericNew(type, NULL, NULL);
	if (self == NULL)
		return NULL;
	// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
	memcpy(&self->prefix, &prefix, sizeof(cidr_prefix_t));
	return (PyObject *)self;
}

static PyObject *
ipv6network_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	PyObject *arg;
	cidr_prefix_t prefix;
	int strict = 1;
	IPv6Network *self;

	static char *kwlist[] = {"", "strict", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O|p", kwlist, &arg,
	                                 &strict))
		return NULL;

	prefix.addr.family = CIDR_AF_UNSPEC;

	if (network_construct_impl(arg, CIDR_AF_INET6, strict, &prefix) < 0)
		return NULL;

	self = (IPv6Network *)PyType_GenericNew(type, NULL, NULL);
	if (self == NULL)
		return NULL;
	// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
	memcpy(&self->prefix, &prefix, sizeof(cidr_prefix_t));
	return (PyObject *)self;
}

/* -------------------------------------------------------------------
 * tp_dealloc.
 * No heap-allocated members to free; just the base object dealloc.
 * See ARCHITECTURE.md §8.10.
 * ------------------------------------------------------------------- */

static void
ipv4network_dealloc(PyObject *self)
{
	PyObject_Del(self);
}

static void
ipv6network_dealloc(PyObject *self)
{
	PyObject_Del(self);
}

/* -------------------------------------------------------------------
 * Property getters.
 * All properties are read-only per ARCHITECTURE.md §8.7.2.
 * ------------------------------------------------------------------- */

static PyObject *
ipv4network_get_network_address(PyObject *self, void *closure)
{
	IPv4Network *n = (IPv4Network *)self;

	(void)closure;
	return binding_addr_to_pyobj(&n->prefix.addr);
}

static PyObject *
ipv6network_get_network_address(PyObject *self, void *closure)
{
	IPv6Network *n = (IPv6Network *)self;

	(void)closure;
	return binding_addr_to_pyobj(&n->prefix.addr);
}

static PyObject *
ipv4network_get_broadcast_address(PyObject *self, void *closure)
{
	IPv4Network *n = (IPv4Network *)self;
	cidr_addr_t bcast;
	cidr_err_t rc;

	(void)closure;
	rc = cidr_prefix_broadcast(&n->prefix, &bcast);
	if (rc != CIDR_OK) {
		cidr_set_python_error(rc, NULL);
		return NULL;
	}
	return binding_addr_to_pyobj(&bcast);
}

static PyObject *
ipv6network_get_broadcast_address(PyObject *self, void *closure)
{
	(void)self;
	(void)closure;
	PyErr_SetString(libcidr_FamilyError,
	                "broadcast_address is not defined for IPv6 networks");
	return NULL;
}

static PyObject *
ipv4network_get_prefixlen(PyObject *self, void *closure)
{
	IPv4Network *n = (IPv4Network *)self;

	(void)closure;
	return PyLong_FromLong((long)n->prefix.pfxlen);
}

static PyObject *
ipv6network_get_prefixlen(PyObject *self, void *closure)
{
	IPv6Network *n = (IPv6Network *)self;

	(void)closure;
	return PyLong_FromLong((long)n->prefix.pfxlen);
}

static PyObject *
ipv4network_get_netmask(PyObject *self, void *closure)
{
	IPv4Network *n = (IPv4Network *)self;
	cidr_addr_t mask;
	cidr_err_t rc;

	(void)closure;
	rc = cidr_prefix_mask(&n->prefix, &mask);
	if (rc != CIDR_OK) {
		cidr_set_python_error(rc, NULL);
		return NULL;
	}
	mask.family = CIDR_AF_INET;
	return binding_addr_to_pyobj(&mask);
}

static PyObject *
ipv6network_get_netmask(PyObject *self, void *closure)
{
	IPv6Network *n = (IPv6Network *)self;
	cidr_addr_t mask;
	cidr_err_t rc;

	(void)closure;
	rc = cidr_prefix_mask(&n->prefix, &mask);
	if (rc != CIDR_OK) {
		cidr_set_python_error(rc, NULL);
		return NULL;
	}
	mask.family = CIDR_AF_INET6;
	return binding_addr_to_pyobj(&mask);
}

static PyObject *
ipv4network_get_with_prefixlen(PyObject *self, void *closure)
{
	IPv4Network *n = (IPv4Network *)self;
	char buf[CIDR_PREFIX_STR_MAX];
	cidr_err_t rc;

	(void)closure;
	rc = cidr_prefix_format(&n->prefix, buf, sizeof(buf));
	if (rc != CIDR_OK) {
		cidr_set_python_error(rc, NULL);
		return NULL;
	}
	return PyUnicode_FromString(buf);
}

static PyObject *
ipv6network_get_with_prefixlen(PyObject *self, void *closure)
{
	IPv6Network *n = (IPv6Network *)self;
	char buf[CIDR_PREFIX_STR_MAX];
	cidr_err_t rc;

	(void)closure;
	rc = cidr_prefix_format(&n->prefix, buf, sizeof(buf));
	if (rc != CIDR_OK) {
		cidr_set_python_error(rc, NULL);
		return NULL;
	}
	return PyUnicode_FromString(buf);
}

static PyObject *
ipv4network_get_version(PyObject *self, void *closure)
{
	(void)self;
	(void)closure;
	return PyLong_FromLong(4);
}

static PyObject *
ipv6network_get_version(PyObject *self, void *closure)
{
	(void)self;
	(void)closure;
	return PyLong_FromLong(6);
}

/*
 * num_addresses - compute 2^(max_pfxlen - prefix->pfxlen) as a Python int.
 * Uses uint64_t arithmetic for small shifts (< 64 bits) and Python big
 * integer arithmetic for larger shifts.
 */
static PyObject *
network_num_addresses(cidr_family_t family, uint8_t pfxlen)
{
	int max_bits = (family == CIDR_AF_INET) ? 32 : 128;
	int shift = max_bits - pfxlen;

	if (shift < 0) {
		PyErr_SetString(libcidr_InvalidArgumentError,
		                "prefix length exceeds maximum for family");
		return NULL;
	}

	if ((size_t)shift < 64) {
		/* SAFETY: shift < 64 ensures 1ULL << shift is well-defined.*/
		return PyLong_FromUnsignedLongLong(1ULL << shift);
	}

	/* Shift >= 64: use Python big integer left shift. */
	PyObject *one = PyLong_FromLong(1);
	if (one == NULL)
		return NULL;
	PyObject *shift_obj = PyLong_FromLong((long)shift);
	if (shift_obj == NULL) {
		Py_DECREF(one);
		return NULL;
	}
	PyObject *result = PyNumber_Lshift(one, shift_obj);
	Py_DECREF(shift_obj);
	Py_DECREF(one);
	return result;
}

static PyObject *
ipv4network_get_num_addresses(PyObject *self, void *closure)
{
	IPv4Network *n = (IPv4Network *)self;

	(void)closure;
	return network_num_addresses(CIDR_AF_INET, n->prefix.pfxlen);
}

static PyObject *
ipv6network_get_num_addresses(PyObject *self, void *closure)
{
	IPv6Network *n = (IPv6Network *)self;

	(void)closure;
	return network_num_addresses(CIDR_AF_INET6, n->prefix.pfxlen);
}

/* -------------------------------------------------------------------
 * Methods.
 * See ARCHITECTURE.md §8.7.3.
 * ------------------------------------------------------------------- */

/*
 * overlaps(other) -> bool
 *
 * Returns True if this network and other share at least one address.
 * Backed by cidr_prefix_overlaps(). Raises FamilyError on cross-family.
 */
static PyObject *
ipv4network_overlaps(PyObject *self, PyObject *args)
{
	IPv4Network *n = (IPv4Network *)self;
	PyObject *other;
	const cidr_prefix_t *other_prefix;
	bool result;
	cidr_err_t rc;

	if (!PyArg_ParseTuple(args, "O", &other))
		return NULL;

	if (PyObject_TypeCheck(other, ipv4network_type))
		other_prefix = &((IPv4Network *)other)->prefix;
	else if (PyObject_TypeCheck(other, ipv6network_type))
		other_prefix = &((IPv6Network *)other)->prefix;
	else {
		PyErr_SetString(PyExc_TypeError,
		                "IPv4Network or IPv6Network expected");
		return NULL;
	}

	rc = cidr_prefix_overlaps(&n->prefix, other_prefix, &result);
	if (rc != CIDR_OK) {
		cidr_set_python_error(rc, NULL);
		return NULL;
	}
	if (result) {
		Py_INCREF(Py_True);
		return Py_True;
	}
	Py_INCREF(Py_False);
	return Py_False;
}

static PyObject *
ipv6network_overlaps(PyObject *self, PyObject *args)
{
	IPv6Network *n = (IPv6Network *)self;
	PyObject *other;
	const cidr_prefix_t *other_prefix;
	bool result;
	cidr_err_t rc;

	if (!PyArg_ParseTuple(args, "O", &other))
		return NULL;

	if (PyObject_TypeCheck(other, ipv4network_type))
		other_prefix = &((IPv4Network *)other)->prefix;
	else if (PyObject_TypeCheck(other, ipv6network_type))
		other_prefix = &((IPv6Network *)other)->prefix;
	else {
		PyErr_SetString(PyExc_TypeError,
		                "IPv4Network or IPv6Network expected");
		return NULL;
	}

	rc = cidr_prefix_overlaps(&n->prefix, other_prefix, &result);
	if (rc != CIDR_OK) {
		cidr_set_python_error(rc, NULL);
		return NULL;
	}
	if (result) {
		Py_INCREF(Py_True);
		return Py_True;
	}
	Py_INCREF(Py_False);
	return Py_False;
}

/*
 * supernet() -> IPv4Network | IPv6Network
 *
 * Returns the parent network at prefixlen - 1.
 * Raises AddressOverflowError on /0.
 * Backed by cidr_prefix_supernet(). See ARCHITECTURE.md §8.7.3.
 */
static PyObject *
ipv4network_supernet(PyObject *self, PyObject *noargs)
{
	IPv4Network *n = (IPv4Network *)self;
	cidr_prefix_t parent;
	cidr_err_t rc;

	(void)noargs;
	rc = cidr_prefix_supernet(&n->prefix, &parent);
	if (rc != CIDR_OK) {
		cidr_set_python_error(rc, NULL);
		return NULL;
	}
	return binding_prefix_to_pyobj(&parent);
}

static PyObject *
ipv6network_supernet(PyObject *self, PyObject *noargs)
{
	IPv6Network *n = (IPv6Network *)self;
	cidr_prefix_t parent;
	cidr_err_t rc;

	(void)noargs;
	rc = cidr_prefix_supernet(&n->prefix, &parent);
	if (rc != CIDR_OK) {
		cidr_set_python_error(rc, NULL);
		return NULL;
	}
	return binding_prefix_to_pyobj(&parent);
}

/*
 * subnets(prefixlen) -> iterator
 *
 * Returns a SubnetIterator over all subnets at the given prefix length.
 * Backed by cidr_subnet_iter_init/next. See ARCHITECTURE.md §8.7.3, §8.9.
 */
static PyObject *
network_subnets_impl(const cidr_prefix_t *prefix, cidr_family_t family,
                     PyObject *args, PyObject *kwargs)
{
	SubnetIterator *iter_obj;
	int target_pfxlen;
	cidr_err_t rc;

	static char *kwlist[] = {"prefixlen", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "i", kwlist,
	                                 &target_pfxlen))
		return NULL;

	iter_obj = (SubnetIterator *)PyType_GenericNew(subnetiterator_type,
	                                               NULL, NULL);
	if (iter_obj == NULL)
		return NULL;

	rc = cidr_subnet_iter_init(&iter_obj->iter, prefix,
	                           (uint8_t)target_pfxlen);
	if (rc != CIDR_OK) {
		Py_DECREF(iter_obj);
		cidr_set_python_error(rc, NULL);
		return NULL;
	}

	iter_obj->family = family;
	return (PyObject *)iter_obj;
}

static PyObject *
ipv4network_subnets(PyObject *self, PyObject *args, PyObject *kwargs)
{
	IPv4Network *n = (IPv4Network *)self;

	return network_subnets_impl(&n->prefix, CIDR_AF_INET, args, kwargs);
}

static PyObject *
ipv6network_subnets(PyObject *self, PyObject *args, PyObject *kwargs)
{
	IPv6Network *n = (IPv6Network *)self;

	return network_subnets_impl(&n->prefix, CIDR_AF_INET6, args, kwargs);
}

/*
 * Contains implementation shared by contains() method and __contains__.
 *
 * Accepts: IPv4Address, IPv6Address, or string.
 * Returns: 1 if contained, 0 if not, -1 on error (exception set).
 */
static int
network_contains_impl(cidr_prefix_t *prefix, PyObject *addr_obj)
{
	cidr_addr_t addr;
	bool result;
	cidr_err_t rc;
	cidr_family_t expected = prefix->addr.family;

	if (PyObject_TypeCheck(addr_obj, ipv4address_type)) {
		if (expected != CIDR_AF_INET) {
			PyErr_SetString(libcidr_FamilyError,
			                "address family mismatch");
			return -1;
		}
		// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
		memcpy(&addr, &((IPv4Address *)addr_obj)->addr, sizeof(addr));
	} else if (PyObject_TypeCheck(addr_obj, ipv6address_type)) {
		if (expected != CIDR_AF_INET6) {
			PyErr_SetString(libcidr_FamilyError,
			                "address family mismatch");
			return -1;
		}
		// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
		memcpy(&addr, &((IPv6Address *)addr_obj)->addr, sizeof(addr));
	} else if (PyUnicode_Check(addr_obj)) {
		if (binding_string_to_addr(addr_obj, &addr, expected) < 0)
			return -1;
	} else {
		PyErr_SetString(PyExc_TypeError,
		                "address string or address object expected");
		return -1;
	}

	rc = cidr_prefix_contains(prefix, &addr, &result);
	if (rc != CIDR_OK) {
		cidr_set_python_error(rc, NULL);
		return -1;
	}
	return result ? 1 : 0;
}

/*
 * contains(addr) -> bool
 *
 * Returns True if addr falls within this network.
 * Explicit complement to __contains__. See ARCHITECTURE.md §8.7.3.
 */
static PyObject *
ipv4network_contains(PyObject *self, PyObject *args)
{
	IPv4Network *n = (IPv4Network *)self;
	PyObject *addr_obj;
	int r;

	if (!PyArg_ParseTuple(args, "O", &addr_obj))
		return NULL;
	r = network_contains_impl(&n->prefix, addr_obj);
	if (r < 0)
		return NULL;
	if (r) {
		Py_INCREF(Py_True);
		return Py_True;
	}
	Py_INCREF(Py_False);
	return Py_False;
}

static PyObject *
ipv6network_contains(PyObject *self, PyObject *args)
{
	IPv6Network *n = (IPv6Network *)self;
	PyObject *addr_obj;
	int r;

	if (!PyArg_ParseTuple(args, "O", &addr_obj))
		return NULL;
	r = network_contains_impl(&n->prefix, addr_obj);
	if (r < 0)
		return NULL;
	if (r) {
		Py_INCREF(Py_True);
		return Py_True;
	}
	Py_INCREF(Py_False);
	return Py_False;
}

/* -------------------------------------------------------------------
 * Protocol: __str__, __repr__, __hash__, __contains__.
 * See ARCHITECTURE.md §8.7.4.
 * ------------------------------------------------------------------- */

static PyObject *
ipv4network_str(PyObject *self)
{
	IPv4Network *n = (IPv4Network *)self;
	char buf[CIDR_PREFIX_STR_MAX];
	cidr_err_t rc;

	rc = cidr_prefix_format(&n->prefix, buf, sizeof(buf));
	if (rc != CIDR_OK) {
		cidr_set_python_error(rc, NULL);
		return NULL;
	}
	return PyUnicode_FromString(buf);
}

static PyObject *
ipv6network_str(PyObject *self)
{
	IPv6Network *n = (IPv6Network *)self;
	char buf[CIDR_PREFIX_STR_MAX];
	cidr_err_t rc;

	rc = cidr_prefix_format(&n->prefix, buf, sizeof(buf));
	if (rc != CIDR_OK) {
		cidr_set_python_error(rc, NULL);
		return NULL;
	}
	return PyUnicode_FromString(buf);
}

static PyObject *
ipv4network_repr(PyObject *self)
{
	IPv4Network *n = (IPv4Network *)self;
	char buf[CIDR_PREFIX_STR_MAX];
	cidr_err_t rc;

	rc = cidr_prefix_format(&n->prefix, buf, sizeof(buf));
	if (rc != CIDR_OK) {
		cidr_set_python_error(rc, NULL);
		return NULL;
	}
	return PyUnicode_FromFormat("IPv4Network('%s')", buf);
}

static PyObject *
ipv6network_repr(PyObject *self)
{
	IPv6Network *n = (IPv6Network *)self;
	char buf[CIDR_PREFIX_STR_MAX];
	cidr_err_t rc;

	rc = cidr_prefix_format(&n->prefix, buf, sizeof(buf));
	if (rc != CIDR_OK) {
		cidr_set_python_error(rc, NULL);
		return NULL;
	}
	return PyUnicode_FromFormat("IPv6Network('%s')", buf);
}

/* djb2-derived hash of family + address bytes + prefix length. */
static Py_hash_t
ipv4network_hash(PyObject *self)
{
	IPv4Network *n = (IPv4Network *)self;
	const uint8_t *v4 = n->prefix.addr.addr.v4;
	Py_hash_t h = 5381;

	/*
	 * SAFETY: family is guaranteed to be CIDR_AF_INET for a valid
	 * IPv4Network instance. No hash state is shared with IPv6.
	 */
	h = ((h << 5) + h) + (Py_hash_t)n->prefix.addr.family;
	for (int i = 0; i < 4; i++)
		h = ((h << 5) + h) + (Py_hash_t)v4[i];
	h = ((h << 5) + h) + (Py_hash_t)n->prefix.pfxlen;
	return h;
}

static Py_hash_t
ipv6network_hash(PyObject *self)
{
	IPv6Network *n = (IPv6Network *)self;
	const uint8_t *v6 = n->prefix.addr.addr.v6;
	Py_hash_t h = 5381;

	/*
	 * SAFETY: family is guaranteed to be CIDR_AF_INET6 for a valid
	 * IPv6Network instance. No hash state is shared with IPv4.
	 */
	h = ((h << 5) + h) + (Py_hash_t)n->prefix.addr.family;
	for (int i = 0; i < 16; i++)
		h = ((h << 5) + h) + (Py_hash_t)v6[i];
	h = ((h << 5) + h) + (Py_hash_t)n->prefix.pfxlen;
	return h;
}

/*
 * sq_contains / __contains__ — implements "addr in network" syntax.
 * Delegates to network_contains_impl(). See ARCHITECTURE.md §8.7.4.
 * Returns 1 for contained, 0 for not, -1 on error (exception set).
 */
static int
ipv4network_contains_slot(PyObject *self, PyObject *value)
{
	int r = network_contains_impl(&((IPv4Network *)self)->prefix, value);

	if (r < 0)
		return -1;
	return r;
}

static int
ipv6network_contains_slot(PyObject *self, PyObject *value)
{
	int r = network_contains_impl(&((IPv6Network *)self)->prefix, value);

	if (r < 0)
		return -1;
	return r;
}

/* -------------------------------------------------------------------
 * Rich comparison: __eq__, __ne__, __lt__, __le__, __gt__, __ge__.
 * Uses cidr_prefix_cmp() for ordering per ARCHITECTURE.md §8.7.4.
 * ------------------------------------------------------------------- */

static PyObject *
ipv4network_richcmp(PyObject *a, PyObject *b, int op)
{
	PyObject *result;
	int cmp;
	cidr_err_t rc;

	if (!PyObject_TypeCheck(b, ipv4network_type)) {
		if (PyObject_TypeCheck(b, ipv6network_type)) {
			cidr_set_python_error(CIDR_ERR_FAMILY, NULL);
			return NULL;
		}
		Py_RETURN_NOTIMPLEMENTED;
	}

	rc = cidr_prefix_cmp(&((IPv4Network *)a)->prefix,
	                     &((IPv4Network *)b)->prefix, &cmp);
	if (rc != CIDR_OK) {
		cidr_set_python_error(rc, NULL);
		return NULL;
	}

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
ipv6network_richcmp(PyObject *a, PyObject *b, int op)
{
	PyObject *result;
	int cmp;
	cidr_err_t rc;

	if (!PyObject_TypeCheck(b, ipv6network_type)) {
		if (PyObject_TypeCheck(b, ipv4network_type)) {
			cidr_set_python_error(CIDR_ERR_FAMILY, NULL);
			return NULL;
		}
		Py_RETURN_NOTIMPLEMENTED;
	}

	rc = cidr_prefix_cmp(&((IPv6Network *)a)->prefix,
	                     &((IPv6Network *)b)->prefix, &cmp);
	if (rc != CIDR_OK) {
		cidr_set_python_error(rc, NULL);
		return NULL;
	}

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

static PyGetSetDef ipv4network_getset[] = {
    {"network_address", ipv4network_get_network_address, NULL,
     "network address (host bits zero)", NULL},
    {"broadcast_address", ipv4network_get_broadcast_address, NULL,
     "broadcast address (IPv4 only)", NULL},
    {"prefixlen", ipv4network_get_prefixlen, NULL, "prefix length", NULL},
    {"netmask", ipv4network_get_netmask, NULL, "prefix mask", NULL},
    {"with_prefixlen", ipv4network_get_with_prefixlen, NULL,
     "canonical CIDR string", NULL},
    {"version", ipv4network_get_version, NULL, "address family version (4)",
     NULL},
    {"num_addresses", ipv4network_get_num_addresses, NULL,
     "total number of addresses in this network", NULL},
    {NULL, NULL, NULL, NULL, NULL}};

static PyGetSetDef ipv6network_getset[] = {
    {"network_address", ipv6network_get_network_address, NULL,
     "network address (host bits zero)", NULL},
    {"broadcast_address", ipv6network_get_broadcast_address, NULL,
     "broadcast address (IPv4 only; raises FamilyError on IPv6)", NULL},
    {"prefixlen", ipv6network_get_prefixlen, NULL, "prefix length", NULL},
    {"netmask", ipv6network_get_netmask, NULL, "prefix mask", NULL},
    {"with_prefixlen", ipv6network_get_with_prefixlen, NULL,
     "canonical CIDR string", NULL},
    {"version", ipv6network_get_version, NULL, "address family version (6)",
     NULL},
    {"num_addresses", ipv6network_get_num_addresses, NULL,
     "total number of addresses in this network", NULL},
    {NULL, NULL, NULL, NULL, NULL}};

/* -------------------------------------------------------------------
 * PyMethodDef tables.
 * ------------------------------------------------------------------- */

static PyMethodDef ipv4network_methods[] = {
    {"overlaps", ipv4network_overlaps, METH_VARARGS,
     "overlaps(other) -> bool\n\n"
     "Return True if this network and other share any address."},
    {"supernet", ipv4network_supernet, METH_NOARGS,
     "supernet() -> IPv4Network\n\n"
     "Return the parent network at prefixlen - 1."},
    {"subnets", (PyCFunction)(void (*)(void))ipv4network_subnets,
     METH_VARARGS | METH_KEYWORDS,
     "subnets(prefixlen) -> iterator\n\n"
     "Return an iterator over all subnets at the given prefix length."},
    {"contains", ipv4network_contains, METH_VARARGS,
     "contains(addr) -> bool\n\n"
     "Return True if addr falls within this network."},
    {NULL, NULL, 0, NULL}};

static PyMethodDef ipv6network_methods[] = {
    {"overlaps", ipv6network_overlaps, METH_VARARGS,
     "overlaps(other) -> bool\n\n"
     "Return True if this network and other share any address."},
    {"supernet", ipv6network_supernet, METH_NOARGS,
     "supernet() -> IPv6Network\n\n"
     "Return the parent network at prefixlen - 1."},
    {"subnets", (PyCFunction)(void (*)(void))ipv6network_subnets,
     METH_VARARGS | METH_KEYWORDS,
     "subnets(prefixlen) -> iterator\n\n"
     "Return an iterator over all subnets at the given prefix length."},
    {"contains", ipv6network_contains, METH_VARARGS,
     "contains(addr) -> bool\n\n"
     "Return True if addr falls within this network."},
    {NULL, NULL, 0, NULL}};

/* -------------------------------------------------------------------
 * PyType_Slot arrays and PyType_Spec definitions.
 * ------------------------------------------------------------------- */

static PyType_Slot ipv4network_slots[] = {
    {Py_tp_new, (void *)ipv4network_new},
    {Py_tp_dealloc, (void *)ipv4network_dealloc},
    {Py_tp_richcompare, (void *)ipv4network_richcmp},
    {Py_tp_hash, (void *)ipv4network_hash},
    {Py_tp_str, (void *)ipv4network_str},
    {Py_tp_repr, (void *)ipv4network_repr},
    {Py_sq_contains, (void *)ipv4network_contains_slot},
    {Py_tp_methods, (void *)ipv4network_methods},
    {Py_tp_getset, (void *)ipv4network_getset},
    {Py_tp_doc, (void *)"IPv4 network (CIDR prefix)."},
    {0, NULL}};

static PyType_Slot ipv6network_slots[] = {
    {Py_tp_new, (void *)ipv6network_new},
    {Py_tp_dealloc, (void *)ipv6network_dealloc},
    {Py_tp_richcompare, (void *)ipv6network_richcmp},
    {Py_tp_hash, (void *)ipv6network_hash},
    {Py_tp_str, (void *)ipv6network_str},
    {Py_tp_repr, (void *)ipv6network_repr},
    {Py_sq_contains, (void *)ipv6network_contains_slot},
    {Py_tp_methods, (void *)ipv6network_methods},
    {Py_tp_getset, (void *)ipv6network_getset},
    {Py_tp_doc, (void *)"IPv6 network (CIDR prefix)."},
    {0, NULL}};

static PyType_Spec ipv4network_spec = {"libcidr.IPv4Network",
                                       sizeof(IPv4Network), 0,
                                       Py_TPFLAGS_DEFAULT, ipv4network_slots};

static PyType_Spec ipv6network_spec = {"libcidr.IPv6Network",
                                       sizeof(IPv6Network), 0,
                                       Py_TPFLAGS_DEFAULT, ipv6network_slots};

/* ===================================================================
 * SubnetIterator type.
 * See ARCHITECTURE.md §8.9, CODING_STANDARDS.md §6.
 * =================================================================== */

/*
 * SubnetIterator struct is already defined above (needed by
 * network_subnets_impl). The type provides __iter__ (return self)
 * and __next__ (yield next network, StopIteration on CIDR_ERR_DONE).
 */

/* -------------------------------------------------------------------
 * tp_dealloc.
 * No heap-allocated members.
 * ------------------------------------------------------------------- */

static void
subnetiterator_dealloc(PyObject *self)
{
	PyObject_Del(self);
}

/* -------------------------------------------------------------------
 * __iter__: return self.
 * ------------------------------------------------------------------- */

static PyObject *
subnetiterator_iter(PyObject *self)
{
	Py_INCREF(self);
	return self;
}

/* -------------------------------------------------------------------
 * __next__: yield the next subnet.
 * Calls cidr_subnet_iter_next(). On CIDR_ERR_DONE raises StopIteration.
 * On CIDR_OK constructs and returns the next network object.
 * See ARCHITECTURE.md §8.9.
 * ------------------------------------------------------------------- */

static PyObject *
subnetiterator_next(PyObject *self)
{
	SubnetIterator *si = (SubnetIterator *)self;
	cidr_prefix_t subnet;
	cidr_err_t rc;

	rc = cidr_subnet_iter_next(&si->iter, &subnet);
	if (rc == CIDR_ERR_DONE) {
		PyErr_SetNone(PyExc_StopIteration);
		return NULL;
	}
	if (rc != CIDR_OK) {
		cidr_set_python_error(rc, NULL);
		return NULL;
	}

	return binding_prefix_to_pyobj(&subnet);
}

/* -------------------------------------------------------------------
 * PyType_Slot arrays and PyType_Spec.
 * ------------------------------------------------------------------- */

static PyType_Slot subnetiterator_slots[] = {
    {Py_tp_dealloc, (void *)subnetiterator_dealloc},
    {Py_tp_iter, (void *)subnetiterator_iter},
    {Py_tp_iternext, (void *)subnetiterator_next},
    {Py_tp_doc, (void *)"Subnet iterator for CIDR prefix enumeration."},
    {0, NULL}};

static PyType_Spec subnetiterator_spec = {
    "libcidr.SubnetIterator", sizeof(SubnetIterator), 0, Py_TPFLAGS_DEFAULT,
    subnetiterator_slots};

/* ===================================================================
 * Bulk entry points.
 * Module-level functions per ARCHITECTURE.md §8.8.1.
 * =================================================================== */

/*
 * bulk_extract_prefixes - extract a cidr_prefix_t array from a Python
 *                         list of IPv4Network/IPv6Network objects.
 *
 * obj:      Python sequence of network objects
 * count:    receives the number of objects
 * family:   receives the common address family
 *
 * Returns a heap-allocated array on success; NULL on error (exception
 * set). Caller must free() the returned array.
 * See ARCHITECTURE.md §8.8.1.
 */
static cidr_prefix_t *
bulk_extract_prefixes(PyObject *obj, size_t *count, cidr_family_t *family)
{
	PyObject *seq;
	Py_ssize_t n;
	cidr_prefix_t *arr;
	cidr_family_t fam = CIDR_AF_UNSPEC;

	seq = PySequence_Fast(obj, "argument must be a list or tuple");
	if (seq == NULL)
		return NULL;

	n = PySequence_Length(seq);
	if (n < 0) {
		Py_DECREF(seq);
		return NULL;
	}

	/* Determine family from the first element. */
	if (n > 0) {
		PyObject *first = PySequence_GetItem(seq, 0);

		if (first == NULL) {
			Py_DECREF(seq);
			return NULL;
		}
		if (PyObject_TypeCheck(first, ipv4network_type))
			fam = CIDR_AF_INET;
		else if (PyObject_TypeCheck(first, ipv6network_type))
			fam = CIDR_AF_INET6;
		else {
			Py_DECREF(first);
			Py_DECREF(seq);
			PyErr_SetString(
			    libcidr_FamilyError,
			    "all items must be IPv4Network or IPv6Network");
			return NULL;
		}
		Py_DECREF(first);
	}

	// NOLINTNEXTLINE(clang-analyzer-optin.portability.UnixAPI)
	arr = (cidr_prefix_t *)malloc((size_t)n * sizeof(cidr_prefix_t));
	if (arr == NULL && n > 0) {
		Py_DECREF(seq);
		PyErr_NoMemory();
		return NULL;
	}

	for (Py_ssize_t i = 0; i < n; i++) {
		PyObject *item = PySequence_GetItem(seq, i);
		const cidr_prefix_t *src;

		if (item == NULL) {
			Py_DECREF(seq);
			free(arr);
			return NULL;
		}
		if (fam == CIDR_AF_INET) {
			if (!PyObject_TypeCheck(item, ipv4network_type)) {
				Py_DECREF(item);
				Py_DECREF(seq);
				free(arr);
				PyErr_SetString(libcidr_FamilyError,
				                "mixed IPv4 and IPv6 networks");
				return NULL;
			}
			src = &((IPv4Network *)item)->prefix;
		} else {
			if (!PyObject_TypeCheck(item, ipv6network_type)) {
				Py_DECREF(item);
				Py_DECREF(seq);
				free(arr);
				PyErr_SetString(libcidr_FamilyError,
				                "mixed IPv4 and IPv6 networks");
				return NULL;
			}
			src = &((IPv6Network *)item)->prefix;
		}
		// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
		memcpy(&arr[i], src, sizeof(cidr_prefix_t));
		Py_DECREF(item);
	}

	Py_DECREF(seq);
	*count = (size_t)n;
	*family = fam;
	return arr;
}

/*
 * bulk_addrs_from_list - extract a cidr_addr_t array from a Python list
 *                        of IPv4Address/IPv6Address objects.
 *
 * obj:      Python sequence of address objects
 * count:    receives the number of objects
 * family:   receives the common address family
 *
 * Returns a heap-allocated array on success; NULL on error (exception
 * set). Caller must free() the returned array.
 * See ARCHITECTURE.md §8.8.1.
 */
static cidr_addr_t *
bulk_addrs_from_list(PyObject *obj, size_t *count, cidr_family_t *family)
{
	PyObject *seq;
	Py_ssize_t n;
	cidr_addr_t *arr;
	cidr_family_t fam = CIDR_AF_UNSPEC;

	seq = PySequence_Fast(obj, "argument must be a list or tuple");
	if (seq == NULL)
		return NULL;

	n = PySequence_Length(seq);
	if (n < 0) {
		Py_DECREF(seq);
		return NULL;
	}

	if (n > 0) {
		PyObject *first = PySequence_GetItem(seq, 0);

		if (first == NULL) {
			Py_DECREF(seq);
			return NULL;
		}
		if (PyObject_TypeCheck(first, ipv4address_type))
			fam = CIDR_AF_INET;
		else if (PyObject_TypeCheck(first, ipv6address_type))
			fam = CIDR_AF_INET6;
		else {
			Py_DECREF(first);
			Py_DECREF(seq);
			PyErr_SetString(
			    libcidr_FamilyError,
			    "all items must be IPv4Address or IPv6Address");
			return NULL;
		}
		Py_DECREF(first);
	}

	// NOLINTNEXTLINE(clang-analyzer-optin.portability.UnixAPI)
	arr = (cidr_addr_t *)malloc((size_t)n * sizeof(cidr_addr_t));
	if (arr == NULL && n > 0) {
		Py_DECREF(seq);
		PyErr_NoMemory();
		return NULL;
	}

	for (Py_ssize_t i = 0; i < n; i++) {
		PyObject *item = PySequence_GetItem(seq, i);
		const cidr_addr_t *src;

		if (item == NULL) {
			Py_DECREF(seq);
			free(arr);
			return NULL;
		}
		if (fam == CIDR_AF_INET) {
			if (!PyObject_TypeCheck(item, ipv4address_type)) {
				Py_DECREF(item);
				Py_DECREF(seq);
				free(arr);
				PyErr_SetString(
				    libcidr_FamilyError,
				    "mixed IPv4 and IPv6 addresses");
				return NULL;
			}
			src = &((IPv4Address *)item)->addr;
		} else {
			if (!PyObject_TypeCheck(item, ipv6address_type)) {
				Py_DECREF(item);
				Py_DECREF(seq);
				free(arr);
				PyErr_SetString(
				    libcidr_FamilyError,
				    "mixed IPv4 and IPv6 addresses");
				return NULL;
			}
			src = &((IPv6Address *)item)->addr;
		}
		// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
		memcpy(&arr[i], src, sizeof(cidr_addr_t));
		Py_DECREF(item);
	}

	Py_DECREF(seq);
	*count = (size_t)n;
	*family = fam;
	return arr;
}

/*
 * libcidr.bulk_parse(srcs) -> list
 *
 * Parse a list of address strings. All items are attempted regardless of
 * individual parse failures. Returns a list of IPv4Address/IPv6Address
 * objects. Failed items appear as None in the result list. Raises
 * ParseError or FamilyError after the full batch completes.
 *
 * Backed by cidr_bulk_parse(). See ARCHITECTURE.md §8.8.1.
 */
static PyObject *
libcidr_bulk_parse(PyObject *self, PyObject *args)
{
	PyObject *seq;
	PyObject *fast;
	Py_ssize_t count;
	const char **srcs = NULL;
	PyObject *utf8_hold = NULL;
	cidr_addr_t *out = NULL;
	cidr_err_t *errs = NULL;
	cidr_err_t rc;
	PyObject *result = NULL;

	(void)self;

	if (!PyArg_ParseTuple(args, "O", &seq))
		return NULL;

	fast = PySequence_Fast(seq, "argument must be a list or tuple");
	if (fast == NULL)
		return NULL;

	count = PySequence_Length(fast);
	if (count < 0) {
		Py_DECREF(fast);
		return NULL;
	}
	if (count == 0) {
		Py_DECREF(fast);
		return PyList_New(0);
	}

	/* Allocate working arrays. */
	srcs = (const char **)malloc((size_t)count * sizeof(const char *));
	out = (cidr_addr_t *)malloc((size_t)count * sizeof(cidr_addr_t));
	errs = (cidr_err_t *)malloc((size_t)count * sizeof(cidr_err_t));
	utf8_hold = PyList_New(count);
	if (srcs == NULL || out == NULL || errs == NULL || utf8_hold == NULL) {
		PyErr_NoMemory();
		goto error;
	}

	/* Pre-fill utf8_hold with Py_None for safe cleanup. */
	for (Py_ssize_t i = 0; i < count; i++) {
		Py_INCREF(Py_None);
		// NOLINTNEXTLINE(bugprone-multi-level-implicit-pointer-conversion)
		if (PyList_SetItem(utf8_hold, i, Py_None) < 0)
			goto error;
	}

	/* Convert each Python string to a C string. */
	for (Py_ssize_t i = 0; i < count; i++) {
		PyObject *item = PySequence_GetItem(fast, i);
		PyObject *utf8;

		if (item == NULL)
			goto error;
		if (!PyUnicode_Check(item)) {
			Py_DECREF(item);
			PyErr_SetString(libcidr_InvalidArgumentError,
			                "all items must be strings");
			goto error;
		}

		utf8 = PyUnicode_AsEncodedString(item, "utf-8", "strict");
		Py_DECREF(item);
		if (utf8 == NULL)
			goto error;
		/* PyList_SetItem steals the utf8 reference. */
		if (PyList_SetItem(utf8_hold, i, utf8) < 0)
			goto error;
		srcs[i] = PyBytes_AsString(utf8);
	}

	/* SAFETY: srcs[] pointers are valid because utf8_hold keeps the
	 * bytes objects alive. utf8_hold is not released until after the
	 * C call returns. */
	rc = cidr_bulk_parse(srcs, (size_t)count, out, errs);

	/* Build result list regardless of batch errors. */
	result = PyList_New(count);
	if (result == NULL)
		goto error;

	for (Py_ssize_t i = 0; i < count; i++) {
		if (errs[i] == CIDR_OK) {
			PyObject *addr_obj = binding_addr_to_pyobj(&out[i]);

			if (addr_obj == NULL)
				goto error;
			/* PyList_SetItem steals addr_obj reference. */
			if (PyList_SetItem(result, i, addr_obj) < 0)
				goto error;
		} else {
			Py_INCREF(Py_None);
			if (PyList_SetItem(result, i, Py_None) < 0)
				goto error;
		}
	}

	/* After full batch, raise on the return code (precedence handled
	 * by cidr_bulk_parse). */
	if (rc != CIDR_OK) {
		cidr_set_python_error(rc, NULL);
		goto error;
	}

	Py_DECREF(fast);
	Py_DECREF(utf8_hold);
	// NOLINTNEXTLINE(bugprone-multi-level-implicit-pointer-conversion)
	free((void *)srcs);
	free(out);
	free(errs);
	return result;

error:
	Py_XDECREF(result);
	Py_DECREF(fast);
	Py_XDECREF(utf8_hold);
	// NOLINTNEXTLINE(bugprone-multi-level-implicit-pointer-conversion)
	free((void *)srcs);
	free(out);
	free(errs);
	return NULL;
}

/*
 * libcidr.bulk_contains(addrs, prefixes) -> list
 *
 * For each address, return the index of the first matching prefix, or -1
 * if no prefix matched. Backed by cidr_bulk_contains(). Mixed-family
 * input raises FamilyError. See ARCHITECTURE.md §8.8.1.
 */
static PyObject *
libcidr_bulk_contains(PyObject *self, PyObject *args)
{
	PyObject *addrs_obj;
	PyObject *prefixes_obj;
	cidr_addr_t *addrs = NULL;
	cidr_prefix_t *prefixes = NULL;
	size_t addr_count;
	size_t prefix_count;
	cidr_family_t addr_fam;
	cidr_family_t prefix_fam;
	ssize_t *matches = NULL;
	cidr_err_t rc;
	PyObject *result = NULL;

	(void)self;

	if (!PyArg_ParseTuple(args, "OO", &addrs_obj, &prefixes_obj))
		return NULL;

	addrs = bulk_addrs_from_list(addrs_obj, &addr_count, &addr_fam);
	if (addrs == NULL)
		return NULL;

	prefixes =
	    bulk_extract_prefixes(prefixes_obj, &prefix_count, &prefix_fam);
	if (prefixes == NULL)
		goto error;

	matches = malloc(addr_count * sizeof(ssize_t));
	if (matches == NULL && addr_count > 0) {
		PyErr_NoMemory();
		goto error;
	}

	if (addr_count > 0 && prefix_count > 0 && addr_fam != prefix_fam) {
		PyErr_SetString(
		    libcidr_FamilyError,
		    "address family mismatch between addrs and prefixes");
		goto error;
	}

	rc = cidr_bulk_contains(addrs, addr_count, prefixes, prefix_count,
	                        matches, NULL);
	if (rc != CIDR_OK) {
		cidr_set_python_error(rc, NULL);
		goto error;
	}

	result = PyList_New((Py_ssize_t)addr_count);
	if (result == NULL)
		goto error;

	for (size_t i = 0; i < addr_count; i++) {
		PyObject *item = PyLong_FromSsize_t(matches[i]);

		if (item == NULL)
			goto error;
		if (PyList_SetItem(result, (Py_ssize_t)i, item) < 0)
			goto error;
	}

	free(matches);
	free(prefixes);
	free(addrs);
	return result;

error:
	Py_XDECREF(result);
	free(matches);
	free(prefixes);
	free(addrs);
	return NULL;
}

/*
 * libcidr.bulk_aggregate(prefixes) -> list
 *
 * Aggregate a list of networks to a minimal covering set. Returns a new
 * list; the input is not modified. Backed by cidr_bulk_aggregate().
 * Mixed-family input raises FamilyError. See ARCHITECTURE.md §8.8.1.
 */
static PyObject *
libcidr_bulk_aggregate(PyObject *self, PyObject *args)
{
	PyObject *prefixes_obj;
	cidr_prefix_t *prefixes = NULL;
	cidr_prefix_t *copy = NULL;
	size_t count;
	size_t out_count;
	cidr_family_t fam;
	cidr_err_t rc;
	PyObject *result = NULL;

	(void)self;

	if (!PyArg_ParseTuple(args, "O", &prefixes_obj))
		return NULL;

	prefixes = bulk_extract_prefixes(prefixes_obj, &count, &fam);
	if (prefixes == NULL)
		return NULL;

	if (count == 0) {
		free(prefixes);
		return PyList_New(0);
	}

	/*
	 * Copy the prefix array: cidr_bulk_aggregate operates in place
	 * on the caller's array. We must not modify the caller's list.
	 * See ARCHITECTURE.md §8.8.1.
	 */
	copy = malloc(count * sizeof(cidr_prefix_t));
	if (copy == NULL) {
		PyErr_NoMemory();
		goto error;
	}
	// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
	memcpy(copy, prefixes, count * sizeof(cidr_prefix_t));

	rc = cidr_bulk_aggregate(copy, count, &out_count);
	if (rc != CIDR_OK) {
		cidr_set_python_error(rc, NULL);
		goto error;
	}

	/* Build result from the first out_count prefixes. */
	result = PyList_New((Py_ssize_t)out_count);
	if (result == NULL)
		goto error;

	for (size_t i = 0; i < out_count; i++) {
		PyObject *net_obj = binding_prefix_to_pyobj(&copy[i]);

		if (net_obj == NULL)
			goto error;
		if (PyList_SetItem(result, (Py_ssize_t)i, net_obj) < 0)
			goto error;
	}

	free(copy);
	free(prefixes);
	return result;

error:
	Py_XDECREF(result);
	free(copy);
	free(prefixes);
	return NULL;
}

/*
 * libcidr.bulk_sort(prefixes, order) -> list
 *
 * Sort a list of networks in the specified order. Returns a new list;
 * the input is not modified. Backed by cidr_bulk_sort().
 * See ARCHITECTURE.md §8.8.1.
 */
static PyObject *
libcidr_bulk_sort(PyObject *self, PyObject *args)
{
	PyObject *prefixes_obj;
	int order;
	cidr_prefix_t *prefixes = NULL;
	cidr_prefix_t *copy = NULL;
	size_t count;
	cidr_family_t fam;
	cidr_err_t rc;
	PyObject *result = NULL;

	(void)self;

	if (!PyArg_ParseTuple(args, "Oi", &prefixes_obj, &order))
		return NULL;

	prefixes = bulk_extract_prefixes(prefixes_obj, &count, &fam);
	if (prefixes == NULL)
		return NULL;

	if (count == 0) {
		free(prefixes);
		return PyList_New(0);
	}

	/*
	 * Copy the prefix array: cidr_bulk_sort operates in place on the
	 * caller's array. We must not modify the caller's list.
	 * See ARCHITECTURE.md §8.8.1.
	 */
	copy = (cidr_prefix_t *)malloc(count * sizeof(cidr_prefix_t));
	if (copy == NULL) {
		PyErr_NoMemory();
		goto error;
	}
	// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
	memcpy(copy, prefixes, count * sizeof(cidr_prefix_t));

	rc = cidr_bulk_sort(copy, count, (cidr_sort_order_t)order);
	if (rc != CIDR_OK) {
		cidr_set_python_error(rc, NULL);
		goto error;
	}

	result = PyList_New((Py_ssize_t)count);
	if (result == NULL)
		goto error;

	for (size_t i = 0; i < count; i++) {
		PyObject *net_obj = binding_prefix_to_pyobj(&copy[i]);

		if (net_obj == NULL)
			goto error;
		if (PyList_SetItem(result, (Py_ssize_t)i, net_obj) < 0)
			goto error;
	}

	free(copy);
	free(prefixes);
	return result;

error:
	Py_XDECREF(result);
	free(copy);
	free(prefixes);
	return NULL;
}

/*
 * Module method table.
 */
static PyMethodDef libcidr_methods[] = {
    {"bulk_parse", libcidr_bulk_parse, METH_VARARGS,
     "bulk_parse(srcs) -> list\n\n"
     "Parse a list of address strings. All items are attempted; "
     "failed items appear as None. Raises ParseError or FamilyError "
     "after the full batch completes."},
    {"bulk_contains", libcidr_bulk_contains, METH_VARARGS,
     "bulk_contains(addrs, prefixes) -> list\n\n"
     "For each address, return the index of the first matching "
     "prefix, or -1 if no prefix matched."},
    {"bulk_aggregate", libcidr_bulk_aggregate, METH_VARARGS,
     "bulk_aggregate(prefixes) -> list\n\n"
     "Aggregate a list of networks to a minimal covering set. "
     "Returns a new list; the input is not modified."},
    {"bulk_sort", libcidr_bulk_sort, METH_VARARGS,
     "bulk_sort(prefixes, order) -> list\n\n"
     "Sort a list of networks in the specified order "
     "(SORT_NETWORK_ASC or SORT_PFXLEN_DESC). Returns a new list; "
     "the input is not modified."},
    {NULL, NULL, 0, NULL}};

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

	/* --- Type registration: IPv4Network, IPv6Network, SubnetIterator ---
	 */
	/* See ARCHITECTURE.md §8.7, §8.9. */

	{
		PyObject *v4ntype = PyType_FromSpec(&ipv4network_spec);

		if (v4ntype == NULL)
			goto error;
		ipv4network_type = (PyTypeObject *)v4ntype;
		Py_INCREF(v4ntype);
		if (PyModule_AddObject(m, "IPv4Network", v4ntype) < 0)
			goto error;
	}
	{
		PyObject *v6ntype = PyType_FromSpec(&ipv6network_spec);

		if (v6ntype == NULL)
			goto error;
		ipv6network_type = (PyTypeObject *)v6ntype;
		Py_INCREF(v6ntype);
		if (PyModule_AddObject(m, "IPv6Network", v6ntype) < 0)
			goto error;
	}
	{
		PyObject *stype = PyType_FromSpec(&subnetiterator_spec);

		if (stype == NULL)
			goto error;
		subnetiterator_type = (PyTypeObject *)stype;
		Py_INCREF(stype);
		if (PyModule_AddObject(m, "SubnetIterator", stype) < 0)
			goto error;
	}

	return m;

error:
	Py_XDECREF((PyObject *)ipv4address_type);
	ipv4address_type = NULL;
	Py_XDECREF((PyObject *)ipv6address_type);
	ipv6address_type = NULL;
	Py_XDECREF((PyObject *)ipv4network_type);
	ipv4network_type = NULL;
	Py_XDECREF((PyObject *)ipv6network_type);
	ipv6network_type = NULL;
	Py_XDECREF((PyObject *)subnetiterator_type);
	subnetiterator_type = NULL;
	Py_DECREF(m);
	return NULL;
}
