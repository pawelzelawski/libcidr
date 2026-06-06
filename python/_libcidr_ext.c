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
 *
 * Later phases add:
 *   7.2 - IPv4Address, IPv6Address types
 *   7.3 - IPv4Network, IPv6Network types
 *   7.4 - SubnetIterator type
 *   7.5 - Bulk entry points
 *   7.6 - memoryview entry point
 */

#define Py_LIMITED_API 0x030B0000
#include <Python.h>

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

/* Forward declaration (unused until Phase 7.2+ adds callers). */
static int cidr_set_python_error(cidr_err_t, const char *)
    __attribute__((unused));

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

	return m;

error:
	Py_DECREF(m);
	return NULL;
}
