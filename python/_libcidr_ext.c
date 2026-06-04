/*
 * _libcidr_ext.c - CPython binding layer for libcidr.
 *
 * Stable ABI: Py_LIMITED_API = 0x030B0000 (CPython 3.11+).
 * No IP arithmetic logic. Pure translation layer.
 * See ARCHITECTURE.md §8 for the binding specification.
 */

#define Py_LIMITED_API 0x030B0000
#include <Python.h>

PyMODINIT_FUNC PyInit_libcidr(void)
{
	return PyModule_Create(NULL);
}
