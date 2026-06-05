/*
 * _libcidr_ext.c - CPython binding layer for libcidr.
 *
 * Stable ABI: Py_LIMITED_API = 0x030B0000 (CPython 3.11+).
 * No IP arithmetic logic. Pure translation layer.
 * See ARCHITECTURE.md §8 for the binding specification.
 *
 * PyInit_libcidr -- module initialisation entry point.
 *
 * Creates the libcidr module with an empty method table.
 * Types, exceptions, and functions are registered in later phases.
 * Returns the module object on success, or NULL with an exception
 * set on failure.
 */

#define Py_LIMITED_API 0x030B0000
#include <Python.h>

/*
 * Module method table. Populated in later phases as Python-level
 * functions are added.
 */
static PyMethodDef libcidr_methods[] = {{NULL, NULL, 0, NULL}};

static struct PyModuleDef libcidr_module = {
    PyModuleDef_HEAD_INIT,
    "libcidr",
    NULL, /* m_doc */
    -1,   /* m_size: per-module state */
    libcidr_methods,
    NULL, /* m_slots */
    NULL, /* m_traverse */
    NULL, /* m_clear */
    NULL  /* m_free */
};

PyMODINIT_FUNC
PyInit_libcidr(void)
{
	return PyModule_Create(&libcidr_module);
}
