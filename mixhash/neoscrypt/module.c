#include <Python.h>

#include "neoscrypt.h"

static PyObject *neoscrypt_getpowhash(PyObject *self, PyObject *args)
{
    unsigned char *output;
    PyObject *value;
#if PY_MAJOR_VERSION >= 3
    PyBytesObject *input;
#else
    PyStringObject *input;
#endif
    if (!PyArg_ParseTuple(args, "S", &input))
        return NULL;
    Py_INCREF(input);
    output = PyMem_Malloc(32);

#if PY_MAJOR_VERSION >= 3
    neoscrypt((unsigned char *)PyBytes_AsString((PyObject*) input), output);
#else
    neoscrypt((unsigned char *)PyString_AsString((PyObject*) input), output);
#endif

    Py_DECREF(input);
#if PY_MAJOR_VERSION >= 3
    value = Py_BuildValue("y#", output, 32);
#else
    value = Py_BuildValue("s#", output, 32);
#endif
    PyMem_Free(output);
    return value;
}

static PyMethodDef NeoScryptMethods[] = {
    { "getPoWHash", neoscrypt_getpowhash, METH_VARARGS, "Returns proof-of-work hash using NeoScrypt" },
    { NULL, NULL, 0, NULL }
};

PyMODINIT_FUNC initneoscrypt(void) {
    (void) Py_InitModule("neoscrypt", NeoScryptMethods);
}
