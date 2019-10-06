/* pysslctx_psk_wrapper */
#include <search.h> /* for bsearch(3), bfind(3), bdelete(3), ... */

#define PY_SSIZE_T_CLEAN 1 /* PyArg_Parse() returne Py_ssize_t for s# */
#include <Python.h>

#include <structmember.h>

#include "openssl/ssl.h"

/* get the PySSLContext_PSK_Wrapper from a pointer to its sslctx, as
   the sslctx is all we get from OpenSSL, and we keep these in a tree. */
#define container_of(ptr, type, member) ({                      \
	const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
	(type *)( (char *)__mptr - offsetof(type,member) );})

void *ctx_to_wrapper_tree=NULL; /* managed via bsearch() and friends */

/* this is enough of the definition of typedef struct ... PySSLContext from
   cpython's _ssl.c to find the ctx member. */
typedef struct PySSLContext {
    PyObject_HEAD
    SSL_CTX *ctx;
    /* everything else is omitted */
} PySSLContext ;

/* this is our wrapper object, it stores a pointer to the python SSL context and
   the underlaying openssl SSL_CTX */
static PyTypeObject PySSLContext_PSK_Wrapper_Type;
typedef struct PySSLContext_PSK_Wrapper {
	PyObject_HEAD
	PySSLContext *pyctx;  /* PySSLContext */
	SSL_CTX *sslctx;     /* needed for tfind/tsearch/... */
	PyObject *py_psk_server_cb;
	PyObject *py_psk_client_cb;
} PySSLContext_PSK_Wrapper;

/* compare two indirect pointers, in this case pointing to SSL_CTX */
static int
ctx_to_wrapper_compare(const void *a, const void *b)
{
	SSL_CTX *ca = *((SSL_CTX**)a), *cb = *((SSL_CTX**)b);

	return (uintptr_t)(ca) - (uintptr_t)(cb);
}

/* prototypes for the openssl callbacks we need to implement */
static unsigned int psk_client_cb(SSL *ssl, const char *hint, char *identity,
	unsigned int max_identity_len, 	unsigned char *psk,
	unsigned int max_psk_len);

static unsigned int psk_server_cb(SSL *ssl, const char *identity, unsigned char *psk,
	unsigned int max_psk_len);

static PyObject *
PySSLContext_PSK_Wrapper_new(PyTypeObject *subtype, PyObject *args, PyObject *kwds)
{
	PyObject *pyctx;
	PySSLContext_PSK_Wrapper *self;

	(void) subtype;
	(void) kwds;

	/* first argument given *MUST* be a PySSLContext, otherwise truly
	   horrible things will happen! */
	if (!PyArg_ParseTuple(args, "O", &pyctx))
		return NULL;

	/* Fields not defined by the Python object header are not initialized! */
	if(!(self = PyObject_New(PySSLContext_PSK_Wrapper, &PySSLContext_PSK_Wrapper_Type)))
		return NULL;

	self->pyctx = (PySSLContext*)pyctx;
	self->sslctx = self->pyctx->ctx;
	self->py_psk_client_cb = NULL;
	self->py_psk_server_cb = NULL;

	if (!(tsearch(&(self->sslctx), &ctx_to_wrapper_tree, ctx_to_wrapper_compare))) {
		fprintf(stderr, "Out of memory! Should never happen!\n");
		Py_TYPE(self)->tp_free(self);
		return NULL;
	}

	fprintf(stderr, "Wrapper for PySSLContext %p, SSL_CTX %p generated at %p.\n",
		self->pyctx, self->sslctx, self);

	Py_INCREF(self->pyctx);

	/* register our generic callback with OpenSSL */
	SSL_CTX_set_psk_client_callback(self->sslctx, psk_client_cb);
	SSL_CTX_set_psk_server_callback(self->sslctx, psk_server_cb);

	return (PyObject*)self;
}

static void
PySSLContext_PSK_Wrapper_dealloc(PyObject *_self)
{
	PySSLContext_PSK_Wrapper *self = (PySSLContext_PSK_Wrapper*)_self;

	tdelete(&(self->sslctx), &ctx_to_wrapper_tree, ctx_to_wrapper_compare);

	Py_DECREF(self->pyctx);
	Py_TYPE(self)->tp_free(self);
}

/* given a SSL structure, get the CONTEXT, then find the context wrapper in the
  ctx_to_wrapper_tree using tfind(3). */

PySSLContext_PSK_Wrapper *
wrapper_from_ssl(SSL *ssl)
{
	SSL_CTX *ctx, ***ppctx;
	PySSLContext_PSK_Wrapper *wrap;

	ctx = SSL_get_SSL_CTX(ssl);

	/* we store pointers to pointers to SSL_CTX, so tfind returns
	   pointers to pointers to pointers to SSL_CTX */
	ppctx = tfind(&ctx, &ctx_to_wrapper_tree, ctx_to_wrapper_compare);
	if (!ppctx) {
		fprintf(stderr, "Could not find wrapper for SSL_CTX %p!\n", ctx);
		return NULL;
	}

	wrap = container_of(*ppctx, PySSLContext_PSK_Wrapper, sslctx);
	return wrap;
}

/*
     This callback function is called from OpenSSL.

     https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_psk_client_callback.html

     It's used to set the identity (to be sent to the server), and the preshared key.

     Puts psk and identity into the respective buffers (pointed to by the char* arguments,
     the maximum size is given as the _len). Identity is NUL terminated, length of
     PSK is returned.
*/
static unsigned int psk_client_cb(SSL *ssl, const char *hint, char *identity,
	unsigned int max_identity_len, 	unsigned char *psk,
	unsigned int max_psk_len)
{
	unsigned int ret = 0;
	const char *psk_buf, *identity_buf;
	PyObject *res; /* python function result */
	PyGILState_STATE gstate;
	PySSLContext_PSK_Wrapper *wrapper;
	Py_ssize_t psk_len, identity_len;

	if (!(wrapper = wrapper_from_ssl(ssl)))
		return -1;

	gstate = PyGILState_Ensure();

	if (!PyCallable_Check(wrapper->py_psk_client_cb)) {
		fprintf(stderr, "Callback function psk_client_cb is not callable!\n");
		goto release;
	}

	res = PyObject_CallFunction(wrapper->py_psk_client_cb, "s", hint);
	if (!res) {
		fprintf(stderr, "Could not call python callback!\n");
		goto release;
	}

	if(!PyArg_Parse(res, "(s#s#)", &psk_buf, &psk_len, &identity_buf, &identity_len)) {
		fprintf(stderr, "Python callback did not return two bytes/str!\n");
		goto decref;
	}

	if (psk_len > max_psk_len) {
		fprintf(stderr, "Python callback did return too many bytes %ld > %u!\n",
			psk_len, max_psk_len);
		goto decref;
	}

	if (identity_len + 1> max_identity_len) {
		fprintf(stderr, "Python callback did return too many bytes %ld+1 > %u!\n",
			identity_len, max_identity_len);
		goto decref;
	}

	memcpy(psk, psk_buf, psk_len);

	/* 0 terminated */
	memcpy(identity, identity_buf, identity_len);
	identity[max_identity_len] = '\0';

	ret = psk_len;
decref:
	Py_DECREF(res);
release:
	PyGILState_Release(gstate);
	return ret;
}

/* https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_psk_server_callback.html

The callback function is given the connection in parameter ssl, NUL-terminated
PSK identity sent by the client in parameter identity, and a buffer psk of length
max_psk_len bytes where the pre-shared key is to be stored.

The return value is the number of bytes returned as the preshared key. (put in psk)
*/

static unsigned int psk_server_cb(SSL *ssl, const char *identity, unsigned char *psk,
	unsigned int max_psk_len)
{
	unsigned int ret = 0;
	const char *psk_buf;
	PyObject *res; /* python function result */
	PyGILState_STATE gstate;
	PySSLContext_PSK_Wrapper *wrapper;
	Py_ssize_t psk_len;
	
	if (!(wrapper = wrapper_from_ssl(ssl)))
		return -1;

	gstate = PyGILState_Ensure();

	if (!PyCallable_Check(wrapper->py_psk_server_cb)) {
		fprintf(stderr, "Callback function psk_server_cb is not callable!\n");
		goto release;
	}

	res = PyObject_CallFunction(wrapper->py_psk_server_cb, "s", identity);
	if (!res) {
		fprintf(stderr, "Could not call python callback!\n");
		goto release;
	}

	if(!PyArg_Parse(res, "s#", &psk_buf, &psk_len)) {
		fprintf(stderr, "Python callback did not return bytes/str!\n");
		goto decref;
	}

	if (psk_len > max_psk_len) {
		fprintf(stderr, "Python callback did return too many bytes %ld > %u!\n",
			psk_len, max_psk_len);
		goto decref;
	}

	memcpy(psk, psk_buf, psk_len);
	ret = psk_len;

	fprintf(stderr, "Returned %u bytes.\n", ret);
decref:
	Py_DECREF(res);
release:
	PyGILState_Release(gstate);
	return ret;
}

PyMemberDef PySSLContext_PSK_Wrapper_members[] = {
	{
		.name = "psk_client_cb",
		.type = T_OBJECT_EX,
		.offset = offsetof(PySSLContext_PSK_Wrapper, py_psk_client_cb)
	},
	{
		.name = "psk_server_cb",
		.type = T_OBJECT_EX,
		.offset = offsetof(PySSLContext_PSK_Wrapper, py_psk_server_cb)
	},
	{ NULL }
};

static PyGetSetDef PySSLContext_PSK_Wrapper_getset[] = {
	{ NULL }
};

static PyTypeObject PySSLContext_PSK_Wrapper_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "PySSLContext_PSK_Wrapper",
	.tp_basicsize = sizeof(PySSLContext_PSK_Wrapper),
	.tp_dealloc = PySSLContext_PSK_Wrapper_dealloc,
	.tp_new = PySSLContext_PSK_Wrapper_new,
	.tp_getset = PySSLContext_PSK_Wrapper_getset,
	.tp_members = PySSLContext_PSK_Wrapper_members
};

/* === Module === */

static struct PyModuleDef pysslcontext_psk_wrapper = {
	.m_base = PyModuleDef_HEAD_INIT,
	.m_name = "pysslcontext_psk_wrapper"
};

PyMODINIT_FUNC
PyInit_pysslcontext_psk_wrapper(void)
{
	PyObject *m, *d;

	if (PyType_Ready(&PySSLContext_PSK_Wrapper_Type) == -1) {
		fprintf(stderr, "PyType_Ready(PySSLContext_PSK_Wrapper_Type) returned -1!\n");
		return NULL;
	}

	m = PyModule_Create(&pysslcontext_psk_wrapper);
	d = PyModule_GetDict(m);

	PyDict_SetItemString(d, "PySSLContext_PSK_Wrapper",
		(PyObject *)&PySSLContext_PSK_Wrapper_Type);

	return m;
}