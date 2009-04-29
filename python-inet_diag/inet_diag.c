/*
 * Copyright (C) 2009 Red Hat Inc.
 *
 * Arnaldo Carvalho de Melo <acme@redhat.com>
 *
 * Using code from the iproute2 package which was written mostly by:
 *
 * Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 * This application is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; version 2.
 *
 * This application is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */
#include <Python.h>

#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <arpa/inet.h>
#include "inet_diag_copy.h"

#ifndef __unused
#define __unused __attribute__ ((unused))
#endif
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

enum {
	TCP_DB,
	DCCP_DB,
	UDP_DB,
	RAW_DB,
	UNIX_DG_DB,
	UNIX_ST_DB,
	PACKET_DG_DB,
	PACKET_R_DB,
	NETLINK_DB,
	MAX_DB
};

enum {
	SS_UNKNOWN,
	SS_ESTABLISHED,
	SS_SYN_SENT,
	SS_SYN_RECV,
	SS_FIN_WAIT1,
	SS_FIN_WAIT2,
	SS_TIME_WAIT,
	SS_CLOSE,
	SS_CLOSE_WAIT,
	SS_LAST_ACK,
	SS_LISTEN,
	SS_CLOSING,
	SS_MAX
};

static const char *sstate_name[] = {
	"UNKNOWN",
	[SS_ESTABLISHED] = "ESTAB",
	[SS_SYN_SENT]	 = "SYN-SENT",
	[SS_SYN_RECV]	 = "SYN-RECV",
	[SS_FIN_WAIT1]	 = "FIN-WAIT-1",
	[SS_FIN_WAIT2]	 = "FIN-WAIT-2",
	[SS_TIME_WAIT]	 = "TIME-WAIT",
	[SS_CLOSE]	 = "UNCONN",
	[SS_CLOSE_WAIT]  = "CLOSE-WAIT",
	[SS_LAST_ACK]	 = "LAST-ACK",
	[SS_LISTEN]	 = "LISTEN",
	[SS_CLOSING]	 = "CLOSING",
};

#define SS_ALL ((1 << SS_MAX) - 1)

static int default_states = SS_ALL & ~((1 << SS_LISTEN) |
				       (1 << SS_CLOSE) |
				       (1 << SS_TIME_WAIT) |
				       (1 << SS_SYN_RECV));

static const char *tmr_name[] = {
	"off",
	"on",
	"keepalive",
	"timewait",
	"persist",
	"unknown"
};

struct inet_socket {
	PyObject_HEAD
	struct inet_diag_msg msg;
};

/* destructor */
static void inet_socket__dealloc(struct inet_socket *self)
{
	PyObject_Del(self);
}

/* prints query object in human readable format */
static int inet_socket__print(struct inet_socket *self, FILE *fp,
			      int flags __unused)
{
	char bufsaddr[1024];
	char bufdaddr[1024];
	inet_ntop(self->msg.idiag_family, &self->msg.id.idiag_src,
		  bufsaddr, sizeof(bufsaddr));
	inet_ntop(self->msg.idiag_family, &self->msg.id.idiag_dst,
		  bufdaddr, sizeof(bufdaddr));
	fprintf(fp, "<inet_socket state=%s rqueue=%d wqueue=%d "
		    "saddr=%s sport=%d "
		    "daddr=%s dport=%d>",
		sstate_name[self->msg.idiag_state],
		self->msg.idiag_rqueue,
		self->msg.idiag_wqueue,
		bufsaddr, ntohs(self->msg.id.idiag_sport),
		bufdaddr, ntohs(self->msg.id.idiag_dport));
	return 0;
}

static char inet_socket__daddr_doc__[] =
"daddr() -- get internet socket destination address";
static PyObject *inet_socket__daddr(struct inet_socket *self,
				    PyObject *args __unused)
{
	char buf[1024];
	inet_ntop(self->msg.idiag_family, &self->msg.id.idiag_dst,
		  buf, sizeof(buf));
	return PyString_FromString(buf);
}

static char inet_socket__saddr_doc__[] =
"saddr() -- get internet socket source address";
static PyObject *inet_socket__saddr(struct inet_socket *self,
				    PyObject *args __unused)
{
	char buf[1024];
	inet_ntop(self->msg.idiag_family, &self->msg.id.idiag_src,
		  buf, sizeof(buf));
	return PyString_FromString(buf);
}

#define INET_SOCK__STR_METHOD(name, field, table, doc)		\
static char inet_socket__##name##_doc__[] = #name "() -- " doc;	\
static PyObject *inet_socket__##name(struct inet_socket *self,	\
				     PyObject *args __unused)	\
{ return PyString_FromString(table[self->msg.field]); }

#define INET_SOCK__INT_METHOD(name, field, doc)			\
static char inet_socket__##name##_doc__[] = #name "() -- " doc;	\
static PyObject *inet_socket__##name(struct inet_socket *self,	\
				     PyObject *args __unused)	\
{ return Py_BuildValue("i", self->msg.field); }

INET_SOCK__INT_METHOD(dport, id.idiag_dport,
		      "get internet socket destination port");
INET_SOCK__INT_METHOD(sport, id.idiag_sport,
		      "get internet socket source port");
INET_SOCK__INT_METHOD(bound_iface, id.idiag_if,
		      "get interface this socket is bound to");
INET_SOCK__INT_METHOD(family, idiag_family,
		      "get address family of this socket");
INET_SOCK__INT_METHOD(receive_queue, idiag_rqueue,
		      "get internet socket receive queue length");
INET_SOCK__INT_METHOD(write_queue, idiag_wqueue,
		      "get internet socket write queue length");
INET_SOCK__INT_METHOD(inode, idiag_inode,
		      "get internet socket associated inode");
INET_SOCK__STR_METHOD(state, idiag_state, sstate_name,
		      "get internet socket state");
INET_SOCK__STR_METHOD(timer, idiag_timer, tmr_name,
		      "get internet socket running timer");
INET_SOCK__INT_METHOD(timer_expiration, idiag_expires,
		      "get expiration time (in ms) for running timer");
INET_SOCK__INT_METHOD(retransmissions, idiag_retrans,
		      "get connection retransmissions timer");
INET_SOCK__INT_METHOD(uid, idiag_uid,
		      "get connection owner user id");

#define INET_SOCK__METHOD(name)	{			\
	.ml_name  = #name,				\
	.ml_meth  = (PyCFunction)inet_socket__##name,	\
	.ml_doc	  = inet_socket__##name##_doc__,	\
}

static struct PyMethodDef inet_socket__methods[] = {
	INET_SOCK__METHOD(bound_iface),
	INET_SOCK__METHOD(daddr),
	INET_SOCK__METHOD(saddr),
	INET_SOCK__METHOD(dport),
	INET_SOCK__METHOD(sport),
	INET_SOCK__METHOD(family),
	INET_SOCK__METHOD(receive_queue),
	INET_SOCK__METHOD(write_queue),
	INET_SOCK__METHOD(inode),
	INET_SOCK__METHOD(state),
	INET_SOCK__METHOD(timer),
	INET_SOCK__METHOD(timer_expiration),
	INET_SOCK__METHOD(retransmissions),
	INET_SOCK__METHOD(uid),
	{ .ml_name = NULL, }
};

static PyObject *inet_socket__getattr(struct inet_socket *self, char *name)
{
	/* module name */
	if (!strcmp(name, "__module__"))
		return PyString_FromString("_inet_socket");

	/* class name */
	if (!strcmp(name, "__class__"))
		return PyString_FromString("inet_socket");

	/* seeks name in methods (fallback) */
	return Py_FindMethod(inet_socket__methods, (PyObject *)self, name);
}

static PyTypeObject inet_socket__type = {
	PyObject_HEAD_INIT(NULL)
	.tp_name	= "inet_socket",
	.tp_basicsize	= sizeof(struct inet_socket),
	.tp_dealloc	= (destructor)inet_socket__dealloc,
	.tp_print	= (printfunc)inet_socket__print,
	.tp_getattr	= (getattrfunc)inet_socket__getattr,
};

/* constructor */
static PyObject *inet_socket__new(struct inet_diag_msg *r)
{
	struct inet_socket *self;

	self = PyObject_NEW(struct inet_socket, &inet_socket__type);
	if (self == NULL)
		return NULL;

	self->msg = *r;
	if (self->msg.idiag_timer >= ARRAY_SIZE(tmr_name) - 1) {
		/* Unknown timer */
		self->msg.idiag_timer = ARRAY_SIZE(tmr_name) - 1;
	}

	return (PyObject *)self;
}

struct inet_diag {
	PyObject_HEAD
	int		socket;		/* NETLINK socket */
	char		buf[8192];
	struct nlmsghdr *h;
	int		len;
};

/* destructor */
static void inet_diag__dealloc(struct inet_diag *self)
{
	close(self->socket);
	PyObject_Del(self);
}

/* prints query object in human readable format */
static int inet_diag__print(struct inet_diag *self __unused,
			    FILE *fp, int flags __unused)
{
	if (self->socket >= 0)
		fprintf(fp, "<Opened inet_diag socket>");
	else
		fprintf(fp, "<Closed large object>");
	
	return 0;
}

static char inet_diag__get_doc__[] =
"read() -- read from inet_diag_sock. ";
static PyObject *inet_diag__get(struct inet_diag *self, PyObject *args __unused)
{
try_again_nlmsg_ok:
	if (!NLMSG_OK(self->h, self->len)) {
		struct sockaddr_nl nladdr;
try_again_recvmsg:
	{
		struct iovec iov[1] = {
			[0] = {
				.iov_base = self->buf,
				.iov_len  = sizeof(self->buf),
			},
		};
		struct msghdr msg = {
			.msg_name    = &nladdr,
			.msg_namelen = sizeof(nladdr),
			.msg_iov     = iov,
			.msg_iovlen  = 1,
		};
		self->len = recvmsg(self->socket, &msg, 0);

		if (self->len < 0) {
			if (errno == EINTR)
				goto try_again_recvmsg;
out_eof:
			close(self->socket);
			PyErr_SetString(PyExc_OSError, strerror(errno));
			return NULL;
		}

		if (self->len == 0) { /* EOF, how to signal properly? */
			close(self->socket);
			PyErr_SetNone(PyExc_EOFError);
			return NULL;
		}

		self->h = (void *)self->buf;
	}
	}

	if (self->h->nlmsg_seq != 123456) {
		self->h = NLMSG_NEXT(self->h, self->len);
		goto try_again_nlmsg_ok;
	}

	if (self->h->nlmsg_type == NLMSG_DONE)
		goto out_eof;

	if (self->h->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = NLMSG_DATA(self->h);
		if (self->h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
			PyErr_SetString(PyExc_OSError, "message truncated");
			close(self->socket);
		} else {
			errno = -err->error;
			PyErr_SetString(PyExc_OSError, strerror(errno));
			
		}
		return NULL;
	}

	struct inet_diag_msg *r = NLMSG_DATA(self->h);
	self->h = NLMSG_NEXT(self->h, self->len);

	return inet_socket__new(r);
}

static struct PyMethodDef inet_diag__methods[] = {
	{
		.ml_name  = "get",
		.ml_meth  = (PyCFunction)inet_diag__get,
		.ml_flags = METH_VARARGS,
		.ml_doc	  = inet_diag__get_doc__,
	},
	{
		.ml_name = NULL,
	}
};

static PyObject *inet_diag__getattr(struct inet_diag *self, char *name)
{
	/* module name */
	if (!strcmp(name, "__module__"))
		return PyString_FromString("_inet_diag");

	/* class name */
	if (!strcmp(name, "__class__"))
		return PyString_FromString("inet_diag");

	/* seeks name in methods (fallback) */
	return Py_FindMethod(inet_diag__methods, (PyObject *)self, name);
}

static PyTypeObject inet_diag_type = {
	PyObject_HEAD_INIT(NULL)
	.tp_name	= "inet_diag",
	.tp_basicsize	= sizeof(struct inet_diag),
	.tp_dealloc	= (destructor)inet_diag__dealloc,
	.tp_print	= (printfunc)inet_diag__print,
	.tp_getattr	= (getattrfunc)inet_diag__getattr,
};

/* constructor */
static char inet_diag_create__doc__[] =
"create() -- creates a new inet_diag socket.";
static PyObject *inet_diag__create(PyObject *args __unused)
{
	struct inet_diag *self = PyObject_NEW(struct inet_diag,
					      &inet_diag_type);
	if (self == NULL)
		return NULL;

	self->socket = socket(AF_NETLINK, SOCK_RAW, NETLINK_INET_DIAG);
	if (self->socket < 0)
		goto out_err;

	struct sockaddr_nl nladdr = {
		.nl_family = AF_NETLINK,
	};
	struct {
		struct nlmsghdr nlh;
		struct inet_diag_req r;
	} req = {
		.nlh = {
			.nlmsg_len   = sizeof(req),
			.nlmsg_type  = TCPDIAG_GETSOCK,
			.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST,
			.nlmsg_seq   = 123456,
		},
		.r = {
			.idiag_family = AF_INET,
			.idiag_states = default_states,
		},
	};
	struct iovec iov[1] = {
		[0] = {
			.iov_base = &req,
			.iov_len  = sizeof(req),
		},
	};
	struct msghdr msg = {
		.msg_name    = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov     = iov,
		.msg_iovlen  = 1,
	};

	if (sendmsg(self->socket, &msg, 0) < 0)
		goto out_err;

	self->len = 0;
	return (PyObject *)self;
out_err:
	PyErr_SetString(PyExc_OSError, strerror(errno));
	Py_XDECREF(self);
	return NULL;
}

static struct PyMethodDef python_inet_diag__methods[] = {
	{
		.ml_name  = "create",
		.ml_meth  = (PyCFunction)inet_diag__create,
		.ml_flags = METH_VARARGS,
		.ml_doc	  = inet_diag_create__doc__
	},
	{	.ml_name = NULL, },
};

PyMODINIT_FUNC initinet_diag(void)
{
	PyObject *m;
	m = Py_InitModule("inet_diag", python_inet_diag__methods);
	PyModule_AddIntConstant(m, "TCP_DB", TCP_DB); /* Select TCP sockets. */
	PyModule_AddIntConstant(m, "SS_ESTABLISHED", SS_ESTABLISHED);
	PyModule_AddIntConstant(m, "SS_SYN_SENT",    SS_SYN_SENT);
	PyModule_AddIntConstant(m, "SS_SYN_RECV",    SS_SYN_RECV);
	PyModule_AddIntConstant(m, "SS_FIN_WAIT1",   SS_FIN_WAIT1);
	PyModule_AddIntConstant(m, "SS_FIN_WAIT2",   SS_FIN_WAIT2);
	PyModule_AddIntConstant(m, "SS_TIME_WAIT",   SS_TIME_WAIT);
	PyModule_AddIntConstant(m, "SS_CLOSE",	     SS_CLOSE);
	PyModule_AddIntConstant(m, "SS_CLOSE_WAIT",  SS_CLOSE_WAIT);
	PyModule_AddIntConstant(m, "SS_LAST_ACK",    SS_LAST_ACK);
	PyModule_AddIntConstant(m, "SS_LISTEN",	     SS_LISTEN);
	PyModule_AddIntConstant(m, "SS_CLOSING",     SS_CLOSING);
}
