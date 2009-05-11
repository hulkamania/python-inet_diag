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
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include "inet_diag_copy.h"

#ifndef __unused
#define __unused __attribute__ ((unused))
#endif
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* From libnetlink */
static int parse_rtattr(struct rtattr *tb[], int max,
			struct rtattr *rta, int len)
{
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max)
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta,len);
	}
	if (len)
		fprintf(stderr, "!!!Deficit %d, rta_len=%d\n", len, rta->rta_len);
	return 0;
}

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

static const int default_states = SS_ALL & ~((1 << SS_LISTEN) |
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
	struct inet_diag_meminfo *ext_memory;
	struct tcp_info *ext_protocol;
	char *ext_congestion;
};

/* destructor */
static void inet_socket__dealloc(struct inet_socket *self)
{
	free(self->ext_memory);
	free(self->ext_protocol);
	free(self->ext_congestion);
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

static char inet_socket__sock_doc__[] =
"saddr() -- get internet socket pointer";
static PyObject *inet_socket__sock(struct inet_socket *self,
				   PyObject *args __unused)
{
	return Py_BuildValue("l", (((unsigned long)self->msg.id.idiag_cookie[0]) << 32) |
				  self->msg.id.idiag_cookie[1]);
}

static char inet_socket__congestion_algorithm_doc__[] =
"saddr() -- get internet socket congestion algorithm being used";
static PyObject *inet_socket__congestion_algorithm(struct inet_socket *self,
						   PyObject *args __unused)
{
	if (self->ext_congestion == NULL) {
		PyErr_SetString(PyExc_OSError,			
				"no congestion algorithm on this socket");
		return NULL;
	}
	return PyString_FromString(self->ext_congestion);
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

#define INET_SOCK__NET_INT_METHOD(name, field, doc)			\
static char inet_socket__##name##_doc__[] = #name "() -- " doc;	\
static PyObject *inet_socket__##name(struct inet_socket *self,	\
				     PyObject *args __unused)	\
{ return Py_BuildValue("i", ntohs(self->msg.field)); }

#define INET_SOCK__EXT_INT_METHOD(name, ext, field, doc)	\
static char inet_socket__##name##_doc__[] = #name "() -- " doc;	\
static PyObject *inet_socket__##name(struct inet_socket *self,	\
				     PyObject *args __unused)	\
{								\
	if (self->ext_##ext == NULL) {				\
		PyErr_SetString(PyExc_OSError,			\
				"extension not requested");	\
		return NULL;					\
	}							\
	return Py_BuildValue("l", self->ext_##ext->field); 	\
}
		
INET_SOCK__NET_INT_METHOD(dport, id.idiag_dport,
			  "get internet socket destination port");
INET_SOCK__NET_INT_METHOD(sport, id.idiag_sport,
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
INET_SOCK__EXT_INT_METHOD(receive_queue_memory, memory, idiag_rmem,
			  "get memory in bytes allocated for socket receive queue");
INET_SOCK__EXT_INT_METHOD(write_queue_used_memory, memory, idiag_wmem,
			  "get number of bytes queued from socket write queue");
INET_SOCK__EXT_INT_METHOD(write_queue_memory, memory, idiag_tmem,
			  "get number of bytes allocated for the socket write queue");
INET_SOCK__EXT_INT_METHOD(forward_alloc, memory, idiag_fmem,
			  "memory in bytes a socket can allocate before the "
			  "socket buffer autotuning routines enter memory pressure");
INET_SOCK__EXT_INT_METHOD(congestion_state, protocol, tcpi_ca_state,
			  "get socket congestion state");
INET_SOCK__EXT_INT_METHOD(windows_probes_out, protocol, tcpi_probes,
			  "get number of unanswered 0 window probes");
INET_SOCK__EXT_INT_METHOD(protocol_options, protocol, tcpi_options,
			  "get protocol specific options being used in the socket");
INET_SOCK__EXT_INT_METHOD(receive_window_scale_shift, protocol, tcpi_rcv_wscale,
			  "get receive window scale shift used in this socket");
INET_SOCK__EXT_INT_METHOD(send_window_scale_shift, protocol, tcpi_snd_wscale,
			  "get send window scale shift used in this socket");
INET_SOCK__EXT_INT_METHOD(rto, protocol, tcpi_rto,
			  "get retransmission timeout used on this socket");
INET_SOCK__EXT_INT_METHOD(rtt, protocol, tcpi_rtt,
			  "get round trip time calculated on this socket");
INET_SOCK__EXT_INT_METHOD(rttvar, protocol, tcpi_rttvar,
			  "get round trip time variation calculated on this socket");
INET_SOCK__EXT_INT_METHOD(ato, protocol, tcpi_ato,
			  "get socket ack timeout value");
INET_SOCK__EXT_INT_METHOD(cwnd, protocol, tcpi_snd_cwnd,
			  "get socket congestion window");
INET_SOCK__EXT_INT_METHOD(ssthresh, protocol, tcpi_snd_ssthresh,
			  "get socket slow start threshold");

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
	INET_SOCK__METHOD(sock),
	INET_SOCK__METHOD(family),
	INET_SOCK__METHOD(receive_queue),
	INET_SOCK__METHOD(write_queue),
	INET_SOCK__METHOD(inode),
	INET_SOCK__METHOD(state),
	INET_SOCK__METHOD(timer),
	INET_SOCK__METHOD(timer_expiration),
	INET_SOCK__METHOD(retransmissions),
	INET_SOCK__METHOD(uid),
	INET_SOCK__METHOD(receive_queue_memory),
	INET_SOCK__METHOD(write_queue_used_memory),
	INET_SOCK__METHOD(write_queue_memory),
	INET_SOCK__METHOD(forward_alloc),
	INET_SOCK__METHOD(congestion_state),
	INET_SOCK__METHOD(windows_probes_out),
	INET_SOCK__METHOD(protocol_options),
	INET_SOCK__METHOD(receive_window_scale_shift),
	INET_SOCK__METHOD(send_window_scale_shift),
	INET_SOCK__METHOD(congestion_algorithm),
	INET_SOCK__METHOD(rto),
	INET_SOCK__METHOD(rtt),
	INET_SOCK__METHOD(rttvar),
	INET_SOCK__METHOD(ato),
	INET_SOCK__METHOD(cwnd),
	INET_SOCK__METHOD(ssthresh),
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
static PyObject *inet_socket__new(struct inet_diag_msg *r, int nlmsg_len)
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

	self->ext_memory = NULL;
	self->ext_protocol = NULL;
	self->ext_congestion = NULL;

	if (nlmsg_len) {
		struct rtattr *tb[INET_DIAG_MAX + 1];

		parse_rtattr(tb, INET_DIAG_MAX, (struct rtattr *)(r + 1),
			     nlmsg_len);

		if (tb[INET_DIAG_MEMINFO]) {
			struct inet_diag_meminfo *minfo = RTA_DATA(tb[INET_DIAG_MEMINFO]);

			self->ext_memory = malloc(sizeof(*self->ext_memory));
			if (self->ext_memory == NULL)
				goto out_err;

			*self->ext_memory = *minfo;
		}

		if (tb[INET_DIAG_INFO]) {
			struct tcp_info *info = RTA_DATA(tb[INET_DIAG_INFO]);
			size_t len = RTA_PAYLOAD(tb[INET_DIAG_INFO]);

			self->ext_protocol = malloc(sizeof(*self->ext_protocol));
			if (self->ext_protocol == NULL)
				goto out_err;

			/* workaround for older kernels with less fields */
			if (len < sizeof(*info))
				memset(self->ext_protocol + len, 0,
				       sizeof(*info) - len);

			*self->ext_protocol = *info;
		}

		if (tb[INET_DIAG_CONG]) {
                        self->ext_congestion = strdup(RTA_DATA(tb[INET_DIAG_CONG]));
			if (self->ext_congestion == NULL)
				goto out_err;
		}
	}

	return (PyObject *)self;
out_err:
	PyErr_SetNone(PyExc_MemoryError);
	Py_XDECREF(self);
	return NULL;
}

struct inet_diag {
	PyObject_HEAD
	int		socket;		/* NETLINK socket */
	char		buf[8192];
	struct nlmsghdr *h;
	size_t		len;
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
		int len = recvmsg(self->socket, &msg, 0);

		if (len < 0) {
			if (errno == EINTR)
				goto try_again_recvmsg;
out_eof:
			close(self->socket);
			PyErr_SetString(PyExc_OSError, strerror(errno));
			return NULL;
		}

		if (len == 0) { /* EOF, how to signal properly? */
			close(self->socket);
			PyErr_SetNone(PyExc_EOFError);
			return NULL;
		}

		self->len = len;
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
	const int nlmsg_len = self->h->nlmsg_len - NLMSG_LENGTH(sizeof(*r));
	self->h = NLMSG_NEXT(self->h, self->len);

	return inet_socket__new(r, nlmsg_len);
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
static PyObject *inet_diag__create(PyObject *mself __unused, PyObject *args,
				   PyObject *keywds)
{
	int states = default_states;
	int extensions = INET_DIAG_NONE;
	static char *kwlist[] = { "states", "extensions", };
	struct inet_diag *self = PyObject_NEW(struct inet_diag,
					      &inet_diag_type);
	if (self == NULL)
		return NULL;

	if (!PyArg_ParseTupleAndKeywords(args, keywds, "|ii", kwlist,
					 &states, &extensions))
		goto out_err;

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
			.idiag_states = states,
			.idiag_ext    = extensions,
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
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
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
	PyModule_AddIntConstant(m, "SS_ALL",	     SS_ALL);
	PyModule_AddIntConstant(m, "default_states", default_states);
	PyModule_AddIntConstant(m, "EXT_MEMORY",     1 << (INET_DIAG_MEMINFO - 1));
	PyModule_AddIntConstant(m, "EXT_PROTOCOL",   1 << (INET_DIAG_INFO - 1));
	PyModule_AddIntConstant(m, "EXT_TCP_VEGAS",  1 << (INET_DIAG_VEGASINFO - 1));
	PyModule_AddIntConstant(m, "EXT_CONGESTION", 1 << (INET_DIAG_CONG - 1));
	PyModule_AddIntConstant(m, "PROTO_OPT_TIMESTAMPS", TCPI_OPT_TIMESTAMPS);
	PyModule_AddIntConstant(m, "PROTO_OPT_SACK", TCPI_OPT_SACK);
	PyModule_AddIntConstant(m, "PROTO_OPT_WSCALE", TCPI_OPT_WSCALE);
	PyModule_AddIntConstant(m, "PROTO_OPT_ECN", TCPI_OPT_ECN);
}
