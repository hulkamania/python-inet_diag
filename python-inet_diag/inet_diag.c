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
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <linux/inet_diag.h>
#include <linux/sock_diag.h>

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <netdb.h>
#include <dirent.h>
#include <fnmatch.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include "diag_filter.h"
#ifndef __unused
#define __unused __attribute__ ((unused))
#endif
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#ifndef NETLINK_INET_DIAG
#define NETLINK_INET_DIAG 4
#endif

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

static const int listen_states = (1<<SS_LISTEN) | (1<<SS_CLOSE);

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
    struct user_ent *proc;
	char *ext_congestion;
};

/* destructor */
static void inet_socket__dealloc(struct inet_socket *self)
{
	free(self->ext_memory);
	free(self->ext_protocol);
    free(self->proc);
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

/* process and user lookup */
struct user_ent {
    struct user_ent *next;
    unsigned int    ino;
    int             pid;
    int             fd;
    char            process[4096];
};

#define USER_ENT_HASH_SIZE  256
struct user_ent *user_ent_hash[USER_ENT_HASH_SIZE] = {0};

int show_users = 0;

static int user_ent_hashfn(unsigned int ino)
{
    int val = (ino >> 24) ^ (ino >> 16) ^ (ino >> 8) ^ ino;

    return val & (USER_ENT_HASH_SIZE - 1);
}

static void user_ent_add(unsigned int ino, int pid, int fd)
{
    struct user_ent *p, **pp;

    p = malloc(sizeof(struct user_ent));
    if (!p)
        abort();
    p->next = NULL;
    p->ino = ino;
    p->pid = pid;
    p->fd = fd;

    pp = &user_ent_hash[user_ent_hashfn(ino)];
    p->next = *pp;
    *pp = p;
}

static void user_ent_hash_build(void)
{   
    const char *root = getenv("PROC_ROOT") ? : "/proc/";
    struct dirent *d;
    char name[1024];
    int nameoff;
    DIR *dir;

    strcpy(name, root);
    if (strlen(name) == 0 || name[strlen(name)-1] != '/')
        strcat(name, "/");

    nameoff = strlen(name);

    dir = opendir(name);
    if (!dir)
        return;

    while ((d = readdir(dir)) != NULL) {
        struct dirent *d1;
        int pid, pos;
        DIR *dir1;
        char crap;

        if (sscanf(d->d_name, "%d%c", &pid, &crap) != 1)
            continue;

        sprintf(name + nameoff, "%d/fd/", pid);
        pos = strlen(name);
        if ((dir1 = opendir(name)) == NULL)
            continue;

        while ((d1 = readdir(dir1)) != NULL) {
            const char *pattern = "socket:[";
            unsigned int ino;
            char lnk[64];
            int fd;
            ssize_t link_len;

            if (sscanf(d1->d_name, "%d%c", &fd, &crap) != 1)
                continue;

            sprintf(name+pos, "%d", fd);

            link_len = readlink(name, lnk, sizeof(lnk)-1);
            if (link_len == -1)
                continue;
            lnk[link_len] = '\0';

            if (strncmp(lnk, pattern, strlen(pattern)))
                continue;

            sscanf(lnk, "socket:[%u]", &ino);

            user_ent_add(ino, pid, fd);
        }
        closedir(dir1);
    }
    closedir(dir);
}

static int find_users(unsigned ino, struct user_ent *found)
{
    struct user_ent *p;
    int cnt = 0;

    if (!ino)
        return 0;

    p = user_ent_hash[user_ent_hashfn(ino)];
    while (p) {
        if (p->ino != ino)
            goto next;

        found->ino  = p->ino;
        found->fd   = p->fd;
        found->pid  = p->pid;
        found->next = NULL;

        cnt++;
    next:
        p = p->next;
    }

    //get the full process path
    char tmp[4096];
    const char *root = getenv("PROC_ROOT") ? : "/proc/";

    snprintf(tmp, sizeof(tmp), "%s/%d/exe", root, found->pid);
    char *bin_path = canonicalize_file_name(tmp);
    if ( bin_path != NULL ) {
        strncpy(found->process, bin_path, 4096);
        free(bin_path);
    }

    return cnt;
}

static void clear_users(void)
{
    struct user_ent *p;
    struct user_ent *temp;
    int i;

    for (i = 0; i < USER_ENT_HASH_SIZE; i++) {
        if ( user_ent_hash[i] != 0 ) {
            p = user_ent_hash[i];
            while ( p != NULL ) {
                temp = p;
                p    = p->next;
                free(temp);
            }
        }
    user_ent_hash[i] = 0;
    }
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
"sock() -- get internet socket pointer";
static PyObject *inet_socket__sock(struct inet_socket *self,
				   PyObject *args __unused)
{
	return Py_BuildValue("l", (((unsigned long)self->msg.id.idiag_cookie[0]) << 32) |
				  self->msg.id.idiag_cookie[1]);
}

static char inet_socket__congestion_algorithm_doc__[] =
"congestion_algorithm() -- get internet socket congestion algorithm being used";
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

static char inet_socket__process_doc__[] =
"process() -- get name of process";
static PyObject *inet_socket__process(struct inet_socket *self,
                    PyObject *args __unused)
{
    if (self->proc == NULL) {
        PyErr_SetString(PyExc_OSError,          
                "no process found or proc not specified");
        return NULL;
    }
    return PyString_FromString(self->proc->process);
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
		
#define INET_SOCK__PROC_INT_METHOD(name, field, doc)            \
static char inet_socket__##name##_doc__[] = #name "() -- " doc; \
static PyObject *inet_socket__##name(struct inet_socket *self,  \
                     PyObject *args __unused)   \
{ return Py_BuildValue("i", self->proc->field); }

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
INET_SOCK__PROC_INT_METHOD(pid, pid,
              "get process id");
INET_SOCK__PROC_INT_METHOD(fd, fd,
              "get file descriptor");

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
    INET_SOCK__METHOD(process),
    INET_SOCK__METHOD(pid),
    INET_SOCK__METHOD(fd),
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
static PyObject *inet_socket__new(struct inet_diag_msg *r, int nlmsg_len, struct user_ent *proc)
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
    self->proc = NULL;

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

        if( proc != NULL) {
            self->proc = malloc(sizeof(*self->proc));
            if (self->proc == NULL)
                goto out_err;
            self->proc->ino = proc->ino;
            self->proc->pid = proc->pid;
            self->proc->fd = proc->fd;
            strcpy(self->proc->process, proc->process);
        }
	}
    free(proc);

	return (PyObject *)self;
out_err:
	PyErr_SetNone(PyExc_MemoryError);
	Py_XDECREF(self);
	return NULL;
}

struct inet_diag {
	PyObject_HEAD
	int                socket;		/* NETLINK socket */
    char               *bytecode;   /* NETLINK filter */
    struct diag_filter *filter;     /* NETLINK filter */
	char               buf[8192];
	struct             nlmsghdr *h;
	size_t             len;
};

/* destructor */
static void inet_diag__dealloc(struct inet_diag *self)
{
	close(self->socket);
    clear_users();
    if ( self->bytecode != NULL ) {
        free(self->bytecode);
    }
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

    struct user_ent *found;
    if (!(found=malloc(sizeof(struct user_ent)))) abort();
    if ( show_users > 0 ) {
        find_users(r->idiag_inode, found);
    }

    return inet_socket__new(r, nlmsg_len, found);
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

struct aafilter
{
    int               family;
    int               mask;
    unsigned long int prefix;
    int               port;
    struct aafilter   *next;
};

static void filter_patch(char *a, int len, int reloc)
{
    while (len > 0) {
        struct inet_diag_bc_op *op = (struct inet_diag_bc_op*)a;
        if (op->no == len+4)
            op->no += reloc;
        len -= op->yes;
        a += op->yes;
    }
    if (len < 0)
        abort();
}

static int filter_bytecompile(struct diag_filter *f, char **bytecode)
{
    switch (f->type) {
        case DIAG_BC_AUTO:
    {
        if (!(*bytecode=malloc(4))) abort();
        ((struct inet_diag_bc_op*)*bytecode)[0] = (struct inet_diag_bc_op){ INET_DIAG_BC_AUTO, 4, 8 };
        return 4;
    }
        case DIAG_BC_D_COND:
        case DIAG_BC_S_COND:
    {
        struct aafilter *a = (void*)f->pred;
        struct aafilter *b;
        char *ptr;
        int  code = (f->type == DIAG_BC_D_COND ? INET_DIAG_BC_D_COND : INET_DIAG_BC_S_COND);
        int len = 0;

        for (b=a; b; b=b->next) {
            len += 4 + sizeof(struct inet_diag_hostcond);
            if (a->family == AF_INET6)
                len += 16;
            else
                len += 4;
            if (b->next)
                len += 4;
        }
        if (!(ptr = malloc(len))) abort();
        *bytecode = ptr;
        for (b=a; b; b=b->next) {
            struct inet_diag_bc_op *op = (struct inet_diag_bc_op *)ptr;
            int alen = (a->family == AF_INET6 ? 16 : 4);
            int oplen = alen + 4 + sizeof(struct inet_diag_hostcond);
            struct inet_diag_hostcond *cond = (struct inet_diag_hostcond*)(ptr+4);

            *op = (struct inet_diag_bc_op){ code, oplen, oplen+4 };
            cond->family = a->family;
            cond->port = a->port;
            cond->prefix_len = a->mask;
            memcpy(cond->addr, &a->prefix, alen);
            ptr += oplen;
            if (b->next) {
                op = (struct inet_diag_bc_op *)ptr;
                *op = (struct inet_diag_bc_op){ INET_DIAG_BC_JMP, 4, len - (ptr-*bytecode)};
                ptr += 4;
            }
        }
        return ptr - *bytecode;
    }
        case DIAG_BC_D_GE:
    {
        struct aafilter *x = (void*)f->pred;
        if (!(*bytecode=malloc(8))) abort();
        ((struct inet_diag_bc_op*)*bytecode)[0] = (struct inet_diag_bc_op){ INET_DIAG_BC_D_GE, 8, 12 };
        ((struct inet_diag_bc_op*)*bytecode)[1] = (struct inet_diag_bc_op){ 0, 0, x->port };
        return 8;
    }
        case DIAG_BC_D_LE:
    {
        struct aafilter *x = (void*)f->pred;
        if (!(*bytecode=malloc(8))) abort();
        ((struct inet_diag_bc_op*)*bytecode)[0] = (struct inet_diag_bc_op){ INET_DIAG_BC_D_LE, 8, 12 };
        ((struct inet_diag_bc_op*)*bytecode)[1] = (struct inet_diag_bc_op){ 0, 0, x->port };
        return 8;
    }
        case DIAG_BC_S_GE:
    {
        struct aafilter *x = (void*)f->pred;
        if (!(*bytecode=malloc(8))) abort();
        ((struct inet_diag_bc_op*)*bytecode)[0] = (struct inet_diag_bc_op){ INET_DIAG_BC_S_GE, 8, 12 };
        ((struct inet_diag_bc_op*)*bytecode)[1] = (struct inet_diag_bc_op){ 0, 0, x->port };
        return 8;
    }
        case DIAG_BC_S_LE:
    {
        struct aafilter *x = (void*)f->pred;
        if (!(*bytecode=malloc(8))) abort();
        ((struct inet_diag_bc_op*)*bytecode)[0] = (struct inet_diag_bc_op){ INET_DIAG_BC_S_LE, 8, 12 };
        ((struct inet_diag_bc_op*)*bytecode)[1] = (struct inet_diag_bc_op){ 0, 0, x->port };
        return 8;
    }

        case DIAG_FILTER_AND:
    {
        char *a1, *a2, *a, l1, l2;
        l1 = filter_bytecompile(f->pred, &a1);
        l2 = filter_bytecompile(f->post, &a2);
        if (!(a = malloc(l1+l2))) abort();
        memcpy(a, a1, l1);
        memcpy(a+l1, a2, l2);
        free(a1); free(a2);
        filter_patch(a, l1, l2);
        *bytecode = a;
        return l1+l2;
    }
        case DIAG_FILTER_OR:
    {
        char *a1, *a2, *a, l1, l2;
        l1 = filter_bytecompile(f->pred, &a1);
        l2 = filter_bytecompile(f->post, &a2);
        if (!(a = malloc(l1+l2+4))) abort();
        memcpy(a, a1, l1);
        memcpy(a+l1+4, a2, l2);
        free(a1); free(a2);
        *(struct inet_diag_bc_op*)(a+l1) = (struct inet_diag_bc_op){ INET_DIAG_BC_JMP, 4, l2+4 };
        *bytecode = a;
        return l1+l2+4;
    }
        case DIAG_FILTER_NOT:
    {
        char *a1, *a, l1;
        l1 = filter_bytecompile(f->pred, &a1);
        if (!(a = malloc(l1+4))) abort();
        memcpy(a, a1, l1);
        free(a1);
        *(struct inet_diag_bc_op*)(a+l1) = (struct inet_diag_bc_op){ INET_DIAG_BC_JMP, 4, 8 };
        *bytecode = a;
        return l1+4;
    }
        default:
        abort();
    }
}

/* constructor */
static char inet_diag_create__doc__[] =
"create([states, extensions, socktype, src, sport, dst, dport, le_spt, le_dpt, ge_spt, ge_dpt, join=DIAG_FILTER_AND])\n\n\
Creates a new inet_diag socket object. Filters include:\n\
- socket states (SENT, RECV, etc.)\n\
- source addr and source port (must be used together)\n\
- dest addr and dest port (must be used together)\n\
- <=, >= source and dest port\n\n\
All specified source and dest filters can either be joined with DIAG_FILTER_AND or DIAG_FILTER_OR.";
static PyObject *inet_diag__create(PyObject *mself __unused, PyObject *args,
				   PyObject *keywds)
{
	int states = default_states;
	int extensions = INET_DIAG_NONE;
    int socktype = IPPROTO_TCP;
    const char *src;
    const char *dst;
    int sport  = -1;
    int dport  = -1;
    int le_spt = -1;
    int le_dpt = -1;
    int ge_spt = -1;
    int ge_dpt = -1;
    int proc   = 0;
    int join   = DIAG_FILTER_AND;
    static char *kwlist[] = { "states", "extensions", "socktype", "src", "dst", "sport", "dport", "le_spt", "le_dpt", "ge_spt", "ge_dpt", "join", "proc" };
	struct inet_diag *self = PyObject_NEW(struct inet_diag,
					      &inet_diag_type);
	if (self == NULL)
		return NULL;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "|iiissiiiiiiii", kwlist,
                     &states, &extensions, &socktype, &src, &dst, &sport, &dport, &le_spt, &le_dpt, &ge_spt, &ge_dpt, &join, &proc))
		goto out_err;

    /* TODO: have different levels of process identification */
    if ( proc > 0 ) {
        show_users++;
        user_ent_hash_build();
    }

	self->socket = socket(AF_NETLINK, SOCK_RAW, NETLINK_INET_DIAG);
	if (self->socket < 0)
		goto out_err;

	struct sockaddr_nl nladdr = {
		.nl_family = AF_NETLINK,
	};

	struct {
		struct nlmsghdr nlh;
        struct inet_diag_req_v2 r;
	} req = {
		.nlh = {
			.nlmsg_len   = sizeof(req),
            .nlmsg_type  = SOCK_DIAG_BY_FAMILY,
			.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST,
			.nlmsg_seq   = 123456,
		},
		.r = {
            .sdiag_family    = AF_INET,
            .sdiag_protocol  = socktype,
			.idiag_states = states,
			.idiag_ext    = extensions,
		},
	};

    // filter preparation
    struct diag_filter *filter;
    int f_exists = 0;
    if ( src != NULL && sport != -1 ) {
        struct in_addr in_src = {};
        inet_aton(src, &in_src);

        filter = &(struct diag_filter){
            .type = DIAG_BC_S_COND,
            .pred = (void*)&(struct aafilter){
                .family = AF_INET,
                .mask   = 32,
                .prefix = in_src.s_addr,
                .port   = sport,
                .next   = NULL,
            },
            .post = NULL
        };
        f_exists = 1;
    }

    if ( dst != NULL && dport != -1 ) {
        struct in_addr in_dst = {};
        inet_aton(dst, &in_dst);

        struct diag_filter tmp_dst = (struct diag_filter){
            .type = DIAG_BC_D_COND,
            .pred = (void*)&(struct aafilter){
                .family = AF_INET,
                .mask   = 32,
                .prefix = in_dst.s_addr,
                .port   = dport,
                .next   = NULL,
            },
            .post = NULL
        };

        if ( f_exists != 0 ) {
            filter = &(struct diag_filter){
                .type = join,
                .pred = filter,
                .post = &tmp_dst,
            };
        } else {
            filter   = &tmp_dst;
            f_exists = 1;
        }
    }

    if ( le_spt != -1 ) {
        struct diag_filter tmp_le_spt = {
            .type = DIAG_BC_S_LE,
            .pred = (void*)&(struct aafilter){
                .port = le_spt,
                .next = NULL,
            },
            .post = NULL
        };

        if ( f_exists != 0 ) {
            filter = &(struct diag_filter){
                .type = join,
                .pred = filter,
                .post = &tmp_le_spt,
            };
        } else {
            filter   = &tmp_le_spt;
            f_exists = 1;
        }
    }

    if ( le_dpt != -1 ) {
        struct diag_filter tmp_le_dpt = {
            .type = DIAG_BC_D_LE,
            .pred = (void*)&(struct aafilter){
                .port = le_dpt,
                .next = NULL,
            },
            .post = NULL
        };

        if ( f_exists != 0 ) {
            filter = &(struct diag_filter){
                .type = join,
                .pred = filter,
                .post = &tmp_le_dpt,
            };
        } else {
            filter   = &tmp_le_dpt;
            f_exists = 1;
        }
    }

    if ( ge_spt != -1 ) {
        struct diag_filter tmp_ge_spt = {
            .type = DIAG_BC_S_GE,
            .pred = (void*)&(struct aafilter){
                .port = ge_spt,
                .next = NULL,
            },
            .post = NULL
        };

        if ( f_exists != 0 ) {
            filter = &(struct diag_filter){
                .type = join,
                .pred = filter,
                .post = &tmp_ge_spt,
            };
        } else {
            filter   = &tmp_ge_spt;
            f_exists = 1;
        }
    }

    if ( ge_dpt != -1 ) {
        struct diag_filter tmp_ge_dpt = {
            .type = DIAG_BC_D_GE,
            .pred = (void*)&(struct aafilter){
                .port = ge_dpt,
                .next = NULL,
            },
            .post = NULL
        };

        if ( f_exists != 0 ) {
            filter = &(struct diag_filter){
                .type = join,
                .pred = filter,
                .post = &tmp_ge_dpt,
            };
        } else {
            filter   = &tmp_ge_dpt;
            f_exists = 1;
        }
    }

    struct iovec iov[3];
    iov[0] = (struct iovec){
			.iov_base = &req,
			.iov_len  = sizeof(req),
	};

    // append the filter    
    struct rtattr rta; 

    int filter_len = 0;
    if ( f_exists != 0 ) {
        filter_len   = filter_bytecompile(filter, &(self->bytecode));
        rta.rta_type = INET_DIAG_REQ_BYTECODE;
        rta.rta_len  = RTA_LENGTH(filter_len);

        iov[1] = (struct iovec){ &rta, sizeof(rta) };
        iov[2] = (struct iovec){ self->bytecode, filter_len };

        req.nlh.nlmsg_len += RTA_LENGTH(filter_len);
    } else {
        self->bytecode = NULL;
    }

	struct msghdr msg = {
		.msg_name    = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov     = iov,
        .msg_iovlen  = ( f_exists != 0 ? 3 : 1 ),
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
    m = Py_InitModule3("inet_diag", python_inet_diag__methods, "Example:\n\n\
    > import inet_diag\n\
    > from socket import IPPROTO_TCP\n\
    > idiag = inet_diag.create(states = inet_diag.default_states, extensions = inet_diag.EXT_MEMORY, socktype = IPPROTO_TCP, le_dpt = 500)\n\
    > while True:\n\
    >     try:\n\
    >         s = idiag.get()\n\
    >     except:\n\
    >         break\n\
    >     print s");
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
    PyModule_AddIntConstant(m, "listen_states", listen_states);
	PyModule_AddIntConstant(m, "EXT_MEMORY",     1 << (INET_DIAG_MEMINFO - 1));
	PyModule_AddIntConstant(m, "EXT_PROTOCOL",   1 << (INET_DIAG_INFO - 1));
	PyModule_AddIntConstant(m, "EXT_TCP_VEGAS",  1 << (INET_DIAG_VEGASINFO - 1));
	PyModule_AddIntConstant(m, "EXT_CONGESTION", 1 << (INET_DIAG_CONG - 1));
	PyModule_AddIntConstant(m, "PROTO_OPT_TIMESTAMPS", TCPI_OPT_TIMESTAMPS);
	PyModule_AddIntConstant(m, "PROTO_OPT_SACK", TCPI_OPT_SACK);
	PyModule_AddIntConstant(m, "PROTO_OPT_WSCALE", TCPI_OPT_WSCALE);
	PyModule_AddIntConstant(m, "PROTO_OPT_ECN", TCPI_OPT_ECN);
	PyModule_AddIntConstant(m, "TCPDIAG_GETSOCK", TCPDIAG_GETSOCK);
	PyModule_AddIntConstant(m, "DCCPDIAG_GETSOCK", DCCPDIAG_GETSOCK);
    PyModule_AddIntConstant(m, "DIAG_FILTER_AND", DIAG_FILTER_AND);
    PyModule_AddIntConstant(m, "DIAG_FILTER_OR", DIAG_FILTER_OR);
}
