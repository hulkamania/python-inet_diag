#! /usr/bin/python
# -*- python -*-
# -*- coding: utf-8 -*-
#   Copyright (C) 2009 Red Hat Inc.
#   Written by Arnaldo Carvalho de Melo <acme@redhat.com>
#
#   This application is free software; you can redistribute it and/or
#   modify it under the terms of the GNU General Public License
#   as published by the Free Software Foundation; version 2.
#
#   This application is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#   General Public License for more details.

import getopt, inet_diag, os, procfs, re, socket, sys

version="0.1"

def not_implemented(o):
	print "%s not implemented yet" % o 

state_width = 10
addr_width = 18
serv_width = 7
screen_width = 80
netid_width = 0
( TCP_DB,
  DCCP_DB,
  UDP_DB,
  RAW_DB,
  UNIX_DG_DB,
  UNIX_ST_DB,
  PACKET_DG_DB,
  PACKET_R_DB,
  NETLINK_DB,
  MAX_DB ) = range(10)

ALL_DB = ((1 << MAX_DB) - 1)

def print_ms_timer(s):
	timeout = s.timer_expiration()

	if timeout < 0:
		timeout = 0
	secs = timeout / 1000
	minutes = secs / 60
	secs = secs % 60
	msecs = timeout % 1000
	if minutes:
		msecs = 0
		rc = "%dmin" % minutes
		if minutes > 9:
			secs = 0
	else:
		rc = ""

	if secs:
		if secs > 9:
			msecs = 0
		rc += "%d%s" % (secs, msecs and "." or "sec")

	if msecs:
		rc += "%03dms" % msecs

	return rc

class socket_link:
	def __init__(self, pid, fd):
		self.pid = pid
		self.fd	 = fd

def print_sockets(states, families, socktype, show_options = False, show_mem = False,
		  show_protocol_info = False, show_details = False,
		  show_users = False):
	if show_users:
		ps = procfs.pidstats()
		inode_re = re.compile(r"socket:\[(\d+)\]")
		inodes = {}
		for pid in ps.keys():
			dirname = "/proc/%d/fd" % pid
			try:
				filenames = os.listdir(dirname)
			except: # Process died
				continue
			for fd in filenames:
				pathname = os.path.join(dirname, fd)
				try:
					linkto = os.readlink(pathname)
				except:
					break
				inode_match = inode_re.match(linkto)
				if not inode_match:
					continue
				inode = int(inode_match.group(1))
				sock = socket_link(pid, int(fd))
				if inodes.has_key(inode):
					inodes[inode].append(sock)
				else:
					inodes[inode] = [ sock, ]
	extensions = 0
	if show_mem:
		extensions |= inet_diag.EXT_MEMORY;
	if show_protocol_info:
		extensions |= inet_diag.EXT_PROTOCOL | inet_diag.EXT_CONGESTION;
	idiag = inet_diag.create(states = states, extensions = extensions,
				 socktype = socktype); 
	print "%-*s %-6s %-6s %*s:%-*s %*s:%-*s" % \
	      (state_width, "State",
	       "Recv-Q", "Send-Q",
	       addr_width, "Local Address",
	       serv_width, "Port",
	       addr_width, "Peer Address",
	       serv_width, "Port")
	while True:
		try:
			s = idiag.get()
		except:
			break
		if not (families & (1 << s.family())):
			continue
		print "%-*s %-6d %-6d %*s:%-*d %*s:%-*d " % \
		      (state_width, s.state(),
		       s.receive_queue(), s.write_queue(),
		       addr_width, s.saddr(), serv_width, s.sport(),
		       addr_width, s.daddr(), serv_width, s.dport()),
		if show_options:
			timer = s.timer()
			if timer != "off":
				print "timer:(%s,%s,%d)" % (timer,
							    print_ms_timer(s),
							    s.retransmissions()),
		if show_users:
			inode = s.inode()
			if inodes.has_key(inode):
				print "users:(" + \
				      ",".join(map(lambda sock: '("%s",%d,%d)' % (ps[sock.pid]["stat"]["comm"],
										  sock.pid, sock.fd),
						   inodes[inode])) + ")",

		if show_details:
			uid = s.uid()
			if uid:
				print "uid:%d" % uid,
			print "ino:%d sk:%x" % (s.inode(), s.sock()),

		if show_mem:
			try:
				print "\n\t mem:(r%u,w%u,f%u,t%u)" % \
					(s.receive_queue_memory(),
					 s.write_queue_used_memory(),
					 s.write_queue_memory(),
					 s.forward_alloc()),
			except:
				pass

		if show_protocol_info:
			try:
				options = s.protocol_options()
				if options & inet_diag.PROTO_OPT_TIMESTAMPS:
					print "ts",
				if options & inet_diag.PROTO_OPT_SACK:
					print "sack",
				if options & inet_diag.PROTO_OPT_ECN:
					print "ecn",
				print s.congestion_algorithm(),
				if options & inet_diag.PROTO_OPT_WSCALE:
					print "wscale:%d,%d" % (s.receive_window_scale_shift(),
							        s.send_window_scale_shift()),
			except:
				pass

			try:
				print "rto:%g" % s.rto(),
			except:
				pass

			try:
				print "rtt:%g/%g ato:%g cwnd:%d" % \
					(s.rtt() / 1000.0, s.rttvar() / 1000.0,
					 s.ato() / 1000.0, s.cwnd()),
			except:
				pass

			try:
				ssthresh = s.ssthresh()
				if ssthresh < 0xffff:
					print "ssthresh:%d" % ssthresh,
			except:
				pass

		print

def usage():
	print '''Usage: ss [ OPTIONS ]
       ss [ OPTIONS ] [ FILTER ]
   -h, --help		this message
   -V, --version	output version information
   -n, --numeric	don't resolve service names
   -r, --resolve	resolve host names
   -a, --all		display all sockets
   -l, --listening	display listening sockets
   -o, --options	show timer information
   -e, --extended	show detailed socket information
   -m, --memory		show socket memory usage
   -p, --processes	show process using socket
   -i, --info		show internal TCP information
   -s, --summary	show socket usage summary

   -4, --ipv4		display only IP version 4 sockets
   -6, --ipv6		display only IP version 6 sockets
   -0, --packet		display PACKET sockets
   -t, --tcp		display only TCP sockets
   -u, --udp		display only UDP sockets
   -d, --dccp		display only DCCP sockets
   -w, --raw		display only RAW sockets
   -x, --unix		display only Unix domain sockets
   -f, --family=FAMILY	display sockets of type FAMILY

   -A, --query=QUERY
       QUERY := {all|inet|tcp|udp|raw|unix|packet|netlink}[,QUERY]

   -F, --filter=FILE   read filter information from FILE
       FILTER := [ state TCP-STATE ] [ EXPRESSION ]'''

def main():
	global serv_width, state_width, addr_width, serv_width, \
	       screen_width, netid_width
	try:
		opts, args = getopt.getopt(sys.argv[1:],
					   "hVnraloempis460tudwxf:A:F:",
					   ("help", "version", "numeric",
					    "resolve", "all", "listening",
					    "options", "extended",
					    "memory", "processes", "info",
					    "summary", "ipv4", "ipv6",
					    "packet", "tcp", "udp",
					    "dccp", "raw", "unix",
					    "family=", "query=",
					    "filter="))
	except getopt.GetoptError, err:
		usage()
		print str(err)
		sys.exit(2)

	states = inet_diag.default_states
	families = (1 << socket.AF_INET) | (1 << socket.AF_INET6)
	resolve_ports = True

	if not opts:
		print_sockets(states, families, inet_diag.TCPDIAG_GETSOCK)
		sys.exit(0)

	show_options = False
	show_details = False
	show_mem = False
	show_protocol_info = False
	show_users = False
	dbs = 0

	for o, a in opts:
   		if o in ( "-V", "--version"):
			print version
   		elif o in ( "-n", "--numeric"):
			resolve_ports = False
			serv_width = 5
   		elif o in ( "-r", "--resolve"):
			not_implemented(o)
   		elif o in ( "-a", "--all"):
			states = inet_diag.SS_ALL;
   		elif o in ( "-l", "--listening"):
			states = 1 << inet_diag.SS_LISTEN;
   		elif o in ( "-o", "--options"):
			show_options = True
   		elif o in ( "-e", "--extended"):
			show_options = True
			show_details = True
   		elif o in ( "-m", "--memory"):
			show_mem = True
   		elif o in ( "-p", "--processes"):
			show_users = True
   		elif o in ( "-i", "--info"):
			show_protocol_info = True
   		elif o in ( "-s", "--summary"):
			not_implemented(o)
   		elif o in ( "-4", "--ipv4"):
			families = 1 << socket.AF_INET
   		elif o in ( "-6", "--ipv6"):
			families = 1 << socket.AF_INET6
   		elif o in ( "-0", "--packet"):
			not_implemented(o)
   		elif o in ( "-t", "--tcp"):
			dbs |= (1 << TCP_DB)
   		elif o in ( "-u", "--udp"):
			dbs |= (1 << UDP_DB)
   		elif o in ( "-d", "--dccp"):
			dbs |= (1 << DCCP_DB)
   		elif o in ( "-w", "--raw"):
			dbs |= (1 << RAW_DB)
   		elif o in ( "-x", "--unix"):
			dbs |= (1 << UNIX_DB)
   		elif o in ( "-f", "--family"):
			if a == "inet":
				families = 1 << socket.AF_INET
			elif a == "inet6":
				families = 1 << socket.AF_INET6
   		elif o in ( "-A", "--query"):
			not_implemented(o)
		else:
			usage()
			return

        addrp_width = screen_width
        addrp_width -= netid_width + 1
        addrp_width -= state_width + 1
        addrp_width -= 14
	if addrp_width & 1:
		if netid_width:
			netid_width += 1
		elif state_width:
			state_width += 1

	addrp_width /= 2
	addrp_width -= 1

	if addrp_width < 15 + serv_width + 1:
		addrp_width = 15 + serv_width + 1

	addr_width = addrp_width - serv_width - 1

	if dbs == 0 or dbs & (1 << TCP_DB):
		print_sockets(states, families,
			      inet_diag.TCPDIAG_GETSOCK, show_options,
			      show_mem, show_protocol_info,
			      show_details, show_users)

	if dbs & (1 << DCCP_DB):
		print_sockets(states, families,
			      inet_diag.DCCPDIAG_GETSOCK, show_options,
			      show_mem, show_protocol_info,
			      show_details, show_users)

if __name__ == '__main__':
    main()
