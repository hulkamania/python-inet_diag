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

import getopt, inet_diag, sys

version="0.1"

def not_implemented(o):
	print "%s not implemented yet" % o 

state_width = 10
addr_width = 18

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

def print_sockets(states, show_options = False, show_mem = False,
		  show_protocol_info = False, show_details = False):
	extensions = 0
	if show_mem:
		extensions |= inet_diag.EXT_MEMORY;
	if show_protocol_info:
		extensions |= inet_diag.EXT_PROTOCOL | inet_diag.EXT_CONGESTION;
	idiag = inet_diag.create(states = states, extensions = extensions); 
	print "%-*s %-6s %-6s %*s:%-5s   %*s:%-5s  " % \
	      (state_width, "State",
	       "Recv-Q", "Send-Q",
	       addr_width, "Local Address", "Port",
	       addr_width, "Peer Address", "Port")
	while True:
		try:
			s = idiag.get()
		except:
			break
		print "%-*s %-6d %-6d %*s:%-5d   %*s:%-5d   " % \
		      (state_width, s.state(),
		       s.receive_queue(), s.write_queue(),
		       addr_width, s.saddr(), s.sport(),
		       addr_width, s.daddr(), s.dport()),
		if show_options:
			timer = s.timer()
			if timer != "off":
				print "timer:(%s,%s,%d)" % (timer,
							    print_ms_timer(s),
							    s.retransmissions()),

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

	show_options = False
	show_details = False
	show_mem = False
	show_protocol_info = False
	states = inet_diag.default_states
	resolve_ports = True

	if not opts:
		print_sockets(states)
		sys.exit(0)

	for o, a in opts:
   		if o in ( "-V", "--version"):
			print version
   		elif o in ( "-n", "--numeric"):
			resolve_ports = False
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
			not_implemented(o)
   		elif o in ( "-i", "--info"):
			show_protocol_info = True
   		elif o in ( "-s", "--summary"):
			not_implemented(o)
   		elif o in ( "-4", "--ipv4"):
			not_implemented(o)
   		elif o in ( "-6", "--ipv6"):
			not_implemented(o)
   		elif o in ( "-0", "--packet"):
			not_implemented(o)
   		elif o in ( "-t", "--tcp"):
			not_implemented(o)
   		elif o in ( "-u", "--udp"):
			not_implemented(o)
   		elif o in ( "-d", "--dccp"):
			not_implemented(o)
   		elif o in ( "-w", "--raw"):
			not_implemented(o)
   		elif o in ( "-x", "--unix"):
			not_implemented(o)
   		elif o in ( "-f", "--family"):
			not_implemented(o)
   		elif o in ( "-A", "--query"):
			not_implemented(o)
		else:
			usage()
			return

	print_sockets(states, show_options, show_mem, show_protocol_info,
		      show_details)

if __name__ == '__main__':
    main()
