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

import getopt, inet_diag, os, re, sys, procfs

version="0.1"

state_width = 10
addr_width = 15
timer_width = 7

def load_sockets():
	idiag = inet_diag.create()
	inodes = {}
	while True:
		try:
			s = idiag.get()
		except:
			break
		inodes[s.inode()] = s
	return inodes

ps = None
inode_re = None
inodes = None

def thread_mapper(s):
	global ps
	try:
		return [ int(s), ]
	except:
		pass
	if not ps:
		ps = procfs.pidstats()

	try:
		return ps.find_by_regex(re.compile(fnmatch.translate(s)))
	except:
		return ps.find_by_name(s)

def print_sockets(pid, indent = 0):
	header_printed = False
	dirname = "/proc/%d/fd" % pid
	try:
		filenames = os.listdir(dirname)
	except: # Process died
		return
	for filename in filenames:
		pathname = os.path.join(dirname, filename)
		try:
			linkto = os.readlink(pathname)
		except: # Process died
			continue
		inode_match = inode_re.match(linkto)
		if not inode_match:
			continue
		inode = int(inode_match.group(1))
		if not inodes.has_key(inode):
			continue
		if not header_printed:
			try:
				print "\n%s%d: %s" % (indent * "  ", pid,
						      procfs.process_cmdline(ps[pid]))
			except:
				return
			header_printed = True
		s = inodes[inode]
		print "  %-*s %-6d %-6d %*s:%-5d %*s:%-5d %-*s" % \
		      (state_width, s.state(),
		       s.receive_queue(), s.write_queue(),
		       addr_width, s.saddr(), s.sport(),
		       addr_width, s.daddr(), s.dport(),
		       timer_width, s.timer())

def usage():
	print '''Usage: psk [ OPTIONS ]
       psk [ OPTIONS ] [PID-LIST]
   -h, --help		this message
   -V, --version	output version information'''

def main():
	global ps, inode_re, inodes

	try:
		opts, args = getopt.getopt(sys.argv[1:],
					   "hV",
					   ("help", "version"))
	except getopt.GetoptError, err:
		usage()
		print str(err)
		sys.exit(2)

	for o, a in opts:
   		if o in ( "-V", "--version"):
			print version
			return
		else:
			usage()
			return

	if args:
		pid_list = reduce(lambda i, j: i + j,
                                  map(thread_mapper, args))
				
	inodes = load_sockets()
	ps = procfs.pidstats()
	pids = ps.keys()
	pids.sort()
	inode_re = re.compile(r"socket:\[(\d+)\]")
	ps.reload_threads()
	for pid in pids:
		if args and pid not in pid_list:
			continue
		print_sockets(pid)
		if ps[pid].has_key("threads"):
			for tid in ps[pid]["threads"].keys():
				print_sockets(tid, 1)

if __name__ == '__main__':
    main()
