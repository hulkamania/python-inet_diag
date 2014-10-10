#!/usr/bin/python2

from distutils.core import setup, Extension

inet_diag = Extension('inet_diag',
		      sources = ['python-inet_diag/inet_diag.c'])

# don't reformat this line, Makefile parses it
setup(name='inet_diag',
      version='0.1',
      description='Python module to interface with inet_diag',
      author='Arnaldo Carvalho de Melo',
      author_email='acme@redhat.com',
      url='https://rt.wiki.kernel.org/index.php/Tuna',
      ext_modules=[inet_diag])
