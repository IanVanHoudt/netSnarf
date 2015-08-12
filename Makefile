# The MIT License (MIT)

# Copyright (c) 2015 Ian Van Houdt

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


# Makefile for netSnarf


CC=gcc
# WLAN- Flag set for dev on wireless enabled laptop.
#		Disable when building for wired device
CPPFLAGS=-DWLAN -DIP_ONLY -DWITH_HISTORY -DDNS -DSIMPLE_DISPLAY
CPPFLAGS_VERBOSE= $(filter-out -DSIMPLE_DISPLAY,$(CPPFLAGS))
LDFLAGS=
LDLIBS=-lpcap -lmysqlclient

PWD_VAR=pwd
PWD=$(shell $(PWD_VAR))
INC_LIB=-I$(PWD)/include
INC_LIB+=-I/usr/include/mysql

DAEMON_PATH=src/daemon
DB_PATH=src/database
DNS_PATH=src/dns

DAEMON=$(DAEMON_PATH)/*c
DB=$(DB_PATH)/*c
DNS=$(DNS_PATH)/*c

EXE=snarfd

all: daemon 

verbose:
	$(CC) $(DAEMON) $(DB) $(DNS) $(INC_LIB) $(LDLIBS) $(CPPFLAGS_VERBOSE) -o $(EXE)

daemon:
	$(CC) $(DAEMON) $(DB) $(DNS) $(INC_LIB) $(LDLIBS) $(CPPFLAGS) -o $(EXE)

clean:
	rm -rf *.o $(EXE)
