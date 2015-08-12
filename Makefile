# Copyright (c) Ian Van Houdt 2015
# Makefile for wireSnarf

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
