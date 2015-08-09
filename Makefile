# Copyright (c) Ian Van Houdt 2015
# Makefile for wireSnarf

CC=gcc
# WLAN- Flag set for dev on wireless enabled laptop.
#		Disable when building for wired device
CFLAGS=-D WLAN -D IP_ONLY -D WITH_HISTORY -D DNS -D SIMPLE_DISPLAY
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

all: daemon 

daemon:
	$(CC) $(DAEMON) $(DB) $(DNS) $(INC_LIB) $(LDLIBS) $(CFLAGS) -o snarfd

clean:
	rm -rf *.o snarfd daemon
