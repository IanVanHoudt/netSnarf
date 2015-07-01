# Copyright (c) Ian Van Houdt 2015
# Makefile for wireSnarf

CC=gcc
CFLAGS=

DAEMON_PATH=src/daemon
DB_PATH=src/database
DNS_PATH=src/dns

DAEMON=$(DAEMON_PATH)/*c
DB=$(DB_PATH)/*c
DNS=$(DNS_PATH)/*c

all: daemon 

daemon:
	$(CC) $(DAEMON) -o snarf

clean:
	rm -rf *.o snarf daemon
