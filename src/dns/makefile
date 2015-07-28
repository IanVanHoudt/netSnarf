PWD_VAR=pwd
PWD=$(shell $(PWD_VAR))
INC_LIB=$(PWD)/../../include
CFLAGS=-DDNS_TEST
EXEC=testdns

all:
	gcc dns.c -o $(EXEC) -I$(INC_LIB) $(CFLAGS)

clean:
	rm -rf $(EXEC)

