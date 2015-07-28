PWD_VAR=pwd
PWD=$(shell $(PWD_VAR))
INC_LIB=$(PWD)/../../include
MYSQLCFLAGS=`mysql_config –cflags`
MYSQLLIBS=`mysql_config –libs`
CFLAGS=-D DB_TEST
EXEC=testdb

all:
	gcc database.c -o $(EXEC)  -I/usr/include/mysql -I$(INC_LIB) -lmysqlclient $(CFLAGS)

clean:
	rm -rf $(EXEC)
