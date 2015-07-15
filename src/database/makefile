PWD_VAR=pwd
PWD=$(shell $(PWD_VAR))
INC_LIB=$(PWD)/../../include
MYSQLCFLAGS=`mysql_config –cflags`
MYSQLLIBS=`mysql_config –libs`

all:
	gcc database.c -o testdb  -I/usr/include/mysql -I$(INC_LIB) -lmysqlclient -DDB_TEST

clean:
	rm -rf testdb
