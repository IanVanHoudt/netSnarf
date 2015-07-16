/* Copyright (c) Ian Van Houdt 2015 */

/*
*   database.h
*
*   header file for routines found in the snarf database module
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <mysql.h>

MYSQL *connect_to_database(char *server, char *db_name, char *user, 
                           char *pw);
int add_to_database(char *ip, char *domain_name);
int remove_row_from_database();
int remove_all_from_database();
int dump_database(FILE*);
