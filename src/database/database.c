/* Copyright (c) Ian Van Houdt 2015 */

/*
*   database.c
*
*   implemetation for a database module for the snarf program
*/

#include "database.h"

#ifdef DB_TEST
/* 
*  test main() for making sure database module can connect and interact
*  with the mysql database used by snarf.  Normally, the database module
*  acts as a library for the snarf daemon, and doesn't not run 
*  independently
*/
int main() {

    MYSQL *conn;
    MYSQL_RES *res;
    MYSQL_ROW row;

    char *server = "localhost";
    char *user = "root";
    char *pw = "root";
    char *database = "snarfdb";

    conn = mysql_init(NULL);

    /* Connect to database */
    if (!mysql_real_connect(conn, server, user, pw, database, 0, NULL, 0))
    {
        fprintf(stderr, "%s\n", mysql_error(conn));
        exit(1);
    }

    /* Send SQL query */
    if (mysql_query(conn, "show tables"))
    {
        fprintf(stderr, "%s\n", mysql_error(conn));
        exit(1);
    }

    res = mysql_use_result(conn);

    /* Output table name */
    fprintf(stdout, "MySQL Tables in database %s: \n", database);
    while ((row = mysql_fetch_row(res)) != NULL)
        fprintf(stdout, "%s\n", row[0]);

    mysql_free_result(res);
    mysql_close(conn);

    return 0;
}
#endif

MYSQL *connect_to_database(char *server, char *database, char *user, 
                           char *pw)
{
    MYSQL *conn;

    server = "localhost";
    user = "root";
    pw = "root";
    database = "snarfdb";

    conn = mysql_init(NULL);

    /* Connect to database */
    if (!mysql_real_connect(conn, server, user, pw, database, 0, NULL, 0))
    {
        fprintf(stderr, "%s\n", mysql_error(conn));
        exit(1);
    }

    return conn;
}

int add_to_database(char *ip, char *domain_name)
{
    fprintf(stdout, "adding %s to database\n", ip);
}
