/*
* The MIT License (MIT)
*
* Copyright (c) 2015 Ian Van Houdt

* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:

* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.

* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

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
    conn = mysql_init(NULL);

    /* Connect to database */
    if (!mysql_real_connect(conn, server, user, pw, database, 0, NULL, 0))
    {
        fprintf(stderr, "%s\n", mysql_error(conn));
        exit(1);
    }

    return conn;
}

int add_to_database(MYSQL *conn, char *ip, char *domain_name)
{
    // TODO: find a smarter way to calculate size of query buffer than
    // hardcoding 128
    char *query_buff = (char *)malloc(sizeof(char) * 128);

    if (!domain_name)
    {
        domain_name = "NULL";
    }

    sprintf(query_buff, "INSERT INTO %s VALUES('%s', '%s', now());", 
                         HISTORY_TABLE, ip, domain_name);
    mysql_query(conn, query_buff);
    free(query_buff);

    return 0;
}

int show_history(MYSQL *conn)
{
    char *query_buff = (char *)malloc(sizeof(char) *128);
    sprintf(query_buff, "SELECT * FROM %s ORDER BY date;", HISTORY_TABLE);

    mysql_query(conn, query_buff);
    MYSQL_RES *result = mysql_store_result(conn);

    int total_rows = mysql_num_rows(result);
    int total_columns = mysql_num_fields(result);
    MYSQL_ROW row;

    while ((row = mysql_fetch_row(result)))
    {
        int i = 0;
        for (i; i < total_columns; i++)
        {
            fprintf(stdout, "%s\n", row[i]);
        }

        fprintf(stdout, "\n");
    }

    mysql_free_result(result);
}

int clear_history(MYSQL *conn)
{
    char *query_buff = (char *)malloc(sizeof(char) * 128);
    sprintf(query_buff, "DELETE FROM %s;", HISTORY_TABLE);

    mysql_query(conn, query_buff);
    free(query_buff);

    return 0;
}
