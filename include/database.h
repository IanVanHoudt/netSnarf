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
*   database.h
*
*   header file for routines found in the snarf database module
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <mysql.h>

#define HISTORY_TABLE "history"

MYSQL *connect_to_database(char *server, char *db_name, char *user, 
                           char *pw);
int add_to_database(MYSQL *conn, char *ip, char *domain_name);
int remove_row_from_database();
int remove_all_from_database();
int dump_database(FILE*);
