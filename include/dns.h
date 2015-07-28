/* Copyright (c) Ian Van Houdt 2015 */

/*
*   dns.h
*
*   header file for routines found in the snarf dns module
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define HOST_NAME_LEN 60
int getHostnameByIP(char *ip, char **host_name);
