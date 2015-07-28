/* Copyright (c) Ian Van Houdt 2015 */

/*
*   dns.c
*
*   implementation for a dns lookup module for the snarf program
*/

#include "dns.h"

//only ipv4 supported at this point
int SNARF_INET_TYPE = AF_INET;

#ifdef DNS_TEST
int main(int argc, char *argv[])
{
    char *ip = "8.8.8.8";
#else
int getHostnameByIP(char *ip, char **host_name)
{
#endif

    struct sockaddr_in addr;
    addr.sin_family = SNARF_INET_TYPE;
    inet_pton(AF_INET, ip, &addr.sin_addr);
 
    char node[NI_MAXHOST];
    int res = getnameinfo((struct sockaddr*)&addr, sizeof(addr), node, sizeof(node), NULL, 0, 0);
    if (res)
    {
      printf("[DNS] %s\n", gai_strerror(res));
      return -1;
    }
    printf("%s\n", node);

    //TODO: strncpy
    *host_name = (char*) malloc(sizeof(char) * HOST_NAME_LEN);
    strcpy(*host_name, node);

    return 0;
}
