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
