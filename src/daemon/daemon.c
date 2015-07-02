/* Copyright (c) Ian Van Houdt 2015 */

/*
*	daemon.c
*		The daemon for the wireSnarf project. 
*
*	notable functions:
* 		int main()
*/

#include "../../include/daemon.h"

int DEBUG = 1;

int main(int argc, char *argv[])
{
    char *dev = NULL; /* name of the device to use */  
    char *net = NULL; /* dot notation of the network address */ 
    char *mask = NULL;/* dot notation of the network mask    */ 
    int ret;   /* return code */ 
    char errbuf[PCAP_ERRBUF_SIZE]; 
    bpf_u_int32 netp; /* ip          */ 
    bpf_u_int32 maskp;/* subnet mask */ 
    struct in_addr addr; 

    if (argc == 2)
        dev = argv[1];
    else
    {
#ifdef WLAN
        dev = "wlan0";
#else
        /* need to run as root or via sudo */
        dev = pcap_lookupdev(errbuf);
#endif
    }

    if (dev == NULL) exit_nicely(errbuf, __LINE__);

    if (DEBUG) fprintf(stdout, "Dev: %s\n", dev);

    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
    if (ret == -1) exit_nicely(errbuf, __LINE__);

    addr.s_addr = netp;
    net = inet_ntoa(addr);
    if (!net) exit_nicely("inet_ntoa", __LINE__);
    
    if (DEBUG) fprintf(stdout, "Net: %s\n", net);

    addr.s_addr = maskp;
    mask = inet_ntoa(addr);
    if (!mask) exit_nicely(__FILE__, __LINE__);

    if (DEBUG) fprintf(stdout, "Mask: %s\n", mask);

    return 0;
}


void setup_device(char *dev, char *net, char *mask, struct in_addr *addr, 
                  int ret, bpf_u_int32 *netp, bpf_u_int32 *maskp, char *errbuf)
{


}

int exit_nicely(char *loc, int line)
{
    if (*loc && loc)
        fprintf(stderr, "\nWhoa, had issue (%s) at line %d! Exiting\n", loc, line);
    else
        fprintf(stderr, "\nWhoa, had issue at line %d! Exiting\n", line);

    exit(1);
}


