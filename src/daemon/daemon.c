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
    int ret;   /* return code */
    int num_pkts; 
    char *dev = NULL; /* name of the device to use */  
    char errbuf[PCAP_ERRBUF_SIZE]; 

    pcap_t *dev_handle;
    const u_char *packet;
    struct pcap_pkthdr hdr;
    struct ether_header *eptr;

    /* Select device: wlan if developing, else lookup or supply via cli */
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

    device_info(dev, errbuf);

    /* open device */
    dev_handle = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);
    if (!dev_handle) exit_nicely(errbuf, __LINE__);

    pcap_loop(dev_handle, num_pkts, handle_packet, NULL);

    return 0;
}


void device_info(char *dev, char *errbuf)
{
    int ret;
    char *net = NULL; /* dot notation of the network address */ 
    char *mask = NULL;/* dot notation of the network mask    */ 
    bpf_u_int32 netp; /* ip          */ 
    bpf_u_int32 maskp;/* subnet mask */ 
    struct in_addr addr; 

    fprintf(stdout, "Dev: %s\n", dev);

    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
    if (ret == -1) exit_nicely(errbuf, __LINE__);

    addr.s_addr = netp;
    net = inet_ntoa(addr);
    if (!net) exit_nicely("inet_ntoa", __LINE__);
    
    fprintf(stdout, "Net: %s\n", net);

    addr.s_addr = maskp;
    mask = inet_ntoa(addr);
    if (!mask) exit_nicely(__FILE__, __LINE__);

    fprintf(stdout, "Mask: %s\n", mask);
}

void handle_packet(u_char *args, const struct pcap_pkthdr *hdr,
                 const u_char *pkt) 
{
    static int count = 1;
    fprintf(stdout, "%d, ", count);
    count++;
}

int exit_nicely(char *loc, int line)
{
    if (*loc && loc)
        fprintf(stderr, "\nWhoa, had issue (%s) at line %d! Exiting\n", loc, line);
    else
        fprintf(stderr, "\nWhoa, had issue at line %d! Exiting\n", line);

    exit(1);
}


