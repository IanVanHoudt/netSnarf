/* Copyright (c) Ian Van Houdt 2015 */

/*
*	daemon.c
*		The daemon for the wireSnarf project. 
*
*	notable functions:
* 		int main()
*/

#include "daemon.h"
#include "database.h"

/*
   Set of DEBUG IDs
   0: No debug output
   1: Basic debug output
   2: Extensive debug output
*/
int DEBUG = 1;
int ETH_DEBUG = 1;
int IP_DEBUG = 1;
int TCP_DEBUG = 1;

#define DATABASE "snarfdb"
#define LOCALHOST "localhost"
#define USER "root"
#define PW "root"

char *SELF_IP = NULL;
MYSQL *conn = NULL;

int main(int argc, char *argv[])
{
    int ret;
    int num_pkts; 
    char *dev = NULL;  
    char errbuf[PCAP_ERRBUF_SIZE]; 

    pcap_t *dev_handle;
    const u_char *packet;
    struct pcap_pkthdr hdr;
    struct ether_header *eptr;

#ifdef WITH_HISTORY
    conn = connect_to_database(LOCALHOST, DATABASE, USER, PW);
#endif

    /* Select device: wlan if developing, else lookup or supply via cli */
    if (argc == 2)
        dev = argv[1];
    else
    {
#ifdef WLAN
        dev = "wlan0";
#else
        dev = pcap_lookupdev(errbuf);
#endif
    }

    if (dev == NULL) exit_nicely(errbuf, __LINE__);

    device_info(dev, errbuf);

    dev_handle = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);
    if (!dev_handle) exit_nicely(errbuf, __LINE__);

    pcap_loop(dev_handle, num_pkts, handle_packet, NULL);

    return 0;
}


void device_info(char *dev, char *errbuf)
{
    int ret;
    char *net = NULL;
    char *mask = NULL; 
    bpf_u_int32 netp; 
    bpf_u_int32 maskp; 
    struct in_addr addr; 

    fprintf(stdout, "Dev: %s\n", dev);

    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
    if (ret == -1) exit_nicely(errbuf, __LINE__);

    addr.s_addr = netp;
    net = inet_ntoa(addr);
    if (!net) exit_nicely("inet_ntoa", __LINE__);
    SELF_IP = net;
    
    fprintf(stdout, "Net: %s\n", net);

    addr.s_addr = maskp;
    mask = inet_ntoa(addr);
    if (!mask) exit_nicely(__FILE__, __LINE__);

    fprintf(stdout, "Mask: %s\n", mask);
}

void handle_packet(u_char *args, const struct pcap_pkthdr *hdr,
                   const u_char *pkt) 
{
    /* 
        Here is the core of snarf; the packet handler.  Whatever new
        modules/features will likely be added here, implemented 
        similarly to the ETHERTYPE_IP stmt below.  As packets come in,
        deal with them according to whatever criteria you want, and make
        the calls here as much as possible, rather than within other calls 
        (such as calling a DB or DNS routine from within the 
        inspect_ip_header() function).  This will help maintain modularity
        and extensibility.
    */

    static int count = 1;
    char *ip_addr;

    if (DEBUG) fprintf(stdout, "\t====================\n");
    u_int16_t eth_type = inspect_ethernet_header(args, hdr, pkt);

    if (eth_type == ETHERTYPE_IP && ETHERTYPE_IP != 0)
    {
        // parse ip and handle
        inspect_ip_header(args, hdr, pkt, &ip_addr);
#ifdef WITH_HISTORY
#ifdef DNS
        /* DNS lookup */
        // TODO: Think about way to limit excessive DNS lookups, ie to cache
        // results to avoid uncessary calls, like  maintaining array of ips 
        // that have already been resolved.  This won't be super efficient, 
        // but an array search will be much faster than send DNS requests
        // over the network (unless it's getting hits from the DNS cache...)
#else
        // Domain name is NULL if no DNS
        add_to_database(ip_addr, NULL);
#endif //DNS
#endif //WITH_HISTORY
    }

    count++;
}

u_int16_t inspect_ethernet_header(u_char *args, const struct pcap_pkthdr *hdr,
                      const u_char *pkt)
{
    struct ether_header *eth;
    eth = (struct ether_header *) pkt;

    if(ETH_DEBUG)
    {
        fprintf(stdout, "\n\t[Eth] Type: ");
        switch (ntohs(eth->ether_type))
        {
            case (ETHERTYPE_IP):
                fprintf(stdout, "IP");
                break;
            case (ETHERTYPE_ARP):
                if (ETH_DEBUG > 1) fprintf(stdout, "ARP");
                break;
            case (ETHERTYPE_REVARP):
                if (ETH_DEBUG > 1) fprintf(stdout, "REVARP");
                break;
            default:
                fprintf(stdout, "Uknown Type");
                return -1; 
        }

        fprintf(stdout, "\n\t[Eth] source: %s\n", 
                ether_ntoa((const struct ether_addr *) eth->ether_shost));
        fprintf(stdout, "\t[Eth] destination: %s\n\n", 
                ether_ntoa((const struct ether_addr *) eth->ether_dhost));

    }

    return ntohs(eth->ether_type);
}

void inspect_ip_header(u_char *args, const struct pcap_pkthdr *hdr, 
                       const u_char *pkt, char **ip_addr)
{
    struct my_ip *ip;
    u_int16_t version, ip_len;

    if (IP_DEBUG) fprintf(stdout, "\t\t[IP]\n");

    ip = (struct my_ip*) (pkt + ETH_HDR_LEN);

    version = IP_V(ip); 
    ip_len = IP_HL(ip)*4;

    if (version != 4)
    {
        fprintf(stderr, "[IP] IPv%d currently unsupported in %s", 
                         version, PROGRAM);
        return;
    }

    if (ip_len < 20)
    {
        fprintf(stderr, "[IP] Invalid IP header length: %u bytes\n", 
                         ip_len);
        return;
    }

    if (IP_DEBUG)
    {
        fprintf(stdout, "\t\tSource Addr: %s\n", inet_ntoa(ip->ip_src));
        fprintf(stdout, "\t\tDest Addr: %s\n", inet_ntoa(ip->ip_dst));
    }

#ifdef WITH_HISTORY
    /* Add to database */

    *ip_addr = (char*) malloc(sizeof(char) * IP_ADDR_LEN);
    // src IP is not yours, so src will be recorded in DB
    if (strcmp(inet_ntoa(ip->ip_src), SELF_IP) != 0)
        strcpy(*ip_addr, inet_ntoa(ip->ip_src));
    // src IP is yours, so dst will be recorded in DB
    else
        strcpy(*ip_addr, inet_ntoa(ip->ip_dst));
#endif

#ifndef IP_ONLY
    /* Inspect and handle TCP*/
    //At this juncture, only handle TCP. Easy to add others later
    switch(ip->ip_p)
    {
        case IPPROTO_TCP:
            if (IP_DEBUG) fprintf(stdout, "\t\tProtocol: TCP\n\n");
            inspect_tcp_header(args, hdr, pkt, ip);
            break;
        case IPPROTO_UDP:
            return;
        case IPPROTO_ICMP:
            return;
        case IPPROTO_IP:
            return;
        default:
            return;
    }
#endif
}

void inspect_tcp_header(u_char *args, const struct pcap_pkthdr *hdr,
                        const u_char *pkt, struct my_ip *ip)
{
    struct my_tcp *tcp;
    u_int16_t tcp_len;

    if (TCP_DEBUG) fprintf(stdout, "\t\t\t[TCP]\n");

    tcp = (struct my_tcp*) (pkt + ETH_HDR_LEN + IP_HL(ip)*4);

    tcp_len = TH_OFF(tcp)*4;
    if (tcp_len < 20)
    {
         fprintf(stderr, "[TCP] Invalid TCP header length: %u bytes\n", 
                         tcp_len);
        return;
    }
    
    if (TCP_DEBUG)
    {
        fprintf(stdout, "\t\t\tSource Port: %d\n", ntohs(tcp->th_sport));
        fprintf(stdout, "\t\t\tDest Port: %d\n", ntohs(tcp->th_dport));
    }

 
}

int exit_nicely(char *loc, int line)
{
    if (*loc && loc)
        fprintf(stderr, "\nWhoa, had issue (%s) at line %d! Exiting\n", loc, line);
    else
        fprintf(stderr, "\nWhoa, had issue at line %d! Exiting\n", line);

    exit(1);
}


