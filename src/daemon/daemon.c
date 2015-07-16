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
    /*
    char *server = "localhost";
    char *database = "snarfdb";
    char *user = "root";
    char *pw = "root";
    */
    MYSQL *conn = connect_to_database(LOCALHOST, DATABASE, USER, PW);
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

    if (DEBUG) fprintf(stdout, "\t====================\n");
    u_int16_t eth_type = inspect_ethernet_header(args, hdr, pkt);

    if (eth_type == ETHERTYPE_IP && ETHERTYPE_IP != 0)
    {
        // parse ip and handle
        inspect_ip_header(args, hdr, pkt);
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
                       const u_char *pkt)
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

    /* DNS lookup */
    // TODO: Think about way to limit excessive DNS lookups, ie to cache
    // results to avoid uncessary calls, such as maintaining array of ips 
    // that have already been resolved.  This won't be super efficient, 
    // but an array search will be much faster than send DNS requests
    // over the network (unless it's getting hits from the DNS cache...)


#ifdef WITH_HISTORY
    /* Add to database */
#ifdef DNS

#else
    // NULL for domain_name
    add_to_database(inet_ntoa(ip->ip_dst), NULL);
#endif
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


