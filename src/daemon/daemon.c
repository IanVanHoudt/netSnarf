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
*	daemon.c
*		The daemon for the wireSnarf project. 
*
*/

#include "daemon.h"
#include "database.h"
#include "dns.h"

/*
   Set of DEBUG IDs
   0: No debug output
   1: Basic debug output
   2: Extensive debug output
*/

#ifndef SIMPLE_DISPLAY
int DEBUG = 1;
int ETH_DEBUG = 1;
int IP_DEBUG = 1;
int TCP_DEBUG = 1;
#else
int DEBUG = 0;
int ETH_DEBUG = 0;
int IP_DEBUG = 0;
int TCP_DEBUG = 0;
#endif

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

    char *ival = NULL;
    int iflag = 0;
    int c;
    opterr = 0;

    while ((c = getopt(argc, argv, "i:csh")) != -1)
    {
        switch (c)
        {

            /* select interface */
            case 'i':
                ival = optarg;
                iflag = 1;
                break;

            /* clear history table */
            case 'c':
#ifdef WITH_HISTORY
                clear_history(conn);
                exit_nicely("History cleared");
#else
                exit_nicely("History database not in use.");
#endif

            /* show history */
            case 's':
#ifdef WITH_HISTORY
                show_history(conn);
                exit_nicely(NULL);
#else
                exit_nicely("History database not in use.");
#endif
  
            /* print help */
            case 'h':
                fprintf(stdout, "netSnarf Help:\n\tsnarf [OPTION]"
                                "\nOPTIONS\n"
                                "\t-c    "
                                "clear history records (requires database module)\n"
                                "\t-h    "
                                "help, prints cli options\n"
                                "\t-i <interface>    "
                                "selects network interface to use for sniffing\n"
                                "\t-s    "
                                "show history records (requires database module)\n");
                exit_nicely("");

            case '?':
                if (optopt == 'i')
                {
                    fprintf(stderr,
                            "Option -%c requires an argurment.\n", optopt);
                }
                else if (isprint(optopt))
                {
                    fprintf(stderr, "Unknown option '-%c'.\n", optopt);
                }
                else
                {
                    fprintf(stderr, 
                            "Unknown option character '\\x%x'.\n", optopt);
                }
                return 1;

            default:
                fprintf(stdout, "Starting packet sniffer\n");

        }
    }

    /* Select device: wlan if developing, else lookup or supply via cli */
    if (iflag)
        dev = ival;
    else
    {
#ifdef WLAN
        dev = "wlan0";
#else
        dev = pcap_lookupdev(errbuf);
#endif
    }

    if (dev == NULL) error_nicely(errbuf, __LINE__);

    /* Get basic information on capture interface/device */
    device_info(dev, errbuf);

    dev_handle = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);
    if (!dev_handle) error_nicely(errbuf, __LINE__);

    /* primary packet handling engine */
    pcap_loop(dev_handle, num_pkts, handle_packet, NULL);

    if (conn)
        mysql_close(conn);

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
    if (ret == -1) error_nicely(errbuf, __LINE__);

    addr.s_addr = netp;
    net = inet_ntoa(addr);
    if (!net) error_nicely("inet_ntoa", __LINE__);
    SELF_IP = net;
    
    fprintf(stdout, "Net: %s\n", net);

    addr.s_addr = maskp;
    mask = inet_ntoa(addr);
    if (!mask) error_nicely(__FILE__, __LINE__);

    fprintf(stdout, "Mask: %s\n", mask);
}

void handle_packet(u_char *args, const struct pcap_pkthdr *hdr,
                   const u_char *pkt) 
{
    /* 
        Here is the core of snarf; the packet handler.  Whatever new
        modules/features should probably be added here, and implemented 
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
        // NOTE: Think about way to limit excessive DNS lookups, ie to cache
        // results to avoid uncessary calls, like  maintaining array of ips 
        // that have already been resolved.  This won't be super efficient, 
        // but an array search will be much faster than send DNS requests
        // over the network (unless it's getting hits from the DNS cache...)
        char *domain_name = NULL;
        if (getHostnameByIP(ip_addr, &domain_name) != 0)
            fprintf(stderr, "DNS Lookup yielded no hostname!\n");
        add_to_database(conn, ip_addr, domain_name);
        free(domain_name);
#else
        // Domain name is NULL if no DNS
        add_to_database(conn, ip_addr, NULL);
#endif //DNS
#endif //WITH_HISTORY

        free(ip_addr);
    }
#ifdef SIMPLE_DISPLAY
    fflush(stdout);
    fprintf(stdout, "\r");
    fprintf(stdout, "%d", count);
#endif
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
    {
        strncpy(*ip_addr, inet_ntoa(ip->ip_src), strlen(inet_ntoa(ip->ip_src)) + 1);
    }
    // src IP is yours, so dst will be recorded in DB
    else
    {
        strncpy(*ip_addr, inet_ntoa(ip->ip_dst), strlen(inet_ntoa(ip->ip_dst)) + 1);
    }
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
int exit_nicely(char *message)
{
    if (*message && message)
        fprintf(stdout, "Exiting: %s\n", message);
    else
        fprintf(stdout, "Exiting\n");

    if (conn)
        mysql_close(conn);

    exit(0);
}
int error_nicely(char *loc, int line)
{
    if (*loc && loc)
        fprintf(stderr, "\nWhoa, had issue (%s) at line %d! Exiting\n", loc, line);
    else
        fprintf(stderr, "\nWhoa, had issue at line %d! Exiting\n", line);

    if (conn)
        mysql_close(conn);

    exit(1);
}


