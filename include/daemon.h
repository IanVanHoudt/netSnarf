/* Copyright (c) Ian Van Houdt 2015 */

/*
*	daemon.h
*
*	header file for the snarf daemon
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>

#define PROGRAM         "netSnarf"
#define ETH_HDR_LEN     14
#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)
#define IP_ADDR_LEN     16

struct my_ip
{
        u_char  ip_vhl;
        u_char  ip_tos;
        u_short ip_len;
        u_short ip_id;
        u_short ip_off;
        #define IP_RF 0x8000
        #define IP_DF 0x4000
        #define IP_MF 0x2000
        #define IP_OFFMASK 0x1fff
        u_char  ip_ttl;
        u_char  ip_p;
        u_short ip_sum;
        struct  in_addr ip_src,ip_dst;
};

/* TCP header */
typedef u_int tcp_seq;
 
struct my_tcp
{
        u_short th_sport;
        u_short th_dport;
        tcp_seq th_seq;
        tcp_seq th_ack;
        u_char  th_offx2;
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;
        u_short th_sum;
        u_short th_urp;
};

void device_info(char*, char*);
void handle_packet(u_char*, const struct pcap_pkthdr*, const u_char*);
u_int16_t inspect_ethernet_header(u_char*, const struct pcap_pkthdr*, const u_char*);
void inspect_ip_header(u_char*, const struct pcap_pkthdr*, const u_char*, 
                       char**);
void inspect_tcp_header(u_char*, const struct pcap_pkthdr*, const u_char*, struct my_ip*);

int exit_nicely(char*, int);

/*

============ netinet/ip.h
struct ip 
  { 
#if __BYTE_ORDER == __LITTLE_ENDIAN 
    unsigned int ip_hl:4;                header length  
    unsigned int ip_v:4;                 version  
#endif 
#if __BYTE_ORDER == __BIG_ENDIAN 
    unsigned int ip_v:4;                 version  
    unsigned int ip_hl:4;                header length  
#endif 
    u_int8_t ip_tos;                     type of service  
    u_short ip_len;                      total length  
    u_short ip_id;                       identification  
    u_short ip_off;                      fragment offset field  
#define IP_RF 0x8000                     reserved fragment flag  
#define IP_DF 0x4000                     dont fragment flag  
#define IP_MF 0x2000                     more fragments flag  
#define IP_OFFMASK 0x1fff                mask for fragmenting bits  
    u_int8_t ip_ttl;                     time to live  
    u_int8_t ip_p;                       protocol  
    u_short ip_sum;                      checksum  
    struct in_addr ip_src, ip_dst;       source and dest address  
  }; 
============
*/
