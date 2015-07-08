/* Copyright (c) Ian Van Houdt 2015 */

/*
*	daemon.h
*		header file for the snarf daemon
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */ 
#include <net/ethernet.h>
#include <netinet/ether.h>

void device_info(char*, char*);
void handle_packet(u_char*, const struct pcap_pkthdr*, const u_char*);
void inspect_ethernet(u_char*, const struct pcap_pkthdr*, const u_char*);
void inspect_ip_header(const struct pcap_pkthdr*, const u_char*);
int exit_nicely(char*, int);

