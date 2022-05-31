#ifndef HEADER_H
#define HEADER_H

#include <iostream>
#include <unordered_map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <semaphore.h>
#include <aio.h>
#include <sys/types.h>
#include <signal.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/time.h>
#include <pthread.h>
#include <fcntl.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/poll.h>

struct iphdr {
    unsigned char ihl;
	unsigned char version;
	unsigned char tos;
	unsigned short tot_len;
	unsigned short id;
	unsigned short flag_off;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short check;
	unsigned int saddr;
	unsigned int daddr;
};

struct icmphdr {
	unsigned char type;
	unsigned char code;
	unsigned short check;
	unsigned short identifier;
	unsigned short seq;
	unsigned char data[32];
    union {
        struct {
            unsigned short id;
            unsigned short sequence;
        } echo;

        struct {
            unsigned short unused;
            unsigned short mtu;
        } frag;
    } un;
};

static inline unsigned short in_cksum(unsigned short *ptr, int nbytes) 
{ 
	register long sum; 
	u_short oddbyte; 
	register u_short answer; 

	sum = 0; 
	while(nbytes > 1) 
	{ 
		sum += *ptr++; 
		nbytes -= 2; 
	} 

	if(nbytes == 1) 
	{ 
		oddbyte = 0; 
		*((u_char *) &oddbyte) = *(u_char *)ptr; 
		sum += oddbyte; 
	} 

	sum = (sum >> 16) + (sum & 0xffff); 
	sum += (sum >> 16); 
	answer = ~sum; 

	return(answer); 
}

bool Ping(std::string HostIP,unsigned LocalHostIP); // ICMP 探测指定主机
void* Thread_TCPconnectHost(void* param); // TCP connect 扫描


#endif