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

// struct iphdr {
//     unsigned char ihl;
// 	unsigned char version;
// 	unsigned char tos;
// 	unsigned short tot_len;
// 	unsigned short id;
// 	unsigned short flag_off;
// 	unsigned char ttl;
// 	unsigned char protocol;
// 	unsigned short check;
// 	unsigned int saddr;
// 	unsigned int daddr;
// };

// struct icmphdr {
// 	unsigned char type;
// 	unsigned char code;
// 	unsigned short check;
// 	unsigned short identifier;
// 	unsigned short seq;
// 	unsigned char data[32];
//     union {
//         struct {
//             unsigned short id;
//             unsigned short sequence;
//         } echo;

//         struct {
//             unsigned short unused;
//             unsigned short mtu;
//         } frag;
//     } un;
// };

struct TCPConHostThrParam
{
	std::string HostIP;
	unsigned HostPort;
};

struct TCPConThrParam
{
	std::string HostIP;
	unsigned BeginPort;
	unsigned EndPort;
};

struct pseudohdr   
{  
	unsigned int saddr; 
	unsigned int daddr; 
	char useless; 
	unsigned char protocol; 
	unsigned short length; 
};

struct TCPSYNHostThrParam
{
	std::string HostIP;
	unsigned HostPort;
    unsigned LocalPort;
	unsigned LocalHostIP;
};

struct TCPSYNThrParam
{
	std::string HostIP;
	unsigned BeginPort;
	unsigned EndPort;
	unsigned LocalHostIP;
};


struct TCPFINThrParam
{
	std::string HostIP;
	unsigned BeginPort;
	unsigned EndPort;
	unsigned LocalHostIP;
};

struct UDPThrParam
{
	std::string HostIP;
	unsigned BeginPort;
	unsigned EndPort;
	unsigned LocalHostIP;
};

struct UDPScanHostThrParam
{
	std::string HostIP;
	unsigned HostPort;
    unsigned LocalPort;
	unsigned LocalHostIP;
};

struct ipicmphdr 
{ 
	struct iphdr ip; 
	struct icmphdr icmp; 
}; 

struct TCPFINHostThrParam
{
	std::string HostIP;
	unsigned HostPort;
    unsigned LocalPort;
	unsigned LocalHostIP;
};

struct IPHeader {
    unsigned char headerLen : 4;
    unsigned char version : 4;
    unsigned char tos;
    unsigned short length;
    unsigned short ident;
    unsigned short fragFlags;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    unsigned int srcIP;
    unsigned int dstIP;
    IPHeader(unsigned int src, unsigned int dst, int protocol) {
        version = 4;
        headerLen = 5;
        srcIP = src;
        dstIP = dst;
        ttl = (char)128;
        this -> protocol = protocol;
        if (protocol == IPPROTO_TCP) {
            length = htons(20 + 20);
        } 
		else if (protocol == IPPROTO_UDP) {
            length = htons(20 + 8);
        }
    }
};

struct TCPHeader {
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t seq;
    uint32_t ack;
    uint8_t null1 : 4;
    uint8_t length : 4;
    uint8_t FIN : 1;
    uint8_t SYN : 1;
    uint8_t RST : 1;
    uint8_t PSH : 1;
    uint8_t ACK : 1;
    uint8_t URG : 1;
    uint8_t null2 : 2;
    uint16_t windowSize;
    uint16_t checkSum;
    uint16_t ptr;
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

static inline unsigned int GetLocalHostIP(void) 
{ 
	FILE *fd; 
	char buf[20] = {0x00}; 

	fd = popen("/sbin/ifconfig | grep inet | grep -v 127 | awk '{print $2}' | cut -d \":\" -f 2", "r"); 
	if(fd == NULL)
	{ 
		fprintf(stderr, "cannot get source ip -> use the -f option\n"); 
		exit(-1); 
	} 
	fscanf(fd, "%20s", buf); 
	return(inet_addr(buf)); 
} 

bool Ping(std::string HostIP,unsigned LocalHostIP); // ICMP 探测指定主机
void* Thread_TCPconnectHost(void* param); // TCP connect 扫描
void* Thread_TCPconnectScan(void* param);
void* Thread_TCPSYNHost(void* param);
void* Thread_TCPSynScan(void* param);
void* UDPScanHost(void* param);
void* Thread_UDPScan(void* param);
void* Thread_TCPFinScan(void* param);
void* Thread_TCPFINHost(void* param);
#endif