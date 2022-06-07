#include "header.h"

pthread_mutex_t UDPPrintlocker = PTHREAD_MUTEX_INITIALIZER;

void* UDPScanHost(void* param) {
    struct UDPScanHostThrParam *p = (struct UDPScanHostThrParam*) param;
    std::string HostIP = p -> HostIP;
	unsigned HostPort = p -> HostPort;
	unsigned LocalPort = p -> LocalPort;
	unsigned LocalHostIP = p -> LocalHostIP;

    int UDPSock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); 
    if(UDPSock < 0)
	{
		pthread_mutex_lock(&UDPPrintlocker);
		std::cout << "Can't creat raw icmp socket !" << std::endl;
		pthread_mutex_unlock(&UDPPrintlocker);
	}
    int on = 1;
    int ret = setsockopt(UDPSock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)); 

    if (ret < 0) 
	{
		pthread_mutex_lock(&UDPPrintlocker);
		std::cout << "Can't set raw socket !" << std::endl;
		pthread_mutex_unlock(&UDPPrintlocker);
	}

    struct sockaddr_in UDPScanHostAddr; 
    memset(&UDPScanHostAddr, 0, sizeof(UDPScanHostAddr));
	UDPScanHostAddr.sin_family = AF_INET;
	UDPScanHostAddr.sin_addr.s_addr = inet_addr(&HostIP[0]);
	UDPScanHostAddr.sin_port = htons(HostPort); 

    char packet[sizeof(struct iphdr) + sizeof(struct udphdr)]; 
    memset(packet, 0x00, sizeof(packet)); 

	struct iphdr *ip = (struct iphdr *)packet; 
    struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct iphdr)); 
    struct pseudohdr *pseudo = (struct pseudohdr *)(packet + sizeof(struct iphdr) - sizeof(struct pseudohdr)); 

    udp -> source = htons(LocalPort);                 
    udp -> dest = htons(HostPort);           
    udp -> len = htons(sizeof(struct udphdr));
    udp -> check = 0;  

	pseudo -> saddr = LocalHostIP; 
    pseudo -> daddr = inet_addr(&HostIP[0]); 
    pseudo -> useless = 0; 
    pseudo -> protocol = IPPROTO_UDP; 
    pseudo -> length = udp->len; 

    udp->check = in_cksum((u_short *)pseudo,sizeof(struct udphdr)+sizeof(struct pseudohdr));
	
	ip -> ihl = 5; 
	ip -> version = 4; 
	ip -> tos = 0x10; 
	ip -> tot_len = sizeof(packet); 
	ip -> frag_off = 0; 
	ip -> ttl = 69; 
	ip -> protocol = IPPROTO_UDP; 
	ip -> check = 0; 
	ip -> saddr = inet_addr("192.168.1.168"); 
	ip -> daddr = inet_addr(&HostIP[0]);

    int n = sendto(UDPSock, packet, ip -> tot_len, 0, (struct sockaddr *)&UDPScanHostAddr, sizeof(UDPScanHostAddr)); 
	if (n < 0) 
	{
		pthread_mutex_lock(&UDPPrintlocker);
		std::cout << "Send message to Host Failed !" << std::endl;
		pthread_mutex_unlock(&UDPPrintlocker);
	}

	if(fcntl(UDPSock, F_SETFL, O_NONBLOCK) == -1) 
	{
		pthread_mutex_lock(&UDPPrintlocker);
        std::cout << "Set socket in non-blocked model fail !" << std::endl;
		pthread_mutex_unlock(&UDPPrintlocker);
	}
	
    struct timeval TpStart, TpEnd; 
    struct ipicmphdr hdr;
    gettimeofday(&TpStart,NULL);             //get start time
	do 
	{
		//receive response message
        n = read(UDPSock, (struct ipicmphdr *)&hdr, sizeof(hdr));

		if(n > 0)
		{
			if((hdr.ip.saddr == inet_addr(&HostIP[0])) && (hdr.icmp.code == 3) && (hdr.icmp.type == 3))
			{
				pthread_mutex_lock(&UDPPrintlocker);
				std::cout << "Host: " << HostIP << " Port: " << HostPort << " closed !" << std::endl;
				pthread_mutex_unlock(&UDPPrintlocker);
				break;
			}
		}
		//time out?
		gettimeofday(&TpEnd,NULL);
		float TimeUse = (1000000 * (TpEnd.tv_sec - TpStart.tv_sec) + (TpEnd.tv_usec - TpStart.tv_usec)) / 1000000.0;
		if(TimeUse < 3)
		{
			continue;
		}
		else
		{
			pthread_mutex_lock(&UDPPrintlocker);
			std::cout << "Host: " << HostIP << " Port: " << HostPort << " open !" << std::endl;
			pthread_mutex_unlock(&UDPPrintlocker);
			break;
		}
	} 
	while(true);

    //close socket
	close(UDPSock);
	delete p;
}


void* Thread_UDPScan(void* param)
{

	// pthread_t subThreadID;
	// pthread_attr_t attr;
	// int ret;
    
	struct UDPThrParam *p = (struct UDPThrParam*) param;
	std::string HostIP = p -> HostIP;
	unsigned BeginPort = p -> BeginPort;
	unsigned EndPort = p -> EndPort;
	unsigned LocalHostIP = p -> LocalHostIP;
	

	unsigned LocalPort = 1024;
 
	for (unsigned TempPort = BeginPort; TempPort <= EndPort; TempPort++) 
	{
        UDPScanHostThrParam *pUDPScanHostParam = new UDPScanHostThrParam;
        pUDPScanHostParam->HostIP = HostIP;
		pUDPScanHostParam->HostPort = TempPort;
        pUDPScanHostParam->LocalPort = TempPort + LocalPort;
        pUDPScanHostParam->LocalHostIP = LocalHostIP;
		UDPScanHost(pUDPScanHostParam);

	}
    //---------------exit thread----------------------
    std::cout << "UDP Scan thread exit !" << std::endl;
	pthread_exit(NULL);
}