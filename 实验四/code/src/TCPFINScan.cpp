#include "header.h"

int TCPFinThrdNum;
pthread_mutex_t TCPFinPrintlocker = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t TCPFinScanlocker = PTHREAD_MUTEX_INITIALIZER;

void* Thread_TCPFINHost(void* param) {
    /*------------与 TCP SYN 扫描类似-----------------*/ 
    //填充 TCP FIN 数据包
    struct TCPFINHostThrParam *p = (struct TCPFINHostThrParam*)param;
    std::string HostIP = p -> HostIP;
	unsigned HostPort = p->HostPort;
	unsigned LocalPort = p->LocalPort;
	unsigned LocalHostIP = p->LocalHostIP;

    struct sockaddr_in FINScanHostAddr;
    memset(&FINScanHostAddr, 0, sizeof(FINScanHostAddr));
	FINScanHostAddr.sin_family = AF_INET;
	FINScanHostAddr.sin_addr.s_addr = inet_addr(&HostIP[0]);
	FINScanHostAddr.sin_port = htons(HostPort); 

    int FinSock=socket(PF_INET, SOCK_RAW, IPPROTO_TCP); 
	if (FinSock < 0) {
		pthread_mutex_lock(&TCPFinPrintlocker);
		std::cout << "Can't creat raw socket !" << std::endl;
		pthread_mutex_unlock(&TCPFinPrintlocker);
	}

    int FinRevSock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP); 
	if (FinRevSock < 0) 
	{
		pthread_mutex_lock(&TCPFinPrintlocker);
		std::cout << "Can't creat raw socket !" << std::endl;
		pthread_mutex_unlock(&TCPFinPrintlocker);
	}
	int flag = 1;
    if (setsockopt(FinSock, IPPROTO_IP, IP_HDRINCL, (void*)&flag, sizeof(int)) ==
        -1) {
        std::cout << "set IP_HDRINCL error.\n";
    }
	if (setsockopt(FinRevSock, IPPROTO_IP, IP_HDRINCL, (void*)&flag, sizeof(int)) ==
        -1) {
        std::cout << "set IP_HDRINCL error.\n";
    }


    char sendbuf[8192];
    struct pseudohdr *ptcph = (struct pseudohdr*)sendbuf; 
    struct tcphdr *tcph = (struct tcphdr*)(sendbuf + sizeof(struct pseudohdr)); 

    
    
	ptcph->saddr = LocalHostIP; 
    ptcph->daddr = inet_addr(&HostIP[0]); 
    ptcph->useless = 0; 
    ptcph->protocol = IPPROTO_TCP; 
    ptcph->length = htons(sizeof(struct tcphdr));


    tcph->th_sport = htons(LocalPort);  
    tcph->th_dport = htons(HostPort); 
    tcph->th_seq = htonl(123456); 
    tcph->th_ack = 0; 
    tcph->th_x2 = 0; 
    tcph->th_off = 5; 
    tcph->th_flags = TH_FIN; 
    tcph->th_win = htons(65535); 
    tcph->th_sum = 0; 
    tcph->th_urp = 0; 
	tcph->th_sum = in_cksum((unsigned short*)ptcph, 20 + 12);

	IPHeader IPheader(ptcph -> saddr, ptcph -> daddr, IPPROTO_TCP);
	char temp[sizeof(IPHeader) + sizeof(struct tcphdr)];

	memcpy((void*)temp, (void*)&IPheader, sizeof(IPheader));
	memcpy((void*)(temp+sizeof(IPheader)), (void*)tcph, sizeof(struct tcphdr));

    //发送 TCP FIN 数据包
    int len = sendto(FinSock, temp, sizeof(IPHeader) + sizeof(struct tcphdr), 0, (struct sockaddr *)&FINScanHostAddr, sizeof(FINScanHostAddr)); 
	if(len < 0) 
	{
		pthread_mutex_lock(&TCPFinPrintlocker);
		std::cout << "Send TCP FIN Packet error !" << std::endl;
		pthread_mutex_unlock(&TCPFinPrintlocker);		
	} 
    
    //将套接字设置为非阻塞模式
    if(fcntl(FinRevSock, F_SETFL, O_NONBLOCK) == -1) 
	{
		pthread_mutex_lock(&TCPFinPrintlocker);
        std::cout << "Set socket in non-blocked model fail !" << std::endl;
		pthread_mutex_unlock(&TCPFinPrintlocker);
	}

    int FromAddrLen = sizeof(struct sockaddr_in);

    //接收 TCP 响应数据包循环
    struct timeval TpStart,TpEnd; 
    char recvbuf[8192];
    struct sockaddr_in FromAddr;
    std::string SrcIP, DstIP, LocalIP;
    gettimeofday(&TpStart, NULL); //获得开始接收时刻 
    struct in_addr in_LocalhostIP;
    do {
        //调用 recvfrom 函数接收数据包
        len = recvfrom(FinRevSock, recvbuf, sizeof(recvbuf), 0, (struct sockaddr*) &FromAddr, (socklen_t*) &FromAddrLen);
		if(len > 0)
		{
            std::string SrcIP = inet_ntoa(FromAddr.sin_addr);
            if(1)
			{      
                //响应数据包的源地址等于目标主机地址 
                struct ip *iph = (struct ip *)recvbuf; 
				int i = iph -> ip_hl * 4; 
				struct tcphdr *tcph = (struct tcphdr *)&recvbuf[i]; 

				SrcIP = inet_ntoa(iph->ip_src);       
				DstIP = inet_ntoa(iph->ip_dst);       
				
                
				in_LocalhostIP.s_addr = LocalHostIP;
				LocalIP = inet_ntoa(in_LocalhostIP);  

				unsigned SrcPort = ntohs(tcph->th_sport);  
				unsigned DstPort = ntohs(tcph->th_dport); 

				// std::cout << "___________________________" << std::endl;

				// std::cout << HostIP << ' ' << SrcIP << std::endl;
				// std::cout << LocalIP << ' ' << DstIP << std::endl;
				// std::cout << SrcPort << ' ' << HostPort<< std::endl;
				// std::cout << DstPort << ' ' << LocalPort<< std::endl;
                //判断响应数据包的源地址是否等于目标主机地址，目的地址是否等于本机 IP 地址，源端口是否等于被扫描端口，目的端口是否等于本机端口号
                if(HostIP == SrcIP && LocalIP == DstIP && SrcPort == HostPort && DstPort == LocalPort)
				{
                    //判断是否为 RST 数据包
					if (tcph->th_flags == 0x14) 
					{  
						pthread_mutex_lock(&TCPFinPrintlocker);
						std::cout << "Host: " << SrcIP << " Port: " << ntohs(tcph -> th_sport) << " closed !" << std::endl;
						pthread_mutex_unlock(&TCPFinPrintlocker);
					}
					break;				
				}
            }
        }
        //判断等待响应数据包时间是否超过 3 秒
        gettimeofday(&TpEnd, NULL);
        float TimeUse = (1000000 * (TpEnd.tv_sec - TpStart.tv_sec) + (TpEnd.tv_usec - TpStart.tv_usec)) / 1000000.0;
        if(TimeUse < 5)
        {
            continue;
        }
        else
        {
            //超时，扫描端口开启 
            pthread_mutex_lock(&TCPFinPrintlocker);
            std::cout << "Host: " << HostIP << " Port: " << HostPort << " open !" << std::endl;
            pthread_mutex_unlock(&TCPFinPrintlocker);
            break;
        }
    }
    while(true);
    //退出子线程
    delete p;
    close(FinSock);
	close(FinRevSock);

	pthread_mutex_lock(&TCPFinScanlocker);
    TCPFinThrdNum--;
	pthread_mutex_unlock(&TCPFinScanlocker);
}


void* Thread_TCPFinScan(void* param) {
	struct TCPFINThrParam *p = (struct TCPFINThrParam*)param;
	std::string HostIP = p->HostIP;
	unsigned BeginPort = p->BeginPort;
	unsigned EndPort = p->EndPort;
	unsigned LocalHostIP = p->LocalHostIP;

	TCPFinThrdNum = 0;
	unsigned LocalPort = 1024;

    pthread_attr_t attr, lattr;
    pthread_t listenThreadID, subThreadID;
	for (unsigned TempPort = BeginPort; TempPort <= EndPort;TempPort++) 
	{
        struct TCPFINHostThrParam *pTCPFINHostParam = new TCPFINHostThrParam;
        pTCPFINHostParam->HostIP = HostIP;
		pTCPFINHostParam->HostPort = TempPort;
        pTCPFINHostParam->LocalPort = TempPort + LocalPort;
		pTCPFINHostParam->LocalHostIP = LocalHostIP;


		pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
                

		int ret = pthread_create(&subThreadID,&attr,Thread_TCPFINHost,pTCPFINHostParam);
		if (ret == -1) 
		{
			std::cout << "Can't create the TCP FIN Scan Host thread !" << std::endl;
		}

		pthread_attr_destroy(&attr);
		pthread_mutex_lock(&TCPFinScanlocker);
        TCPFinThrdNum++;
		pthread_mutex_unlock(&TCPFinScanlocker);

		while (TCPFinThrdNum>100)
		{
			sleep(3);
		}
	}

	while (TCPFinThrdNum != 0)
	{
		sleep(1);
	}

    std::cout << "TCP FIN scan thread exit !" << std::endl;
	pthread_exit(NULL);
}