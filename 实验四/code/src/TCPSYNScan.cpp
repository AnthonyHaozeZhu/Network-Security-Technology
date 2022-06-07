#include "header.h"

pthread_mutex_t TCPSynPrintlocker = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t TCPSynScanlocker = PTHREAD_MUTEX_INITIALIZER;

int TCPSynThrdNum;

void* Thread_TCPSYNHost(void* param) {
    /*变量定义*/
    //获得目标主机的IP地址和扫描端口号
    struct TCPSYNHostThrParam *p = (struct TCPSYNHostThrParam*) param;
    std::string HostIP = p -> HostIP;
    unsigned HostPort = p -> HostPort;
    unsigned LocalPort = p -> LocalPort;
	unsigned LocalHostIP = p -> LocalHostIP;

    struct sockaddr_in SYNScanHostAddr;
    memset(&SYNScanHostAddr, 0, sizeof(SYNScanHostAddr));
    SYNScanHostAddr.sin_family = AF_INET;
    SYNScanHostAddr.sin_addr.s_addr = inet_addr(HostIP.c_str());
    SYNScanHostAddr.sin_port = htons(HostPort);
    //创建套接字
    int SynSock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(SynSock < 0) {
        pthread_mutex_lock(&TCPSynPrintlocker);
		std::cout << "Can't creat raw socket !" << std::endl;
		pthread_mutex_unlock(&TCPSynPrintlocker);
    }
    int flag = 1;
    if (setsockopt(SynSock, IPPROTO_IP, IP_HDRINCL, (void*)&flag, sizeof(int)) ==
        -1) {
        std::cout << "set IP_HDRINCL error.\n";
    }
    //填充TCP SYN数据包
    char sendbuf[8192];
    char recvbuf[8192];
    struct pseudohdr *ptcph = (struct pseudohdr*) sendbuf;
    struct tcphdr *tcph = (struct tcphdr*)(sendbuf + sizeof(struct pseudohdr));
    //填充TCP伪头部，用于计算校验和
    ptcph -> saddr = LocalHostIP;
    ptcph -> daddr = inet_addr(HostIP.c_str());
    in_addr src, dst;
    ptcph -> useless = 0;
    ptcph -> protocol = IPPROTO_TCP;
    ptcph -> length = htons(sizeof(struct tcphdr));
    
    src.s_addr = ptcph -> saddr;
    dst.s_addr = ptcph -> daddr;
    // std::cout<<inet_ntoa(src)<<" "<<inet_ntoa(dst)<<" "<<sizeof(struct tcphdr)<<" "<<sizeof(struct pseudohdr)<<std::endl;

    //填充TCP头
    memset(tcph, 0, sizeof(struct tcphdr));
    // std::cout<<LocalPort<<" "<<HostPort<<std::endl;
    tcph->th_sport = htons(LocalPort);  
    tcph->th_dport = htons(HostPort); 
    tcph->th_seq = htonl(123456); 
    tcph->th_ack = 0; 
    tcph->th_x2 = 0; 
    tcph->th_off = 5; 
    tcph->th_flags = TH_SYN; 
    tcph->th_win = htons(65535); 
    tcph->th_sum = 0; 
    tcph->th_urp = 0; 
	tcph->th_sum = in_cksum((unsigned short*)ptcph, 20 + 12);

    IPHeader IPheader(ptcph -> saddr, ptcph -> daddr, IPPROTO_TCP);
	char temp[sizeof(IPHeader) + sizeof(struct tcphdr)];

	memcpy((void*)temp, (void*)&IPheader, sizeof(IPheader));
	memcpy((void*)(temp+sizeof(IPheader)), (void*)tcph, sizeof(struct tcphdr));

    //发送TCP SYN数据包
    int len = sendto(SynSock, temp, sizeof(IPHeader) + sizeof(struct tcphdr), 0, (struct sockaddr *)&SYNScanHostAddr, sizeof(SYNScanHostAddr));
    // std::cout << sizeof(IPHeader) <<" "<< sizeof(struct tcphdr)<<" "<<len << std::endl;
    if(len < 0) {
        pthread_mutex_lock(&TCPSynPrintlocker);
		std::cout << "Send TCP SYN Packet error !" << std::endl;
		pthread_mutex_unlock(&TCPSynPrintlocker);
    }
    int count = 0;
    std::string SrcIP;
    struct ip *iph;
    flag = 1;
    sockaddr_in recvAddr;
    int addrLen = sizeof(recvAddr);
    do{
        len = recvfrom(SynSock, recvbuf, 8192, 0, (sockaddr*)&recvAddr,
                        (socklen_t*)&addrLen);
        if(len < 0) { 
            /*接收错误*/
            pthread_mutex_lock(&TCPSynPrintlocker);
            std::cout << "Read TCP SYN Packet error !" << std::endl;
            pthread_mutex_unlock(&TCPSynPrintlocker);
        }
        else {
            struct ip *iph = (struct ip *)recvbuf; 
            int i = iph -> ip_hl * 4; 
            tcph = (struct tcphdr *)(recvbuf + i); 

            std::string SrcIP = inet_ntoa(iph -> ip_src);
            std::string DstIP = inet_ntoa(iph -> ip_dst);
            struct in_addr in_LocalhostIP;
            in_LocalhostIP.s_addr = LocalHostIP;
            std::string LocalIP = inet_ntoa(in_LocalhostIP);

            unsigned SrcPort = ntohs(tcph -> th_sport);    
            unsigned DstPort = ntohs(tcph -> th_dport);  
            //判断响应数据包的源地址是否等于目标主机地址，目的地址是否等于本机
            //IP地址，源端口是否等于被扫描端口，目的端口是否等于本机端口号
            // std::cout << "___________________________" << std::endl;

            // std::cout << HostIP << ' ' << SrcIP << std::endl;
            // std::cout << LocalIP << ' ' << DstIP << std::endl;
            // std::cout << SrcPort << ' ' << HostPort<< std::endl;
            // std::cout << DstPort << ' ' << LocalPort<< std::endl;
            if(HostIP == SrcIP && LocalIP == DstIP && SrcPort == HostPort && DstPort == LocalPort)
            {
                // std::cout<<(int)(tcph->th_flags)<<std::endl;
                if(tcph->th_flags == 0x12) //判断是否为SYN|ACK数据包
                {
                    /*端口开启*/
                    flag = 0;
                    pthread_mutex_lock(&TCPSynPrintlocker);
                    std::cout << "Host: " << SrcIP << " Port: " << ntohs(tcph -> th_sport) << " open !" << std::endl;
                    pthread_mutex_unlock(&TCPSynPrintlocker);
                }
                if(tcph->th_flags == 0x14) //判断是否为RST数据包
                { 
                    /*端口关闭*/
                    flag = 0; 
                    pthread_mutex_lock(&TCPSynPrintlocker);
                    std::cout << " Port: " << ntohs(tcph -> th_sport) << " closed !" << std::endl;
                    pthread_mutex_unlock(&TCPSynPrintlocker); 
                }
            }
        }
    } while(count++ < 20 && flag);
    //退出子线程
    if(flag){
        pthread_mutex_lock(&TCPSynPrintlocker);
        std::cout << "Host: " << SrcIP << " Port: " << HostPort << " closed !" << std::endl;
        pthread_mutex_unlock(&TCPSynPrintlocker);
    }
    delete p;
    close(SynSock);
    pthread_mutex_lock(&TCPSynScanlocker);
    TCPSynThrdNum--;
    pthread_mutex_unlock(&TCPSynScanlocker);
}

void* Thread_TCPSynScan(void* param) {
    /*变量定义*/
    //获得目标主机的IP地址和扫描的起始端口号，终止端口号，以及本机的IP地址
    struct TCPSYNThrParam *p = (struct TCPSYNThrParam*)param;
    std::string HostIP = p -> HostIP;
    unsigned BeginPort = p-> BeginPort;
	unsigned EndPort = p-> EndPort;
	unsigned LocalHostIP = p -> LocalHostIP;

    //循环遍历扫描端口
    TCPSynThrdNum = 0;
    unsigned LocalPort = 1024;
    pthread_attr_t attr,lattr;
    pthread_t listenThreadID,subThreadID;
    for (unsigned TempPort = BeginPort; TempPort <= EndPort; TempPort++)
    {
        //设置子线程参数
        struct TCPSYNHostThrParam *pTCPSYNHostParam =
        new TCPSYNHostThrParam;
        pTCPSYNHostParam->HostIP = HostIP;
        pTCPSYNHostParam->HostPort = TempPort;
        pTCPSYNHostParam->LocalPort = TempPort + LocalPort;
        pTCPSYNHostParam->LocalHostIP = LocalHostIP;
        //将子线程设置为分离状态
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
        //创建子线程
        int ret = pthread_create(&subThreadID, &attr, Thread_TCPSYNHost, pTCPSYNHostParam);
        if (ret==-1) 
		{
			std::cout << "Can't create the TCP SYN Scan Host thread !" << std::endl;
		}
        pthread_attr_destroy(&attr);
        //子线程数加1
        pthread_mutex_lock(&TCPSynScanlocker);
        TCPSynThrdNum++;
        pthread_mutex_unlock(&TCPSynScanlocker);
        //子线程数大于100，休眠
        while(TCPSynThrdNum > 100) { 
            sleep(3); 
        }
    }
    while(TCPSynThrdNum != 0) { 
        sleep(1);
    }
    //返回主流程
    pthread_exit(NULL);
}
