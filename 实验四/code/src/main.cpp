#include "header.h"

void print_h(int argc, char *argv[]) {
    if (2 != argc) {
        std::cout << "参数错误." << std::endl;
        return;
    }
    std::cout << "MD5：usage:\n" << "\t" << "[-h] --help information " << std::endl;
    std::cout << "\t" << "[-c] --TCP connect scan" << std::endl;
    std::cout << "\t" << "[-s] --TCP syn scan" << std::endl;
    std::cout << "\t" << "[-f] --TCP fin scan" << std::endl;
    std::cout << "\t" << "[-u] --UDP scan" << std::endl;
}

bool Ping(std::string HostIP, unsigned LocalHostIP) {
    struct iphdr *ip; 
    struct icmphdr *icmp;
    unsigned short LocalPort = 8888;

    int PingSock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    
    int on = 1;
    int ret = setsockopt(PingSock, 0, IP_HDRINCL, &on, sizeof(on));
    
    int SendBufSize = sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct timeval);
    char *SendBuf = (char*)malloc(SendBufSize);
    memset(SendBuf, 0, sizeof(SendBuf));

    ip = (struct iphdr*)SendBuf;
    ip -> ihl = 5;
    ip -> version = 4;
    ip -> tos = 0;
    ip -> tot_len = htons(SendBufSize);
    ip -> id = rand();
    ip -> ttl = 64;
    ip -> flag_off = 0x40;
    ip -> protocol = IPPROTO_ICMP;
    ip -> check = 0;
    ip -> saddr = LocalHostIP;
    ip -> daddr = inet_addr(&HostIP[0]);

    //填充icmp头
    icmp = (struct icmphdr*)(ip + 1);
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = htons(LocalPort);
    icmp->un.echo.sequence = 0;

    struct timeval *tp = (struct timeval*) &SendBuf[28];
    gettimeofday(tp, NULL);
    icmp -> check = in_cksum((u_short *)icmp, sizeof(struct icmphdr) + sizeof(struct timeval));

    //设置套接字的发送地址
    struct sockaddr_in PingHostAddr;
    PingHostAddr.sin_family = AF_INET;
    PingHostAddr.sin_addr.s_addr = inet_addr(&HostIP[0]);
    int Addrlen = sizeof(struct sockaddr_in);

    //发送ICMP请求
    ret = sendto(PingSock, SendBuf, SendBufSize, 0, (struct sockaddr*) &PingHostAddr, sizeof(PingHostAddr));
    if(ret < 0) {
        std::cout << "sendto error" << std::endl;
        return false;
    }

    if(fcntl(PingSock, F_SETFL, O_NONBLOCK) == -1) {
        perror("fcntl error");
        return false;
    }

    struct timeval TpStart, TpEnd;
    bool flags;
    //循环等待接收ICMP响应
    gettimeofday(&TpStart, NULL); //获得循环起始时刻
    flags = false;

    char RecvBuf[1024];
    struct sockaddr_in FromAddr;
    struct icmp* Recvicmp;
    struct ip* Recvip;
    std::string SrcIP, DstIP, LocalIP;
    struct in_addr in_LocalhostIP;

    do {
        //接收ICMP响应
        ret = recvfrom(PingSock, RecvBuf, 1024, 0, (struct sockaddr*) &FromAddr,
        (socklen_t*) &Addrlen);
        if (ret > 0) //如果接收到一个数据包，对其进行解析
        {
            Recvip = (struct ip*) RecvBuf;
            Recvicmp = (struct icmp*) (RecvBuf + (Recvip -> ip_hl * 4));
            SrcIP = inet_ntoa(Recvip -> ip_src); //获得响应数据包IP头的源地址
            DstIP = inet_ntoa(Recvip -> ip_dst); //获得响应数据包IP头的目的地址
            in_LocalhostIP.s_addr = LocalHostIP;
            LocalIP = inet_ntoa(in_LocalhostIP); //获得本机IP地址
            //判断该数据包的源地址是否等于被测主机的IP地址，目的地址是否等于
            //本机IP地址，ICMP头的type字段是否为ICMP_ECHOREPLY
            if (SrcIP == HostIP && DstIP == LocalIP &&
            Recvicmp->icmp_type == ICMP_ECHOREPLY) { 
                /*ping成功，退出循环*/
                std::cout << "Ping Host " << HostIP << " Successfully !" << std::endl;
				flags =true;
				break;
            }
        }
        //获得当前时刻，判断等待相应时间是否超过3秒，若是，则退出等待。
        gettimeofday(&TpEnd, NULL);
        float TimeUse = (1000000 * (TpEnd.tv_sec - TpStart.tv_sec) + (TpEnd.tv_usec - TpStart.tv_usec)) / 1000000.0;
        if(TimeUse < 3) {
            continue; 
        }
        else {
            flags = false;
            break;
        }
    } while(true);
    return flags;
}

int main(int argc,char *argv[]) { 
    std::unordered_map<std::string, void(*)(int, char*[])> mapOp = {{"-h", print_h}};
    if (argc < 2) { 
        std::cout << "参数错误，argc = " << argc << std::endl;
        return -1;
    }
    std::string op = argv[1];
    if (mapOp.find(op) != mapOp.end()) {
        mapOp[op](argc, argv);
        return 0;
    }
    std::string HostIP;
    std::cout << "Please input IP address of a Host:";
	std::cin >> HostIP;
    return 0;
}