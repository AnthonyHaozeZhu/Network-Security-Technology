#include "header.h"

int TCPConThrdNum;
pthread_mutex_t TCPConPrintlocker = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t TCPConScanlocker = PTHREAD_MUTEX_INITIALIZER;

void* Thread_TCPconnectHost(void* param) {
    /*变量定义*/
    //获得目标主机的IP地址和扫描端口号
    struct TCPConHostThrParam *p = (struct TCPConHostThrParam*) param;
    std::string HostIP = p -> HostIP;
    unsigned HostPort = p -> HostPort;
    //创建流套接字
    int ConSock = socket(AF_INET,SOCK_STREAM,0);
    if(ConSock < 0) {
        pthread_mutex_lock(&TCPConPrintlocker);

    }

    //设置连接主机地址
    struct sockaddr_in HostAddr;
    memset(&HostAddr, 0, sizeof(HostAddr));
    HostAddr.sin_family = AF_INET;
    HostAddr.sin_addr.s_addr = inet_addr(&HostIP[0]);
    HostAddr.sin_port = htons(HostPort);
    //connect目标主机
    int ret = connect(ConSock, (struct sockaddr*) &HostAddr, sizeof(HostAddr));
    if(ret < 0) {
        pthread_mutex_lock(&TCPConPrintlocker);
        std::cout << "TCP connect scan: " << HostIP << ":" << HostPort << " is closed" << std::endl;
        pthread_mutex_unlock(&TCPConPrintlocker);
    } else {
        pthread_mutex_lock(&TCPConPrintlocker);
        std::cout << "TCP connect scan: " << HostIP << ":" << HostPort << " is open" << std::endl;
        pthread_mutex_unlock(&TCPConPrintlocker);
    }
    delete p;
    close(ConSock); //关闭套接字
    //子线程数减1
    pthread_mutex_lock(&TCPConScanlocker);
    TCPConThrdNum--;
    pthread_mutex_unlock(&TCPConScanlocker);
} // TCP connect 扫描

void* Thread_TCPconnectScan(void* param)
{
    /*变量定义*/
    //获得扫描的目标主机IP，启始端口，终止端口
    struct TCPConThrParam *p = (struct TCPConThrParam*) param;
    std::string HostIP = p -> HostIP;
    unsigned BeginPort = p -> BeginPort;
    unsigned EndPort = p->EndPort;
    TCPConThrdNum = 0; //将线程数设为0
    //开始从起始端口到终止端口循环扫描目标主机的端口
    pthread_t subThreadID;
	pthread_attr_t attr;
    for (unsigned TempPort = BeginPort; TempPort <= EndPort; TempPort++)
    {
        //设置子线程参数
        TCPConHostThrParam *pConHostParam = new TCPConHostThrParam;
        pConHostParam->HostIP = HostIP;
        pConHostParam->HostPort = TempPort;
        //将子线程设为分离状态
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
        //创建connect目标主机指定的端口子线程
        int ret = pthread_create(&subThreadID, &attr, Thread_TCPconnectHost, pConHostParam);
        if(ret == -1) {
            std::cout << "Create TCP connect scan thread error!" << std::endl;
        }
        //线程数加1
        pthread_mutex_lock(&TCPConScanlocker);
        TCPConThrdNum++;
        pthread_mutex_unlock(&TCPConScanlocker);
        //如果子线程数大于100，暂时休眠
        while (TCPConThrdNum>100) {
            sleep(3); 
        }
    }
    //等待子线程数为0，返回
    while (TCPConThrdNum != 0) {
        sleep(1);
    }
    pthread_exit(NULL);
}
