#include "client.h"

int main()
{
    char strIpAddr[16];
    std::cin >> strIpAddr;
    int nConnectSocket, nLength;
    struct sockaddr_in sDestAddr;
    if((nConnectSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket");
        exit(errno);
    }
    sDestAddr.sin_family = AF_INET;
    sDestAddr.sin_port = htons(6000);
    sDestAddr.sin_addr.s_addr = inet_addr(strIpAddr);
    if(connect(nConnectSocket, (struct sockaddr*)&sDestAddr, sizeof(sDestAddr)) != 0) {
        perror("Connect");
        exit(errno);
    }
    else {
        std::cout << "Connect Succcess!" << std::endl;
        std::cout << "Begin to chat.." << std::endl;
        char *temp = "benbenmi";
        SecretChat(nConnectSocket, strIpAddr, temp);
    }
    close(nConnectSocket);
}
