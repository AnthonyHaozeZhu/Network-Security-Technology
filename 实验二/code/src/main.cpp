#include "head.h"

int main()
{
    std::cout << "Client or Server?" << std::endl;
    char temp;
    std::cin >> temp;
    if(temp == 's') {
        std::cout << "Listening..." << std::endl;
        int nListenSocket, nAcceptSocket;
        socklen_t  nLength;
        struct sockaddr_in sLocalAddr, sRemoteAddr;
        bzero(&sLocalAddr, sizeof(sLocalAddr));
        sLocalAddr.sin_family = PF_INET;
        sLocalAddr.sin_port = htons(6060);
        sLocalAddr.sin_addr.s_addr = INADDR_ANY;
        if ((nListenSocket = socket(PF_INET, SOCK_STREAM, 0)) == -1)
        {
            perror("socket");
            exit(1);
        }

        if(bind(nListenSocket, (struct sockaddr*) &sLocalAddr, sizeof(struct sockaddr)) == -1) {
            perror("bind");
            exit(1);
        }

        if(listen(nListenSocket, 5) == -1) {
            perror("listen");
            exit(1);
        }

        nAcceptSocket = accept(nListenSocket, (struct sockaddr*) &sRemoteAddr, &nLength);
        close(nListenSocket);
        std::cout << "server: got connection from " << inet_ntoa(sRemoteAddr.sin_addr) << ", port " << ntohs(sRemoteAddr.sin_port) << ", socket " << nAcceptSocket << std::endl;
        SecretChat(nAcceptSocket, inet_ntoa(sRemoteAddr.sin_addr), "benbenmi");
        close(nAcceptSocket);
    }
    else {
        std::cout << "Please input the server address:" << std::endl;
        char strIpAddr[16];
        std::cin >> strIpAddr;
        int nConnectSocket, nLength;
        struct sockaddr_in sDestAddr;
        if((nConnectSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("Socket");
            exit(errno);
        }
        sDestAddr.sin_family = AF_INET;
        sDestAddr.sin_port = htons(6060);
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
}
