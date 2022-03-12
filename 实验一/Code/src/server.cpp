#include "server.h"

int main()
{
    int nListenSocket, nAcceptSocket;
    socklen_t  nLength;
    struct sockaddr_in sLocalAddr, sRemoteAddr;
    bzero(&sLocalAddr, sizeof(sLocalAddr));
    sLocalAddr.sin_family = PF_INET;
    sLocalAddr.sin_port = htons(6000);
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