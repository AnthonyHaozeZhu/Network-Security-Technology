#include "head.h"

int main()
{
    std::cout << "Client or Server?" << std::endl;
    char temp;
    std::cin >> temp;
    if(temp == 's') {
        int nListenSocket,nAcceptSocket;
        struct sockaddr_in sLocalAddr, sRemoteAddr;
        bzero(&sLocalAddr, sizeof(sLocalAddr));
        sLocalAddr.sin_family = PF_INET;
        sLocalAddr.sin_port = htons(6000);
        sLocalAddr.sin_addr.s_addr = INADDR_ANY;
        if ((nListenSocket = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
            perror("socket");
            exit(1);
        }
        if(bind(nListenSocket, (struct sockaddr *) &sLocalAddr, sizeof(struct sockaddr)) == -1) {
            perror("bind");
            exit(1);
        }
        if(listen(nListenSocket, 5) == -1) {
            perror("listen");
            exit(1);
        }
        printf("Listening...\n");
        socklen_t nLength = 0;
        nAcceptSocket = accept(nListenSocket, (struct sockaddr*)&sRemoteAddr, &nLength);
        close(nListenSocket);
        printf("server: got connection from %s, port %d, socket %d\n",inet_ntoa(sRemoteAddr.sin_addr), ntohs(sRemoteAddr.sin_port), nAcceptSocket);
        
        //negotiate key
        PublicKey cRsaPublicKey;
        CRsaOperate CRsaOperate;
        //CRsaOperate.show_par();
        cRsaPublicKey = CRsaOperate.GetPublicKey();
        if(send(nAcceptSocket, (char *)(&cRsaPublicKey), sizeof(cRsaPublicKey), 0) != sizeof(cRsaPublicKey)){
            perror("send");
            exit(0);
        }else{
            printf("successful send the RSA public key. \n");
        }
        unsigned long long nEncryptDesKey[4];
        char *strDesKey = new char[8];
        if(4*sizeof(unsigned long long) != TotalRecv(nAcceptSocket,(char *)nEncryptDesKey, 4*sizeof(unsigned long long),0)) {
            perror("TotalRecv DES key error");
            exit(0);
        }
        else {
            printf("successful get the DES key\n");
            unsigned short * pDesKey = (unsigned short *)strDesKey;
            for(int i = 0;i < 4; i++) {
                pDesKey[i] = CRsaOperate.Decry(nEncryptDesKey[i]);
                //cout << pDesKey[i] << endl;
            }
        }
        
        printf("Begin to chat...\n");
        SecretChat(nAcceptSocket,inet_ntoa(sRemoteAddr.sin_addr),strDesKey);
        close(nAcceptSocket);
    }
    else {
        std::cout << "Please input the server address:" << std::endl;
        char strIPAddr[16];
        std::cin >> strIPAddr;
        int nConnectSocket, nLength;
        struct sockaddr_in sDestAddr;
        if((nConnectSocket = socket(AF_INET,SOCK_STREAM, 0)) < 0) {
            perror("Socket");
            exit(errno);
        }
        int SEVERPORT = 6000;

        sDestAddr.sin_family = AF_INET;
        sDestAddr.sin_port = htons(SEVERPORT);
        sDestAddr.sin_addr.s_addr = inet_addr(strIPAddr);
        if(connect(nConnectSocket, (struct sockaddr *) &sDestAddr, sizeof(sDestAddr)) != 0) {
            perror("Connect");
            exit(errno);
        }
        else {
            printf("Connect Success! \n");
            char *strDesKey = new char [8];
            GerenateDesKey(strDesKey);
            printf("Create DES key success\n");
            PublicKey cRsaPublicKey;
            if(sizeof(cRsaPublicKey) == TotalRecv(nConnectSocket,(char *)&cRsaPublicKey, sizeof(cRsaPublicKey),0)) {
                printf("Successful get the RSA public Key\n");
            }
            else {
                perror("Get RSA public key ");
                exit(0);
            }
            unsigned long long nEncryptDesKey[4];
            unsigned short *pDesKey = (unsigned short *)strDesKey;
            for(int i = 0; i < 4; i++) {
                nEncryptDesKey[i] = CRsaOperate::Encry(pDesKey[i],cRsaPublicKey);
            }
            if(sizeof(unsigned long long)*4 != send(nConnectSocket, (char *)nEncryptDesKey,sizeof(unsigned long long)*4, 0)) {
                perror("Send DES key Error");
                exit(0);
            }
            else {
                printf("Successful send the encrypted DES Key\n");
            }
            printf("Begin to chat...\n");
            SecretChat(nConnectSocket,strIPAddr,strDesKey);
        }
        close(nConnectSocket);
    }
}
