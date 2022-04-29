#ifndef CLIENT_H
#define CLIENT_H

#include "DES.h"
#include "RSA.h"
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <semaphore.h>
#include <aio.h>
#include <sys/types.h>
#include <signal.h>


#define BUFFERSIZE 64
char strSocketBuffer[BUFFERSIZE];
char strDecryBuffer[BUFFERSIZE];
char strStdinBuffer[BUFFERSIZE];
char strEncryBuffer[BUFFERSIZE];


size_t TotalRecv(int s, void *buf, size_t len, int flags){
    size_t nCurSize = 0;
    while(nCurSize <len)
    {
        ssize_t nRes = recv(s,((char*)buf)+nCurSize,len-nCurSize,flags);
        if(nRes<0||nRes+nCurSize>len)
        {
            return -1;
        }
        nCurSize+=nRes;
    }
    return nCurSize;
}

void GerenateDesKey(char* x){
    int i;
    srand(time(NULL));
    for (i = 0; i < 8; i++)
    {
        switch ((rand() % 3))
        {
        case 1:
            x[i] = 'A' + rand() % 26;
            break;
        case 2:
            x[i] = 'a' + rand() % 26;
            break;
        default:
            x[i] = '0' + rand() % 10;
            break;
        }
    }
    x[i] = '\0';
}

void SecretChat(int nSock, char *pRemoteName, char *pKey){

    std::cout << pRemoteName << std::endl;
    CDesOperate cDes;
    std::cout << pKey << std::endl;
    int klength = strlen(pKey);
    if(klength != 8){
        printf("%s\n",pKey);
        printf("Key length error\n");
        return;
    }

    //select model
    fd_set cHandleSet;
    struct timeval tv;
    int nRet;
    while(1){
        FD_ZERO(&cHandleSet);
        FD_SET(nSock, &cHandleSet);
        FD_SET(0, &cHandleSet);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        nRet = select(nSock>0? nSock+ 1:1, &cHandleSet, NULL, NULL, &tv);
        if(nRet < 0){
            printf("Select error!\n");
            break;
        }
        if(nRet == 0){
            continue;
        }
        if(FD_ISSET(nSock,&cHandleSet)){
            bzero(&strSocketBuffer, BUFFERSIZE);
            int nLength = 0;
            nLength = TotalRecv(nSock, strSocketBuffer,BUFFERSIZE,0);
            if(nLength !=BUFFERSIZE) break;
            else{
                int nLen = BUFFERSIZE;
                cDes.Decry(strSocketBuffer,BUFFERSIZE,strDecryBuffer,nLen,pKey,8);
                strDecryBuffer[BUFFERSIZE-1]=0;
                if(strDecryBuffer[0]!=0&&strDecryBuffer[0]!='\n'){
                    printf("Receive message form <%s>: %s",pRemoteName,strDecryBuffer);
                    if(0==memcmp("quit",strDecryBuffer,4)){
                        printf("Quit!\n");
                        break;
                    }
                }
            }
        }
        if(FD_ISSET(0,&cHandleSet)){
            bzero(&strStdinBuffer, BUFFERSIZE);
            while(strStdinBuffer[0]==0){
                if (fgets(strStdinBuffer, BUFFERSIZE, stdin) == NULL){
                    continue;
                }
            }
            int nLen = BUFFERSIZE;
            cDes.Encry(strStdinBuffer,BUFFERSIZE,strEncryBuffer,nLen,pKey,8);
            if(send(nSock, strEncryBuffer, BUFFERSIZE,0)!=BUFFERSIZE){
                perror("send");
            }else{
                if(0==memcmp("quit",strStdinBuffer,4)){
                    printf("Quit!\n");
                    break;
                }
            }
        }
    }
}

#endif