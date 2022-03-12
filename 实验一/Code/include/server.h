#ifndef SERVER_H
#define SERVER_H

#include "DES.h"
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

#define BUFFERSIZE 64

char strStdinBuffer[BUFFERSIZE];
char strSocketBuffer[BUFFERSIZE];
char strEncryBuffer[BUFFERSIZE];
char strDecryBuffer[BUFFERSIZE];



size_t TotalRecv(int s, void* buf, size_t len, int flags)
{
    size_t nCurSize = 0;
    while (nCurSize < len)
    {
        size_t nRes = recv(s, ((char*)buf) + nCurSize, len - nCurSize, flags);
        if (nRes<0 || nRes + nCurSize>len)
        {
            return -1;
        }
        nCurSize += nRes;
    }
    return nCurSize;
}

void SecretChat(int nSock, char* pRemoteName, char* pKey)
{
    CDesOperate cDes;
    if (strlen(pKey) != 8)
    {
        printf("Key length error");
        return;
    }
    pid_t nPid;
    nPid = fork();
    if (nPid != 0)
    {
        while (1)
        {
            bzero(&strSocketBuffer, BUFFERSIZE);
            int nLength = 0;
            nLength = TotalRecv(nSock, strSocketBuffer, BUFFERSIZE, 0);
            if (nLength != BUFFERSIZE)
            {
                break;
            }
            else
            {
                int nLen = BUFFERSIZE;
                cDes.Decry(strSocketBuffer, BUFFERSIZE, strDecryBuffer, nLen, pKey, 8);
                strDecryBuffer[BUFFERSIZE - 1] = 0;
                if (strDecryBuffer[0] != 0 && strDecryBuffer[0] != '\n') {
                    printf("Receive message form <%s>: %s\n",pRemoteName, strDecryBuffer);
                    if (0 == memcmp("quit", strDecryBuffer, 4))
                    {
                        printf("Quit!\n");
                        break;
                    }
                }
            }
        }
    }
    else
    {
        while (1)
        {
            bzero(&strStdinBuffer, BUFFERSIZE);
            while (strStdinBuffer[0] == 0)
            {
                if (fgets(strStdinBuffer, BUFFERSIZE, stdin) == NULL)
                {
                    continue;
                }
            }
            int nLen = BUFFERSIZE;
            cDes.Encry(strStdinBuffer, BUFFERSIZE, strEncryBuffer, nLen, pKey, 8);
            if (send(nSock, strEncryBuffer, BUFFERSIZE, 0) != BUFFERSIZE)
            {
                perror("send");
            }
            else
            {
                if (0 == memcmp("quit", strStdinBuffer, 4))
                {
                    printf("Quit!\n");
                    break;
                }
            }
        }
    }
}

#endif