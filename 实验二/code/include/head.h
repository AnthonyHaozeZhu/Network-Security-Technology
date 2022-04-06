#ifndef CLIENT_H
#define CLIENT_H

#include "DES.h"
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

#define BUFFERSIZE 64
char strSocketBuffer[BUFFERSIZE];
char strDecryBuffer[BUFFERSIZE];
char strStdinBuffer[BUFFERSIZE];
char strEncryBuffer[BUFFERSIZE];

size_t TotalRecv(int s, void* buf, size_t len, int flags)
{
    size_t nCurSize = 0;
    while (nCurSize < len)
    {
        size_t nRes = recv(s, ((char*)buf) + nCurSize, len - nCurSize, flags);
        if (nRes < 0 || nRes + nCurSize > len)
        {
            return -1;
        }
        nCurSize += nRes;
    }
    return nCurSize;
}

void SecretChat(int nSock, char* pRemoteName, string pKey)
{
	//声明DES类对象
	CDesOperate cDes;

	//select机制相关的声明变量
	fd_set cHandleSet;
	struct timeval tv;
	int nRet;

    //设置密钥
	if (pKey.length() != 8)
	{
		perror("Key length error.");
		exit(1);
		return;
	}
	cDes.key = StrToBit(pKey);
	cDes.Generate_Keys();

	while (1)
	{
		FD_ZERO(&cHandleSet); 
		FD_SET(nSock, &cHandleSet); //套接字加入cHandleSet
		FD_SET(0, &cHandleSet);//0是标准输入，加入cHandleSet
		tv.tv_sec = 1;//设置超时时间
		tv.tv_usec = 0; 
		//程序只监控套接字和标准输入上的读操作
		nRet = select(nSock>0? nSock+ 1:1, &cHandleSet, NULL, NULL, &tv);
		//失败
		if(nRet< 0)
		{
			printf("Select ERROR!\n");
			break;
		}
		//超时
		if(0==nRet)
		{
			continue;
		}

		//接收客户端的消息
		if(FD_ISSET(nSock, &cHandleSet))
		{
			bzero(&strSocketBuffer, BUFFERSIZE);//缓冲区清零
			int nLength = 0;
			nLength = recv(nSock, strSocketBuffer, BUFFERSIZE, 0);
			if(nLength <=0)
			{
				continue;
			}
			else
			{
				//将接收到的密文解密
				std::string plain = cDes.String_Decrypt((std::string)strSocketBuffer);
				plain[nLength - 1] = 0;
				//输出解密后的内容
				printf("\nReceive message from <%s>: %s\n\n",pRemoteName, plain.c_str());
				//接收quit信息
				if (0 == memcmp("quit", plain.c_str(), 4))
				{
					printf("Quit!\n");
					break;
				}	
			} 
		} 
		//将输入数据发送给客户端
		if(FD_ISSET(0, &cHandleSet))
		{
			char strStdinBuffer[BUFFERSIZE];//输入缓冲区
			memset(&strStdinBuffer, 0, sizeof(strStdinBuffer));//输入缓冲区清零
			while (strStdinBuffer[0] == 0)
			{
				std::cin.getline(strStdinBuffer,BUFFERSIZE);
			}
			//将输入的明文转换成密文
			std::string cipher = cDes.String_Encrypt((std::string)strStdinBuffer);
			//发送密文
			if (send(nSock, cipher.c_str(), BUFFERSIZE, 0) != BUFFERSIZE)
			{
				perror("Send error.");
			}
			else
			{
				//退出
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