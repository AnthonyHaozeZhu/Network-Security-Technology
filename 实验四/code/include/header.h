#ifndef HEADER_H
#define HEADER_H

#include <iostream>

bool Ping(std::string HostIP,unsigned LocalHostIP); // ICMP 探测指定主机
void* Thread_TCPconnectHost(void* param); // TCP connect 扫描


#endif