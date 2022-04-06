/*
 * @Author: AnthonyZhu
 * @Date: 2022-04-06 17:58:00
 * @LastEditors: Please set LastEditors
 * @LastEditTime: 2022-04-06 19:50:25
 * @FilePath: /实验二/code/include/RSA.h
 * @Description: 
 * 
 * Copyright (c) 2022 by HaozeZhu, All Rights Reserved. 
 */

#ifndef RSA_H
#define RSA_H

#include <iostream>
typedef unsigned long long  __int64;

struct PublicKey {
    __int64 nE;
    __int64 nN;
};

struct RSAKeyPair {
    __int64 publicKey_e;
    __int64 secretKey_d;
    __int64 n;
};

struct RsaParam{
    unsigned long long e;
    unsigned long long n;
    unsigned long long d;
    unsigned long long f;
    unsigned long long p;
    unsigned long long q;
    unsigned long long s;
};


class CRsaOperate {
private:
    inline __int64 MulMod(__int64 a, unsigned long b, unsigned long n);
    __int64 PowMod(__int64 base, __int64 pow, __int64 n);
    long RabinMillerKnl(__int64 &n);
    long RabinMiller(__int64 &n, long loop=100);
    __int64 RandPrime(char bit);
    __int64 Gcd(__int64 &p, __int64 &q);
    __int64 Euclid(__int64 e, __int64 t_n);
    __int64 Encry(unsigned short nScore, PublicKey &cKey);
    unsigned short Decry(__int64 nScore);
public:
    PublicKey GetPublicKey();
    RsaParam RsaGetParam();
};

#endif