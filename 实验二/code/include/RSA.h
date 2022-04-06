/*
 * @Author: AnthonyZhu
 * @Date: 2022-04-06 17:58:00
 * @LastEditors: Please set LastEditors
 * @LastEditTime: 2022-04-07 00:43:26
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
    __int64 e;
    __int64 n;
    __int64 d;
    __int64 f;
    __int64 p;
    __int64 q;
    __int64 s;
};


class CRsaOperate {
public:
    RsaParam m_cParament;  
    CRsaOperate(); 
    static inline __int64 MulMod(__int64 a, unsigned long b, unsigned long n);
    static __int64 PowMod(__int64 base, __int64 pow, __int64 n);
    static long RabinMillerKnl(__int64 &n);
    static long RabinMiller(__int64 &n, long loop);
    static __int64 RandPrime(char bit);
    static __int64 Gcd(__int64 &p, __int64 &q);
    static __int64 Euclid(__int64 e, __int64 t_n);
    static __int64 Encry(unsigned short nScore, PublicKey &cKey);
    unsigned short Decry(__int64 nScore);
    PublicKey GetPublicKey();
};

RsaParam RsaGetParam();

#endif