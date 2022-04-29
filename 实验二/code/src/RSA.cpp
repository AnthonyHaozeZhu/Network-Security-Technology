/*
 * @Author: AnthonyZhu
 * @Date: 2022-04-06 19:18:21
 * @LastEditors: Please set LastEditors
 * @LastEditTime: 2022-04-07 00:39:55
 * @FilePath: /实验二/code/src/RSA.cpp
 * @Description: 
 * 
 * Copyright (c) 2022 by HaozeZhu, All Rights Reserved. 
 */

#include "RSA.h"

inline __int64 CRsaOperate::MulMod(__int64 a, unsigned long b, unsigned long n) {
    return (a % n) * (b % n) % n;
}
__int64 CRsaOperate::PowMod(__int64 base, __int64 pow, __int64 n) {
    __int64 a = base, b = pow, c = 1;
    while(b){
        while(!(b & 1)){
            b >>= 1;
            a = MulMod(a, a, n);
        }
        b--;
        c = MulMod(a, c, n);
    }
    return c;
}


long CRsaOperate::RabinMillerKnl(__int64 &n) {
    __int64 a, q, k, v;
    q = n - 1;
    k = 0;
    while(!(q & 1)) {
        ++k;
        q >>= 1;
    }
    a = 2 + rand() % (n - 3);
    v = PowMod(a, q, n);
    if(v == 1) {
        return 1;
    }
    for(int j = 0; j < k; j++) {
        unsigned int z = 1;
        for(int w = 0; w < j; w++) {
            z *= 2;
        }
        if(PowMod(a, z*q, n) == n - 1)
            return 1;
    }
    return 0;
}


long CRsaOperate::RabinMiller(__int64 &n, long loop=100) {
    for(long i = 0; i < loop ; i++){
        if(!RabinMillerKnl(n)){
            return 0;
        }
    }
    return 1;
}


__int64 CRsaOperate::RandPrime(char bit) {
    __int64 base;
    do{
        base = (unsigned long)1 << (bit - 1);
        base += rand() % (base);
        base |= 1;
    }
    while(!RabinMiller(base, 30));
    return base;
}


__int64 CRsaOperate::Gcd(__int64 &p, __int64 &q) {
    unsigned long long a = p > q ? p : q;
    unsigned long long b = p < q ? p : q;
    unsigned long long t;
    if( p == q ){
        return p;
    }else{
        while(b){
            a = a % b;
            t = a;
            a = b;
            b = t;
        }
        return a;
    }
}


__int64 CRsaOperate::Euclid(__int64 e, __int64 t_n) { 
    unsigned long long Max = 0xffffffffffffffff - t_n;
    unsigned long long i = 1;
    while(1){
        if(((i*t_n)+1)%e == 0){
            return ((i*t_n)+1)/e;
        }
        i++;
        unsigned long long Tmp = (i+1)*t_n;
        if(Tmp > Max){
            return 0;
        }
    }
    return 0;
}


__int64 CRsaOperate::Encry(unsigned short nScore, PublicKey &cKey) {
    return PowMod(nScore, cKey.nE, cKey.nN);
}

unsigned short CRsaOperate::Decry(__int64 nScore) {
     unsigned long long nRes = PowMod(nScore, m_cParament.d, m_cParament.n);
    unsigned short *pRes = (unsigned short *)&(nRes);
    if(pRes[1] != 0 || pRes[3] != 0 || pRes[2] != 0) {
        return 0;
    }
    else {
        return pRes[0];
    }
}

PublicKey CRsaOperate::GetPublicKey() {
    PublicKey cTmp;
    cTmp.nE = this -> m_cParament.e;
    cTmp.nN = this -> m_cParament.n;
    return cTmp;
}


RsaParam RsaGetParam() {
    RsaParam Rsa = { 0 };
    unsigned long long t;
    Rsa.p = CRsaOperate::RandPrime(16);
    Rsa.q = CRsaOperate::RandPrime(16);
    Rsa.n = Rsa.p * Rsa.q;
    Rsa.f = (Rsa.p - 1) * (Rsa.q - 1);
    do {
        Rsa.e = rand() % Rsa.f;
        Rsa.e |= 1;
    }
    while(CRsaOperate::Gcd(Rsa.e, Rsa.f) != 1);
    Rsa.d = CRsaOperate::Euclid(Rsa.e, Rsa.f);
    Rsa.s = 0;
    t = Rsa.n >> 1;
    while(t) {
        Rsa.s++;
        t >>= 1;
    }
    return Rsa;
}

CRsaOperate::CRsaOperate() {
    this -> m_cParament = RsaGetParam();
}