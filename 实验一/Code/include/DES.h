#ifndef DES_H
#define DES_H

#include <iostream>
#include "DES.h"
#define SUCCESS 1
#define DESENCRY 0

typedef int INT32;
typedef uint32_t ULONG32;
typedef uint8_t ULONG8;
class CDesOperate{
private:
    //recursive key 16
	ULONG32 m_arrOutKey[16][2];
    //initial key
    ULONG32 m_arrBufKey[2];

    //execute whole action
    INT32 HandleData(ULONG32 *left, ULONG8 choice);
    //execute 16 round without IP
    INT32 MakeData(ULONG32 *left, ULONG32 *right, ULONG32 number);
    //generate 1 recursive key
    INT32 MakeKey(ULONG32 *keyleft, ULONG32 *keyright, ULONG32 number);
    //generate 16 recursive key
    INT32 MakeFirstKey(ULONG32 *keyP);

public:
    CDesOperate();
    INT32 Encry(char *pPlaintext, int nPlaintextLength, 
    char *pCipherBuffer, int &nCipherBufferLength, char *pKey, int nKeyLength);
    INT32 Decry(char *pCipher, int nCipherBufferLength,
    char *pPlaintextBuffer, int &nPlaintextBufferLength, char *pKey, int nKeyLength);
};
#endif